use morph_core::ebpf_observer::{
    decode_ringbuf_event, decode_ringbuf_stream, encode_ringbuf_event, sample_decoded_events,
    EbpfEventKind, EbpfObserveEvent, EBPF_EVENT_FRAME_SIZE, EBPF_FRAME_VERSION,
};
use morph_core::error::FailPolicy;
use morph_core::http_proxy::{build_proxy_router, ProxyConfig, ProxyState};
use morph_core::ollama::{
    ascii_table_to_json, html_table_to_json, kv_to_json, redact_pii, rename_json_fields,
    send_http1_request, xml_to_json, CaseStyle, OllamaClient, ParsedUrl,
};
use morph_core::pipeline::{
    CircuitBreaker, CircuitState, EnginePreference, MutationPipeline, MutationRequest,
};
use morph_core::plugins::{builtin_plugins, validate_plugin, OutputFormat};
use morph_core::stdio_interceptor::{run_mutated_command, StdioOptions};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_ascii_table_to_json_fixed_width_and_pipe() {
    let fixed = "\
PID     SERVICE            STATE     MEM_MB   ACTIVE
-----------------------------------------------------
1042    auth-gateway       RUNNING   128.4    true
1188    ledger-worker      DEGRADED  512.0    false
";
    let parsed = ascii_table_to_json(fixed).expect("fixed width table parses");
    let rows = parsed.as_array().expect("json array");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["pid"], json!(1042));
    assert_eq!(rows[0]["service"], json!("auth-gateway"));
    assert_eq!(rows[0]["mem_mb"], json!(128.4));
    assert_eq!(rows[0]["active"], json!(true));
    assert_eq!(rows[1]["state"], json!("DEGRADED"));
    assert_eq!(rows[1]["active"], json!(false));

    let piped = "\
+----+--------------+--------+
| ID | Node Name    | Healthy|
+----+--------------+--------+
| 1  | edge-us-01   | true   |
| 2  | edge-eu-02   | false  |
+----+--------------+--------+
";
    let parsed_pipe = ascii_table_to_json(piped).expect("piped table parses");
    let prows = parsed_pipe.as_array().expect("pipe array");
    assert_eq!(prows.len(), 2);
    assert_eq!(prows[0]["id"], json!(1));
    assert_eq!(prows[0]["node_name"], json!("edge-us-01"));
    assert_eq!(prows[1]["healthy"], json!(false));
}

#[test]
fn test_kv_and_xml_and_html_parsers() {
    let kv_raw = "\
[service]
name = billing-core
replicas = 4
tls_enabled = true
";
    let kv = kv_to_json(kv_raw).expect("kv parses");
    assert_eq!(kv["service"]["name"], json!("billing-core"));
    assert_eq!(kv["service"]["replicas"], json!(4));
    assert_eq!(kv["service"]["tls_enabled"], json!(true));

    let xml_raw = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- legacy erp response -->
<OrderResponse status="CONFIRMED">
  <OrderId>ORD-77</OrderId>
  <Amount>199.95</Amount>
  <Note><![CDATA[A & B <raw>]]></Note>
  <Item sku="A1"><Qty>2</Qty></Item>
  <Item sku="B2"><Qty>5</Qty></Item>
</OrderResponse>"#;
    let xml = xml_to_json(xml_raw).expect("xml parses");
    assert_eq!(xml["order_response"]["@status"], json!("CONFIRMED"));
    assert_eq!(xml["order_response"]["order_id"], json!("ORD-77"));
    assert_eq!(xml["order_response"]["amount"], json!(199.95));
    assert_eq!(xml["order_response"]["note"], json!("A & B <raw>"));
    let items = xml["order_response"]["item"].as_array().expect("repeated elements promoted to array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["@sku"], json!("A1"));
    assert_eq!(items[1]["qty"], json!(5));

    let html = "<table><tr><th>Host</th><th>Latency Ms</th></tr><tr><td>n1</td><td>12.5</td></tr></table>";
    let hval = html_table_to_json(html).expect("html table parses");
    assert_eq!(hval[0]["host"], json!("n1"));
    assert_eq!(hval[0]["latency_ms"], json!(12.5));
}

#[test]
fn test_rename_json_fields_and_pii_redaction() {
    let input = json!({
        "usr_id": "u_12",
        "billing_tier": "pro",
        "legacy_debug_flag": 1
    });
    let mut map = BTreeMap::new();
    map.insert("usr_id".into(), "userId".into());
    let mut add = BTreeMap::new();
    add.insert("apiVersion".into(), json!("v2"));

    let out = rename_json_fields(
        &input,
        &map,
        Some(CaseStyle::CamelCase),
        &["legacy_debug_flag".into()],
        &add,
    );
    assert_eq!(out["userId"], json!("u_12"));
    assert_eq!(out["billingTier"], json!("pro"));
    assert_eq!(out["apiVersion"], json!("v2"));
    assert!(out.get("legacy_debug_flag").is_none());

    let raw_log = "user=alice@corp.io ip=192.168.10.55 ssn=123-45-6789 phone=415-555-0142 auth=Bearer tok_1234567890abcdef";
    let (scrubbed, report) = redact_pii(raw_log);
    assert!(scrubbed.contains("[REDACTED:EMAIL]"));
    assert!(scrubbed.contains("[REDACTED:IPV4]"));
    assert!(scrubbed.contains("[REDACTED:SSN]"));
    assert!(scrubbed.contains("[REDACTED:PHONE]"));
    assert!(scrubbed.contains("Bearer [REDACTED:TOKEN]"));
    assert_eq!(report.emails_redacted, 1);
    assert_eq!(report.ipv4_redacted, 1);
    assert_eq!(report.ssn_redacted, 1);
    assert_eq!(report.phones_redacted, 1);
    assert_eq!(report.tokens_redacted, 1);
}

#[test]
fn test_ollama_rejects_non_loopback_endpoint() {
    let err = OllamaClient::new("http://198.51.100.10:11434", "llama3.2", 1000)
        .expect_err("non-loopback endpoint must be rejected");
    assert_eq!(err.error_code(), "non_loopback_endpoint");

    let ok = OllamaClient::new("http://127.0.0.1:11434", "llama3.2", 1000);
    assert!(ok.is_ok());
}

#[test]
fn test_ebpf_ring_buffer_binary_frame_roundtrip_and_validation() {
    let ev = EbpfObserveEvent {
        version: EBPF_FRAME_VERSION,
        event_kind: EbpfEventKind::SysEnterWrite,
        timestamp_ns: 9_876_543_210,
        pid: 2048,
        tgid: 2048,
        uid: 1000,
        fd: 1,
        byte_count: 1024,
        comm: "legacy-cli".into(),
        read_only: true,
        preview: "PID SERVICE STATE".into(),
    };

    let bytes = encode_ringbuf_event(&ev);
    assert_eq!(bytes.len(), EBPF_EVENT_FRAME_SIZE);
    let decoded = decode_ringbuf_event(&bytes).expect("frame decodes cleanly");
    assert_eq!(decoded, ev);

    // Concatenate two frames and verify stream decoder
    let mut stream = Vec::new();
    stream.extend_from_slice(&bytes);
    stream.extend_from_slice(&bytes);
    let many = decode_ringbuf_stream(&stream).expect("stream decodes");
    assert_eq!(many.len(), 2);

    // Corrupt magic must fail cleanly
    let mut bad_magic = bytes;
    bad_magic[0] = 0x00;
    assert!(decode_ringbuf_event(&bad_magic).is_err());

    // Stripping read-only verified flag must be rejected
    let mut no_ro = bytes;
    no_ro[58] = 0;
    no_ro[59] = 0;
    assert!(decode_ringbuf_event(&no_ro).is_err());

    assert_eq!(sample_decoded_events().len(), 3);
}

#[test]
fn test_all_builtin_plugins_pass_validation() {
    let builtins = builtin_plugins();
    assert_eq!(builtins.len(), 5);
    for plugin in &builtins {
        validate_plugin(plugin).expect("builtin plugin must pass schema validation");
    }
}

#[tokio::test]
async fn test_mock_ollama_http_and_circuit_breaker_failover() {
    // Spawn ephemeral local mock Ollama server returning valid JSON chat response
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut req_buf = [0u8; 4096];
        let _ = socket.read(&mut req_buf).await;
        let body = r#"{"message":{"role":"assistant","content":"[{\"service\":\"auth\",\"ok\":true}]"}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(resp.as_bytes()).await.unwrap();
    });

    let client = OllamaClient::new(&format!("http://{addr}"), "llama3.2", 2000).unwrap();
    let circuit = CircuitBreaker::new(2, 30_000);
    let pipeline = MutationPipeline::new(Some(client), circuit);

    let res = pipeline
        .mutate(MutationRequest {
            rule_id: "cli-to-json".into(),
            input: "SERVICE  OK\nauth     true".into(),
            engine: EnginePreference::OllamaWithFallback,
            output_format: Some(OutputFormat::Json),
            fail_policy: Some(FailPolicy::FailOpen),
            pretty: false,
            source: "test-ollama".into(),
        })
        .await
        .expect("mock ollama mutation succeeds");

    server_handle.await.unwrap();
    assert_eq!(res.engine_used, "ollama");
    assert!(!res.fallback_triggered);
    let parsed: Value = serde_json::from_str(&res.output).unwrap();
    assert_eq!(parsed[0]["service"], json!("auth"));

    // Now test failover + circuit breaker trip when Ollama is offline (closed port)
    let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);

    let dead_client = OllamaClient::new(&format!("http://{dead_addr}"), "llama3.2", 300).unwrap();
    let cb = CircuitBreaker::new(2, 60_000);
    let failover_pipeline = MutationPipeline::new(Some(dead_client), cb.clone());

    for _ in 0..2 {
        let r = failover_pipeline
            .mutate(MutationRequest {
                rule_id: "cli-table-to-json".into(),
                input: "PID  NAME\n10   worker".into(),
                engine: EnginePreference::OllamaWithFallback,
                output_format: Some(OutputFormat::Json),
                fail_policy: Some(FailPolicy::FailOpen),
                pretty: false,
                source: "test-failover".into(),
            })
            .await
            .expect("must fall back cleanly to deterministic parser without crashing");

        assert_eq!(r.engine_used, "deterministic-fallback");
        assert!(r.fallback_triggered);
        let parsed: Value = serde_json::from_str(&r.output).unwrap();
        assert_eq!(parsed[0]["pid"], json!(10));
        assert_eq!(parsed[0]["name"], json!("worker"));
    }

    assert_eq!(cb.status().state, CircuitState::Open);
    assert_eq!(cb.status().total_trips, 1);

    // Third request sees circuit already OPEN immediately and still mutates via deterministic fallback
    let fast_fallback = failover_pipeline
        .mutate(MutationRequest {
            rule_id: "cli-table-to-json".into(),
            input: "PID  NAME\n22   cron".into(),
            engine: EnginePreference::OllamaWithFallback,
            output_format: Some(OutputFormat::Json),
            fail_policy: Some(FailPolicy::FailOpen),
            pretty: false,
            source: "test-circuit-open".into(),
        })
        .await
        .expect("open circuit still mutates deterministically");
    assert_eq!(fast_fallback.circuit_state, CircuitState::Open);
    assert!(fast_fallback
        .fallback_reason
        .unwrap_or_default()
        .contains("circuit breaker open"));
}

#[tokio::test]
async fn test_stdio_interceptor_captures_and_mutates_child_process() {
    let pipeline = MutationPipeline::new(None, CircuitBreaker::new(3, 5000));
    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        (
            "cmd",
            vec![
                "/C".into(),
                "echo PID  SERVICE  STATE & echo 101  api-gw   RUNNING & echo 202  worker   STOPPED"
                    .into(),
            ],
        )
    } else {
        (
            "sh",
            vec![
                "-c".into(),
                "printf 'PID  SERVICE  STATE\\n101  api-gw   RUNNING\\n202  worker   STOPPED\\n'"
                    .into(),
            ],
        )
    };

    let exec = run_mutated_command(
        &pipeline,
        program,
        &args,
        StdioOptions {
            rule_id: "cli-to-json".into(),
            timeout_ms: 5000,
            max_output_bytes: 1024 * 1024,
            engine: EnginePreference::Deterministic,
            output_format: Some(OutputFormat::Json),
            fail_policy: Some(FailPolicy::FailOpen),
            pretty: false,
            include_stderr_in_input: false,
        },
    )
    .await
    .expect("stdio child process succeeds");

    assert_eq!(exec.exit_code, 0);
    assert!(!exec.timed_out);
    let parsed: Value = serde_json::from_str(&exec.mutation.output).expect("valid JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 2);
    assert_eq!(parsed[0]["pid"], json!(101));
    assert_eq!(parsed[0]["service"], json!("api-gw"));
    assert_eq!(parsed[1]["state"], json!("STOPPED"));
}

#[tokio::test]
async fn test_live_axum_http_proxy_xml_to_json_and_control_panel_api() {
    // 1. Ephemeral legacy XML upstream server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let upstream_task = tokio::spawn(async move {
        let (mut socket, _) = upstream_listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await;
        let xml_body = r#"<?xml version="1.0"?><Invoice id="INV-42"><Total>512.75</Total><Paid>true</Paid></Invoice>"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            xml_body.len(),
            xml_body
        );
        socket.write_all(resp.as_bytes()).await.unwrap();
    });

    // 2. Start real Axum 0.8 reverse proxy on ephemeral loopback port
    let pipeline = MutationPipeline::new(None, CircuitBreaker::new(3, 10_000));
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr: SocketAddr = proxy_listener.local_addr().unwrap();

    let cfg = ProxyConfig {
        listen_addr: proxy_addr,
        upstream_url: format!("http://{upstream_addr}"),
        default_rule_id: "xml-to-json".into(),
        engine: EnginePreference::Deterministic,
        output_format: Some(OutputFormat::Json),
        upstream_timeout_ms: 5000,
        max_body_bytes: 2 * 1024 * 1024,
        allow_non_loopback_bind: false,
    };

    let state = Arc::new(ProxyState::new(pipeline, &cfg).unwrap());
    let router = build_proxy_router(state);
    let proxy_task = tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, router).await;
    });

    let parsed_proxy = ParsedUrl::parse_http(&format!("http://{proxy_addr}")).unwrap();

    // 3. Request legacy XML endpoint through morph-os proxy -> receive live JSON!
    let proxied = send_http1_request(
        &parsed_proxy,
        "GET",
        "/v1/invoices/42",
        &[],
        &[],
        5000,
        1024 * 1024,
    )
    .await
    .expect("proxy HTTP request succeeds");

    assert_eq!(proxied.status, 200);
    assert_eq!(proxied.header("x-morph-mutated"), Some("true"));
    assert_eq!(proxied.header("x-morph-rule"), Some("legacy-xml-to-rest-json"));
    assert_eq!(proxied.header("x-morph-engine"), Some("deterministic"));
    let body_json: Value = serde_json::from_slice(&proxied.body).expect("mutated JSON body");
    assert_eq!(body_json["mutated_by"], json!("morph-os"));
    assert_eq!(body_json["payload"]["invoice"]["@id"], json!("INV-42"));
    assert_eq!(body_json["payload"]["invoice"]["total"], json!(512.75));
    assert_eq!(body_json["payload"]["invoice"]["paid"], json!(true));

    // 4. Verify Control Panel API endpoints (/_morph/health, /_morph/events, /_morph/plugins, /_morph/ebpf/spec)
    let health = send_http1_request(&parsed_proxy, "GET", "/_morph/health", &[], &[], 5000, 1024 * 1024)
        .await
        .expect("health succeeds");
    assert_eq!(health.status, 200);
    let health_json: Value = serde_json::from_slice(&health.body).unwrap();
    assert_eq!(health_json["status"], json!("ok"));
    assert_eq!(health_json["plugin_count"], json!(5));

    let events = send_http1_request(&parsed_proxy, "GET", "/_morph/events", &[], &[], 5000, 1024 * 1024)
        .await
        .expect("events succeeds");
    let events_json: Value = serde_json::from_slice(&events.body).unwrap();
    assert!(!events_json["events"].as_array().unwrap().is_empty());

    let ebpf = send_http1_request(&parsed_proxy, "GET", "/_morph/ebpf/spec", &[], &[], 5000, 1024 * 1024)
        .await
        .expect("ebpf spec succeeds");
    let ebpf_json: Value = serde_json::from_slice(&ebpf.body).unwrap();
    assert_eq!(ebpf_json["spec"]["frame_size_bytes"], json!(112));

    upstream_task.await.unwrap();
    proxy_task.abort();
}

#[tokio::test]
async fn test_csv_ndjson_formats_and_disk_plugin_loader_and_circuit_recovery() {
    // 1. Validate real plugins/*.json manifests from workspace root
    let plugins_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let loaded = morph_core::plugins::load_plugins_from_dir(&plugins_dir)
        .expect("workspace plugins directory loads and validates");
    assert_eq!(loaded.len(), 5);

    let pipeline = MutationPipeline::from_plugins(loaded, None, CircuitBreaker::new(2, 60));

    // 2. Test CSV and NDJSON serialization on legacy CLI table
    let csv_res = pipeline
        .mutate(MutationRequest {
            rule_id: "cli-table-to-json".into(),
            input: "PID  NAME\n10   alpha\n20   beta".into(),
            engine: EnginePreference::Deterministic,
            output_format: Some(OutputFormat::Csv),
            fail_policy: None,
            pretty: false,
            source: "test-csv".into(),
        })
        .await
        .expect("csv mutation succeeds");
    assert!(csv_res.output.starts_with("pid,name\n") || csv_res.output.starts_with("name,pid\n"));

    let ndjson_res = pipeline
        .mutate(MutationRequest {
            rule_id: "cli-table-to-json".into(),
            input: "PID  NAME\n10   alpha\n20   beta".into(),
            engine: EnginePreference::Deterministic,
            output_format: Some(OutputFormat::Ndjson),
            fail_policy: None,
            pretty: false,
            source: "test-ndjson".into(),
        })
        .await
        .expect("ndjson mutation succeeds");
    assert_eq!(ndjson_res.output.lines().count(), 2);

    // 3. Test CircuitBreaker cooldown transition: Closed -> Open -> HalfOpen -> Closed
    let cb = CircuitBreaker::new(1, 60);
    cb.record_failure("simulated timeout");
    assert_eq!(cb.status().state, CircuitState::Open);
    assert!(cb.allow_request().is_err());

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    assert!(cb.allow_request().is_ok());
    assert_eq!(cb.status().state, CircuitState::HalfOpen);
    cb.record_success();
    assert_eq!(cb.status().state, CircuitState::Closed);
}
