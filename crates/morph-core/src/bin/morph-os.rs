use clap::{Parser, Subcommand, ValueEnum};
use morph_core::ebpf_observer::{sample_decoded_events, EbpfObserverSpec};
use morph_core::http_proxy::{serve_proxy, ProxyConfig};
use morph_core::ollama::OllamaClient;
use morph_core::pipeline::{
    CircuitBreaker, EnginePreference, MutationPipeline, MutationRequest,
};
use morph_core::plugins::{load_plugins_from_dir, OutputFormat};
use morph_core::stdio_interceptor::{run_mutated_command, StdioOptions};
use morph_core::MORPH_OS_VERSION;
use std::fs;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "morph-os",
    version = MORPH_OS_VERSION,
    about = "Local runtime stream, HTTP API reverse-proxy, and DOM mutator (Rust + WASM + local Ollama)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliEngine {
    Deterministic,
    Ollama,
    OllamaStrict,
}

impl From<CliEngine> for EnginePreference {
    fn from(value: CliEngine) -> Self {
        match value {
            CliEngine::Deterministic => EnginePreference::Deterministic,
            CliEngine::Ollama => EnginePreference::OllamaWithFallback,
            CliEngine::OllamaStrict => EnginePreference::OllamaStrict,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFormat {
    Json,
    Ndjson,
    Csv,
    Text,
}

impl From<CliFormat> for OutputFormat {
    fn from(value: CliFormat) -> Self {
        match value {
            CliFormat::Json => OutputFormat::Json,
            CliFormat::Ndjson => OutputFormat::Ndjson,
            CliFormat::Csv => OutputFormat::Csv,
            CliFormat::Text => OutputFormat::Text,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DemoVariant {
    Table,
    Kv,
    Xml,
    Pii,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Explicitly spawn a CLI tool, capture its stdio pipes, and mutate output on the fly.
    Run {
        #[arg(long, default_value = "cli-table-to-json")]
        rule: String,
        #[arg(long, value_enum, default_value_t = CliEngine::Deterministic)]
        engine: CliEngine,
        #[arg(long, default_value = "http://127.0.0.1:11434")]
        ollama_url: String,
        #[arg(long, default_value = "llama3.2")]
        model: String,
        #[arg(long, value_enum)]
        format: Option<CliFormat>,
        #[arg(long, default_value_t = 15_000)]
        timeout_ms: u64,
        #[arg(long)]
        plugins_dir: Option<PathBuf>,
        #[arg(long)]
        compact: bool,
        #[arg(long)]
        stats: bool,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Run the opt-in loopback HTTP/API reverse-proxy mutator and Control Panel REST API.
    Proxy {
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        #[arg(long)]
        upstream: String,
        #[arg(long, default_value = "legacy-xml-to-rest-json")]
        rule: String,
        #[arg(long, value_enum, default_value_t = CliEngine::Deterministic)]
        engine: CliEngine,
        #[arg(long, default_value = "http://127.0.0.1:11434")]
        ollama_url: String,
        #[arg(long, default_value = "llama3.2")]
        model: String,
        #[arg(long, value_enum)]
        format: Option<CliFormat>,
        #[arg(long, default_value_t = 10_000)]
        timeout_ms: u64,
        #[arg(long)]
        plugins_dir: Option<PathBuf>,
    },
    /// Mutate an inline payload, file, or stdin stream directly using any registered rule.
    Mutate {
        #[arg(long, default_value = "cli-table-to-json")]
        rule: String,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = CliEngine::Deterministic)]
        engine: CliEngine,
        #[arg(long, default_value = "http://127.0.0.1:11434")]
        ollama_url: String,
        #[arg(long, default_value = "llama3.2")]
        model: String,
        #[arg(long, value_enum)]
        format: Option<CliFormat>,
        #[arg(long)]
        plugins_dir: Option<PathBuf>,
        #[arg(long)]
        pretty: bool,
    },
    /// Emit realistic legacy unstructured CLI output for instant self-contained testing.
    DemoCli {
        #[arg(long, value_enum, default_value_t = DemoVariant::Table)]
        variant: DemoVariant,
    },
    /// Validate all community JSON mutation plugin manifests in a directory.
    ValidatePlugins {
        #[arg(long, default_value = "plugins")]
        dir: PathBuf,
    },
    /// Print the read-only Linux eBPF observability tracepoint spec and wire-decoded samples.
    EbpfSpec {
        #[arg(long)]
        decode_sample: bool,
    },
    /// Print version, build architecture, and safety boundaries.
    Version,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli).await {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("morph-os error: {msg}");
            ExitCode::from(1)
        }
    }
}

fn build_pipeline(
    plugins_dir: Option<&PathBuf>,
    engine: EnginePreference,
    ollama_url: &str,
    model: &str,
    timeout_ms: u64,
) -> Result<MutationPipeline, String> {
    let ollama = if matches!(
        engine,
        EnginePreference::OllamaWithFallback | EnginePreference::OllamaStrict
    ) {
        Some(
            OllamaClient::new(ollama_url, model, timeout_ms.min(8_000))
                .map_err(|e| e.to_string())?,
        )
    } else {
        None
    };

    let circuit = CircuitBreaker::new(3, 15_000);
    MutationPipeline::with_plugins_dir(plugins_dir.map(|p| p.as_path()), ollama, circuit)
        .map_err(|e| e.to_string())
}

async fn execute(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Commands::Run {
            rule,
            engine,
            ollama_url,
            model,
            format,
            timeout_ms,
            plugins_dir,
            compact,
            stats,
            cmd,
        } => {
            let eng: EnginePreference = engine.into();
            let pipeline =
                build_pipeline(plugins_dir.as_ref(), eng, &ollama_url, &model, timeout_ms)?;
            let program = &cmd[0];
            let args = &cmd[1..];

            let opts = StdioOptions {
                rule_id: rule,
                timeout_ms,
                max_output_bytes: 8 * 1024 * 1024,
                engine: eng,
                output_format: format.map(Into::into),
                fail_policy: None,
                pretty: !compact,
                include_stderr_in_input: false,
            };

            let res = run_mutated_command(&pipeline, program, args, opts)
                .await
                .map_err(|e| e.to_string())?;

            println!("{}", res.mutation.output);
            if stats {
                eprintln!(
                    "[morph-os] rule={} engine={} latency_ms={:.2} in_bytes={} out_bytes={} exit_code={} circuit={}",
                    res.mutation.rule_id,
                    res.mutation.engine_used,
                    res.mutation.latency_ms,
                    res.mutation.input_bytes,
                    res.mutation.output_bytes,
                    res.exit_code,
                    res.mutation.circuit_state.as_str()
                );
            }
            if res.exit_code == 0 {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(res.exit_code.clamp(1, 255) as u8))
            }
        }

        Commands::Proxy {
            listen,
            upstream,
            rule,
            engine,
            ollama_url,
            model,
            format,
            timeout_ms,
            plugins_dir,
        } => {
            let eng: EnginePreference = engine.into();
            let pipeline =
                build_pipeline(plugins_dir.as_ref(), eng, &ollama_url, &model, timeout_ms)?;
            let listen_addr: SocketAddr = listen
                .parse()
                .map_err(|e| format!("invalid --listen address '{listen}': {e}"))?;

            let cfg = ProxyConfig {
                listen_addr,
                upstream_url: upstream.clone(),
                default_rule_id: rule.clone(),
                engine: eng,
                output_format: format.map(Into::into),
                upstream_timeout_ms: timeout_ms,
                max_body_bytes: 8 * 1024 * 1024,
                allow_non_loopback_bind: false,
            };

            eprintln!(
                "morph-os proxy v{MORPH_OS_VERSION} listening on http://{listen_addr} -> {upstream} (rule={rule})"
            );
            eprintln!("control panel api: http://{listen_addr}/_morph/health");
            serve_proxy(pipeline, cfg)
                .await
                .map_err(|e| e.to_string())?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Mutate {
            rule,
            input,
            file,
            engine,
            ollama_url,
            model,
            format,
            plugins_dir,
            pretty,
        } => {
            let eng: EnginePreference = engine.into();
            let pipeline =
                build_pipeline(plugins_dir.as_ref(), eng, &ollama_url, &model, 10_000)?;

            let payload = if let Some(inline) = input {
                inline
            } else if let Some(path) = file {
                fs::read_to_string(&path)
                    .map_err(|e| format!("failed to read '{}': {e}", path.display()))?
            } else {
                let mut buf = String::new();
                io::stdin()
                    .read_to_string(&mut buf)
                    .map_err(|e| format!("failed to read stdin: {e}"))?;
                buf
            };

            let res = pipeline
                .mutate(MutationRequest {
                    rule_id: rule,
                    input: payload,
                    engine: eng,
                    output_format: format.map(Into::into),
                    fail_policy: None,
                    pretty,
                    source: "cli:mutate".to_string(),
                })
                .await
                .map_err(|e| e.to_string())?;

            println!("{}", res.output);
            Ok(ExitCode::SUCCESS)
        }

        Commands::DemoCli { variant } => {
            match variant {
                DemoVariant::Table => {
                    println!("PID     SERVICE            STATE     MEM_MB   UPTIME_S   RESTARTS");
                    println!("------------------------------------------------------------------");
                    println!("1042    auth-gateway       RUNNING   128.4    86420      0");
                    println!("1188    ledger-worker      DEGRADED  512.0    14210      3");
                    println!("1204    legacy-cron        RUNNING   44.2     604800     0");
                    println!("1319    report-exporter    STOPPED   0.0      0          1");
                }
                DemoVariant::Kv => {
                    println!("[service]");
                    println!("name = legacy-billing-daemon");
                    println!("version = 2.4.1");
                    println!("healthy = true");
                    println!("active_connections = 148");
                    println!("[memory]");
                    println!("rss_mb = 312.75");
                    println!("heap_limit_mb = 1024");
                }
                DemoVariant::Xml => {
                    println!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                    println!("<OrderResponse status=\"CONFIRMED\" region=\"us-east-1\">");
                    println!("  <OrderId>ORD-90421</OrderId>");
                    println!("  <TotalAmount>249.50</TotalAmount>");
                    println!("  <Expedited>true</Expedited>");
                    println!("  <Item sku=\"SKU-101\"><Qty>2</Qty><Price>99.75</Price></Item>");
                    println!("  <Item sku=\"SKU-204\"><Qty>1</Qty><Price>50.00</Price></Item>");
                    println!("</OrderResponse>");
                }
                DemoVariant::Pii => {
                    println!("2026-11-25T14:02:11Z INFO auth_worker user=ops.admin@example.org ip=10.42.8.19 ssn=123-45-6789 phone=415-555-0199 auth=\"Bearer morph_demo_token_998877665544\"");
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::ValidatePlugins { dir } => {
            let loaded = load_plugins_from_dir(&dir).map_err(|e| e.to_string())?;
            if loaded.is_empty() {
                return Err(format!("no plugin manifests found in '{}'", dir.display()));
            }
            for spec in &loaded {
                println!(
                    "PASS  {:<32} v{:<8} target={:?} rules={}",
                    spec.id,
                    spec.version,
                    spec.target_kind,
                    spec.rules.len()
                );
            }
            println!("Summary: {}/{} PASS", loaded.len(), loaded.len());
            Ok(ExitCode::SUCCESS)
        }

        Commands::EbpfSpec { decode_sample } => {
            let payload = if decode_sample {
                serde_json::json!({
                    "spec": EbpfObserverSpec::default_spec(),
                    "sample_events": sample_decoded_events()
                })
            } else {
                serde_json::json!({
                    "spec": EbpfObserverSpec::default_spec()
                })
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }

        Commands::Version => {
            println!("morph-os {MORPH_OS_VERSION}");
            println!("arch: {}-{}", std::env::consts::ARCH, std::env::consts::OS);
            println!("engines: stdio-interceptor, loopback-http-proxy, ebpf-read-only-decoder, wasm-dom-mutator, local-ollama");
            println!("safety: strict user-space boundaries, loopback-only LLM, fail-open circuit breaker");
            Ok(ExitCode::SUCCESS)
        }
    }
}
