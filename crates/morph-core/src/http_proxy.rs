use crate::ebpf_observer::{sample_decoded_events, EbpfObserverSpec};
use crate::error::MorphError;
use crate::ollama::{send_http1_request, ParsedUrl};
use crate::pipeline::{
    EnginePreference, MutationPipeline, MutationRequest,
};
use crate::plugins::OutputFormat;
use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::{AllowOrigin, CorsLayer};

const DEFAULT_MAX_PROXY_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Configuration for the explicit loopback HTTP/API reverse-proxy mutator.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub upstream_url: String,
    pub default_rule_id: String,
    pub engine: EnginePreference,
    pub output_format: Option<OutputFormat>,
    pub upstream_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub allow_non_loopback_bind: bool,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<ParsedUrl, MorphError> {
        if !self.allow_non_loopback_bind && !self.listen_addr.ip().is_loopback() {
            return Err(MorphError::NonLoopbackEndpoint(self.listen_addr.to_string()));
        }
        ParsedUrl::parse_http(&self.upstream_url)
    }
}

/// Shared state mounted into the Axum 0.8 reverse proxy and Control Panel API.
pub struct ProxyState {
    pub pipeline: MutationPipeline,
    pub upstream: ParsedUrl,
    pub upstream_url: String,
    pub default_rule_id: String,
    pub default_engine: EnginePreference,
    pub default_output_format: Option<OutputFormat>,
    pub upstream_timeout_ms: u64,
    pub max_body_bytes: usize,
    pub started_at: Instant,
}

impl ProxyState {
    pub fn new(pipeline: MutationPipeline, config: &ProxyConfig) -> Result<Self, MorphError> {
        let upstream = config.validate()?;
        Ok(Self {
            pipeline,
            upstream,
            upstream_url: config.upstream_url.clone(),
            default_rule_id: config.default_rule_id.clone(),
            default_engine: config.engine,
            default_output_format: config.output_format,
            upstream_timeout_ms: config.upstream_timeout_ms.max(100),
            max_body_bytes: config.max_body_bytes.max(1024),
            started_at: Instant::now(),
        })
    }
}

/// Request payload for `POST /_morph/mutate`.
#[derive(Debug, Deserialize)]
pub struct ApiMutatePayload {
    pub rule_id: String,
    pub input: String,
    #[serde(default)]
    pub engine: EnginePreference,
    #[serde(default)]
    pub output_format: Option<OutputFormat>,
    #[serde(default = "default_pretty_true")]
    pub pretty: bool,
}

fn default_pretty_true() -> bool {
    true
}

/// Health payload for `GET /_morph/health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub upstream_url: String,
    pub default_rule_id: String,
    pub plugin_count: usize,
    pub circuit_state: String,
}

/// Strictly validates that a CORS `Origin` header belongs to a local loopback or Tauri desktop origin.
pub fn is_allowed_local_origin(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if rest.is_empty() || rest.contains('/') || rest.contains('@') || rest.contains('?') {
        return false;
    }
    match scheme {
        "tauri" => rest == "localhost",
        "http" | "https" => {
            let (host, port_opt) = if let Some(after_bracket) = rest.strip_prefix('[') {
                let Some((ipv6, tail)) = after_bracket.split_once(']') else {
                    return false;
                };
                if tail.is_empty() {
                    (ipv6, None)
                } else if let Some(p) = tail.strip_prefix(':') {
                    (ipv6, Some(p))
                } else {
                    return false;
                }
            } else if let Some((h, p)) = rest.split_once(':') {
                (h, Some(p))
            } else {
                (rest, None)
            };
            if let Some(p) = port_opt {
                if p.is_empty() || p.parse::<u16>().is_err() {
                    return false;
                }
            }
            matches!(host, "127.0.0.1" | "localhost" | "::1" | "tauri.localhost")
        }
        _ => false,
    }
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    res
}

/// Builds the complete Axum 0.8 router containing Control Panel API endpoints under `/_morph/*`
/// and the fallback transparent reverse-proxy mutator for all upstream routes.
pub fn build_proxy_router(state: Arc<ProxyState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            origin.to_str().is_ok_and(is_allowed_local_origin)
        }))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT, header::AUTHORIZATION]);

    Router::new()
        .route("/_morph/health", get(handle_health))
        .route("/_morph/events", get(handle_events))
        .route("/_morph/mutate", post(handle_direct_mutate))
        .route("/_morph/plugins", get(handle_plugins))
        .route("/_morph/circuit", get(handle_circuit))
        .route("/_morph/circuit/reset", post(handle_circuit_reset))
        .route("/_morph/ebpf/spec", get(handle_ebpf_spec))
        .fallback(handle_proxy_forward)
        .layer(DefaultBodyLimit::max(DEFAULT_MAX_PROXY_BODY_BYTES))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(cors)
        .with_state(state)
}

/// Starts the Axum 0.8 + Tokio HTTP reverse-proxy mutator until a shutdown signal arrives.
pub async fn serve_proxy(
    pipeline: MutationPipeline,
    config: ProxyConfig,
) -> Result<(), MorphError> {
    let state = Arc::new(ProxyState::new(pipeline, &config)?);
    let app = build_proxy_router(state);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| MorphError::IoError(format!("proxy server error: {e}")))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn handle_health(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let resp = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        upstream_url: state.upstream_url.clone(),
        default_rule_id: state.default_rule_id.clone(),
        plugin_count: state.pipeline.list_plugins().len(),
        circuit_state: state.pipeline.circuit().status().state.as_str().to_string(),
    };
    Json(resp)
}

async fn handle_events(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    Json(json!({
        "events": state.pipeline.recent_events(100)
    }))
}

async fn handle_plugins(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    Json(json!({
        "plugins": state.pipeline.list_plugins()
    }))
}

async fn handle_circuit(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    Json(state.pipeline.circuit().status())
}

async fn handle_circuit_reset(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    state.pipeline.circuit().reset();
    Json(state.pipeline.circuit().status())
}

async fn handle_ebpf_spec() -> impl IntoResponse {
    Json(json!({
        "spec": EbpfObserverSpec::default_spec(),
        "sample_events": sample_decoded_events()
    }))
}

async fn handle_direct_mutate(
    State(state): State<Arc<ProxyState>>,
    Json(payload): Json<ApiMutatePayload>,
) -> Response {
    let req = MutationRequest {
        rule_id: payload.rule_id,
        input: payload.input,
        engine: payload.engine,
        output_format: payload.output_format,
        fail_policy: None,
        pretty: payload.pretty,
        source: "control-panel".to_string(),
    };

    match state.pipeline.mutate(req).await {
        Ok(res) => (StatusCode::OK, Json(res)).into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": err.error_code(),
                "message": err.to_string()
            })),
        )
            .into_response(),
    }
}

async fn handle_proxy_forward(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    let method = req.method().as_str().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let rule_override = req
        .headers()
        .get("x-morph-rule")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let rule_id = rule_override.unwrap_or_else(|| state.default_rule_id.clone());

    let engine = match req
        .headers()
        .get("x-morph-engine")
        .and_then(|v| v.to_str().ok())
    {
        Some("ollama") | Some("ollama-with-fallback") => EnginePreference::OllamaWithFallback,
        Some("ollama-strict") => EnginePreference::OllamaStrict,
        Some("deterministic") => EnginePreference::Deterministic,
        _ => state.default_engine,
    };

    let mut forward_headers: Vec<(String, String)> = Vec::new();
    for (k, v) in req.headers() {
        let name = k.as_str();
        if name.eq_ignore_ascii_case("x-morph-rule")
            || name.eq_ignore_ascii_case("x-morph-engine")
        {
            continue;
        }
        if let Ok(val) = v.to_str() {
            forward_headers.push((name.to_string(), val.to_string()));
        }
    }

    let max_body = state.max_body_bytes.max(DEFAULT_MAX_PROXY_BODY_BYTES.min(state.max_body_bytes));
    let body_bytes = match to_bytes(req.into_body(), max_body).await {
        Ok(b) => b.to_vec(),
        Err(e) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({
                    "error": "request_body_too_large",
                    "message": e.to_string()
                })),
            )
                .into_response();
        }
    };

    let upstream_resp = match send_http1_request(
        &state.upstream,
        &method,
        &path_and_query,
        &forward_headers,
        &body_bytes,
        state.upstream_timeout_ms,
        state.max_body_bytes,
    )
    .await
    {
        Ok(r) => r,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": err.error_code(),
                    "message": err.to_string(),
                    "upstream": state.upstream_url
                })),
            )
                .into_response();
        }
    };

    let upstream_body_text = String::from_utf8_lossy(&upstream_resp.body).to_string();
    let mutation = match state
        .pipeline
        .mutate(MutationRequest {
            rule_id: rule_id.clone(),
            input: upstream_body_text,
            engine,
            output_format: state.default_output_format,
            fail_policy: None,
            pretty: false,
            source: format!("proxy:{method} {path_and_query}"),
        })
        .await
    {
        Ok(m) => m,
        Err(err) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": err.error_code(),
                    "message": err.to_string()
                })),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status).unwrap_or(StatusCode::OK);
    let mut out_headers = HeaderMap::new();

    for (k, v) in &upstream_resp.headers {
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("content-type")
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            out_headers.append(hn, hv);
        }
    }

    let content_type = if mutation.mutated {
        match mutation.output_format {
            OutputFormat::Json => "application/json; charset=utf-8",
            OutputFormat::Ndjson => "application/x-ndjson; charset=utf-8",
            OutputFormat::Csv => "text/csv; charset=utf-8",
            OutputFormat::Text => "text/plain; charset=utf-8",
        }
    } else {
        upstream_resp
            .header("content-type")
            .unwrap_or("application/octet-stream")
    };

    insert_header(&mut out_headers, "content-type", content_type);
    insert_header(
        &mut out_headers,
        "content-length",
        &mutation.output.len().to_string(),
    );
    insert_header(
        &mut out_headers,
        "x-morph-mutated",
        if mutation.mutated { "true" } else { "false" },
    );
    insert_header(&mut out_headers, "x-morph-rule", &mutation.rule_id);
    insert_header(
        &mut out_headers,
        "x-morph-latency-ms",
        &format!("{:.2}", mutation.latency_ms),
    );
    insert_header(&mut out_headers, "x-morph-engine", &mutation.engine_used);
    insert_header(
        &mut out_headers,
        "x-morph-circuit",
        mutation.circuit_state.as_str(),
    );

    let mut response = Response::new(Body::from(mutation.output));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    response
}

fn insert_header(map: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(hv) = HeaderValue::from_str(value) {
        map.insert(HeaderName::from_static(name), hv);
    }
}
