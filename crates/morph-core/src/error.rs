use serde::{Deserialize, Serialize};
use std::fmt;

/// Governs how the mutation pipeline responds when an engine fails or times out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FailPolicy {
    /// Never drop traffic or crash the host stream; fall back to deterministic or pass-through.
    #[default]
    FailOpen,
    /// Abort and surface the typed error to the caller when mutation cannot complete cleanly.
    FailClosed,
}

/// Typed error surface for morph-os runtime mutation engines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum MorphError {
    InvalidRule(String),
    InvalidInput(String),
    Timeout { operation: String, timeout_ms: u64 },
    BufferLimitExceeded { limit_bytes: usize, observed_bytes: usize },
    UpstreamError(String),
    NonLoopbackEndpoint(String),
    OllamaUnavailable(String),
    CircuitOpen { retry_after_ms: u64, last_error: String },
    ProcessSpawnFailed(String),
    PluginValidationFailed { plugin_id: String, reason: String },
    EbpfFrameMalformed(String),
    PanicRecovered(String),
    IoError(String),
    SerializationError(String),
}

impl MorphError {
    /// Returns a stable machine-readable error classification string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRule(_) => "invalid_rule",
            Self::InvalidInput(_) => "invalid_input",
            Self::Timeout { .. } => "timeout",
            Self::BufferLimitExceeded { .. } => "buffer_limit_exceeded",
            Self::UpstreamError(_) => "upstream_error",
            Self::NonLoopbackEndpoint(_) => "non_loopback_endpoint",
            Self::OllamaUnavailable(_) => "ollama_unavailable",
            Self::CircuitOpen { .. } => "circuit_open",
            Self::ProcessSpawnFailed(_) => "process_spawn_failed",
            Self::PluginValidationFailed { .. } => "plugin_validation_failed",
            Self::EbpfFrameMalformed(_) => "ebpf_frame_malformed",
            Self::PanicRecovered(_) => "panic_recovered",
            Self::IoError(_) => "io_error",
            Self::SerializationError(_) => "serialization_error",
        }
    }

    /// Indicates whether a fail-open pipeline can safely degrade without failing the host stream.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. }
                | Self::OllamaUnavailable(_)
                | Self::CircuitOpen { .. }
                | Self::InvalidInput(_)
                | Self::PanicRecovered(_)
                | Self::SerializationError(_)
        )
    }
}

impl fmt::Display for MorphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRule(msg) => write!(f, "invalid mutation rule: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input payload: {msg}"),
            Self::Timeout {
                operation,
                timeout_ms,
            } => write!(f, "{operation} timed out after {timeout_ms}ms"),
            Self::BufferLimitExceeded {
                limit_bytes,
                observed_bytes,
            } => write!(
                f,
                "stream buffer exceeded cap of {limit_bytes} bytes (observed {observed_bytes} bytes)"
            ),
            Self::UpstreamError(msg) => write!(f, "upstream request failed: {msg}"),
            Self::NonLoopbackEndpoint(ep) => write!(
                f,
                "endpoint '{ep}' rejected: local LLM endpoints must bind strictly to loopback (127.0.0.1, localhost, or [::1])"
            ),
            Self::OllamaUnavailable(msg) => write!(f, "local Ollama unavailable: {msg}"),
            Self::CircuitOpen {
                retry_after_ms,
                last_error,
            } => write!(
                f,
                "circuit breaker open (retry in {retry_after_ms}ms; last error: {last_error})"
            ),
            Self::ProcessSpawnFailed(msg) => write!(f, "failed to spawn child process: {msg}"),
            Self::PluginValidationFailed { plugin_id, reason } => {
                write!(f, "plugin '{plugin_id}' failed validation: {reason}")
            }
            Self::EbpfFrameMalformed(msg) => write!(f, "malformed eBPF ring-buffer frame: {msg}"),
            Self::PanicRecovered(msg) => write!(f, "recovered from isolated panic: {msg}"),
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
            Self::SerializationError(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for MorphError {}

impl From<std::io::Error> for MorphError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for MorphError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}
