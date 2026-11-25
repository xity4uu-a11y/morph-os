//! `morph-core`: Pure-Rust runtime stream, loopback HTTP reverse-proxy, and read-only eBPF
//! observability engine for `morph-os`.

pub mod ebpf_observer;
pub mod error;
pub mod http_proxy;
pub mod ollama;
pub mod pipeline;
pub mod plugins;
pub mod stdio_interceptor;

pub use error::{FailPolicy, MorphError};
pub use pipeline::{
    CircuitBreaker, CircuitState, CircuitStatus, EnginePreference, MutationPipeline,
    MutationRequest, MutationResult, MutationTelemetryEvent,
};
pub use plugins::{OutputFormat, PluginSpec, RuleStep, TargetKind};

/// Crate version string.
pub const MORPH_OS_VERSION: &str = env!("CARGO_PKG_VERSION");
