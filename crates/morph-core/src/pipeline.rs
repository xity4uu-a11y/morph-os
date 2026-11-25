use crate::error::{FailPolicy, MorphError};
use crate::ollama::{
    ascii_table_to_json, html_table_to_json, json_to_csv, json_to_ndjson, kv_to_json, redact_pii,
    rename_json_fields, sha256_hex, xml_to_json, OllamaClient,
};
use crate::plugins::{builtin_plugins, load_plugins_from_dir, OutputFormat, PluginSpec, RuleStep};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const MAX_TELEMETRY_EVENTS: usize = 256;

/// Circuit breaker state machine for isolating flaky or offline local LLM runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half-open",
        }
    }
}

/// Serializable snapshot of circuit breaker metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStatus {
    pub state: CircuitState,
    pub consecutive_failures: u32,
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
    pub retry_after_ms: u64,
    pub total_trips: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct CircuitInner {
    state: CircuitState,
    consecutive_failures: u32,
    failure_threshold: u32,
    cooldown: Duration,
    opened_at: Option<Instant>,
    total_trips: u64,
    total_successes: u64,
    total_failures: u64,
    last_error: Option<String>,
}

/// Thread-safe circuit breaker protecting streams and reverse-proxy requests from LLM stalls.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    inner: Arc<Mutex<CircuitInner>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown_ms: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CircuitInner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                failure_threshold: failure_threshold.max(1),
                cooldown: Duration::from_millis(cooldown_ms.max(50)),
                opened_at: None,
                total_trips: 0,
                total_successes: 0,
                total_failures: 0,
                last_error: None,
            })),
        }
    }

    /// Checks whether an external/local-LLM attempt is permitted right now.
    pub fn allow_request(&self) -> Result<(), MorphError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match guard.state {
            CircuitState::Closed | CircuitState::HalfOpen => Ok(()),
            CircuitState::Open => {
                if let Some(opened) = guard.opened_at {
                    let elapsed = opened.elapsed();
                    if elapsed >= guard.cooldown {
                        guard.state = CircuitState::HalfOpen;
                        Ok(())
                    } else {
                        let remaining = guard
                            .cooldown
                            .saturating_sub(elapsed)
                            .as_millis() as u64;
                        Err(MorphError::CircuitOpen {
                            retry_after_ms: remaining,
                            last_error: guard
                                .last_error
                                .clone()
                                .unwrap_or_else(|| "prior LLM failure".into()),
                        })
                    }
                } else {
                    guard.state = CircuitState::HalfOpen;
                    Ok(())
                }
            }
        }
    }

    /// Records a healthy LLM completion and closes the breaker.
    pub fn record_success(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.state = CircuitState::Closed;
        guard.consecutive_failures = 0;
        guard.opened_at = None;
        guard.total_successes += 1;
        guard.last_error = None;
    }

    /// Records an LLM timeout/failure and trips the circuit open once threshold is reached.
    pub fn record_failure(&self, reason: impl Into<String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.consecutive_failures += 1;
        guard.total_failures += 1;
        guard.last_error = Some(reason.into());
        if guard.state == CircuitState::HalfOpen
            || guard.consecutive_failures >= guard.failure_threshold
        {
            if guard.state != CircuitState::Open {
                guard.total_trips += 1;
            }
            guard.state = CircuitState::Open;
            guard.opened_at = Some(Instant::now());
        }
    }

    /// Manually resets the circuit breaker back to `Closed`.
    pub fn reset(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.state = CircuitState::Closed;
        guard.consecutive_failures = 0;
        guard.opened_at = None;
        guard.last_error = None;
    }

    /// Returns a point-in-time metrics snapshot.
    pub fn status(&self) -> CircuitStatus {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let retry_after_ms = if guard.state == CircuitState::Open {
            guard
                .opened_at
                .map(|t| guard.cooldown.saturating_sub(t.elapsed()).as_millis() as u64)
                .unwrap_or(0)
        } else {
            0
        };
        CircuitStatus {
            state: guard.state,
            consecutive_failures: guard.consecutive_failures,
            failure_threshold: guard.failure_threshold,
            cooldown_ms: guard.cooldown.as_millis() as u64,
            retry_after_ms,
            total_trips: guard.total_trips,
            total_successes: guard.total_successes,
            total_failures: guard.total_failures,
            last_error: guard.last_error.clone(),
        }
    }
}

/// Engine selection policy for a mutation call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EnginePreference {
    /// Zero-LLM pure deterministic Rust parser/transformer (sub-millisecond).
    #[default]
    Deterministic,
    /// Attempts local Ollama first; on timeout/offline/circuit-open falls back cleanly to deterministic rules.
    OllamaWithFallback,
    /// Requires local Ollama to succeed (respects fail policy if unavailable).
    OllamaStrict,
}

/// Input specification for a single mutation invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationRequest {
    pub rule_id: String,
    pub input: String,
    #[serde(default)]
    pub engine: EnginePreference,
    #[serde(default)]
    pub output_format: Option<OutputFormat>,
    #[serde(default)]
    pub fail_policy: Option<FailPolicy>,
    #[serde(default)]
    pub pretty: bool,
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "direct".to_string()
}

/// Result returned from a completed mutation pipeline execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationResult {
    pub event_id: String,
    pub timestamp_utc: String,
    pub rule_id: String,
    pub engine_used: String,
    pub output_format: OutputFormat,
    pub mutated: bool,
    pub fallback_triggered: bool,
    pub fallback_reason: Option<String>,
    pub latency_ms: f64,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub input_sha256: String,
    pub output_sha256: String,
    pub circuit_state: CircuitState,
    pub output: String,
}

/// Compact audit event stored in the in-memory telemetry ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationTelemetryEvent {
    pub event_id: String,
    pub timestamp_utc: String,
    pub source: String,
    pub rule_id: String,
    pub engine_used: String,
    pub mutated: bool,
    pub fallback_triggered: bool,
    pub fallback_reason: Option<String>,
    pub latency_ms: f64,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub circuit_state: CircuitState,
    pub before_preview: String,
    pub after_preview: String,
}

/// Modular crash-isolated runtime mutation pipeline with circuit breaker and telemetry ring buffer.
#[derive(Clone)]
pub struct MutationPipeline {
    plugins: Arc<BTreeMap<String, PluginSpec>>,
    aliases: Arc<BTreeMap<String, String>>,
    ollama: Option<OllamaClient>,
    circuit: CircuitBreaker,
    events: Arc<Mutex<VecDeque<MutationTelemetryEvent>>>,
    seq: Arc<AtomicU64>,
}

impl MutationPipeline {
    /// Builds a pipeline loaded with all built-in plugins and optional local Ollama client.
    pub fn new(ollama: Option<OllamaClient>, circuit: CircuitBreaker) -> Self {
        Self::from_plugins(builtin_plugins(), ollama, circuit)
    }

    /// Loads plugins from a directory, merging them over built-in defaults.
    pub fn with_plugins_dir(
        dir: Option<&Path>,
        ollama: Option<OllamaClient>,
        circuit: CircuitBreaker,
    ) -> Result<Self, MorphError> {
        let mut merged: BTreeMap<String, PluginSpec> = builtin_plugins()
            .into_iter()
            .map(|p| (p.id.clone(), p))
            .collect();

        if let Some(path) = dir {
            if path.exists() {
                for spec in load_plugins_from_dir(path)? {
                    merged.insert(spec.id.clone(), spec);
                }
            }
        }

        Ok(Self::from_plugins(
            merged.into_values().collect(),
            ollama,
            circuit,
        ))
    }

    /// Builds a pipeline from an explicit list of validated plugins.
    pub fn from_plugins(
        list: Vec<PluginSpec>,
        ollama: Option<OllamaClient>,
        circuit: CircuitBreaker,
    ) -> Self {
        let mut plugins = BTreeMap::new();
        let mut aliases = BTreeMap::new();
        for spec in list {
            for alias in &spec.aliases {
                aliases.insert(alias.clone(), spec.id.clone());
            }
            plugins.insert(spec.id.clone(), spec);
        }
        Self {
            plugins: Arc::new(plugins),
            aliases: Arc::new(aliases),
            ollama,
            circuit,
            events: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_TELEMETRY_EVENTS))),
            seq: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn circuit(&self) -> &CircuitBreaker {
        &self.circuit
    }

    pub fn list_plugins(&self) -> Vec<PluginSpec> {
        self.plugins.values().cloned().collect()
    }

    pub fn resolve_plugin(&self, rule_id: &str) -> Option<&PluginSpec> {
        if let Some(p) = self.plugins.get(rule_id) {
            return Some(p);
        }
        if let Some(canonical) = self.aliases.get(rule_id) {
            return self.plugins.get(canonical);
        }
        None
    }

    pub fn recent_events(&self, limit: usize) -> Vec<MutationTelemetryEvent> {
        let guard = self.events.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().rev().take(limit.max(1)).cloned().collect()
    }

    /// Executes a mutation with strict panic isolation, local Ollama circuit breaking,
    /// and deterministic or pass-through fallback per fail policy.
    pub async fn mutate(&self, req: MutationRequest) -> Result<MutationResult, MorphError> {
        let start = Instant::now();
        let spec = self.resolve_plugin(&req.rule_id).ok_or_else(|| {
            MorphError::InvalidRule(format!(
                "unknown rule '{}'; available: {}",
                req.rule_id,
                self.plugins
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;

        let fail_policy = req.fail_policy.unwrap_or(spec.fail_policy);
        let output_format = req.output_format.unwrap_or(spec.output_format);
        let mut fallback_triggered = false;
        let mut fallback_reason: Option<String> = None;
        let mut engine_used = "deterministic".to_string();
        let mut mutated = true;

        let final_output: Result<String, MorphError> = match req.engine {
            EnginePreference::Deterministic => {
                run_deterministic_isolated(spec, &req.input, output_format, req.pretty)
            }
            EnginePreference::OllamaWithFallback | EnginePreference::OllamaStrict => {
                match self.try_ollama_mutation(spec, &req.input, output_format, req.pretty).await {
                    Ok(out) => {
                        engine_used = "ollama".to_string();
                        Ok(out)
                    }
                    Err(err) => {
                        if req.engine == EnginePreference::OllamaWithFallback {
                            fallback_triggered = true;
                            fallback_reason = Some(err.to_string());
                            engine_used = "deterministic-fallback".to_string();
                            run_deterministic_isolated(spec, &req.input, output_format, req.pretty)
                        } else {
                            Err(err)
                        }
                    }
                }
            }
        };

        let output_text = match final_output {
            Ok(text) => text,
            Err(err) => {
                if fail_policy == FailPolicy::FailOpen && err.is_recoverable() {
                    fallback_triggered = true;
                    fallback_reason = Some(err.to_string());
                    engine_used = "pass-through-fallback".to_string();
                    mutated = false;
                    req.input.clone()
                } else {
                    return Err(err);
                }
            }
        };

        let elapsed_ms = (start.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        let seq_num = self.seq.fetch_add(1, Ordering::Relaxed);
        let event_id = format!("evt-{seq_num:06}");
        let timestamp_utc = DateTime::<Utc>::from(SystemTime::now()).to_rfc3339();
        let circuit_state = self.circuit.status().state;

        let result = MutationResult {
            event_id: event_id.clone(),
            timestamp_utc: timestamp_utc.clone(),
            rule_id: spec.id.clone(),
            engine_used: engine_used.clone(),
            output_format,
            mutated,
            fallback_triggered,
            fallback_reason: fallback_reason.clone(),
            latency_ms: elapsed_ms,
            input_bytes: req.input.len(),
            output_bytes: output_text.len(),
            input_sha256: sha256_hex(req.input.as_bytes()),
            output_sha256: sha256_hex(output_text.as_bytes()),
            circuit_state,
            output: output_text.clone(),
        };

        self.push_event(MutationTelemetryEvent {
            event_id,
            timestamp_utc,
            source: req.source,
            rule_id: spec.id.clone(),
            engine_used,
            mutated,
            fallback_triggered,
            fallback_reason,
            latency_ms: elapsed_ms,
            input_bytes: req.input.len(),
            output_bytes: output_text.len(),
            circuit_state,
            before_preview: truncate_preview(&req.input, 220),
            after_preview: truncate_preview(&output_text, 220),
        });

        Ok(result)
    }

    async fn try_ollama_mutation(
        &self,
        spec: &PluginSpec,
        input: &str,
        output_format: OutputFormat,
        pretty: bool,
    ) -> Result<String, MorphError> {
        let client = self.ollama.as_ref().ok_or_else(|| {
            MorphError::OllamaUnavailable("no local Ollama client configured".into())
        })?;

        self.circuit.allow_request()?;
        let expect_json = matches!(
            output_format,
            OutputFormat::Json | OutputFormat::Ndjson | OutputFormat::Csv
        );

        match client.chat(&spec.llm_prompt, input, expect_json).await {
            Ok(raw) => {
                self.circuit.record_success();
                if expect_json {
                    let parsed: Value = serde_json::from_str(&raw)?;
                    format_value(&parsed, output_format, pretty)
                } else {
                    Ok(raw)
                }
            }
            Err(err) => {
                self.circuit.record_failure(err.to_string());
                Err(err)
            }
        }
    }

    fn push_event(&self, event: MutationTelemetryEvent) {
        let mut guard = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= MAX_TELEMETRY_EVENTS {
            guard.pop_front();
        }
        guard.push_back(event);
    }
}

fn run_deterministic_isolated(
    spec: &PluginSpec,
    input: &str,
    output_format: OutputFormat,
    pretty: bool,
) -> Result<String, MorphError> {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        execute_rule_chain(&spec.rules, input, output_format, pretty)
    }));

    match outcome {
        Ok(res) => res,
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic in mutation rule".into());
            Err(MorphError::PanicRecovered(msg))
        }
    }
}

fn execute_rule_chain(
    steps: &[RuleStep],
    input: &str,
    output_format: OutputFormat,
    pretty: bool,
) -> Result<String, MorphError> {
    let mut current_text = input.to_string();
    let mut current_val: Option<Value> = None;

    for step in steps {
        match step {
            RuleStep::AsciiTableToJson => {
                let parsed = ascii_table_to_json(&current_text)?;
                current_val = Some(parsed);
            }
            RuleStep::KvToJson => {
                let parsed = kv_to_json(&current_text)?;
                current_val = Some(parsed);
            }
            RuleStep::XmlToJson => {
                let parsed = xml_to_json(&current_text)?;
                current_val = Some(parsed);
            }
            RuleStep::HtmlTableToJson => {
                let parsed = html_table_to_json(&current_text)?;
                current_val = Some(parsed);
            }
            RuleStep::ParseJson => {
                let parsed: Value = serde_json::from_str(&current_text).map_err(|e| {
                    MorphError::InvalidInput(format!("expected valid JSON input: {e}"))
                })?;
                current_val = Some(parsed);
            }
            RuleStep::RenameFields {
                mappings,
                case_style,
                drop_fields,
                add_fields,
            } => {
                let base = match current_val.take() {
                    Some(v) => v,
                    None => serde_json::from_str(&current_text).map_err(|e| {
                        MorphError::InvalidInput(format!(
                            "rename_fields requires JSON input or prior parser step: {e}"
                        ))
                    })?,
                };
                current_val = Some(rename_json_fields(
                    &base,
                    mappings,
                    *case_style,
                    drop_fields,
                    add_fields,
                ));
            }
            RuleStep::RedactPii {
                include_report_envelope,
            } => {
                let target_str = match &current_val {
                    Some(v) => serde_json::to_string(v)?,
                    None => current_text.clone(),
                };
                let (scrubbed, report) = redact_pii(&target_str);
                current_text = scrubbed.clone();
                if *include_report_envelope {
                    let mut env = Map::new();
                    env.insert("scrubbed".into(), Value::String(scrubbed));
                    env.insert("redacted_total".into(), Value::from(report.total() as u64));
                    env.insert("report".into(), serde_json::to_value(report)?);
                    current_val = Some(Value::Object(env));
                } else if let Ok(v) = serde_json::from_str::<Value>(&scrubbed) {
                    current_val = Some(v);
                } else {
                    current_val = Some(Value::String(scrubbed));
                }
            }
            RuleStep::WrapEnvelope {
                schema_version,
                data_key,
            } => {
                let inner = current_val
                    .take()
                    .unwrap_or_else(|| Value::String(current_text.clone()));
                let mut env = Map::new();
                env.insert("schema_version".into(), Value::String(schema_version.clone()));
                env.insert("mutated_by".into(), Value::String("morph-os".into()));
                env.insert(data_key.clone(), inner);
                current_val = Some(Value::Object(env));
            }
        }
    }

    match current_val {
        Some(val) => format_value(&val, output_format, pretty),
        None => Ok(current_text),
    }
}

fn format_value(value: &Value, format: OutputFormat, pretty: bool) -> Result<String, MorphError> {
    match format {
        OutputFormat::Json => {
            if pretty {
                Ok(serde_json::to_string_pretty(value)?)
            } else {
                Ok(serde_json::to_string(value)?)
            }
        }
        OutputFormat::Ndjson => json_to_ndjson(value),
        OutputFormat::Csv => json_to_csv(value),
        OutputFormat::Text => match value {
            Value::String(s) => Ok(s.clone()),
            other => Ok(serde_json::to_string_pretty(other)?),
        },
    }
}

fn truncate_preview(text: &str, max_chars: usize) -> String {
    let clean: String = text.chars().take(max_chars).collect();
    if text.chars().count() > max_chars {
        format!("{clean}...")
    } else {
        clean
    }
}
