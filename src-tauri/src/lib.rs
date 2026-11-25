use morph_core::ebpf_observer::{sample_decoded_events, EbpfObserveEvent, EbpfObserverSpec};
use morph_core::ollama::OllamaClient;
use morph_core::pipeline::{
    CircuitBreaker, CircuitStatus, EnginePreference, MutationPipeline, MutationRequest,
    MutationResult,
};
use morph_core::plugins::{OutputFormat, PluginSpec};
use morph_core::stdio_interceptor::{run_mutated_command, StdioExecutionResult, StdioOptions};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::State;

pub struct DesktopState {
    pub pipeline: MutationPipeline,
}

impl DesktopState {
    pub fn initialize() -> Self {
        let ollama = OllamaClient::new("http://127.0.0.1:11434", "llama3.2", 4000).ok();
        let circuit = CircuitBreaker::new(3, 15_000);
        let plugins_dir = PathBuf::from("../plugins");
        let pipeline = MutationPipeline::with_plugins_dir(
            plugins_dir.exists().then_some(plugins_dir.as_path()),
            ollama,
            circuit.clone(),
        )
        .unwrap_or_else(|_| MutationPipeline::new(None, circuit));
        Self { pipeline }
    }
}

#[derive(Debug, Deserialize)]
pub struct MutatePayloadArgs {
    pub rule_id: String,
    pub input: String,
    #[serde(default)]
    pub engine: EnginePreference,
    #[serde(default)]
    pub output_format: Option<OutputFormat>,
    #[serde(default = "default_pretty")]
    pub pretty: bool,
}

fn default_pretty() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct RunCliMutationArgs {
    pub rule_id: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub engine: EnginePreference,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Serialize)]
pub struct EbpfInspectionPayload {
    pub spec: EbpfObserverSpec,
    pub sample_events: Vec<EbpfObserveEvent>,
}

#[tauri::command]
pub async fn mutate_payload(
    state: State<'_, DesktopState>,
    payload: MutatePayloadArgs,
) -> Result<MutationResult, String> {
    state
        .pipeline
        .mutate(MutationRequest {
            rule_id: payload.rule_id,
            input: payload.input,
            engine: payload.engine,
            output_format: payload.output_format,
            fail_policy: None,
            pretty: payload.pretty,
            source: "tauri-ipc".to_string(),
        })
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn run_cli_mutation(
    state: State<'_, DesktopState>,
    payload: RunCliMutationArgs,
) -> Result<StdioExecutionResult, String> {
    run_mutated_command(
        &state.pipeline,
        &payload.program,
        &payload.args,
        StdioOptions {
            rule_id: payload.rule_id,
            timeout_ms: payload.timeout_ms,
            engine: payload.engine,
            ..StdioOptions::default()
        },
    )
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_plugins(state: State<'_, DesktopState>) -> Vec<PluginSpec> {
    state.pipeline.list_plugins()
}

#[tauri::command]
pub fn get_circuit_status(state: State<'_, DesktopState>) -> CircuitStatus {
    state.pipeline.circuit().status()
}

#[tauri::command]
pub fn inspect_ebpf_spec() -> EbpfInspectionPayload {
    EbpfInspectionPayload {
        spec: EbpfObserverSpec::default_spec(),
        sample_events: sample_decoded_events(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(DesktopState::initialize())
        .invoke_handler(tauri::generate_handler![
            mutate_payload,
            run_cli_mutation,
            list_plugins,
            get_circuit_status,
            inspect_ebpf_spec
        ])
        .run(tauri::generate_context!())
        .expect("error while running morph-os desktop application");
}
