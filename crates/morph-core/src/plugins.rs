use crate::error::{FailPolicy, MorphError};
use crate::ollama::CaseStyle;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Execution surface targeted by a mutation plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    CliStdio,
    HttpProxy,
    DomWasm,
    StreamGeneric,
}

/// Output wire format requested from the mutation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    #[default]
    Json,
    Ndjson,
    Csv,
    Text,
}

/// A deterministic transformation step executed inside a plugin rule chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuleStep {
    AsciiTableToJson,
    KvToJson,
    XmlToJson,
    HtmlTableToJson,
    ParseJson,
    RenameFields {
        #[serde(default)]
        mappings: BTreeMap<String, String>,
        #[serde(default)]
        case_style: Option<CaseStyle>,
        #[serde(default)]
        drop_fields: Vec<String>,
        #[serde(default)]
        add_fields: BTreeMap<String, Value>,
    },
    RedactPii {
        #[serde(default)]
        include_report_envelope: bool,
    },
    WrapEnvelope {
        schema_version: String,
        #[serde(default = "default_data_key")]
        data_key: String,
    },
}

fn default_data_key() -> String {
    "data".to_string()
}

/// Declarative mutation plugin manifest (mirrors `plugins/schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSpec {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub name: String,
    pub version: String,
    pub target_kind: TargetKind,
    pub description: String,
    pub author: String,
    #[serde(default)]
    pub fail_policy: FailPolicy,
    #[serde(default)]
    pub output_format: OutputFormat,
    pub rules: Vec<RuleStep>,
    pub llm_prompt: String,
    pub rust_hook_template: String,
    #[serde(default)]
    pub sample_input: String,
}

/// Validates a single plugin manifest against morph-os structural & safety invariants.
pub fn validate_plugin(spec: &PluginSpec) -> Result<(), MorphError> {
    if spec.id.is_empty()
        || !spec
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || spec.id.starts_with('-')
        || spec.id.ends_with('-')
    {
        return Err(MorphError::PluginValidationFailed {
            plugin_id: spec.id.clone(),
            reason: "plugin id must be non-empty kebab-case ASCII (a-z, 0-9, '-')".into(),
        });
    }

    if !is_valid_semver(&spec.version) {
        return Err(MorphError::PluginValidationFailed {
            plugin_id: spec.id.clone(),
            reason: format!("version '{}' is not valid semver (MAJOR.MINOR.PATCH)", spec.version),
        });
    }

    if spec.name.trim().is_empty() || spec.description.trim().is_empty() || spec.author.trim().is_empty() {
        return Err(MorphError::PluginValidationFailed {
            plugin_id: spec.id.clone(),
            reason: "name, description, and author must be non-empty".into(),
        });
    }

    if spec.rules.is_empty() {
        return Err(MorphError::PluginValidationFailed {
            plugin_id: spec.id.clone(),
            reason: "plugin must define at least one deterministic rule step".into(),
        });
    }

    if spec.llm_prompt.trim().is_empty() || spec.llm_prompt.len() > 8192 {
        return Err(MorphError::PluginValidationFailed {
            plugin_id: spec.id.clone(),
            reason: "llm_prompt must be between 1 and 8192 bytes".into(),
        });
    }

    if spec.rust_hook_template.trim().is_empty() {
        return Err(MorphError::PluginValidationFailed {
            plugin_id: spec.id.clone(),
            reason: "rust_hook_template must be non-empty".into(),
        });
    }

    for alias in &spec.aliases {
        if alias.is_empty()
            || !alias
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(MorphError::PluginValidationFailed {
                plugin_id: spec.id.clone(),
                reason: format!("invalid alias '{alias}': must be kebab-case ASCII"),
            });
        }
    }

    Ok(())
}

fn is_valid_semver(version: &str) -> bool {
    let core = version.split('-').next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Loads and validates all `*.json` plugin manifests from a directory (skipping `schema.json`).
pub fn load_plugins_from_dir(dir: &Path) -> Result<Vec<PluginSpec>, MorphError> {
    if !dir.exists() {
        return Err(MorphError::IoError(format!(
            "plugins directory '{}' does not exist",
            dir.display()
        )));
    }

    let mut paths: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|e| e.to_str()) == Some("json")
                && path.file_name().and_then(|n| n.to_str()) != Some("schema.json")
        })
        .collect();
    paths.sort();

    let mut plugins = Vec::with_capacity(paths.len());
    for path in paths {
        let raw = fs::read_to_string(&path)?;
        let spec: PluginSpec = serde_json::from_str(&raw).map_err(|e| {
            MorphError::PluginValidationFailed {
                plugin_id: path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                reason: format!("invalid JSON manifest: {e}"),
            }
        })?;
        validate_plugin(&spec)?;
        plugins.push(spec);
    }

    Ok(plugins)
}

/// Returns built-in validated mutation plugins so the standalone single binary works anywhere offline.
pub fn builtin_plugins() -> Vec<PluginSpec> {
    let mut v1_map = BTreeMap::new();
    v1_map.insert("usr_id".into(), "userId".into());
    v1_map.insert("usr_name".into(), "displayName".into());
    v1_map.insert("acct_bal_cents".into(), "balanceCents".into());
    v1_map.insert("created_dt".into(), "createdAt".into());
    v1_map.insert("is_actv".into(), "isActive".into());

    let mut v2_meta = BTreeMap::new();
    v2_meta.insert("apiVersion".into(), Value::String("v2".into()));

    vec![
        PluginSpec {
            id: "cli-table-to-json".into(),
            aliases: vec!["cli-to-json".into(), "ascii-table".into()],
            name: "Legacy CLI ASCII Table to JSON".into(),
            version: "1.0.0".into(),
            target_kind: TargetKind::CliStdio,
            description: "Parses legacy fixed-width, bordered, or pipe-delimited CLI stdout tables into strict typed JSON records.".into(),
            author: "morph-os-core".into(),
            fail_policy: FailPolicy::FailOpen,
            output_format: OutputFormat::Json,
            rules: vec![RuleStep::AsciiTableToJson],
            llm_prompt: "Convert the legacy CLI stdout table into a strict JSON array of objects using snake_case keys and inferred numeric/boolean types. Output ONLY valid JSON.".into(),
            rust_hook_template: "pub fn mutate_cli_stream(raw: &str) -> Result<serde_json::Value, morph_core::MorphError> {\n    morph_core::ollama::ascii_table_to_json(raw)\n}".into(),
            sample_input: "PID     SERVICE            STATE     MEM_MB   UPTIME_S   RESTARTS\n------------------------------------------------------------------\n1042    auth-gateway       RUNNING   128.4    86420      0\n1188    ledger-worker      DEGRADED  512.0    14210      3\n1204    legacy-cron        RUNNING   44.2     604800     0\n1319    report-exporter    STOPPED   0.0      0          1".into(),
        },
        PluginSpec {
            id: "legacy-xml-to-rest-json".into(),
            aliases: vec!["xml-to-json".into(), "soap-to-json".into()],
            name: "Legacy XML / SOAP Payload to REST JSON".into(),
            version: "1.0.0".into(),
            target_kind: TargetKind::HttpProxy,
            description: "Translates XML and legacy enterprise SOAP responses on the fly into normalized snake_case REST JSON with schema envelope.".into(),
            author: "morph-os-core".into(),
            fail_policy: FailPolicy::FailOpen,
            output_format: OutputFormat::Json,
            rules: vec![
                RuleStep::XmlToJson,
                RuleStep::WrapEnvelope {
                    schema_version: "2026-11-rest-v2".into(),
                    data_key: "payload".into(),
                },
            ],
            llm_prompt: "Translate the incoming XML document into a clean, typed JSON object with snake_case keys and arrays for repeated elements. Output ONLY valid JSON.".into(),
            rust_hook_template: "pub fn mutate_xml_response(body: &str) -> Result<serde_json::Value, morph_core::MorphError> {\n    morph_core::ollama::xml_to_json(body)\n}".into(),
            sample_input: "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<OrderResponse status=\"CONFIRMED\" region=\"us-east-1\">\n  <OrderId>ORD-90421</OrderId>\n  <TotalAmount>249.50</TotalAmount>\n  <Expedited>true</Expedited>\n  <Item sku=\"SKU-101\"><Qty>2</Qty><Price>99.75</Price></Item>\n  <Item sku=\"SKU-204\"><Qty>1</Qty><Price>50.00</Price></Item>\n</OrderResponse>".into(),
        },
        PluginSpec {
            id: "api-v1-to-v2-translator".into(),
            aliases: vec!["v1-to-v2-api".into(), "api-v2".into()],
            name: "REST API v1 to v2 Schema Translator".into(),
            version: "1.0.0".into(),
            target_kind: TargetKind::HttpProxy,
            description: "Renames legacy snake_case v1 API fields to camelCase v2 contracts, drops deprecated columns, and injects apiVersion metadata.".into(),
            author: "morph-os-core".into(),
            fail_policy: FailPolicy::FailOpen,
            output_format: OutputFormat::Json,
            rules: vec![
                RuleStep::ParseJson,
                RuleStep::RenameFields {
                    mappings: v1_map,
                    case_style: Some(CaseStyle::CamelCase),
                    drop_fields: vec!["legacy_debug_flag".into(), "internal_row_ver".into()],
                    add_fields: v2_meta,
                },
            ],
            llm_prompt: "Migrate this legacy v1 JSON API payload to v2 camelCase schema, renaming usr_id->userId, usr_name->displayName, acct_bal_cents->balanceCents, created_dt->createdAt, is_actv->isActive, and dropping legacy_debug_flag. Output ONLY valid JSON.".into(),
            rust_hook_template: "pub fn mutate_v1_to_v2(val: &serde_json::Value) -> serde_json::Value {\n    morph_core::ollama::rename_json_fields(val, &Default::default(), Some(morph_core::ollama::CaseStyle::CamelCase), &[], &Default::default())\n}".into(),
            sample_input: "{\n  \"usr_id\": \"u_88412\",\n  \"usr_name\": \"Ada Lovelace\",\n  \"acct_bal_cents\": 145090,\n  \"created_dt\": \"2024-03-18T11:20:00Z\",\n  \"is_actv\": true,\n  \"billing_tier\": \"enterprise\",\n  \"legacy_debug_flag\": 1\n}".into(),
        },
        PluginSpec {
            id: "wasm-dom-accessibility-mutator".into(),
            aliases: vec!["dom-table-to-json".into(), "dom-mutator".into()],
            name: "WASM Browser DOM & HTML Table Mutator".into(),
            version: "1.0.0".into(),
            target_kind: TargetKind::DomWasm,
            description: "Extracts legacy HTML tables into structured JSON records and pairs with the compiled WebAssembly DOM kernel for local accessibility upgrades.".into(),
            author: "morph-os-core".into(),
            fail_policy: FailPolicy::FailOpen,
            output_format: OutputFormat::Json,
            rules: vec![RuleStep::HtmlTableToJson],
            llm_prompt: "Extract the HTML table into a clean JSON array with snake_case column headers and typed values. Output ONLY valid JSON.".into(),
            rust_hook_template: "pub fn mutate_html_table(html: &str) -> Result<serde_json::Value, morph_core::MorphError> {\n    morph_core::ollama::html_table_to_json(html)\n}".into(),
            sample_input: "<table id=\"legacy-grid\">\n  <tr><th>Host</th><th>Region</th><th>Latency Ms</th><th>Healthy</th></tr>\n  <tr><td>edge-01.internal</td><td>iad</td><td>12.4</td><td>true</td></tr>\n  <tr><td>edge-02.internal</td><td>fra</td><td>28.9</td><td>true</td></tr>\n  <tr><td>edge-03.internal</td><td>nrt</td><td>61.2</td><td>false</td></tr>\n</table>".into(),
        },
        PluginSpec {
            id: "pii-stream-scrubber".into(),
            aliases: vec!["pii-scrub".into(), "redact-pii".into()],
            name: "Zero-Cloud PII & Secret Stream Scrubber".into(),
            version: "1.0.0".into(),
            target_kind: TargetKind::StreamGeneric,
            description: "Deterministically redacts emails, IPv4 addresses, SSNs, Luhn-valid card numbers, API keys, and phone numbers in real-time streams.".into(),
            author: "morph-os-core".into(),
            fail_policy: FailPolicy::FailClosed,
            output_format: OutputFormat::Json,
            rules: vec![RuleStep::RedactPii {
                include_report_envelope: true,
            }],
            llm_prompt: "Scrub all personally identifiable information (emails, SSNs, IPv4s, cards, bearer tokens) replacing them with [REDACTED:<TYPE>] placeholders. Output ONLY JSON with keys 'scrubbed' and 'redacted_count'.".into(),
            rust_hook_template: "pub fn scrub_stream_chunk(raw: &str) -> (String, morph_core::ollama::RedactionReport) {\n    morph_core::ollama::redact_pii(raw)\n}".into(),
            sample_input: "2026-11-25T14:02:11Z INFO auth_worker user=ops.admin@example.org ip=10.42.8.19 ssn=123-45-6789 phone=415-555-0199 auth=\"Bearer morph_demo_token_998877665544\"".into(),
        },
    ]
}
