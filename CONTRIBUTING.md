# Contributing to morph-os

Thank you for contributing to `morph-os`. We welcome community **JSON Mutation Plugins**, **deterministic Rust parsers/hooks**, **WASM DOM routines**, and **Control Panel improvements**.

---

## Safety & Architectural Rules (Non-Negotiable)

All contributions must preserve `morph-os`'s explicit user-space safety boundaries:

1. **No live-process memory tampering:** Never introduce Frida injection, `ptrace`/DLL injection into unconsented processes, kernel memory writes (`bpf_probe_write_user`), or DRM/authentication bypasses.
2. **Zero cloud egress:** Local LLM integrations must enforce strict loopback endpoints (`127.0.0.1`, `localhost`, `[::1]`) and work cleanly offline via deterministic fallbacks.
3. **Zero panics on untrusted payloads:** Parsers must handle malformed UTF-8, truncated XML, empty stdout, and oversized payloads gracefully via typed `MorphError` variants.
4. **Minimalist UI & clean text:** No emojis and no neon gradients in source files, UI components, SVGs, or documentation.

---

## Authoring a Community Mutation Plugin

Every plugin lives in `plugins/<plugin-id>.json` and must validate against `plugins/schema.json`.

### 1. JSON Plugin Manifest Template

Save as `plugins/my-legacy-log-to-json.json`:

```json
{
  "id": "my-legacy-log-to-json",
  "aliases": ["legacy-log"],
  "name": "Legacy Key-Value Service Log to JSON",
  "version": "1.0.0",
  "target_kind": "cli-stdio",
  "description": "Parses INI-style and key-value daemon status output into normalized JSON with PII scrubbing.",
  "author": "your-github-handle",
  "fail_policy": "fail-open",
  "output_format": "json",
  "rules": [
    {
      "op": "kv_to_json"
    },
    {
      "op": "redact_pii",
      "include_report_envelope": false
    }
  ],
  "llm_prompt": "Parse the legacy key-value daemon log into a clean JSON object with snake_case keys and typed scalar values. Output ONLY valid JSON.",
  "rust_hook_template": "pub fn mutate_daemon_kv(raw: &str) -> Result<serde_json::Value, morph_core::MorphError> {\n    let (clean, _report) = morph_core::ollama::redact_pii(raw);\n    morph_core::ollama::kv_to_json(&clean)\n}",
  "sample_input": "[daemon]\nname = batch-engine\nactive = true\nworkers = 8"
}
```

### 2. Supported Deterministic `rules[].op` Primitives

- `ascii_table_to_json` — Fixed-width, bordered, tab-separated, or pipe-delimited ASCII tables
- `kv_to_json` — `key = value`, `key: value`, and `[section]` config/log blocks
- `xml_to_json` — Recursive-descent XML/SOAP documents (attributes, CDATA, repeated arrays)
- `html_table_to_json` — HTML `<table>` / `<tr>` / `<th>` / `<td>` extraction
- `parse_json` — Parse incoming JSON for downstream field transformations
- `rename_fields` — Key mapping (`mappings`), `case_style` (`snake_case` / `camel_case`), `drop_fields`, `add_fields`
- `redact_pii` — Deterministic scrubbing of emails, IPv4s, SSNs, Luhn cards, phones, and bearer/API tokens
- `wrap_envelope` — Wraps output in `{ "schema_version": "...", "mutated_by": "morph-os", "<data_key>": ... }`

### 3. Adding a Custom Rust Hook in `morph-core`

If your format requires a new deterministic parser:

1. Implement a pure, panic-free function in `crates/morph-core/src/ollama.rs` returning `Result<serde_json::Value, MorphError>`.
2. Add a corresponding variant to `RuleStep` in `crates/morph-core/src/plugins.rs` and handle it inside `execute_rule_chain` in `crates/morph-core/src/pipeline.rs`.
3. Update `plugins/schema.json` and `scripts/validate-plugins.mjs` with the new `op` identifier.
4. Add unit and end-to-end tests in `crates/morph-core/tests/engine_tests.rs`.

---

## Local Verification Checklist Before Opening a Pull Request

Run the full verification suite locally:

```bash
# 1. Rust formatting, clippy (zero warnings), and full test suite
cargo fmt --all -- --check
cargo clippy -p morph-core --all-targets -- -D warnings
cargo test -p morph-core -- --nocapture

# 2. Native WebAssembly 1.0 kernel compilation & validation
node scripts/compile-wasm.mjs

# 3. Dual validation of all community plugin manifests (Node + Rust)
node scripts/validate-plugins.mjs
cargo run -p morph-core -- validate-plugins --dir plugins

# 4. Control Panel typecheck, Vitest suite (including WASM instantiation), and production build
cd ui
npm run typecheck
npm test
npm run build
```

All checks must pass with zero warnings and zero errors.
