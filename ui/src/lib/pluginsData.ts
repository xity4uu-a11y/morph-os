/**
 * Built-in catalog mirroring `plugins/*.json` and read-only Linux eBPF wire telemetry samples
 * so the Control Panel provides instant offline inspection alongside live proxy polling.
 */

export interface PluginCatalogItem {
  id: string;
  aliases: string[];
  name: string;
  version: string;
  targetKind: "cli-stdio" | "http-proxy" | "dom-wasm" | "stream-generic";
  description: string;
  author: string;
  failPolicy: "fail-open" | "fail-closed";
  llmPrompt: string;
  rustHookTemplate: string;
  sampleInput: string;
}

export interface EbpfSampleFrame {
  eventKind: string;
  timestampNs: number;
  pid: number;
  fd: number;
  byteCount: number;
  comm: string;
  readOnly: boolean;
  preview: string;
}

export const PLUGIN_CATALOG: PluginCatalogItem[] = [
  {
    id: "cli-table-to-json",
    aliases: ["cli-to-json", "ascii-table"],
    name: "Legacy CLI ASCII Table to JSON",
    version: "1.0.0",
    targetKind: "cli-stdio",
    description:
      "Parses legacy fixed-width, bordered, or pipe-delimited CLI stdout tables into strict typed JSON records.",
    author: "morph-os-core",
    failPolicy: "fail-open",
    llmPrompt:
      "Convert the legacy CLI stdout table into a strict JSON array of objects using snake_case keys and inferred numeric/boolean types. Output ONLY valid JSON.",
    rustHookTemplate: `pub fn mutate_cli_stream(raw: &str) -> Result<serde_json::Value, morph_core::MorphError> {
    morph_core::ollama::ascii_table_to_json(raw)
}`,
    sampleInput: `PID     SERVICE            STATE     MEM_MB   UPTIME_S   RESTARTS
------------------------------------------------------------------
1042    auth-gateway       RUNNING   128.4    86420      0
1188    ledger-worker      DEGRADED  512.0    14210      3
1204    legacy-cron        RUNNING   44.2     604800     0
1319    report-exporter    STOPPED   0.0      0          1`,
  },
  {
    id: "legacy-xml-to-rest-json",
    aliases: ["xml-to-json", "soap-to-json"],
    name: "Legacy XML / SOAP Payload to REST JSON",
    version: "1.0.0",
    targetKind: "http-proxy",
    description:
      "Translates XML and legacy enterprise SOAP responses on the fly into normalized snake_case REST JSON with a versioned schema envelope.",
    author: "morph-os-core",
    failPolicy: "fail-open",
    llmPrompt:
      "Translate the incoming XML document into a clean, typed JSON object with snake_case keys and arrays for repeated sibling elements. Output ONLY valid JSON.",
    rustHookTemplate: `pub fn mutate_xml_response(body: &str) -> Result<serde_json::Value, morph_core::MorphError> {
    morph_core::ollama::xml_to_json(body)
}`,
    sampleInput: `<?xml version="1.0" encoding="UTF-8"?>
<OrderResponse status="CONFIRMED" region="us-east-1">
  <OrderId>ORD-90421</OrderId>
  <TotalAmount>249.50</TotalAmount>
  <Expedited>true</Expedited>
  <Item sku="SKU-101"><Qty>2</Qty><Price>99.75</Price></Item>
  <Item sku="SKU-204"><Qty>1</Qty><Price>50.00</Price></Item>
</OrderResponse>`,
  },
  {
    id: "api-v1-to-v2-translator",
    aliases: ["v1-to-v2-api", "api-v2"],
    name: "REST API v1 to v2 Schema Translator",
    version: "1.0.0",
    targetKind: "http-proxy",
    description:
      "Renames legacy snake_case v1 API fields to camelCase v2 contracts, drops deprecated debug fields, and injects apiVersion metadata.",
    author: "morph-os-core",
    failPolicy: "fail-open",
    llmPrompt:
      "Migrate this legacy v1 JSON API payload to v2 camelCase schema, renaming usr_id->userId, usr_name->displayName, acct_bal_cents->balanceCents, created_dt->createdAt, is_actv->isActive. Output ONLY valid JSON.",
    rustHookTemplate: `pub fn mutate_v1_to_v2(val: &serde_json::Value) -> serde_json::Value {
    morph_core::ollama::rename_json_fields(val, &Default::default(), Some(morph_core::ollama::CaseStyle::CamelCase), &[], &Default::default())
}`,
    sampleInput: `{
  "usr_id": "u_88412",
  "usr_name": "Ada Lovelace",
  "acct_bal_cents": 145090,
  "created_dt": "2024-03-18T11:20:00Z",
  "is_actv": true,
  "billing_tier": "enterprise",
  "legacy_debug_flag": 1
}`,
  },
  {
    id: "wasm-dom-accessibility-mutator",
    aliases: ["dom-table-to-json", "dom-mutator"],
    name: "WASM Browser DOM & HTML Table Mutator",
    version: "1.0.0",
    targetKind: "dom-wasm",
    description:
      "Extracts legacy HTML tables into structured JSON records and pairs with the compiled WebAssembly DOM kernel for local accessibility upgrades.",
    author: "morph-os-core",
    failPolicy: "fail-open",
    llmPrompt:
      "Extract the HTML table into a clean JSON array with snake_case column headers and typed values. Output ONLY valid JSON.",
    rustHookTemplate: `pub fn mutate_html_table(html: &str) -> Result<serde_json::Value, morph_core::MorphError> {
    morph_core::ollama::html_table_to_json(html)
}`,
    sampleInput: `<table id="legacy-grid">
  <tr><th>Host</th><th>Region</th><th>Latency Ms</th><th>Healthy</th></tr>
  <tr><td>edge-01.internal</td><td>iad</td><td>12.4</td><td>true</td></tr>
  <tr><td>edge-02.internal</td><td>fra</td><td>28.9</td><td>true</td></tr>
  <tr><td>edge-03.internal</td><td>nrt</td><td>61.2</td><td>false</td></tr>
</table>`,
  },
  {
    id: "pii-stream-scrubber",
    aliases: ["pii-scrub", "redact-pii"],
    name: "Zero-Cloud PII & Secret Stream Scrubber",
    version: "1.0.0",
    targetKind: "stream-generic",
    description:
      "Deterministically redacts emails, IPv4 addresses, SSNs, Luhn-valid card numbers, API keys, and phone numbers in real-time streams.",
    author: "morph-os-core",
    failPolicy: "fail-closed",
    llmPrompt:
      "Scrub all personally identifiable information (emails, SSNs, IPv4s, cards, bearer tokens) replacing them with [REDACTED:<TYPE>] placeholders. Output ONLY JSON.",
    rustHookTemplate: `pub fn scrub_stream_chunk(raw: &str) -> (String, morph_core::ollama::RedactionReport) {
    morph_core::ollama::redact_pii(raw)
}`,
    sampleInput: `2026-11-25T14:02:11Z INFO auth_worker user=ops.admin@example.org ip=10.42.8.19 ssn=123-45-6789 phone=415-555-0199 auth="Bearer morph_demo_token_998877665544"`,
  },
];

export const SAMPLE_EBPF_FRAMES: EbpfSampleFrame[] = [
  {
    eventKind: "sys_enter_write",
    timestampNs: 1764083500000012,
    pid: 4182,
    fd: 1,
    byteCount: 342,
    comm: "legacy-ps",
    readOnly: true,
    preview: "PID     SERVICE            STATE     MEM_MB",
  },
  {
    eventKind: "stdout_flush",
    timestampNs: 1764083500001420,
    pid: 4182,
    fd: 1,
    byteCount: 196,
    comm: "legacy-ps",
    readOnly: true,
    preview: "1042    auth-gateway       RUNNING   128.4",
  },
  {
    eventKind: "tcp_send_meta",
    timestampNs: 1764083500004910,
    pid: 4210,
    fd: 7,
    byteCount: 518,
    comm: "erp-xml-svc",
    readOnly: true,
    preview: '<?xml version="1.0"?><OrderResponse status=',
  },
];
