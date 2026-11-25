/**
 * Deterministic client-side mutation core + local morph-os proxy / Tauri IPC bridge.
 * Mirrors the Rust `morph-core` parsers so the Control Panel works both standalone in a browser
 * and connected to a live local `morph-os proxy` or Tauri v2 desktop runtime.
 */

import { extractHtmlTableToJson, queryLocalOllama } from "./wasmMutator";

export type UiEngine = "deterministic" | "ollama" | "webllm-webgpu";
export type UiFormat = "json" | "ndjson" | "csv";
export type CircuitState = "closed" | "open" | "half-open";

export interface UiMutationOutput {
  eventId: string;
  timestampUtc: string;
  ruleId: string;
  engineUsed: string;
  outputFormat: UiFormat;
  mutated: boolean;
  fallbackTriggered: boolean;
  fallbackReason: string | null;
  latencyMs: number;
  inputBytes: number;
  outputBytes: number;
  circuitState: CircuitState;
  output: string;
}

export interface CircuitTracker {
  state: CircuitState;
  consecutiveFailures: number;
  failureThreshold: number;
  cooldownMs: number;
  openedAtMs: number | null;
  totalTrips: number;
  lastError: string | null;
}

export function createCircuitTracker(failureThreshold = 2, cooldownMs = 15000): CircuitTracker {
  return {
    state: "closed",
    consecutiveFailures: 0,
    failureThreshold,
    cooldownMs,
    openedAtMs: null,
    totalTrips: 0,
    lastError: null,
  };
}

function toSnakeCase(raw: string): string {
  return (
    raw
      .trim()
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/[^a-zA-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .toLowerCase() || "field"
  );
}

function toCamelCase(raw: string): string {
  const snake = toSnakeCase(raw);
  return snake.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

function parseTypedScalar(raw: string): unknown {
  const t = raw.trim();
  if (t === "" || t === "-" || t === "--" || t.toLowerCase() === "null" || t.toLowerCase() === "n/a") {
    return null;
  }
  if (t.toLowerCase() === "true") return true;
  if (t.toLowerCase() === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(t) && !(t.length > 1 && t.startsWith("0") && !t.startsWith("0."))) {
    const n = Number(t);
    if (Number.isFinite(n)) return n;
  }
  return t;
}

function isSeparatorLine(line: string): boolean {
  const t = line.trim();
  return t.length === 0 || /^[-=+|_{}\s~*]+$/.test(t);
}

export function asciiTableToJson(input: string): Record<string, unknown>[] {
  const lines = input
    .split(/\r?\n/)
    .map((l) => l.trimEnd())
    .filter((l) => !isSeparatorLine(l));

  if (lines.length < 2) {
    throw new Error("ASCII table requires at least a header row and one data row");
  }

  const pipeLines = lines.filter((l) => l.includes("|"));
  let headers: string[];
  let dataRows: string[][];

  if (pipeLines.length >= 2) {
    const splitPipe = (l: string) =>
      l
        .trim()
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split("|")
        .map((c) => c.trim());
    headers = splitPipe(pipeLines[0]).map(toSnakeCase);
    dataRows = pipeLines.slice(1).map(splitPipe);
  } else {
    const splitMulti = (l: string) =>
      l
        .trim()
        .split(/\s{2,}|\t+/)
        .map((c) => c.trim())
        .filter((c) => c.length > 0);
    const hdrRaw = splitMulti(lines[0]);
    const useSingle = hdrRaw.length < 2;
    headers = (useSingle ? lines[0].trim().split(/\s+/) : hdrRaw).map(toSnakeCase);
    dataRows = lines.slice(1).map((row) =>
      useSingle ? row.trim().split(/\s+/) : splitMulti(row)
    );
  }

  return dataRows.map((cells) => {
    const obj: Record<string, unknown> = {};
    headers.forEach((h, idx) => {
      obj[h] = parseTypedScalar(cells[idx] ?? "");
    });
    return obj;
  });
}

export function xmlToJson(input: string): Record<string, unknown> {
  let pos = 0;
  const src = input;

  const skipWsAndProlog = () => {
    while (pos < src.length) {
      while (pos < src.length && /\s/.test(src[pos])) pos += 1;
      if (src.startsWith("<?", pos)) {
        const end = src.indexOf("?>", pos);
        if (end === -1) throw new Error("Unclosed XML declaration");
        pos = end + 2;
      } else if (src.startsWith("<!--", pos)) {
        const end = src.indexOf("-->", pos);
        if (end === -1) throw new Error("Unclosed XML comment");
        pos = end + 3;
      } else {
        break;
      }
    }
  };

  const readName = (): string => {
    const start = pos;
    while (pos < src.length && /[A-Za-z0-9_:\-.]/.test(src[pos])) pos += 1;
    if (pos === start) throw new Error(`Expected XML identifier at offset ${pos}`);
    return src.slice(start, pos);
  };

  const decodeEntities = (s: string) =>
    s
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'");

  const parseElement = (): [string, unknown] => {
    skipWsAndProlog();
    if (src[pos] !== "<") throw new Error(`Expected '<' at offset ${pos}`);
    pos += 1;
    const tagName = readName();
    const attrs: [string, string][] = [];

    while (pos < src.length) {
      while (pos < src.length && /\s/.test(src[pos])) pos += 1;
      if (src.startsWith("/>", pos)) {
        pos += 2;
        return [tagName, buildNode(attrs, [], "")];
      }
      if (src[pos] === ">") {
        pos += 1;
        break;
      }
      const attrName = readName();
      while (pos < src.length && /\s/.test(src[pos])) pos += 1;
      if (src[pos] !== "=") throw new Error(`Expected '=' for attribute ${attrName}`);
      pos += 1;
      while (pos < src.length && /\s/.test(src[pos])) pos += 1;
      const q = src[pos];
      if (q !== '"' && q !== "'") throw new Error(`Expected quote for attribute ${attrName}`);
      pos += 1;
      const end = src.indexOf(q, pos);
      if (end === -1) throw new Error(`Unclosed attribute ${attrName}`);
      attrs.push([attrName, decodeEntities(src.slice(pos, end))]);
      pos = end + 1;
    }

    const children: [string, unknown][] = [];
    let text = "";

    while (pos < src.length) {
      if (src.startsWith("<!--", pos)) {
        const end = src.indexOf("-->", pos);
        if (end === -1) throw new Error("Unclosed XML comment");
        pos = end + 3;
      } else if (src.startsWith("<![CDATA[", pos)) {
        pos += 9;
        const end = src.indexOf("]]>", pos);
        if (end === -1) throw new Error("Unclosed CDATA");
        text += src.slice(pos, end);
        pos = end + 3;
      } else if (src.startsWith("</", pos)) {
        pos += 2;
        const closeName = readName();
        while (pos < src.length && /\s/.test(src[pos])) pos += 1;
        if (src[pos] !== ">") throw new Error(`Expected '>' closing </${closeName}>`);
        pos += 1;
        if (closeName !== tagName) {
          throw new Error(`Mismatched closing tag </${closeName}> for <${tagName}>`);
        }
        break;
      } else if (src[pos] === "<") {
        children.push(parseElement());
      } else {
        const nextLt = src.indexOf("<", pos);
        const end = nextLt === -1 ? src.length : nextLt;
        text += decodeEntities(src.slice(pos, end));
        pos = end;
      }
    }

    return [tagName, buildNode(attrs, children, text)];
  };

  const buildNode = (
    attrs: [string, string][],
    children: [string, unknown][],
    text: string
  ): unknown => {
    const trimmed = text.trim();
    if (attrs.length === 0 && children.length === 0) {
      return trimmed.length === 0 ? null : parseTypedScalar(trimmed);
    }
    const obj: Record<string, unknown> = {};
    for (const [k, v] of attrs) {
      obj[`@${toSnakeCase(k)}`] = parseTypedScalar(v);
    }
    for (const [k, v] of children) {
      const key = toSnakeCase(k);
      if (key in obj) {
        const existing = obj[key];
        if (Array.isArray(existing)) {
          existing.push(v);
        } else {
          obj[key] = [existing, v];
        }
      } else {
        obj[key] = v;
      }
    }
    if (trimmed.length > 0) {
      obj.text = parseTypedScalar(trimmed);
    }
    return obj;
  };

  const [rootName, rootVal] = parseElement();
  return { [toSnakeCase(rootName)]: rootVal };
}

const V1_TO_V2_RENAMES: Record<string, string> = {
  usr_id: "userId",
  usr_name: "displayName",
  acct_bal_cents: "balanceCents",
  created_dt: "createdAt",
  is_actv: "isActive",
};

const V1_DROPPED = new Set(["legacy_debug_flag", "internal_row_ver"]);

export function translateV1ToV2Api(input: string): Record<string, unknown> {
  const parsed = JSON.parse(input) as unknown;
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk);
    if (node && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        if (V1_DROPPED.has(k)) continue;
        const nextKey = V1_TO_V2_RENAMES[k] ?? toCamelCase(k);
        out[nextKey] = walk(v);
      }
      return out;
    }
    return node;
  };
  const result = walk(parsed);
  if (result && typeof result === "object" && !Array.isArray(result)) {
    return { ...(result as Record<string, unknown>), apiVersion: "v2" };
  }
  return { apiVersion: "v2", data: result };
}

export function redactPiiText(input: string): {
  scrubbed: string;
  redacted_total: number;
  report: Record<string, number>;
} {
  const report = {
    emails_redacted: 0,
    ipv4_redacted: 0,
    ssn_redacted: 0,
    tokens_redacted: 0,
    phones_redacted: 0,
  };

  let out = input.replace(/Bearer\s+[A-Za-z0-9._-]{12,}/g, () => {
    report.tokens_redacted += 1;
    return "Bearer [REDACTED:TOKEN]";
  });
  out = out.replace(/\b(?:sk_live_|sk_test_|ghp_|gho_|xoxb-|AIza)[A-Za-z0-9._-]{8,}\b/g, () => {
    report.tokens_redacted += 1;
    return "[REDACTED:API_KEY]";
  });
  out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, () => {
    report.emails_redacted += 1;
    return "[REDACTED:EMAIL]";
  });
  out = out.replace(/\b\d{3}-\d{2}-\d{4}\b/g, () => {
    report.ssn_redacted += 1;
    return "[REDACTED:SSN]";
  });
  out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (m) => {
    if (m === "127.0.0.1") return m;
    report.ipv4_redacted += 1;
    return "[REDACTED:IPV4]";
  });
  out = out.replace(/\b\d{3}[-.]\d{3}[-.]\d{4}\b/g, () => {
    report.phones_redacted += 1;
    return "[REDACTED:PHONE]";
  });

  const redacted_total = Object.values(report).reduce((a, b) => a + b, 0);
  return { scrubbed: out, redacted_total, report };
}

export function formatMutationValue(value: unknown, format: UiFormat): string {
  if (format === "ndjson") {
    if (Array.isArray(value)) {
      return value.map((item) => JSON.stringify(item)).join("\n");
    }
    return JSON.stringify(value);
  }
  if (format === "csv") {
    const rows = Array.isArray(value)
      ? (value.filter((v) => v && typeof v === "object") as Record<string, unknown>[])
      : value && typeof value === "object"
        ? [value as Record<string, unknown>]
        : [];
    if (rows.length === 0) return "";
    const cols: string[] = [];
    for (const row of rows) {
      for (const k of Object.keys(row)) {
        if (!cols.includes(k)) cols.push(k);
      }
    }
    const esc = (v: unknown) => {
      const s = v === null || v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v);
      return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    return [cols.map(esc).join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join(
      "\n"
    );
  }
  return JSON.stringify(value, null, 2);
}

export function runDeterministicRule(ruleId: string, input: string, format: UiFormat): string {
  let value: unknown;
  switch (ruleId) {
    case "cli-table-to-json":
    case "cli-to-json":
      value = asciiTableToJson(input);
      break;
    case "legacy-xml-to-rest-json":
    case "xml-to-json":
      value = {
        schema_version: "2026-11-rest-v2",
        mutated_by: "morph-os",
        payload: xmlToJson(input),
      };
      break;
    case "api-v1-to-v2-translator":
    case "v1-to-v2-api":
      value = translateV1ToV2Api(input);
      break;
    case "wasm-dom-accessibility-mutator":
    case "dom-table-to-json":
      value = extractHtmlTableToJson(input);
      break;
    case "pii-stream-scrubber":
    case "pii-scrub":
      value = redactPiiText(input);
      break;
    default:
      throw new Error(`Unsupported rule '${ruleId}'`);
  }
  return formatMutationValue(value, format);
}

let eventCounter = 1;

/**
 * Executes a mutation through the selected engine with full circuit-breaker isolation
 * and automatic deterministic failover so the UI never hangs or drops payloads.
 */
export async function executeWorkbenchMutation(params: {
  ruleId: string;
  input: string;
  engine: UiEngine;
  format: UiFormat;
  ollamaUrl: string;
  ollamaModel: string;
  llmPrompt: string;
  circuit: CircuitTracker;
}): Promise<{ result: UiMutationOutput; nextCircuit: CircuitTracker }> {
  const start = performance.now();
  const nextCircuit: CircuitTracker = { ...params.circuit };
  const enc = new TextEncoder();

  let output = "";
  let engineUsed = "deterministic";
  let fallbackTriggered = false;
  let fallbackReason: string | null = null;
  let mutated = true;

  const allowLlmAttempt = (): boolean => {
    if (nextCircuit.state === "open" && nextCircuit.openedAtMs !== null) {
      if (Date.now() - nextCircuit.openedAtMs >= nextCircuit.cooldownMs) {
        nextCircuit.state = "half-open";
        return true;
      }
      return false;
    }
    return true;
  };

  if (params.engine === "ollama" || params.engine === "webllm-webgpu") {
    if (!allowLlmAttempt()) {
      fallbackTriggered = true;
      fallbackReason = `Circuit breaker OPEN (${nextCircuit.lastError ?? "LLM unavailable"}); executed deterministic rule`;
      engineUsed = "deterministic-fallback";
      output = runDeterministicRule(params.ruleId, params.input, params.format);
    } else if (params.engine === "webllm-webgpu") {
      const hasGpu = typeof navigator !== "undefined" && Boolean((navigator as Navigator & { gpu?: unknown }).gpu);
      fallbackTriggered = true;
      fallbackReason = hasGpu
        ? "WebGPU adapter ready; no local WebLLM weights preloaded — executed deterministic kernel"
        : "WebGPU adapter unavailable in browser context — executed deterministic kernel";
      engineUsed = "deterministic-fallback";
      output = runDeterministicRule(params.ruleId, params.input, params.format);
    } else {
      try {
        const raw = await queryLocalOllama(
          params.ollamaUrl,
          params.ollamaModel,
          params.llmPrompt,
          params.input,
          3000
        );
        const parsed = JSON.parse(raw) as unknown;
        output = formatMutationValue(parsed, params.format);
        engineUsed = "ollama";
        nextCircuit.state = "closed";
        nextCircuit.consecutiveFailures = 0;
        nextCircuit.openedAtMs = null;
        nextCircuit.lastError = null;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        nextCircuit.consecutiveFailures += 1;
        nextCircuit.lastError = message;
        if (
          nextCircuit.state === "half-open" ||
          nextCircuit.consecutiveFailures >= nextCircuit.failureThreshold
        ) {
          if (nextCircuit.state !== "open") nextCircuit.totalTrips += 1;
          nextCircuit.state = "open";
          nextCircuit.openedAtMs = Date.now();
        }
        fallbackTriggered = true;
        fallbackReason = `Local Ollama failed (${message}); fell back cleanly to deterministic rule`;
        engineUsed = "deterministic-fallback";
        output = runDeterministicRule(params.ruleId, params.input, params.format);
      }
    }
  } else {
    try {
      output = runDeterministicRule(params.ruleId, params.input, params.format);
    } catch (err) {
      mutated = false;
      fallbackTriggered = true;
      fallbackReason = err instanceof Error ? err.message : String(err);
      engineUsed = "pass-through-fallback";
      output = params.input;
    }
  }

  const latencyMs = Math.round((performance.now() - start) * 100) / 100;
  const result: UiMutationOutput = {
    eventId: `ui-${String(eventCounter++).padStart(5, "0")}`,
    timestampUtc: new Date().toISOString(),
    ruleId: params.ruleId,
    engineUsed,
    outputFormat: params.format,
    mutated,
    fallbackTriggered,
    fallbackReason,
    latencyMs,
    inputBytes: enc.encode(params.input).byteLength,
    outputBytes: enc.encode(output).byteLength,
    circuitState: nextCircuit.state,
    output,
  };

  return { result, nextCircuit };
}
