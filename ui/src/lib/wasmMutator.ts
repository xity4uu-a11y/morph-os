/**
 * Real WebAssembly 1.0 DOM Mutation Engine + WebLLM WebGPU / Local Ollama Bridge.
 * Loads the compiled `dom_mutator.wasm` kernel, verifies it with `WebAssembly.validate()`,
 * executes linear-memory scans/masks/FNV-1a hashes, and performs opt-in DOM table extraction
 * and semantic accessibility upgrades entirely on the local device.
 */

export interface WasmDomExports {
  memory: WebAssembly.Memory;
  count_tag_matches: (
    ptr: number,
    len: number,
    needlePtr: number,
    needleLen: number
  ) => number;
  mask_ascii_digits: (ptr: number, len: number, replacement: number) => number;
  fnv1a_hash: (ptr: number, len: number) => number;
  normalize_whitespace: (ptr: number, len: number) => number;
}

export interface WasmMutationMetrics {
  wasmValidated: boolean;
  binaryBytes: number;
  memoryBytes: number;
  tableRowsDetected: number;
  tableCellsDetected: number;
  headerCellsDetected: number;
  maskedDigits: number;
  fnv1aHex: string;
  normalizedLength: number;
  latencyMs: number;
}

export interface DomMutationOutput {
  upgradedHtml: string;
  extractedJson: Record<string, unknown>[];
  normalizedSnippet: string;
  maskedPreview: string;
  metrics: WasmMutationMetrics;
}

export class WasmDomKernel {
  readonly exports: WasmDomExports;
  readonly binaryBytes: number;
  readonly validated: boolean;
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder();

  private constructor(exports: WasmDomExports, binaryBytes: number, validated: boolean) {
    this.exports = exports;
    this.binaryBytes = binaryBytes;
    this.validated = validated;
  }

  /** Instantiates the compiled WebAssembly 1.0 binary from raw bytes with strict validation. */
  static async fromBytes(bytes: Uint8Array): Promise<WasmDomKernel> {
    const bufferCopy = new Uint8Array(bytes.byteLength);
    bufferCopy.set(bytes);
    const validated = WebAssembly.validate(bufferCopy);
    if (!validated) {
      throw new Error("dom_mutator.wasm failed WebAssembly.validate()");
    }
    const instantiated = await WebAssembly.instantiate(bufferCopy);
    const exports = instantiated.instance.exports as unknown as WasmDomExports;
    if (
      !exports.memory ||
      typeof exports.count_tag_matches !== "function" ||
      typeof exports.mask_ascii_digits !== "function" ||
      typeof exports.fnv1a_hash !== "function" ||
      typeof exports.normalize_whitespace !== "function"
    ) {
      throw new Error("dom_mutator.wasm is missing required exported functions");
    }
    return new WasmDomKernel(exports, bytes.byteLength, validated);
  }

  /** Fetches and instantiates `/dom_mutator.wasm` in browser environments. */
  static async fromUrl(url = "/dom_mutator.wasm"): Promise<WasmDomKernel> {
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`Failed to fetch WASM module from ${url} (HTTP ${resp.status})`);
    }
    const buffer = await resp.arrayBuffer();
    return WasmDomKernel.fromBytes(new Uint8Array(buffer));
  }

  private ensureCapacity(requiredBytes: number): Uint8Array {
    const current = this.exports.memory.buffer.byteLength;
    if (requiredBytes > current) {
      const additionalPages = Math.ceil((requiredBytes - current) / 65536);
      this.exports.memory.grow(additionalPages);
    }
    return new Uint8Array(this.exports.memory.buffer);
  }

  countTagMatches(source: string, needle: string): number {
    const srcBytes = this.encoder.encode(source);
    const needleBytes = this.encoder.encode(needle);
    const needleOffset = srcBytes.length + 16;
    const mem = this.ensureCapacity(needleOffset + needleBytes.length + 16);
    mem.set(srcBytes, 0);
    mem.set(needleBytes, needleOffset);
    return this.exports.count_tag_matches(0, srcBytes.length, needleOffset, needleBytes.length);
  }

  maskAsciiDigits(source: string, replacementChar = "*"): { text: string; maskedCount: number } {
    const srcBytes = this.encoder.encode(source);
    const mem = this.ensureCapacity(srcBytes.length + 16);
    mem.set(srcBytes, 0);
    const code = replacementChar.charCodeAt(0) & 0xff;
    const maskedCount = this.exports.mask_ascii_digits(0, srcBytes.length, code);
    const updated = new Uint8Array(this.exports.memory.buffer, 0, srcBytes.length);
    return {
      text: this.decoder.decode(updated),
      maskedCount,
    };
  }

  fnv1aHex(source: string): string {
    const srcBytes = this.encoder.encode(source);
    const mem = this.ensureCapacity(srcBytes.length + 16);
    mem.set(srcBytes, 0);
    const hash = this.exports.fnv1a_hash(0, srcBytes.length) >>> 0;
    return hash.toString(16).padStart(8, "0");
  }

  normalizeWhitespace(source: string): string {
    const srcBytes = this.encoder.encode(source);
    const mem = this.ensureCapacity(srcBytes.length + 16);
    mem.set(srcBytes, 0);
    const newLen = this.exports.normalize_whitespace(0, srcBytes.length);
    const updated = new Uint8Array(this.exports.memory.buffer, 0, newLen);
    return this.decoder.decode(updated);
  }
}

function toSnakeCase(raw: string): string {
  return (
    raw
      .trim()
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/[^a-zA-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .toLowerCase() || "column"
  );
}

function parseScalar(raw: string): unknown {
  const t = raw.trim();
  if (t === "" || t === "-" || t.toLowerCase() === "null" || t.toLowerCase() === "n/a") {
    return null;
  }
  if (t.toLowerCase() === "true") return true;
  if (t.toLowerCase() === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(t) && !(t.length > 1 && t.startsWith("0") && !t.startsWith("0."))) {
    const num = Number(t);
    if (Number.isFinite(num)) return num;
  }
  return t;
}

/** Deterministic HTML table parser returning typed JSON records. */
export function extractHtmlTableToJson(html: string): Record<string, unknown>[] {
  const trMatches = [...html.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)];
  if (trMatches.length === 0) return [];

  const parsedRows: { isHeader: boolean; cells: string[] }[] = [];
  for (const m of trMatches) {
    const inner = m[1];
    const cellMatches = [...inner.matchAll(/<(th|td)\b[^>]*>([\s\S]*?)<\/\1>/gi)];
    if (cellMatches.length === 0) continue;
    const isHeader = cellMatches.some((c) => c[1].toLowerCase() === "th");
    const cells = cellMatches.map((c) =>
      c[2]
        .replace(/<[^>]+>/g, "")
        .replace(/&amp;/g, "&")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/\s+/g, " ")
        .trim()
    );
    parsedRows.push({ isHeader, cells });
  }

  if (parsedRows.length === 0) return [];
  const hasHeader = parsedRows[0].isHeader || parsedRows.length >= 2;
  const headers = hasHeader
    ? parsedRows[0].cells.map(toSnakeCase)
    : parsedRows[0].cells.map((_, i) => `col_${i}`);
  const dataRows = hasHeader ? parsedRows.slice(1) : parsedRows;

  return dataRows.map((row) => {
    const rec: Record<string, unknown> = {};
    headers.forEach((h, idx) => {
      rec[h] = parseScalar(row.cells[idx] ?? "");
    });
    return rec;
  });
}

/** Upgrades legacy HTML tables with ARIA roles, column scopes, and keyboard focus navigation. */
export function injectAccessibilityAttributes(html: string): string {
  let out = html.replace(/<table\b(?![^>]*\brole=)([^>]*)>/gi, '<table role="table" aria-label="Mutated Legacy Table"$1>');
  out = out.replace(/<th\b(?![^>]*\bscope=)([^>]*)>/gi, '<th scope="col"$1>');
  out = out.replace(/<tr\b(?![^>]*\btabindex=)([^>]*)>/gi, '<tr tabindex="0"$1>');
  return out;
}

/** Executes the full WASM linear-memory analysis + DOM accessibility upgrade + JSON table extraction. */
export function runWasmDomMutation(
  html: string,
  kernel: WasmDomKernel,
  options: { maskDigits?: boolean } = {}
): DomMutationOutput {
  const start = performance.now();
  const lower = html.toLowerCase();
  const tableRowsDetected = kernel.countTagMatches(lower, "<tr");
  const tableCellsDetected = kernel.countTagMatches(lower, "<td");
  const headerCellsDetected = kernel.countTagMatches(lower, "<th");
  const fnv1aHex = kernel.fnv1aHex(html);
  const normalizedSnippet = kernel.normalizeWhitespace(html);
  const maskResult = options.maskDigits
    ? kernel.maskAsciiDigits(normalizedSnippet, "*")
    : { text: normalizedSnippet, maskedCount: 0 };

  const upgradedHtml = injectAccessibilityAttributes(html);
  const extractedJson = extractHtmlTableToJson(html);
  const latencyMs = Math.round((performance.now() - start) * 100) / 100;

  return {
    upgradedHtml,
    extractedJson,
    normalizedSnippet,
    maskedPreview: maskResult.text,
    metrics: {
      wasmValidated: kernel.validated,
      binaryBytes: kernel.binaryBytes,
      memoryBytes: kernel.exports.memory.buffer.byteLength,
      tableRowsDetected,
      tableCellsDetected,
      headerCellsDetected,
      maskedDigits: maskResult.maskedCount,
      fnv1aHex,
      normalizedLength: normalizedSnippet.length,
      latencyMs,
    },
  };
}

/** Detects whether the local browser exposes WebGPU for lazy WebLLM execution. */
export function detectWebGpuSupport(): { supported: boolean; detail: string } {
  const nav = typeof navigator !== "undefined" ? (navigator as Navigator & { gpu?: unknown }) : undefined;
  if (nav && nav.gpu) {
    return {
      supported: true,
      detail: "WebGPU adapter API detected (lazy WebLLM ready)",
    };
  }
  return {
    supported: false,
    detail: "WebGPU unavailable in this runtime; deterministic + local Ollama engines active",
  };
}

/**
 * Lazy local semantic bridge calling strictly loopback Ollama (`127.0.0.1:11434/api/chat`).
 * Rejects any non-loopback URL before opening a socket.
 */
export async function queryLocalOllama(
  baseUrl: string,
  model: string,
  systemPrompt: string,
  input: string,
  timeoutMs = 3500
): Promise<string> {
  const parsed = new URL(baseUrl);
  const host = parsed.hostname.toLowerCase();
  if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1" && host !== "[::1]") {
    throw new Error(`Refused non-loopback LLM endpoint '${baseUrl}'`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(`${baseUrl.replace(/\/$/, "")}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        model,
        stream: false,
        format: "json",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: input },
        ],
      }),
    });
    if (!resp.ok) {
      throw new Error(`Local Ollama HTTP ${resp.status}`);
    }
    const data = (await resp.json()) as { message?: { content?: string }; response?: string };
    const text = (data.message?.content ?? data.response ?? "").trim();
    if (!text) {
      throw new Error("Local Ollama returned an empty response");
    }
    return text;
  } finally {
    clearTimeout(timer);
  }
}
