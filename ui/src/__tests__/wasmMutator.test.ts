import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  extractHtmlTableToJson,
  injectAccessibilityAttributes,
  runWasmDomMutation,
  WasmDomKernel,
} from "../lib/wasmMutator";

const wasmPath = path.resolve(__dirname, "../../../wasm/dom_mutator.wasm");

describe("WebAssembly 1.0 DOM Mutator Kernel (wasm/dom_mutator.wasm)", () => {
  it("passes native WebAssembly.validate() and instantiates all exported kernels", async () => {
    const bytes = new Uint8Array(fs.readFileSync(wasmPath));
    expect(WebAssembly.validate(bytes)).toBe(true);

    const kernel = await WasmDomKernel.fromBytes(bytes);
    expect(kernel.validated).toBe(true);
    expect(kernel.binaryBytes).toBeGreaterThan(200);

    // 1. Tag scanning in WASM linear memory
    const html = "<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>";
    expect(kernel.countTagMatches(html, "<tr")).toBe(2);
    expect(kernel.countTagMatches(html, "<th")).toBe(2);
    expect(kernel.countTagMatches(html, "<td")).toBe(2);

    // 2. In-place ASCII digit masking
    const masked = kernel.maskAsciiDigits("order-90421 total 249.50", "#");
    expect(masked.maskedCount).toBe(10);
    expect(masked.text).toBe("order-##### total ###.##");

    // 3. Deterministic 32-bit FNV-1a digest
    const hashA = kernel.fnv1aHex("morph-os");
    const hashB = kernel.fnv1aHex("morph-os");
    expect(hashA).toBe(hashB);
    expect(hashA).toMatch(/^[0-9a-f]{8}$/);

    // 4. In-place whitespace normalization
    expect(kernel.normalizeWhitespace("  \t legacy   table\r\n  row \t ")).toBe("legacy table row");
  });

  it("mutates legacy HTML tables with ARIA attributes and extracts typed JSON", async () => {
    const bytes = new Uint8Array(fs.readFileSync(wasmPath));
    const kernel = await WasmDomKernel.fromBytes(bytes);
    const legacyHtml = `<table>
      <tr><th>Host</th><th>Latency Ms</th><th>Healthy</th></tr>
      <tr><td>edge-01</td><td>14.2</td><td>true</td></tr>
      <tr><td>edge-02</td><td>42.8</td><td>false</td></tr>
    </table>`;

    const result = runWasmDomMutation(legacyHtml, kernel, { maskDigits: true });
    expect(result.metrics.wasmValidated).toBe(true);
    expect(result.metrics.tableRowsDetected).toBe(3);
    expect(result.metrics.tableCellsDetected).toBe(6);
    expect(result.metrics.maskedDigits).toBeGreaterThan(0);

    expect(result.extractedJson).toEqual([
      { host: "edge-01", latency_ms: 14.2, healthy: true },
      { host: "edge-02", latency_ms: 42.8, healthy: false },
    ]);

    expect(result.upgradedHtml).toContain('role="table"');
    expect(result.upgradedHtml).toContain('scope="col"');
    expect(result.upgradedHtml).toContain('tabindex="0"');

    // Also verify helpers directly
    expect(extractHtmlTableToJson(legacyHtml)).toHaveLength(2);
    expect(injectAccessibilityAttributes("<table><tr><th>K</th></tr></table>")).toContain(
      'scope="col"'
    );
  });
});
