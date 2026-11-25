import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CircuitTracker,
  createCircuitTracker,
  executeWorkbenchMutation,
  UiEngine,
  UiFormat,
  UiMutationOutput,
} from "./lib/deterministicMutators";
import { PLUGIN_CATALOG, SAMPLE_EBPF_FRAMES } from "./lib/pluginsData";
import {
  detectWebGpuSupport,
  DomMutationOutput,
  runWasmDomMutation,
  WasmDomKernel,
} from "./lib/wasmMutator";

type TabId = "workbench" | "wasm" | "proxy" | "plugins";
type ThemeMode = "light" | "dark";

interface ProxyHealthSnapshot {
  status: string;
  version: string;
  uptime_seconds: number;
  upstream_url: string;
  default_rule_id: string;
  plugin_count: number;
  circuit_state: string;
}

const DEFAULT_HTML_PLAYGROUND = `<table id="legacy-ops-grid">
  <tr>
    <th>Instance</th>
    <th>Region</th>
    <th>CPU Pct</th>
    <th>Account Ref</th>
    <th>Healthy</th>
  </tr>
  <tr>
    <td>worker-01.prod</td>
    <td>us-east-1</td>
    <td>38.4</td>
    <td>ACCT-4092-8810</td>
    <td>true</td>
  </tr>
  <tr>
    <td>worker-02.prod</td>
    <td>eu-central-1</td>
    <td>71.2</td>
    <td>ACCT-5120-9941</td>
    <td>true</td>
  </tr>
  <tr>
    <td>worker-03.prod</td>
    <td>ap-northeast-1</td>
    <td>94.8</td>
    <td>ACCT-7741-3005</td>
    <td>false</td>
  </tr>
</table>`;

export function App() {
  const [theme, setTheme] = useState<ThemeMode>("light");
  const [activeTab, setActiveTab] = useState<TabId>("workbench");

  // Workbench state
  const [selectedRuleId, setSelectedRuleId] = useState<string>(PLUGIN_CATALOG[0].id);
  const [engine, setEngine] = useState<UiEngine>("deterministic");
  const [outputFormat, setOutputFormat] = useState<UiFormat>("json");
  const [ollamaUrl, setOllamaUrl] = useState<string>("http://127.0.0.1:11434");
  const [ollamaModel, setOllamaModel] = useState<string>("llama3.2");
  const [rawInput, setRawInput] = useState<string>(PLUGIN_CATALOG[0].sampleInput);
  const [circuit, setCircuit] = useState<CircuitTracker>(() => createCircuitTracker(2, 15000));
  const [lastResult, setLastResult] = useState<UiMutationOutput | null>(null);
  const [history, setHistory] = useState<UiMutationOutput[]>([]);
  const [running, setRunning] = useState<boolean>(false);

  // WASM DOM Playground state
  const [wasmKernel, setWasmKernel] = useState<WasmDomKernel | null>(null);
  const [wasmError, setWasmError] = useState<string | null>(null);
  const [htmlSnippet, setHtmlSnippet] = useState<string>(DEFAULT_HTML_PLAYGROUND);
  const [maskDigits, setMaskDigits] = useState<boolean>(true);
  const [wasmOutput, setWasmOutput] = useState<DomMutationOutput | null>(null);

  // Local proxy inspector state
  const [proxyBaseUrl, setProxyBaseUrl] = useState<string>("http://127.0.0.1:8787");
  const [proxyHealth, setProxyHealth] = useState<ProxyHealthSnapshot | null>(null);
  const [proxyError, setProxyError] = useState<string | null>(null);
  const [copiedPluginId, setCopiedPluginId] = useState<string | null>(null);

  const webGpuInfo = useMemo(() => detectWebGpuSupport(), []);

  const activePlugin = useMemo(
    () => PLUGIN_CATALOG.find((p) => p.id === selectedRuleId) ?? PLUGIN_CATALOG[0],
    [selectedRuleId]
  );

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  // Load real compiled WebAssembly 1.0 module on mount
  useEffect(() => {
    let cancelled = false;
    WasmDomKernel.fromUrl("/dom_mutator.wasm")
      .then((kernel) => {
        if (!cancelled) {
          setWasmKernel(kernel);
          setWasmError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setWasmError(err instanceof Error ? err.message : String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Re-run WASM DOM mutation whenever snippet, toggle, or kernel updates
  useEffect(() => {
    if (!wasmKernel) return;
    setWasmOutput(runWasmDomMutation(htmlSnippet, wasmKernel, { maskDigits }));
  }, [wasmKernel, htmlSnippet, maskDigits]);

  const runMutation = useCallback(
    async (overrideInput?: string, overrideRuleId?: string) => {
      const targetRule = overrideRuleId ?? selectedRuleId;
      const plugin = PLUGIN_CATALOG.find((p) => p.id === targetRule) ?? PLUGIN_CATALOG[0];
      const payload = overrideInput ?? rawInput;
      setRunning(true);
      try {
        const { result, nextCircuit } = await executeWorkbenchMutation({
          ruleId: targetRule,
          input: payload,
          engine,
          format: outputFormat,
          ollamaUrl,
          ollamaModel,
          llmPrompt: plugin.llmPrompt,
          circuit,
        });
        setCircuit(nextCircuit);
        setLastResult(result);
        setHistory((prev) => [result, ...prev].slice(0, 32));
      } finally {
        setRunning(false);
      }
    },
    [selectedRuleId, rawInput, engine, outputFormat, ollamaUrl, ollamaModel, circuit]
  );

  // Execute initial deterministic preview on first mount
  useEffect(() => {
    void runMutation(PLUGIN_CATALOG[0].sampleInput, PLUGIN_CATALOG[0].id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRuleChange = (nextRuleId: string) => {
    const plugin = PLUGIN_CATALOG.find((p) => p.id === nextRuleId) ?? PLUGIN_CATALOG[0];
    setSelectedRuleId(plugin.id);
    setRawInput(plugin.sampleInput);
    void runMutation(plugin.sampleInput, plugin.id);
  };

  const pollLocalProxy = async () => {
    setProxyError(null);
    try {
      const resp = await fetch(`${proxyBaseUrl.replace(/\/$/, "")}/_morph/health`);
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const data = (await resp.json()) as ProxyHealthSnapshot;
      setProxyHealth(data);
    } catch (err: unknown) {
      setProxyHealth(null);
      setProxyError(
        `Proxy not reachable at ${proxyBaseUrl} (${err instanceof Error ? err.message : String(err)}). Start locally with: morph-os proxy --listen 127.0.0.1:8787 --upstream http://127.0.0.1:9000 --rule xml-to-json`
      );
    }
  };

  const copyHook = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedPluginId(id);
      setTimeout(() => setCopiedPluginId(null), 1600);
    } catch {
      setCopiedPluginId(null);
    }
  };

  const circuitBadgeClass =
    circuit.state === "closed"
      ? "pill pill-pass"
      : circuit.state === "half-open"
        ? "pill pill-warn"
        : "pill pill-fail";

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-group">
          <div className="brand-mark" aria-hidden="true">
            M/
          </div>
          <div>
            <h1 className="brand-title">morph-os</h1>
            <p className="brand-subtitle">Local Runtime Stream, API &amp; DOM Mutator v1.0.0</p>
          </div>
        </div>

        <nav className="nav-tabs" aria-label="Control Panel Views">
          <button
            type="button"
            className={`nav-tab ${activeTab === "workbench" ? "active" : ""}`}
            onClick={() => setActiveTab("workbench")}
          >
            Stream &amp; CLI Workbench
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === "wasm" ? "active" : ""}`}
            onClick={() => setActiveTab("wasm")}
          >
            WASM DOM Playground
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === "proxy" ? "active" : ""}`}
            onClick={() => setActiveTab("proxy")}
          >
            Proxy &amp; Telemetry
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === "plugins" ? "active" : ""}`}
            onClick={() => setActiveTab("plugins")}
          >
            Plugins ({PLUGIN_CATALOG.length})
          </button>
        </nav>

        <div className="topbar-meta">
          <span className={circuitBadgeClass}>
            <span className="status-dot" />
            CIRCUIT: {circuit.state.toUpperCase()}
          </span>
          <span className="pill">CLOUD: 0 B</span>
          <button
            type="button"
            className="btn"
            onClick={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
          >
            {theme === "light" ? "Dark Mode" : "Light Mode"}
          </button>
        </div>
      </header>

      <main className="main-content">
        {activeTab === "workbench" && (
          <>
            <div className="section-header">
              <div>
                <h2 className="section-title">Live Stream &amp; API Mutation Workbench</h2>
                <p className="section-desc">
                  Reshape legacy CLI tables, XML responses, v1 REST schemas, and PII-bearing logs
                  strictly on-device with automatic circuit-breaker failover.
                </p>
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                {circuit.state !== "closed" && (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setCircuit(createCircuitTracker(2, 15000))}
                  >
                    Reset Circuit
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={running}
                  onClick={() => void runMutation()}
                >
                  {running ? "Mutating..." : "Run Mutation"}
                </button>
              </div>
            </div>

            <section className="controls-bar" aria-label="Mutation Engine Controls">
              <label className="control-field">
                <span className="control-label">Mutation Rule</span>
                <select
                  className="select-input"
                  value={selectedRuleId}
                  onChange={(e) => handleRuleChange(e.target.value)}
                >
                  {PLUGIN_CATALOG.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.id} ({p.targetKind})
                    </option>
                  ))}
                </select>
              </label>

              <label className="control-field">
                <span className="control-label">Engine</span>
                <select
                  className="select-input"
                  value={engine}
                  onChange={(e) => setEngine(e.target.value as UiEngine)}
                >
                  <option value="deterministic">Deterministic (Rust / Zero-LLM)</option>
                  <option value="ollama">Local Ollama (127.0.0.1:11434)</option>
                  <option value="webllm-webgpu">WebLLM WebGPU (Lazy Browser)</option>
                </select>
              </label>

              <label className="control-field" style={{ minWidth: "130px" }}>
                <span className="control-label">Output Format</span>
                <select
                  className="select-input"
                  value={outputFormat}
                  onChange={(e) => setOutputFormat(e.target.value as UiFormat)}
                >
                  <option value="json">JSON</option>
                  <option value="ndjson">NDJSON</option>
                  <option value="csv">CSV</option>
                </select>
              </label>

              {engine === "ollama" && (
                <>
                  <label className="control-field">
                    <span className="control-label">Loopback Ollama URL</span>
                    <input
                      className="text-input mono"
                      value={ollamaUrl}
                      onChange={(e) => setOllamaUrl(e.target.value)}
                    />
                  </label>
                  <label className="control-field" style={{ minWidth: "140px" }}>
                    <span className="control-label">Model</span>
                    <input
                      className="text-input mono"
                      value={ollamaModel}
                      onChange={(e) => setOllamaModel(e.target.value)}
                    />
                  </label>
                </>
              )}
            </section>

            {lastResult?.fallbackTriggered && lastResult.fallbackReason && (
              <div className="notice-bar notice-warn" role="status">
                <span>
                  <strong>Failover Active:</strong> {lastResult.fallbackReason}
                </span>
                <span className="mono">ENGINE={lastResult.engineUsed}</span>
              </div>
            )}

            <section className="metrics-strip" aria-label="Execution Metrics">
              <div className="metric-card">
                <div className="metric-label">Latency</div>
                <div className="metric-value">
                  {lastResult ? `${lastResult.latencyMs.toFixed(2)} ms` : "--"}
                </div>
                <div className="metric-sub">End-to-end local transform</div>
              </div>
              <div className="metric-card">
                <div className="metric-label">Engine Executed</div>
                <div className="metric-value">{lastResult?.engineUsed ?? "deterministic"}</div>
                <div className="metric-sub">{webGpuInfo.detail}</div>
              </div>
              <div className="metric-card">
                <div className="metric-label">Payload Delta</div>
                <div className="metric-value">
                  {lastResult ? `${lastResult.inputBytes} B -> ${lastResult.outputBytes} B` : "--"}
                </div>
                <div className="metric-sub">Rule: {activePlugin.id}</div>
              </div>
              <div className="metric-card">
                <div className="metric-label">Circuit Trips</div>
                <div className="metric-value">
                  {circuit.totalTrips} ({circuit.state})
                </div>
                <div className="metric-sub">Fail policy: {activePlugin.failPolicy}</div>
              </div>
            </section>

            <section className="split-panes" aria-label="Before and After Diff">
              <div className="pane-card">
                <div className="pane-header">
                  <span className="pane-title">BEFORE — Raw Legacy Input</span>
                  <span className="pane-meta">
                    {rawInput.split(/\r?\n/).length} lines / {new TextEncoder().encode(rawInput).byteLength} B
                  </span>
                </div>
                <textarea
                  className="code-editor"
                  aria-label="Raw Legacy Input"
                  value={rawInput}
                  onChange={(e) => setRawInput(e.target.value)}
                  spellCheck={false}
                />
              </div>

              <div className="pane-card">
                <div className="pane-header">
                  <span className="pane-title">
                    AFTER — Mutated {outputFormat.toUpperCase()} Output
                  </span>
                  <span className="pane-meta">
                    {lastResult
                      ? `${lastResult.output.split(/\r?\n/).length} lines / ${lastResult.outputBytes} B`
                      : "Pending"}
                  </span>
                </div>
                <pre className="code-output">{lastResult?.output ?? ""}</pre>
              </div>
            </section>
          </>
        )}

        {activeTab === "wasm" && (
          <>
            <div className="section-header">
              <div>
                <h2 className="section-title">Compiled WebAssembly 1.0 DOM Mutator</h2>
                <p className="section-desc">
                  Runs the real compiled <span className="mono">wasm/dom_mutator.wasm</span> binary
                  in browser linear memory for tag scanning, whitespace normalization, digit
                  masking, FNV-1a hashing, and ARIA accessibility upgrades.
                </p>
              </div>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={maskDigits}
                  onChange={(e) => setMaskDigits(e.target.checked)}
                />
                Run WASM in-place ASCII digit masking
              </label>
            </div>

            {wasmError && (
              <div className="notice-bar notice-warn" role="alert">
                <span>WASM load status: {wasmError}</span>
              </div>
            )}

            <section className="metrics-strip">
              <div className="metric-card">
                <div className="metric-label">WASM Kernel</div>
                <div className="metric-value">
                  {wasmOutput?.metrics.wasmValidated ? "VALIDATED" : "LOADING"}
                </div>
                <div className="metric-sub">
                  {wasmOutput ? `${wasmOutput.metrics.binaryBytes} B binary / 64 KiB page` : "--"}
                </div>
              </div>
              <div className="metric-card">
                <div className="metric-label">DOM Tags Scanned</div>
                <div className="metric-value">
                  {wasmOutput
                    ? `${wasmOutput.metrics.tableRowsDetected} tr / ${wasmOutput.metrics.tableCellsDetected} td`
                    : "--"}
                </div>
                <div className="metric-sub">
                  {wasmOutput ? `${wasmOutput.metrics.headerCellsDetected} header cells` : "--"}
                </div>
              </div>
              <div className="metric-card">
                <div className="metric-label">FNV-1a Digest (WASM)</div>
                <div className="metric-value">
                  {wasmOutput ? `0x${wasmOutput.metrics.fnv1aHex}` : "--"}
                </div>
                <div className="metric-sub">
                  Digits masked: {wasmOutput?.metrics.maskedDigits ?? 0}
                </div>
              </div>
              <div className="metric-card">
                <div className="metric-label">Kernel Latency</div>
                <div className="metric-value">
                  {wasmOutput ? `${wasmOutput.metrics.latencyMs.toFixed(2)} ms` : "--"}
                </div>
                <div className="metric-sub">Zero external host calls</div>
              </div>
            </section>

            <section className="split-panes">
              <div className="pane-card">
                <div className="pane-header">
                  <span className="pane-title">BEFORE — Legacy HTML Table Markup</span>
                  <span className="pane-meta">{htmlSnippet.length} chars</span>
                </div>
                <textarea
                  className="code-editor"
                  aria-label="Legacy HTML Table Input"
                  value={htmlSnippet}
                  onChange={(e) => setHtmlSnippet(e.target.value)}
                  spellCheck={false}
                />
              </div>

              <div className="pane-card">
                <div className="pane-header">
                  <span className="pane-title">AFTER — Extracted JSON &amp; ARIA-Upgraded DOM</span>
                  <span className="pane-meta">
                    {wasmOutput ? `${wasmOutput.extractedJson.length} records` : "0 records"}
                  </span>
                </div>
                <pre className="code-output">
                  {wasmOutput
                    ? `// Structured JSON Records\n${JSON.stringify(wasmOutput.extractedJson, null, 2)}\n\n// WASM Masked & Normalized Buffer Preview\n${wasmOutput.maskedPreview}\n\n// ARIA Accessibility Upgraded HTML\n${wasmOutput.upgradedHtml}`
                    : "Loading dom_mutator.wasm..."}
                </pre>
              </div>
            </section>
          </>
        )}

        {activeTab === "proxy" && (
          <>
            <div className="section-header">
              <div>
                <h2 className="section-title">Loopback Proxy &amp; Read-Only eBPF Telemetry</h2>
                <p className="section-desc">
                  Inspect live local reverse-proxy mutations and strictly read-only 112-byte Linux
                  eBPF ring-buffer frames (<span className="mono">tracepoint/syscalls/sys_enter_write</span>).
                </p>
              </div>
              <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                <input
                  className="text-input mono"
                  aria-label="Local Proxy Base URL"
                  value={proxyBaseUrl}
                  onChange={(e) => setProxyBaseUrl(e.target.value)}
                  style={{ width: "220px" }}
                />
                <button type="button" className="btn btn-primary" onClick={() => void pollLocalProxy()}>
                  Probe Local Proxy
                </button>
              </div>
            </div>

            {proxyHealth && (
              <div className="notice-bar">
                <span>
                  Connected to <span className="mono">{proxyBaseUrl}</span> -&gt; upstream{" "}
                  <span className="mono">{proxyHealth.upstream_url}</span> (rule:{" "}
                  <span className="mono">{proxyHealth.default_rule_id}</span>)
                </span>
                <span className="pill pill-pass">LIVE v{proxyHealth.version}</span>
              </div>
            )}

            {proxyError && (
              <div className="notice-bar notice-warn">
                <span>{proxyError}</span>
              </div>
            )}

            <div className="pane-card">
              <div className="pane-header">
                <span className="pane-title">Recent Local Mutation Exchanges</span>
                <span className="pane-meta">{history.length} recorded</span>
              </div>
              <div className="data-table-wrap" style={{ border: "none", borderRadius: 0 }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Event</th>
                      <th>Rule</th>
                      <th>Engine</th>
                      <th>Latency</th>
                      <th>Size Delta</th>
                      <th>Circuit</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((item) => (
                      <tr key={item.eventId}>
                        <td className="mono">{item.eventId}</td>
                        <td className="mono">{item.ruleId}</td>
                        <td className="mono">{item.engineUsed}</td>
                        <td className="mono">{item.latencyMs.toFixed(2)} ms</td>
                        <td className="mono">
                          {item.inputBytes} B -&gt; {item.outputBytes} B
                        </td>
                        <td>
                          <span
                            className={`pill ${
                              item.circuitState === "closed"
                                ? "pill-pass"
                                : item.circuitState === "half-open"
                                  ? "pill-warn"
                                  : "pill-fail"
                            }`}
                          >
                            {item.circuitState}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pane-card">
              <div className="pane-header">
                <span className="pane-title">
                  Read-Only Linux eBPF Ring-Buffer Frame Inspector (ebpf/trace_spec.c)
                </span>
                <span className="pill pill-pass">READ-ONLY VERIFIED / 112 B FRAME</span>
              </div>
              <div className="data-table-wrap" style={{ border: "none", borderRadius: 0 }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>PID</th>
                      <th>FD</th>
                      <th>Comm</th>
                      <th>Bytes</th>
                      <th>Bounded 48-Byte Preview</th>
                    </tr>
                  </thead>
                  <tbody>
                    {SAMPLE_EBPF_FRAMES.map((frame) => (
                      <tr key={frame.timestampNs}>
                        <td className="mono">{frame.eventKind}</td>
                        <td className="mono">{frame.pid}</td>
                        <td className="mono">{frame.fd}</td>
                        <td className="mono">{frame.comm}</td>
                        <td className="mono">{frame.byteCount} B</td>
                        <td className="mono">{frame.preview}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {activeTab === "plugins" && (
          <>
            <div className="section-header">
              <div>
                <h2 className="section-title">Validated Community Mutation Plugins</h2>
                <p className="section-desc">
                  All manifests conform to <span className="mono">plugins/schema.json</span> and
                  combine deterministic Rust steps with optional local Ollama prompts.
                </p>
              </div>
            </div>

            <section className="plugin-grid">
              {PLUGIN_CATALOG.map((plugin) => (
                <article key={plugin.id} className="plugin-card">
                  <div className="plugin-top">
                    <div>
                      <h3 className="plugin-name">{plugin.name}</h3>
                      <div className="plugin-id">
                        {plugin.id} (aliases: {plugin.aliases.join(", ")})
                      </div>
                    </div>
                    <span className="pill">{plugin.targetKind}</span>
                  </div>
                  <p className="plugin-desc">{plugin.description}</p>
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                    <span className="pill">v{plugin.version}</span>
                    <span className="pill">author: {plugin.author}</span>
                    <span className="pill">policy: {plugin.failPolicy}</span>
                  </div>
                  <pre className="code-snippet">{plugin.rustHookTemplate}</pre>
                  <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
                    <button
                      type="button"
                      className="btn"
                      onClick={() => void copyHook(plugin.id, plugin.rustHookTemplate)}
                    >
                      {copiedPluginId === plugin.id ? "Copied" : "Copy Rust Hook"}
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => {
                        handleRuleChange(plugin.id);
                        setActiveTab("workbench");
                      }}
                    >
                      Load in Workbench
                    </button>
                  </div>
                </article>
              ))}
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
