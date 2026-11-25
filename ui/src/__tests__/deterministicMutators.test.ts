import { describe, expect, it } from "vitest";
import {
  asciiTableToJson,
  createCircuitTracker,
  executeWorkbenchMutation,
  formatMutationValue,
  redactPiiText,
  translateV1ToV2Api,
  xmlToJson,
} from "../lib/deterministicMutators";

describe("Deterministic client-side mutators", () => {
  it("parses fixed-width legacy CLI ASCII tables into typed JSON records", () => {
    const raw = [
      "PID     SERVICE         STATE     MEM_MB   HEALTHY",
      "---------------------------------------------------",
      "1042    auth-gateway    RUNNING   128.4    true",
      "1188    ledger-worker   DEGRADED  512.0    false",
    ].join("\n");

    const rows = asciiTableToJson(raw);
    expect(rows).toEqual([
      { pid: 1042, service: "auth-gateway", state: "RUNNING", mem_mb: 128.4, healthy: true },
      { pid: 1188, service: "ledger-worker", state: "DEGRADED", mem_mb: 512, healthy: false },
    ]);

    const csv = formatMutationValue(rows, "csv");
    expect(csv.split("\n")[0]).toBe("pid,service,state,mem_mb,healthy");
  });

  it("translates XML payloads with attributes and repeated tags into structured JSON", () => {
    const xml = `<?xml version="1.0"?>
      <OrderResponse status="CONFIRMED">
        <OrderId>ORD-77</OrderId>
        <Item sku="A1"><Qty>2</Qty></Item>
        <Item sku="B2"><Qty>3</Qty></Item>
      </OrderResponse>`;
    const parsed = xmlToJson(xml) as { order_response: Record<string, unknown> };
    expect(parsed.order_response["@status"]).toBe("CONFIRMED");
    expect(parsed.order_response.order_id).toBe("ORD-77");
    expect(Array.isArray(parsed.order_response.item)).toBe(true);
  });

  it("migrates legacy v1 API payloads to v2 camelCase contracts", () => {
    const out = translateV1ToV2Api(
      JSON.stringify({
        usr_id: "u_99",
        usr_name: "Grace Hopper",
        acct_bal_cents: 4200,
        legacy_debug_flag: 1,
        billing_tier: "enterprise",
      })
    );
    expect(out).toEqual({
      userId: "u_99",
      displayName: "Grace Hopper",
      balanceCents: 4200,
      billingTier: "enterprise",
      apiVersion: "v2",
    });
  });

  it("redacts emails, IPv4, SSNs, phones, and bearer tokens while preserving 127.0.0.1", () => {
    const res = redactPiiText(
      "user=dev@acme.io ip=10.2.3.4 local=127.0.0.1 ssn=123-45-6789 phone=415-555-0199 Bearer secret_token_123456"
    );
    expect(res.scrubbed).toContain("[REDACTED:EMAIL]");
    expect(res.scrubbed).toContain("[REDACTED:IPV4]");
    expect(res.scrubbed).toContain("127.0.0.1");
    expect(res.scrubbed).toContain("[REDACTED:SSN]");
    expect(res.scrubbed).toContain("[REDACTED:PHONE]");
    expect(res.scrubbed).toContain("Bearer [REDACTED:TOKEN]");
    expect(res.redacted_total).toBe(5);
  });

  it("executes deterministic workbench mutations with zero-crash telemetry", async () => {
    const { result, nextCircuit } = await executeWorkbenchMutation({
      ruleId: "cli-table-to-json",
      input: "ID  NAME\n1   alpha\n2   beta",
      engine: "deterministic",
      format: "ndjson",
      ollamaUrl: "http://127.0.0.1:11434",
      ollamaModel: "llama3.2",
      llmPrompt: "Convert to JSON",
      circuit: createCircuitTracker(),
    });
    expect(result.mutated).toBe(true);
    expect(result.engineUsed).toBe("deterministic");
    expect(nextCircuit.state).toBe("closed");
    expect(result.output.split("\n")).toHaveLength(2);
  });
});
