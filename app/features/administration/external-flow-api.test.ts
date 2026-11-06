import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { decodeExternalFlows, updateExternalFlow } from "./external-flow-api";
const intent = { flow_id: "openrouter" as const, enabled: false, expected_version: 4, idempotency_key: "external-flow-retained-0001" };
const receipt = { flow_id: "openrouter", enabled: false, version: 5, idempotency_key: intent.idempotency_key };
const legacy = { id: "identity-provider", required: true, categories: ["identity_metadata"], enabled: true, health: "degraded" };
describe("external flow transport and server catalog", () => {
  it("accepts exact legacy read-only inventory and current optional metadata without inventing readiness", () => {
    const item = { id: "openrouter", name: "OpenRouter", required: false, categories: ["redacted_summary"], enabled: true, available: false, version: 4, health: "unknown" };
    expect(decodeExternalFlows({ items: [legacy, item] })).toEqual([legacy, item]);
    for (const value of [{ items: [legacy, legacy] }, { items: [{ ...item, available: "true" }] }, { items: [{ ...item, version: 0 }] }, { items: [{ ...item, untrusted: true }] }, { items: [{ ...item, categories: ["private_prompt"] }] }]) expect(() => decodeExternalFlows(value)).toThrow();
  });
  it("binds exact CAS intent and same key header using CSRF/fresh/scope shared transport", async () => {
    let sent!: Request;
    const client = createAPIClient({ getCSRFToken: () => "owned-csrf", getExpectedScope: () => "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003", fetch: async request => { sent = request; return new Response(JSON.stringify(receipt), { headers: { "Content-Type": "application/json" } }); } });
    expect(await updateExternalFlow(client, intent, new AbortController().signal)).toEqual(receipt);
    expect(sent.method).toBe("PATCH"); expect(await sent.json()).toEqual(intent);
    expect(sent.headers.get("Idempotency-Key")).toBe(intent.idempotency_key); expect(sent.headers.get("X-CSRF-Token")).toBe("owned-csrf"); expect(sent.headers.get("X-Zasp-Fresh-Auth")).toBe("confirmed"); expect(sent.headers.has("X-Zasp-Expected-Scope")).toBe(true);
  });
  it("rejects required or malformed intents before I/O and rejects mismatched success receipts", async () => {
    const fetch = vi.fn(); const client = createAPIClient({ fetch });
    for (const invalid of [{ ...intent, flow_id: "stytch" }, { ...intent, expected_version: 0 }, { ...intent, expected_version: 100000000000001 }, { ...intent, idempotency_key: "short" }, { ...intent, idempotency_key: "_" + "a".repeat(15) }]) await expect(updateExternalFlow(client, invalid as typeof intent, new AbortController().signal)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
    for (const bad of [{ ...receipt, flow_id: "posthog" }, { ...receipt, enabled: true }, { ...receipt, version: 4 }, { ...receipt, idempotency_key: "changed-retained-key" }, { ...receipt, extra: true }]) {
      const client = createAPIClient({ fetch: async () => new Response(JSON.stringify(bad), { headers: { "Content-Type": "application/json" } }) });
      await expect(updateExternalFlow(client, intent, new AbortController().signal)).rejects.toThrow();
    }
  });
});
