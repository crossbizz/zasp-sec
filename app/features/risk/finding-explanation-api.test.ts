import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { createFindingExplanationAPI, decodeFindingExplanation, findingExplanationVersion } from "./finding-explanation-api";

const intent = { finding_id: "pid_20000001-0000-4000-8000-000000000001", finding_version: 7, idempotency_key: "test-request-00000001" };
const complete = { request_id: "pid_20000001-0000-4000-8000-000000000002", state: "complete", result_retained: false, source: { finding_id: intent.finding_id, finding_version: 7 }, sent_fields: ["rule", "severity", "evidence_count"], explanation: "Check the current evidence.", recommendation: "Review scope." };

describe("finding explanation transport", () => {
  it("sends only the finding intent through authenticated, CSRF and scoped shared transport", async () => {
    const requests: Request[] = [];
    const api = createFindingExplanationAPI(createAPIClient({ getCSRFToken: () => "owned-csrf", getExpectedScope: () => "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003", fetch: async request => { requests.push(request); return new Response(JSON.stringify(complete), { headers: { "Content-Type": "application/json" } }); } }));
    const controller = new AbortController();
    expect(await api.createAIExplanation(intent, controller.signal)).toEqual(complete);
    const request = requests[0];
    expect(request.method).toBe("POST"); expect(new URL(request.url).pathname).toBe("/api/v1/ai/explanations");
    expect(await request.json()).toEqual(intent); expect(request.headers.get("Idempotency-Key")).toBe(intent.idempotency_key);
    expect(request.headers.get("X-CSRF-Token")).toBe("owned-csrf"); expect(request.headers.has("X-Zasp-Expected-Scope")).toBe(true); expect(request.credentials).toBe("same-origin");
  });
  it("rejects invalid intent before I/O and parses only safe quoted versions", async () => {
    const fetch = vi.fn(); const api = createFindingExplanationAPI(createAPIClient({ fetch }));
    for (const finding_version of [0, -1, 1.5, 1000001, Number.MAX_SAFE_INTEGER + 1]) await expect(api.createAIExplanation({ ...intent, finding_version }, new AbortController().signal)).rejects.toThrow();
    for (const idempotency_key of ["a".repeat(15), "_" + "a".repeat(15), "a".repeat(129)]) await expect(api.createAIExplanation({ ...intent, idempotency_key }, new AbortController().signal)).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
    for (const etag of ["7", 'W/"7"', '"0"', '"01"', '"7.0"', '"1000001"', '"9007199254740992"', '"7"\n']) expect(findingExplanationVersion(etag)).toBeNull();
    expect(findingExplanationVersion('"7"')).toBe(7); expect(findingExplanationVersion('"1000000"')).toBe(1000000);
  });
  it("accepts metadata-only complete replay and pending states, but rejects foreign source and untrusted shape", () => {
    const metadata = Object.fromEntries(Object.entries(complete).filter(([key]) => key !== "explanation" && key !== "recommendation"));
    for (const state of ["reserved", "started", "complete", "failed", "unknown"]) expect(decodeFindingExplanation({ ...metadata, state }, intent).state).toBe(state);
    for (const response of [
      { ...complete, source: { ...complete.source, finding_version: 8 } },
      { ...complete, source: { ...complete.source, finding_id: complete.request_id } },
      { ...complete, sent_fields: ["rule", "severity", "evidence_contents"] },
      { ...complete, state: ["complete"] }, { ...complete, state: { value: "complete" } }, { ...complete, state: 1 },
      { ...complete, result_retained: true }, { ...complete, raw_response: "private" },
      { ...complete, state: "unknown" }, { ...complete, explanation: "x".repeat(2049) },
      { ...complete, source: { ...complete.source, title: "private" } },
    ]) expect(() => decodeFindingExplanation(response, intent)).toThrow();
  });
});
