import { describe, expect, it } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import type { TestProbeCatalog, TestSchedule, TestScheduleInput } from "../../../apps/web/api/generated";
import { createProductionRedTeamAPI } from "./api";

// The probe library and the re-test schedule of a red team definition:
//   GET /api/v1/test-probes            getProbeCatalog
//   GET /api/v1/tests/{id}/schedule    getSchedule
//   PUT /api/v1/tests/{id}/schedule    putSchedule
const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const definitionID = "pid_94000001-0000-4000-8000-000000000001";
const otherID = "pid_94000002-0000-4000-8000-000000000002";
const names = ["prompt_injection", "tool_abuse", "data_leakage", "authorization_bypass", "excessive_agency", "sensitive_information", "indirect_injection", "poisoned_resource", "cross_agent_delegation"] as const;
const catalog: TestProbeCatalog = {
  version: "zasp-probe-library-v1", digest: "b".repeat(64), probe_count: 1080, default_sample_size: 25,
  categories: names.map((category) => ({ category, title: category.replaceAll("_", " "), probe_count: 120, techniques: ["direct_override"], frameworks: [{ framework: "owasp_llm_top10_2025" as const, control: "LLM01", title: "Prompt Injection" }] })),
};
const unsaved: TestSchedule = { definition_id: definitionID, version: 0, enabled: false, cadence_seconds: null, on_target_change: false, next_run_at: null, last_run_id: null, last_trigger: null, last_outcome: null, last_fired_at: null, updated_at: null };
const saved: TestSchedule = { ...unsaved, version: 1, enabled: true, cadence_seconds: 86400, on_target_change: true, next_run_at: "2026-11-15T10:00:00Z", updated_at: "2026-11-14T10:00:00Z" };

function apiReturning(body: unknown, status = 200) {
  const requests: Request[] = [];
  const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf-value", fetch: async (request) => {
    requests.push(request.clone() as Request);
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } });
  return { api: createProductionRedTeamAPI(client, scope), requests };
}

describe("red team probe library client", () => {
  it("reads the probe catalog with the request scope", async () => {
    const { api, requests } = apiReturning(catalog);
    await expect(api.getProbeCatalog()).resolves.toEqual(catalog);
    expect(requests).toHaveLength(1);
    expect(new URL(requests[0].url).pathname).toBe("/api/v1/test-probes");
    expect(requests[0].method).toBe("GET");
    expect(requests[0].headers.get("X-Zasp-Expected-Scope")).toBe(scope);
  });

  it("rejects a catalog whose counts disagree", async () => {
    await expect(apiReturning({ ...catalog, probe_count: 1081 }).api.getProbeCatalog()).rejects.toMatchObject({ kind: "invalid_response" });
  });
});

describe("red team schedule client", () => {
  it("reads the schedule of the named definition", async () => {
    const { api, requests } = apiReturning(saved);
    await expect(api.getSchedule(definitionID)).resolves.toEqual(saved);
    expect(new URL(requests[0].url).pathname).toBe(`/api/v1/tests/${definitionID}/schedule`);
    expect(requests[0].headers.get("X-Zasp-Expected-Scope")).toBe(scope);
  });

  it("reads an unsaved schedule as version 0", async () => {
    await expect(apiReturning(unsaved).api.getSchedule(definitionID)).resolves.toMatchObject({ version: 0, enabled: false });
  });

  it("rejects the schedule of another definition", async () => {
    await expect(apiReturning({ ...saved, definition_id: otherID }).api.getSchedule(definitionID)).rejects.toMatchObject({ kind: "invalid_response" });
  });

  it("refuses a malformed definition id before any request", async () => {
    const { api, requests } = apiReturning(saved);
    await expect(api.getSchedule("not-an-id")).rejects.toBeTruthy();
    await expect(api.putSchedule("not-an-id", { expected_version: 0, enabled: false, on_target_change: false })).rejects.toBeTruthy();
    expect(requests).toHaveLength(0);
  });

  it("saves a schedule with the expected version, an idempotency key and the exact body", async () => {
    const input: TestScheduleInput = { expected_version: 0, enabled: true, cadence_seconds: 86400, on_target_change: true };
    const { api, requests } = apiReturning(saved);
    await expect(api.putSchedule(definitionID, input)).resolves.toEqual(saved);
    expect(requests).toHaveLength(1);
    const request = requests[0];
    expect(request.method).toBe("PUT");
    expect(new URL(request.url).pathname).toBe(`/api/v1/tests/${definitionID}/schedule`);
    expect(request.headers.get("Idempotency-Key")).toMatch(/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/);
    expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(scope);
    expect(await request.json()).toEqual(input);
  });

  it("uses a new idempotency key for each save", async () => {
    const { api, requests } = apiReturning(saved);
    const input: TestScheduleInput = { expected_version: 0, enabled: true, cadence_seconds: 86400, on_target_change: true };
    await api.putSchedule(definitionID, input);
    await api.putSchedule(definitionID, input);
    expect(requests[0].headers.get("Idempotency-Key")).not.toBe(requests[1].headers.get("Idempotency-Key"));
  });

  it.each([
    ["a negative version", { expected_version: -1, enabled: false, on_target_change: false }],
    ["a fractional version", { expected_version: 0.5, enabled: false, on_target_change: false }],
    ["an enabled schedule with no cadence and no target-change trigger", { expected_version: 0, enabled: true, on_target_change: false }],
  ])("refuses %s before any request", async (_name, input) => {
    const { api, requests } = apiReturning(saved);
    await expect(api.putSchedule(definitionID, input as TestScheduleInput)).rejects.toMatchObject({ kind: "invalid_configuration" });
    expect(requests).toHaveLength(0);
  });

  it("accepts an enabled schedule that only re-tests on a target change", async () => {
    const changeOnly: TestSchedule = { ...saved, cadence_seconds: null, next_run_at: null };
    await expect(apiReturning(changeOnly).api.putSchedule(definitionID, { expected_version: 0, enabled: true, on_target_change: true })).resolves.toEqual(changeOnly);
  });

  it.each([
    ["another definition", { definition_id: otherID }],
    ["a version that is not the next one", { version: 2 }],
    ["a different enabled state", { enabled: false, next_run_at: null }],
    ["a different target-change trigger", { on_target_change: false }],
    ["a different cadence", { cadence_seconds: 7200 }],
  ])("rejects a saved schedule with %s", async (_name, patch) => {
    const { api } = apiReturning({ ...saved, ...patch });
    await expect(api.putSchedule(definitionID, { expected_version: 0, enabled: true, cadence_seconds: 86400, on_target_change: true })).rejects.toMatchObject({ kind: "invalid_response" });
  });

  it("reports a version conflict from the server as a product error", async () => {
    const { api } = apiReturning({ code: "version_conflict", message: "The schedule changed.", correlation_id: "pid_94000003-0000-4000-8000-000000000003", retryable: false }, 409);
    await expect(api.putSchedule(definitionID, { expected_version: 0, enabled: true, cadence_seconds: 86400, on_target_change: true })).rejects.toMatchObject({ name: "APIProductError", status: 409, product: { code: "version_conflict" } });
  });
});
