import { describe, expect, it } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import type { TestDefinition, TestDefinitionInput, TestRun } from "../../../apps/web/api/generated";
import { createProductionRedTeamAPI, type ProductionRedTeamAPI } from "./api";

const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const definitionID = "pid_93000001-0000-4000-8000-000000000001";
const targetID = "pid_93000002-0000-4000-8000-000000000002";
const runID = "pid_93000003-0000-4000-8000-000000000003";
const otherID = "pid_93000004-0000-4000-8000-000000000004";
const auditID = "pid_93000005-0000-4000-8000-000000000005";
const receiptID = "pid_93000006-0000-4000-8000-000000000006";
const attempt = { idempotencyKey: "redteam_authority_0001" };
const input: TestDefinitionInput = { id: definitionID, name: "Scoped safety", target_id: targetID, target_kind: "agent_endpoint", categories: ["prompt_injection", "tool_abuse"], safety: { environment: "staging", credential_class: "read_only", expected_side_effects: ["bounded evaluation"] } };
const definition: TestDefinition = { ...input, version: 1, enabled: true, created_at: "2026-09-08T10:00:00Z", updated_at: "2026-09-08T10:00:00Z" };
const run: TestRun = { id: runID, version: 1, definition_id: definitionID, definition_version: 1, status: "queued", attempt: 0, cancel_requested: false, queued_at: "2026-09-08T10:01:00Z" };
const update = { name: input.name, target_id: input.target_id, target_kind: input.target_kind, categories: input.categories, safety: input.safety, enabled: false };
const cancelled: TestRun = { ...run, version: 2, status: "cancelled", cancel_requested: true, completed_at: "2026-09-08T10:02:00Z", error_code: "cancelled" };

function apiReturning<T extends { readonly version: number }>(body: T, status = 200) {
  const requests: Request[] = [];
  const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf-value", fetch: async (request) => {
    requests.push(request.clone() as Request);
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ETag: `"${body.version}"`, "X-Audit-ID": auditID, "X-Mutation-Receipt-ID": receiptID } });
  } });
  return { api: createProductionRedTeamAPI(client), requests };
}

describe("production Red Team request-bound API", () => {
  const operations: { name: string; body: TestDefinition | TestRun | (TestRun & { attempts: readonly [] }); call(api: ProductionRedTeamAPI): Promise<unknown> }[] = [
    { name: "definition read", body: definition, call: (api) => api.getDefinition(definitionID) },
    { name: "definition create", body: definition, call: (api) => api.createDefinition(input, attempt) },
    { name: "definition update", body: { ...definition, enabled: false, version: 2 }, call: (api) => api.updateDefinition(definitionID, 1, update, attempt) },
    { name: "run create", body: run, call: (api) => api.runDefinition(definitionID, 1, runID, attempt) },
    { name: "run read", body: { ...run, attempts: [] }, call: (api) => api.getRun(runID) },
    { name: "run cancel", body: cancelled, call: (api) => api.cancelRun(runID, 1, attempt) },
  ];
  for (const operation of operations) {
    it(`${operation.name} accepts the exact response`, async () => {
      await expect(operation.call(apiReturning(operation.body).api)).resolves.toEqual(operation.body);
    });
    it(`${operation.name} rejects a schema-valid different resource`, async () => {
      await expect(operation.call(apiReturning({ ...operation.body, id: otherID }).api)).rejects.toMatchObject({ kind: "invalid_response" });
    });
  }
  for (const drift of [
    { name: "different target", patch: { target_id: otherID } },
    { name: "different categories", patch: { categories: ["data_leakage"] } },
    { name: "different name", patch: { name: "Unexpected definition" } },
    { name: "different safety", patch: { safety: { ...input.safety, credential_class: "test_write" } } },
    { name: "disabled create", patch: { enabled: false } },
    { name: "wrong creation version", patch: { version: 2 } },
  ]) {
    it(`rejects ${drift.name} in a creation receipt`, async () => {
      await expect(apiReturning({ ...definition, ...drift.patch }).api.createDefinition(input, attempt)).rejects.toMatchObject({ kind: "invalid_response" });
    });
  }
  it("accepts canonical set ordering without accepting changed members", async () => {
    const body = { ...definition, categories: [...definition.categories].reverse() };
    await expect(apiReturning(body).api.createDefinition(input, attempt)).resolves.toEqual(body);
  });
  it("rejects an update that did not apply the requested enable state", async () => {
    await expect(apiReturning({ ...definition, version: 2 }).api.updateDefinition(definitionID, 1, update, attempt)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  for (const patch of [{ definition_id: otherID }, { definition_version: 2 }, { version: 2 }, { cancel_requested: true }]) {
    it(`rejects run receipt drift ${JSON.stringify(patch)}`, async () => {
      await expect(apiReturning({ ...run, ...patch }).api.runDefinition(definitionID, 1, runID, attempt)).rejects.toMatchObject({ kind: "invalid_response" });
    });
  }
  it("rejects a cancellation receipt without cancellation authority", async () => {
    await expect(apiReturning({ ...run, version: 2 }).api.cancelRun(runID, 1, attempt)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it("accepts an exact leased cancellation request without claiming terminal cleanup", async () => {
    const body: TestRun = { ...run, version: 3, status: "leased", attempt: 1, cancel_requested: true, started_at: "2026-09-08T10:01:01Z" };
    await expect(apiReturning(body).api.cancelRun(runID, 2, attempt)).resolves.toEqual(body);
  });
  it("accepts the same stored creation receipt on an exact retry", async () => {
    const { api, requests } = apiReturning(run, 202);
    await expect(api.runDefinition(definitionID, 1, runID, attempt)).resolves.toEqual(run);
    await expect(api.runDefinition(definitionID, 1, runID, attempt)).resolves.toEqual(run);
    expect(requests.map((request) => request.headers.get("Idempotency-Key"))).toEqual([attempt.idempotencyKey, attempt.idempotencyKey]);
    expect(await requests[0]!.json()).toEqual(await requests[1]!.json());
  });
  it("preserves exact request identity and version on transport", async () => {
    const { api, requests } = apiReturning(run, 202);
    await api.runDefinition(definitionID, 1, runID, attempt);
    expect(new URL(requests[0]!.url).pathname).toBe(`/api/v1/tests/${definitionID}/runs`);
    expect(requests[0]!.headers.get("If-Match")).toBe('"1"');
    expect(requests[0]!.headers.get("Idempotency-Key")).toBe(attempt.idempotencyKey);
    expect(await requests[0]!.json()).toEqual({ run_id: runID });
  });
});
