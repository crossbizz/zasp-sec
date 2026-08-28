import { describe, expect, it } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import type { AttackLabPreflight, AttackLabRun } from "../../../apps/web/api/generated";
import { createProductionRedTeamAPI } from "./api";

const scope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const sourceRunID = "pid_91000001-0000-4000-8000-000000000001";
const runID = "pid_91000002-0000-4000-8000-000000000002";
const definitionID = "pid_91000003-0000-4000-8000-000000000003";
const targetID = "pid_91000004-0000-4000-8000-000000000004";
const auditID = "pid_91000005-0000-4000-8000-000000000005";
const receiptID = "pid_91000006-0000-4000-8000-000000000006";
const limits = { cpu: "500m", memory: "1Gi", ephemeral_storage: "2Gi", timeout_seconds: 300 } as const;
const preflight: AttackLabPreflight = { source_run_id: sourceRunID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", allowed_destinations: ["adapter.customer.example"], success_criterion: "Reject direct prompt injection", expected_side_effects: ["bounded evaluation"], decision_digest: "a".repeat(64), decision_expires_at: "2099-08-28T10:05:00Z", limits };
const queued: AttackLabRun = { id: runID, version: 1, source_run_id: sourceRunID, definition_id: definitionID, definition_version: 2, target_id: targetID, target_kind: "agent_endpoint", environment: "staging", credential_class: "read_only", destination: "adapter.customer.example", status: "queued", attempt: 0, cancel_requested: false, cleanup_state: "pending", limits, queued_at: "2026-08-28T10:00:00Z" };

describe("production Attack Lab API", () => {
  it("loads exact server-derived preflight before creating an approved run", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf-value", fetch: async (request) => {
      requests.push(request.clone() as Request);
      return new URL(request.url).pathname.endsWith("/preflight") ? jsonResponse(preflight) : jsonResponse(queued, 202, { ETag: '"1"', "X-Audit-ID": auditID, "X-Mutation-Receipt-ID": receiptID });
    } });
    const api = createProductionRedTeamAPI(client);
    await expect(api.preflightAttackLab(sourceRunID)).resolves.toEqual(preflight);
    await expect(api.createAttackLabRun(preflight, runID, { idempotencyKey: "attack_lab_create_0001" })).resolves.toEqual(queued);
    expect(new URL(requests[0]!.url).searchParams.get("source_run_id")).toBe(sourceRunID);
    expect(requests[1]!.headers.get("If-Match")).toBe('"0"');
    expect(requests[1]!.headers.get("Idempotency-Key")).toBe("attack_lab_create_0001");
    expect(await requests[1]!.json()).toEqual({ run_id: runID, source_run_id: sourceRunID, decision_digest: preflight.decision_digest, approved: true });
  });

  it("version-fences cancel and rerun while preserving the server-derived source", async () => {
    const requests: Request[] = [];
    const cancelled: AttackLabRun = { ...queued, version: 2, status: "cancelled", cancel_requested: true, cleanup_state: "complete", completed_at: "2026-08-28T10:01:00Z", error_code: "cancelled" };
    const rerun = { ...queued, id: "pid_91000007-0000-4000-8000-000000000007", source_run_id: queued.source_run_id } satisfies AttackLabRun;
    let call = 0;
    const client = createAPIClient({ getExpectedScope: () => scope, getCSRFToken: () => "csrf-value", fetch: async (request) => {
      requests.push(request.clone() as Request); call += 1; return jsonResponse(call === 1 ? cancelled : rerun, call === 1 ? 200 : 202, { ETag: `"${call === 1 ? 2 : 1}"`, "X-Audit-ID": auditID, "X-Mutation-Receipt-ID": receiptID });
    } });
    const api = createProductionRedTeamAPI(client);
    await expect(api.cancelAttackLabRun(runID, 1, { idempotencyKey: "attack_lab_cancel_0001" })).resolves.toEqual(cancelled);
    await expect(api.rerunAttackLabRun(runID, 2, rerun.id, { idempotencyKey: "attack_lab_rerun_00001" })).resolves.toEqual(rerun);
    expect(requests.map((request) => request.headers.get("If-Match"))).toEqual(['"1"', '"2"']);
    expect(await requests[1]!.json()).toEqual({ run_id: rerun.id });
  });
});

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
}
