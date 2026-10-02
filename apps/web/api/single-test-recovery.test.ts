import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "./client";
import { decodeSingleTestRecovery, getSingleTestRecovery, requestSingleTestRecovery } from "./single-test-recovery";
import { createSingleTestRecoveryIntent } from "../../../app/features/securityagents/recovery-intent";

const id = "pid_78000003-0000-4000-8000-000000000003";
const other = "pid_78000004-0000-4000-8000-000000000004";
const scope = { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" };
const identity = { definition_version: 3, input_digest: "a".repeat(64) };
const initial = { run_id: id, parent_version: 7, status: "not_requested", reason: "not_requested", request_identity: identity, command: null, accepted_at: null, completion: null };
const command = { command_id: other, command_digest: "b".repeat(64), start: { ref: { ...scope, run_id: id }, ...identity } };
const queued = { ...initial, parent_version: 8, status: "queued", reason: "queued", command, accepted_at: "2026-09-27T19:00:00.000001Z" };
const complete = { ...queued, status: "complete", reason: "verified", completion: { receipt_id: other, evidence_kind: "stop", evidence_digest: "c".repeat(64), outcome: "needs_human", completed_at: "2026-09-27T19:01:00Z" } };
function response(body: unknown, status = 200, extra = {}) { return new Response(JSON.stringify(body), { status, headers: {
  "Content-Type": "application/json", "Cache-Control": "no-store", "ETag": `"${(body as typeof initial).parent_version}"`,
  "X-Audit-ID": id, "X-Mutation-Receipt-ID": other, ...extra,
} }); }
describe("scoped SingleTest recovery client", () => {
  it.each([initial, queued, complete, { ...complete, command: null, completion: { ...complete.completion, evidence_kind: "already_complete" } }])("accepts truthful closed view %#", body => {
    expect(decodeSingleTestRecovery(body, id, scope)).toEqual(body);
  });
  it.each([
    { ...initial, extra: true }, { ...initial, run_id: other }, { ...initial, parent_version: 1.5 },
    { ...initial, request_identity: { ...identity, input_digest: "child digest" } },
    { ...initial, command }, { ...initial, accepted_at: queued.accepted_at },
    { ...queued, reason: "verified" }, { ...queued, command: null },
    { ...queued, command: { ...command, start: { ...command.start, input_digest: "d".repeat(64) } } },
    { ...queued, command: { ...command, start: { ...command.start, ref: { ...scope, run_id: id, organization_id: other } } } },
    { ...queued, accepted_at: "2026-02-30T19:00:00Z" },
    { ...complete, completion: null }, { ...complete, completion: { ...complete.completion, outcome: "success" } },
    { ...complete, command: null }, { ...complete, completion: { ...complete.completion, evidence_kind: "already_complete" } },
  ])("rejects mismatched authority or evidence %#", body => { expect(() => decodeSingleTestRecovery(body, id, scope)).toThrow(); });
  it("uses the real API client with pinned scope, no cache and cancellation", async () => {
    const fetcher = vi.fn(async (_request: Request) => response(initial));
    const controller = new AbortController();
    const client = createAPIClient({ fetch: fetcher });
    expect(await getSingleTestRecovery(client, id, scope, controller.signal)).toEqual(initial);
    const request = fetcher.mock.calls[0]![0];
    expect(new URL(request.url).pathname).toBe(`/api/v1/security-agent-runs/${id}/cleanup-recovery`);
    expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(Object.values(scope).join("/"));
    controller.abort(); expect(request.signal.aborted).toBe(true);
  });
  it("sends explicit retained body/version/key and accepts only matching receipt identity", async () => {
    const fetcher = vi.fn(async (_request: Request) => response(queued, 202));
    const client = createAPIClient({ fetch: fetcher, getCSRFToken: () => "csrf-token" });
    const intent = createSingleTestRecoveryIntent(initial, id, 7);
    const attempt = { idempotencyKey: "wf_78000005-0000-4000-8000-000000000005" };
    const result = await requestSingleTestRecovery(client, intent, scope, attempt);
    expect(result.value).toEqual(queued);
    const request = fetcher.mock.calls[0]![0];
    expect(request.method).toBe("POST"); expect(request.headers.get("If-Match")).toBe('"7"');
    expect(request.headers.get("Idempotency-Key")).toBe(attempt.idempotencyKey);
    expect(await request.json()).toEqual(intent.body);
  });
  it("rejects cacheable views and response ETag mismatch", async () => {
    for (const headers of [{ "Cache-Control": "public" }, { ETag: '"99"' }]) {
      const client = createAPIClient({ fetch: async () => response(initial, 200, headers) });
      await expect(getSingleTestRecovery(client, id, scope)).rejects.toThrow();
    }
  });
  it("rejects foreign scope before transport", async () => {
    const fetcher = vi.fn(async () => response(initial));
    await expect(getSingleTestRecovery(createAPIClient({ fetch: fetcher }), id, { ...scope, organization_id: "bad" })).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
});
