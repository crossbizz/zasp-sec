import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { IntegrationFreshness, IntegrationSchedule, IntegrationSync } from "../../../apps/web/api/generated";
import { createIntegrationsAPI, createWorkflowMutationAttempt, createWorkflowReceiptReconciler, IntegrationDiscoveryConflict } from "./api";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const syncID = "pid_20000002-0000-4000-8000-000000000002";
const snapshotID = "pid_20000003-0000-4000-8000-000000000003";
const receiptHeaders = { ETag: '"1"', "Cache-Control": "no-store", "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001", "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002" };
const sync: IntegrationSync = {
  id: syncID, integration_id: integrationID, trigger_kind: "manual", status: "queued", attempt: 0,
  requested_at: "2026-08-19T00:00:00Z", started_at: null, completed_at: null,
  discovered_count: 0, changed_count: 0, removed_count: 0, snapshot_id: null, last_error_code: null, retry_at: null,
};
const schedule: IntegrationSchedule = {
  integration_id: integrationID, cadence_seconds: 3600, state: "enabled", time_zone: "UTC", next_run_at: "2026-08-19T01:00:00Z",
  version: 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z",
};
const freshness: IntegrationFreshness = {
  integration_id: integrationID, version: 7,
  last_good: { snapshot_id: snapshotID, collected_at: "2026-08-19T00:00:02Z", discovered_count: 10, changed_count: 3, removed_count: 1 },
  latest_sync: { ...sync, status: "succeeded", attempt: 1, started_at: "2026-08-19T00:00:01Z", completed_at: "2026-08-19T00:00:02Z", discovered_count: 10, changed_count: 3, removed_count: 1, snapshot_id: snapshotID },
  projections: {
    risk: { state: "current", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: null },
    graph: { state: "pending", snapshot_id: snapshotID, completed_at: null, last_error_code: null },
    search: { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "retryable" },
  }, updated_at: "2026-08-19T00:00:04Z",
};

describe("production integration discovery API", () => {
  it("strictly binds freshness, schedule, sync detail, and every history page to the requested integration", async () => {
    const GET = vi.fn(async (path: string, options: { params?: { query?: { cursor?: string } } }) => {
      if (path === "/api/v1/integrations/{id}/freshness") return result(freshness, 200, { ETag: '"7"', "Cache-Control": "no-store" });
      if (path === "/api/v1/integrations/{id}/schedule") return result(schedule, 200, { ETag: '"1"', "Cache-Control": "no-store" });
      if (path === "/api/v1/integrations/{id}/syncs/{syncId}") return result(sync, 200, { ETag: '"1"', "Cache-Control": "no-store" });
      if (path === "/api/v1/integrations/{id}/syncs") {
        const continuing = options.params?.query?.cursor === undefined;
        return result({ items: [sync], page_info: continuing ? { next_cursor: "b3JnLXBhZ2UtMg", has_more: true } : { next_cursor: null, has_more: false } }, 200, { "Cache-Control": "no-store" });
      }
      throw new Error(`unexpected GET ${path}`);
    });
    const api = createIntegrationsAPI({ GET } as unknown as APIClient);

    await expect(api.getIntegrationFreshness(integrationID)).resolves.toEqual({ value: freshness, version: '"7"' });
    await expect(api.getIntegrationSchedule(integrationID)).resolves.toEqual({ value: schedule, version: '"1"' });
    await expect(api.getIntegrationSync(integrationID, syncID)).resolves.toEqual({ value: sync, version: '"1"' });
    await expect(api.listIntegrationSyncs(integrationID)).resolves.toEqual([sync, sync]);
    expect(GET).toHaveBeenCalledWith("/api/v1/integrations/{id}/syncs", expect.objectContaining({ params: { path: { id: integrationID }, query: { cursor: "b3JnLXBhZ2UtMg", limit: 100 } } }));
  });

  it("treats an authorized not-found schedule as an absent singleton", async () => {
    const GET = vi.fn(async () => productError(404, "not_found"));
    await expect(createIntegrationsAPI({ GET } as unknown as APIClient).getIntegrationSchedule(integrationID)).resolves.toBeNull();
  });

  it("accepts a durable manual sync only as exact no-store 202 and retains its mutation authority", async () => {
    const POST = vi.fn(async () => result(sync, 202, receiptHeaders));
    const attempt = createWorkflowMutationAttempt();
    await expect(createIntegrationsAPI({ POST } as unknown as APIClient).syncIntegration(integrationID, '"5"', attempt)).resolves.toEqual({ value: sync, version: '"1"', auditID: receiptHeaders["X-Audit-ID"], receiptID: receiptHeaders["X-Mutation-Receipt-ID"] });
    expect(POST).toHaveBeenCalledWith("/api/v1/integrations/{id}/sync", { params: { path: { id: integrationID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"5"' } }, body: {} });
  });

  it("replays a lost sync response with the exact idempotency key, If-Match, and empty intent", async () => {
    const POST = vi.fn()
      .mockRejectedValueOnce(new TypeError("response lost after commit"))
      .mockResolvedValueOnce(result(sync, 202, receiptHeaders));
    await expect(createIntegrationsAPI({ POST } as unknown as APIClient).syncIntegration(integrationID, '"5"')).resolves.toMatchObject({ value: sync });
    const calls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> }; body: unknown }]>;
    expect(calls).toHaveLength(2);
    expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
    expect(calls.map(([, options]) => options.params.header["If-Match"])).toEqual(['"5"', '"5"']);
    expect(calls.map(([, options]) => options.body)).toEqual([{}, {}]);
  });

  it.each([
    ["foreign integration", { ...sync, integration_id: "pid_20000009-0000-4000-8000-000000000009" }, receiptHeaders],
    ["non-manual result", { ...sync, trigger_kind: "schedule" }, receiptHeaders],
    ["non-queued result", { ...sync, status: "running", started_at: "2026-08-19T00:00:01Z" }, receiptHeaders],
    ["prepopulated queued counts", { ...sync, discovered_count: 1 }, receiptHeaders],
    ["missing no-store", sync, { ...receiptHeaders, "Cache-Control": "private" }],
  ])("rejects a sync response with %s", async (_name, value, headers) => {
    const POST = vi.fn(async () => result(value, 202, headers));
    await expect(createIntegrationsAPI({ POST } as unknown as APIClient).syncIntegration(integrationID, '"5"')).rejects.toMatchObject({ kind: "invalid_response" });
  });

  it("turns sync and schedule 409s into locked authoritative-refetch conflicts", async () => {
    const client = { POST: vi.fn(async () => productError(409, "conflict")), PUT: vi.fn(async () => productError(409, "conflict")), DELETE: vi.fn(async () => productError(409, "conflict")) } as unknown as APIClient;
    const api = createIntegrationsAPI(client);
    await expect(api.syncIntegration(integrationID, '"5"')).rejects.toBeInstanceOf(IntegrationDiscoveryConflict);
    await expect(api.putIntegrationSchedule(integrationID, '"0"', { cadence_seconds: 3600, state: "enabled" })).rejects.toBeInstanceOf(IntegrationDiscoveryConflict);
    await expect(api.deleteIntegrationSchedule(integrationID, '"1"')).rejects.toBeInstanceOf(IntegrationDiscoveryConflict);
  });

  it("creates and deletes the UTC singleton with exact versions, receipts, and retained headers", async () => {
    const attempt = createWorkflowMutationAttempt();
    const PUT = vi.fn(async () => result(schedule, 200, receiptHeaders));
    const DELETE = vi.fn(async () => ({ response: new Response(null, { status: 204, headers: { ...receiptHeaders, ETag: '"2"' } }) }));
    const api = createIntegrationsAPI({ PUT, DELETE } as unknown as APIClient);

    await expect(api.putIntegrationSchedule(integrationID, '"0"', { cadence_seconds: 3600, state: "enabled" }, attempt)).resolves.toMatchObject({ value: schedule, version: '"1"' });
    await expect(api.deleteIntegrationSchedule(integrationID, '"1"', attempt)).resolves.toMatchObject({ value: undefined, version: '"2"' });
    expect(PUT).toHaveBeenCalledWith("/api/v1/integrations/{id}/schedule", { params: { path: { id: integrationID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"0"' } }, body: { cadence_seconds: 3600, state: "enabled" } });
    expect(DELETE).toHaveBeenCalledWith("/api/v1/integrations/{id}/schedule", { params: { path: { id: integrationID }, header: { "Idempotency-Key": attempt.idempotencyKey, "If-Match": '"1"' } } });
  });

  it("authoritatively reconciles sync and schedule receipts before acknowledgement", async () => {
    const capturedScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
    const GET = vi.fn(async (path: string) => {
      if (path === "/api/v1/integrations/{id}/syncs/{syncId}") return result(sync, 200, { ETag: '"1"', "Cache-Control": "no-store" });
      if (path === "/api/v1/integrations/{id}/schedule") return result(schedule, 200, { ETag: '"1"', "Cache-Control": "no-store" });
      throw new Error(`unexpected GET ${path}`);
    });
    const reconcile = createWorkflowReceiptReconciler({ GET } as unknown as APIClient, capturedScope);
    const scope = { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" };
    const receiptBase = { id: receiptHeaders["X-Mutation-Receipt-ID"], idempotency_key: "wf_11111111-1111-4111-8111-111111111111", audit_id: receiptHeaders["X-Audit-ID"], correlation_id: "pid_30000003-0000-4000-8000-000000000003", created_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-25T00:00:00Z" };
    const syncReceipt = { ...receiptBase, operation: "syncIntegration", resource_kind: "integration_sync", resource_id: syncID, resource_version: 1, result: sync, intent: { body: {}, expected_version: 5, idempotency_key: receiptBase.idempotency_key, integration_id: integrationID, scope } };
    const scheduleReceipt = { ...receiptBase, operation: "putIntegrationSchedule", resource_kind: "integration_schedule", resource_id: integrationID, resource_version: 1, result: schedule, intent: { body: { cadence_seconds: 3600, state: "enabled" }, expected_version: 0, idempotency_key: receiptBase.idempotency_key, integration_id: integrationID, scope } };

    await expect(reconcile(syncReceipt as never, new AbortController().signal)).resolves.toBeUndefined();
    await expect(reconcile(scheduleReceipt as never, new AbortController().signal)).resolves.toBeUndefined();
    expect(GET).toHaveBeenNthCalledWith(1, "/api/v1/integrations/{id}/syncs/{syncId}", expect.objectContaining({ params: { path: { id: integrationID, syncId: syncID } }, headers: { "X-Zasp-Expected-Scope": capturedScope } }));
    expect(GET).toHaveBeenNthCalledWith(2, "/api/v1/integrations/{id}/schedule", expect.objectContaining({ params: { path: { id: integrationID } }, headers: { "X-Zasp-Expected-Scope": capturedScope } }));
  });
});

function result(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return { data, response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }) };
}

function productError(status: number, code: string) {
  const error = { code, message: "request rejected", correlation_id: "pid_90000001-0000-4000-8000-000000000001", retryable: false };
  return { error, response: new Response(JSON.stringify(error), { status, headers: { "Content-Type": "application/json" } }) };
}
