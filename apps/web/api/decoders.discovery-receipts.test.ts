import { describe, expect, it } from "vitest";

import { decodeWorkflowMutationReceipt } from "./decoders";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const syncID = "pid_20000002-0000-4000-8000-000000000002";
const scopeKey = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const scope = {
  organization_id: "pid_10000001-0000-4000-8000-000000000001",
  workspace_id: "pid_10000002-0000-4000-8000-000000000002",
  environment_id: "pid_10000003-0000-4000-8000-000000000003",
};
const sync = {
  id: syncID, integration_id: integrationID, trigger_kind: "manual", status: "queued", attempt: 0,
  requested_at: "2026-08-19T00:00:00Z", started_at: null, completed_at: null,
  discovered_count: 0, changed_count: 0, removed_count: 0, snapshot_id: null, last_error_code: null, retry_at: null,
};
const schedule = {
  integration_id: integrationID, cadence_seconds: 3600, state: "enabled", time_zone: "UTC", next_run_at: "2026-08-19T01:00:00Z",
  version: 2, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z",
};
const base = {
  id: "pid_11111111-1111-4111-8111-111111111111",
  idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
  audit_id: "pid_33333333-3333-4333-8333-333333333333",
  correlation_id: "pid_44444444-4444-4444-8444-444444444444",
  created_at: "2026-08-19T00:00:00Z",
  expires_at: "2026-08-25T00:00:00Z",
};

function syncReceipt() {
  return { ...base, operation: "syncIntegration", resource_kind: "integration_sync", resource_id: syncID, resource_version: 1, result: sync,
    intent: { body: {}, expected_version: 5, idempotency_key: base.idempotency_key, integration_id: integrationID, scope } };
}

function putScheduleReceipt() {
  return { ...base, operation: "putIntegrationSchedule", resource_kind: "integration_schedule", resource_id: integrationID, resource_version: 2, result: schedule,
    intent: { body: { cadence_seconds: 3600, state: "enabled" }, expected_version: 1, idempotency_key: base.idempotency_key, integration_id: integrationID, scope } };
}

function deleteScheduleReceipt() {
  return { ...base, operation: "deleteIntegrationSchedule", resource_kind: "integration_schedule", resource_id: integrationID, resource_version: 3,
    result: { ...schedule, state: "deleted", next_run_at: null, version: 3, updated_at: "2026-08-19T00:00:02Z" },
    intent: { body: {}, expected_version: 2, idempotency_key: base.idempotency_key, integration_id: integrationID, scope } };
}

describe("discovery workflow receipt decoding", () => {
  it.each([syncReceipt(), putScheduleReceipt(), deleteScheduleReceipt()])("accepts exact scoped $operation receipts", (value) => {
    expect(decodeWorkflowMutationReceipt(value, scopeKey)).toEqual(value);
  });

  it.each([
    ["missing captured scope", syncReceipt(), undefined],
    ["foreign captured scope", syncReceipt(), "pid_90000001-0000-4000-8000-000000000001/pid_90000002-0000-4000-8000-000000000002/pid_90000003-0000-4000-8000-000000000003"],
    ["sync intent key mismatch", { ...syncReceipt(), intent: { ...syncReceipt().intent, idempotency_key: "wf_99999999-9999-4999-8999-999999999999" } }, scopeKey],
    ["foreign sync integration", { ...syncReceipt(), result: { ...sync, integration_id: "pid_20000009-0000-4000-8000-000000000009" } }, scopeKey],
    ["non-manual sync result", { ...syncReceipt(), result: { ...sync, trigger_kind: "schedule" } }, scopeKey],
    ["schedule version drift", { ...putScheduleReceipt(), result: { ...schedule, version: 99 } }, scopeKey],
    ["schedule body drift", { ...putScheduleReceipt(), intent: { ...putScheduleReceipt().intent, body: { cadence_seconds: 7200, state: "enabled" } } }, scopeKey],
    ["delete without tombstone", { ...deleteScheduleReceipt(), result: { ...schedule, version: 3 } }, scopeKey],
    ["undeclared schedule intent", { ...putScheduleReceipt(), intent: { ...putScheduleReceipt().intent, scheduler_id: syncID } }, scopeKey],
  ])("rejects %s", (_name, value, captured) => {
    expect(() => decodeWorkflowMutationReceipt(value, captured)).toThrow("schema mismatch");
  });
});
