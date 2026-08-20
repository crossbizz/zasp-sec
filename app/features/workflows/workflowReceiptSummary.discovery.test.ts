import { describe, expect, it } from "vitest";

import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";
import { workflowReceiptSummary } from "./workflowReceiptSummary";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const syncID = "pid_20000002-0000-4000-8000-000000000002";
const snapshotID = "pid_20000003-0000-4000-8000-000000000003";
const scope = { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003" };
const base = { id: "pid_11111111-1111-4111-8111-111111111111", idempotency_key: "wf_11111111-1111-4111-8111-111111111111", audit_id: "pid_33333333-3333-4333-8333-333333333333", correlation_id: "pid_44444444-4444-4444-8444-444444444444", created_at: "2026-08-19T00:00:00Z", expires_at: "2026-08-25T00:00:00Z" };

describe("safe discovery workflow receipt summaries", () => {
  it("summarizes a sync without exposing sync, snapshot, scope, or internal error identifiers", () => {
    const result = { id: syncID, integration_id: integrationID, trigger_kind: "manual", status: "succeeded", attempt: 1, requested_at: "2026-08-19T00:00:00Z", started_at: "2026-08-19T00:00:01Z", completed_at: "2026-08-19T00:00:02Z", discovered_count: 10, changed_count: 3, removed_count: 1, snapshot_id: snapshotID, last_error_code: null, retry_at: null };
    const receipt = { ...base, operation: "syncIntegration", resource_kind: "integration_sync", resource_id: syncID, resource_version: 1, result, intent: { body: {}, expected_version: 5, idempotency_key: base.idempotency_key, integration_id: integrationID, scope } } as WorkflowMutationReceipt;
    const serialized = JSON.stringify(workflowReceiptSummary(receipt));
    expect(serialized).toContain("Manual inventory sync");
    expect(serialized).toContain("succeeded");
    expect(serialized).toContain("10");
    for (const hidden of [syncID, snapshotID, scope.organization_id, scope.workspace_id, scope.environment_id, base.idempotency_key]) expect(serialized).not.toContain(hidden);
  });

  it.each(["putIntegrationSchedule", "deleteIntegrationSchedule"])("summarizes %s without internal identifiers", (operation) => {
    const deleted = operation === "deleteIntegrationSchedule";
    const result = { integration_id: integrationID, cadence_seconds: 3600, state: deleted ? "deleted" : "enabled", time_zone: "UTC", next_run_at: deleted ? null : "2026-08-19T01:00:00Z", version: deleted ? 2 : 1, created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:00:01Z" };
    const receipt = { ...base, operation, resource_kind: "integration_schedule", resource_id: integrationID, resource_version: result.version, result, intent: { body: deleted ? {} : { cadence_seconds: 3600, state: "enabled" }, expected_version: deleted ? 1 : 0, idempotency_key: base.idempotency_key, integration_id: integrationID, scope } } as WorkflowMutationReceipt;
    const serialized = JSON.stringify(workflowReceiptSummary(receipt));
    expect(serialized).toContain(deleted ? "Delete automatic sync schedule" : "enabled");
    expect(serialized).toContain("UTC");
    for (const hidden of [integrationID, scope.organization_id, scope.workspace_id, scope.environment_id, base.idempotency_key]) expect(serialized).not.toContain(hidden);
  });
});
