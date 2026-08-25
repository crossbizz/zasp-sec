import { describe, expect, it } from "vitest";

import {
  decodeIntegrationFreshness,
  decodeIntegrationSchedule,
  decodeIntegrationSync,
  decodeIntegrationSyncPage,
  decodeRecoveryBackup,
  decodeRecoveryRestore,
} from "./decoders";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const syncID = "pid_20000002-0000-4000-8000-000000000002";
const snapshotID = "pid_20000003-0000-4000-8000-000000000003";
const recoveryScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
const backupID = "pid_71000001-0000-4000-8000-000000000001";
const restoreID = "pid_71000002-0000-4000-8000-000000000002";
const manifest = {
  reference: `s3://zasp-recovery/organizations/${recoveryScope.split("/")[0]}/workspaces/${recoveryScope.split("/")[1]}/environments/${recoveryScope.split("/")[2]}/artifacts/pid_71000003-0000-4000-8000-000000000003`,
  version_id: "version-recovery-0001",
  sha256: "a".repeat(64),
  size_bytes: 512,
  media_type: "application/vnd.zasp.recovery-manifest+json",
  schema: "recovery_signed_manifest_v1",
  signing_key_id: "11111111-1111-4111-8111-111111111111",
  signature: "A".repeat(43),
} as const;
const evidence = {
  reference: `s3://zasp-recovery/organizations/${recoveryScope.split("/")[0]}/workspaces/${recoveryScope.split("/")[1]}/environments/${recoveryScope.split("/")[2]}/artifacts/pid_71000004-0000-4000-8000-000000000004`,
  version_id: "version-evidence-0001",
  sha256: "b".repeat(64),
  size_bytes: 256,
  media_type: "application/json",
  schema: "recovery_validation_v1",
} as const;
const counts = { assets: 12, findings: 3, policies: 2 } as const;
const queuedBackup = { id: backupID, version: 1, state: "queued", retention_days: 30, attempt: 0, created_at: "2026-08-25T12:00:00Z" } as const;
const queuedRestore = { id: restoreID, version: 1, state: "queued", target_environment: "recovery-e2e-01", attempt: 0, manifest, created_at: "2026-08-25T12:00:00Z" } as const;

const sync = {
  id: syncID,
  integration_id: integrationID,
  trigger_kind: "manual",
  status: "succeeded",
  attempt: 1,
  requested_at: "2026-08-19T00:00:00Z",
  started_at: "2026-08-19T00:00:01Z",
  completed_at: "2026-08-19T00:00:02Z",
  discovered_count: 10,
  changed_count: 3,
  removed_count: 1,
  snapshot_id: snapshotID,
  last_error_code: null,
  retry_at: null,
} as const;

const schedule = {
  integration_id: integrationID,
  cadence_seconds: 3600,
  state: "enabled",
  time_zone: "UTC",
  next_run_at: "2026-08-19T01:00:00Z",
  version: 2,
  created_at: "2026-08-19T00:00:00Z",
  updated_at: "2026-08-19T00:00:01Z",
} as const;

const freshness = {
  integration_id: integrationID,
  version: 7,
  last_good: {
    snapshot_id: snapshotID,
    collected_at: "2026-08-19T00:00:02Z",
    discovered_count: 10,
    changed_count: 3,
    removed_count: 1,
  },
  latest_sync: sync,
  projections: {
    risk: { state: "current", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: null },
    graph: { state: "pending", snapshot_id: snapshotID, completed_at: null, last_error_code: null },
    search: { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "terminal" },
  },
  updated_at: "2026-08-19T00:00:04Z",
} as const;

describe("production discovery response decoders", () => {
  it("accepts exact queued, running, succeeded, and failed recovery tuples", () => {
    expect(decodeRecoveryBackup(queuedBackup, recoveryScope)).toEqual(queuedBackup);
    expect(decodeRecoveryBackup({ ...queuedBackup, version: 2, state: "capturing", attempt: 1, started_at: "2026-08-25T12:00:01Z" }, recoveryScope).state).toBe("capturing");
    expect(decodeRecoveryBackup({ ...queuedBackup, version: 3, state: "succeeded", attempt: 1, manifest, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:02Z" }, recoveryScope).state).toBe("succeeded");
    expect(decodeRecoveryBackup({ ...queuedBackup, version: 3, state: "failed", attempt: 1, error_code: "exhausted", started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:02Z" }, recoveryScope).state).toBe("failed");

    expect(decodeRecoveryRestore(queuedRestore, recoveryScope)).toEqual(queuedRestore);
    expect(decodeRecoveryRestore({ ...queuedRestore, version: 2, state: "rebuilding", attempt: 1, started_at: "2026-08-25T12:00:01Z", validation_evidence: { state: "validated", expected_counts: counts, observed_counts: counts, evidence } }, recoveryScope).state).toBe("rebuilding");
    expect(decodeRecoveryRestore({ ...queuedRestore, version: 5, state: "succeeded", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:05Z", observed_counts: counts, validation_evidence: { state: "validated", expected_counts: counts, observed_counts: counts, evidence }, cleanup_evidence: { state: "deleted", evidence } }, recoveryScope).state).toBe("succeeded");
    expect(decodeRecoveryRestore({ ...queuedRestore, version: 5, state: "failed_cleanup", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:05Z", error_code: "cleanup_failed", cleanup_evidence: { state: "failed", evidence } }, recoveryScope).state).toBe("failed_cleanup");
  });

  it.each([
    ["queued backup with a start", { ...queuedBackup, started_at: "2026-08-25T12:00:01Z" }],
    ["successful backup without manifest", { ...queuedBackup, state: "succeeded", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:02Z" }],
    ["foreign-scope manifest", { ...queuedBackup, state: "succeeded", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:02Z", manifest: { ...manifest, reference: manifest.reference.replace(recoveryScope.split("/")[0], "pid_90000001-0000-4000-8000-000000000001") } }],
    ["internal worker member", { ...queuedBackup, worker_id: backupID }],
  ])("rejects recovery backup drift: %s", (_name, value) => {
    expect(() => decodeRecoveryBackup(value, recoveryScope)).toThrow("schema mismatch");
  });

  it.each([
    ["count mismatch", { ...queuedRestore, state: "succeeded", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:05Z", observed_counts: counts, validation_evidence: { state: "validated", expected_counts: counts, observed_counts: { ...counts, assets: 11 }, evidence }, cleanup_evidence: { state: "deleted", evidence } }],
    ["successful restore with failed cleanup", { ...queuedRestore, state: "succeeded", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:05Z", observed_counts: counts, validation_evidence: { state: "validated", expected_counts: counts, observed_counts: counts, evidence }, cleanup_evidence: { state: "failed", evidence } }],
    ["failed cleanup without evidence", { ...queuedRestore, state: "failed_cleanup", attempt: 1, started_at: "2026-08-25T12:00:01Z", completed_at: "2026-08-25T12:00:05Z", error_code: "cleanup_failed" }],
    ["production target", { ...queuedRestore, target_environment: "production" }],
    ["internal provider payload", { ...queuedRestore, provider_error: "secret" }],
  ])("rejects recovery restore drift: %s", (_name, value) => {
    expect(() => decodeRecoveryRestore(value, recoveryScope)).toThrow("schema mismatch");
  });

  it("accepts exact bounded sync, history, schedule, and independent freshness projections", () => {
    expect(decodeIntegrationSync(sync)).toEqual(sync);
    expect(decodeIntegrationSyncPage({ items: [sync], page_info: { next_cursor: null, has_more: false } })).toEqual({ items: [sync], page_info: { next_cursor: null, has_more: false } });
    expect(decodeIntegrationSchedule(schedule)).toEqual(schedule);
    expect(decodeIntegrationFreshness(freshness)).toEqual(freshness);
  });

  it.each([
    ["initial queue", { ...sync, status: "queued", attempt: 0, started_at: null, completed_at: null, discovered_count: 0, changed_count: 0, removed_count: 0, snapshot_id: null, last_error_code: null, retry_at: null }],
    ["retry queue", { ...sync, status: "queued", attempt: 2, completed_at: null, snapshot_id: null, last_error_code: "rate_limited", retry_at: "2026-08-19T00:00:03Z" }],
  ])("accepts the canonical %s sync tuple", (_name, value) => {
    expect(decodeIntegrationSync(value)).toEqual(value);
  });

  it.each([
    ["pending retry", { state: "pending", snapshot_id: snapshotID, completed_at: null, last_error_code: "retryable" }],
    ["cancelled degradation", { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "cancelled" }],
    ["succeeded-binding mismatch", { state: "degraded", snapshot_id: snapshotID, completed_at: null, last_error_code: "outcome_unknown" }],
    ["unavailable projection", { state: "unavailable", snapshot_id: null, completed_at: null, last_error_code: null }],
  ])("accepts the canonical %s projection state", (_name, projection) => {
    expect(decodeIntegrationFreshness({ ...freshness, projections: { ...freshness.projections, graph: projection } }).projections.graph).toEqual(projection);
  });

  it.each([
    ["extra sync member", { ...sync, worker_id: syncID }],
    ["invalid attempt", { ...sync, attempt: 101 }],
    ["completion before request", { ...sync, completed_at: "2026-08-18T23:59:59Z" }],
    ["queued sync with committed snapshot", { ...sync, status: "queued", started_at: null, completed_at: null, snapshot_id: snapshotID }],
    ["initial queue with retry state", { ...sync, status: "queued", attempt: 0, completed_at: null, snapshot_id: null, last_error_code: "retryable", retry_at: "2026-08-19T00:00:03Z" }],
    ["retry queue without start", { ...sync, status: "queued", attempt: 2, started_at: null, completed_at: null, snapshot_id: null, last_error_code: "retryable", retry_at: "2026-08-19T00:00:03Z" }],
    ["retry queue without stable error", { ...sync, status: "queued", attempt: 2, completed_at: null, snapshot_id: null, last_error_code: null, retry_at: "2026-08-19T00:00:03Z" }],
    ["retry queue without retry time", { ...sync, status: "queued", attempt: 2, completed_at: null, snapshot_id: null, last_error_code: "retryable", retry_at: null }],
    ["retry queue with completion", { ...sync, status: "queued", attempt: 2, snapshot_id: null, last_error_code: "retryable", retry_at: "2026-08-19T00:00:03Z" }],
    ["foreign failure code", { ...sync, status: "failed", snapshot_id: null, last_error_code: "provider_stack_trace" }],
  ])("rejects %s", (_name, value) => {
    expect(() => decodeIntegrationSync(value)).toThrow("schema mismatch");
  });

  it.each([
    ["non-UTC schedule", { ...schedule, time_zone: "America/Los_Angeles" }],
    ["short cadence", { ...schedule, cadence_seconds: 299 }],
    ["disabled next run", { ...schedule, state: "disabled", next_run_at: schedule.next_run_at }],
    ["extra schedule member", { ...schedule, scheduler_job_id: syncID }],
  ])("rejects %s", (_name, value) => {
    expect(() => decodeIntegrationSchedule(value)).toThrow("schema mismatch");
  });

  it.each([
    ["foreign latest sync", { ...freshness, latest_sync: { ...sync, integration_id: "pid_20000009-0000-4000-8000-000000000009" } }],
    ["collapsed projection shape", { ...freshness, projections: { state: "current" } }],
    ["current projection without completion", { ...freshness, projections: { ...freshness.projections, risk: { ...freshness.projections.risk, completed_at: null } } }],
    ["pending projection without snapshot", { ...freshness, projections: { ...freshness.projections, graph: { state: "pending", snapshot_id: null, completed_at: null, last_error_code: null } } }],
    ["pending projection with completion", { ...freshness, projections: { ...freshness.projections, graph: { state: "pending", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: null } } }],
    ["pending projection with terminal error", { ...freshness, projections: { ...freshness.projections, graph: { state: "pending", snapshot_id: snapshotID, completed_at: null, last_error_code: "terminal" } } }],
    ["degraded retry projection", { ...freshness, projections: { ...freshness.projections, search: { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "retryable" } } }],
    ["degraded terminal projection without completion", { ...freshness, projections: { ...freshness.projections, search: { state: "degraded", snapshot_id: snapshotID, completed_at: null, last_error_code: "terminal" } } }],
    ["degraded mismatch projection with completion", { ...freshness, projections: { ...freshness.projections, search: { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "outcome_unknown" } } }],
    ["unavailable projection with snapshot", { ...freshness, projections: { ...freshness.projections, search: { state: "unavailable", snapshot_id: snapshotID, completed_at: null, last_error_code: null } } }],
    ["unavailable projection with error", { ...freshness, projections: { ...freshness.projections, search: { state: "unavailable", snapshot_id: null, completed_at: null, last_error_code: "terminal" } } }],
    ["internal projection error", { ...freshness, projections: { ...freshness.projections, search: { ...freshness.projections.search, last_error_code: "opensearch_index_failed" } } }],
    ["extra freshness member", { ...freshness, outbox_id: syncID }],
  ])("rejects %s", (_name, value) => {
    expect(() => decodeIntegrationFreshness(value)).toThrow("schema mismatch");
  });
});
