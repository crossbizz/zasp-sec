import { describe, expect, it } from "vitest";

import {
  decodeIntegrationFreshness,
  decodeIntegrationSchedule,
  decodeIntegrationSync,
  decodeIntegrationSyncPage,
} from "./decoders";

const integrationID = "pid_20000001-0000-4000-8000-000000000001";
const syncID = "pid_20000002-0000-4000-8000-000000000002";
const snapshotID = "pid_20000003-0000-4000-8000-000000000003";

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
    search: { state: "degraded", snapshot_id: snapshotID, completed_at: "2026-08-19T00:00:03Z", last_error_code: "retryable" },
  },
  updated_at: "2026-08-19T00:00:04Z",
} as const;

describe("production discovery response decoders", () => {
  it("accepts exact bounded sync, history, schedule, and independent freshness projections", () => {
    expect(decodeIntegrationSync(sync)).toEqual(sync);
    expect(decodeIntegrationSyncPage({ items: [sync], page_info: { next_cursor: null, has_more: false } })).toEqual({ items: [sync], page_info: { next_cursor: null, has_more: false } });
    expect(decodeIntegrationSchedule(schedule)).toEqual(schedule);
    expect(decodeIntegrationFreshness(freshness)).toEqual(freshness);
  });

  it.each([
    ["extra sync member", { ...sync, worker_id: syncID }],
    ["invalid attempt", { ...sync, attempt: 101 }],
    ["completion before request", { ...sync, completed_at: "2026-08-18T23:59:59Z" }],
    ["queued sync with committed snapshot", { ...sync, status: "queued", started_at: null, completed_at: null, snapshot_id: snapshotID }],
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
    ["internal projection error", { ...freshness, projections: { ...freshness.projections, search: { ...freshness.projections.search, last_error_code: "opensearch_index_failed" } } }],
    ["extra freshness member", { ...freshness, outbox_id: syncID }],
  ])("rejects %s", (_name, value) => {
    expect(() => decodeIntegrationFreshness(value)).toThrow("schema mismatch");
  });
});
