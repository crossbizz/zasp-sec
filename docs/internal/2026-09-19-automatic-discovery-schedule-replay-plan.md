# Automatic Discovery Schedule Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one scheduled discovery occurrence survive scheduler process loss and lease reclaim without duplicate sync, job or outbox records.

**Architecture:** Add release60 after the reviewed release59 handoff. Stable Go occurrence identities are already implemented; release60 adds occurrence uniqueness and a fenced registered rebind inside the existing admission transaction, then the current scheduler completes under the replacement lease. Release59 and release13 remain byte-for-byte unchanged.

**Tech Stack:** Go1.24, PostgreSQL registered `SECURITY DEFINER` functions with forced release identity, pgx integration tests, Node22 connected browser harness, pinned network-disabled PostgreSQL container.

**Spec:** `docs/internal/2026-09-19-automatic-discovery-schedule-replay-design.md`

## Global Constraints

- Do not edit any release13 or release59 SQL file, checksum or fingerprint.
- Release59 must be frozen and independently accepted before Task1 begins. Then
  recheck that60 is free; rebase if another reviewed migration owns60.
- Public cadence remains300 seconds minimum. A due-now schedule is diagnostic SQL evidence only.
- Only a current registered scheduler lease may rebind an incomplete exact occurrence.
- Different scope, schedule, integration, due time, sync ID, job ID, outbox ID or request digest must fail atomically.
- Tasks1,2 and3 run sequentially with exclusive ownership of migration registry,
  CLI and scheduler PostgreSQL test files.
- Old lease tokens cannot complete after rebind. Completed occurrences cannot rebind.
- No fixture or local controlled provider may be described as live customer-cluster proof.
- No push occurs until affected SQL/Go, connected browser, UI/build and release gates pass on current source hashes.

## Verification execution contract

Run Go with `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off` and a task-owned
`GOCACHE`. Inspect the pinned image's `.Architecture` with
`docker image inspect`; map `arm64` to `GOARCH=arm64` and `amd64` to
`GOARCH=amd64`, stopping on anything else. Build the PostgreSQL test binary with
`GOOS=linux CGO_ENABLED=0`, then run it in the
pinned network-none, read-only PostgreSQL image. Every selector must report zero
skips and its database, relay and container must join before the result counts.

Task evidence files are fixed:

- Task1: `release60-red.log`
- Task2: `release60-migration-green.log` and `release60-cycle-green.log`
- Task3: `release60-replay-green.log` and `release60-review.md`
- Task4: `connected-12.log`
- Task5: `release60-publication-gates.log`

Focused selectors are
`TestAutomaticDiscoveryScheduledOccurrenceRebindPostgres`,
`TestProductionDiscoveryScheduleReplay`,
`TestProductionDiscoveryScheduleReplayPostgres`, and
`TestProductionRuntimeAutomaticDiscoveryScheduler`. Grouped verification adds
the full `./migrations`, affected `./apiserver` and `./agentsec-worker` race
packages, then the existing Node production-combined harness tests.

---

### Task 1: Freeze release59 and prove the release60 RED

**Files:**
- Modify: `services/platform/apiserver/automatic_discovery_scheduler_postgres_test.go`
- Create: `docs/internal/automatic-discovery-sync-20260919/release60-red.log`

**Interfaces:**
- Consumes: reviewed `migrations.ProductionSecurityAgentWebhooks()` and the current registered scheduler repository.
- Produces: one exact failing replay assertion bound to source hashes and SQLSTATE23505.

- [ ] **Step 1: Confirm migration ownership**

Require the external release59 owner handoff plus independent review verdict and
exact hashes. Search production migration/CLI sources, excluding `*_test.go`, for
`version: 60`, `0060_`, registered `up-to-60` or `down-from-60` command cases and
require no result. Release59 compatibility tests intentionally name `up-to-60`
as the unsupported future boundary; Task2 owns moving those assertions only after
release60 exists. Hash the frozen release59 Go/SQL/test files and record them in
`docs/internal/automatic-discovery-sync-20260919/progress.md`.

- [ ] **Step 2: Extend the existing registered RED fixture**

Install exact release59 before running the current schedule test. Retain two
registered scheduler connections and the actual5-second lease expiry. Assign all
real PostgreSQL replay cases to this test file. First retain same-key/same-digest
tests that vary sync, job and outbox IDs independently, proving normalized return
IDs cannot authorize a receipt rebind. Then add changed IDs/request digest with a
different idempotency key so provisional writes occur before the occurrence
conflict. Assert every proposed ID is absent; compare all receipt fields and
generation; and snapshot full schedule/integration-scoped sync, job, outbox,
authority plus freshness values/versions, not counts alone. Add distinct due-time,
simultaneous admission/reclaim, direct table-write/RLS and wrong-principal
controls. Historical duplicate-install rejection stays mandatory in Task2, where
the release60 install function exists; Task1 must not invent or skip an
interface-only substitute. Add scheduled-only Go decoder tests that reject any
returned/proposed ID mismatch while leaving manual-sync replay semantics unchanged.

- [ ] **Step 3: Verify the behavioral RED**

Compile the apiserver test binary for the pinned PostgreSQL image and run only `TestAutomaticDiscoveryScheduledOccurrenceRebindPostgres` in an owned network-none/read-only container. Expected result: the intended exact replay fails with SQLSTATE23505 `schedule run conflict`; zero skips; PostgreSQL and the container join cleanly.

### Task 2: Implement additive release60 with occurrence fencing

**Files:**
- Create: `services/platform/migrations/sql/0060_production_discovery_schedule_replay.up.sql`
- Create: `services/platform/migrations/sql/0060_production_discovery_schedule_replay.down.sql`
- Create: `services/platform/migrations/production_discovery_schedule_replay.go`
- Create: `services/platform/migrations/production_discovery_schedule_replay_test.go`
- Modify: `services/platform/migrations/migrations.go`
- Modify: `services/platform/migrations/migrations_test.go`
- Modify: `services/platform/agentsec-migrate/main.go`
- Modify: `services/platform/agentsec-migrate/main_test.go`
- Modify: `services/platform/agentsec-migrate/bootstrap_release.go`
- Modify: `services/platform/agentsec-migrate/bootstrap_release_test.go`
- Modify: `services/platform/agentsec-migrate/release_readiness_test.go`
- Modify: `services/platform/agentsec-migrate/existing_tests_command_test.go`
- Modify: `services/platform/agentsec-migrate/security_agent_exports_command_test.go`
- Modify: `services/platform/agentsec-migrate/attack_lab_command_test.go`

**Interfaces:**
- Consumes: exact release59 readiness and the release13 scheduled-admission signature.
- Produces: `ProductionDiscoveryScheduleReplay()`, `DiscoveryScheduleReplayFingerprint()`, `Runner.UpProductionDiscoveryScheduleReplay`, `Runner.DownProductionDiscoveryScheduleReplay`, `up-to-60`, `down-from-60`, and release60 readiness.

- [ ] **Step 1: Write migration identity tests first**

Require version60/name `production_discovery_schedule_replay`, embedded up/down SQL, exact predecessor59 gate, metadata/fingerprint insertion, `up-to-60`, `down-from-60`, count bound60 and ordered metadata inclusion. Run the focused migration and CLI tests and retain the expected missing-symbol/unsupported-command RED.

- [ ] **Step 2: Write registered release-cycle RED cases**

Test59 to60 to59 to60 on an empty candidate dataset. Require exact owners,
`SECURITY DEFINER`, `search_path=pg_catalog, public`, no PUBLIC execution,
scheduler-only execution, occurrence constraint, nonnegative
`rebind_generation` and completion columns. Revoke grants and alter every replaced
definition class to prove readiness refusal. Add positive rebind/completion
evidence and require down to refuse without deleting it. Use two connections to
race down against rebind; down takes the table lock before checking evidence, so
it either excludes admission safely or rolls back with evidence retained.

- [ ] **Step 3: Add the occurrence schema**

After taking the migration advisory lock, lock schedules and schedule runs in
admission-compatible order before the preflight predicate, and retain the locks
through installation. Before adding the constraint, reject any grouped duplicate of
`(organization_id,workspace_id,environment_id,schedule_id,scheduled_for)`, and
reject any incomplete existing receipt, with SQLSTATE55000 and unchanged metadata.
Add `rebind_generation bigint NOT NULL DEFAULT 0 CHECK(rebind_generation>=0)`,
nullable completion digest/result columns with paired-null and digest-length
checks, and unique constraint `zasp_discovery_schedule_runs_occurrence_key` on
the exact occurrence tuple. A two-connection preflight-versus-old-admission test
must prove installation either observes and rejects a committed receipt or
excludes the old admission while locks are held. Also let an already executing
predecessor call resume after install: treat its empty-occurrence first write as
an unsupported maintenance-fence violation, then prove subsequent release60
replay refuses without changing or duplicating that legacy receipt.

- [ ] **Step 4: Add the fenced registered admission body**

Lock and validate the enabled schedule under the current live worker/token. Call
the existing sync admission inside the same transaction, then require its returned
sync, job and outbox IDs to equal the caller's three proposed IDs before touching
the receipt. Keep manual-sync replay unchanged. Insert the schedule-run row with
generation0. On occurrence conflict, return an exact same-owner/token replay with
generation unchanged; for a different current lease, update only lease owner/token
and increment once where stored immutable fields match and completion is absent.
Require one exact row or raise SQLSTATE23505 `schedule run conflict`. Test
generation0, same-token replay0, replacement1, replacement retry1 and a later
legitimate replacement2.

- [ ] **Step 5: Add release identity and compatibility**

Snapshot each replaced predecessor definition, owner and EXECUTE ACL before
modification. The inventory must include the ten release59 ancestry functions,
attack-lab audit fingerprint, execution live fingerprint/readiness/security,
scheduled admission/completion and every release59 guard/readiness with a59 row
bound. Create release60 security, live-fingerprint and readiness functions covering
the saved inventory, columns, constraint, functions and grants. Nonrecursive
compatibility wrappers accept each known predecessor compiled argument pair only
after full release60 readiness; unknown pairs and drift fail. Test existing API,
worker, projection, export and webhook boundaries plus scheduler60 readiness.
Down sets a bounded lock timeout, takes locks in migration-advisory then
schedule-runs-table order, checks evidence, and restores saved definitions,
owners/ACLs and exact release59 readiness only when no release60 evidence exists.

- [ ] **Step 6: Run focused GREEN**

Run migration unit tests, CLI tests and the owned registered release-cycle PostgreSQL group. Require zero skips and a normal database/container join. Run `git diff --check` and hash every release60 source and log.

### Task 3: Connect the repository and settle the exact occurrence

**Files:**
- Modify: `services/platform/apiserver/discovery_execution_repository.go`
- Modify: `services/platform/apiserver/discovery_execution_repository_test.go`
- Modify: `services/platform/apiserver/automatic_discovery_scheduler_postgres_test.go`
- Modify: `services/platform/agentsec-worker/production_runtime.go`
- Modify: `services/platform/agentsec-worker/production_runtime_test.go`

**Interfaces:**
- Consumes: release60 registered admission/readiness and the reviewed stable occurrence seed.
- Produces: a scheduler repository that refuses startup without exact release60, replays under the replacement lease and completes once.

- [ ] **Step 1: Write repository readiness RED**

Require scheduler construction to call release60 readiness with its compiled checksum/fingerprint and reject release59-only, unknown checksum, drifted fingerprint, wrong principal and revoked EXECUTE. Non-scheduler discovery repositories keep their existing release gates.

- [ ] **Step 2: Write completion-fence RED**

After actual lease expiry and a second registered claim, require exact replay to
return `Replayed=true`, stable sync/job/outbox IDs and one durable occurrence.
Completion with the first token must fail; completion with the replacement token
advances once and stores an occurrence completion digest/result. Lost completion
response replay after the next due instant and after a later claim returns that
same result without mutating the later occurrence. A changed completion digest,
changed identities/digest and a completed occurrence remain rejected with full
scope state unchanged. Separately test a pre-install expired legacy orphan and a
deliberately unsupported post-release60 old-first writer; the subsequent
release60 replay fails closed without mapping, receipt mutation or extra writes.

- [ ] **Step 3: Select the release60 entrypoint and readiness**

Change scheduler admission/runtime construction to the release60 registered
boundary, add scheduled-only returned/proposed ID equality decoding, and connect
the release60 durable completion wrapper/result. Preserve worker/projection
repository behavior, manual-sync replay and public schedule schemas. No fallback
to release13 is allowed when release60 is expected. Task2 owns the SQL completion
wrapper and receipt storage; Task3 owns its Go call/decoding/runtime composition.

- [ ] **Step 4: Run grouped GREEN and review**

Run the focused owned PostgreSQL replay/release group, full affected apiserver and worker race selectors, and migration tests. Dispatch an independent read-only review of SQL fencing, readiness, grants, rollback and Go decoding. Correct every Critical or Important finding, rerun affected groups, and obtain re-review.

### Task 4: Rerun connected automatic discovery acceptance

**Files:**
- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `scripts/production-combined-e2e.test.mjs`
- Create: `docs/internal/automatic-discovery-sync-20260919/connected-12.log`
- Update: `docs/internal/automatic-discovery-sync-20260919/progress.md`

**Interfaces:**
- Consumes: reviewed release60 migration, scheduler binary, canonical Kubernetes collection and owned bridge.
- Produces: one source-bound connected manifest proving restart replay and the existing discovery acceptance matrix.

- [ ] **Step 1: Move automatic-discovery mode to exact release60**

Write a behavioral RED for every automatic-mode58 pin. Change automatic mode,
and only that mode, to `up-to-60`, release60 fingerprint/readiness and
`ZASP_EXPECTED_SCHEMA_VERSION=60` before process start. Record release60 in the
manifest and include migration SQL/Go, migration registry/CLI, scheduler
repository/runtime construction and harness source hashes. Preserve unrelated
export-mode58 evidence. Keep caught stage errors separate from join errors. Do
not widen relay, cadence, lease or process timeouts.

- [ ] **Step 2: Run attempt12 once**

Use Node22, offline Go modules, the pinned network-none PostgreSQL image and the frozen source. Do not restart a live attempt. Require public schedule create/replay/delete, foreign denial, an actual300-second wait, first scheduler process exit, replacement scheduler reclaim after the real5-second lease, one sync/job/outbox, changed Kubernetes collection, typed inventory browser reload, failed/partial last-good retention, disable/delete withdrawal and clean joins.

- [ ] **Step 3: Validate source-bound evidence**

Require `completed:true`, zero join/cleanup errors, exact release60 readiness and
identity before scheduler start, exact source/binary SHA-256 values, exact
container absence, all child process joins and one occurrence row with positive
rebind generation plus durable completion evidence. Record controlled-provider
limits and do not promote live-provider status.

### Task 5: Update authoritative status and publication gates

**Files:**
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify only when evidence changes a row: `docs/internal/implementation_production_availability_v1.5.tsv`
- Modify: `docs/internal/automatic-discovery-sync-20260919/progress.md`

**Interfaces:**
- Consumes: reviewed release60 and connected attempt12 evidence.
- Produces: current 728-row evidence with no fixture-as-live overstatement.

- [ ] **Step 1: Record the bounded result**

Link release60, review and connected manifests. State which automatic-discovery requirements are proven locally and which live customer/provider/deployment gates remain external. Do not change production/component/blocked classification without row-specific evidence.

- [ ] **Step 2: Run grouped publication verification**

Run `node scripts/implementation-status-check.mjs`, affected Go/Node/OpenAPI checks, full UI tests, typecheck, lint, runnable UI build and production release gate. Require `git diff --check` and review the complete publication diff against the original plan.

- [ ] **Step 3: Publish only the coherent candidate**

Commit and push only after every preceding gate passes on the same source hashes and the UI remains runnable. Record commit/push evidence in the authoritative ledger. A local fixture never closes live provider, cloud IAM, deployment, advisory or customer-cluster gates.
