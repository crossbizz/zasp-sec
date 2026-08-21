# Runtime ingest reconciliation implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an immutable v17 authority that rate-limits each tenant sensor and recovers exact S3 objects left behind by Reserve-to-upload process crashes.

**Architecture:** v15 and v16 stay byte-for-byte unchanged. A new v17 migration adds wrapper functions for reserve/finalize, a leased reconciliation queue, and exact readiness/fingerprint authority. The event-ingest process runs one bounded background reconciler that claims stale reservations, verifies the immutable S3 object with `HeadObject`, and calls the existing fenced reconciliation function with deterministic job/outbox IDs.

**Tech Stack:** PostgreSQL 15+, Go 1.24, pgx v5, AWS SDK v2 S3, existing runtimeevent and event-ingest packages.

**Spec:** `.superpowers/sdd/2026-08-19-production-auto-discovery-and-response/task-6-brief.md`

## Global constraints

- Never amend v10-v16 migration files.
- Private ingest derives organization/workspace/environment only from the sensor credential.
- Exact idempotency replay never consumes rate quota.
- S3 inspection uses the configured bucket owner, KMS key, checksum mode, object key, content metadata, and version ID.
- Reconciliation effects are scope, batch, generation, request-digest, worker, and lease-token fenced.
- Database ACK follows the verified S3 effect; shutdown stops claims and waits within the configured shutdown timeout.
- Errors returned to sensors and logs contain stable codes only.

---

### Task 1: Restore frozen releases and add v17 registration

**Files:**
- Restore: `services/platform/migrations/sql/0015_runtime_data_plane.{up,down}.sql`
- Restore: `services/platform/migrations/sql/0016_runtime_gateway_reconciliation.{up,down}.sql`
- Create: `services/platform/migrations/sql/0017_runtime_ingest_reconciliation.{up,down}.sql`
- Modify: `services/platform/migrations/migrations.go`
- Modify: `services/platform/agentsec-migrate/main.go`
- Test: `services/platform/migrations/runtime_ingest_reconciliation_test.go`
- Test: `services/platform/agentsec-migrate/main_test.go`

**Interfaces:**
- Produces: `ProductionRuntimeIngestReconciliation() Metadata`
- Produces: `ProductionRuntimeIngestReconciliationSemanticFingerprint() string`
- Produces: runner methods `UpProductionRuntimeIngestReconciliation` and `DownProductionRuntimeIngestReconciliation`

- [ ] **Step 1: Write failing metadata and runner tests**

```go
func TestProductionRuntimeIngestReconciliationRegistersImmutableV17(t *testing.T) {
    metadata := ProductionRuntimeIngestReconciliation()
    if metadata.Version() != 17 || metadata.Name() != "runtime_ingest_reconciliation" {
        t.Fatalf("metadata=%d/%s", metadata.Version(), metadata.Name())
    }
}
```

- [ ] **Step 2: Run the focused tests and verify missing v17 symbols fail**

Run: `go test ./migrations ./agentsec-migrate -run 'RuntimeIngestReconciliation|ReachesV17' -count=1`

- [ ] **Step 3: Restore v15/v16 and add v17 metadata/runner wiring**

The v17 release guard calls exact v16 readiness with the committed v16 checksum and fingerprint. Its down guard requires exact v17 fingerprint/security readiness and no active reconciliation leases.

- [ ] **Step 4: Run metadata, empty-to-v17, v16-to-v17, down, and re-up tests**

Run: `go test -race ./migrations ./agentsec-migrate -run 'RuntimeIngestReconciliation|ReachesV17' -count=1`

- [ ] **Step 5: Commit**

```bash
git add services/platform/migrations services/platform/agentsec-migrate
git commit -m "feat(runtime): add v17 ingest reconciliation authority"
```

### Task 2: Add exact database rate and reconciliation authority

**Files:**
- Modify: `services/platform/migrations/sql/0017_runtime_ingest_reconciliation.up.sql`
- Modify: `services/platform/migrations/sql/0017_runtime_ingest_reconciliation.down.sql`
- Test: `services/platform/apiserver/runtime_ingest_reconciliation_postgres_test.go`

**Interfaces:**
- Produces: `zasp_runtime_reserve_batch_v17(...) -> jsonb`
- Produces: `zasp_runtime_finalize_batch_v17(...) -> jsonb`
- Produces: `zasp_runtime_claim_reconciliation(worker text, token text, lease_seconds int, limit int) -> jsonb`
- Produces: `zasp_runtime_release_reconciliation(scope..., batch text, generation bigint, worker text, token text, delay_seconds int, error_code text) -> jsonb`
- Produces: `zasp_runtime_finish_reconciliation(scope..., batch text, generation bigint, worker text, token text, artifact authority...) -> jsonb`

- [ ] **Step 1: Write real-PostgreSQL REDs**

Prove all of these before implementation: batch 601 in a 60-second sensor window fails with SQLSTATE `53300`; the original idempotency key still replays; another sensor can reserve; v17 backfills one work row for each stale v15 `uploading` batch; two claimers cannot own the same row; wrong worker/token cannot release or finish; an exact finish creates one job/outbox/stage set; response-loss replay returns the same result.

- [ ] **Step 2: Run REDs**

Run: `go test ./apiserver -run '^TestProductionRuntimeIngestReconciliationPostgres' -count=1 -v`

- [ ] **Step 3: Implement the v17 SQL authority**

`zasp_runtime_reserve_batch_v17` authenticates first, relies on the existing sensor advisory lock, handles existing idempotency before quota, enforces 600 batches, 600,000 events, and 1 GiB per rolling 60 seconds, delegates to v15 reserve, and inserts one reconciliation-work row. `zasp_runtime_finalize_batch_v17` delegates to v15 finalize and terminalizes that work row. Claims use `FOR UPDATE SKIP LOCKED`, bounded attempts, and exact worker/token leases.

- [ ] **Step 4: Pin v17 fingerprint and prove guarded down/re-up**

Run: `go test -race ./apiserver ./migrations ./agentsec-migrate -run 'RuntimeIngestReconciliation|ReachesV17' -count=1`

- [ ] **Step 5: Commit**

```bash
git add services/platform/migrations services/platform/apiserver
git commit -m "feat(runtime): fence stale ingest reconciliation"
```

### Task 3: Add version-pinned S3 inspection and repository decoding

**Files:**
- Modify: `services/platform/runtimeevent/production_ingest.go`
- Modify: `services/platform/runtimeevent/production_repository.go`
- Create: `services/platform/runtimeevent/production_reconciliation.go`
- Modify: `services/platform/runtimeevent/s3rawstore/store.go`
- Test: matching `_test.go` files

**Interfaces:**
- Produces: `RawArtifactInspector.Inspect(context.Context, RawArtifactExpectation) (RawArtifact, error)`
- Produces: `ProductionReconciliationRepository.Claim/Release/Finish`
- Produces: `ProductionReconciler.RunOnce(context.Context) error`

- [ ] **Step 1: Write REDs for lost upload acknowledgement, missing object, drift, replay, and hostile output**

The exact object case must call Finish once. Missing S3 data releases with stable `not_found`. Checksum, size, media type, KMS key, owner, scope metadata, key, and version drift never finalize. Panic/cancellation return stable errors without retaining object metadata.

- [ ] **Step 2: Run REDs**

Run: `go test ./runtimeevent ./runtimeevent/s3rawstore -run 'Reconciliation|Inspect' -count=1`

- [ ] **Step 3: Implement minimal inspector, strict decoders, and reconciler**

Derive job/outbox product IDs from `batch_id + "\x00runtime-job"` and `batch_id + "\x00runtime-outbox"`, matching live ingest. Clear temporary checksum and metadata buffers on every exit.

- [ ] **Step 4: Run package race and vet gates**

Run: `go test -race ./runtimeevent ./runtimeevent/s3rawstore -count=1 && go vet ./runtimeevent ./runtimeevent/s3rawstore`

- [ ] **Step 5: Commit**

```bash
git add services/platform/runtimeevent
git commit -m "feat(runtime): reconcile versioned ingest artifacts"
```

### Task 4: Compose the bounded production loop

**Files:**
- Modify: `services/event-ingest/production.go`
- Modify: `services/event-ingest/production_runtime.go`
- Modify: `services/event-ingest/production_server.go`
- Modify: `deploy/staging/product/templates/workloads.yaml`
- Modify: `deploy/production/release-contract.mjs`
- Test: matching Go and Node tests

**Interfaces:**
- Consumes: `ProductionReconciler.RunOnce(context.Context) error`
- Produces: one loop owned by `productionIngestDependencies.Close`

- [ ] **Step 1: Write lifecycle/config/render REDs**

Prove construction rejects intervals outside 5 seconds to 5 minutes, the loop does not claim before readiness, empty polls are bounded, cancellation stops new claims, Close waits for the current S3/DB call, and the rendered Deployment carries exact interval/stale/lease settings without broader IAM.

- [ ] **Step 2: Run REDs**

Run: `go test ./... -run 'Reconciliation|ProductionIngest' -count=1` from `services/event-ingest`, then `node --test deploy/production/release-contract.test.mjs`.

- [ ] **Step 3: Implement the loop and release values**

Use one ticker, one item per claim, a lease longer than twice `OperationTimeout`, and `ShutdownTimeout` for final drain. The existing ingest role keeps only S3 Head/Put plus exact v17 functions; no list-bucket grant is added.

- [ ] **Step 4: Run race, vet, render, and diff gates**

Run: `go test -race ./... -count=1 && go vet ./...`; run the production release contract; run `git diff --check`.

- [ ] **Step 5: Commit**

```bash
git add services/event-ingest deploy
git commit -m "feat(ingest): run stale upload reconciliation"
```

### Task 5: Prove the crash matrix and update status

**Files:**
- Modify: `scripts/production-combined-e2e.mjs`
- Modify: `scripts/production-combined-e2e.test.mjs`
- Modify: `docs/internal/agent_security_platform_status.md`

- [ ] **Step 1: Add an executable crash proof**

Reserve, put an exact versioned object, terminate before finalize, rotate the sensor token, restart event-ingest, and assert one queued batch plus one deterministic outbox. Repeat with lost DB response and assert no second job/outbox. A second tenant must continue ingesting while tenant one is at quota.

- [ ] **Step 2: Run focused static and local full E2E gates**

Run: `node --test scripts/production-combined-e2e.test.mjs`; run the installed-browser combined E2E when its local prerequisites are present.

- [ ] **Step 3: Promote only rows proven by source and executable evidence**

Do not promote the managed SQS/S3/OpenSearch row until the managed cloud proof has run. Record that external gate plainly.

- [ ] **Step 4: Run the coherent checkpoint gates**

Run focused Go race/vet, migration empty/v16-to-v17/down/re-up, release render, secret scan, combined E2E, ledger validation, and `git diff --check`.

- [ ] **Step 5: Commit and push main**

```bash
git add scripts docs/internal/agent_security_platform_status.md
git commit -m "test(runtime): prove ingest crash recovery"
git push origin HEAD:main
```
