# Session search v2 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Backfill and query sandbox-aware sessions with durable target-specific progress.

**Architecture:** Separate fixed-v2 outbox and lease/query authorities. Existing v1
checkpoint history stays unchanged. Deploy v2 readers only after verified backfill.

**Tech Stack:** Go, PostgreSQL18, OpenSearch3, TypeScript UI.

**Spec:** `docs/internal/2026-09-11-session-search-v2-design.md`

## Global constraints

No released migration edits. No new direct table grants. Exact compiled50
readiness for new authorities. Default target remains v1. No microtask credit or
push until full product-path acceptance. Preserve all original728 requirements.

## 1. Durable receipt backfill and enqueue

Files: migration50 up/down SQL, `production_runtime_sandbox_binding.go`, new
`apiserver/runtime_sandbox_search_backfill_postgres_test.go`.
Consumes canonical projection receipts and completed stage references. Produces
`zasp_runtime_sandbox_search_outbox` and private trigger
`zasp_runtime_sandbox_search_enqueue()`.

- [x] Write actual PostgreSQL tests: finish a v1 receipt on49, index its old queue,
  install50, assert new queue pending/attempt0 and old queue unchanged. Finish
  after50 and assert atomic enqueue; replay must not reset progress.
  ```sql
  SELECT state,attempt FROM zasp_runtime_sandbox_search_outbox;
  SELECT state,attempt FROM zasp_runtime_session_search_outbox;
  ```
- [x] Run RED: `go -C services/platform test -race ./apiserver -run '^TestRuntimeSandboxSearchBackfill' -count=1` with PostgreSQL18 on PATH.
- [x] Create the separate table with existing lease constraints and explicit
  receipt FK, fixed target encoded by table identity, forced RLS and private
  authority policy. Backfill via receipt/project/complete join; install a private
  receipt trigger under the same lock. Fingerprint every new catalog object.
  ```sql
  INSERT INTO zasp_runtime_sandbox_search_outbox
  (organization_id,workspace_id,environment_id,batch_id,batch_generation,
   receipt_digest,receipt_reference,receipt_version,document_ids)
  SELECT r.organization_id,r.workspace_id,r.environment_id,r.batch_id,r.batch_generation,
   r.receipt_digest,p.result_reference,p.result_version_id,
   zasp_runtime_session_search_document_ids(r.organization_id,r.workspace_id,
     r.environment_id,r.batch_id,r.batch_generation,r.event_ids)
  FROM zasp_runtime_session_projection_receipts r
  JOIN zasp_runtime_stage_work p USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
  JOIN zasp_runtime_stage_work c USING(organization_id,workspace_id,environment_id,batch_id,batch_generation)
  WHERE p.stage='project' AND p.state='succeeded' AND p.result_digest=r.receipt_digest
    AND c.stage='complete' AND c.state='succeeded';
  ```
  Missing/corrupt legacy progress is not permission to omit a receipt. Reject
  migration if any canonical receipt is absent from the new table.
- [x] Extend readiness and guarded rollback; test drift, attempts and reinstall.
- [ ] Run focused and full sandbox PostgreSQL races; independent review. Commit
  only with a coherent reviewed migration checkpoint and passing ledger check.

## 2. Lease and freshness authorities

Progress: query status/hydration and scoped indexes are implemented and reviewed
locally. Lease and recovery-hold controls passed actual PostgreSQL races40.506s.
Review found no concrete SQL authority defect. Full sandbox regression passed
363.577s under the later legacy-filter pin. Publication remains gated by task4.

Files: migration50 up/down SQL; new
`apiserver/runtime_sandbox_search_authority_postgres_test.go`.
Consumes task1 table; produces claim(text,text,integer),
heartbeat(text,text,text,text,bigint,text,text,integer,integer),
finish(text,text,text,text,bigint,text,text,integer,bytea,text,text[],integer),
query_status(text,text,text,text), query_hydrate(text,text,text,text,text[]),
all under the sandbox names in the spec.

- [x] Write RED tests for actual registered principals, wrong-target finish,
  contention, expired/foreign leases, receipt replay, recovery holds and drift.
  ```sql
  SELECT zasp_runtime_sandbox_search_claim('worker','sandbox-token-0001',30);
  SELECT zasp_runtime_sandbox_query_status($1,$2,$3,$4);
  ```
- [x] Implement fixed-table authorities using existing42 lease validation and43
  query response shapes, with release50 gates after locks and before returns.
  API has only query EXECUTE, index role only lease EXECUTE; private helpers stay
  authority-only. Include every function/ACL in readiness and rollback.
- [x] Prove v1 checkpoint state cannot yield v2 `current`; prove hydration rechecks
  tenant/principal and target. Run full sandbox races and independent review.

## 3. Bind selected worker and API to matching progress

Progress: API and worker now bind to the same fixed target as their provider.
Compiled50 gates apply before v2 operations. A real Go/PostgreSQL lease round
trip passed11.052s, and all affected package races passed. The review's harness
cleanup fix passed independent re-review and parent verification17.665s.
The executor's v2 receipt gate is also fixed and reviewed. Actual provider
cutover remains task4; whole-draft release gates remain open.

Files: `agentsec-worker/runtime_session_search_database.go`,
`production_runtime.go`, `apiserver/runtime_session_search_repository.go`,
`agentsec-api/policy_production.go`, their tests.
Consumes task2 signatures; produces matching SQL authority for configured index.

- [x] Write RED tests that choose v2 and reject missing50 functions before
  provider search/write. Include empty/v1 compatibility.
- [x] Add closed-target constructors retaining old signatures as v1 defaults.
  ```go
  // Select once at composition; every operation uses this fixed target.
  switch name {
  case "", "zasp-runtime-sessions-v1": // existing authority
  case "zasp-runtime-sessions-v2": // sandbox authority, compiled50 probe
  default: return nil, errRuntimeUnavailable
  }
  ```
- [x] Bind claims/heartbeat/finish and both API status/hydrate to the selected
  authority; reject malformed readiness and any fallback. Run full package races
  plus composed PostgreSQL tests. Independent review before the next task.

## 4. Producer and deployment cutover acceptance

Progress: legacy enqueue filtering and its independent insert-only version fence
are local and reviewed. Expanded backfill/rollback/lock checks passed30.312s;
fresh v1-after50 claim/heartbeat/finish/replay compatibility passed6.032s.
Full sandbox regression under the new pin passed363.577s. Actual local
provider/API-repository historical cutover passed:7 receipts,58 occurrences,
2 scopes, target-specific freshness and unchanged v1 history. Independent review
approved this bounded checkpoint. Production routing and deployment are unchanged.

Explicit CLI commands are locally implemented and reviewed: `up-to-50` and
guarded `down-to-49`, with plain `up` still49. Actual PostgreSQL command-handler
and post-migration registration acceptance passed5.608s, including retained
evidence refusing rollback, clean rollback/reinstall and unchanged SQL producer
versions. This is not spawned-binary or deployed rollout acceptance. Full verify
still fails the chart49/embedded50 contract until the deployment phases are wired.

Composed proof uses the existing runtime-only provider harness, gated by
`ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY=true` and
`ZASP_COMBINED_E2E_RUNTIME_SANDBOX_SEARCH=true`. The new proof runs after the
existing49 ingestion/recovery cases. It upgrades through the actual50 runner,
initializes the separate v2 index, drains canonical receipts with the production
search processor and reads through the selected API repository. The default
full browser harness stays on49. Its opt-in must reject broad mode before
starting dependencies and must require the cutover proof marker, not just a
successful child exit.

Required assertions: v1 remains current while v2 is empty/catching up; all scoped
canonical receipts backfill from actual versioned S3 objects; selected v2 API is
current only after provider visibility/checkpoints; tenant denial still applies;
v1 checkpoint rows are unchanged. This checkpoint does not activate producers
or replace the subsequent fresh-sandbox-receipt/browser/deployment acceptance.

Deployment IAM now includes exact v2 mapping/marker reads, worker
bulk/mget/refresh, API search and initializer index/marker PUT resources in their
respective roles. V1 access and role separation are unchanged. Evaluated offline
Terraform checks passed2/2, including a discovered queue-encryption configuration
fix that preserves all14 explicit customer keys. Negative permission mutations
failed, and independent review approved the local changes and CI wiring. Local
provider success does not prove cloud IAM, so managed-provider attestation stays
a separate deployment gate.

The phase design is now recorded in
`docs/internal/2026-09-11-sandbox-rollout-design.md`: compatibility49, parallel
backfill50, then query cutover50. It includes actual compatible-pod and captured
receipt-set transition evidence; rendered manifests or a Boolean cannot prove
those prerequisites. Design review is complete; phase-aware Helm implementation
and transition enforcement remain open.

Files: worker/deployment registration and composed acceptance tests identified
by the existing runtime acceptance suite; authoritative internal ledger.
Consumes tasks1-3 and fixed-v2 provider driver. Produces verified rollout sequence.

- [ ] Write failing composed49→50 tests with actual OpenSearch: historical receipt
  backfill, old API during backfill, switched v2 API, then new sandbox receipt.
- [ ] Filter legacy enqueue/claims to supported historical receipt versions;
  retain immutable old checkpoint rows. Test in-flight old workers and recovery.
- [ ] Register guarded50 rollout, v2 initializer/worker/API ordering and producer
  activation only after target visibility/backfill proof. Add failure controls
  for empty index, pending/quarantined work, lost ACK and interrupted rollout.
- [ ] Run composed provider acceptance, browser/UI tests, full `npm run verify`,
  ledger check and independent review; publish only after all release gates pass.

Execution: the tasks share migration50 and have sequential dependencies, so use
manual TDD with independent review in the existing isolated worktree under the user's autonomous
authorization. Repeated approval pauses are waived; failed safety gates are not.
