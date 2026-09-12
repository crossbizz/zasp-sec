# Sandbox query cutover implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Read the design before changing code. Obtain ownership for each proposed file first; no commits or delegation unless separately authorized.

**Goal:** Prove one fixed50 backfill-to-query executor with a complete receipt
capture, real PostgreSQL fence and one conditional Kubernetes mutation.

**Architecture:** One Go executor owns the connection and dispatch lifetime.
Private adapters collect current evidence; a read-only Node adapter reuses the
existing backfill observer. The first slice has no live command or production
provenance fallback.

**Tech Stack:** Go, pgx, existing AWS/S3/OpenSearch clients, Node's existing release
renderer/observer, PostgreSQL18 fixtures and Go HTTP/TLS test servers.

**Spec:** `docs/internal/2026-09-11-sandbox-query-cutover-design.md`.

## Global constraints

- Fixed schema50, API v1 to v2, with both session workers retained.
- No migration SQL, pins, privilege grants, principal registration or production
  routing changes. No live cluster/provider operations in the first slice.
- Complete canonical capture, never a caller receipt subset or queue-only scan.
- Evidence younger than30 seconds at authorized dispatch; proposed fence lifetime
  15 seconds. No server-expiry or distributed-transaction claim.
- No reusable authorization token, blind retry, automatic rollback or repair.
- At most one dispatch per invocation. Contenders against the same old API
  UID/resourceVersion/template have at most one applied CAS, not globally one
  dispatch after a fence is released.
- `applied`, `refused`, `indeterminate` describe dispatch; rollout has a separate
  state. All mutation transports must preserve that distinction.
- Existing dirty changes belong to their owners. Use apply_patch, retain RED and
  GREEN logs and leave work unstaged unless directed otherwise.

## Package boundary before coding

Create `services/platform/internal/sandboxcutover/` with these responsibilities:

| File | Responsibility |
| --- | --- |
| `cutover.go` | Fixed executor, dependency validation and state transitions. |
| `types.go` | Immutable request/binding/capture/audit/result records and adapter interfaces. |
| `capture.go` | Complete ordered canonical query and deterministic digest encoding. |
| `postgres.go` | Dedicated pgx connection, compiled readiness and transaction-held fence. |
| `kubernetes.go` | Pinned HTTPS reads, fixed JSON Patch and read-only reconciliation. |
| `observation.go` | Bounded invocation of the existing Node observer with owned input. |
| `cutover_test.go` | Behavioral state-machine tests; no source-text assertions. |
| `kubernetes_test.go` | Real TLS transport and conditional-patch server tests. |

Create `deploy/production/sandbox-query-observation.mjs` and `.test.mjs` as a
read-only bridge to the existing renderer/backfill observer. It must not expose
an apply command or accept previously collected evidence as current.

Extend `services/platform/runtimeindex/opensearchdriver/` with
`session_visibility.go` and `session_visibility_test.go` for bounded exact-document
search verification. Do not change current Search/Apply behavior.

Create `services/platform/agentsec-migrate/runtime_sandbox_cutover_postgres_test.go`
for composed acceptance, reusing the same-package `startMigrationPostgres`,
`connectMigrationPostgres`, migration runner and fixture identities. This avoids
extracting or copying the large PostgreSQL harness. Import the new internal
package; never add cutover dispatch to the migration executable.

The package entry point is:

```go
func ExecuteSandboxQueryCutover(ctx context.Context, request Request, deps Dependencies) Result
```

`Request` has only `ReleaseReference string`. `Dependencies` contains a release
verifier, database, artifact reader, exact-search verifier, Kubernetes client,
observer, clock and transition-ID generator. Production construction must reject
missing/typed-nil dependencies. The request cannot override limits or endpoints.

The verifier consumes the reference and returns an immutable `ReleaseBinding`:
approved artifact digest, approved backfill/query resources and admitted templates,
image IDs, server/CA/namespace UID, database and provider identities. Its real
production implementation is a prerequisite, not part of the first slice. Test
construction uses a fixed, test-owned bundle and labels it fixture provenance.
Do not export a constructor that turns arbitrary JSON into an approved release.

The database interface has `Capture(ctx, binding) (Capture, error)` and
`WithFence(ctx, binding, func(Fence) error) (FenceResult, error)`, with explicit
`FenceResult.CleanupConfirmed` independent of callback/operation error. `Fence` exposes `Ready`,
`Capture` and `AliveAt` (database time plus live-query success), all on that same
transaction. `Capture` holds ordered receipt records, count and digest; each record
contains the exact tuple/event IDs, receipt digest, project reference/version/
digest, stage implementation versions and expected document IDs from the design.

The artifact adapter returns digest-validated immutable receipt/archive bytes for
a captured record. The search adapter verifies the documents produced by
`sessionsearch.BuildDocuments`. The Kubernetes adapter exposes only current reads,
fixed `DispatchQuery` and read-only `Reconcile`; it does not accept arbitrary JSON
Patch operations from a request. `DispatchQuery` consumes the approved binding,
the observed old API identity and newly created audit record.

## Task 1: Freeze refusal and outcome behavior

**Files:** New `types.go`, `cutover.go`, `cutover_test.go`.

- [x] Write `TestCutoverRejectsUnverifiedReleaseBeforeDependencies`: verifier error
  yields refused/not_started, zero database/provider/Kubernetes calls.
- [x] Add `TestCutoverClosedTransition` with49/51, query-already-active, changed
  worker selection and a release differing beyond the API template; each refuses
  before fence or dispatch. Add nil-context and typed-nil dependency controls.
- [x] Define just enough interfaces and a refusing executor for tests to compile.
  Add `TestCutoverDispatchesOnlyOnce`: a valid fixed fixture must cause exactly
  one dispatch and preserve its generated transition ID. Run it and retain the
  behavioral RED from the refusing implementation.
- [x] Implement the fixed flow with fake boundaries and add
  `TestCutoverLostResponseIsIndeterminate`, `TestCutoverReconcilesAppliedResponse`
  and `TestCutoverDefiniteCASRejectionIsRefused`. A timeout must never increment
  dispatch count beyond one; cleanup must execute once.
- [x] Run `go test -race ./internal/sandboxcutover -count=1` from services/platform.
  Review the public input surface before proceeding. No live constructor yet.

Task1 review checkpoint (2026-09-12): root spec review and independent quality
review approved this scoped core. Independent race PASS1.484s; root race
PASS1.485s. The cleanup correction has behavioral RED0.523s and GREEN1.490s in
`/tmp/zasp-cutover-task1-cleanup-red.log` and
`/tmp/zasp-cutover-task1-cleanup-green.log`. `FenceResult.CleanupConfirmed` now
reports confirmed rollback/close independently of callback failure; an applied
outcome survives unconfirmed cleanup. The initial refusing skeleton and restored
artifact-verification mutation are recorded in `/tmp/zasp-cutover-task1-report.md`.
These are fixture-boundary tests, not real fence/CAS or provenance evidence.

## Task 2: Real canonical capture and PostgreSQL fence

**Files:** New `capture.go`, `postgres.go`, composed PostgreSQL test file.

- [x] Install exact50 in an owned PostgreSQL18 fixture with the existing runner.
  Adapt the existing owner-fixture pattern for canonical completed receipt rows;
  document these inserts separately from registered worker transitions.
- [x] `TestSandboxCutoverPostgresCanonicalCapture` deletes one fixture queue row
  and requires refusal. An external Go overlay replacing the target LEFT JOIN
  with an inner JOIN reproduced silent receipt omission. The incomplete-authority
  matrix covers digest/order/reference/version/generation and quarantined rows;
  `TestSandboxCutoverPostgresCannotBorrowOtherScopeStages` checks missing project
  and complete authority with the same batch/event IDs retained in another scope.
  Exact canonical/stage/both-target snapshots are unchanged by refused captures.
- [x] Implement a canonical-receipt-led query with ordered, length-delimited
  digest encoding and hard row/byte bounds. Zero rows is an explicit empty set,
  still requiring all readiness/provenance checks; it is not a skipped verifier.
- [x] Write `TestSandboxCutoverFenceBlocksNewReceipt` using a second owner
  connection and a channel barrier. First run an unfenced implementation to show
  the insert completes too early. Then acquire SHARE schema/metadata and SHARE
  ROW EXCLUSIVE receipt/queue locks NOWAIT in one transaction. Prove the writer
  proceeds only after cleanup and its receipt was not included in the cutoff.
- [x] Cover self-conflicting contention in the new-receipt test, deterministic
  complete-set recapture in canonical/two-scope tests, mixed registry/readiness
  drift in `TestSandboxCutoverPostgresRejectsMixedReleaseState`, and expiry in
  `TestSandboxCutoverFenceExpiresOnServer`. Existing principal registration proves
  real index-worker denial of capture/fencing/direct canonical reads; the fixture
  migration owner succeeds. No production grants added.
- [x] Force callback failure and cancellation, then prove a second connection
  can acquire the same lock set. Test the server transaction timeout independently
  of graceful rollback. Never infer lock release merely from a local context error.
- [x] Run the focused actual PostgreSQL command below and retain terminal logs.

Task2 checkpoint: implementer full actual PostgreSQL races passed65.153s; root
independent full races passed62.486s. Independent quality review then reproduced
a contender-test masking gap. The corrected assertion requires no callback entry
and probes before queuing a writer, so writer fairness cannot mask the lock mode.
An isolated SHARE-mode overlay failed4.525s, and final shared-source contender plus
cross-scope races passed11.912s. The initial quality-review subsets passed21.576s
(actual PostgreSQL) and3.369s (bounds/deadline units). Evidence and limitations are
recorded in `2026-09-11-sandbox-query-cutover-evidence.md`. Transport row/byte
overflow tests use a bounded row-stream fixture, not10,001 actual producer batches.
No composed provider/Kubernetes transition or production provenance is claimed.

```sh
cd services/platform
env PATH=/opt/homebrew/opt/postgresql@18/bin:$PATH go test -race ./agentsec-migrate -run '^TestSandboxCutover' -count=1 -v
```

## Task 3: Exact read-only provider visibility

**Files:** New driver visibility files and executor artifact/search integration.

- [x] Add `VerifyVisibleDocuments(ctx context.Context, expected []sessionsearch.Document) error`
  on the fixed session index. Write a real HTTP fixture test where one expected
  occurrence is absent even though the investigation aggregation would look
  healthy. Require RED against a temporary aggregation-only verifier.
- [x] Implement tenant-scoped, bounded IDs search and exact document comparison.
  Reject duplicate IDs, extra/missing hits, wrong scope/digest/source contents,
  timeout, partial shards, malformed JSON and mapping/marker drift. Match by ID
  and compare the canonical order; don't rely on response order.
- [x] Record every HTTP method/path in `TestVisibilityHasNoWriteSideEffects` and
  require only mapping/marker GET and fixed-index POST_search. No refresh, bulk,
  marker PUT or schema initialization. Use existing API search IAM.
- [x] Connect immutable artifact reads and BuildDocuments to the executor. Test
  altered receipt/archive bytes fail before dispatch and provider responses can
  never supply the expected data. Add explicit row/byte/time bound failures.
- [x] Run `go test -race ./runtimeindex/opensearchdriver ./internal/sandboxcutover -count=1`.

Task3 artifact checkpoint (2026-09-12): root source review and independent quality
review approved `artifacts.go` and its actual SDK tests. Fresh focused races passed
1.794s in `/tmp/zasp-cutover-artifact-43465.log`; the independent run passed1.780s.
Both historical projection1 and Strong source-qualified sandbox projection2 use
real projection/receipt codecs, version-pinned HEAD/GET and BuildDocuments.
Non-slow corruptions must reach their target with unexpired5s contexts. Receipt
and archive share one total read deadline. SDK construction remains a supplied
trusted boundary, not endpoint/provenance discovery. A concurrent full package
run captured intermediate observation cleanup RED, so the full-package checkbox
above was open at that checkpoint. Final91549 supersedes it with complete
component races21.570s/1.906s. The isolated count-only visibility overlay57954
failed0.631s for missing, duplicate, source and version mismatches while retaining
the healthy total count; unchanged source passed the same selection1.396s.
Exact evidence: `/tmp/zasp-visibility-count-only.1lmuXr/report.md`.

## Task 4: Pinned observation and one real conditional PATCH

**Files:** New Node bridge/tests, `observation.go`, Kubernetes adapter/tests.

- [x] Write bridge tests using actual50 renders. Require all11 backfill consumers,
  same UID/generation/templates/images, no old ReplicaSet pods, exact namespace
  UID, and observation expiry below30 seconds. Reuse the existing observer; don't
  duplicate its selector/replica validation.
- [x] Write `TestCutoverPinsKubernetesTransport` with TLS test servers: wrong CA,
  server, namespace UID, redirect or replaced configuration refuses with zero
  PATCH. The bridge receives the same pinned configuration as the Go transport.
- [x] Add `TestCutoverCASUsesOriginalIdentity`. The test server changes its
  Deployment resourceVersion between read and patch. A temporary unconditional
  patch implementation must produce RED; the correct JSON Patch tests UID,
  resourceVersion and old template and refuses this race.
- [x] Verify one successful request changes only the approved API template and
  namespaced audit annotations. Preserve unrelated metadata. Exercise JSON
  Pointer escaping and opaque, nonnumeric resourceVersions.
- [x] Add `TestCutoverLatePersistenceIsIndeterminate`: server accepts the body,
  delays persistence beyond client timeout and later exposes the exact transition.
  Require one dispatch, fence release and read-only reconciliation to applied.
  Also test mismatched annotation/UID/template never becomes applied.
- [x] Run Node bridge/observer tests and Go package races; retain RED/GREEN logs.

```sh
node --test deploy/production/sandbox-query-observation.test.mjs deploy/production/compatibility-observation.test.mjs
```

## Task 5: Composed acceptance and honest handoff

**Files:** Composed PostgreSQL test file and package tests only.

- [x] Write `TestSandboxCutoverComposedPostgres`: actual50, exact canonical
  receipts/artifacts, real read-only provider HTTP and TLS Kubernetes server;
  require complete initial capture, fresh fenced recapture and one matching PATCH.
- [x] Add `TestSandboxCutoverConcurrentFenceRefuses`: hold invocation A's fence
  at a channel barrier while B tries to acquire it. Require B refused with zero
  dispatches; A can dispatch once. Also reject a fresh invocation observing an
  already-query Deployment. No audit object can bypass fresh checks.
- [x] Add `TestSandboxCutoverDelayedPersistenceOverlap`: A dispatches, times out
  indeterminate and releases its fence while the HTTP server retains its request.
  B performs fresh capture/provider/consumer checks, acquires the fence, observes
  the same old API UID/resourceVersion/template and dispatches with its own ID.
  Release server barriers in both A-first and B-first subtests. Require one
  dispatch per invocation (two total), exactly one applied CAS and no retry.
  The losing conditional request is rejected when its response is available;
  otherwise its invocation remains indeterminate. Read-only reconciliation may
  mark only the matching transition ID applied. The winner's annotation must
  never make the other invocation applied, even with an identical target template.
  Retain and compare both cutoff/evidence records; do not introduce durable intent
  or admission machinery to force a globally single dispatch.
- [x] Test a new receipt before fence acquisition refuses/restarts the whole
  operation. A receipt released after authorized dispatch may be pending normally.
  Confirm neither v1 nor v2 rows are changed by the executor itself.
- [x] Add failed-rollout and old-replica controls. Applied/pending and
  applied/failed must remain distinct from refused. Ensure reconciliation cannot
  call dispatch, queue writes, schema rollback or provider initialization.
- [x] Run the full affected Go packages, existing release/observer Node suites,
  and `git diff --check`. Read terminal logs before claiming a pass. If a test
  requires a mutation control, use an isolated copy while other agents run providers.
- [x] Request independent review of cleanup, dispatch ambiguity, DB lock order,
  complete-set capture and trust boundaries. Report local fixture proof only.

Task5 bounded composition checkpoint (2026-09-12): the new
`runtime_sandbox_cutover_composed_postgres_test.go` owns this composed lane and
reuses Task2's PostgreSQL fixture. Final composed races passed35.133s, no skips,
in `/tmp/zasp-cutover-composed-74496.log`. Independent correction review passed
14.364s in `/tmp/zasp-cutover-composed-independent.log` and closed all findings.
The cleanup regression first failed0.551s when a barrier release did not cancel
or join its owned task. Cleanup now cancels, releases and boundedly joins before
provider/admin/PostgreSQL teardown; writer errors return to the parent test.
A fresh invocation against the query Deployment refuses without changing the
winning audit/template or sending another PATCH. An external CAS-removal overlay
failed both delayed winner orders9.648s; shared source was untouched.

Canonical completed rows are declared fixture inserts derived from real receipt
and archive bytes. Release approval and consumer observation are fixed fixtures.
This closes the listed local PG/HTTP/TLS composition checks, not full11 Go observer
integration, real producer completion, live provenance or deployment authority.
Full affected-package verification and observer composition remain separate gates.

### Full11 observer integration

Continue after the base Go observation adapter's independent review closes.
This is the existing Task4/5 integration, not a live deployment command.

- [x] Add `ObservationClient.ObserveQuery` with the existing constructor-bound
  configuration and lifetime. Derive the expected11 entries by copying the fixed
  backfill pins and changing only the API template digest to `Binding.To`.
  Invoke the fixed `observe-query` operation. Query snapshots must not enter the
  backfill revalidation cache, and caller values cannot override pins or profiles.
  Test valid query evidence, old API replicas, unchanged non-API pins and cache
  isolation before approving this method for composed rollout.

Query method checkpoint: scoped independent specification/quality review approved
the two-file slice with no findings. Focused Node22 races passed7.997s and the
full package passed19.357s, no skips. The old-profile behavioral control failed
1.012s; a separate cache-publication overlay failed1.084s. It uses actual Node
full11 validation with controlled resource responses, not the later TLS/PG lane.

- [x] Add `runtime_sandbox_cutover_observation_postgres_test.go`. Extend only
  the existing composed fixture constructor/list routes where required. The new
  lane fixes schema50 annotations, generation/status and all Deployment/ReplicaSet/
  Pod templates before constructing immutable clients; leave the reviewed
  lightweight contention lane unchanged. API list and single-object responses
  must read the same mutex-protected object used by conditional PATCH.
- [x] The controlled kubectl executable validates read-only arguments and the
  private kubeconfig, then makes actual HTTPS GETs to the owned TLS server using
  its CA and token. It never returns precomputed observations. Require each
  observation's namespace/deployments/replicasets/pods/namespace sequence and the
  same server, namespace UID and credentials as the mutation client.
- [x] Compose actual Go-to-Node initial observation and fenced revalidation with
  PostgreSQL/provider/TLS cutover. Require ten observation GETs, one applied PATCH
  and unchanged canonical evidence. Old API pods, missing target2 worker and
  drift after the initial observation must refuse with zero PATCH; fenced refusal
  must confirm cleanup.
- [x] After dispatch, retain old API replicas and require applied/pending.
  Advance only the explicit test-owned controller state to healthy query replicas
  and require applied/complete through the actual query observer and final exact
  TLS reconciliation. Current-generation deadline failure remains applied/failed.
  Preserve audit/evidence and one PATCH. A fresh cutover invocation stays refused.
  Use an isolated query-observation bypass control to detect false completion.
- [x] Cancel/release/join owned tasks, close the observer, then close fixture
  resources. Verify private credential directories disappear. Run focused actual
  PostgreSQL races and affected package/Node tests, then obtain scoped review.

Full11 checkpoint: scoped independent specification and quality review approved
the two-file integration with no findings. Final component races passed21.570s
and1.906s, all actual PostgreSQL cutover tests passed128.623s, and94 Node release
tests passed. Positive observer-wiring RED5.092s and query-bypass RED5.694s
demonstrate that synthetic or API-only evidence cannot satisfy these tests.

Release approval, completed canonical rows and controller advancement remain
declared test fixtures. This integration cannot establish live artifact trust,
real admission, authenticated intake, registered completion or production rollout.

## Stop boundary

Task5 rollout implementation checkpoint (2026-09-12): independent design review
approved new `rollout.go`/`rollout_test.go` with a separate read-only result (no
invented cleanup confirmation). It uses the fixed Kubernetes client to establish
the exact applied UID/template/audit. Current-generation, unambiguous
ProgressDeadlineExceeded means applied/failed. Other incomplete evidence remains
applied/pending. Complete requires the trusted query observer's full11 ready
consumer snapshot, fresh identity digest/API fields, then a second read-only
reconciliation matching its opaque resourceVersion and audit. Check cancellation
and freshness again after that last GET. No dispatch, retry, repair or database/
provider mutation occurs. Test stale generation, old replicas, malformed/duplicate
conditions, late cancellation and resourceVersion/audit drift with real TLS plus
an explicitly controlled query-observer boundary. The real Go query-observer
method follows the initial backfill adapter and remains a separate integration gate.

The package plus controlled transport/PG acceptance is the first deliverable.
Do not add a production command with fixture provenance, an `approved=true`
escape hatch or a writable migration-role Secret mount to an existing workload.
The next design approval must identify the real artifact/admission verifier and
restricted deployment identity before a live entry point is wired. Original
provider/browser/fresh-producer and rollout gates remain in their existing plans.
