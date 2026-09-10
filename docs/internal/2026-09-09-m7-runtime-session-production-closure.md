# M7 runtime-session production closure

## Scope and audit

Preserve the original v1.5 requirements. M7 sessions are correlated agent
runtime investigations, not console authentication sessions. Independent
review confirmed that M7-01 through M7-04, M7-06 and M7-07a inherited credit
from the wrong domain or from manually seeded fixture behavior. Their
production credit is withheld; historical completion remains unchanged.
M7-05 already has component-only status. Other M7 tasks are not reassessed
by this bounded audit.

Source evidence:

- `services/platform/sessioncontrol/sessioncontrol.go` contains a process-local
  projector without a production caller.
- `services/platform/apiserver/administration_repository.go` reads console
  authentication sessions, using the constant agent ID `product-console`.
- `zasp_session_events` has no production writer. Existing event-query fixtures
  insert records directly and do not prove runtime composition.
- `app/features/sessions/SessionsComplianceView.tsx` eagerly loads those
  sessions and events without structured search or a paginated timeline.

## Ordered implementation

1. Carry the verified, immutable runtime projection receipt through completion
   into one PostgreSQL transaction. A new migration binds the exact bytes to
   the recorded predecessor artifact digest and live completion lease. Persist
   event confidence and tenant scope atomically with terminal completion.
   Reject conflicting replay and preserve unknown attribution.
2. Expose runtime-session summaries and canonically ordered event pages through
   the original session operation IDs, without conflating login revocation
   with runtime isolation. Keep authentication behavior available and explicit.
3. Implement all original structured OpenSearch filters. Use fixed term/range
   clauses and tenant constraints, never client DSL. Keep content collection
   settings and missing metadata explicit. Add bounded cursor pagination.
4. Connect the UI to the generated product client with filters, freshness,
   per-event confidence and a paginated timeline. Verify scope changes, errors,
   replay and out-of-order events with the production-composed browser harness.

OpenSearch query semantics are based on its official documentation:
[term queries](https://docs.opensearch.org/latest/query-dsl/term/term/) and
[composite pagination](https://docs.opensearch.org/latest/aggregations/bucket/composite/).
The concrete index upgrade and historical-data boundary require verification
before shipping; this document does not claim that upgrade has been implemented.

## Verification status

The first completion receipt propagation test was observed failing because
neither the executor effect nor finish request carried the receipt. Its focused
Go race test now passes. Repository tests reject absent/malformed receipts
before a database call and bind valid receipt bytes to the sole atomic finish
function, without a legacy fallback.

Migration 40 persists scoped events and projection receipts. Its semantic
fingerprint is `7f965cecd58fa1cec602bd85f4b7ac81a9984f8216bf51444a17b31194311063`.
Real PostgreSQL regressions cover wrong scope, worker, lease, predecessor,
receipt bytes, missing required arguments, role permissions, conflicting
events, exact replay and per-event confidence. A conflict rolls back terminal
completion and receipt insertion in the same transaction.

Superpowers review found a rollback race: a completion could commit after the
emptiness check and lose its new rows during Down. The concurrent database
regression failed before the fix. Down now locks both tables before inspecting
them, waits for in-flight completion, and refuses rollback with retained data.
Both focused PostgreSQL tests passed, including an independent reviewer run.

The CLI and chart now target schema 40. Completion-only readiness requires the
exact schema fingerprint and coordinator principal, with no older-schema
fallback. The initial readiness/CLI regressions failed before implementation;
focused tests and the full migration CLI/catalog suites now pass. Future-release
drift tests moved to 41. Review also found the existing API schema ceiling still
at 39; a real PostgreSQL regression reproduced the API rejection on installed 40.
The ceiling is now 40, with a separate unsupported-41 rejection regression.

The full `npm run verify` passed with 1,083 frontend tests, release checks,
production import checks and UI build before the late API ceiling correction
and additional CI regression step.
The final composed Chrome/runtime proof passed after the API correction. The
harness requires
worker-written session events, preserved unknown attribution, predecessor
receipt binding and unchanged projection data after queue redelivery.
It also passed existing multi-tenant discovery, runtime security, pinned Red
Team engine, Attack Lab, administration and restart/reload flows. The existing
session screen still reads console sessions; this run does not claim a runtime
session UI. Owned local services were cleaned up. Live cloud/provider gates
remain NOT RUN.

Final local verification passed after the API and CI corrections:

- `npm run verify`: 190 files / 1,083 frontend tests, type-checking, lint,
  release contracts, production build/import checks and the 728-row ledger.
- `go test -C services/platform -race -count=1 ./agentsec-migrate ./migrations ./runtimeevent`.
- `go test -C services/platform -race -count=1 ./apiserver -run '^TestRuntimeSession|^TestPostgresSchemaReadiness'`.
- The Node runtime/harness/ledger/runner regression selection: 51 passed,
  two explicitly gated tests skipped. They are not counted as executed proofs.
- The nine exact workflow tests passed after the new mandatory CI step was
  added to both the expected command list and valid fixture. Independent
  review reproduced the initial mismatch and verified the correction.

Superpowers review found no remaining blocker in the persistence slice.
The first push CI 34386033723 and PR CI 34386102164 failed in the full-history
secret scan. A redacted local reproduction isolated one newly committed fixed
hexadecimal lease token in the in-memory repository fixture. It is not a
provisioned credential. The pre-commit history scan had not included that new
commit. Following the existing repository policy, the correction ignores only
the exact commit/path/rule/line fingerprint, with no broad path or rule waiver.
The code and UI are unchanged. Corrected push CI 34387513826 and PR CI
34387517605 passed. PR 23 merged as 7144e713 on September 9; main CI
34388500569 also passed. Local checks are not substituted for CI.
Independent review confirmed the synthetic-only scope and exact fingerprint
exception. The full 1,347-commit history scan now passes without a finding.
The corrected full verification run also passed, including 1,083 frontend
tests, all 36 release checks, UI build/import checks and the authoritative ledger.

The ledger regression first failed on M7-01's inherited production credit.
No M7 task is promoted by this persistence slice: summary APIs, structured
search and the runtime-session UI still need their own end-to-end acceptance.

M5-22 shipped in PR 22 as main 55e819eb, with push/PR/main CI passing. All 42
M5 tasks are now production-available under their individual acceptance criteria.
The corrected current ledger is 531 production-available, 136 component-only
and 61 external gates. No live-cloud deployment,
customer collection, or launch-readiness claim is made here.

## Runtime summary and API implementation

Migration 41 adds scoped summaries derived from committed runtime events.
Backfill and trigger installation share a write-exclusion transaction. Live
inserts update counts and confidence atomically, replay leaves summaries
unchanged, event updates are rejected, and deletion rebuilds the remaining
summary. Rollback removes only the derived layer, preserving source events.
The semantic fingerprint is
`f7ab24a108da3edb743e164646f0db64119dd505f50723cde3a4635565b96d4f`.

The original listSessions, getSession and listSessionEvents operations now
have a runtime read path. Console behavior remains the default compatibility
path; callers select kind=runtime for runtime collections. Product IDs address
correlated sessions. The literal unattributed identifies a labeled collection,
not an inferred session. Unknown agent/principal values remain null. Runtime
IDs cannot revoke console sessions. Event cursors bind scope, principal,
filters and the exact investigation path. SQL rechecks the current identity
membership and investigate_sessions permission under the registered API role.

Real PostgreSQL tests pass for backfill, completion replay, restricted-role
reads, canonical HTTP pagination, cross-scope/missing stable errors and
deprovisioning. Observed database lock waits prove insert/insert and both
insert/delete interleavings; summaries match independent source aggregates.
Tests also cover immutable updates and deleting the last unknown event.
The CLI/migrations/runtime-event race suites passed, including old release
rollback/reapply paths. OpenAPI and generated clients preserve console-only
revocation and expose separate runtime DTOs; strict decoders reject
inconsistent counts, forged attribution and event order/schema drift.

Independent Superpowers review found no blocker in this slice and reran its
PostgreSQL/API and decoder suites. Full verification caught an ES target
incompatibility in BigInt literal syntax; the implementation now uses BigInt
construction and focused type/lint checks pass.

Final local verification passed: 1,108 frontend tests in 191 files, type/lint,
six staging and 36 release checks, production build/import checks and ledger
validation. The scoped PostgreSQL/API race suite passed, including negative
RLS/ACL/trigger-drift readiness and membership-role downgrade despite stale
requested permissions. The complete Chrome/runtime harness passed, with a
clean browser console and owned-resource cleanup.

The first browser attempt queried Production although the real worker writes
Staging; its empty response correctly preserved isolation. The second passed
the read/isolation checks but incorrectly expected a raw scope-permission edit
to revoke a role-derived permission. The final proof uses the worker's actual
Staging evidence, denies reads from Production, and changes the exact owned
membership to read_only_viewer against the still-live browser cookie. It
expects 403 and restores the original security_admin role and Production scope
in finally. No event rows were inserted or moved by the browser proof.

Independent Superpowers review accepted each original M7-01/02/03/04 criterion
as individually eligible after shipping CI passes. This pending-ship entry
does not yet restore their credit. M7-05, M7-06 and M7-07a remain component-only;
all structured search fields and the runtime-session UI still require their
own acceptance. The existing console-session UI remained runnable throughout.

### Shipped acceptance

PR 24 shipped implementation af31c6c9 and merged as main 4bf800f4 on September
9, 2026. Push CI 34391545741, PR CI 34391587105 and main CI 34392565900 all
passed. The previously conditional independent acceptance now restores exactly
M7-01, M7-02, M7-03 and M7-04. Current authoritative totals are 535
production-available, 132 component-only and 61 blocked/external, with all 728
original IDs retained. Historical Complete/Blocked counts are unchanged.
This is shipped source-path and composed local proof, not live cloud evidence.

### Structured-search foundation, not M7-05 acceptance

The next slice carries bounded observed metadata through the production sensor
normalizer, ingestion and canonical archive. Tetragon supplies process, file and
network-resource digests only. OTLP may carry observed principal/credential
product references, domain/resource digests and allow/monitor/block decisions.
These are observations, not authenticated ownership or correlation assertions.
No credential secret is accepted. Hashes reduce retained raw content but aren't
encryption or anonymization. Empty metadata preserves legacy archive bytes;
metadata-only mode still removes content payloads.

Source regression tests first failed when supported metadata was rejected,
then passed after the bounded schema was added. A separate valid process-exit
fixture exposed the existing transport check rejecting content-free exits.
The check now permits empty content while retaining source/class/action, size,
time, identity and metadata validation. The reviewer accepted this correction.

The new sessionsearch component emits only fixed, tenant-scoped exact-term
filters and a bounded investigation-ID composite aggregation. Process/file/
domain/resource selectors use the same domain-separated digests as ingestion.
Raw query/DSL, invalid references, time bounds and unbounded pagination fail
closed. All requested filters match the same event occurrence.

Search documents are derived by checking a committed receipt digest, decoding
its exact archive and reproducing the original projection. They retain unknown
agent/session attribution, expose absent legacy selectors honestly and never
index provider content. Independent review found a cross-batch replay conflict
in the proposed scope/event key. A new regression reproduced it before changing
the key to scope/batch/generation/event occurrence identity. Identical receipt
replay remains byte-identical; valid cross-batch occurrences retain separate
provenance. OpenSearch doc_count must not become a canonical session event count.
Session counts and read authorization remain PostgreSQL-owned.

This does not modify the existing immutable runtime index or supply a production
search endpoint. The new index/driver, durable indexing/backfill authority,
worker and API composition, search freshness, and runtime UI are still pending.
M7-05, M7-06 and M7-07a retain component-only status. The foundation race suites
and full verification passed, including 1,108 frontend tests, type/lint,
release checks, production build/import checks and all 728 ledger entries.

The fresh Chrome/runtime proof also passed: owned PostgreSQL, SQS, S3 and
OpenSearch, worker-written session reads, scoped discovery, Red Team, Attack
Lab, administration, restart/reload and clean-console checks. All owned
resources were cleaned up. This preserves the stated local-fixture boundaries.
The replay correction passed independent re-review and race tests; an added
semantic fixture proves that observed principal/credential/decision selectors
do not upgrade a Probable correlation to an attributed session.

PR 25 initially failed push CI 34394771791 and PR CI 34394828007 because the
new runtime search Go suites were added to the workflow after local full
verification without updating its exact contract fixture. The application
tests otherwise passed. The correction updates both contract expectations and
adds six negative cases preventing omission of any new package. Final-tree
full verification must pass before the correction is pushed; no merge or
additional task credit is permitted from the failed runs.

The corrected final tree passed full verification with 1,114 frontend tests,
all 15 workflow-contract tests, type/lint, release checks, build/import checks
and ledger validation. Independent review accepted the correction. PR 25
shipped implementation 61fd1876 and correction 8c040966 as main 81258ec4.
Push CI 34397443735, PR CI 34397448795 and main CI 34398331273 passed.
The production count remains 535, with 132 component-only and 61 external gates.

### Dedicated session-search index, verification in progress

The next component uses a separate immutable `zasp-runtime-sessions-v1` mapping
and marker. It shares the bounded SigV4 transport but cannot alter the existing
raw-event index or accept an arbitrary index/DSL. Writes use immutable batch
occurrences and complete only after exact source readback and explicit refresh.
Unknown acknowledgements are reconciled without immediately repeating writes.
Missing required fields, source drift and refresh failure do not produce a
successful write receipt. An isolated missing-metadata-version regression
failed before canonical source-shape validation was added.

Reads require exact schema readiness, three-field tenant scope, closed filters,
bounded composite pagination, successful shards and no timeout. Raw failures
are not exposed as provider messages or empty result sets. Canonical event
counts and current-principal authorization remain PostgreSQL-owned. Time
bounds are rounded inward to the archive/index millisecond resolution, with
an inclusive lower bound rounded up and upper bound rounded down. This avoids
including an event before a submillisecond lower bound and matches the fixed
[OpenSearch date format](https://docs.opensearch.org/latest/mappings/supported-field-types/date/).

The first real driver proof failed refresh because the owned single-node
OpenSearch fixture had one unassigned default replica. The second observed
`total=2, successful=1, failed=0`, then explicitly configured only the disposable
session index with zero replicas. Production refresh validation was not relaxed;
this is not replica or HA evidence. Exact writes and replay then passed.

The next failure was strict response decoding: OpenSearch 3.8 emitted a
`terminated_early` flag for the size-zero hit collector. An isolated owned
service reproduced the full response. The
[3.8 hit collector](https://github.com/opensearch-project/OpenSearch/blob/3.8.0/server/src/main/java/org/opensearch/search/query/TopDocsCollectorContext.java)
uses non-forced termination when hit counting is disabled, while
[QueryPhase](https://github.com/opensearch-project/OpenSearch/blob/3.8.0/server/src/main/java/org/opensearch/search/query/QueryPhase.java)
composes aggregation collection separately. The closed request explicitly sets
`terminate_after=0`, accepts this typed flag, and still rejects timeouts and
failed/incomplete shards. The running real-engine matrix checks all ten filter
kinds, same-event conjunction, cross-batch deduplication, complete pagination
and positive/negative tenant controls rather than relying on response shape alone.

The worker-committed proof reads real completed PostgreSQL receipt authority
and its exact S3 artifact. Additional semantic filter fixtures are synthetic,
isolated from every product tenant and explicitly not provider/identity
attestation. A durable production indexing outbox/worker, backfill/freshness,
read API composition and investigation UI remain pending. M7-05 is not credited.

The complete Chrome/runtime rerun passed, including the real-engine selector
matrix, worker-committed receipt indexing, existing discovery/security flows,
restart/reload, tenant denial and clean-console checks. All owned resources
were cleaned up. Independent re-review accepted the source-shape, time-bound,
replica-fixture and closed-query termination handling corrections. The harness
now requires both dedicated search proof markers and includes a regression
against removing them. Final-tree verification and shipping CI remain pending;
this evidence does not promote M7-05 or claim production search composition.

The final PR 26 tree passed full verification: 191 frontend files and 1,114
tests, type/lint, release contracts, production build/import and all 728 ledger
entries. The real pipeline rerun and independent review passed. Implementation
bcf938a3 shipped in PR 26 as main 82dfc922. Push CI 34410423363, PR CI
34410427513 and main CI 34411177421 passed. Counts remain 535 production-available,
132 component-only and 61 blocked/external.

### Durable session indexing, release verification in progress

Migration 42, `production_runtime_session_search`, derives an indexing outbox
from committed projection receipts. Backfill and the receipt-insert trigger
share the completion transaction. Canonical evidence isn't removed or rewritten.
The queue has forced tenant RLS and no direct worker/API table permissions.
Only the registered index-worker principal can claim, renew and finish bounded
attempts. Checkpoints bind scope, batch, generation, receipt SHA, ordered document
IDs, worker, lease token and attempt. Exact lost-ack retries reconcile; foreign,
expired and stale authority fails. Exhausted work is retained in quarantine.

Independent review found a lock-wait expiry defect. A real PostgreSQL test first
reproduced a finish call accepting a lease after waiting past its deadline.
Finish and heartbeat now sample the clock after their row lock. Grant deadlines
are also sampled after acquisition. The corrected test and independent rerun
passed. Added real-engine checks cover simultaneous claims, retry delay,
quarantine, attempt exhaustion and refusal to downgrade an active lease.

The existing production index-worker composition now consumes this separate
queue, verifies the exact versioned S3 receipt/archive against PostgreSQL
authority, reproduces the document IDs, and finishes only after exact immutable
OpenSearch readback and refresh. Periodic and final lease renewal fence completion.
Cancellation, unknown writes and lost acknowledgements don't become successes.

Review also found a shared readiness gate could stop healthy raw indexing when
session indexing was unavailable. Two failing regressions now pass with separate
processor gates; combined health still reports the failure. The owned pipeline
caught a SQL boolean/JSON adapter mismatch. Readiness now returns JSONB, and an
idle claim is explicit JSON null, distinct from a missing/error response.

The schema-init job initializes the three fixed inventory/raw/session indexes;
unit tests cover order, readback and failure short-circuiting. Its IAM allows
only fixed create/marker/mapping paths. The session worker has separate fixed
read and bulk/readback/refresh paths without session schema-write permission.
Review caught missing `s3:GetObjectVersion`; the existing runtime object prefix
now permits pinned-version reads. A regression failed before that IAM correction
and passed afterward. These are source/contract checks, not live AWS attestation.

The schema-42 owned PostgreSQL/SQS/S3/OpenSearch pipeline passed using actual
production worker composition, completion-triggered outbox authority, live lease
renewal, indexed checkpoint and idle replay without another claim. All ten
structured selectors, same-event conjunction, canonical occurrence grouping,
pagination and foreign-tenant controls passed. The single-node replica and
synthetic-selector limitations above still apply. Owned resources were cleaned
up. The three-index bootstrap orchestration has unit proof; the local harness
initializes the raw/session drivers directly and doesn't attest the AWS init job.

Harness/release/ledger checks passed 72 tests with two explicitly gated cleanup
tests skipped. Full UI/build verification, full Chrome proof, final review and
shipping CI are still pending for this outbox slice. No M7-05 credit: production
search API authorization/hydration, backlog freshness and UI acceptance remain.

The first full Chrome run stopped before API startup because the shared API
schema query still rejected versions above 41. A new real API-role repository
startup/readiness regression reproduced that failure. The query now admits
verified schema 42 while retaining its exact readiness function and rejecting
an unknown schema 43. The corrected focused race suite passed in 8.274 seconds.
The broad API suite also found an older router test still rejecting runtime
product IDs on reads. Its corrected matrix accepts valid runtime IDs and the
unattributed collection for read operations, rejects malformed IDs, and continues
to reject runtime targets for console-session revocation. Router code is unchanged.
The migration-version fixture now covers valid 42 and future-version 43 denial.
All owned resources from the failed Chrome run were cleaned up. Full final-tree
verification and Chrome are being rerun; nothing from this slice has been pushed.

The corrected final tree passed full verification with 191 frontend files and
1,114 tests, type/lint, release contracts, production build/import and ledger
validation. The complete API race suite passed in 316.098 seconds. Migration,
worker, session-search and index race suites passed; the complete migration CLI
suite had also passed. Independent re-review accepted the API/routing corrections
and reran the focused real PostgreSQL tests successfully.

The fresh Chrome/runtime rerun passed against schema 42: worker-written runtime
sessions, scoped discovery, administration, Red Team, Attack Lab, restart/reload,
tenant denial and clean-console checks. All owned resources were cleaned up.
The release-source gate passed. Terraform format/validate and an offline plan
passed without apply or live IAM attestation. Staged secret scanning found no
secrets; three privacy-scanner matches were verified CI run IDs. Shipping CI is
pending. M7-05, M7-06 and M7-07a remain component-only.

PR 27 shipped f622283f as main 885d0ff0. Push CI 34415255545, PR CI 34415268146
and main CI 34416118644 passed. The ledger remains 535 production-available,
132 component-only and 61 external gates.

### Authorized structured-search API, implementation in progress

Migration 43 adds scoped, current-principal search preflight and batched canonical
hydration without direct API table grants. Backlog queries use three partial
scope indexes, bounded 1,001-row probes with explicit capped counters, and one
newest checkpoint lookup. Empty candidates still require fresh authorization and
return backlog/quarantine state. Missing candidates fail instead of being silently
dropped from pagination. Source summaries own event counts and unknown identity.
The migration retains canonical evidence and indexing work on downgrade.

The real PostgreSQL foundation test passed in 5.291 seconds, and independent
review reran it in 4.917 seconds. Release CLI and migration race suites passed
after registering version 43. API repository tests cover preflight denial,
revocation during search, empty-result reauthorization, fixed provider failures,
scope/ID/count drift, and unsupported filters before I/O. Null capped/confidence
fields first reproduced false acceptance and now fail validation.

Checkpoint state is not search-provider health, unseen-event completeness,
complete selector metadata, or a consistent cross-store snapshot. The production
API now composes the dedicated index with current-principal preflight and
canonical hydration. API IAM adds only fixed session mapping/marker GET and
search POST resources. It receives no indexing or schema-mutation permission.
The OpenAPI contract and generated client publish all ten structured selectors
and optional, strictly decoded checkpoint status. The runtime list response is
not cached. Its opaque cursor binds the principal, scope and complete query.

Independent review found a no-index compatibility path that silently ignored
new selectors. Nine regression cases reproduced unfiltered success before the
fix. That fallback now rejects unrecognized selector keys before database I/O.
The focused repository race suite passed in 2.014 seconds, including malformed
candidate pages and authorized empty results that retain checkpoint status.

The expanded real PostgreSQL test passed in 6.107 seconds. It proves schema 43
API startup, unknown-44 denial, 101-candidate hydration versus 102 rejection,
and exact/capped counts at 1,000/1,001 for both pending and quarantined work.
Boundary data is explicitly synthetic and rolled back, with constraints and
triggers intact. It is not archive, worker or provider acceptance evidence.
The generated-client decoder selection passed 39 tests and the OpenAPI identity
contracts passed four. Full verification passed 191 files / 1,128 frontend
tests, type-checking, lint, release contracts, production build/import checks
and all 728 ledger rows.

Terraform formatting, validation and the offline plan passed without apply.
The composed browser harness now routes only the three fixed session-read
endpoints to its owned real OpenSearch and checks worker-written matching,
canonical counts, missing metadata, checkpoint status and provider failure.
The fresh full Chrome/runtime run passed those checks plus discovery,
administration, runtime security, Red Team, Attack Lab, restart/reload and
tenant denial. Owned services were cleaned up. The release-source gate passed.
Independent re-review reran focused races in 7.342 seconds and found no remaining
blocker. It assessed the exact original M7-05 deliverable and verification
criterion as satisfied, conditional on final verification and shipping/main CI.
The full API race suite passed in 299.208 seconds. Final harness/release/ledger
contracts passed 75 tests, with two explicitly gated cleanup tests skipped.
Staged secret scanning passed; three privacy findings were verified CI run IDs,
not phone numbers. Shipping CI is pending. M7-05, M7-06 and M7-07a receive no new
production credit yet; the UI work is next.

PR 28 shipped API commit afec5951 as main d46085cf. Push CI 34418436066 and
PR CI 34418438831 passed. Main CI 34419096909 is running. The 1,354-commit
history secret scan passed before the branch push. M7-05 remains component-only
until the final main gate passes.

### Runtime Sessions list UI, implementation in progress

The production Sessions route defaults to runtime investigations. It uses the
generated API client, fixed `kind=runtime`, a 25-item page, all ten structured
selectors and cancellation. Filters submit explicitly and reset pagination.
The view never eagerly fetches all sessions or their event histories. Query/API
identity fencing hides older results before effect cleanup; the production
principal/scope key resets the view on authorization-context changes.

Summaries retain canonical counts, per-confidence totals, unknown principal and
agent identity, event times and projection time. Unattributed is labeled as an
evidence collection, not a session inferred from unrelated events. Checkpoints,
pending/quarantine counts and observed-only coverage remain visible even when
there are no matches. Provider errors are unavailable states, not empty success.
Console login sessions and their existing revocation flow remain separate.

Eight focused UI tests passed, including all-selector API transport, missing
checkpoint rejection, unknown attribution, backlog on empty results, provider
failure, bounded paging/filter reset, context-change cancellation and console
separation. Independent Superpowers review reran all eight and found no blocker.
Full verification passed 192 frontend files / 1,136 tests, type-checking, lint,
release contracts, production build/import checks and the unchanged ledger.
The fresh full Chrome/runtime run passed the real UI proof: an incorrect process
filter returns no matches, the worker's actual process returns its canonical
unknown collection, confidence and indexing status remain explicit, and changing
scopes clears old results and filters. Responsive bounds passed at 1,440, 1,024
and 390 pixels. The existing console-login revocation, discovery, runtime security,
Red Team, Attack Lab and restart/reload checks also passed. Owned resources were
cleaned up. Independent original-task review found no remaining M7-06 criterion
gap; acceptance remains conditional on its dependency and shipping/main CI.
M7-07a timeline work remains separate and pending.

The final release-source gate passed. Harness/release/ledger contracts passed
76 tests, with two explicitly gated cleanup tests skipped. Staged secret scanning
passed; four privacy-scanner matches were verified CI run IDs, not phone numbers.
The UI slice is ready for shipping CI, without changing task availability yet.

PR 28 main CI 34419096909 passed after merge d46085cf. M7-05's original
structured-search criterion is now accepted and protected against ledger
regression. The current count is 536 production-available, 131 component-only
and 61 external gates. PR 29 contains the independently reviewed M7-06 UI;
its shipping checks are pending. No M7-06 or M7-07a credit is claimed yet.

### Runtime timeline shell, implementation in progress

The runtime list opens a target-bound drawer using generated summary and event
APIs. Each request reads one 25-event page; it never eagerly accumulates a whole
investigation. Strict decoding rejects a foreign target, reverse order, repeated
page boundary or malformed response. Query identity and cancellation hide prior
rows when the investigation, filter or principal/scope client changes. Unknown
identity and source confidence stay explicit. The page explains that event-time
pagination and fresh summaries are not a cross-request snapshot.

The real pipeline fixture now submits 26 events in descending event-time order.
All 26 pass through the existing SQS, canonical archive, five-stage worker,
completion receipt, PostgreSQL projection and immutable session index. The
owned pipeline-only proof passed with unchanged replay and receipt invariants.
No session rows are seeded to satisfy the browser. Its new browser assertion
expects the original evidence IDs in reverse ingress order across 25-plus-1
pages, checks distinct event IDs and source/confidence, returns to page one,
and switches scope while the drawer is mounted. Full Chrome proof is pending.

Independent timeline/list/decoder tests passed 56 tests. Review caught a
harness gap that closed the drawer before scope switching; it now keeps the
drawer mounted and asserts teardown. A separate RED test reproduced same-scope
cross-principal runtime event cursor reuse. Runtime event cursors now bind the
current principal as well as scope, query and investigation; console cursor
compatibility is unchanged. Focused runtime-read race tests passed. This also
corrects the earlier summary/API section's premature principal-binding claim
for event cursors, which previously bound only scope, query and investigation.
Full final verification, original-task acceptance and shipping CI remain gates.

Full UI verification passed 193 frontend files / 1,145 tests, type-checking,
lint, release checks, build and production-import checks. The full Chrome run
has passed the new timeline proof, including mounted-drawer scope teardown;
the remaining composed workflows and cleanup are still running.

### Event-row and mixed-evidence acceptance audit

Independent original-criterion review withdrew M7-07b, M7-07c and M7-07 credits.
The production runtime decoder accepts tool/runtime/network/file, not credential
or policy. The new timeline shows evidence IDs as text, without evidence links.
Its focused rendering fixture uses Exact and the real worker fixture uses
Unattributed. Neither proves visible Probable-versus-Exact differentiation.
The composed runtime fixture is single-class Tetragon evidence, not the required
mixed-evidence session. Historical six-class `sessioncontrol` component tests
have no production caller and cannot satisfy these criteria.

The ledger regression first failed on these inherited credits, then passed
after assigning the three tasks to T14-data-workflows as component-only.
Current totals are 533 production-available, 134 component-only and 61 external
gates. All 728 original IDs and historical statuses remain intact. These gaps
do not invalidate M7-07a's narrower canonical timeline-shell criterion. The
three tasks remain next in their original dependency order.

The complete Chrome/runtime run passed and cleaned up its owned services. The
release-source gate passed, including exact source SBOM/license/container/secret
checks and API resilience tests. Independent review accepted M7-07a's original
criterion conditionally on final API verification, its M7-06 dependency and CI.

The first full API race run failed the existing 100,000-row reconciliation
index test. Its plan scanned approximately 100,100 candidates before sorting;
this was real excess work, not an index-name-only assertion. Three isolated
unchanged repeats passed in 70.309 seconds. Review found the fixture refreshed
statistics only for effects, leaving the trigger-populated lane catalog and
OAuth anti-join tables uncontrolled. The experiment now analyzes all three
after loading. All index, row, buffer and spill assertions remain unchanged;
neither planner flags nor production SQL are relaxed. Five controlled repeats
and the full API suite are running. These checks do not establish bounds for
arbitrarily stale production statistics; a persistent controlled-statistics
failure requires a forward query migration, not editing shipped migration 11.

PR 29's corrected push CI 34420736786 and PR CI 34420739605 passed. It merged
as main 71920e15; main CI 34421351398 is running. M7-06 remains component-only
until that gate passes.

The controlled-statistics reconciliation proof passed five race repeats in
171.343 seconds. The final complete API race suite passed in 283.945 seconds.
Independent review accepted the fixture-only correction with the stated
statistics limitation. Final harness/release/ledger contracts passed 80 tests,
with two explicitly gated cleanup tests skipped. Staged gitleaks passed;
eight MEDIUM privacy findings were verified as one fixed synthetic ProductID
and CI run numbers, with zero HIGH findings. The timeline slice is ready for
shipping CI. M7-07a is not promoted before its dependency and shipping gates.
