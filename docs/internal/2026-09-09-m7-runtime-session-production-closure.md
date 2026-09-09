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
