# M5 Red Team production closure

Status: audit and implementation in progress. No M5 promotions yet.

The original M5-01 through M5-22 requirements remain in scope. Existing
production routes and worker adapters are not sufficient evidence for the
whole task group; each original deliverable still needs its own verification.

The first audit identified these gaps:

- Red Team browser API responses are schema/ETag checked but are not all bound
  to the requested resource, definition version, or mutation intent.
- The UI creates new mutation identities on retry, permits competing actions,
  and does not disable writes when its source query becomes stale.
- The production target predicate checks discovery freshness and target
  configuration, but does not itself check the authoritative environment
  class. Non-production safety labels supplied by a caller are not sufficient.
- The target adapter receives a run ID but its database resolver currently
  resolves only scope and target. Run/lease/category authorization must be
  checked before resolving credentials or invoking a target.
- Capability-derived pack recommendations exist in the legacy component, not
  yet in the verified production create flow.

Execution keeps API/UI request recovery separate from the database and target
execution authority. Use Superpowers test-first regressions, independent
review, actual PostgreSQL and composed-worker/browser verification. Do not
promote any M5 task based on a fixture or by weakening a safety check.

The preceding M3-52d slice passed both push/PR CI and merged through PR #9 as
`c082b80cf5612bd201cdd3104433c6fc954d8745`; main CI `34290871149` passed. Its
pre-push scanner warnings were numeric false positives: a GitHub CI run ID and
two synthetic product-ID fragments, not personal or payment data.

The Red Team browser API now binds all six resource-read/mutation methods to
the exact request identity and intent. Seventeen valid-schema mismatches were
accepted before the fix; the new suite now passes 28 checks, including stored
receipt replay and leased cancellation without a false terminal claim.
Independent review approved compatibility with the SQL receipt semantics.
Existing API/UI checks and type-check also pass. This is a bounded improvement,
not completion of M5 or its target-safety authority.

## Schema 37 admission safety

The actual PostgreSQL regression first accepted a fresh target after its
authoritative environment changed to production. The guarded forward migration
now rejects that target. Create/update definition, new run admission, and worker
claim also require an exact match to the authoritative environment and an
active, unexpired operator registration in the existing scoped credential
registry. Discovery metadata and caller-supplied credential labels cannot grant
that authority. Existing migrations are unchanged.

The actual database checks now cover environment mismatch, credential-class
mismatch, revoked/expired credentials, credential-reference drift, and stale
discovery. Registered API and worker principals prove safe creation/queue/claim,
denial after revocation, and an unchanged queued run after a rejected claim.
Rollback restores the exact v36 fingerprint and prior target semantics;
reapplying restores protection. Public EXECUTE drift, helper-body drift, and an
unknown future version fail readiness. Independent review reran the expanded
test under the race detector and approved this bounded change.

The CLI, deployment schema expectation, API readiness ceiling, and combined
test release assertion now target 37. Full CLI verification exposed the
additional central migration-version ceiling; that was updated without relaxing
checksum or future-version rejection. Fresh CLI/migration race verification
passes. All 185 frontend test files (1,015 tests), type-check, lint, production
source/compiled imports, release rendering, build, and 728-row ledger checks
pass. The release-source gate passes while keeping built-image/cloud gates
external. The fresh-build installed-Chrome combined journey passes on schema
37, including actual local runtime queue/archive/index dependencies and all
previous discovery, isolation, security, Attack Lab, recovery, identity, and
restart/reload assertions. The full API race suite passes (265.534 seconds).
An obsolete readiness source assertion was updated from ceiling 36 to 37;
its focused regression and the full suite both passed afterward.

This does not yet prove adapter-time run/lease/category authorization, the
Promptfoo process composition, reliable UI mutation recovery, capability-derived
pack recommendations, or live cloud execution. Those remain required before
promoting M5-01 through M5-22. The authoritative production counts remain
515 available, 152 component-only, 61 blocked/external, and zero missing.

## Execution regressions and current runtime slice

The prior runner treated every nonzero Promptfoo process exit as an engine
error. The pinned [Promptfoo 0.121.19 evaluation source](https://github.com/promptfoo/promptfoo/blob/0.121.19/src/node/doEval.ts)
uses exit 100 for a completed evaluation below the pass threshold, after writing
its output. The production runner now accepts exits 0 and 100 only after strict
output normalization; other exits remain bounded engine errors. The actual-image
regression first reproduced the incorrect engine-error verdict, then passed
safe, unsafe, and unavailable-adapter cases after the fix.

Inspection of the exact pinned container also confirms that
`/app/node_modules/.bin/promptfoo` does not exist; its package declares
`dist/src/entrypoint.js` as the CLI. A network-isolated actual-image regression
first failed on the safe evaluation with the prior production runner. The Go
runner now pins `/app/dist/src/entrypoint.js`, invoked through the pinned Node
executable. The exact Promptfoo 0.121.19 base image executes the production JS
runner against a synthetic offline HTTPS adapter. This does not yet compose the
actual Go adapter, queue consumer, database, and evidence store into one flow.

The safety/API slice was merged in [PR 10](https://github.com/crossbizz/zasp-sec/pull/10),
main commit `f4ee827a0688815cd832a50dbf4701bedbd87890`. Push CI 34292928981,
PR CI 34292956848, and main CI 34293529974 passed. The pre-push scan reported
eight medium matches: four synthetic product-ID fragments classified as card
numbers and four GitHub CI-run-ID mentions classified as phone numbers. Inspection
confirmed those false positives; no high finding was reported.

Migration 38, `production_red_team_invocation`, requires
exact tenant scope, run, live lease, category, current definition version,
enabled target, non-production environment, active matching credential, and
current discovery provenance before resolving an endpoint. The old five-argument
resolver now denies requests; its private implementation is not executable by
the adapter. The actual PostgreSQL regression reproduced the legacy bypass
before the fix. Positive invocation, eight request-field mismatch denials,
eight live-authority invalidations, principal isolation, ACL drift, future-schema
denial, exact v37 rollback, and reapply now pass under the race detector.

Separate actual PostgreSQL regressions reproduced check-constraint failures
when claiming cancelled or exhausted leased runs. Migration 38 clears terminal
lease fields in both branches; both regressions pass. Its pinned semantic
fingerprint is `8c373c0aa7c2fabcfd2e46b0d2bf05a078f68b0f1257e2866083e996de880a0b`.
The CLI, central version validation, deployment expectation, API ceiling, and
combined-journey schema assertion target 38 without weakening historical
checksums or unknown-future-version rejection.

The worker sends the lease through an allowlisted child environment and exact
`X-Zasp-Run-Lease` header, not persisted input or evidence. Missing, malformed,
or ambiguous leases are rejected before resolution. Eight simultaneous actual
database queries reproduced seven `connection busy` errors in the adapter's
shared connection. A bounded eight-connection pool now passes the concurrency
race regression; the adapter startup uses the new release readiness function.

The offline image proof owns one UUID-labelled container and a temporary
test-only TLS directory, with bounded cleanup. An actual SIGTERM run exited 143;
inspection confirmed both the owned container and temporary key directory were
removed. This is local interruption evidence, not a cloud shutdown claim.

Independent Superpowers review identified stale release-contract schema
expectations and unbounded database work during HTTP requests/shutdown. Both
were fixed. The production HTTP server now imposes request-context deadlines
and cancels active handlers before shutdown; database readiness/queries have
configured deadlines and lifetime cancellation, and pool close is bounded.
An actual HTTP/PostgreSQL regression first failed for both timeout and shutdown,
then passed under the race detector. Independent re-review reran those checks
and found no remaining blocker for this bounded slice.

Fresh verification passes: all 185 frontend files / 1,015 tests; contracts,
tenancy, type-check, lint, source and compiled import checks, release rendering,
build, and all 728 ledger rows. Full API race passes (276.711 seconds), as do
full CLI/migrations/worker/adapter race checks; the final adapter lifecycle race
suite passes (4.642 seconds). The exact-image proof passes all five tests,
including actual pass/fail/engine-error execution (23.922 seconds).
The fresh Chrome combined run passes on schema 38, including the actual local
runtime SQS/S3/OpenSearch pipeline and prior discovery, tenant isolation,
Security Agent, Attack Lab, recovery, identity, and restart/reload journeys.
The release-source gate passes; built-image signing/scans, remote CI, live
providers, and public DNS/TLS remain separately required release gates.
No M5 task is promoted by this bounded slice.

Reproduce the opt-in actual-image regression with:

```sh
ZASP_PROMPTFOO_IMAGE_TEST=true node --test workers/redteam-node/runner.test.mjs workers/redteam-node/image.integration.test.mjs
```

It requires Docker and the exact digest-pinned image. Without the explicit flag,
the image test is skipped; a skipped image test is not execution evidence.

The runtime slice is merged in [PR 11](https://github.com/crossbizz/zasp-sec/pull/11),
implementation `3bd7be0227e158a8236c5c09c74165bfbea920e8`, main
`87bdba15c35011966bd7a2cfc706eda71d27f126`. Push CI 34295449725, PR CI
34295474737, and main CI 34296047515 passed. The push scan had 12 medium
matches: three CI IDs, four synthetic product-ID fragments, and five occurrences
of the fixed test-service hostname. Inspection confirmed those intended test
and evidence values; there was no high finding.

## Retained UI request closure

New regressions reproduced two run requests from one synchronous double-click,
missing retained retry after an ambiguous response, stale data with writes still
enabled, and a request following a changed session scope. The current UI slice
retains one validated request and idempotency key before I/O, keyed by principal
plus organization/workspace/environment. It freezes the request, requires
explicit retry, aborts on unmount or lost authority, and verifies local checkpoint
acknowledgement. It does not retain API credentials, worker leases, native output,
or response receipts. The API explicitly pins the captured tenant scope.

All 60 focused API, UI, and controller tests pass. Independent review identified
two additional regressions: a first authoritative version conflict permanently
locked writes, and delayed rejection cleanup could delete a replaced checkpoint.
Both were reproduced failing, fixed, and independently re-reviewed with all 60
tests passing. Only a known first-response version conflict releases its request;
ambiguous or idempotency conflicts retain the original request. Cleanup verifies
exact stored ownership and current authority, and fails closed on storage failure.
The UI closes stale details and locks writes through authoritative refresh.

The fresh browser proof exposed an incomplete legacy Attack Lab target fixture:
tests/runs/tools returned 200, but agents returned 503 because its winning
source/snapshot/evidence links were missing. Explicit joined fixture provenance
now satisfies the unchanged production validation. The next run reached exact-scope
retry; its wait was corrected to require the confirmed unlocked state, not the
temporary disappearance of Retry while submitting. The fresh full Chrome run
then passed, including cleanup. A real API 202 was consumed before injecting
503 response loss. Reload and a Production-to-Staging scope round trip retained
the exact request body, idempotency key, version, and scope. PostgreSQL proved
one queued run, zero attempts, one audit, one receipt, and one outbox record
before and after retry; cancellation produced one cancelled run with two audit
and receipt records and still one outbox. Confirmed recovery left no checkpoint.

Fresh `npm run verify` passed: 186 frontend files / 1,044 tests, contracts,
tenancy/race checks, type-check, lint, build, source/compiled import checks,
release rendering, and the 728-row ledger. The release-source gate passed.
Independent review approved this bounded recovery slice and separately reran
all 60 focused tests. The slice is merged via PR 12: implementation
`46c0551b8870cf33c0f656d1363c6ff7b4da4f17`, main
`a17171f4df78be70fc34fe4d37b13dee913d5f9f`. Push CI 34297746379 and PR CI
34297776266 passed. Main CI 34298409019 is in progress. The six medium push-scan
matches were three synthetic product-ID fragments and three CI IDs; no high
finding was reported, and the hook was not bypassed.
This is not a Red Team worker/Promptfoo/S3 composition claim or an M5 promotion.

## Capability recommendations in progress

The production create flow now reads exact-target inventory detail and paged
agent capabilities through scoped product APIs. It recommends only relevant
reachable, nonblocked boundaries with explanations and evidence IDs. Names and
tags do not establish capabilities; data-read access does not establish data
classification. Direct tool targets use their own discovery evidence and never
send a tool ID to an agent endpoint. Missing, stale, foreign, or unavailable
authority does not produce a confirmed recommendation. Selection is explicit
and remains separate from execution admission.

Seven selector and six API tests passed after the missing production behavior
was reproduced failing. The initial installed-Chrome combined proof passed
agent identity-boundary and direct-tool recommendations, explicit selection,
safety fields, and zero created definitions/runs. Review found that an open
wizard could outlive its evidence expiry. A clock-advance test reproduced that
failure; the API now retains target identity and expiry, the UI refreshes when
evidence expires, and Apply rechecks both. Automatic expiry and late old-target
response tests pass. Independent review reran all 30 selector/API/UI tests and
approved this bounded slice. Fresh full verification passed: 188 frontend
files / 1,062 tests, contracts, tenant/race checks, types, warning-free lint,
build, exact source/compiled imports, release rendering, and all 728 ledger
rows. The release-source gate passed. The latest fresh Chrome run passed the
new recommendation journey and all prior lifecycle checks, including cleanup.
A final lint-only retry-reference extraction was covered by full verification.
Task-level review found the original M5-03 deliverable and verification covered;
its ledger promotion waits for this change to ship with passing remote CI.
M5-15 and worker/Promptfoo/S3 completion remain separate. No task promotion is
claimed yet.
