# M5 Red Team production closure

Status: audit and implementation in progress. M5-01, M5-03, and M5-04 promoted
after individual acceptance review and passing main CI; all other open tasks
retain their existing classifications.

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
34297776266 and main CI 34298409019 passed. The six medium push-scan
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

PR 13 merged implementation `75e0838b2d234df6f02a432d93fdbf9110105dd4`
as main `e573e987db1b3bb71613a9a4199947e0f5f218cb`. Push CI 34298883240
and PR CI 34298942610 passed. Main CI 34299688370 failed one existing
`ZaspApp.test.tsx` URL assertion: the heading rendered before the passive
route-normalization effect replaced `/inventory/tools` with `/`. The test now
awaits that exact URL assertion; it still requires zero product fetches and
exactly one bootstrap request. No product code or authorization checks changed.
Independent review approved the synchronization correction and independently
reran all 30 application tests successfully. Fresh full `npm run verify` passed
all 1,062 frontend tests, contracts, race/tenant checks, types, lint, build,
source/compiled imports, release checks, and the 728-row ledger.

PR 14 merged correction `932a09b505e09b2f83a81171dd54c4a2083db17c` as
main `06210ff446a634bcf578c862da003b46708c37d2`. Push CI 34300181142,
PR CI 34300212338, and main CI 34300722566 passed. All five medium push-scan
matches were CI run IDs, not personal data; there were no high findings.

## Individual task acceptance

M5-01 is production-available: `apiserver/red_team_repository.go` defines the
production definition/run/attempt types and safety metadata; the published
OpenAPI schemas distinguish `engine_error`, `pass`, and `fail`.
M5-03 is production-available based on the selector/API/UI and fresh Chrome
proof above. M5-04 is production-available: the real PostgreSQL authoritative
environment/credential tests reject unsafe fixtures before queueing, and the
mounted definition view displays persisted expected side effects. Independent
review checked each original deliverable separately. Totals are now 518
production-available, 149 component-only, 61 blocked/external, zero missing.

M5-05 through M5-12 stay component-only. Production routes and several success
cases exist, but each operation still needs the original required handler
success plus stable product-error assertions. The legacy MemoryStore handler
suite does not close that production verification gap. M5-02 and M5-14 still
need the input/raw-artifact reference and policy-redaction acceptance audit.
These classifications are not a whole-M5 completion or live-cloud readiness claim.

## Composed Red Team runtime and cancellation proof

The opt-in combined proof now starts the actual production outbox and Red Team
worker compositions against disposable PostgreSQL and local SQS/S3/KMS services.
A real browser creates and queues the definition/run. The worker invokes the
production Go launcher, Node adapter, pinned Promptfoo image, and lease-bound
Go HTTPS target adapter. The image runs as production UID/GID 1000 with a
read-only root, dropped capabilities, bounded resources, and exact production
secret paths. Only the customer target invocation is a deterministic fixture;
cloud role attestation and customer HTTPS execution are not claimed.

The fresh full Chrome proof passed. Actual duplicate SQS publication produced
one attempt and one target invocation. The completed run had no active lease.
The exact versioned evidence object matched PostgreSQL size/checksum and KMS
bindings, contained normalized verdicts, and excluded the secret fixture,
adapter token, and lease. Both queue and DLQ had zero visible, in-flight, and
delayed messages, confirmed by empty receives. Reload showed the durable result
and Verify safely eligibility. The separate real-SIGTERM harness test passed:
its exact owned runtime container, processes, and temporary root were removed.
That interruption test establishes container cleanup, not that Promptfoo had
already started when the signal arrived.

A real descendant-heartbeat test first failed because CommandContext killed
only the launcher. The Linux supervisor now owns a dedicated process group,
observes termination with WNOWAIT, and sends all group signals before reaping
the leader. This pins the process identity against PID/PGID reuse. Loss of wait
ownership never permits another signal; reconciliation cannot block the failed
operation. Unsupported operating systems fail closed. Node cancellation kills
and reaps its Promptfoo child without writing a completed result. Actual pinned
image checks passed for protected, unsafe, engine-error, and cancellation
outcomes. Linux subprocess tests cover graceful and stubborn descendants plus
completion/cancellation races. Independent review approved the bounded runtime
slice and independently reran 15 Node/runtime-helper tests. A regression
assertion reproduced and then rejected signaling after lost wait ownership.

This proof still stores normalized output, not the original required input/raw
artifact bundle. M5-02 and M5-14 remain component-only. It is not a live AWS,
customer credential, deployed image, or whole-M5 acceptance claim. CI now runs
the runtime-helper, Node cancellation, combined-proof contract, and ledger
regression suites on every push and pull request.

The syscall supervisor directly uses the existing checksum-pinned `x/sys`
v0.44.0 module. The direct dependency ledger now records its inspected
BSD-3-Clause license and exact version/owner/runtime metadata; no module version
or checksum changed. This license was already accepted by the production
release scanner. The dependency policy tests reject metadata drift, and the
independent reviewer reran all 81 dependency tests successfully. The workflow
contract was updated for the extra CI step and now checks its valid baseline
before hostile workflow mutations.

Fresh full `npm run verify` passed all 1,063 frontend tests, contract and
tenant/race checks, types, warning-free lint, the production build, exact
source/compiled import checks, release rendering, and all 728 ledger rows.
The release-source gate passed. The focused Node/runtime/ledger suite passed
45 tests; two opt-in interruption tests were skipped there, with the Red Team
interruption test separately executed and passed as recorded above. Latest
Linux cancellation and completion-race subprocess tests passed three repeated
executions in the pinned image. Remote push/PR/main CI remains to be recorded.

PR 15 push CI 34302662350 passed full application verification, then its new
regression step exposed a harness portability defect: the ordinary SIGTERM
test tried `/opt/homebrew/bin/initdb` on Linux. PostgreSQL tools now come from
bounded `pg_config --bindir` discovery, validated before temporary resources are
created. The source regression and actual local SIGTERM cleanup passed, and
independent review approved the fix. This changes PostgreSQL discovery only;
the full Chrome harness still requires the documented local browser setup.

The original M5-05 through M5-12 handler acceptance gaps now have one explicit
matrix covering all eight operations. Each case exercises the production
handler plus PostgresRepository with only the SQL transport replaced. Browser
and PAT cases assert exact successful JSON/status, tenant-scoped SQL operation,
ETag, audit and receipt boundaries, plus exact stable product-error JSON with
no mutation authority. The matrix passed under the Go race detector and an
independent reviewer reran it and approved each task separately. It is now a
required CI command. This is not a live database or middleware authentication
proof. Task promotions wait for the tests to ship with passing verification.
Fresh full verification after the portability correction passed, including
1,063 frontend tests and the production build. The exact latest CI command and
workflow contract also passed locally. The first push scan's 20 medium matches
were inspected: synthetic IDs/DSNs, CI IDs, and explicit local Docker/Kubernetes
hostnames; there were no high findings and no scanner bypass.

PR 15 merged runtime commit `f3a93f2a13acd9e068d8911c222c8fc8826485ae`
and portability/API-acceptance commit `15175edf8753e6b96d09b29fbba414fe0cc3bf91`
as main `3854ee5f1fc7b4f900e28fb1c63746ad3dd83019`. Corrected push CI
34303330721 and PR CI 34303333610 passed, including Linux cleanup and the
eight-operation API matrix. The correction push had two inspected medium
matches: a CI ID and a synthetic product ID; no high finding. Main CI
34303890095 passed. Input/raw-artifact work continues separately and is
not included in this merge. Independent task-level review accepted M5-05
through M5-12, M5-13, and M5-15. The authoritative ledger now records 528
production-available, 139 component-only, and 61 blocked/external tasks.
M5-02 and M5-14 have not been promoted.

## Durable input and native evidence, schema 39

The artifact slice uploads the exact typed runner input before invoking the
target. Its separate immutable S3 receipt contains the tenant-scoped object,
version, SHA-256 and size. The result object is a versioned evidence bundle
containing that receipt, the normalized summary, and the native Promptfoo
result structure under `red-team-artifact-redaction-v1`.

The policy retains only pinned engine metadata, curated prompt/category,
provider label, pass/fail and HTTP status. Response bodies and grader reasons
are replaced with `[REDACTED]`; arbitrary fields, headers, provider configuration,
secret-key fields and runtime credentials are excluded. This is policy-redacted
native evidence, not an unfiltered transcript. Both native and normalized
results must agree with the exact run/input/category authority. Missing boolean
results were reproduced as incorrectly accepted, then rejected by required
fields and hostile tests. S3 receipt tests reject wrong scope, identity, size,
checksum, version, bucket syntax and object path.

Schema 39 stores the input receipt on the immutable attempt. New completion
requires it atomically with the existing tenant/live-lease/digest authority.
The old completion signature denies execution and its private implementation
cannot be called by the worker. Legacy attempts honestly omit the new field.
Rollback refuses to discard retained receipts; empty rollback and reapply
restore the exact prior fingerprint. The new semantic fingerprint is
`945775780a1752765398d6da17ce9aaf75c2fec8877d20c14c871020bfb0039c`.

The worker requires this exact release before processing. CLI/catalog, API
compatibility ceiling, deployment job/schema expectations and the combined
harness target 39. The public contract and generated client expose the optional
receipt. Strict browser decoding rejects malformed and cross-scope input
references. The result drawer shows object/version/checksum/size, or explicitly
identifies legacy attempts without an input artifact.

Actual PostgreSQL race tests pass for exact down/reapply, fingerprint/permission
drift, wrong tenant/run/worker/token/digest/input scope, expired lease, wrong
principal, private-helper denial, retained receipt and guarded rollback. Public
readback uses the registered API principal and production repository constructor.
Independent review reran and approved the corrected PostgreSQL proof. Initial
readback used an incomplete test principal setup; production authorization was
not weakened to make that test pass.

The actual pinned Promptfoo image passed all ten engine/artifact/runner checks,
including protected, unsafe, engine-error and cancellation outcomes. Worker
and adapter race suites passed. Release rendering passed 32 tests after exact
schema-job assertions were advanced to 39. Types and warning-free lint pass.
The schema39 full browser/runtime proof passed. The browser created a test and
queued its run; the actual composed outbox/SQS/worker/pinned-engine/Go-adapter
path retained exactly one attempt and invocation under physical duplicate
delivery. Both input and result S3 objects matched their exact version,
checksum, size and KMS binding. The result bundle was independently rebuilt
from its durable input, normalized summary and redacted native structure, and
matched byte-for-byte. PostgreSQL and the reloaded browser retained the exact
input receipt. Queue and DLQ were empty. Browser exception/console checks and
owned resource cleanup passed.

The first schema39 full journey stopped earlier at temporary-policy deployment
pending. A bounded policy-database error trace was added to the harness. The
same full journey then passed without changing product policy behavior; the
earlier failure's cause is not confirmed and no fix is claimed for it. Full
verification is being rerun. This section does not yet promote M5-02 or M5-14.

Independent original-task review accepted M5-02 and M5-14 as eligible once this
slice ships and required CI passes. It also accepted M5-18's original
fixture-level criterion from the already shipped production Kubernetes
provider: run-scoped jobs, Fargate profile selection and cleanup ownership.
That does not attest live Fargate scheduling. The worker race suite reran the
production Kubernetes manifest and UID-fenced cleanup tests successfully.

The next M5 gaps remain explicit: M5-16 needs result grouping by security
outcome; M5-17 needs the production provider's capabilities/isolation contract
mapped and tested; M5-19 needs a production timeout/cleanup fixture. M5-20 still
requires the original dedicated test IAM role reference, without inheriting
the product worker role. M5-21 needs a direct undeclared-egress denial fixture,
and M5-22 needs an undeclared-host request against the production proxy with
zero forwarding. None of these requirements has been removed or credited
from local policy-library tests alone.

Fresh full `npm run verify` passed all 1,078 frontend tests, contract/tenant/race
checks, types, warning-free lint, release rendering, production build,
source/compiled import checks and all 728 ledger rows. The separate production
release-source gate passed. The focused Node/runtime/ledger suite passed 48
tests with two opt-in interruption tests skipped, and the API acceptance/input
reference race tests passed. Remote push/PR/main checks remain pending.

PR 16 merged artifact commit `ca26f084f4ddb671617c4ff2f598dfb1ae59fe6e`
as main `99bb766feaef6b5cee4528cd5421e20a9a3c211f`. Push CI
34306374745 and PR CI 34306402626 passed. The full API race suite also
passed locally in 314 seconds, and a second complete schema39 Chrome/runtime
journey passed, including temporary-policy enforcement, durable redacted
artifacts, reload and owned cleanup. The pre-push scan's 20 medium matches
were individually inspected: synthetic IDs, CI run IDs and an explicit local
Kubernetes hostname. There were no high findings and no bypass.

Main CI 34306928829 passed. With the shipped evidence and independent
task-level acceptance, M5-02, M5-14 and M5-18 are now production-available.
The ledger records 531 production-available, 136 component-only and 61
blocked/external tasks, totaling all 728. M5-18's credit remains limited to
its original production-provider fixture criterion, not live Fargate proof.

## M5-16 security-outcome results

The production results view now groups runs into unsafe behavior observed,
curated checks passed, evaluation errors, in progress, and cancelled. Pending
or cancelled states cannot become a completed security outcome even if a
malformed fixture supplies a failing verdict. A passed pack does not claim
coverage beyond its selected categories. Evaluation errors establish no
security verdict.

Verify safely is available only for a completed failing evaluation with an
attempt, completion time and evidence reference, without cancellation. It
navigates to the existing Attack Lab safety review, not execution approval.
The browser proof selects the exact source run, obtains a fresh server safety
decision, checks that approval remains unchecked and Run remains disabled,
and compares durable run/outbox counts before and after navigation.

Outcome unit tests and rendered UI tests were observed failing before the
implementation, then passed all 22 focused tests. The browser source-contract
test likewise failed before its new assertions and passed afterward.
Independent Superpowers review reran all 22 tests and found no blocker.
M5-16 remains component-only until full verification, browser proof, shipping
and required CI pass.

The full fresh-build Chrome journey passed, including outcome grouping,
exact-source fresh safety review with zero new execution authority, all
existing product journeys, clean console/exception streams and owned cleanup.
All 1,082 frontend tests passed. Full verification then caught the new pure
outcome module missing from the exact production-import allowlist. A regression
reproduced that rejection, then passed with only that exact source added;
demo siblings and outcome test modules remain rejected. All seven import
contract tests and the 38-file source graph pass. The release-source gate
also passed. Full verification is being rerun after this integration correction.

The corrected full verification passed: 190 frontend files and 1,082 tests,
tenant/race and API contracts, types, warning-free lint, all release rendering,
production build, source and compiled import boundaries, and all 728 ledger
rows. The runtime/Node/ledger CI regression command passed 50 tests with two
opt-in interruption cases skipped. Independent final review passed all 30
import/ledger tests. The pre-push scan's six medium matches were inspected and
all were documented CI run IDs; there were no high findings or bypass.

PR 17 shipped outcome commit `03c1db9d` after push CI 34307535807 and
PR CI 34307549558 passed. It merged as main
`4aa5888651f1051241049761ac2a62b8e71974fe`. Main CI 34308044218 is pending;
M5-16 has not yet received production credit.

## M5-17 production sandbox lifecycle contract

The production provider now exposes Create, Run, Cancel, Destroy and typed
Capabilities, plus the retained reconciliation operation. Create schedules
the exact owned Job. Run observes it without creating another execution.
Capabilities declare EKS Fargate pod isolation, proxy-only egress, UID-fenced
lifecycle operations, and the exact CPU/memory/storage/timeout bounds. These
declarations are not evidence that a particular pod achieved isolation;
cluster readiness and exact pod/profile checks remain separate. Unsupported
capabilities fail before consuming or claiming queue work.

Cancellation is called only after a durable cleanup checkpoint, or while
resuming an existing cancelled checkpoint. An uncertain cancellation response
retains that checkpoint and cannot destroy, finish or acknowledge the run.
Restart resumes termination and final cleanup without creating or running
another sandbox. A failed checkpoint commit performs no destructive provider
I/O. Readiness and lifecycle panics remain bounded failures.

Independent review found a real termination gap in the existing Kubernetes
cleanup: background Job deletion could return Job404 while owned pods still
ran. This is consistent with Kubernetes' documented
[background garbage collection](https://kubernetes.io/docs/concepts/architecture/garbage-collection/).
The correction uses foreground deletion with the exact UID precondition,
then verifies dependent-pod absence even when the Job was already missing.
The exact namespace/job selector must return an explicit non-null, unpaginated
PodList. Owned pods keep cleanup pending. Foreign or malformed ownership
fails closed, with no destructive pod requests. Only an empty list permits
completion. Thus foreground deletion alone is not treated as sufficient proof.

Tests were observed failing for missing lifecycle capabilities, missing
checkpointed cancellation, premature acknowledgement after cancellation
failure, and all five Job404/pod-list regressions. They pass after the changes.
The real Kubernetes API transport fixture is also exercised through the
controller cancellation boundary: a live owned pod forbids finish/ACK, then
restart after confirmed absence permits idempotent completion. Tests cover
foreign UID denial, uncertain deletion, repeated Destroy and repeated Run
without another Create. The full worker race suite passed in 7.983 seconds.
Independent re-review reran the focused race suite and accepted M5-17's
original contract and fake-provider criterion, contingent on remaining
verification, shipping and CI. No live Fargate isolation claim is made.

Main CI 34308044218 passed for PR 17. M5-16 now has production credit,
bringing the ledger to 532 production-available, 135 component-only and 61
blocked/external tasks. Its anti-demotion regression failed before the ledger
update and passes afterward. M5-17 remains component-only until its own ship
and CI closure.

The fresh-build full Chrome journey passed with the updated provider contract:
production Attack Lab approval, composed controller/outbox, evidence, cleanup,
rerun, cancellation and reload; red-team pinned-engine artifacts and safe
handoff; all discovery, security, recovery, administration and restart checks.
Console/exception checks and owned process/container cleanup passed. This
journey still uses its explicitly identified local sandbox/provider fixture;
the real Kubernetes API cleanup behavior is covered by the separate hostile
transport/controller tests above, not a live Fargate deployment.

Final full verification passed all 1,082 frontend tests, tenant/race and API
contracts, types, warning-free lint, release rendering, production build,
source/compiled import checks and the 728-row ledger. The separate release
source gate passed. The runtime/Node/ledger command passed 50 tests with two
explicit opt-in interruption tests skipped. The pre-push scan's 19 medium
matches were inspected individually: seven CI IDs, eight synthetic Kubernetes
UIDs, three fixture-token suffixes and one synthetic product ID. No high
finding or scanner bypass occurred. Push/PR/main CI remains to be recorded.

PR 18 shipped sandbox contract commit `da9aeaef` after push CI 34308745174
and PR CI 34308747843 passed. It merged as main
`11305902ab8f2a2481fbfbcaadac25d762caf5ee`. Main CI 34309274962 passed.
M5-17 now has production credit under its original fixture criterion. The
ledger has 533 production-available, 134 component-only and 61 blocked/external
rows, with no missing rows. This does not attest live Fargate isolation.

## M5-19 absolute sandbox timeout and retained reason

Production collection now uses the remaining time from the durable attempt
start plus its approved 300-second limit. A resumed attempt cannot obtain
another five-minute budget. An already-expired attempt performs no collection,
and a result returned after the deadline cannot become a security verdict.
The existing production manifest tests retain exact CPU, memory, ephemeral
storage and active-deadline bounds.

Only an exact namespace/name/UID Job reporting Failed=True with
Reason=DeadlineExceeded, or expiration of the approved collection budget,
establishes the fixed timeout explanation. Contradictory completion, caller
cancellation/deadline and HTTP transport timeout do not. Both Job polling and
completed-Job dependent-evidence retrieval apply the same distinction. A
private typed marker preserves the cause through provider normalization;
the public result remains inconclusive with error_code=outcome_unknown.
Its bounded Kubernetes evidence says the approved attempt deadline elapsed
and sandbox cleanup is required. No raw provider message is retained, and
the result does not claim the sandbox stopped exactly at the deadline.

Tests reproduced the reset budget, absent timeout explanation, rejected
subsecond remainder and completed-Job evidence-read gap before each fix.
They now cover exact Kubernetes deadline, foreign ownership, contradictory
completion, local budget expiry, caller and HTTP timeout distinctions,
500-millisecond resumed remainder, late success and expiry with no I/O.
The production Kubernetes HTTP path is exercised through the controller:
bounded timeout evidence is retained before cleanup, uncertain deletion
cannot finish/ACK, and restart resumes cleanup without rerunning evaluation.

The corrected full worker race suite passed in 8.275 seconds. Independent
Superpowers re-review passed the timeout/deadline race tests and accepted
M5-19's original limits/timeout fixture criterion, contingent on final
verification, shipping and CI. M5-19 remains component-only. This is not a
live Fargate execution or exact-deadline termination claim.

The full Chrome product check passed again, including actual pinned red-team
execution, versioned input/result evidence, sandbox UI, reload, discovery,
security, recovery and administration. Browser exception/console checks and
owned-resource cleanup passed. Its sandbox remains an identified local
fixture. The final completed-Job error-branch correction was separately
verified by its new regression and the full worker race suite.

Final full verification and the separate release source gate passed after
that correction. Production build and compiled import checks passed; the
ledger still contained 728 rows. No live cloud or deployment gate is claimed.

The final runtime/Node/ledger regression command passed 50 tests with two
explicit opt-in interruption tests skipped. Independent final review accepted
the code and reconciled the 533/134/61 ledger, promoting only M5-17 after its
main CI passed. The pre-push scan's 15 medium matches were individually
inspected: six CI IDs, six synthetic Kubernetes UID suffixes, two fixed
in-cluster fixture hostnames and one synthetic fixture-token suffix. No high
finding or scanner bypass occurred. M5-19 shipping and CI remain pending.

PR 19 shipped timeout commit `90e80f23` after push CI 34309888042 and
PR CI 34309939481 passed. It merged as main
`be4db822d4a6818ba750f5635e717ea9c19b49f8`; main CI 34310435523 passed.
M5-19 now has production credit. The authoritative ledger has 534
production-available, 133 component-only and 61 blocked/external rows.

## M5-20 dedicated sandbox test identity

The controller now requires a same-account runner-test role distinct from its
own role. Release rendering passes that exact reference to the controller and
dedicated sandbox service account. Readiness rejects missing/foreign/product
roles, extra identity annotations, automounted API credentials and secret
references. Job create/reconcile cannot select a different configured role.

Terraform creates a separate runner-test role with exact EKS OIDC provider,
STS audience and isolated service-account subject. Its explicit deny-all
policy and permissions boundary grant no AWS resource permissions or role
chaining. The current curated runner reaches approved targets through the
product egress proxy; it has no approved direct AWS actions. This identity is
separate from the Fargate infrastructure execution role. AWS documents that
the infrastructure role is not inherited by containers in its
[pod execution role reference](https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html).

The Job specifies its own STS-only, 600-second projected token, read-only
0440 mount, exact test-role environment and disabled metadata fallback.
All required web-identity, region and regional-STS keys and the token volume
are already present. The official
[AWS webhook implementation](https://github.com/aws/amazon-eks-pod-identity-webhook/blob/master/pkg/handler/handler.go)
preserves these existing keys and volume. The runner rejects product roles,
static/session credentials, credential profiles, container credential
endpoints and moved token paths before starting. No AWS API invocation is
needed or claimed by this proxy-only runner.

Review during implementation found that completed-Pod collection had checked
image/ownership without checking actual identity. It now validates the actual
Pod service account, explicit disabled automount, exact token volumes/mounts,
AWS environment and absence of injected credentials or extra containers.
The observed Fargate profile name was also corrected to the provisioned
`attack-lab` profile; the previous `agentsec-attack-lab` check rejected the
correct profile. Its exact fixture failed before the correction and passed
afterward.

Red tests reproduced missing/inherited/foreign-role configuration, absent
Terraform identity, seven accepted hostile Pod identities and seven accepted
runner startup credential drifts. Green coverage includes those cases,
service-account readiness mutations, no-I/O rejection of another test role,
and manifest mutations for role, audience, lifetime, path, permissions and
mount ownership. Full worker, runner and runner-library race suites passed
in 8.099, 2.571 and 2.281 seconds. The four focused Attack Lab release tests
passed. Terraform validation passed after installing the exact locked,
HashiCorp-signed providers with backend disabled and lockfile read-only.
No Terraform apply or live IAM/Fargate proof occurred. M5-20 remains
component-only pending independent acceptance, final checks and shipping CI.

Independent Superpowers review found no M5-20 acceptance blocker and separately
passed focused worker/runner identity tests under the race detector. The full
Chrome product check passed again, including actual pinned red-team runtime,
versioned evidence, sandbox UI, discovery, security, recovery, administration,
reload and cross-tenant denials. Its sandbox is still an explicit local
provider fixture; actual Kubernetes identity behavior is covered by the
separate HTTP fixtures. Browser exception/console checks and owned-resource
cleanup passed. Final full verification and release checks are running.

The first full verification stopped at an older foundation test that rejected
every wildcard Action, including explicit Deny. Its corrected check exempts
only the exact deny-all statement and retains rejection of wildcard Allow,
missing Effect and mixed deny/allow input. The new regression reproduced the
false rejection before the correction. The release source gate and 50-test
runtime/Node/ledger command passed, with two opt-in interruption tests skipped.

Read-only review of the next task found that M5-21 still needs a constrained
S3 infrastructure exception and a connected network-denial fixture with a
reachable positive control. The current regional S3 prefix-list allowance
is broader than image pulls; test-role IAM denial does not block anonymous
or presigned traffic. M0-19's existing proof has different networking and
cannot be reused unchanged as M5-21 evidence. These remain open; M5-20's
identity tests do not claim proxy-only enforcement or live networking proof.

Corrected full verification passed all 1,083 frontend tests, tenant/race and
API contracts, types, warning-free lint, 34 release checks, production build,
38-file source and 7-client/8-server compiled import checks, and the 728-row
ledger. Independent final review passed all four corrected foundation tests
and all 23 ledger tests and accepted the delta. The staged scan's 55 medium
matches were individually inspected: six CI IDs, 11 synthetic Kubernetes UID
suffixes, 35 fixture AWS account numbers and three fixed in-cluster hostnames.
No high finding or scanner bypass occurred. M5-20 shipping and CI are pending.

After identity commit `782e625e` was pushed, the next deployment-path audit
found two older preflight/evidence validators still expecting no runner role.
Their updated positive fixtures reproduced rejection; the missing-role
preflight fixture also reproduced incorrect acceptance. Both validators now
require the exact test role. The staging evidence validator's stale migration
job name was brought to the shipped schema39 name. Missing/product runner
roles still reject, and the gate tests are now part of root verification.
This correction is included before M5-20 receives production credit.

The preflight correction passed all six Node gate tests and independent
review. Adding the gate command exposed three additional exact-command
assertions in OpenAPI/workflow tests; these now include the new check while
retaining every existing verification command. All 17 focused quality tests
passed, followed by the complete root verification, including 1,083 frontend
tests, the newly wired staging gates, 34 release checks, production build and
the 534/133/61 ledger. No product UI or runtime changed in this correction.

PR 20 shipped identity commits `782e625e` and `4f6497d3` as main `5289e80f`.
Corrected push CI `34376119528`, PR CI `34376124000` and main CI `34377164185`
all passed. The follow-up scan had five inspected medium fixture-account
matches and no high finding. M5-20 is now production-available, with a
regression rejecting silent demotion. Ledger: **535/132/61**, all 728 rows.

## M5-21: bounded sandbox egress

The prior regional S3 allowance shared the product's unrestricted gateway
endpoint. A denied test IAM role cannot stop anonymous or presigned S3
traffic. Runners now use two dedicated private subnets and an isolated route
table with no NAT/Internet route. Their S3 endpoint permits only GetObject
on the regional ECR starport image-layer bucket. The product endpoint is
unchanged. Source: [AWS ECR endpoint guidance](https://docs.aws.amazon.com/AmazonECR/latest/userguide/vpc-endpoints.html)
and [gateway endpoint routing](https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html).

Terraform and the executable Linux fixture share six protocol/port rules.
Tests also bind exact proxy, ECR, S3 and control-plane/DNS destination
references and reject extra runner egress. The original production
SecurityGroupPolicy and strict CNI configuration remain in place. Explicit
subnet overrides must be inside the VPC and disjoint from product and other
runner subnets. Terraform validation, an offline plan, and five Terraform
plan tests passed, including overlap/outside rejection. Nothing was applied.

The test-first contract check failed before Terraform consumed the shared
rules, then passed after wiring. The owned Linux packet fixture passed twice:
proxy and infrastructure allowed, direct destination and wrong proxy port
denied, four kernel-dropped packets, UID 65532, zero probe capabilities, and
independent reachable nonce controls before and after. The contract hash was
`ef0aa90d2e3618cf39d285ae1b695b281cd4a63afd7144550ec3189c1ed3a2a5`.
Independent review caught untracked uncertain creates. Pre-registered names
and exact ownership reconciliation now cover lost network/container create
responses. Actual SIGTERM-after-allocation acceptance passed and confirmed
all owned resources were removed. Its first cleanup assertion used an
invalid Docker listing command; the corrected container/network listing
passed. No false cleanup pass was retained.

A connected runner deployment audit found that Lstat rejected Kubernetes'
atomic ConfigMap CA projection. The production regression reproduced that
failure. The reader now uses os.OpenRoot confinement, supporting relative
projected links while rejecting absolute, escaping and dangling links and
retaining certificate, size and inode checks. Runner/library race tests
passed. Independent review accepted cleanup, exact SG assertions and this
CA correction, rerunning three fixture tests, two release tests and both
runner/library race suites successfully.

This is fixture-level M5-21 evidence, not live AWS SG attachment, endpoint
policy enforcement, Fargate scheduling or ECR image pulls. DNS and required
infrastructure endpoints remain explicit exceptions. A live profile upgrade
requires draining owned runs before replacement and cloud verification
before consumption resumes. See `proofs/attack-lab-egress/README.md` for the
boundary, reproduction and inspected proof-only dependency licenses.

Initial root verification passed 1,082 frontend tests and failed the single
exact workflow-step inventory because the new mandatory network CI step
increased it from ten to eleven. The corrected inventory retains every
existing gate and adds the exact new command. Final verification and
shipping are pending; M5-21 and M5-22 remain uncredited.

Corrected root verification passed all 1,083 frontend tests, tenant/RLS race
checks, API contracts, types, warning-free lint, six staging gate tests,
36 release checks, production build, both import graphs and the 535/132/61
ledger. The production release gate and complete worker race suite passed,
as did the 50 runtime/ledger regressions (two opt-in skips). Linux fixture
go vet passed. Full Chrome combined acceptance passed discovery, typed
inventory, sensor controls, multi-tenant security actions, pinned Red Team
runtime, Attack Lab, recovery, administration, restart/reload and clean
console checks. Its external-provider and isolated sandbox fixtures remain
explicit; no live cloud proof was claimed. Owned browser, process, Docker
and PostgreSQL resources were cleaned up. The staged scan had six inspected
CI-ID matches and no high finding. Shipping CI remains pending.

M5-21 implementation `053fac2e` shipped as PR 21 / main `7500d9bc` after
push CI `34379127396` and PR CI `34379133194` passed, including the actual
Linux packet and SIGTERM fixtures. Main CI `34380166718` also passed. The
original direct-denial criterion has independent acceptance. M5-21 is now
production-available, guarded against silent demotion. Ledger: **536/131/61**.

## M5-22: signed proxy-token production closure

The worker already signs a canonical HMAC capability binding organization,
workspace, environment, run, exact destination, POST-only method, input
digest and the durable attempt's deadline. The production proxy verifies
the signature and then resolves the exact active run through its isolated
PostgreSQL principal. Review found three remaining production defects:
stale expiry after blocking resolution, one pgx connection shared across
concurrent requests/readiness, and missing request/lifetime cancellation.

New regression tests reproduced expired-token and expired-durable-authority
forwarding after resolution, missing resolver/forward deadlines, and late
success accepted after authority expiry. The handler now gives all work a
token deadline, rechecks time after durable resolution, narrows downstream
credential/DNS/HTTP work to the earlier durable expiry, and rejects late
success. Signing-key verification and clearing are synchronized. Expiry
during actual HTTPSForwarder credential retrieval produced zero DNS or
target transport calls. Concurrent token verification and Close passed the
race detector.

The production proxy uses a bounded pgxpool (maximum eight, minimum one),
bounded startup/readiness/query contexts, cancellation tied to service
lifetime, and HTTP request deadlines with a server BaseContext. Service
cancellation precedes draining and dependency closure. Real disposable
PostgreSQL tests passed concurrent queries, saturated-pool deadline,
blocked-query HTTP timeout and shutdown cancellation. Test binary discovery
uses bounded pg_config fallback; CI fails if PostgreSQL is unavailable
instead of silently skipping. No new production dependency was added.

The combined browser proof now calls the actual worker token-construction
path while its real leased run is active. The actual runner sends that token
through a real TLS proxy handler and the isolated PostgreSQL repository to
a controlled TLS canary. Valid scope/run/destination/input succeed. Signed
undeclared-host and foreign-run variants produce zero downstream calls;
an expired worker-issued token produces neither downstream nor durable
resolver calls. The downstream transport and Kubernetes sandbox remain
explicit local fixtures, not production cloud-credential or networking
evidence. The complete Chrome run passed and cleaned its resources. The
final late-success rejection was added after that browser binary was built
and is covered by its reproduced-failure/corrected-pass regression.

All worker, proxy, runner and capability race suites passed. Independent
review accepted the corrected diff and reran full proxy library and process
race suites, including real PostgreSQL tests. Root verification and final
shipping remain pending; M5-22 is not yet credited.

Final root verification passed all 1,083 frontend tests, tenant/RLS and API
contracts, types, warning-free lint, six staging gates, 36 release checks,
production build/import checks and the 728-row ledger. The production
release gate also passed, as did the 50 runtime/ledger regressions (two
opt-in skips). CI now requires the complete proxy process/library and
capability race suites alongside the existing runner and packet checks.
M5-22 awaits shipping and CI; live-cloud boundaries are unchanged.

The staged scan's ten medium findings were individually inspected: four CI
IDs, one synthetic Kubernetes UID suffix, one fixture AWS account number,
two fixed in-cluster hostnames and two documentation-range network values.
No high finding or scanner bypass occurred.
