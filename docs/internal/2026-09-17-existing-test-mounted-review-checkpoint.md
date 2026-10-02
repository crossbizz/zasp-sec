# Mounted existing-test acceptance review

## Current cancellation ruling and runtime review

Final independent V2 review approved bounded mounted spec compliance and quality,
with no remaining Critical/Important findings. Reviewer confirmed the exact
patch hash, engine-error JSON/screenshot, foreign/missing409 and owner positive
controls, and four-case evidence mapping. Minor stale historical heading was
relabeled in the report. Full release, ancillary-write absence, immutable worker
image provenance and live cloud/provider acceptance remain outside this result.

Final run15 completed with the corrected contract, all four outcome cases and
the cancellation controls. The retained cancellation JSON records foreign409,
missing409, queued version1 unchanged and owner cancelled version2, mapped to
the four recorded proof digests. Controller inspected the completed log and
freshly passed28 focused helper tests. The implementer observed overall exit0
and owned cleanup. Final frozen-source review remains pending; this is local
composition acceptance, not deployable-image or live-provider proof.

Run14 completed all four local outcome/evidence/reload/history cases, then failed
the harness's404 expectation for foreign cancellation. The inherited migration18
function selects scope, version and cancellable state together and raises
SQLSTATE40001/HTTP409 when absent. Preserve that non-enumerating contract; add a
nonexistent-ID409 negative control alongside unchanged foreign run-row evidence
and successful valid owner cancellation. Do not introduce a scoped existence
pre-read merely to satisfy the incorrect expectation. Full batch acceptance is
still pending after this test correction.

Independent runtime source review approved local composition with no
Critical/Important defect: registered planner, outbox/SQS, pinned engine,
TLS/HMAC adapter, committed invocation journal, artifacts and reconciler are
actually composed. It did not execute services or prove live production.
The worker-image identity is synthetic, cloud/provider/customer transport are
local fixtures, and linked mode skips the standalone empty-queue/DLQ and secret
sentinel assertions. Those broader claims remain unproved by this batch.

Independent Superpowers source review found three Important acceptance gaps in
`scripts/existing-test-mounted-browser.mjs`. No Critical finding was reported.
This review did not run a browser, service or test and is not acceptance proof.

1. Foreign cancellation uses version 1 against settled runs. An own-scope list
   response proves read access only. Admit another run through the public UI,
   capture its current cancellable version, prove foreign refusal leaves durable
   authority unchanged, then prove owner cancellation succeeds with the valid
   preconditions. Do not insert the run or controls through fixture SQL.
2. Linked history checks only require the run ID in body text, which the ordinary
   list already contains. Verify scoped URL parameters and the selected Red team
   run drawer before and after reload. Exercise the before-run link for the
   remediated case as well as the linked after-run.
3. Pending state and settled outcome/reason are asserted through APIs but not
   sufficiently in rendered evidence. Assert the pending/no-verdict display and
   each expected outcome and safe reason within Recorded test evidence, including
   baseline-unavailable and engine-error cases.

All three were sent to the existing implementer for one grouped correction and
browser verification batch. They are open until actual checks pass and review
confirms the changes. They identify weaknesses in acceptance tests, not proven
production authorization or display defects.

The reviewed helper contains all four action/autonomy combinations. Creation,
simulation, activation, controls, trigger and approval use UI handlers. No direct
insertion of agent definitions, enabled controls, plans, runs, links or settled
proofs was found. Identity/discovery/risk prerequisites and synthetic approver and
foreign sessions remain declared local fixtures. Planner/execution callbacks use
composed processors with controlled transport; none is live provider evidence.

Execution checkpoint: run2 failed during compilation for lack of disk space;
the implementer confirmed tool session36578 is terminal and cleanup completed.
No run3 had started at that checkpoint. A later root check found 1.5 GiB free
without root deletion. The implementer resumed after synchronization and will
check owned handles and headroom before one bounded retry. End-to-end acceptance,
release gates and task production promotion remain unproved.

## Correction and execution checkpoint

The implementer added focused validators for rendered evidence, exact history
selection and valid cancellation refusal with owner success. Root reran
`existing-test-mounted-browser.test.mjs`, `red-team-runtime-proof.test.mjs`, and
`browser-e2e-helpers.test.mjs`: 14 tests passed, zero failed or skipped
(output eb9e9b). These tests validate helper behavior, not a mounted browser.

Run3 started with 6.7 GiB free and got past compilation. Its log then recorded
`agentsec-migrate` failure after installed release12, followed by cleanup steps.
No browser scenario ran. The implementer owns terminal-handle confirmation and
diagnosis of that setup failure; do not mark these review findings accepted from
the helper tests alone.

Independent source re-review now resolves all three Important findings with no
new Critical/Important issue in that delta. The foreign-denial snapshot covers
the run row only, not every audit/receipt table; do not claim zero ancillary
writes. This is source-only approval. Run4 also stopped at release13 setup and
the implementer confirmed terminal cleanup. Neither run establishes browser
acceptance; readiness/locale diagnostics remain underway.

## Locale setup correction

Root repeated the known compiled55 reference test in the same cached PostgreSQL
image: `TestSecurityAgentExistingTestCompiledFingerprintPostgres` passed in4.35s,
with owned PostgreSQL joined cleanly and container exit0 (7e574f). This exercises
the existing C/UTF8 fixture and does not certify new mounted source.

The mounted Docker fixture was then aligned to that reference using exactly
`POSTGRES_INITDB_ARGS=--no-locale --encoding=UTF8`. The implementer observed a
focused argument-test RED before the change. Root reran four selected Node
helper files:28 passed, zero failures (ac894f). Run9 now passes actual migration13,
the48 chain and the unchanged55 fingerprint assertion before durable prerequisite
setup. This confirms the locale setup correction without changing schema pins.
The browser/API/runtime portion was still running at that checkpoint; no case
completion or full end-to-end pass is inferred.

## Production catalog routing correction

Run9 reached the actual browser, created two Red Team definitions and enabled
environment/action controls through UI handlers, then failed because the
existing-test templates were absent. The catalog operations went through the
generic workflow repository instead of the dedicated Security Agent repository.
The new distinct-database production-composition regression reproduced that
failure before the two catalog routes were corrected in `security_agent_surface.go`.

Root reran `TestExistingTestCatalogMountedProductionComposition` and
`TestExistingTestDraftMountedProductionComposition`: package pass,0.682s
(6ca3ed). The catalog test checks both actions, healthy/refused/healthy capability,
503 refusal, exclusion of unrelated Attack Lab support and no mutation attempts.
Independent review approved the bounded fix without Critical/Important findings.
Middleware, exact55 gating and static production classification are unchanged.
Run10 is the next actual browser acceptance attempt, not yet accepted here.

Run10 subsequently reached agent creation, validation, simulation, activation,
manual admission and planner/preparation, then stopped on an invalid synthetic
approver session ID. The fixture used a prefix rejected by the existing
`zasp_product_sessions_session_id_check`; the schema was not changed. The
implementer corrected approver/foreign session IDs to the established `session-`
format and launched run11 (owned handle56883). These partial steps do not prove
approval, engine execution, settlement or the full matrix. Final acceptance
remains open.

Run11 reached the pending approval screen but stopped on a harness wait for an
ID that exists in the button's accessible label, not body text. The redundant
body-text wait was removed; exact accessible-label selection remains. Run12 then
passed separate-principal UI approval and the second planner/dispatch pass.
Its actual engine worker reached a stored fail result before reconciler
composition refused a mismatched fixture region (`us-west-2` versus the owned
KMS key's `us-east-1`). The fixture now uses the actual base region; production
validation is unchanged. Run13 is the next attempt. This does not yet establish
settled evidence, displayed outcomes or the four-case matrix.
