# Mounted batch: local acceptance passed

Final run15 exited0 after all four mounted cases and tenant controls passed,
followed by exact owned cleanup. This is local composition evidence, not a
production release or live-provider canary. No capability or ledger row has
been promoted. The lifecycle55 fingerprint remains
`5982d49adccd658e27f84af2098cef3bb90ce743bef6f3eaab411118d78e30da`.

## Final result and review handoff

Final grouped integration log:
`/private/tmp/zasp-existing-test-mounted.l84D5X/mounted-run15.log`.
Tool session75168 exited0; focused-suite session48365 exited0. No handles
remain. Docker listings for the owned PostgreSQL label and both runtime proof
labels were empty after cleanup. No host PostgreSQL, image download, external
provider, cache deletion, commit, staging, push or production enablement occurred.

Final evidence directory:
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-existing-test-browser-evidence-137JPW`.
Each run below has JSON plus a recorded-evidence viewport PNG there. The
cancellation JSON also maps all four exact run IDs and stored proof digests.

| Case | Security Agent run | Result |
| --- | --- | --- |
| Supervised run_test, fail | pid_2d875858-d243-4ec9-a047-05c773304ce6 | needs_human / test_condition_persists |
| Autonomous rerun_test, comparable fail-to-pass | pid_95499324-675b-4d89-a23f-ca3e6f3dcea6 | remediated / test_condition_changed |
| Autonomous run_test, pass without baseline | pid_26c5ad70-5efd-41bc-a0a0-6fa0a1b18fd1 | needs_human / test_baseline_unavailable |
| Supervised rerun_test, target/engine error | pid_bc12d329-1c1e-422d-b39d-a25965238817 | inconclusive / test_outcome_unknown |

For each case, UI created/validated/simulated/activated the definition and
admitted the run. Simulation did not enqueue a test. Both supervised cases
used another authorized principal's actual approval UI. Real planner,
preparation, dispatch, outbox, SQS duplicate delivery, pinned engine, TLS/HMAC
adapter, credential-version resolver, committed invocation journal, KMS-backed
artifacts and scoped reconciler ran. UI evidence was pending with no verdict,
then displayed the exact stored outcome/reason/digest. Available attempt/artifact
identities and comparison cells matched public stored proof after reload.
Linked history and, for remediation, before-run history retained exact four
scope/entity query parameters and the selected Red team run drawer after reload.

Cancellation control run `pid_3038f347-87e6-4ecd-8a0e-fb01428ef22c` was newly
admitted through UI and still queued. Foreign detail reads returned404 with
an own-scope read200 positive control. Foreign cancellation of that run and of
an absent valid ID both returned409 at the exact valid version, with no run
identity in the refusal and the full durable run row unchanged. Owner UI
cancellation then succeeded at version+1. The controller explicitly retained
this released non-enumeration contract, correcting the reviewer's404 expectation.
No public pre-read or cancellation SQL change was made.

Frozen scoped source patch (13 files, excludes this report and inherited edits):
`/private/tmp/zasp-existing-test-mounted.l84D5X/mounted-review-v2.patch`.
SHA-256: `688bfa410a1820ec301e627598e1c53b70d1ca04baf1ee88a849fdd38834292c`.
Pre-edit snapshots, including inherited untracked files, and all failed logs
remain in that directory. V1 is historical; review V2.

Changed files:

- `scripts/production-combined-e2e.mjs`
- `scripts/existing-test-mounted-browser.mjs` (new)
- `scripts/existing-test-mounted-browser.test.mjs` (new)
- `scripts/red-team-runtime-proof.mjs`
- `scripts/red-team-runtime-proof.test.mjs`
- `scripts/owned-browser-postgres.mjs`
- `scripts/owned-browser-postgres.test.mjs`
- `services/platform/agentsec-worker/production_combined_e2e_test.go`
- `services/platform/agentsec-worker/red_team_runtime_combined_e2e_test.go`
- `services/platform/redteamadapter/mounted_existing_test_test.go` (new)
- `services/platform/agentsec-migrate/mounted_readiness_diagnostic_test.go` (new)
- `services/platform/agentsec-api/existing_test_composition_test.go`
- `services/platform/apiserver/security_agent_surface.go`
- This report.

Final focused GREEN:28 Node tests,8 exact named non-database Go tests across
three packages. Logs: `final-focused-node.log`, `final-focused-go.log` in the
baseline directory. Both browser scripts also passed `node --check`.

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform ./agentsec-api ./apiserver ./agentsec-worker -run '^(TestExistingTest(CatalogMountedProductionComposition|DraftMountedProductionComposition|LifecycleBatchCatalog|RuntimeConfiguration|RuntimeComposition)|TestTracedDatabasePreservesExistingTestDraftAuthority|TestCombinedE2E(ExistingTestPlannerUsesPinnedTestNotTrigger|OpenRouterPlannerUsesProductionHTTPBoundary))$' -count=1
/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node --test scripts/owned-browser-postgres.test.mjs scripts/existing-test-mounted-browser.test.mjs scripts/red-team-runtime-proof.test.mjs scripts/browser-e2e-helpers.test.mjs
```

Self-review: the sole product change routes two security catalog operations to
the existing dedicated handler, preserving all other routing. All source55 SQL,
fingerprints, production endpoint restrictions, credential validation and
recovery guards are unchanged. The helper locale correction matches the known
reference fixture and passed the actual runner. Fixture SQL is identity,
discovery/target/credential/risk prerequisite data; it never admits runs, enables
test controls/agents, creates plans or settles evidence. Later reads inspect
durable state without substituting for the public/UI actions. No known remaining
blocker exists for this local mounted slice; controller final review is pending.

Remaining gates and claim limits: cached pinned engine execution is real, but
the recorded synthetic RunnerImage is not immutable deployable-image evidence.
LocalStack and controlled provider/Secrets transport are not live cloud/provider
authority, pricing or canary evidence. The linked path does not re-prove the
standalone queue/DLQ configuration or sentinel/cancellation-process matrix.
Whole-feature/release review, final push UI gate, global operator control repair,
approved advisory/dependency evidence, deployed queue/storage/credential policy,
real-provider canary and production load remain separate gates. Nothing here
promotes production readiness.

## Checkpoint history: source so far

The isolated `ZASP_COMBINED_E2E_EXISTING_TEST=true` combined-harness mode uses the
existing owned Docker database lifecycle, migrates55, checks its fingerprint,
mounts the API/UI and selects four browser cases. It skips unrelated worker,
gateway and CLI builds. Identity, target discovery/provenance, credential and
risk prerequisites are fixtures. Controls, test definitions, agent definitions,
simulations, activation, runs, plans, approvals and settlements are not seeded.

The worker test path uses the actual planner constructor with controlled TLS
provider transport and reported bounded cost, actual preparation/dispatch,
outbox/SQS, cached pinned Promptfoo, KMS-backed artifacts and reconciler. A
separate adapter test binary uses the existing package-private transport seam,
with actual TLS, HMAC, credential-version resolver and PostgreSQL journal.
The controller approved that test-only boundary. Production address policy and
credential policy are unchanged.

Changed source:

- `scripts/production-combined-e2e.mjs`
- `scripts/existing-test-mounted-browser.mjs` (new)
- `scripts/red-team-runtime-proof.mjs` and its test
- `services/platform/agentsec-worker/production_combined_e2e_test.go`
- `services/platform/agentsec-worker/red_team_runtime_combined_e2e_test.go`
- `services/platform/redteamadapter/mounted_existing_test_test.go` (new)

## Verified, and not verified

Focused planner RED: `go test ./agentsec-worker -run
'^TestCombinedE2EExistingTestPlannerUsesPinnedTestNotTrigger$' -count=1` failed
both actions because the controlled planner selected the trigger ID instead of
the pinned test. GREEN: the combined planner HTTP-boundary and pinned-test tests
passed after correcting that fixture's target selection.

Runtime-argument RED: Node's `linked mounted runtime` test failed because the
container arguments lacked `--pull=never`. GREEN: all10 runtime-proof helper
tests passed. Grouped with browser reload helper:11 passed. `node --check` passed
for both browser scripts. The Go adapter package compiled during the focused
two-package run (no adapter runtime selected); the two planner tests passed.

Web build passed with pinned Node22.23.1 and `node node_modules/.bin/vinext build`.
An earlier attempted CLI path `node_modules/vinext/dist/cli/index.js` did not
exist; that was a command-path error, not a product failure.

All Go commands used `/opt/homebrew/bin/go`, `GOTOOLCHAIN=local`, `GOPROXY=off`,
and `GOCACHE=/private/tmp/zasp-budget-go-cache`. No broad host Go suite ran.

Run1 failed before Docker startup: its explicit PATH omitted `/usr/local/bin`,
so spawning Docker returned ENOENT. It retained only a generated1704-byte key in
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-production-e2e-2tQ3lI`.
No container was created. Run2 included the correct PATH, started the owned
Docker PostgreSQL instance, then failed linking the host worker with
`no space left on device`. Cleanup removed its database and temporary binaries.
Free disk was258MiB. These are setup failures, not mounted behavioral REDs.

Logs and pre-edit snapshots, including files already untracked at dispatch,
are retained in `/private/tmp/zasp-existing-test-mounted.l84D5X`. Run2 tool
session36578 completed; there is no known live run from that attempt. No shared
cache or user-owned artifact was removed.

## Historical requirements before run3 (superseded by run15 above)

The current source has not yet completed an API/browser case. Engine invocation,
stored comparison, four-case matrix, tenant negatives and actual UI evidence
remain unverified. Later edits after the focused Go pass need grouped compilation.

Source review found the foreign cancellation check used version1 on settled
runs. That does not prove a valid mutation denial. Replace it with a newly
publicly admitted queued run, exact current version, foreign404 with unchanged
durable authority, then successful owner cancellation. Keep the positive read
checks too. This correction is pending at this checkpoint.

Full release gates, whole-feature review, global operator control repair, fresh
approved advisory evidence, real provider canary/pricing, deployed queue/storage
credentials and production load remain separate gates. No push, staging,
commits, activation outside owned infrastructure or ledger changes occurred.

Scoped patch/hash and final self-review will be appended after the next bounded
run. Do not review the inherited full dirty-tree diff as this batch.

## Resumed checkpoint

Fresh disk check found6.7GiB available. No prior owned browser PostgreSQL,
runtime container, combined-harness process or compiler was active. Run3 is
running in tool session65161, with output retained as `mounted-run3.log` in the
baseline directory above. No disk cleanup occurred in this agent.

The three source-review gaps now have test-helper RED/GREEN evidence: all3 new
tests failed with missing expected exceptions, then passed after adding the
guards. Grouped Node helper run:14 passed. The mounted flow uses those guards:

- Foreign cancellation uses a newly publicly admitted queued run and its exact
  current version. It compares the full durable run row after foreign404, then
  requires owner UI cancellation to succeed with the next version.
- History checks all4 exact entity/scope query parameters and the selected
  `Red team run` drawer's run ID, before and after reload. Remediation also
  follows the saved before-run link.
- Pending evidence has no outcome/reason/proof/comparison in its evidence
  section. Each settled case checks its outcome and safe reason in that same
  section, including no-baseline and engine-error outcomes.

These corrections still require the real mounted run. Helper tests do not
substitute for browser acceptance.

## Migration diagnostic checkpoint, 17:01 PDT

Runs3 through8 have completed and exact owned Docker/database/temp-file cleanup
ran on each. No active tool handle remains. Disk is now43GiB available; this
agent deleted no shared cache or user files. The earlier run3 handle65161 is
closed. Runs4/5/6/7/8 were89663/39940/62917/33088/55103 respectively.

All these attempts stop before browser startup at released migration13, with
releases1 through12 installed. Run4's verbose PostgreSQL server diagnostics
contained no SQL ERROR. Run5's first metadata query used the removed PG setting
`lc_collate` and failed; the corrected query reads `pg_database.datcollate`.
Runs6 onward prove release12 readiness and both security checks true, with its
live fingerprint exactly104a089c5193e41f07cd21f276492e1953aa5c2e4e3f91425c11080e8b2026d4.

New test-only `agentsec-migrate/mounted_readiness_diagnostic_test.go` observes
the real runner inside its transaction and always rolls back even if asked to
commit. It refuses anything except the explicitly opted-in loopback zasp_e2e
database. Run7 and8 observed release13's post-DDL gate: execution security and
reference security are true, but live fingerprint
ceaa07df7fe125f84112c9316997cefcfaad6ed816d0a82a68a768f126501943 differs from
compiled6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c.
The actual runner returns invalid migration state and the observer confirms
max installed version12 after rollback. This diagnostic passing is not mounted
acceptance. No production error redaction, SQL or fingerprint was changed.

Read-only fingerprint variants in run8 did not resolve it: C-order-only returned
the same fingerprint; excluding PG18 NOT NULL catalog rows returned80a4cee6… .
The helper initializes en_US.utf8, while the known-passing same-image lifecycle
fixture initializes C/UTF8. A narrow fixture initialization comparison is next;
no pin update or readiness bypass is authorized.

Exact run command, from the recovery worktree (N is the attempt number):

```sh
set -o pipefail
PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache ZASP_COMBINED_E2E_EXISTING_TEST=true /Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin/node scripts/production-combined-e2e.mjs 2>&1 | tee /private/tmp/zasp-existing-test-mounted.l84D5X/mounted-runN.log
```

No mounted API/browser case, screenshot or stored evidence has passed yet.

## Fixture parity and mounted catalog correction

The controller approved the narrow owned helper change. A focused argument
regression failed before adding
`POSTGRES_INITDB_ARGS=--no-locale --encoding=UTF8`, then passed. The grouped
Node helper suite now has28 passing tests. Source snapshots for both owned
PostgreSQL helper files were captured before this edit in the same baseline
directory. No lifecycle logic, cleanup policy or production collation changed.

Run9 passed the actual migration chain through55 and its unchanged live pin.
It compiled both Linux worker/adapter binaries and mounted the real UI/API.
The browser created two Red Team definitions and enabled environment/run/rerun
controls through public UI. It then failed because the definition template
catalog contained only Finding Response and Temporary Policy Containment.
All owned resources cleaned up. Its empty evidence directory is
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-existing-test-browser-evidence-DxIYjK`.

Root cause: `security_agent_surface.go` sent both catalog operations to the
generic workflow repository, whose `securityAgentExecution` capability is
false. Security mutations already used the dedicated repository. A full
production-composition GET regression with distinct generic/security databases
failed with that exact missing-template response. The surface now routes only
those two additional operations to the existing dedicated handler. The test
also verifies warm capability refusal503, healthy recovery and no unrelated
Attack Lab advertisement or mutation.

Focused GREEN command (four named tests, no host database test):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -C services/platform ./agentsec-api ./apiserver -run '^(TestExistingTest(CatalogMountedProductionComposition|DraftMountedProductionComposition|LifecycleBatchCatalog)|TestTracedDatabasePreservesExistingTestDraftAuthority)$' -count=1
```

Both packages passed. Run10 is active in session96138 using the same bounded
combined command and `mounted-run10.log`. The new production change is only
`services/platform/apiserver/security_agent_surface.go`; its regression extends
`services/platform/agentsec-api/existing_test_composition_test.go`. Both have
pre-edit snapshots. The mounted outcome matrix still has not passed.

## Further mounted checkpoints

Run10/session96138 ended cleanly after actual UI creation, validation, simulation,
activation and manual admission, then successful real planner/preparation.
The allowed approver identity fixture failed the released session-ID check.
Its ID and the foreign fixture ID now use the required `session-` prefix.
Run11/session56883 passed that boundary and rendered the approver's real pending
approval. It then failed a harness selector: approval IDs are in exact accessible
button labels, not visible row text. The redundant visible-ID wait was removed;
the exact accessible-ID selection remains.

Run12/session25357 passed separate-principal UI approval and actual dispatch.
It passed real outbox/SQS duplicate delivery, pinned engine execution, TLS/HMAC
credential validation and one committed target invocation. The expected fail
result and KMS artifacts existed. It then refused reconciler composition:
the reused fixture's us-west-2 region disagreed with the owned us-east-1 KMS ARN.
The fixture now takes the actual owned SDK region, with an explicit production
configuration-validity assertion. No validator was loosened. All three runs
cleaned up their exact resources. No evidence case was accepted prematurely.

Run13/session34619 is currently active. The scoped source review checkpoint
(excluding this report and predating the last two small fixture corrections) is
`/private/tmp/zasp-existing-test-mounted.l84D5X/mounted-review-v1.patch`, SHA-256
`6659cc4f9bac232e9d2d7bde5e57d359c7418366138dacea85757ec0011994a7`.

Run13 ended with all real runtimes/reconcilers passing and its first three
complete browser cases passing. The fourth harness assertion expected
`test_evaluation_inconclusive`, but a target HTTP500 marks invocation outcome
unknown. The existing reconciler explicitly prioritizes
`inconclusive/test_outcome_unknown` with null before/after proofs. Expectations
now assert that exact conservative outcome and null evidence rather than
pretending a verified comparison exists. No production behavior changed.

Run14/session52024 has ended and cleaned up. All four complete outcome cases,
including engine-error, passed. Evidence is retained under
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-existing-test-browser-evidence-72pxaA`.
Recorded-evidence screenshots now scroll the section into view and use the
viewport, after visual inspection showed full-page capture missed the scrolled
drawer content. The remediated screenshot visibly shows its stored disclaimer,
test identity, outcome, reason, proof digest and before attempt.

Run14 then proved foreign scoped detail reads404 and own-scope list200. A newly
UI-admitted queued run used its exact current version for foreign cancellation;
the foreign response was409, the full run-row snapshot stayed unchanged, and
owner UI cancellation succeeded. The harness expected404 and therefore failed.
Released migration18 cancellation SQL738-741 intentionally combines missing
scope, stale version and non-cancellable state as SQLSTATE40001/HTTP409. The
controller is deciding whether to retain this uniform refusal with an additional
nonexistent-ID negative control, or require a separately reviewed API contract
change. No readiness pin/SQL was changed and no full acceptance is claimed.
