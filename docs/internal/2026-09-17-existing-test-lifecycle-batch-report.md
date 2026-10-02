# Existing-test lifecycle batch, September 17

Status: DONE_WITH_CONCERNS. Implementation verification is complete across the
grouped18 and targeted19/20/21 runs at the same final SQL pin. The host database
constraint violation remains a concern; main owns final independent review
closure. This is not a production release or browser-proof claim.
Original 728-task scope and static production action readiness are unchanged.

Review the inherited-dirty-state delta, not HEAD:
`/private/tmp/zasp-existing-test-lifecycle-review-20260917-v5.patch` (22 files).
SHA256: `f4ef90f60d6cef0ff0fb6ad87bf7de93756671a42f92a2b8286b48c7f1a12d13`.
Read-only `git apply --reverse --check` passed against the final worktree.
The untouched baseline is `/private/tmp/zasp-lifecycle-baseline-vxcaHC`.
The patch includes new source/tests and generated types, but not this report.

## What's in the patch

The public catalog probes compiled55 support per request, exposes exactly the
two test actions and appends two single-action templates. It never uses control
enablement as catalog visibility, and a failed capability probe fails closed.

New controls and admission SQL fragments keep API and worker boundaries
separate. Missing controls stay disabled. Public controls have scoped versions,
receipts, idempotency conflict checks and post-lock wall-clock expiry. Activation
re-resolves the exact binding and enabled controls; enabled replay also checks
the original fresh-auth expiry. Legacy activation/simulation fences remain.

Manual finding, attack_path and session admission share the automatic admission
core. Session maps to runtime_decision. The core locks organization admission
before work rows, checks exact test/trigger/control state and per-definition
concurrency, and writes one scoped trigger receipt/run. Automatic admission has
bounded candidates, subtransaction rollback for stale candidates, and delegates
the remaining limit to the legacy scheduler. Latest runtime evidence is selected
before validating its expected version.

Repository, handler, OpenAPI, decoder and UI contracts expose six sorted action
controls at55. Old 2/3/4-action responses remain supported; five and malformed
shapes are rejected. Enabled readback requires55 and the saved identity/reference/
autonomy contract. Control-off does not gate historical reads.

Changed file groups: securityagent/templates.go and template registry test; apiserver workflow handler,
security-agent handler/repositories and five SQL/unit test files; migrations55
registration plus lifecycle/controls/admission fragments; OpenAPI source/test;
web decoder/test/generated types; SecurityAgentsView and its tests. No published
predecessor migration body changed.

## Evidence so far

All owned SQL runs used immutable Linux arm64 test binaries, the cached pinned
PostgreSQL image, network none, read-only mounts and tmpfs. Main ran them and
reported terminal exit plus joined PostgreSQL processes. A later broad host
test-selection mistake violated the no-host-PostgreSQL constraint, detailed below.

| Run | Result |
| --- | --- |
| public activation RED01, output3152b0 | Expected42883, missing registered controls;4.45s |
| calibration02, b80e27 | SQL installed; intermediate observedpin462e786b...;4.09s |
| activation03, dbf5f7 | Fixture's redundant global UPDATE hit inherited recovery guard; corrected to a prerequisite assertion |
| public activation04,5e54cb | PASS4.99s, both actions and supervised/autonomous activation |
| admission RED05,d1914e | Expected42883, missing registered scheduler;3.39s |
| calibration06,13d911 | SQL installed; intermediate observedpin9b2dec0d...;3.59s |
| grouped07,db016d | PublicActivation5.07s, Admission5.07s, TriggerMatrix12.27s, all PASS |
| safety/release08,e940b2 | Safety9.42s and Release8.30s PASS |
| stale09,1a964f | Exposed stale candidate consuming limit1; not counted as intended older-admission RED |
| stale10,f85c6e | Intended RED: older runtime event admitted after newest and public cancellation;9.48s |
| final calibration11,16bbf7 | SQL installed; observed final pin below;3.60s |
| final grouped12,ee662c | All14 selected top-level tests PASS, including stale matrix13.58s, Safety9.60s, fingerprint3.50s, Release9.11s, Lifecycle15.46s |
| mixed scheduler13,a560a6 | PASS6.50s: foreign-only evidence and disabled-binding atomic refusal, then one test plus one legacy admission under limit2, remaining legacy under limit1 |
| review RED14,00d120 | All3 intended failures: request-receipt wait accepted stale trigger, execution-state wait created1, ineligible head starved later work |
| review calibration15,456808 | SQL installed, intermediate observedpin ecc0b107...;4.53s |
| review16,944fa6 | Receipt-wait case PASS; execution-state atomic refusal passed but positive fixture selected earlier newly eligible definition; mixed concurrency case PASS; five disabled heads correctly exposed remaining starvation RED |
| calibration17,3c460c | SQL installed, final observedpin5982d49a...;3.73s |
| grouped18,c05a53 |16of17 top-level tests PASS; only late-wait fixture setup failed, all19 owned PostgreSQL joins clean |
| targeted19,bfc89b | TriggerMatrix14.78s, request-receipt16.68s, execution-state15.92s and fingerprint3.64s PASS; delegated fixture assumed legacy control version0 and failed before its wait, all5 joins clean |
| targeted20,0a6a2a | Receipt16.25s, execution-state14.57s, fingerprint3.42s PASS; delegated fixture held a definition-row lock that the legacy scheduler does not acquire, all4 joins clean |
| delegated21,7fe3f4 | PASS18.22s plus fingerprint4.03s: observed actual scoped legacy advisory wait after prior test-run writes; after clock advance SQLSTATE40001 existing test runtime trigger changed; atomic rollback and subsequent positive admission passed, both joins clean |

Final compiled55 fingerprint:
`5982d49adccd658e27f84af2098cef3bb90ce743bef6f3eaab411118d78e30da`.
It was copied only after owned calibration observed it. Runtime code never
adopts a live fingerprint as authority.

Grouped SQL binary: `/private/tmp/zasp-lifecycle-final-20260917-18`.
Its selection was:
`^Test(ExistingTestLifecycleBatch(PublicActivation|Admission|TriggerMatrix|Safety|MixedSchedule|LateAuthority|DisabledHead)|SecurityAgentExistingTest(CompiledFingerprint|Release|Lifecycle|LegacyActivationFence|LegacySimulationFence|LegacyLifecycleReplay|CandidateRollback|CandidateRollbackRetainedHistory|VersionedDefinition|VersionedCutover))Postgres$`, timeout300s.

The failed late-wait setups were corrected only in tests, with no SQL/pin change.
Final targeted binary `/private/tmp/zasp-lifecycle-delegation-20260917-21` ran
`^Test(ExistingTestLifecycleBatchLateAuthority|SecurityAgentExistingTestCompiledFingerprint)Postgres$/^delegated_wait$`.
All17 selected top-level cases now have passing evidence across18/19/20/21,
including all three late-authority subcases. This does not relabel the earlier
failed commands as successful commands.

The initial host grouped Go command was too broad:
`GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race -count=1 -skip Postgres ./apiserver ./securityagent ./migrations`.

It timed out after601.456s (ecafd1). Some PostgreSQL fixture functions omit
"Postgres" from their names, so `-skip Postgres` did not exclude them. The timeout
stack was TestRuntimePrecisionDeliveryCachedOutboxMutationRejected in a
*_postgres_test.go file. This started prohibited host disposable PostgreSQL.
No broad host apiserver rerun is authorized or planned. Inventories557970 and
main8c958b found no surviving owned Go/apiserver/new PostgreSQL process; the sole
postgres PID69792 and children69793..69802 were three days old, associated with
`/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/zasp-http-fixture-1357075233/postgres-data`.
They were not touched. Per-fixture cleanup after the timeout is not proved.

The same run found the intended template-registry expectation needed both new
IDs; that exact assertion was updated. Migrations passed5.010s. A replacement
host race check now uses an explicit positive allowlist of inspected non-DB
test functions, `-skip Postgres` as backup, and PATH=/usr/bin:/bin so PostgreSQL
binaries cannot be found through PATH. Explicit allowlist command:

```sh
PATH=/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race -count=1 -skip Postgres -run '^(TestExistingTestLifecycleBatch(Catalog|ControlShape|Routing|ActivationReadback|ScheduleRouting|HTTPTriggers|HTTPControls)|TestWorkflowHandler(PublishesOnlyLocallyCompleteCatalogAndTemplates|HidesAndRejectsSessionIsolationWithoutV24Authority|HidesAndRejectsConnectorRevocationWithoutV23Authority|RejectsUnservedSecurityAction|DecodesSecurityAgentContractAndBuildsDurableDefinition)|TestSecurityAgentPublicHandler(ReadsAndMutatesTenantExecutionControls|RejectsTenantGlobalExecutionMutation|QueuesExactTenantFindingRun)|TestSecurityAgentExistingTestWorker(ContextRouting|ReservationRouting|PreparationRouting))$' ./apiserver
PATH=/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache /opt/homebrew/bin/go test -race -count=1 -skip Postgres ./securityagent ./migrations
```

All18 allowlisted top-level apiserver tests passed2.040s (dca670), securityagent
passed1.693s and migrations5.228s (d93b9e). These do not erase the earlier host
constraint violation or claim all apiserver tests passed.
Main independently repeated that safe allowlist at the final pin: apiserver
2.379s, securityagent1.298s, migrations4.923s, all PASS1b9666.

Web grouped command used Node22 and local Vitest on
`apps/web/api/decoders.security-agent-lifecycle.test.ts`,
`apps/web/api/decoders.security-agent.test.ts`, and
`app/features/securityagents/SecurityAgentsView.test.tsx`:120 PASS, output2c2af6,
4.57s. Earlier focused decoder/UI/Go REDs preceded their implementation.

Main's final consumer checks: typecheck, generated OpenAPI check, lint and43
OpenAPI tests PASS92eda5. The exact-length OpenAPI test failed before the oneOf
change (5f386b). UI build/import guard PASS23a857; loopback root and seven built
assets returned200,31bed7, owned server joined with SIGTERM. This is runnable UI
evidence, not authenticated browser proof.

## What the SQL acceptance does and does not prove

Definitions and tenant controls are created/enabled through registered public
functions. Underlying test/target/credential/risk/deployment prerequisites are
fixture data. No fabricated enabled agent definitions, trigger receipts or
prepared runs bypass admission.

Both actions exercise manual/automatic finding, attack_path and runtime_decision
admission and dedup. A newly admitted run is claimed through the production
repository, loads registered planner context, then accepts a deterministic
candidate through registered planner authority and reaches waiting_approval.
This checks the context/digest/preparation contract. It does not invoke the actual
model/provider, reserve planner spend or prove the mounted worker loop.

Safety08 proves atomic version/scope/trigger/pin/test-enabled/credential/control
refusal with a later positive control; stale trigger replay, stale control and
changed-intent refusal; original activation expiry refusal; activation and
control expiry after held audit-table locks. Final12 adds actual run-history
read after control-off and both-action supervised/autonomous repository readback.

Release08 proves old54 client refusal, exact restored54 on unused rollback,
owner/search_path and API/worker/private-helper ACL separation. Final12 adds
fingerprint-tamper cases for new admission/run/scheduler functions.

An inherited global operator-control issue is separate: recovery scope validation
rejects the wildcard global row. Tests do not disable recovery guards or pretend
tenant API can mutate deployment-global authority. This batch uses a valid
deployment-global fixture prerequisite; current operator toggling is not proved.

The additional mixed scheduler13 fixture covers automatic foreign evidence and
disabled-binding refusal before a positive control, without changing foreign
scope. Publicly enabled test and two legacy definitions share caller limit2:
one test and one legacy run, then the remaining legacy under limit1.

Independent review found three Important issues, all reproduced in14. The fixes
compare the exact stored trigger after the request-receipt write, repeat binding/
trigger checks after the singleton execution-state write, and recheck every
newly admitted test run after all later candidates, legacy delegation and release
readiness. Final18 also adds a held legacy-definition lock test for that delegated
wait, then an actual positive control. Final18 exposed a fixture mistake: public
activation cannot move a supervised definition back to validated. The corrected19
fixture omits the unrelated earlier manual runtime definition only in automatic
late-wait subcases; the base matrix still exercises all12 action/trigger/caller
combinations. The earlier16 positive-control failure was a correctly eligible
prior definition. The delegated fixture now reads the current legacy control
version through the public API, and holds the actual scoped automatic-trigger
advisory key. It checks granted run-write and ungranted advisory locks before
advancing time. A definition-row lock was ineffective because the inherited
scheduler does not lock that row and its receipt/run tables have no definition
foreign key. Product activation guards are unchanged.

Stable binding, control, target, credential and trigger eligibility now filters
before the candidate limit. A private snapshot-only candidate_binding function
takes no row locks and cannot authorize admission; the core repeats its checks
under organization-first locks. That helper is in the ACL tests and automatic55
fingerprint/unused-rollback inventory. Scan attempts remain bounded at4*limit,
max100, for candidates that change after selection. Success and legacy combined
remain bounded by the original1..25 limit. Five disabled earlier candidates plus
a simultaneously healthy sixth definition are the new head-starvation regression,
passing7.01s in18. Independent review cleared the three product findings subject
to these lock-fixture results; main can close that condition with21's evidence.

Final owned Docker fixtures are joined, with pg_ctl exit0/server Wait exit0 and
terminal Docker exit0 on21. Immutable binaries, review patches and baseline are
retained for inspection. The earlier host timeout still lacks per-fixture join
proof, despite no surviving owned process in the inventories. No pre-existing
host PostgreSQL process was stopped or altered.

No commit, push, deployment, dependency download, provider invocation, external
audit or production readiness/ledger change. Authenticated browser proof, actual
mounted worker composition and remaining original A-D/release gates stay open.
