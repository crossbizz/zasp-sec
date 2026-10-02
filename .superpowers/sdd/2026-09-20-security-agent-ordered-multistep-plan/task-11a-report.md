# Task 11A preflight: pricing authority is absent

Status: BLOCKED at the brief's explicit pricing stop condition. Base remains
`48d2570f5900d7dcdeb10e96ea5b721007630c60`. No production change, migration,
readiness pin update, commit, push, paid provider call, or public activation.
Task 11 orchestration remains deferred behind this prerequisite.

## What stopped the packet

The production planner cannot produce an approved cost bound.
`services/platform/agentsec-worker/security_agent_prepared_plan.go:55` returns
only the model and `openrouter_credit` unit. Both maxima and the cost-policy pin
remain absent so the durable budget authority stops dispatch.

`services/platform/agentsec-worker/security_agent_cost_policy.go:9` explicitly
has no production constructor or producer. Its consistency checks bind a request,
model, account profile, unit, policy, expiry and maxima; they do not establish
pricing provenance. The sole positive producer found is
`controlledPreparedPlan` in `security_agent_cost_policy_test.go`, with the
synthetic `controlled-transport-v1` policy. That is test evidence, not an
approved account or price source. A non-test source search found no other
producer.

The existing `docs/internal/2026-09-17-production-pricing-critical-path.md`
records the same unresolved code and external-authority gap: exact model,
account and routing charges, token/framing/schema/reasoning bounds, applicable
fees, provenance/validity, and a run-level pricing-policy pin. It explicitly
rejects arbitrary operator maxima, public price snapshots and a verified flag
as substitutes. Task 11A does not authorize supplying those missing approvals.

## Provider and artifact inspection

The current production provider boundary is pinned to OpenRouter chat
completions. `security_agent_planner.go:236` sends the retained request with
authorization, content type, accept and data-policy headers. It does not bind a
provider idempotency key. `security_agent_prepared_plan.go:64` has an in-memory
one-shot guard, which does not survive process loss. This inspection makes no
claim about an external provider feature absent from the code contract.

The safe private design remains possible without claiming provider idempotency:
commit the exact request intent before sending; once marked started, an
unresolved result cannot resend and must reconcile to a visible conservative
state after exact lease expiry. Persist exact returned bytes and usage before
artifact publication or admission. This design is not implemented in this
blocked packet.

The artifact boundary already supports the needed immutable replay primitive.
`artifactstore/s3driver/driver.go:78` uses conditional `If-None-Match: *`, a single
SDK attempt, checksum and metadata validation. On a lost acknowledgement it
discovers the stored version, fetches that exact version, and accepts only exact
content. The discovery path is at line 213. Stable canonical input/output IDs
and durable exact bytes can use this boundary without changing historical
storage code. Different content cannot replace the object.

The generic planner still rejects the ordered two-action context at
`security_agent_planner.go:374`. Task 11A would need its own closed context and
result path; widening that generic path is not authorized. No lock-order or
historical-restoration workaround was attempted after the pricing stop.

## Checks actually run

From `services/platform`:

```text
go test ./agentsec-worker -run '^(TestSecurityAgentPreparedPlanMissingAuthorityReachesReservation|TestSecurityAgentPreparedCostAuthorityRefusesUnboundValues|TestSecurityAgentPreparedPlanDispatchIsOneShot)$' -count=1 -timeout=2m
PASS, package 0.862s

go test ./artifactstore/s3driver -run '^(TestDriverPutIsCreateOnlyAndReconcilesLostAcknowledgement|TestExportStoreSDKCancellationAfterSavedPutRemainsRecoverable)$' -count=1 -timeout=2m
PASS, package 0.436s
```

These are existing fail-closed and artifact-recovery checks, not Task 11A GREEN
or end-to-end submission proof. The missing-pricing test confirms reservation
receives unknown maxima and no policy, then stops with zero transport calls.
No test/process handle remains live.

Before the prerequisite split, a temporary Task 11 inspection test observed
absent `runtime_ready` (SQLSTATE 42883). Its approval-pause case failed earlier
on an invalid owner-fixture ID and is not authority evidence. I removed that
new, owned test after Task 11 was deferred. The original 1,044-entry worktree
status matched the saved baseline byte-for-byte before adding this report.
Unrelated work is preserved.

## Needed to resume

Provide the approved model/account/route pricing authority and its provenance,
validity, maxima derivation and pinning contract, or authorize a separately
reviewed prerequisite that establishes it. A controlled-provider fixture can
test the dormant implementation only after its authority contract is decided;
it cannot close this production prerequisite. No Task 11A implementation or
grouped completion gate has been claimed.

## Post-Task11P implementation and evidence

Restarted from reviewed `701c39ef22a567ec14901a3b349985da974e9306` on
`codex/cached-runtime-ship-20260917`. The earlier blocked preflight above is
preserved as history. Task11P supplies the private exact-body lookup; live
catalog/credential approval remains an external deployment gate.

Read-only preflight rulings: the generic planner deliberately rejects ordered
context. Its HTTP boundary has no durable provider idempotency contract, so a
committed started intent is never a resend permit. The old claim/reserve/settle
helpers have release60 readiness and run-before-budget locking; they cannot be
reused as release61 start authority. A separate private SQL state machine will
take schema, Organization, budget, run, planning lease, provider reservation,
and artifact intent order and recheck authority after waits. It will consume
pricing_lookup, not recreate prices. Existing immutable artifact Put semantics
provide conditional writes and exact-content recovery after lost acknowledgement.
The reviewed admission function remains the only plan/step/approval producer.
Fixtures only seed queued input, identity and scoped configuration, not planning
leases, provider usage, result authority or plans. They are component evidence.

The inherited 1,044 dirty entries were present before edits. `writing-style.md`
was not found in the worktree or its obvious parent locations; repository style
is used. No public route, default wiring, historical SQL, push or live provider
request is authorized.

TDD cycle 1, before production code: the new claim test must fail because the
private planning authority is absent. Command from `services/platform`:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningClaimPostgres$' -count=1 -timeout=3m`.
Observed RED: SQLSTATE 42883, private `planning(text,text,jsonb)` absent;
package 9.600s. The owned PostgreSQL process joined normally.

Cycle 1 GREEN: the same selector passed in 9.911s after a stale-pin identity
probe measured `b1ee9b29bebc7c68a40d4e8bf4b171ddc4e9d92340478c9d0ba1fa8158f7b75f`
(probe 9.721s). The probe is not a semantic RED. Claim produces one budget,
one journal and no provider reservation or plan; exact replay is stable.

Cycle 2 before implementation: `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningLifecyclePostgres$' -count=1 -timeout=3m`
failed in 10.118s at the expected absent prepare operation, SQLSTATE22023.
The test requires durable exact pricing-bound intent, a non-reusable send
permit, exact raw result, actual usage settlement, immutable artifact receipt,
admission refusal before evidence, and stable reviewed admission replay.

Parent security ruling, before implementing the compatibility fence: historical
`zasp_security_agent_budget_settle_planner` allows the original issuer to settle
after lease loss. If executable on a new private planning reservation, that
would bypass the new current-lease gate. Add a release61-only fence for private
planning jobs, with schema/Organization locks before downstream locks. Save
and restore the exact function body, owner and ACL; do not edit historical SQL.
Rollback cost: one more executable restoration row and registered fingerprint
dependency; retained planning evidence must refuse down. Prove stale settlement
refusal and exact unused release60 restoration with dedicated REDs.

Confirmed fence RED before implementation: focused Lifecycle/LegacySettlement
selector failed in 19.182s. The legacy test invoked the actual public settlement
entry as the expired original worker and observed `known:true`, 100 tokens and
500 nano-credits written to a fault-injected reservation under a real private
claim. This proves the bypass, not provider usage. Lifecycle also caught an
implementation error: PostgreSQL bounds regex repetitions at 255, so artifact
version validation must use explicit length plus a character-class predicate.
Two earlier syntax failures (8.888s and 9.066s) were corrected during GREEN;
the subsequent fingerprint probe took 9.487s and measured
`056f890ae5183f560f88c81462bdc05d07bb67a1234874c168b120d702b55ab1`.

Raw transport cycle before implementation: `go test ./agentsec-worker -run '^TestSecurityAgentMultistepPlanningRawTransport$' -count=1 -timeout=2m`
observed the expected missing `sendSecurityAgentOrdered` compile RED. Tests
exercise the retained production HTTP client/body and refuse changed credential,
cancelled context, consumed preparation, oversized output, and a second send.

Raw transport GREEN: 1.510s. Lifecycle plus stale legacy settlement GREEN:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanning(Lifecycle|LegacySettlement)Postgres$' -count=1 -timeout=3m`,
25.980s. The fence rejects the old issuer and leaves accounting untouched. The
real SQL lifecycle uses the private admin-created controlled policy and reviewed
admission, but its provider bytes and artifact version labels are direct component
fixtures, not proof of the worker/provider/store integration.

Worker integration cycle before production code: the new owned-process test
references absent `orderedPlanningConfig`/`runSecurityAgentOrderedPlanning`.
The focused owned-worker selector observed the expected compile RED. It will
drive the real retained HTTP request, private SQL authority and typed artifact
store with a durable, create-only controlled object service; each child process
must be joined by its parent.

First real worker-process RED: focused parent selector failed in 25.462s.
Test-only boundary instrumentation reproduced it in 21.132s: the private claim
returned 27 fields, while the strict Go decoder incorrectly required 29. The
narrow correction is the actual 27-field envelope (28 only for send_permit).
The fake SQL lifecycle was not substituted for this failed integration proof.

Expiry cycle before implementation: `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningExpiryPostgres$/claimed$' -count=1 -timeout=3m`
failed in 10.537s with expected unknown reconciliation operation (SQLSTATE22023).
The tests cover claimed, prepared, started, completed, settled and artifacted
states. Recovery must never call a provider or admit; it may settle only exact
previously committed provider bytes/usage, then expose conservative manual state.

Worker fixture diagnosis: the count fix advanced to the artifact boundary.
The repeated process failure (21.390s; instrumented reproduction 20.900s)
showed decode succeeded, version and digest matched, but scope did not. The
controlled file service serialized `domain.Scope`'s private fields as `{}`.
Fix only that fixture: retain explicit scoped IDs alongside the object and
require exact scope equality during recovery. Production artifact validation
correctly refused the incomplete fixture; it was not relaxed.

The process test now completes an actual controlled provider call and admission
in 5.28s. Its restart then fails at private claim (parent 30.887s): the SQL
admitted-state branch allowed only explicit admit, but the worker resumes by
claiming its retained journal. Narrow fix: allow same-issuer claim/read on an
already-admitted job under the same saved lease expiry, then reverify artifacts
and call the existing exact admission replay. No new send permit is granted.

That dedicated process restart selector is now GREEN, 37.215s: first process
provider_calls=1; fresh restart provider_calls=0; admission snapshot unchanged.
The six-state expiry selector passed in 68.978s on its pre-replay-fix source;
the final freeze gate will revalidate it on the final pin.

Drift RED before correction: `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningDriftPostgres$/(budget_tokens|reservation_model|input_body)$' -count=1 -timeout=3m`
failed in 36.245s, all three returned send_permit=true. Root cause: the common
guard checked stop/deadline and current context, but not the retained budget
values, reservation identity tuple, or exact input bytes. Add those comparisons
before any send/result/accounting operation. Separate pinned size RED: the claim
selector failed in 10.037s because input_size was absent; store the byte count
as a generated column derived from the retained exact body.

Closed-result RED: `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningResultPostgres$/(negative_subnano|summary_unicode_space|version_decimal|index_decimal)$' -count=1 -timeout=3m`
failed in 18.436s for all four cases. Root causes are precise: rounding a
negative fraction before rejecting its sign, SQL btrim stripping only ASCII
spaces, and jsonb numeric equality treating 1.0/0.0 as integers. Check the raw
cost sign first, mirror Go's boundary-space set, and require literal integer
representations for the closed version/index fields. Keep genuine known usage
even when candidate validation fails.

Focused corrections GREEN: all drift/result/claim cases passed in 157.779s;
concurrent claim/prepare/start and exact legacy restoration passed in 22.030s;
lease/deadline/readiness changes across a real blocked run lock passed in 31.161s.
Selected process restart/lost-ack cases (exact/start/result/input_put/output_put/
provider_lost) passed in 120.264s. These use fresh worker processes and a durable
controlled object service; they do not claim live provider/S3 configuration.

Wire-size RED: the owned process selector `/wire_size` failed in 24.946s because
altering the committed response's input_size to 1 did not stop the worker.
SQL stores the correct generated size, but the Go consumer did not compare it
to retained bytes. Add that independent check before artifact or provider I/O.

Baseline preservation ruling: no file/digest survived from the prior agent's
ephemeral 65,685-character, 1,044-entry NUL status snapshot. The controller also
intentionally updated only `docs/internal/implementation_status_v1.5.md` and
`docs/internal/implementation_production_availability_v1.5.tsv` before dispatch.
Do not claim byte-for-byte comparison to that missing artifact. At freeze,
exclude the explicit Task11A owned manifest from NUL status, require 1,044
residual entries, and record the residual status/out-of-manifest diff hashes.

Settlement drift RED before fix: `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningSettlementDriftPostgres$' -count=1 -timeout=3m`
failed in 14.071s. An owner fault changed settled prompt/total tokens from
50/100 to 49/99 while preserving sums and digests; admission accepted it.
The existing admission verifies reservation scope/model/digests and budgets,
not the provider raw usage. The private planning boundary must additionally
compare every settled accounting field to its retained parsed raw response
before replay or admission. This is a planner evidence check, not a change to
the reviewed admission contract.

The settlement-drift correction is GREEN in 14.567s. Raw HTTP transport unit
tests passed in 1.047s. The complete 12-scenario fresh-process restart matrix
passed in 231.942s: exact, claim, prepare, start, result, settle, artifacts,
admit, input_put, output_put, provider_lost and wire_size. A final parser
hypothesis (`E'\\v'` might strip literal v) was disproved: the added positive
`valid_v_summary` regression passed in 13.271s, with no production change.

### Post-Task11P source freeze and grouped gate

Source/test freeze begins on the scoped manifest below, base commit
`701c39ef22a567ec14901a3b349985da974e9306`, branch
`codex/cached-runtime-ship-20260917`. Final registered fingerprint is
`b55f9ee0406aa72d2bd56bc7041b4ae7f1d05b90258e877c5162b0c6305b60d4`.
Scoped gofmt and `git diff --check` pass. No code/test edit is permitted while
the consolidated grouped gate runs; only this evidence report may advance.

Owned source/test paths and frozen SHA-256 digests:

```text
6b622e25618e610170f267f819e9971880b040df416352cb55e67d6ac9348c41  services/platform/agentsec-worker/security_agent_multistep_planning.go
cb0df53ef66a8e1e2a23e3faf328f649e9e20690470e9541f40f352731e62709  services/platform/agentsec-worker/security_agent_multistep_planning_test.go
480a11324cd66129e4fab68901ba17ecfba185352a9e541b2c3da5cd26bc1a01  services/platform/apiserver/security_agent_multistep_planning_drift_postgres_test.go
693e92c27c5bb853d5cbf975539ce0cea42a5f791a6a8b770de14b7538840157  services/platform/apiserver/security_agent_multistep_planning_expiry_postgres_test.go
2508fd8b37f719d2c5e971194cc83e93be91575a7432648c4a0a28c0538796dd  services/platform/apiserver/security_agent_multistep_planning_process_postgres_test.go
97b61c2ef5055e7d77bc96455e2d5bf2733ac7a03303ce50943ddb61e5f18c01  services/platform/apiserver/security_agent_multistep_planning_result_postgres_test.go
1780e1136253662da71cb38b91813eea2bdee4f2adf57ec5f2a099e09926975d  services/platform/apiserver/security_agent_multistep_planning_concurrency_postgres_test.go
f8112e6c79d2620097e5b24171827a0013077d6300c8c43fa05d62c2fa922780  services/platform/apiserver/security_agent_multistep_planning_wait_postgres_test.go
b2507c67574a44244d0b45e7962d3754809ba1fe6ec36724a302ddc15fdc4023  services/platform/apiserver/security_agent_multistep_planning_settlement_postgres_test.go
afad1d4815981f3ca85f82c388d7602e3f3db4069569274f6893e7a842d7561b  services/platform/apiserver/security_agent_multistep_planning_postgres_test.go
e45d797136fbca37531989a780344219fe3b4976516fa4f6696236eac44823af  services/platform/migrations/production_security_agent_multistep.go
195a0107dfa1a1d7f7f5a74afe785bcdf6fcc5218b8e2754d63f3837dee58576  services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql
4d959efb2d43cf81b66380fa4ecefb03ce94ce334e2953cd7b04595056f173b3  services/platform/migrations/sql/0061_production_security_agent_multistep.planning.sql
```

The report itself is the only additional owned path. The residual NUL status
has exactly 1,044 entries, SHA-256
`8d6e77107b6d1fc415702b0807cae792f5db96a160cfa9200b7c8255e0224cef`.
The out-of-manifest tracked binary diff SHA-256 remains
`424738695ff8c3140640e2da91628580cdeebbcbbc66760b11f30f9d507a9184`.
These checks preserve the current available baseline, not a nonexistent older
snapshot. Published historical SQL remains untouched.

Consolidated grouped commands (all from `services/platform`, `-count=1`):

```text
go test ./apiserver -run '^TestSecurityAgentMultistep' -count=1 -timeout=60m
go test -race ./apiserver ./agentsec-worker ./redteamadapter ./internal/multisteppricing -run 'TestSecurityAgentMultistep|TestSecurityAgentOrdered|TestSecurityAgentWorkerRepository|TestSecurityAgentActionProcessor|TestOrderedJournal|TestPricing|Test.*(Budget|Planner|PreparedPlan|RequestBoundCost|IdentityAdministration|Administration)' -count=1 -timeout=75m
go test ./migrations ./artifactstore/... ./redteamadapter -count=1 -timeout=30m
go test ./apiserver ./agentsec-worker -run '^(TestSecurityAgentExistingTest(Worker.*|Journal.*|Invocation.*|Settlement(Postgres|VersionBoundaryPostgres|RecoveryPostgres|StoppedPostgres)|Cancellation.*|StoppedLeased.*|Failure.*|Binding.*|Preparation.*|Reconcile.*|Final.*|Legacy.*|CompiledFingerprint.*|Release.*)|TestLinkedRedTeam.*|TestRedTeam.*|TestExistingTest.*|TestProductionRedTeam.*|TestProductionSecurityAgentTemporaryPolicy.*|TestProductionPolicyDeployment.*|TestSecurityAgentAction.*|TestTemporaryPolicy.*|TestPolicyDeployment.*|TestComposePolicyDeployment.*|TestLoadSecurityAgentActionPrivateKey.*)$' -count=1 -timeout=45m
go test -c -o /tmp/zasp-task11a-legacy.cWr5Tm/worker.test ./agentsec-worker
go test -c -o /tmp/zasp-task11a-legacy.cWr5Tm/adapter.test ./redteamadapter
ZASP_RECONCILE_CLIENT_BINARY=/tmp/zasp-task11a-legacy.cWr5Tm/worker.test ZASP_LINKED_TLS_TEST_BINARY=/tmp/zasp-task11a-legacy.cWr5Tm/adapter.test go test ./apiserver -run '^TestSecurityAgentExistingTest(StoppedQueued|SettlementProcessRestart)Postgres$' -count=1 -timeout=10m
```

First completed grouped result: artifactstore PASS 0.716s, S3 driver PASS
0.930s, redteam adapter PASS 2.305s. Migrations failed in 21.338s at
`TestSecurityAgentMultistepCandidateMetadata`: `source identity unbound`.
Systematic diagnosis: production checksum includes the new NUL-delimited
planning SQL and registration expands its placeholder. The metadata test's
independent expected-fragment list still ends at pricing SQL. Hypothesis:
the stale test oracle omitted the new registered fragment; production metadata
is correct. Source and tests stay frozen until all running handles terminate.
Parent ruling: then correct the test contract minimally, add omission coverage,
and rerun migrations plus affected readiness/fingerprint selectors. If source
or pin must change, rerun every affected gate instead.

### Evidence boundaries and remaining deployment gates

The production planner/model/client and exact request body are exercised by
the controlled RoundTripper. No paid/live provider request occurs. Its declared
raw response is actual input to the real transport/parser/accounting path,
not an estimate inferred from the pricing ceiling. The durable controlled
artifact driver exercises typed immutable storage across fresh processes;
existing S3 driver tests supply separate conditional-write/recovery evidence.
Neither fixture establishes a live credential, approved catalog or deployed S3.

No provider idempotency guarantee exists in the inspected boundary. Starting
is a one-use committed permit; process loss or uncertain transport after that
point never resends, even when the original request may not have left the host.
This intentionally sacrifices automatic completion to preserve at-most-once
dispatch. Expired unknown outcomes retain their reservation and become visible
manual recovery; known committed usage can settle without admission. Expired
completed results also remain unadmitted rather than reopening the lease.

The private entry has no public/default dispatch or scheduler wiring. Task11
orchestration remains separate. Admitted replay requires the same
unexpired saved issuer lease and reverified artifact versions; it never grants
a fresh send permit. Down refuses retained private planning evidence. Unused
down restores the exact saved legacy settlement function definition/owner/ACL.
The migration schema and Organization fences precede downstream locks. No
published historical SQL is changed.

TDD evidence above distinguishes semantic REDs from metadata-pin probes and
diagnostic instrumentation. Concurrency, lock-wait, restoration and some
adversarial cases are additional GREEN regression coverage, not claimed as
independent failing-before-production cycles. This sequencing limitation is
reported rather than retroactively manufacturing RED evidence.

Fresh legacy test binaries built successfully. Their stopped-queued and
settlement-process-restart gate passed in 76.646s, with parent-owned subprocess
cleanup. Full multistep, race and affected legacy selectors remain running.

Compatibility ruling during read-only freeze audit: the shared legacy
settlement wrapper also requires READ COMMITTED before its private-job absence
check. An older transaction snapshot could otherwise miss a newly committed
private job and bypass the fence. The parent accepts this fail-closed prerequisite;
release60 down still restores the byte-exact definition/owner/ACL. Compatibility
cost: unusual release61 callers explicitly using REPEATABLE READ or SERIALIZABLE
must retry in READ COMMITTED. After the current frozen handles finish, add
test-only coverage for ordinary release61 READ COMMITTED settlement, no-mutation
higher-isolation refusal, and restored release60 higher-isolation behavior.
No production change is needed for this accepted ruling.

Another freeze-audit hypothesis was disproved by tracing the shared validator:
although the local operation whitelist uses SQL text comparison, `closed(q,...)`
rejects every null field and missing key before that comparison. Non-string
operations stringify to values outside the whitelist. The suspected null
fall-through is therefore not a reproduced authority defect. Add direct-worker
null/missing/non-string/unknown-operation refusal coverage after the existing
handles finish, but do not alter production or its fingerprint unless a semantic
RED contradicts this trace.

Affected legacy grouped gate PASS: apiserver 731.949s, worker 13.157s. Its
scope covers the previously listed existing-test/linked redteam, action,
temporary-policy, policy deployment and composition selectors. No source or
test changed during that run. Full multistep and race are still active.

Read-only boundedness finding: the private worker SQL-call closure passes its
original caller context; `PostgresJSONDatabase.QueryJSON` adds no deadline.
Artifact/provider work already receives the saved lease deadline, but a
background caller can wait indefinitely on initial or subsequent SQL locks.
The existing process fixture's 30-second outer timeout masks this. Parent
ruling: after frozen handles finish, demonstrate a deadline-observation RED
with a blocking QueryJSON boundary and a background-derived caller, then add
the smallest Go-only per-call cap (earlier of caller deadline, saved authoritative
lease expiry and a fixed 30 seconds). Preserve cancellation and artifact/provider
deadlines. SQL and its pin need not change; rerun affected worker/process/race
and timeout/lease checks after that correction.

Environment observation while awaiting those handles: `ps` wall elapsed jumped
from approximately 33 minutes to 2h07m without either Go 60/75-minute timer
firing. Both test children were still live (CPU totals 12m17s/7m45s). This is
consistent with host suspension or a clock discontinuity, not proof of a test
timeout. Completion status and package timings will be taken from the actual
test results, not inferred from wall elapsed.

Exact-byte finding during the same read-only audit: converting raw HTTP bytes
to a Go string and then JSON encoding can replace invalid UTF-8. The resulting
stored "raw" output would not be byte-identical; an otherwise valid candidate
with an invalid byte in its summary could normalize into an admissible result.
Parent ruling: after the freeze, add unit and fresh-process REDs with invalid
UTF-8 in that position, then reject invalid UTF-8 at the raw transport boundary.
Require exactly one send, durable started/uncertain state, no result/output
artifact/usage settlement/admission, and restart no-resend. This is a Go-only
validation fix; no SQL pin or storage contract expansion is required.

Replay wording clarification: same-issuer admitted claim/read is read-only.
The reviewed admission replay preserves all plan/step/approval identities, while
the private wrapper repeats an idempotent journal update with identical state
and receipt values. This is semantic replay, not a claim of zero row writes.

The parent explicitly superseded the earlier tentative null-operation source
change ruling after the shared-helper trace: add direct-worker refusal coverage;
do not change SQL or its pin unless a semantic RED reproduces mutation. The
confirmed post-freeze production fixes are only SQL-call deadline bounding and
invalid UTF-8 rejection in Go.

### First-freeze full multistep failure (unchanged source)

The full multistep command exited 1 in 3601.058s. It reported two cleanup
conflicts, then reached the active 60-minute timeout while running the final
TestWait/stop_wait subtest. Cause of the cleanup conflicts is not established;
do not attribute them to suspension without focused reproduction evidence.
Parent ruling: preserve exact output; verify owned child cleanup; rerun only
CleanupConservative/reproduced, CleanupConservative/unknown and TestWait/stop_wait
on unchanged source with fresh owned databases. If these pass, this broad run
remains non-final baseline and the final affected gate must cover every unfinished
family after the confirmed last completed test. If they reproduce, trace first.

Exact full-gate failure output and stack:

```text
--- FAIL: TestSecurityAgentMultistepCleanupConservativePostgres (104.08s)
    --- FAIL: TestSecurityAgentMultistepCleanupConservativePostgres/reproduced (25.48s)
        security_agent_multistep_admission_repository_postgres_test.go:410: registered admission fingerprint: b55f9ee0406aa72d2bd56bc7041b4ae7f1d05b90258e877c5162b0c6305b60d4
        security_agent_multistep_application_postgres_test.go:305: private deployment store repository operation conflict
        postgres_integration_test.go:1342: joined owned PostgreSQL pid=71858 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestSecurityAgentMultistepCleanupConservativePostgresreproduced1853064360/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
    --- FAIL: TestSecurityAgentMultistepCleanupConservativePostgres/unknown (16.31s)
        security_agent_multistep_admission_repository_postgres_test.go:410: registered admission fingerprint: b55f9ee0406aa72d2bd56bc7041b4ae7f1d05b90258e877c5162b0c6305b60d4
        security_agent_multistep_application_postgres_test.go:305: private deployment claim repository operation conflict
        postgres_integration_test.go:1342: joined owned PostgreSQL pid=72032 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestSecurityAgentMultistepCleanupConservativePostgresunknown3121036923/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
panic: test timed out after 1h0m0s
	running tests:
		TestSecurityAgentMultistepTestWaitPostgres (55s)
		TestSecurityAgentMultistepTestWaitPostgres/stop_wait (15s)

goroutine 3759 [running]:
testing.(*M).startAlarm.func1()
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:2682 +0x2b0
created by time.goFunc
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/time/sleep.go:215 +0x38

goroutine 1 [chan receive]:
testing.(*T).Run(0x140004c2540, {0x105b0da00?, 0x38?}, 0x106c7f0e0)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:2005 +0x378
testing.runTests.func1(0x140004c2540)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:2477 +0x38
testing.tRunner(0x140004c2540, 0x1400070fc68)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1934 +0xc8
testing.runTests(0x1400000e0f0, {0x107a9f8c0, 0x588, 0x588}, {0x1400051a040?, 0x7?, 0x107ab0420?})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:2475 +0x3b8
testing.(*M).Run(0x14000524140)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:2337 +0x530
main.main()
	_testmain.go:2875 +0x80

goroutine 3680 [IO wait]:
internal/poll.runtime_pollWait(0x10ec27000, 0x72)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/runtime/netpoll.go:351 +0xa0
internal/poll.(*pollDesc).wait(0x140004b3620?, 0x1400067d5c7?, 0x1)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/internal/poll/fd_poll_runtime.go:84 +0x28
internal/poll.(*pollDesc).waitRead(...)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/internal/poll/fd_poll_runtime.go:89
internal/poll.(*FD).Read(0x140004b3620, {0x1400067d5c7, 0x239, 0x239})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/internal/poll/fd_unix.go:165 +0x1e0
os.(*File).read(...)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/file_posix.go:29
os.(*File).Read(0x1400008a3d8, {0x1400067d5c7?, 0x140006b8558?, 0x1044d241c?})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/file.go:144 +0x68
bytes.(*Buffer).ReadFrom(0x140004dd0b0, {0x106c9eb08, 0x1400025e058})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/bytes/buffer.go:217 +0x90
io.copyBuffer({0x106c9ee20, 0x140004dd0b0}, {0x106c9eb08, 0x1400025e058}, {0x0, 0x0, 0x0})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/io/io.go:415 +0x14c
io.Copy(...)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/io/io.go:388
os.genericWriteTo(0x140006b8718?, {0x106c9ee20, 0x140004dd0b0})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/file.go:295 +0x58
os.(*File).WriteTo(0x107ccc108?, {0x106c9ee20?, 0x140004dd0b0?})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/file.go:273 +0x5c
io.copyBuffer({0x106c9ee20, 0x140004dd0b0}, {0x106c9ec00, 0x1400008a3d8}, {0x0, 0x0, 0x0})
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/io/io.go:411 +0x98
io.Copy(...)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/io/io.go:388
os/exec.(*Cmd).writerDescriptor.func1()
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/exec/exec.go:596 +0x40
os/exec.(*Cmd).Start.func2(0x14000670000?)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/exec/exec.go:749 +0x30
created by os/exec.(*Cmd).Start in goroutine 3678
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/os/exec/exec.go:748 +0x6a4

goroutine 3738 [chan receive]:
testing.(*T).Run(0x14000720fc0, {0x105a7a629?, 0x162f13d82?}, 0x1400041ecc0)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:2005 +0x378
github.com/zasp-ai/zasp-sec/services/platform/apiserver.TestSecurityAgentMultistepTestWaitPostgres(0x14000720fc0)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_wait_postgres_test.go:17 +0xb8
testing.tRunner(0x14000720fc0, 0x106c7f0e0)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1934 +0xc8
created by testing.(*T).Run in goroutine 1
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1997 +0x364

goroutine 3678 [runnable]:
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionRedTeamExecution()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/migrations.go:562 +0x84
github.com/zasp-ai/zasp-sec/services/platform/migrations.productionAuditExportsPredecessors()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_audit_exports.go:144 +0xa94
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionAuditExports()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_audit_exports.go:149 +0x38
github.com/zasp-ai/zasp-sec/services/platform/migrations.securityAgentBudgetCandidateTemplate()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_budget_candidate.go:36 +0x94
github.com/zasp-ai/zasp-sec/services/platform/migrations.SecurityAgentBudgetCandidateChecksum()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_budget_candidate.go:41 +0x20
github.com/zasp-ai/zasp-sec/services/platform/migrations.securityAgentRunContextTemplate()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_run_context_candidate.go:25 +0x50
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionSecurityAgentRunContext()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_run_context_candidate.go:32 +0x104
github.com/zasp-ai/zasp-sec/services/platform/migrations.SecurityAgentExistingTestEnqueueCandidateSQL()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_existing_tests.go:27 +0x24
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionSecurityAgentExistingTests()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_existing_tests_release.go:63 +0x38
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionCompliance()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/compliance_release.go:30 +0xd0
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionSecurityAgentAttackLab()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_attack_lab_release.go:48 +0x38
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionSecurityAgentExports()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/security_agent_exports_release.go:50 +0x38
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionSecurityAgentWebhooks()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_security_agent_webhooks.go:22 +0x38
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionDiscoveryScheduleReplay()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_discovery_schedule_replay.go:22 +0x38
github.com/zasp-ai/zasp-sec/services/platform/migrations.ProductionSecurityAgentMultistep()
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_security_agent_multistep.go:73 +0x38
github.com/zasp-ai/zasp-sec/services/platform/apiserver.(*securityAgentMultistepAdmissionRepository).application(0x14000ba5f90, {0x106cb6458, 0x14000256230}, {0x140000d4900, 0x808, 0x900}, {0xc8?})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_application_repository.go:68 +0x8dc
github.com/zasp-ai/zasp-sec/services/platform/apiserver.orderedApplicationCall({0x106cb6458, 0x14000256230}, 0x14000356140, 0x140006ff170, {0x28?})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_application_postgres_test.go:379 +0x114
github.com/zasp-ai/zasp-sec/services/platform/apiserver.seedOrderedTestPredecessor(0x14000670000, {0x106cb6458, 0x14000256230}, 0x14000526280, 0x140000003c0, 0x14000000280, 0x14000356140, {0x105af9fd4, 0x28}, {0x105af9ffc, ...}, ...)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_claim_postgres_test.go:127 +0x8d4
github.com/zasp-ai/zasp-sec/services/platform/apiserver.TestSecurityAgentMultistepTestWaitPostgres.func1.1({0x106cb6458, 0x14000256230}, 0x14000526280, 0x140000003c0, 0x14000000280, {0x105af9fd4, 0x28}, {0x105af9ffc, 0x28}, {0x105afa024, ...}, ...)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_wait_postgres_test.go:22 +0x160
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runOrderedProgressionFixture.func1({0x106cb6458, 0x14000256230}, 0x14000526280, 0x14000000280, {0x105af9fd4, 0x28}, {0x105af9ffc, 0x28}, {0x105afa024, 0x28}, ...)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_progression_authority_postgres_test.go:207 +0x504
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runVersionedExistingTestFixture.func1({0x106cb6458, 0x14000256230}, 0x14000526280, {0x140004671c0, 0x3c})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_existing_test_versioned_postgres_test.go:62 +0x2dc
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runSecurityAgentBudgetFixture.func1({0x106cb6458, 0x14000256230}, 0x14000526280, {0x140004671c0, 0x3c})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_budget_postgres_test.go:51 +0x334
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runSecurityAgentAttackPathFixture(0x14000670000, 0x140008ebe50, {0x0, 0x0, 0x0?})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_attack_path_postgres_test.go:160 +0x296c
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runSecurityAgentBudgetFixture(0x14000670000, 0x140004baea0, {0x0, 0x0, 0x0})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_budget_postgres_test.go:20 +0x60
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runVersionedExistingTestFixture(0x14000670000, 0x140004baef0, {0x0, 0x0, 0x0})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_existing_test_versioned_postgres_test.go:30 +0x60
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runOrderedProgressionFixture(0x14000670000, 0x140004baf30)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_progression_authority_postgres_test.go:190 +0x54
github.com/zasp-ai/zasp-sec/services/platform/apiserver.TestSecurityAgentMultistepTestWaitPostgres.func1(0x14000670000?)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_wait_postgres_test.go:18 +0x3c
testing.tRunner(0x14000670000, 0x1400041ecc0)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1934 +0xc8
created by testing.(*T).Run in goroutine 3738
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1997 +0x364
FAIL	github.com/zasp-ai/zasp-sec/services/platform/apiserver	3601.058s
FAIL
```

Unchanged-source diagnostic command:
`go test ./apiserver -run '^(TestSecurityAgentMultistepCleanupConservativePostgres|TestSecurityAgentMultistepTestWaitPostgres)$/^(reproduced|unknown|stop_wait)$' -count=1 -v -timeout=6m`
passed in 54.922s. Cleanup/reproduced passed in 20.57s, cleanup/unknown in
20.56s including its terminal-effect/child/link refusal cases, and TestWait/
stop_wait in 12.85s. Their fresh owned PostgreSQL PIDs 96527, 96638 and 96798
all logged pg_ctl exit=0 and normal server joins. After the broad timeout,
process inventory showed no leftover full-suite child or orphan PostgreSQL;
only the unrelated still-running race fixture remained. No manual process
termination or source change was needed. The earlier conflicts remain
unreproduced; a specific host-suspension cause is not established.

`go test ./apiserver -list '^TestSecurityAgentMultistep'` confirms TestWaitPostgres
is the final selected family. The timeout interrupted stop_wait after the
concurrent_claim and cancel_wins subtests; schema_wait,
heartbeat_expiry_write_wait and child_nowait had not run. The grouped completion
selector now runs the complete CleanupConservative and TestWait families:
`go test ./apiserver -run '^TestSecurityAgentMultistep(CleanupConservative|TestWait)Postgres$' -count=1 -v -timeout=8m`.
The source and registered pin are still frozen and unchanged.

Grouped completion selector PASS in 160.971s: all CleanupConservative cases
80.77s and all TestWait cases 79.28s. The wait subcases passed in 13.02s
(concurrent_claim), 12.89s (cancel_wins), 12.62s (stop_wait), 12.54s
(schema_wait), 15.27s (heartbeat_expiry_write_wait), and 12.94s (child_nowait).
Every fresh owned PostgreSQL server logged a normal join. This covers the
entire interrupted final family and repeats both previously failed cleanup
cases without a source change. The broad 60-minute command is still recorded
as FAILED baseline, not retrospectively relabeled PASS. Only the broad race
handle remains active.

### Broad race timeout investigation on unchanged freeze

The final original race handle subsequently exited 1: apiserver 4501.791s
(75-minute timeout), worker 9.383s PASS, redteamadapter 3.999s PASS, and
internal/multisteppricing 10.671s PASS. No race-detector finding was printed.
The exact reported assertion failures were:

```text
--- FAIL: TestSecurityAgentMultistepAdmissionRoutePostgres (45.08s)
    security_agent_multistep_admission_repository_postgres_test.go:410: registered admission fingerprint: b55f9ee0406aa72d2bd56bc7041b4ae7f1d05b90258e877c5162b0c6305b60d4
    security_agent_multistep_admission_repository_postgres_test.go:410: registered admission fingerprint: b55f9ee0406aa72d2bd56bc7041b4ae7f1d05b90258e877c5162b0c6305b60d4
    security_agent_multistep_admission_repository_postgres_test.go:395: admission migration SQL: ERROR: multistep durable work or evidence retained (SQLSTATE 55000)
    security_agent_multistep_admission_repository_postgres_test.go:397: SQL detail: 0 0  PL/pgSQL function zasp_sa_multistep_assert_unused() line 10 at RAISE
        SQL statement "SELECT public.zasp_sa_multistep_assert_unused()"
        PL/pgSQL function inline_code_block line 4 at PERFORM
    --- FAIL: TestSecurityAgentMultistepAdmissionRoutePostgres/approval_replay (0.83s)
        security_agent_multistep_admission_repository_postgres_test.go:328: exact replay receipt changed ERROR: ordered admission expired after wait (SQLSTATE 40001)
    postgres_integration_test.go:1342: joined owned PostgreSQL pid=71798 data=/var/folders/0v/qngy01614391_pdtwjmwbcvm0000gn/T/TestSecurityAgentMultistepAdmissionRoutePostgres3693236661/001/data: pg_ctl exit=0 server Wait exit=0 normal-exit
panic: test timed out after 1h15m0s
	running tests:
		TestSecurityAgentMultistepTestSettlementWaitPostgres (6s)
```

Systematic-debugging trace: approval_replay failed on its initial exact replay,
before its deliberately rejected-approval mutation. Admission checks the
saved expiry after lock acquisition, so elapsed wall time can legitimately
refuse the replay; the failed case then retains evidence and its attempted
fixture down refuses. The timeout stack instead showed fixture setup, not a
planning-worker or provider operation: `requireMigrationReadiness` via
`UpProductionCompliance` / `runOrderedProgressionFixture`, waiting in
`pgx.QueryRow`. Hypothesis: these are expiry/whole-suite-budget effects rather
than a reproducible Task11A state transition bug; unchanged independent
reruns are required to test that hypothesis. Host suspension is not asserted
as the cause. Process inventory after both original broad exits showed no
remaining PostgreSQL server, go test parent60552 or apiserver child60753;
no manual termination was necessary.

`go test -race ./apiserver -run '^TestSecurityAgentMultistepAdmissionRoutePostgres$/^approval_replay$' -count=1 -v -timeout=4m`
passed in 14.398s (case0.75s), with fresh owned PostgreSQL pid99970 normally
joined. The original assertion remains unreproduced and the broad run remains
FAILED baseline. A grouped race completion selector is now running every
test at/after TestSecurityAgentMultistepTestSettlementWaitPostgres in the
captured 206-name ordered selection, including all test-expiry/wait families,
planner tenant isolation, context-budget retention, and worker repositories.
Its first settlement-wait family passed22.01s, with fresh PostgreSQL pid99983
normally joined. Source/test files remain unchanged until that handle joins.

Exact application portion of the race timeout's blocked goroutine4954 stack
(the surrounding frames are pgx socket IO and the test harness alarm):

```text
github.com/zasp-ai/zasp-sec/services/platform/apiserver.(*orderedAdmissionMigrationTransaction).QueryRow(0xc0004a0dc8, {0x104021c70, 0xc0001ec1c0}, {0x102b52322, 0x2e}, {0xc0000c0e80, 0x2, 0x2})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_admission_repository_postgres_test.go:413 +0x210
github.com/zasp-ai/zasp-sec/services/platform/migrations.scanRow({0x104021c70, 0xc0001ec1c0}, {0x1310549c8, 0xc0004a0dc8}, {0x102b52322, 0x2e}, {0xc0000c0e80, 0x2, 0x2}, {0xc0001a6450, ...})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/migrations.go:3423 +0x80
github.com/zasp-ai/zasp-sec/services/platform/migrations.requireMigrationReadiness({0x104021c70, 0xc0001ec1c0}, {0x1310549c8, 0xc0004a0dc8}, {0x102b52322, 0x2e}, {0xc000b17e00, 0x40}, {0x102b893a8, 0x40})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/migrations.go:1706 +0x198
github.com/zasp-ai/zasp-sec/services/platform/migrations.(*Runner).UpProductionCompliance.func1({0x104021c70, 0xc0001ec1c0}, {0x1040218b8, 0xc0004a0dc8})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_compliance.go:72 +0x65c
github.com/zasp-ai/zasp-sec/services/platform/migrations.(*Runner).withTransaction(0xc000894880, {0x104021c70, 0xc0001ec1c0}, 0x103feb1a0)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/migrations.go:3210 +0x274
github.com/zasp-ai/zasp-sec/services/platform/migrations.(*Runner).UpProductionCompliance(0xc000894880, {0x104021c70, 0xc0001ec1c0})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/migrations/production_compliance.go:49 +0xc0
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runOrderedProgressionFixture.func1({0x104021c70, 0xc0001ec1c0}, 0xc0001a4140, 0xc0001a48c0, {0x102b2bbab, 0x28}, {0x102b2bbd3, 0x28}, {0x102b2bbfb, 0x28}, ...)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_progression_authority_postgres_test.go:193 +0x310
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runVersionedExistingTestFixture.func1({0x104021c70, 0xc0001ec1c0}, 0xc0001a4140, {0xc0005d51c0, 0x3c})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_existing_test_versioned_postgres_test.go:62 +0x510
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runSecurityAgentBudgetFixture.func1({0x104021c70, 0xc0001ec1c0}, 0xc0001a4140, {0xc0005d51c0, 0x3c})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_budget_postgres_test.go:51 +0x690
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runSecurityAgentAttackPathFixture(0xc000710a80, 0xc000895d50, {0x0, 0x0, 0x0?})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_attack_path_postgres_test.go:160 +0x4a3c
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runSecurityAgentBudgetFixture(0xc000710a80, 0xc000a00da0, {0x0, 0x0, 0x0})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_budget_postgres_test.go:20 +0x94
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runVersionedExistingTestFixture(0xc000710a80, 0xc000a00df0, {0x0, 0x0, 0x0})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_existing_test_versioned_postgres_test.go:30 +0x94
github.com/zasp-ai/zasp-sec/services/platform/apiserver.runOrderedProgressionFixture(0xc000710a80, 0xc000a00e30)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_progression_authority_postgres_test.go:190 +0x88
github.com/zasp-ai/zasp-sec/services/platform/apiserver.exerciseOrderedTestDispatchWithCleanup(...)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_dispatch_postgres_test.go:102
github.com/zasp-ai/zasp-sec/services/platform/apiserver.exerciseOrderedTestDispatch(0xc000710a80, 0x1, {0xc000a00ea8, 0x1, 0x1})
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_dispatch_postgres_test.go:98 +0xb0
github.com/zasp-ai/zasp-sec/services/platform/apiserver.TestSecurityAgentMultistepTestSettlementWaitPostgres(0xc000710a80)
	/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/apiserver/security_agent_multistep_test_dispatch_postgres_test.go:55 +0x58
testing.tRunner(0xc000710a80, 0x103fe8f50)
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1934 +0x168
created by testing.(*T).Run in goroutine 1
	/opt/homebrew/Cellar/go/1.25.6/libexec/src/testing/testing.go:1997 +0x6e4
```

The unchanged grouped race completion command was:
`go test -race ./apiserver -run '^(TestSecurityAgentMultistepTestSettlementWaitPostgres|TestSecurityAgentMultistepTestCancellationPostgres|TestSecurityAgentMultistepTestExpiredUnknownPostgres|TestSecurityAgentMultistepTestExpiredCompletedPostgres|TestSecurityAgentMultistepTestExpiryRacePostgres|TestSecurityAgentMultistepTestExpiryStopPostgres|TestSecurityAgentMultistepTestExpiryCancelPostgres|TestSecurityAgentMultistepTestExpirySettlementPostgres|TestSecurityAgentMultistepTestExpiryCompletedRacePostgres|TestSecurityAgentMultistepTestExpiryCompletedStopPostgres|TestSecurityAgentMultistepTestExpiryCompletedCancelPostgres|TestSecurityAgentMultistepTestExpiryNoJournalPostgres|TestSecurityAgentMultistepTestExpiryResponse|TestSecurityAgentMultistepTestRepositoryBoundary|TestSecurityAgentMultistepTestArtifactJSON|TestSecurityAgentMultistepTestWaitPostgres|TestProductionSecurityAgentPlannerTenantIsolationThroughWorker|TestSecurityAgentRunContextBudgetRetentionPostgres|TestSecurityAgentWorkerRepositoryLoadsAcceptsAndFailsExactPlannerAuthority|TestSecurityAgentWorkerRepositoryRejectsDriftedPlannerContextBeforeUse|TestSecurityAgentWorkerRepositoryPrefersExactV33AttackPathAuthority|TestSecurityAgentWorkerRepositoryUsesExactV28PolicyDeploymentReadiness|TestSecurityAgentWorkerRepositoryRejectsMalformedApprovalExpiryResult|TestSecurityAgentWorkerRepositoryClaimsPlansHeartbeatsAndExecutesExactTenantWork|TestSecurityAgentWorkerRepositoryUsesExactV24SessionIsolationAuthority|TestSecurityAgentWorkerRepositoryAcceptsExactAutonomousPreparationWithoutApproval)$' -count=1 -v -timeout=15m`.
PASS360.214s, including TestWait95.73s, planner tenant isolation14.37s and
context-budget retention5.14s. Every fresh PostgreSQL child normally joined.
All original and diagnostic handles have terminated; source freeze is now
released for the controller-approved Go-only corrections and test-contract
coverage. No production SQL or registered pin change is planned.

### Dedicated post-freeze REDs before production correction

Root cause, SQL deadline: the private worker passes its caller context directly
to QueryJSON; PostgresJSONDatabase supplies no additional deadline. The pricing
lookup also uses that database. A background caller can block indefinitely.
The smallest fix will wrap only this private invocation's database, deriving
each query deadline from min(caller deadline, saved lease deadline, now+30s).
Artifact/provider contexts keep their existing independent contracts.

Command:
`go test ./agentsec-worker -run '^TestSecurityAgentMultistepPlanning(SQLDeadline|RawTransport)$' -count=1 -timeout=1m`.
Expected RED: no finite SQL deadline and invalid UTF-8 accepted. Observed
FAIL1.271s, exactly:
```text
security_agent_multistep_planning_test.go:60: unsafe provider dispatch result invalid_utf8 <nil>
security_agent_multistep_planning_test.go:106: private planning SQL has no finite 30-second bound
security_agent_multistep_planning_test.go:123: SQL child context retained after return
security_agent_multistep_planning_test.go:106: private planning SQL has no finite 30-second bound
```
The blocking QueryJSON fixture is released/cancelled and the worker joined in
both background and cancellation cases; no retry or leaked blocking goroutine
is used.

Root cause, invalid UTF-8: raw transport bytes pass through string conversion
and JSON marshaling before SQL storage; JSON encoding normalizes invalid bytes
to replacement characters. An invalid byte inside an otherwise valid closed
candidate summary therefore becomes admissible. Dedicated actual-worker
process RED:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningWorkerProcessPostgres$/^invalid_utf8$' -count=1 -timeout=2m`.
Expected refusal before raw-result persistence; observed FAIL27.855s:
```text
security_agent_multistep_planning_process_postgres_test.go:75: owned planning worker: exit status 1
=== RUN   TestSecurityAgentMultistepPlanningOwnedPostgres
    security_agent_multistep_planning_test.go:199: fault did not stop worker
--- FAIL: TestSecurityAgentMultistepPlanningOwnedPostgres (5.90s)
```
Owned PostgreSQL pid2232 normally joined. The planned one-condition transport
guard will reject invalid UTF-8 before conversion/persistence, retaining the
committed started/uncertain journal and preserving restart no-resend.

Direct-worker malformed-operation coverage has been added without changing
SQL: the shared closed-object helper already rejects missing/null fields,
and non-string/unknown operations fail the whitelist. This is a regression
test, not a reproduced production defect, per the controller's superseding
ruling. The owned manifest also adds the formerly clean tracked
`services/platform/migrations/production_security_agent_multistep_test.go`
for the stale metadata expectation correction and every-fragment hash binding.

Focused GREEN after the two Go changes:
`go test ./agentsec-worker -run '^TestSecurityAgentMultistepPlanning(SQLDeadline|RawTransport)$' -count=1 -timeout=1m`
PASS1.286s. Additional lease/caller/expired/cap deadline-clamp regressions and
process QueryJSON deadline observation cover the earlier-authority bounds and
both planning and pricing queries. These supplementary cases were added after
the dedicated semantic RED, not claimed as independent pre-fix failures.

Metadata test-contract RED:
`go test ./migrations -run '^TestSecurityAgentMultistep(CandidateMetadata|EveryFragmentBound)$' -count=1 -timeout=1m`
FAIL1.146s solely at CandidateMetadata line44, `source identity unbound`.
The every-fragment mutation test passed on the same unchanged production
checksum implementation. Appending planningSQL to the stale expected
fragment concatenation was the entire correction; no production pin changed.
Grouped focused GREEN:
`go test ./agentsec-worker ./migrations -run '^TestSecurityAgentMultistep(Planning(SQLDeadline.*|RawTransport)|CandidateMetadata|EveryFragmentBound)$' -count=1 -timeout=2m`
worker PASS1.245s, migrations PASS3.471s.

Legacy isolation regression setup initially failed before settlement at
`LoadSecurityAgentPlannerContext`: `repository record not found`
(10.359s). Trace: the release60 repository routes through newer existing-test
planner context, whereas this legacy attack-path fixture lacks that versioned
definition/context contract. Hypothesis: producing the genuine legacy context
and reservation at its original release53, then carrying it through the actual
54..60 upgrade chain, will exercise settlement compatibility without fabricating
authority. The test setup was changed accordingly; no production change.
The probe rolls back both successful and refused settlement transactions and
compares full run/budget/reservation/audit snapshots. It checks normal61 READ
COMMITTED, refusal at61 REPEATABLE READ/SERIALIZABLE, exact60 restored
definition/owner/ACL, and restored60 higher-isolation successful behavior.

The original-release fixture then reached the real reservation boundary but
returned `budget_stop: needs_human / budget_usage_unknown` (FAIL6.038s):
its historical definition has no configured known budget. The existing
legacy settlement test explicitly configures the run budget before loading
the context. This compatibility fixture now likewise supplies controlled
100-token/1000-nanocredit limits before the real context/reserve calls; this
is configuration, not an owner-created reservation/result/usage. No production
behavior was changed to accommodate the test.

The next compatibility probe returned the correct budget_permit but the test
helper defaulted to reservation_id=new-reservation instead of this test's
legacy-compat-reservation (FAIL6.125s). Supplying the helper's existing optional
reservation ID corrected only that assertion. Final focused compatibility
command `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningLegacyRestorationPostgres$' -count=1 -timeout=2m`
PASS10.932s, including all isolation probes and exact body/owner/ACL restore.

Development process/refusal group:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanning(WorkerProcess|OperationRefusal)Postgres$/^(invalid_utf8|.*)$' -count=1 -timeout=6m`
PASS276.365s. The .* alternative selected the complete 13-scenario process
matrix, not just invalid_utf8, plus all seven malformed-operation refusals.
The invalid UTF-8 case proves one send, started/uncertain state, NULL raw/result/
output/usage fields, no output object or admission, fresh-process no-resend,
then expired conservative manual recovery. Controlled component evidence only.

### Final corrected source freeze

Production delta from the original broad-gate freeze is only the private Go
database deadline wrapper and invalid-UTF-8 guard. SQL source and checksum
are unchanged from the original freeze; the registered fingerprint remains
b55f9ee0406aa72d2bd56bc7041b4ae7f1d05b90258e877c5162b0c6305b60d4.
Tests additionally cover malformed operations, deadline clamping, raw UTF-8,
legacy isolation compatibility and every registered checksum fragment. The
metadata expectation correction is test-only.

gofmt and git diff --check passed. Excluding the 14 owned source/test paths,
the residual remains1044 entries with status SHA256
8d6e77107b6d1fc415702b0807cae792f5db96a160cfa9200b7c8255e0224cef and
out-of-manifest tracked diff SHA256
424738695ff8c3140640e2da91628580cdeebbcbbc66760b11f30f9d507a9184.
These compare to this implementer's retained preflight, not the nonexistent
prior agent's baseline artifact. The controller's pre-dispatch documentation
edits are part of the retained unrelated baseline.

Final grouped commands on this freeze:

1. `go test ./apiserver -run '^TestSecurityAgentMultistepPlanning' -count=1 -timeout=20m`
2. `go test ./apiserver -run '^TestSecurityAgentMultistep(AdmissionRoute|AdmissionMigrationWait|AdmissionMigrationLockOrder|RegisteredSavedDefinitionWait|Registered|Schema|RollbackSnapshot|ForeignKeyTriggerDrift|ProgressionAuthority|ProgressionWait|ApplicationClaim|ApplicationWait|TestSettlement|TestSettlementWait|CleanupConservative|LegacyActionRestoration|LegacyExecuteFence)Postgres$' -count=1 -timeout=20m`
3. `go test ./migrations ./artifactstore/... ./redteamadapter ./internal/multisteppricing -count=1 -timeout=10m`
4. `go test -race ./agentsec-worker -run 'TestSecurityAgentMultistep|TestSecurityAgentPlanner|TestSecurityAgentActionProcessor|TestOrderedJournal|Test.*(Budget|PreparedPlan|RequestBoundCost)' -count=1 -timeout=5m`

The old broad60m/75m failures remain baseline failures, supplemented by the
unchanged focused/completion passes documented above; they are not final
proof for the two Go changes. This corrected-freeze group supplies the
affected runtime/process, lease/wait, readiness/restoration, consumer and
worker-race proof without falsely claiming another full multistep pass.

Final group2 PASS389.929s: exact admission/replay and migration lock order,
registered saved-definition waits, registered/schema/rollback and FK drift,
progression/application authority and waits, known test settlement and waits,
all cleanup conservative cases, legacy action restoration and execute fence.
The group ran against the corrected frozen Go source and unchanged SQL pin.

Final group3 PASS: migrations22.687s, artifactstore1.617s,
artifactstore/s3driver1.984s, redteamadapter3.452s,
internal/multisteppricing7.457s. Final worker race group4 PASS9.568s.
The two PostgreSQL groups remain running; no source/test edits are permitted
until they complete.

Frozen owned source/test manifest (SHA256):

```text
b6929b4b343d7142ed8b256cb0e321e70ef3ea3c7c553522f0d2f70af72fff72  services/platform/agentsec-worker/security_agent_multistep_planning.go
46003535643b9910dc2fc9003fe1c34a422e55e0958b0c92a2a95d6a3a56208f  services/platform/agentsec-worker/security_agent_multistep_planning_test.go
28d501bc512b870fda0c5147b196f2e0f1a6a7a23e4e0bf835bb47aa3c0c4dc8  services/platform/apiserver/security_agent_multistep_planning_drift_postgres_test.go
693e92c27c5bb853d5cbf975539ce0cea42a5f791a6a8b770de14b7538840157  services/platform/apiserver/security_agent_multistep_planning_expiry_postgres_test.go
c39c11f4f03c02c8e948098ae67ef5627295f6f43c46b37dfc74e18597c7ff32  services/platform/apiserver/security_agent_multistep_planning_process_postgres_test.go
97b61c2ef5055e7d77bc96455e2d5bf2733ac7a03303ce50943ddb61e5f18c01  services/platform/apiserver/security_agent_multistep_planning_result_postgres_test.go
7a985fdb238c28e601cc0e151f464509c75c18e688855e7dc217e3877b709da7  services/platform/apiserver/security_agent_multistep_planning_concurrency_postgres_test.go
f8112e6c79d2620097e5b24171827a0013077d6300c8c43fa05d62c2fa922780  services/platform/apiserver/security_agent_multistep_planning_wait_postgres_test.go
b2507c67574a44244d0b45e7962d3754809ba1fe6ec36724a302ddc15fdc4023  services/platform/apiserver/security_agent_multistep_planning_settlement_postgres_test.go
afad1d4815981f3ca85f82c388d7602e3f3db4069569274f6893e7a842d7561b  services/platform/apiserver/security_agent_multistep_planning_postgres_test.go
e45d797136fbca37531989a780344219fe3b4976516fa4f6696236eac44823af  services/platform/migrations/production_security_agent_multistep.go
195a0107dfa1a1d7f7f5a74afe785bcdf6fcc5218b8e2754d63f3837dee58576  services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql
4d959efb2d43cf81b66380fa4ecefb03ce94ce334e2953cd7b04595056f173b3  services/platform/migrations/sql/0061_production_security_agent_multistep.planning.sql
f457f22ae8280dae395efd94e8b76fad25d5129e409ded12b60b20cadf6a8052  services/platform/migrations/production_security_agent_multistep_test.go
```

### Final handoff — DONE_WITH_CONCERNS

Final group1 PASS618.706s: complete private planning claim/lifecycle/concurrency,
all drift/refusal/expiry/result/accounting/wait cases, exact legacy compatibility
and restoration, and all13 fresh-process restart scenarios. All four
corrected-freeze groups passed. After the final process joined, process
inventory found no PostgreSQL server remaining. All14 frozen file hashes
still matched; git diff --check and staged diff --check passed.

Source commit: `bcb39d1b0e4a21345df2996137ea159a0d5071b7`
(`feat(agentsec): add private release61 planning authority`), exactly the14
source/test paths in the manifest above, 2008 insertions/6 deletions. Parent
base is reviewed Task11P `701c39ef22a567ec14901a3b349985da974e9306`.
This report is committed separately after the tested source commit so that
the evidence names that exact implementation. No push or activation occurred.

Final grouped summary: planning618.706s; downstream/readiness/restoration389.929s;
migrations22.687s; worker race9.568s; artifactstore1.617s/s3driver1.984s;
provider adapter3.452s; pricing7.457s — all PASS on the corrected freeze.

The unrelated baseline remains exactly1044 entries, with the same retained
status and out-of-manifest tracked-diff hashes recorded above. The index was
empty before the source staging; its exact14-path manifest was checked before
commit. Neither controller-owned documentation file nor any other unrelated
dirty file was staged or changed.

Concerns and boundaries:

- The original full-multistep60m and broad-race75m commands timed out and are
  retained as failed baseline evidence, with their exact assertion failures
  and stack evidence above. Failed cases passed unchanged focused reruns;
  all interrupted tails passed grouped completion gates. No definitive host
  suspension cause is claimed and no full-suite PASS is manufactured.
- Some supplementary concurrency/wait/restoration/adversarial tests were
  added as GREEN regression coverage, not independent pre-production REDs.
  The dedicated authority/lease bypass, lifecycle, process, parser/accounting,
  SQL-deadline and raw-UTF8 semantic REDs are separately recorded.
- Live approved pricing/catalog/credential and deployed artifact configuration
  remain external deployment gates. Controlled provider/file-store/PostgreSQL
  evidence establishes components only. Private61 remains dormant; no public
  API, default worker, CLI/UI, scheduler or route is enabled.
- Unknown non-idempotent provider outcomes never resend and require visible
  conservative manual recovery. Exact raw known usage is never inferred from
  pricing ceilings. This sacrifices automatic completion after ambiguous send.
- Release61 legacy settlement requires READ COMMITTED. Unusual legacy callers
  explicitly using REPEATABLE READ/SERIALIZABLE must retry in READ COMMITTED;
  release60 down restores the exact prior function/owner/ACL and behavior.
  Retained private planning evidence refuses down rather than discarding it.
- Independent spec and quality review remain the controller's next SDD stage;
  this implementation agent has not self-certified independent review.

## Fix round 1 — earliest planning authority deadline

Independent spec/quality review found an Important authority-lifetime gap.
Verified against source at bcb39d1b: SQL creates a300-second lease but creates
the budget deadline from definition.max_duration_seconds (valid range1..86400).
The budget deadline is not returned to Go. Retained pricing_bound.policy
expires_at and the independently verified cost-bound expiresAt are available
but not used by runtime contexts. Runtime uses only lease expiry, and checks
31-second runway only before start; a delayed committed start acknowledgement
can cross the usable authority window. SQL subsequently refuses expired result
recording, leaving a send's exact response/usage unavailable.

Hypothesis: returning an immutable budget start/deadline pair, checking it
against the server context duration/current budget row, and carrying the
earliest caller/lease/budget/active-pricing deadline across every boundary will
close the gap. Check31-second send runway again after start. Preserve30-second
per-query cap, exact readiness/post-wait checks and conservative no-resend.
No late-authority persistence bypass or fabricated usage is authorized.

Before production edits, add semantic REDs at real private SQL claim and real
controlled worker/provider process boundaries: budget/pricing windows earlier
than lease, insufficient runway, delayed committed start acknowledgement,
provider cancellation and timely result retention. Malformed/missing/
inconsistent budget deadline fields must refuse before I/O. Tests remain local
component evidence. SQL changes require a new registered fingerprint and
focused migration/readiness/restoration/consumer gates.

Dedicated RED command:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanning(Claim|WorkerProcess)Postgres$/^(budget_short|pricing_short)$' -count=1 -timeout=3m`.
Observed FAIL50.915s: claim9.39s failed with
`planning response omitted authoritative budget window`; budget_short16.32s
and pricing_short14.86s both reached successful real controlled-provider
admission and failed the expected-refusal assertion `fault did not stop worker`
(child5.90s/5.81s). All three owned PostgreSQL children normally joined.
These expose independent budget and pricing runway bypasses before production
edits. Child caller allowance is90s so the prior30s test caller does not mask
the earlier-authority behavior or conflict with the required31s send runway.

Post-ack semantic RED:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningWorkerProcessPostgres$/^pricing_ack$' -count=1 -timeout=2m`
FAIL61.398s. A real committed start response was deliberately delivered after
the40-second policy expiry (and after its SQL context timed out). The old
runtime still attempted one real controlled HTTP call:
`owned planning worker joined: provider_calls=1` (expected0).
The normal independent SQL witness was bypassed only for this transport test,
so it could not mask an unsafe runtime send. Its owned server normally joined.

Budget window drift RED:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningDriftPostgres$/^budget_(start|window)$' -count=1 -timeout=2m`
FAIL22.981s. Both controlled current-budget clock corruptions issued
`send_permit:true`: `drift permitted provider I/O budget_start true`
and `drift permitted provider I/O budget_window true`. This warrants binding
both start and deadline to the immutable job and exact definition duration.

Smallest coherent correction: planning_jobs now pins budget_started_at and
budget_deadline_at at real claim. SQL normal-operation guards compare the
live pair to the pinned pair and exact definition duration. Go strictly
decodes the nonzero budget timestamps/duration and canonical active pricing
window, then chooses min(caller, lease, budget, pricing) for SQL, artifact,
pricing lookup, start, provider, result, settlement and admission contexts.
The initial claim cannot know a budget that it has not created yet; it retains
the caller/30s SQL cap and SQL's own atomic deadline/post-wait guards.
The independent verified pricing expiry must equal the retained expiry.
After start, the returned state, budget window, lease and pricing bound must
remain identical, the context must still be active, and31s runway must remain.
Thus a late committed acknowledgement never opens external I/O.

Registered identity probe after SQL change:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningClaimPostgres$' -count=1 -timeout=2m`
failed at stale migration pin in9.668s and measured
`c2a7dab23a9d3c4aa0729869ebaefb372ef65ad4bb6aafe14cda5b6ffa182daa`.
This is a metadata refresh probe, not a semantic RED. The registered pin was
updated to that exact value; historical release SQL remains unchanged.

Focused GREEN:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanning(Claim|Drift|WorkerProcess)Postgres$/^(budget_start|budget_window|budget_short|pricing_short|pricing_ack)$' -count=1 -timeout=5m`
PASS125.372s. Worker SQL deadline/raw transport regressions PASS1.187s.
Additional controlled process tests now exercise budget late acknowledgement,
budget/pricing provider cancellation, timely exact result and actual usage
retention, and missing/null/malformed/inconsistent budget or pricing expiry
wire fields. Every SQL and artifact boundary observes its deadline against
the prior authoritative response. Cancellation-only fixtures extend their
independent HTTP timeout to80s so the earlier45s budget/50s pricing bound is
the actual cancellation cause, not the usual one-second test-client timeout.

Extended controlled-process GREEN:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningWorkerProcessPostgres$/^(budget_ack|budget_cancel|pricing_cancel|budget_timely|pricing_timely|wire_budget_.*|wire_pricing)$' -count=1 -timeout=8m`
PASS277.536s. Earliest-authority/unit SQL-cap/raw transport group PASS1.147s.

Additional cancellation trace within the same correction: Task11P's repository
constructor deliberately uses Background+5s for readiness. A deadline-only
wrapper bounds it but does not forward an explicit private caller cancellation.
Dedicated actual-worker RED:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningWorkerProcessPostgres$/^cancel_lookup$' -count=1 -timeout=2m`
FAIL22.371s with `pricing constructor SQL outlived private caller cancellation`;
provider_calls=0 and owned PostgreSQL normally joined. Hypothesis: retaining
the private parent context and attaching/detaching its cancellation to each
SQL child will preserve cancellation even for the nested constructor, without
changing the shared pricing API or creating a retry/goroutine leak.

Cancellation bridge GREEN: the same process selector PASS21.552s. Worker
deadline/earliest-authority/raw-transport race selector PASS2.298s:
`go test -race ./agentsec-worker -run '^TestSecurityAgentMultistepPlanning(SQLDeadline.*|EarliestAuthority|RawTransport)$' -count=1 -timeout=1m`.
The private SQL wrapper retains the invocation parent and attaches its
cancellation with a per-query context.AfterFunc, stopping the callback on
return and cancelling the child context. The shared Task11P constructor is
unchanged. The actual process matrix already builds its child binary with
`go test -race -c`; controlled provider/artifact boundaries are race-covered.

### Fix1 source freeze and affected grouped gate

gofmt and diff-check passed. All14 Task11A source/test paths are frozen;
only7 source/test paths differ from the implementation commit, plus this
evidence report. Excluding that owned manifest/report, the unrelated1044-entry
baseline and both retained SHA256 digests remain unchanged.
Registered fingerprint:
`c2a7dab23a9d3c4aa0729869ebaefb372ef65ad4bb6aafe14cda5b6ffa182daa`.

Frozen commands (no source edits while these run):

1. `go test ./apiserver -run '^TestSecurityAgentMultistepPlanning' -count=1 -timeout=25m`

2. `go test ./apiserver -run '^TestSecurityAgentMultistep(Pricing.*|AdmissionRoute|AdmissionMigrationWait|AdmissionMigrationLockOrder|Registered.*|Schema|RollbackSnapshot|ForeignKeyTriggerDrift|ProgressionAuthority|ProgressionWait|ApplicationClaim|ApplicationWait|TestSettlement|TestSettlementWait|CleanupConservative|LegacyActionRestoration|LegacyExecuteFence)Postgres$' -count=1 -timeout=25m`

3. `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Planning(Concurrent|Wait|LegacyRestoration)|Pricing(Concurrent|Wait)|AdmissionMigrationLockOrder)Postgres$' -count=1 -timeout=10m`

4. `go test ./apiserver -run '^TestProductionSecurityAgentPlannerBudget(Settlement|Reservation)$/^(exact|replay|expired_lease|deadline|wrong_scope)$' -count=1 -timeout=5m`

5. `go test ./migrations ./artifactstore/... ./redteamadapter ./internal/multisteppricing -count=1 -timeout=10m`

6. `go test -race ./agentsec-worker -run 'TestSecurityAgentMultistep|TestSecurityAgentPlanner|TestSecurityAgentActionProcessor|TestOrderedJournal|Test.*(Budget|PreparedPlan|RequestBoundCost)' -count=1 -timeout=5m`

This is the affected new-pin gate, not a rerun of the hours-long broad matrix.
It includes all27 process scenarios, complete planning and pricing families,
budget controls, representative admission/downstream authority, exact
release60 restoration, readiness/fingerprint/wait checks and affected race.
Before prepare selects the active pricing bound, input artifact work is
bounded by caller/lease/budget; after the bound is selected, its expiry also
constrains every boundary. No absent pricing authority is fabricated.
Returned provider bytes that commit before expiry retain exact raw output and
actual usage; a failed/lost bounded result commit remains the established
conservative uncertainty case, never a late-authority write or resend.

Early frozen results: group4 legacy budget controls PASS43.559s; group5
migrations18.806s, artifactstore0.320s, s3driver0.793s, redteamadapter2.296s,
internal/multisteppricing5.480s all PASS; group6 worker race PASS9.483s.
The remaining three PostgreSQL groups are still running on unchanged source.

Frozen group3 PostgreSQL race PASS110.216s: planning concurrency/waits/exact
legacy restoration, pricing concurrency/waits and admission migration lock
order. All14 source/test hashes still match the fix1 freeze.

Frozen group2 complete pricing and representative admission/downstream/
readiness/restoration selector PASS544.820s. Only the complete planning gate
remains active.

During read-only freeze review, one additional same-contract edge was identified:
the claimed-state decoder skips pricing validation because SQL has not selected
a bound yet. Hypothesis: an impossible non-null malformed pricing_bound on a
claimed response could therefore be ignored before input artifact I/O and
subsequent preparation. SQL never emits this shape, but strict wire refusal
must reject it. After all current handles join, add an actual-worker
wire_claim_pricing RED before any small Go-only discriminator correction.
Also add an active-but-less-than31s delayed acknowledgement case to directly
exercise the post-start runway guard independently of already-expired decoding.
SQL and its registered pin will not change for those decoder/runway tests.

Frozen group1 complete planning PASS965.723s. All six grouped commands exited
successfully, all14 frozen hashes matched, and no owned PostgreSQL or test child
remained. Unrelated1044-entry residual and both baseline digests matched.

### Fix1 supplemental decoder RED and runway regression

After every frozen handle joined, added real-worker wire_claim_pricing and
pricing_runway_ack fixtures. The latter returns a committed start response with
20s remaining (still active but less than the required31s), directly exercising
the post-ack runway guard. The former substitutes only an impossible non-null
claimed pricing_bound with malformed expiry; all SQL job state stays real.

RED command:
`go test ./apiserver -run '^TestSecurityAgentMultistepPlanningWorkerProcessPostgres$/^(wire_claim_pricing|pricing_runway_ack)$' -count=1 -timeout=3m`
FAIL56.160s, exactly wire_claim_pricing:
`security_agent_multistep_planning_test.go:278: fault did not stop worker`;
child5.83s, subtest14.60s. Actual worker reached successful admission rather
than refusing the malformed claimed bound. pricing_runway_ack passed unchanged.
Owned PostgreSQL pid15705 joined with pg_ctl exit0/server Wait exit0; no owned
children remained. Root cause/hypothesis confirmed: claimed decoder bypassed
non-null pricing validation, and ignored parse failure became absent expiry.
Minimal correction: claimed jobs must have neither a pricing bound nor a lookup
request; SQL selects both only in prepare. This is a Go-only discriminator
guard; SQL and registered c2a7dab fingerprint remain unchanged.

Final supplemental Go-only freeze: after the discriminator guard and two test
cases above, SQL/pin and all other production sources are unchanged from the
six passing new-pin groups. Source/test files are frozen again. Commands:

1. `go test ./apiserver -run '^TestSecurityAgentMultistepPlanningWorkerProcessPostgres$/^(exact|claim|prepare|budget_short|pricing_short|pricing_runway_ack|wire_.*|cancel_lookup)$' -count=1 -timeout=8m`

2. `go test -race ./agentsec-worker -run 'TestSecurityAgentMultistep|TestSecurityAgentPlanner|TestSecurityAgentActionProcessor|TestOrderedJournal|Test.*(Budget|PreparedPlan|RequestBoundCost)' -count=1 -timeout=5m`

Final supplemental group2 worker race PASS9.193s. Group1 PASS211.849s. The full
planning gate above predates only this Go discriminator guard; final focused
process cases recheck claimed/prepared/success/restart and malformed deadline
branches. The unchanged SQL gates remain new-pin evidence, not old-pin proof.

### Fix1 completion and scope

Source commit: `cc06540cd41681c259f66aa2bd6433b9c6af2622`, based on
`828150b786ff304f00fb5532dedcb786ad1013c7`.
All six affected new-pin groups passed; the final Go-only guard then passed
the focused real-process gate211.849s and worker race9.193s. Child processes
and owned PostgreSQL exited; no handles were left running. Final14-file
freeze hashes matched after tests and immediately before scoped commit.
gofmt/diff-check passed, index was empty before staging, and only these seven
source/test files were committed:

- `services/platform/agentsec-worker/security_agent_multistep_planning.go`
- `services/platform/agentsec-worker/security_agent_multistep_planning_test.go`
- `services/platform/apiserver/security_agent_multistep_planning_drift_postgres_test.go`
- `services/platform/apiserver/security_agent_multistep_planning_postgres_test.go`
- `services/platform/apiserver/security_agent_multistep_planning_process_postgres_test.go`
- `services/platform/migrations/production_security_agent_multistep.go`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.planning.sql`

The eighth changed file is this appended report, committed separately.
No published historical SQL, public/default wiring, production credentials,
or live policy configuration changed. Exact release60 restoration remains
covered by new-pin restoration/migration and race gates. Existing61 legacy
READ COMMITTED compatibility cost is unchanged.

Preservation checks after final tests:
residual_entries=1044;
residual_status_sha256=`8d6e77107b6d1fc415702b0807cae792f5db96a160cfa9200b7c8255e0224cef`;
out_of_manifest_tracked_diff_sha256=`424738695ff8c3140640e2da91628580cdeebbcbbc66760b11f30f9d507a9184`.
These compare the retained fix-round baseline, not the nonexistent original
agent baseline artifact. Controller-owned status documents were preserved.

Limitations: controlled provider/database/artifact fixtures prove components,
not production deployment. No live configuration claim or public activation.
Cancellation or lost result-commit acknowledgement retains conservative
unknown/no-resend behavior; it cannot guarantee raw evidence that never commits
before authority expires. Known raw/actual usage committed in time is retained
and settled, including shorter budget/pricing windows. The supplemental
runway case was an existing-behavior regression (not falsely labeled RED);
the malformed claimed-pricing and cancellation defects have observed semantic
REDs. Earlier original broad timeout limitations remain above; this fix used
the requested affected new-pin matrix, not an hours-long full-matrix rerun.
Independent review of this fix remains the controller's next step.

Final tested source/test SHA256 manifest:

```text
34e8b96c8b5015dadbddc53cddd945c811e93ffdfbd1c97542dfa41f22135bae  services/platform/agentsec-worker/security_agent_multistep_planning.go
758af5d3d628c491495ffa9787044c7f46f98952bb62a024443266e44493487f  services/platform/agentsec-worker/security_agent_multistep_planning_test.go
b9204081a4a54b0442aae953684cde6526ce491c5da7ba5918cae8a36b79d2c3  services/platform/apiserver/security_agent_multistep_planning_drift_postgres_test.go
693e92c27c5bb853d5cbf975539ce0cea42a5f791a6a8b770de14b7538840157  services/platform/apiserver/security_agent_multistep_planning_expiry_postgres_test.go
32777e7b7de56ad20b431c77f2ec33d3ba205c8fd7b365ca4ba14c2788d351cd  services/platform/apiserver/security_agent_multistep_planning_process_postgres_test.go
97b61c2ef5055e7d77bc96455e2d5bf2733ac7a03303ce50943ddb61e5f18c01  services/platform/apiserver/security_agent_multistep_planning_result_postgres_test.go
7a985fdb238c28e601cc0e151f464509c75c18e688855e7dc217e3877b709da7  services/platform/apiserver/security_agent_multistep_planning_concurrency_postgres_test.go
f8112e6c79d2620097e5b24171827a0013077d6300c8c43fa05d62c2fa922780  services/platform/apiserver/security_agent_multistep_planning_wait_postgres_test.go
b2507c67574a44244d0b45e7962d3754809ba1fe6ec36724a302ddc15fdc4023  services/platform/apiserver/security_agent_multistep_planning_settlement_postgres_test.go
40490337c1c875a6a1914dc7cf160296a8ff24b3a62e87b2314db9c47a1ede7f  services/platform/apiserver/security_agent_multistep_planning_postgres_test.go
d5856f0862effad02a6f3e93dad6e574a8144d3035f776ea426dc282fe921add  services/platform/migrations/production_security_agent_multistep.go
195a0107dfa1a1d7f7f5a74afe785bcdf6fcc5218b8e2754d63f3837dee58576  services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql
1fcc193474638ef03aca1f39cf681a5def0a6b2818022ece8983a12f424a782f  services/platform/migrations/sql/0061_production_security_agent_multistep.planning.sql
f457f22ae8280dae395efd94e8b76fad25d5129e409ded12b60b20cadf6a8052  services/platform/migrations/production_security_agent_multistep_test.go
```

Fix1 initial source/test SHA256 manifest (before supplemental Go-only guard):

```text
1e69a0527b561485cbeece9c9bf9e7d366029581601edfe2c5d0e36b980c0225  services/platform/agentsec-worker/security_agent_multistep_planning.go
15064abdccfedccc156bf52895d5c52fd496869d1fa9eecd80d5b3c1f8399bd7  services/platform/agentsec-worker/security_agent_multistep_planning_test.go
b9204081a4a54b0442aae953684cde6526ce491c5da7ba5918cae8a36b79d2c3  services/platform/apiserver/security_agent_multistep_planning_drift_postgres_test.go
693e92c27c5bb853d5cbf975539ce0cea42a5f791a6a8b770de14b7538840157  services/platform/apiserver/security_agent_multistep_planning_expiry_postgres_test.go
6362d49484e9963055f983f30da339e0081bb4e8226f22040421aae19b42df14  services/platform/apiserver/security_agent_multistep_planning_process_postgres_test.go
97b61c2ef5055e7d77bc96455e2d5bf2733ac7a03303ce50943ddb61e5f18c01  services/platform/apiserver/security_agent_multistep_planning_result_postgres_test.go
7a985fdb238c28e601cc0e151f464509c75c18e688855e7dc217e3877b709da7  services/platform/apiserver/security_agent_multistep_planning_concurrency_postgres_test.go
f8112e6c79d2620097e5b24171827a0013077d6300c8c43fa05d62c2fa922780  services/platform/apiserver/security_agent_multistep_planning_wait_postgres_test.go
b2507c67574a44244d0b45e7962d3754809ba1fe6ec36724a302ddc15fdc4023  services/platform/apiserver/security_agent_multistep_planning_settlement_postgres_test.go
40490337c1c875a6a1914dc7cf160296a8ff24b3a62e87b2314db9c47a1ede7f  services/platform/apiserver/security_agent_multistep_planning_postgres_test.go
d5856f0862effad02a6f3e93dad6e574a8144d3035f776ea426dc282fe921add  services/platform/migrations/production_security_agent_multistep.go
195a0107dfa1a1d7f7f5a74afe785bcdf6fcc5218b8e2754d63f3837dee58576  services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql
1fcc193474638ef03aca1f39cf681a5def0a6b2818022ece8983a12f424a782f  services/platform/migrations/sql/0061_production_security_agent_multistep.planning.sql
f457f22ae8280dae395efd94e8b76fad25d5129e409ded12b60b20cadf6a8052  services/platform/migrations/production_security_agent_multistep_test.go
```
