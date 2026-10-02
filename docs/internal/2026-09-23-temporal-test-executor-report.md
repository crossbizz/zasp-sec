# P4C/P4D single-test executor, local evidence

Local bounded-slice verification is complete. Frozen for independent review.
This is not independent acceptance, production activation, or completion of
P4C/P4D. The failed runs below remain part of the evidence.

Worktree: `.worktrees/cached-runtime-ship-20260917`. HEAD remains
`6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. Review compares the captured
pre-edit overlay, not HEAD. The capture script and baseline are in
`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`, prefix
`p4c-test-executor-`. No commits, pushes, production changes, nested agents, or
authoritative ledger edits were made by this executor task.

## What the slice changes

Release74 is additive. It specializes `run_test` and `rerun_test`, retaining
their canonical parent, single step0, child, category, and request identities.
It does not route them through ordered69 or wrap retained claims in Activities.

The immutable66/73 owner records remain historical admission evidence. A74
successor can take over only an untouched parent, under the same parent and
effect locks used by retained claims. Prepared, attempted, leased, or uncertain
historical work stays retained. Both RLS and mutation triggers fence old writes
after takeover. The takeover race test observes `pg_blocking_pids`, then changes
the old attempt before releasing the held parent lock.

Private74 planning, provider reservation, effect, invocation, child receipt,
parent receipt, stop, start-delivery, and SQS-delivery journals carry execution
evidence. A public effect mirror is not invocation authority. There is no
invented lease or reuse of public71 `lease_digest` as an execution key.

Temporal owns ordering, approval waiting, cancellation, classified Activity
retry and settlement. Production composition selects the single-test Product
and the actual planner/native adapter paths. SQL rechecks current configuration,
source, resource/version/safety, credentials, kill switches, approval, price,
request binding and budget before fresh IO. A committed or uncertain invocation
start cannot receive another send permit on retry.

Child evidence and parent settlement are distinct. Completion needs both, with
the existing comparison outcomes, including baseline-unavailable. Unknown
execution keeps debt and capacity even after a terminal parent label.

## Delegation and customer controls

The actual typed activation route writes an explicit version-bound grant with
exact organization/workspace/environment, definition, action, test/version and
target identity. Grant creation checks current SQL membership, scoped permission
JSON and effective role permissions, plus fresh authentication. The test holds
view/manage_workflows true while removing scoped run_tests; read-only denial is
a separate case.

The canonical `security_agent_definition_service` principal is independent of
creator login/session expiry. Automatic child and red-team audit attribution
use this principal; historical parent/scheduler attribution is unchanged.
Automatic supervised approval uses the service principal as requester. A
different currently authorized human must approve. Manual requester authority
remains current human authority.

Existing create/activate/update/delete product routes are the grant lifecycle.
There is no new grant-only endpoint. Configuration changes revoke the exact
version grant atomically and retain the product audit/receipt. Already-active
renewal checks current authority and writes explicit grant evidence; an arbitrary
old activation replay does not create delegation.

Backfill requires matching immutable history, actual activation audit and
receipt, unchanged current active resource/configuration and current grantor
scoped run_tests authority under migration/permission locks. Every candidate has
a granted/skipped decision and evidence. The fixture reaches the actual55
API-role activation writer, then installs56 through74 in that same owned DB.
Hand-built legacy JSON fixtures are only controlled negative evidence.

Validated/draft stay disabled. Installed production activation enables supervised
v3 with approval, then autonomous v4. An earlier test expecting supervised to
stay disabled was wrong; no production change was made for that expectation.

Approval decision/detail/page use additive74 API entries with current catalog
and registered API checks. Decisions retain the installed core, fresh-auth,
requester separation, CAS, expiry, scoped permissions and immutable replay
receipts. Detail/page retain installed context assemblers, filters, pagination
and strict decoding. Release55 refusal after upgrade was correct; the missing
current route was fixed without reviving55 readiness.

The existing typed cancellation API now selects74 for74-owned parents. Its
private copy keeps installed cancellation CAS, replay, audit and63 manual
response projection. Only the exact58 effect-rejection/export-child branch is
removed for this scoped family. Current scoped manager authority remains
required. Cancellation leaves effect, budget and uncertain execution debt intact.

Approval/rejection/cancellation commit one immutable74 control intent with the
existing decision receipt, in the same SQL transaction. The registered executor
relay waits for original accepted_start, then signals/cancels the existing
workflow and records a separate delivery receipt. It never starts a workflow.
Missing workflow or RPC failure is not accepted delivery. A terminal shortcut
requires verified parent or stop evidence and no unresolved obligation. API
roles cannot invoke this relay. Changed receipt/audit identity fails closed.

Installed65 capture previously accepted only approved/rejected decisions. Its
additive compatibility change allows cancelled only for an exact persisted74
owner, registered API session, current74 catalog and matching parent, approval,
intent, receipt and audit. Original approver/decided/fresh-auth checks remain.
An exact cancelled-decision replay returns the immutable receipt; it does not
reopen execution. A fixed synthetic trigger-negative helper exists only in the
owned test DB. It reaches the real65 trigger as the registered API, gets42501
`outbox approval decision absent`, rolls back, and checks zero parent, approval,
audit, receipt,65 command or74 control residue. The separate typed non74 route
refusal is not used as evidence that this trigger branch ran.

Actual API cancellation before planning can settle an absent-obligation stop.
It requires no plan, job, budget, reservation, effect, child or invocation, plus
the committed cancellation decision. Start acceptance remains a separate step;
the decision stays pending until that original start is accepted. Uncertain work
cannot use this proof variant.

P5/P6 must project this exact scoped grant and its version/revocation semantics
into FGA. This slice does not claim an FGA permission decision from a successful
model-readiness probe.

## Transport, shutdown and cleanup

Owned SQS delivery authenticates the exact canonical scoped message, owner,
child, effect, outbox and link. Unsettled delivery wakes the existing workflow
and persists a durable delivery receipt before ACK. Signal or receipt commit
failure prevents ACK. No signal-with-start, fresh logical run, or provider IO
occurs in this processor. Existing retry/DLQ handling remains.

A settled terminal duplicate can ACK without another signal only with original
accepted-start and verified child/parent proof. A separate unsent-cancellation
variant needs a stopped never-started effect, cancelled attempt0 child with no
worker/leases/invocations, immutable stop audit, and settled public link. Its
explicit cancelled/test_run_cancelled snapshot/proof/receipt is not a native
success receipt and carries no artifact claim. Typed reload must show cancelled
and cancelled_before_execution. Missing/tampered proof and started/unknown work
cannot use this terminal shortcut.73 accounting is unchanged; the real link
obligation is discharged, not ignored.

True pending cleanup returns a typed pending observation. A disconnected
signal/timer loop stays wakeable beyond12 observations. After64 observations,
Continue-As-New carries the same product/workflow/effect identity, original24h
business deadline and cleanup-only phase/reason. Cleanup cannot call Plan/Test.
Permanent catalog/identity refusal remains an explicit repair condition with debt.
Repeat start validates the original root, first execution, predecessor history,
task queue and immutable input across continuation. Missing history fails closed.

The live drain test observed a first Close timeout. It then waits for borrowed IO
to return, retries Close successfully, checks each client closes once, and only
then starts the replacement worker. This proves the documented retry contract,
not clean shutdown on the first Close attempt.

## Local test evidence so far

Commands run from `services/platform`; all named logs have the packet prefix.
Owned PostgreSQL stop and process Wait results are recorded in each integration
log. Controlled provider/storage/native/FGA/SQS transport boundaries are labeled
inside the tests; local Temporal and installed SQL are real.

* `go test ./apiserver -run '^TestTemporalTestExecutorServiceGrantPostgres$' -count=1 -v`
  and the focused `agentsec-migrate` installed-release test passed the earlier
  authority/config phase:36.355s and29.707s (`authority-config-cli.log`). Later
  source requires final affected verification.
* Ownership/effect local group passed69.051s (`lock-helper-candidate.log`).
  Planner/native/settlement component groups and production unit groups passed
  earlier, before the remaining approval/cancellation extensions.
* Actual two-tenant production composition passed134.621s, nested98.589s
  (`live-two-tenant-bounded-candidate.log`). This traverses API admission,
  actual Temporal start/worker, prepared-IO drain/restart, current tenant-B API
  DELETE before fresh IO, exact repeat start and durable duplicate SQS ACK.
  External transports and native command execution are controlled.
* Pending/CAN controlled tests passed0.783s, continuation0.871s and resume0.800s.
  The actual local Temporal cleanup continuation passed4.274s with a controlled
  Product (`live` CAN packet log); this is not SQL cleanup proof.
* `automatic-actor-red.log`:50.888s failure23514 on actual child requested_by
  CHECK with inactive creator. The scheduler label is not a ProductID. Source now
  selects the canonical grant principal for automatic child/audit creation.
* `auto-cleanup-candidate.log`:52.182s failure40001 for admitted/no-effect cleanup.
  The absent variant wrote JSON null effect_key, rejected by shared closed().
  Only that exact variant now validates the nullable field separately; the
  global closed predicate is unchanged.
* `approval-cancel-group-candidate.log`:219.729s failed group. Cancellation and
  lost-start subassertions passed; the last role-drift fixture attempted a
  PostgreSQL-forbidden membership cycle0LP01 and was corrected. Supervised
  automatic requester mismatch was observed49.34s. Manual decision/replay and
  occupancy checks passed before old55 typed-read refusal55000 (88.82s case).
  None is a whole-group GREEN.
* Catalog compile logs that fail invalid migration state after independently
  obtaining a fingerprint are pin-update evidence only.42601 compile failures,
  a missing test helper build failure, timestamp/fixture pricing replay errors,
  and synthetic DELETE404 are not behavioral authorization failures.
* `decisions-group-candidate.log`:282.509s PASS, cancellation83.50s,
  automatic61.51s, approval136.46s. These include actual typed cancellation,
  stale CAS/current manager denial, idempotent receipt and one control intent,
  pre-IO refusal after cancellation, registered automatic adapter resolution,
  and approved detail/page foreign-scope behavior. The longer owned approval
  fixture confirmed its earlier120s lifetime failure; production limits stayed
  unchanged. Later decision-proof tests require another affected pass.
* `decision-replay-red.log`:65.157s FAIL. Current74 entry rejected the completed
  parent before the installed receipt replay core could return an existing
  rejected decision. The new stopped-replay branch requires the same receipt,
  control identity and response digest; current caller/configuration and
  fresh-auth checks stay in place. It does not reopen work.
* `live-decisions-candidate.log`:208.643s FAIL, nested173.808s. The late nested
  adapter failed journal readiness before resolution. Source changed while
  this fixture was running and compiles child Go tests late, so this is not
  valid same-source live evidence. A new subprocess preflight compares actual
  installed registration pins with compiled metadata. The next live run must
  hold all relevant source fixed throughout every child process.

## Final affected evidence

All commands below ran from `services/platform`, with `-count=1 -v`. Log names
are relative to the packet and have prefix `p4c-test-executor-`.

| Command selector and package | Result | Log |
| --- | --- | --- |
| `go test ./apiserver ./agentsec-migrate -run '^TestTemporalTestExecutor(ServiceGrant\|Transport\|Cancellation\|Automatic\|Approval\|InstalledRelease)Postgres$'` | Failed aggregate600.789s. Transport85.09s, Automatic99.46s and CLI31.59s/package32.708s passed. | `final-affected-group.log` |
| `go test ./apiserver -run '^TestTemporalTestExecutor(ServiceGrant\|Cancellation\|Approval)Postgres$' -timeout=15m` | PASS501.409s: ServiceGrant146.26s, Cancellation121.75s, Approval232.61s. All three owned PG processes joined normally. | `final-unfinished-group.log` |
| `go test ./apiserver -run '^TestTemporalTestExecutorLivePostgres$' -timeout=6m` | PASS215.898s/case214.91s; nested worker179.211s/case177.97s; PG64811 joined normally. | `live-decisions-final2.log` |
| `go test ./orchestration ./agentsec-worker ./redteamadapter -run '^Test(SingleTest\|TemporalJournalBounds)'` | PASS0.487s/1.541s/0.476s. Live CAN skipped here and run explicitly below. | `final-unit-group.log` |
| `ZASP_SINGLE_TEST_LIVE_TEMPORAL=true go test ./orchestration -run '^TestSingleTestLiveCleanupContinuation$'` | PASS3.956s/case3.63s, actual local Temporal; controlled Product. | `final-live-can.log` |
| `go test ./red-team-adapter -run '^TestProductionAdapter'` | PASS10.319s, production protocol selection and refusal. | `final-adapter-routing.log` |

The aggregate failure was not a product GREEN. ServiceGrant121.25s and
Cancellation121.11s lost nested subprocesses at their120s fixture deadline;
both owned PG processes joined normally. Approval was interrupted after2m53s
by Go's aggregate10-minute limit. Its PG62219 was absent after command exit,
but that interrupted case has no normal stop/Wait receipt. The unfinished-only
run covers those three selectors with finite4-minute owned fixture bounds and
a15-minute aggregate bound. No product execution deadline changed. Finished
selectors were not rerun solely because of the aggregate timeout.

`decision65-prestart-group.log` separately passed API224.664s and CLI29.910s.
`capture-negative-candidate.log` passed112.611s, including the exact65 trigger
negative and independent non74 route refusal. The final approval selector repeats
both on final source. Original stopped-replay RED66.779s identified65's cancelled
state exclusion; prestart RED23.315s identified missing queued cancellation
cleanup. Neither is relabeled as a successful run.

`live-decisions-stable-candidate.log` failed195.054s/case194.13s. Automatic
supervised approval, actual control delivery and rerun remediation passed before
the next manual cancellation fixture reused a definition whose creator had been
deliberately deactivated. The installed manual admission guard requires that
original activation actor's current membership, so the refusal was correct.
Final2 creates/activates a separate supervised definition through the actual
API as current human609, before the nested worker starts. An unused finding rule
prevents incidental automatic admission; the automatic definition's creator
stays inactive. No manual authority was weakened.

The complete final live scenario uses real Temporal1.32.0 and installed SQL.
It traverses two tenants, actual API admission, untouched transfer, duplicate
start, committed preparation, drain/restart, tenant-B API DELETE before fresh IO,
native child and parent receipts, and durable duplicate SQS ACK. It then proves
automatic73 supervised approval through the typed API and production control
relay, the same execution, no preapproval child/effect, and actual failed-baseline
to passed-child remediation. Finally, typed cancellation commits control before
the production relay cancels that same execution; absent-child cleanup verifies
the stop without a native provider call. Typed public readback is checked.
Planner HTTPS, native commands, object storage, identity and FGA transport are
controlled. This does not prove deployed providers, real AWS SQS or FGA checks.

## Source reconciliation

`final-source-before.log`, `source-during-5276.log` and `final-source-after.log`
agree on platform digest
`8905ccf344225f367370bbb037ff540bea9984996ad67b41614942aed599f7bd`.
The first final groups and stable live failure held that source unchanged.

`final2-source-before.log` and `final2-source-after.log` agree on
`eb9d12db3453ec030f529b667697590ef854f8a38210d7e05e2e39c365d70bdd`.
Only three test files changed between snapshots: ServiceGrant's fixture bound,
transport fixture bounds, and the separate live cancellation setup. The snapshot
lists their exact before/after hashes. Production code, SQL and all completed
unit/CLI/transport/automatic selector bodies stayed unchanged. The unfinished
group and successful connected run held final2 source unchanged throughout,
including late nested Go compilation.

The independently compiled74 catalog pin is
`85dab5594b65f66af305c0e972a8e6c96a66779b75b707c6c7ab593ee29688ea`.
Actual CLI `up-temporal-test-executor` installation, repeat readiness and drift
denials are covered. The baseline contains1993 records; all206 prior SQL files
and all six accepted admission/fix1 packet artifacts remain byte-identical.
HEAD is unchanged. Final scoped diff and manifest are generated by
`p4c-test-executor-capture.mjs freeze`; the manifest contains each changed source
hash, every preserved test-log hash, baseline hash and scoped-diff hash.

## Interfaces and retirement work

The new production callers are typed API activation/configuration/approval
routes; the74 start relay and SingleTest workflow/Activities; planner74 SQL;
native linked-test74 adapter/invocation/settlement; and registered red-team SQS
delivery. Executors and compensation use their existing separate registered
DSNs. No new executor DSN or worker role membership was introduced.

P9 inventory:74 private journals and public mirrors; owner RLS/mutation guards;
the NOLOGIN/NOINHERIT/no-membership parent lock role and narrowly scoped lock and
delivery proof helpers; exact registered adapter/worker internal effect SELECT
exceptions; the cancelled-link settlement variant; additive API domain copies
and approval/read dependencies; immutable decision control intents/receipts,
private cancellation core and registered control delivery entries; and the
temporary66 two-object compatibility
surface. That surface saves and verifies original legacy_visible ACL and fingerprint
definition, grants only the required lock-role helper EXECUTE, and projects only
those two original identities after actual74 catalog/registration verification.
Extra grants, role drift, wrapper/body or saved evidence changes must fail ready.
The second temporary surface is65 capture/fingerprint: saved original definitions,
the exact cancelled74 predicate, actual owner/ACL/security attributes and bodies,
and the74 fingerprint projector. It projects only those two original definitions
after actual registered74 catalog equality, with no current_ready recursion.
Both compatibility surfaces need additive P9 retirement. Historical SQL files
must remain immutable then too.

All-owner capacity uses73 unresolved OR74 real unresolved obligations. Org lock
order and retained try-lock/retry behavior remain. Proven unsent released
reservations do not consume capacity; unknown work does.

Unsupported here: other specialized families and triggers, ordered-family
retirement, remaining retained historical uncertain backlog, production cutover,
real AWS/provider/container/FGA authorization operations, and the shared P3/P9
workflow's separate cleanup retry-exhaustion work. Those are not implicitly
completed by this single-test loop.

Concrete remaining caller inventory follows the authoritative retirement TSV,
which this task did not edit:

| Still-required family | Current caller and missing replacement |
| --- | --- |
| Common triggers/source selection | `securityAgentProcessor.RunOnce -> ScheduleSecurityAgentTriggers`, ordered HTTP `trigger_resource`, finding/attack-path and webhook handoffs still need full Temporal Schedule/common-trigger equivalence.73 automatic source selection and this executor do not finish every trigger. |
| Standalone tests, M5-13 | `workerModeRedTeam`, `workerModeTestReconciler`, `existingTestClient.ReconcileOne`; standalone/retained reconciliation and uncertain backlog remain. Preserve red-team-outbox SQS/DLQ. This slice handles only positively74-owned linked deliveries. |
| Policy deployment, M6-18 | `composePolicyDeploymentWorkerRuntime`, `policyDeploymentProcessor`; non-lease signed rollout, gateway terminal receipt and cleanup workflow remain. |
| Attack Lab | Controller/reconciler/outbox modes and `attackLabProcessor`; Fargate lifecycle, scoped proxy, TTL cleanup and parent evidence need their own migration. Required SQS commands remain. |
| Exports/TTL, M2-41/42, M7-12/13/14/19, M7A-23 | Audit/compliance workers and `securityAgentProcessor.reconcileExportSettlements`; actual capture/chunk/manifest, download, cleanup and parent-settlement authority must migrate, including obsolete55 trigger/readiness dependencies. |
| Webhook action, M7A-24 | Existing signed `send_response_webhook` handoff and settlement; no invented inbound webhook trigger is supplied here. |
| Recovery/operator | Recovery/backup outbox modes and `agentsecctl` recovery client; reviewed pending/unknown repair, expired-history behavior and operator acceptance remain. Preserve backup/restore SQS transport. |
| Other legacy actions | Security-agent/action modes and70/71 copied claim/reconciliation controls remain until each family has equivalent replacement evidence and P9 retirement. Streaming ingestion and risk/search/graph projections remain outside this replacement. |

## Self-review and remaining gates

I checked the changed authority paths against the captured overlay: canonical
manual/service identities; current grant/configuration and pre-IO gates;
parent/effect lock order; retained claim fencing; explicit journal selection;
child versus parent evidence; cancellation/unknown capacity; strict typed replay
and readback; signal/ACK ordering; and compatibility projection scope. The
shared Activity change extracts borrowed-client lifetime only. The owned SQS
branch runs before retained claim and ACKs only after verified durable acceptance.
No lease loop runs inside an Activity. Superpowers grouped RED/GREEN and fresh
verification guided the test groups; vendor internals were not tested.

Known operational limits remain explicit:

* First Close timed out. Only joined borrower exit followed by successful retry
  proves client release and safe replacement-worker startup.
* The aggregate timeout sampled a runnable stack repeatedly constructing
  migration metadata through releases55..74. Approval took232.61s in the final
  scoped run; the successful live nested case took177.97s against its180s bound.
  This is a P8 performance/readiness-cost concern, not dismissed as harmless
  test overhead. No opportunistic caching or catalog-verification weakening was
  added. Deployment latency and clean first-attempt shutdown remain gates.
* Missing/expired continuation history is repair-required. Unknown provider
  execution retains obligations; this slice does not install a general operator
  recovery route or fix shared P3 cleanup exhaustion.

Controller owns independent review and publication. No production availability
or whole-P4 completion is claimed.

## Fix1, after the September24 review

The original report and frozen packet remain history. This section records the
first review repair, against a new pre-edit overlay, not against HEAD.

Baseline: `p4c-test-executor-fix1-baseline.json`, SHA256
`af4a02cff741e456ee73e20631426326d3750e9e66648fa134dbe652e7599110`.
It contains2036 platform/report records and hashes the original executor packet.
The separate `p4c-test-executor-fix1-capture.mjs` permits changes to new0074 SQL
only, rejects changes to pre74 SQL or the original packet, and requires the
original report bytes to remain an unchanged prefix.

I used Superpowers review handling, grouped TDD and verification for both
Important findings. Cleanup now keeps ProductUnavailable (retryable only) and
Temporal timeouts inside its cleanup-only loop after a bounded Activity batch
exhausts. Its timer/signal wait and64-observation continuation keep the original
identity, business deadline, cleanup reason and outcome. Permanent refusals,
nonretryable ProductUnavailable and unknown contracts still fail explicitly;
they do not produce cleanup proof or release SQL debt.

Approval replay now authenticates the current registered API and scoped actor,
then verifies the existing receipt against its immutable control/audit proof.
The installed decision core still checks fresh authentication, exact intent,
receipt identity and expiry. A valid replay returns the original response plus
`replayed:true`; it does not call the control writer. New decisions retain live
definition, approval, plan and budget gates. Effect-time authorization is
unchanged.

Minor3 stays open. Changing SingleCleanup from an error-only Activity to a
successful typed pending payload is unsafe in place: older workflow code calls
`Get(...,nil)` and would treat that pending response as proof of completion.
This fix preserves the Activity name and payload contract. A versioned result
transition needs its own replay/worker compatibility proof; ordinary pending
still produces Activity error log noise.

### Focused evidence

Commands below ran from `services/platform`, with `-count=1 -v`. Log names have
the prefix `p4c-test-executor-fix1-` in the existing execution-plan packet.

| Command/selectors | Actual result | Log |
| --- | --- | --- |
| `go test ./orchestration ./apiserver -run '^Test(SingleTestCleanupRecoversExhaustedTransientBatch\|TemporalTestExecutorApprovalReplayPostgres)$' -timeout=6m` | RED: orchestration0.781s; original and continued cleanup failed after12 unavailable/timeout attempts. Permanent refusals passed. Typed approved replay after live deadlines failed with operation conflict: API47.582s/case46.74s, PG69977 normal join. | `group-red.log` |
| `go test ./orchestration ./apiserver -run '^Test(SingleTest\|TemporalTestExecutorApprovalReplayPostgres)' -timeout=6m` | Cleanup unit GREEN0.844s. SQL compile failed42P01 because a declaration referenced the later-created control table; API19.781s, PG70577 normal join. No SQL behavior claimed. | `compile-unit.log` |
| `go test ./apiserver -run '^TestTemporalTestExecutorApprovalReplayPostgres$' -timeout=5m` | Independent SQL compile succeeded and produced pin24aacf71b65ff37a7a92d4f623542940dd84a7ed4b2867c3ac526e4a20660d8a. Expected stale-pin rejection: API20.377s, PG70820 normal join. | `compile2.log` |
| `go test ./orchestration ./apiserver ./agentsec-migrate -run '^Test(SingleTest\|TemporalTestExecutor(ApprovalReplay\|Approval\|InstalledRelease)Postgres)' -timeout=9m` | GREEN: orchestration0.847s; API228.687s (Approval114.57s, Replay113.29s); CLI30.682s/case29.53s. PG71076/71481 and CLI-owned PG joined normally. | `group-green-candidate.log` |
| `ZASP_SINGLE_TEST_LIVE_TEMPORAL=true go test ./apiserver ./orchestration -run '^Test(TemporalTestExecutorLivePostgres\|SingleTestLiveCleanupContinuation)$' -timeout=6m` | GREEN: API238.708s/case237.51s, nested worker178.890s/case177.67s, PG71935 normal join. Real Temporal CAN4.091s/case3.61s. | `connected-green-candidate.log` |

Current verification source digest over2036 platform files:
`1768b8450cdb2f154570bfe757c57741d73c39eb4bba17b55b402e0a23c49c02`.
`p4c-test-executor-fix1-verification-source.json` records each file hash.
The same digest passed before and after the connected run. No platform file
changed during either final group or the nested worker/adapter executions.

The new cleanup tests exhaust12 actual SDK Activity attempts, then observe
attempt1 of the next cleanup batch and supply controlled completion proof.
Original and continued workflows both recover; duplicate wakes and cancellation
do not reenter Plan/Test/Settle. Another case combines one exhausted batch with63
pending observations, checks the exact cleanup-only continuation payload, then
completes it after the original business deadline. These are application tests
with controlled failures, not a claim of a real database outage test. The
unchanged Activity wrapper's pending/unavailable/deadline/permanent result
classification has its own focused test.

The typed API expiry case uses an actual approved decision, expires the live
approval/plan/budget, and gets the exact original result back. Fresh effect
reservation still fails. The connected case completes actual remediated parent
settlement first, then makes the same replay request through the typed API.
Both compare the complete original result and unchanged audit/receipt/control
rows; changed intent/version, stale authentication, revoked scoped run_tests and
expired receipt are denied. The connected run also retains actual approval and
cancellation relay composition, two-tenant pre-IO refusal and controlled native
adapter receipts. Its first Close still times out.

I reviewed the fix against its captured overlay: timeout versus permanent
classification, the64-batch history bound, preserved continuation identity and
deadline, exact receipt/control/audit proof, current API/actor locks, fresh-auth
and expiry delegation to the installed core, and unchanged new-decision/effect
gates. The final preservation check confirms206 pre74 SQL files,170 original
executor artifacts, six accepted predecessor artifacts and every baseline copy
are unchanged. No new permission, table, compatibility wrapper or retirement
surface was added. The existing74 approval entry remains in the P9 inventory.

Freeze outputs are `p4c-test-executor-fix1-scoped.diff` and
`p4c-test-executor-fix1-frozen-source.json`. The manifest binds the changed files,
all fix1 logs, baseline, capture script and original packet hashes. The
`final-preservation.log` records the preservation/source check; no completed
selector was rerun after a relevant source change stopped being necessary.

### Evidence corrections and limits remain

The inactive-creator live fixture admits/schedules first, then deactivates the
creator. It proves POST-admission execution independence, not admission while
the creator is already inactive. The original adapter routing log's
`TestProductionAdapterOwnedRouting` is skipped, not passed. Selected routing
checks and the connected worker proof are separate evidence.

Performance is still a deployment gate. Whole-test timings and metadata stack
samples do not measure individual production readiness/query/start budgets.
First Close also remains open: the accepted evidence is safe retention through
a timeout, borrower exit, then successful Close retry before replacement.
Neither limitation is fixed here. Shared P3/P9 cleanup, external production IO,
OpenFGA projection and full retirement remain separate work.
