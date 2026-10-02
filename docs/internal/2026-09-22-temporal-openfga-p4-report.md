# P4, staged implementation

P4A is a component stage. Automatic discovery is not available through this new route yet. The controller approved staging before source edits; all original 728 obligations remain in scope.

## Before implementation

The baseline copies the dirty overlay at HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`, including platform sources and the retirement inventory. Its manifest is `p4-baseline.json` in `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan`. Applied SQL through 71 stays byte-identical. No commits, publication, authoritative ledger edits, shared database operations or new provisioning are authorized here.

P4A will add a real Temporal SDK Schedule adapter, canonical tenant/schedule identities, scoped discovery workflow messages, current-authority Activity contracts and grouped application tests. No production registration or selector changes until P4B supplies its real authority. The retired 63/64 engines stay retired.

The exact intended Schedule boundary is `DiscoveryScheduleSource.WithCurrentSchedule(ctx, ref, callback)`. Its implementation must serialize the canonical organization/workspace/environment/schedule across instances, reread authoritative desired configuration after acquisition, bound the callback's RPC and release/close safely. P4B should use a dedicated-session advisory lock; it must not keep a SQL transaction open across the RPC. Configuration writers must either share this serialization or persist revision plus durable change delivery, ensuring newer changes are reconciled. SDK 1.48.0 `ScheduleHandle.Update` sends a nil conflict token. This boundary is not SDK optimistic concurrency, and a late RPC can outlive a lock. Ambiguous writes remain unknown/retry/reconcile. Fresh admission and each provider effect independently reject disabled/revoked authority even if a stale Schedule fires.

Workflow contracts will contain canonical scoped references, revision/digest/checkpoint receipts and typed outcomes only. Provider cursor values, configuration, credentials and artifact bodies stay in scoped stores and Activities. A schedule principal is the canonical product schedule ID, independent of its creator's Stytch login session; SQL must check current schedule/connector and exact tenant. Manual runs must already have product admission. Periodic runs enter the same product admission boundary with exact scheduled due time, never actual worker start time.

Evidence planned for P4A: one RED group and the same GREEN group for our identity, desired-state reconciliation, stale enable/disable, duplicate delivery, config-change/timeout and workflow branching contracts. SDK-boundary doubles and Temporal's workflow test environment will be labelled as such. They cannot establish actual SQL permission, provider execution, inventory deduplication, cursor persistence or real Temporal service registration.

## Work still required

- P4B: additive scoped discovery SQL authority, CLI route and independent catalog pins; desired-state change delivery and cross-instance serialization; current connector/service-principal checks; manual/periodic overlap and exact occurrence IDs; actual collectors/checkpoint/inventory adapters; full shipped constructor and local Temporal sync proof. Include two tenants, repeated pages, cursor resume, disable/revoke and real scoped writes. Preserve streaming/projection readiness and helpers.
- P4C remains required for real scheduled existing-test admission and shared per-definition capacity across owners. Route manual, schedule, finding/event, webhook, attack-path and approved-action triggers through common admission with their original budgets and authority. Do not revive old 55 readiness or 63/64.
- P4D owns remaining-family execution and settlement: policy deployment, standalone and linked tests/reconciliation, Attack Lab Fargate control/reconciliation, audit/compliance/Security Agent exports and TTL cleanup, legacy action execution, and operator recovery including failed cleanup with unavailable/expired Temporal history. Resolve actual table-trigger/RLS/readiness boundaries and carry every unfinished family through P8/P9.

Live Stytch, provider, cloud deployment, operations/backup and P8/P9/P10 acceptance gates stay open. P3C's accepted manual `run_test` path is one representative path, not every-family proof.

## P4A, what changed

services/platform/orchestration/schedules.go implements DiscoveryScheduleReconciler against the real SDK ScheduleClient Create/GetHandle/Update interfaces. Its production-intended source contract has no default implementation. It refuses missing callbacks, mismatched source scope, invalid cadence, foreign Schedule action identity and older desired revisions. A change event supplies only canonical IDs. Inside required serialization, the source supplies current configuration; delayed enable events can't supply old enabled state to this API.

Schedule identity is discovery-schedule/v1/{organization}/{workspace}/{environment}/{schedule}/{integration}. Connector display names never appear. The action uses this ID plus /occurrence, and Temporal attaches its nominal occurrence timestamp. DiscoveryScheduledWorkflow verifies TemporalScheduledById against that exact Schedule and reads TemporalScheduledStartTime, then sends nominal time and recorded revision to AdmitDiscoveryScheduled. This timestamp is evidence requiring SQL verification, not authorization. Neither actual worker start time nor a random claim token replaces the due occurrence.

The Activity must reuse retained scheduledRequest identity derivation: canonical scope, schedule ID, integration ID and exact due timestamp for scheduled_sync, scheduled_job, scheduled_outbox and request digest. P4A does not duplicate or change that algorithm. P4B must prove those product IDs through real admission. The resulting admitted DiscoveryStart carries scoped run ID, integration ID and input digest. DiscoveryWorkflowID binds that admitted reference; manual start delivery and reject-duplicate policy still need composition in P4B.

No collector implementation is registered by P4A. DiscoveryProduct specifies four real operations for P4B:

| Boundary | Required product behavior |
| --- | --- |
| AdmitDiscoveryScheduled | Current exact tenant/schedule/connector authority; service principal is schedule ID, never creator session. Validate due/revision, derive stable product IDs and atomically admit with durable start delivery. |
| CollectDiscoveryPage | DiscoveryPageCommand contains admitted start plus expected checkpoint version/digest, never cursor/body. Treat the checkpoint as an untrusted precondition: resolve the scoped persisted page receipt, replay the same result on Activity retry, refuse mismatch before fresh provider I/O. A successful next-page transition uses the new checkpoint. Reload provider/credential/cursor/manifest inside the Activity and recheck current authority. |
| ApplyDiscoverySnapshot | Require verified complete collection. Use existing scoped inventory writers, generation fences and repeated-page deduplication; return immutable inventory receipt digest. |
| FinishDiscovery | Validate and persist typed outcome and matching receipt; enforce idempotency and prevent cancellation overwriting an already complete or unknown result. |

DiscoveryWorkflow continues partial collection only after a strictly advancing checkpoint and valid digest. It applies inventory only after complete, and returns succeeded only after valid apply receipt plus successful product finish. Denied, revoked, malformed, cancelled, outcome_unknown and terminal results remain separate. Outcome_unknown never automatically resends collection. Explicit retryable outcomes use Temporal timers (30 seconds when product supplies no delay, bounded to 3,600 seconds); Activity retries have five attempts and bounded timeouts.

After 256 steps the workflow uses Continue-As-New, carrying checkpoint version/digest and the original deadline. It strips the continuation field from admitted start and passes only the expected checkpoint version/digest as a page precondition; actual cursor and generation are reloaded from product SQL. This is a history bound, not a page-count inventory limit. The 24-hour execution deadline does not reset on continuation. Deadline/retry exhaustion leaves product state incomplete and requires P4D recovery. Cancellation attempts typed product finish using a disconnected context bounded to one minute and three attempts; failed finish remains unresolved. P4B must prove cursor/generation persistence across the real process/Temporal boundary.

## Why these schedule choices

The explicit policy is ALLOW_ALL. Existing schedulerProcessor.process advances after sync admission, without waiting for the previous collection to finish. Distinct manual/periodic admissions can coexist; zasp_execution_job_input in applied13 reserves a generation and rejects another active collection for that scoped integration/source. Temporal Schedule SKIP would suppress periodic admissions whenever a prior workflow stays open and would not serialize separate manual starts anyway. P4B must carry that narrow provider serialization into non-lease product operations; this component stage does not claim concurrent providers are safe.

Catch-up is explicitly 10 seconds, the service's minimum window, with no backfill, immediate trigger, jitter, or pause-on-failure. Cadence is anchored to product time using interval offset, including subsecond precision. Disable maps to paused desired state. Periodic failure doesn't permanently disable a configured connector.

This choice intentionally skips old missed cadences after an outage. The old scheduler admitted one overdue occurrence and then skipped elapsed cadences arithmetically; the replacement avoids a scan backlog and resumes at the next eligible cadence. Freshness/last-good inventory must remain visible during missed scans. Original cadence/freshness requirements remain, but exact outage behavior differs and needs acceptance in P4B/P8. Ten seconds is explicit policy, not the SDK's one-year default. See the [Temporal Schedule API policy](https://pkg.go.dev/go.temporal.io/api/schedule/v1#SchedulePolicies) and [official Go Schedule documentation](https://github.com/temporalio/documentation/blob/main/docs/develop/go/workflows/schedules.mdx).

The SDK's Update request has no conflict token. Revision checks help reject an observed newer action; they are not fencing. A configuration write during reconciliation requires its own durable redelivery. Even a scoped lock cannot prevent a timed-out RPC applying late. ErrScheduleOutcomeUnknown keeps that result separate from acknowledged writes; P4B must retain pending/unknown reconciliation state and reconcile again, including late completion after a prior repair. Production admission/effect checks must reject disabled/revoked current authority throughout that interval. A nil Reconcile result is only acknowledgement of one write.

## Every family still has a caller

The P0 retirement TSV now has explicit P4 stage rows, without deleting its original symbol-level inventory. These are migration obligations, not availability promotions.

| Family and actual caller | Intended route and concrete missing work |
| --- | --- |
| Discovery: production_runtime.go scheduler/discovery cases, schedulerProcessor, discoveryProcessor, DiscoveryExecutionRepository | P4B registered workflows plus extracted collection/checkpoint/inventory Activities. Existing claim/input/heartbeat/finish interfaces are lease-coupled. Need additive authority, CLI/independent pins, desired-state source/delivery, current connector/service-principal checks, real factory/credential/store composition and full-entrypoint sync. |
| Security Agent triggers: PostgresRepository.RunSecurityAgent; securityAgentProcessor.RunOnce calls ScheduleSecurityAgentTriggers; finding/attack-path planning; public ordered decisions | P4C common scoped admission and commands for manual, schedule, finding/event, webhook, attack-path and approved action. Real scheduled existing-test capacity across owners is missing, and old public55 readiness must not be revived. Preserve trigger provenance, budgets, one-way owner activation and existing P3 routes. Response-webhook acceptance/dispatch/settlement remains a separate specialized action path that also needs migration. |
| Separate policy deployment: workerModePolicyDeployment, composePolicyDeploymentWorkerRuntime, policyDeploymentProcessor.apply | P4D Temporal deployment/cleanup plus signed envelope executor and verified gateway receipt. The old lease processor is temporary pending replacement, not a required final engine. Keep M6-18 sequence/device/signature fences, current signing authority, readback and temporary-control expiry. Storage success is not gateway enforcement. |
| Red-team/tests: workerModeRedTeam, composeRedTeamWorkerRuntime, workerModeTestReconciler, composeExistingTestRuntime, existingTestClient.ReconcileOne, red-team outbox | Retain SQS/Promptfoo/HTTPS provider transport. P4D replaces custom lifecycle/reconciliation with Activities and proves standalone and linked terminal settlement, immutable artifacts, cancellation and no uncertain resend. Installed71 classifier still chooses legacy_single_test or retained_ordered; P3C proves only its representative linked manual path. |
| Attack Lab: controller/reconciler/outbox cases, attackLabProcessor, composeAttackLabLinkRuntime | Retain Fargate executor and scoped proxy. P4D needs installed startup, task lifecycle, canary evidence, parent settlement and verified cancellation/TTL cleanup. No long-lived custom lease engine is accepted as the final orchestration. |
| Audit exports: audit-export/audit-export-outbox, auditExportExecutor.Execute; Security Agent reconcileExportSettlements | P4D replaces capture/chunk/manifest/settlement ordering, keeping frozen scope, redaction, artifact readback and download authority. Actual audit_export_jobs INSERT/UPDATE calls a policy trigger that still reaches public55. Constructor-only tests cannot resolve it. Need trigger/RLS/current-principal and artifact-to-parent terminal proof on installed schema. |
| Compliance export and TTL: compliance-export/compliance-cleanup, complianceExportProcessor.RunOnce/process | P4D workflow for capture/upload and deadline cleanup. Retain S3 deletion/retention executors and scoped artifact state. Prove failed upload, revocation, expiry and cleanup receipts; current claim/heartbeat loop is unfinished migration. |
| Legacy single actions: security-agent/security-agent-action, securityAgentProcessor, securityAgentActionProcessor, installed pricing adapter | P4D must route each action and verify its downstream terminal receipt. NewSecurityAgentActionRepository still probes historical22/23/24/27; export constructor also requires recovery readiness. Keep current price binding, unknown-price no-send, revocation, one-shot dispatch and actual usage settlement. |
| Recovery: recovery/recovery-outbox, recoveryBackupProcessor, recoveryOutboxProcessor, agentsecctl recovery client | Retain restricted backup/restore executors, SQS delivery and audited CLI. P4D must add reviewed recovery for failed cleanup and unavailable/expired Temporal history. Product pending/unknown evidence must remain usable; command acknowledgement is not cleanup. No reset or login bypass. |
| Streaming and projections: runtime coordinator/archive/index/correlation/projection/complete; risk/search/graph modes | Outside this durable-workflow cutover. Retain event queues, ACK-last receipts, backpressure, stores and shared readiness/helpers. No filename-prefix deletion. |

Installed70/71 temporary roots, copied claims/reconciliation, role grants, routing classifiers, pricing wrapper and selectors must retire together through a verified additive P9 authority once replacement assertions pass. Historical SQL stays applied and unchanged. None of P4A's source changes touches those constructors or selects a permissive fallback.

## Required transport, mapped to the original tasks

outboxQueueAuthority still selects six specialized queues: agentsec-discovery-jobs, agentsec-runtime-events, agentsec-red-team-tests, agentsec-attack-lab-jobs, agentsec-recovery-backup-jobs, agentsec-recovery-restore-jobs. Their consumers are the production discovery, runtime coordinator, red-team, Attack Lab controller and backup/restore processors. Audit export has its own outbox/executor lane. These coexist with the original three queuedefinition contracts (agentsec-background, agentsec-runtime-events, agentsec-tests) and their DLQs; specialized names don't replace the original requirements.

| Original task | Retained contract and migration consequence |
| --- | --- |
| M0-06 | LocalStack batched message roundtrip and redrive/DLQ evidence remains required. SDK Schedule unit tests cannot replace it. |
| M1-13 | JobQueue/SQS batch interface and bounded publish/consume stay for real transport. |
| M1-33 | All three original queue/schema/retention definitions and DLQs stay; P9 cannot delete them because a workflow moved. |
| M1-41 | Organization/workspace/environment envelopes must reject absent/mismatched scope before side effects in every remaining consumer. |
| M1A-04 | Staging original three queues/DLQs, outputs and redrive policies remain deployment requirements. |
| M3-43 | Runtime consume -> S3 archive -> OpenSearch -> correlation and ACK-last ordering stays outside replacement. |
| M3-52d | Runtime queue/index E2E still proves exact archive/index references, replay safety and empty DLQ. |
| M5-13 | Retain test SQS delivery and Promptfoo adapter; duplicate delivery must yield one attempt/invocation even after Temporal owns lifecycle. |
| M7A-50 | Scoped security_agent.run admission/commands and duplicate-safe delivery are required; retain original replay/no-second-run assertion on final delivery architecture. The existing DB queue is temporary custom orchestration, not a reason to waive the SQS contract. |
| M8-03 | Queue identity, encryption, visibility, bounded redrive and retention hardening remain. |
| M8-17c | Actual queues/DLQs and producer/consumer permission preflight remains before deployment. |
| M8-34 | Backlog age, bounded process memory and observable throttling/saturation still require deployed evidence. |
| M8-59a3 | Cross-Organization S3/export/queue-envelope denial cases remain in the release isolation suite. |

P4B/D must decide each old job consumer's remaining transport role when moving its product ordering. No queue, DLQ, event stream, streaming worker, readiness check or shared helper was removed here.

## Tests, with their limits

All Go commands ran in services/platform using local Go1.25.6 darwin/arm64, GOTOOLCHAIN=auto and empty GOFLAGS. Default vet stayed enabled. No -vet=off, database provisioning, shared reset, Temporal service start, or external provider credentials were used. The final Go1.25.13/advisory gate is not established by this packet.

The grouped command for the application contract cases was:

    go test ./orchestration -run '^TestDiscovery' -count=1

The final group has 11 top-level tests. SDK transport doubles inspect the actual requests emitted by our adapter. Workflow tests execute our real workflow branches in the Temporal SDK test environment with explicitly controlled product Activity responses. This is component evidence, not vendor conformance or end-to-end product success.

| Log in the packet directory | Observed result and reason |
| --- | --- |
| p4-red.log | Expected missing-contract compile RED: undefined DiscoveryScheduleDesired, DiscoveryScheduleRef, NewDiscoveryScheduleReconciler and workflow types, before production implementation. This is not a runtime assertion failure. |
| p4-green-development.log | PASS0.947s for initial identity/reconciliation/workflow group. |
| p4-boundary-red.log | Runtime RED: subsecond anchor was refused; cancellation finished with empty product outcome instead of cancelled. |
| p4-boundary-green.log | PASS0.797s after preserving fractional interval offset and bounded disconnected cancellation finish. |
| p4-continuation-red.log | Runtime RED: page256 returned progress-limit failure, not Continue-As-New. Narrow command used -run '^TestDiscoveryWorkflowLargeInventory'. |
| p4-continuation-green.log | Failed fixture setup after continuation worked: test environment rejected map input for a typed DiscoveryStart. No success claim from this run. |
| p4-continuation-green2.log | PASS0.618s after decoding the captured continuation payload into DiscoveryStart; whole discovery group. |
| p4-page-command-red.log | Runtime RED: first page command had no expected_checkpoint_version, so the assertion saw nil instead of0. Narrow command used -run '^TestDiscoveryWorkflowBindsPage'. |
| p4-page-command-green.log | PASS0.764s for whole discovery group after explicit expected checkpoint version/digest commands. |
| p4-final-unit.log | PASS0.823s: go test ./orchestration -count=1, complete package suite after final source edits. |
| p4-final-race.log | PASS1.861s: go test -race ./orchestration -count=1, complete package suite after final source edits. |

The retained scheduler/repository regression command was:

    go test ./agentsec-worker ./apiserver -run '^Test(ScheduledOccurrenceIdentitySurvivesExpiredLeaseReclaim|SchedulerProcessor.*|NextScheduledRun.*|DiscoveryExecutionRepository.*|DiscoveryExecutionConstructors.*|ProductionDiscoveryScheduleReplayRepositoryRequiresExactRelease60)$' -count=1

p4-retained-regression.log passes worker1.042s/API1.053s. It covers retained occurrence identity/reclaim, admission-before-advance, concurrent claimed leases, arithmetic backlog skipping, strict collection input/checkpoint/repository validation and readiness behavior. It compiles the actual adjacent packages but does not run their full suites or PostgreSQL process tests. The final repeat after the page-command interface edit passes worker1.256s/API1.072s in p4-final-retained-regression.log. Early full package/race results remain in p4-package-green.log and p4-race-green.log; final-unit/final-race supersede them.

The new cases cover tenant-separated schedule/run identity, disabling and duplicate change delivery, stale/foreign configuration refusal, bounded SDK requests, timeout-as-unknown, config change followed by durable-redelivery simulation, fractional anchors, nominal due-time admission, rejected cross-tenant admission, missing Schedule evidence, advancing and repeated checkpoint behavior, typed terminal distinctions, complete-only apply/receipt/finish, cancelled workflow finish, continuation at256 and checkpoint-bound next-page commands.

What these tests do not prove: actual cross-instance advisory locking; durable desired-change delivery; late RPC healing; creator-session-independent SQL authority; current connector revocation before real I/O; shared manual/periodic provider serialization; inventory deduplication; provider cursor/manifest persistence; real Temporal registration; actual SQS; real Stytch/provider deployment. Those remain P4B/P7/P8/P10 gates. No test fixture is a production authorization implementation.

## Self-review and the freeze

I found and corrected three contract defects with failure-first evidence: dropped subsecond cadence anchors, missing typed cancellation finish, and page commands without a checkpoint precondition. The controller also caught the page-count failure boundary; it now uses Continue-As-New, with a real assertion for resumed workflow completion. The first continuation GREEN attempt exposed a test harness argument-type error, which I corrected without changing production behavior.

Changed paths are the three new orchestration files (schedules.go, discovery_workflow.go, discovery_workflow_test.go), this report, and the P0 retirement TSV. Existing scheduler_runtime, discovery_composition, discovery_queue, discovery_cloud, discovery_execution_repository, schedule API composition and production_runtime are deliberately unchanged in P4A; their P4B work remains required. No commits or pushes.

The pre-edit overlay was copied before source edits into p4-baseline, with p4-baseline.json recording 1,943 paths and HEAD. p4-capture.mjs produces p4-frozen-source.json, the overlay-relative p4-scoped.diff and p4-hashes.json. The final capture rejects any source change after its freeze, checks scoped whitespace and checks all202 captured SQL files are byte-identical. The hash manifest records exact before/after file hashes, baseline/freeze/diff hashes and all p4 test-log hashes. Packet files are under .superpowers/sdd/2026-09-22-temporal-openfga-execution-plan; these evidence artifacts are separate from application source.

P4A is ready for independent component review only. P4B must implement the stated authority and page-receipt contracts through the actual shipped constructor and a real local Temporal sync; P4C/D and every listed family remain open.


## P4A fix1: review findings retained verbatim

The original report above records the pre-review implementation and evidence. Fix1 supersedes its ten-second lost-scan policy, inline scheduled collection and deadline/settlement behavior. No original evidence file was overwritten. Both Important findings below are the requirements for this round.

1. **Enforce the original deadline before fresh application work.** [discovery_workflow.go:167](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/orchestration/discovery_workflow.go:167) checks time before collection, but the `complete` branch starts `ApplyDiscoverySnapshot` at line 199 and successful `FinishDiscovery` at line 210 without another deadline check. A resumed/manual run with one second left can receive a complete page two seconds later, apply inventory and report success after its deadline. The check at line 215 is bypassed by that return. The retryable branch also sleeps its entire delay at line 190, even when the original deadline is sooner. The fixed 30-minute Activity schedule-to-close allowance at line 99 is unrelated to the remaining execution budget. This contradicts the reported fixed execution deadline and incomplete-on-exhaustion behavior ([report:44](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/docs/internal/2026-09-22-temporal-openfga-p4-report.md:44)). The Schedule's 24-hour execution timeout at [schedules.go:155](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/orchestration/schedules.go:155) covers scheduled starts, but doesn't establish the same boundary for every direct/manual call and starts before scheduled admission. Bound waits and Activity execution to the remaining original budget, refuse fresh inventory application after expiry, and define how already-committed/uncertain work is settled without inventing success or cancellation. Add a focused near-deadline continuation test with late complete/retryable responses; the existing continuation test at [discovery_workflow_test.go:234](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/orchestration/discovery_workflow_test.go:234) checks deadline transport, not enforcement.

2. **Resolve the missed-run behavior change before accepting the Schedule policy.** [schedules.go:161](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/orchestration/schedules.go:161) hardcodes 10-second catch-up and its adjacent comment intentionally skips older occurrences. Existing [scheduler_runtime.go:84](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/agentsec-worker/scheduler_runtime.go:84) admits the outstanding due occurrence first; lines 93-120 then skip elapsed cadences. Those behaviors differ. If the scheduling service recovers an hour after a daily scan was due, the old path admits one overdue scan, while this policy can leave inventory waiting until the next day. The report acknowledges the change and defers acceptance to P4B/P8 ([report:52](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/docs/internal/2026-09-22-temporal-openfga-p4-report.md:52)); the current brief requires P4A's explicit policy to follow existing product requirements ([brief:48](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4-brief.md:48)). The earlier product plan includes missed-run behavior ([auto-discovery plan:209](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/docs/superpowers/plans/2026-08-19-production-auto-discovery-and-response.md:209)); v1.5 M3-21 requires stale-state visibility and retention, but does not itself choose a catch-up policy ([v1.5 plan:1870](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md:1870)). This is an unresolved product decision, not a claim that v1.5 explicitly mandates one-overdue behavior. Preserve that behavior or obtain an explicit accepted change with its freshness consequences and application-level coverage. The request assertion at [discovery_workflow_test.go:36](/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917/services/platform/orchestration/discovery_workflow_test.go:36) confirms the constant, not its suitability. ALLOW_ALL itself has a reasonable admission-level basis in the existing advance-after-admission flow; actual provider serialization still belongs to P4B.

## P4A fix1: implementation and boundaries

Both Important findings are addressed for component re-review. The controller accepted the integration policy recorded in progress.md: preserve one outstanding overdue occurrence, then skip elapsed cadence slots to the next future due. No automatic discovery availability or whole-P4 completion is claimed.

The pre-fix capture copied 1,946 paths before fix edits and recorded HEAD in p4a-fix1-baseline.json. It includes the existing dirty platform overlay, report and inventory. Original p4 evidence remains untouched. This round changes only schedules.go, discovery_workflow.go, discovery_workflow_test.go, this report and the retirement TSV.

For missed runs, CatchupWindow is one configured cadence. Temporal ticks are wakeups, not authoritative occurrence IDs. PlanDiscoveryDue takes the persisted oldest DueAt, authoritative current time and cadence. It returns that oldest occurrence plus the first future due, or no admission when not due. The P4B SQL boundary must lock the exact tenant/schedule, reread current revision/enabled/connector authority, use DB time and atomically commit occurrence receipt, next due and durable start delivery. Duplicate or late ticks return explicit not_due.

ReconcileDiscoveryDue is now part of DiscoveryScheduleSource. Desired-state and startup reconciliation call the same coalescing admission after an acknowledged Schedule write, including a recreated Schedule. A failed repair callback propagates failure so the durable desired change must remain pending. Unknown or late Schedule RPCs still require durable retry and repair, not an acknowledged complete state. The original scoped-session, configuration-writer redelivery and no-SDK-fencing limits remain.

Both tick and reconciliation admission use one durable start-delivery route. DiscoveryScheduledWorkflow validates the scoped admitted result or explicit not_due and exits without collection. The shared outbox must start the stable DiscoveryWorkflowID duplicate-safely. Admission is not a completed sync. P4B must prove atomic receipt/outbox persistence, restart and duplicate recovery, and eventual collection through the actual shipped entrypoint. This removes the risk of inline scheduled collection running beside the outbox-started collection workflow.

For the deadline, each fresh collection/application Activity and retry wait is bounded to the remaining original budget. The continuation carries the same absolute deadline. Workflow code checks it again after a page result and before apply. DiscoveryPageCommand and DiscoveryApplyCommand carry that deadline as an untrusted precondition; the product implementation must compare it with the persisted original run budget before fresh I/O. A workflow timeout alone cannot fence a late provider response or grant permission to extend the budget.

Apply has one attempt. Errors or invalid receipts go to evidence reconciliation, never an automatic apply resend. Deadline exhaustion and late apply receipts also use ReconcileDiscoveryOutcome. That separate, bounded path may read and settle durable evidence only, with a 20-second attempt limit, one-minute total allowance and at most three attempts. It cannot collect, apply inventory or resend a provider effect. It returns incomplete when nothing was applied, outcome_unknown when application is unresolved, or succeeded only with a verified committed inventory receipt. Cancellation uses the same evidence boundary and cannot replace uncertain or already committed state with invented cancellation. Reconciliation failure leaves unresolved product state for recovery rather than pretending settlement completed.

P4B must implement these contracts against persisted deadlines, page receipts, cursors/generations, current authority and committed inventory. The collection workflow starter must allow the fixed fresh-work deadline plus bounded evidence-only settlement, independently of the Schedule's admission-wakeup timeout. P4D still owns recovery when workflow history or normal settlement is unavailable. No SQL adapter, outbox, production registration, provider executor or new scheduler loop was added in this round.

## P4A fix1: grouped tests and exact evidence

All commands below ran in services/platform with the default vet behavior. Fixtures execute our application policy and workflow branches; they do not prove Temporal service behavior, SQL atomicity, real restart recovery or provider execution.

The focused deadline command was:

    go test ./orchestration -run '^TestDiscoveryOriginalDeadline' -count=1

The application contract group was:

    go test ./orchestration -run '^TestDiscovery' -count=1

The single-delivery RED command was:

    go test ./orchestration -run '^TestDiscoveryScheduledWorkflowUsesExactOccurrenceAndAdmission' -count=1

| Log under the plan packet | Observed result and scope |
| --- | --- |
| p4a-fix1-group-red.log | Missing PlanDiscoveryDue compile RED before implementation. This establishes the absent interface, not runtime policy behavior. |
| p4a-fix1-deadline-red.log | FAIL0.784s from test harness registration ordering. Preserved as a failed fixture attempt, not behavioral evidence. |
| p4a-fix1-deadline-red2.log | Corrected behavioral RED, FAIL0.830s, against unchanged workflow behavior. Late complete/retryable responses lacked reconciliation, retry waits exceeded the budget, and uncertain apply retried without evidence settlement. |
| p4a-fix1-group-green.log | PASS0.821s after initial deadline and coalescing changes, before the single-delivery correction. |
| p4a-fix1-single-delivery-red.log | Behavioral RED, FAIL0.820s: admitted scheduled execution collected once when zero collection was required. |
| p4a-fix1-group-green2.log | PASS0.820s for the whole discovery group after the single-delivery change and late-apply receipt case. |
| p4a-fix1-final-unit.log | PASS0.869s: go test ./orchestration -count=1, full package after final source edits. |
| p4a-fix1-final-race.log | PASS1.866s: go test -race ./orchestration -count=1, full package after final source edits. |
| p4a-fix1-final-retained.log | PASS worker1.238s/API1.108s for the retained selector below; adjacent package compilation and selected existing regressions, not full suites or database process tests. |

The final discovery group contains 15 top-level tests. The deadline group has six controlled cases: late_complete, late_retryable, retry_wait, apply_unknown, apply_committed and late_apply_receipt. They assert a continued run's original one-second budget, emitted fresh Activity timeout limits, zero fresh apply after late collection, bounded retry waiting, one apply attempt on uncertainty, and evidence-backed incomplete/unknown/committed outcomes. These are application assertions, not a claim that mocked Activity timing tests the Temporal server.

The outage group asserts the daily scan one hour late is admitted, multiple missed cadences coalesce to the oldest outstanding occurrence, the next due moves to the first future cadence, duplicate reconciliation does not re-admit, recreation preserves the product due state and a failed first repair remains retryable. The source fixture calls our real arithmetic helper but models persistence in memory. The admitted and not_due scheduled cases assert zero collection in the wakeup workflow. Existing scope, stale revision, disabled state, unknown RPC, subsecond anchor, checkpoint and continuation tests remain in the group.

The retained command was:

    go test ./agentsec-worker ./apiserver -run '^Test(ScheduledOccurrenceIdentitySurvivesExpiredLeaseReclaim|SchedulerProcessor.*|NextScheduledRun.*|DiscoveryExecutionRepository.*|DiscoveryExecutionConstructors.*|ProductionDiscoveryScheduleReplayRepositoryRequiresExactRelease60)$' -count=1

It covers the existing scheduler's occurrence identity/reclaim, admission-before-advance and arithmetic cadence skipping, plus discovery repository validation and readiness. It does not establish the new SQL admission or start-delivery path.

## P4A fix1: frozen handoff and remaining concerns

The fix-only evidence is under .superpowers/sdd/2026-09-22-temporal-openfga-execution-plan:

- p4a-fix1-baseline.json and p4a-fix1-baseline contain the pre-fix hashes and copied overlay.
- p4a-fix1-frozen-source.json records the five frozen paths and exact before/after hashes.
- p4a-fix1-scoped.diff is relative to that copied overlay, not HEAD.
- p4a-fix1-hashes.json records the baseline, freeze, diff and every fix-log hash, plus the historical SQL unchanged check.
- p4a-fix1-capture.mjs checks that final files still match the freeze, rejects SQL changes and checks scoped whitespace.

Self-review found no further source change needed for the two Important findings. The policy and single-delivery boundaries are now explicit, but their product persistence and live integration remain mandatory P4B work. In-memory coalescing and successful admission are not full sync evidence. Unknown late RPC/provider effects remain repair obligations, not atomically fenced operations. P4C shared admission/capacity, P4D downstream families/recovery, all728 scope and the original live/retirement gates remain open. No original p4 packet was replaced, no historical SQL was edited, and no commit, push, shared provisioning or production promotion occurred.

This is a fix1 component-review handoff only. The original reviewer must independently re-review the frozen fix before controller acceptance.
