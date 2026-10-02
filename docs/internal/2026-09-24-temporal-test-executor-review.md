# Spec compliance: Issues found

The bounded single-test executor needs fixes before acceptance. Required cleanup can end without completion evidence after transient failures, and approved-decision replay loses its immutable receipt once the parent finishes. Code quality: Needs fixes.

This is a task-scoped review of the frozen overlay, not whole-branch acceptance or completion of later P4 families, OpenFGA, P8, or P9. Paths below are relative to `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.

## Strengths

- Production composition registers separate single-test execution and cleanup workflows and their Activities; ordered69 remains separate. See `services/platform/agentsec-worker/security_agent_temporal_runtime.go:56` and `services/platform/orchestration/single_test_workflow.go:124`.
- Ownership transfer locks the parent and refuses prepared, attempted, leased, budgeted, or child-bearing work. Automatic takeover checks a scoped service grant rather than treating the scheduler label or human creator as authority. See `services/platform/migrations/sql/0074_production_temporal_test_executor.up.sql:241`, especially lines253-284. The remaining retained owners are explicitly inventoried, not represented as migrated.
- Effect identity is fixed to generation1 and dispatch transitions the reserved effect to started; a retry does not manufacture a fresh send permission. Child settlement is separately validated against parent proof. See `services/platform/migrations/sql/0074_production_temporal_test_executor.effects.sql:94` and `services/platform/migrations/sql/0074_production_temporal_test_executor.settlement.sql:90`.
- The start relay separates Temporal RPC from SQL acknowledgement and validates the accepted workflow identity. See `services/platform/agentsec-worker/security_agent_temporal_single_start.go:23`. The control and transport additions follow the same durable-receipt boundary rather than treating delivery as verified execution.

## Issues

### Critical

None found.

### Important

1. Cleanup exits on exhausted transient failures without completion evidence.

   Location: `services/platform/orchestration/single_test_workflow.go:47` and `:55`.

   SingleCleanup has a bounded retry policy of12 attempts. Once a database/network failure exhausts it, the resulting ProductUnavailable or timeout is not CleanupPending, so the loop returns the error and closes the workflow. The same path exists in the cleanup-only continuation. A later child receipt or wake cannot resume a closed workflow. SQL conservatively retains the obligation and capacity, but Temporal no longer owns its progression. This violates the requirement to keep required cleanup pending until evidence exists; it is not merely a shared P3 follow-up.

   The concrete failure path is `security_agent_temporal_single_product.go:107` reading compensation state, then `orchestration/activities.go:164` classifying unavailable operations as retryable. The existing `TestSingleTestPendingCleanupOutlivesRetryExhaustion` at `orchestration/single_test_workflow_test.go:49` returns13 nonretryable CleanupPending responses. It exercises repeated pending observations, not exhaustion of transient Activity retries.

   Keep retryable/unavailable/timeout cleanup outcomes in durable cleanup-only waiting or continuation after each bounded Activity retry batch. Preserve the original run, deadline, effect identity, and outcome; do not reenter execution. Distinguish permanent invalid/authority errors rather than blindly retrying every error. Add one application-level test that exhausts a transient cleanup batch, recovers the dependency, and supplies proof on the same workflow chain, with no new provider call.

2. Approved receipt replay is rejected after the run becomes terminal.

   Location: `services/platform/migrations/sql/0074_production_temporal_test_executor.approval.sql:23` and `:28`.

   The wrapper permits a terminal replay only for rejected/cancelled decisions. An approved decision followed by successful remediated settlement, or terminal needs_human settlement, fails the current-run-state condition with40001 before reaching the immutable receipt lookup at line39. A client whose successful approval response was lost therefore receives a conflict when retrying its original key after execution finishes, despite an intact, unexpired decision receipt. The approval/plan/budget expiry checks also precede receipt replay and can reject an otherwise valid historical response.

   The unchanged receipt contract returns the stored response before live approval state checks: `services/platform/migrations/sql/0018_security_agent_execution.up.sql:816`. The existing test at `services/platform/apiserver/security_agent_temporal_test_approval_postgres_test.go:143` replays immediately, before terminal execution; it does not cover this regression.

   Separate exact immutable receipt replay from new-decision mutation prerequisites. Preserve current API/actor authority, fresh-auth and receipt identity/intent/expiry checks, and do not weaken effect-time authorization. Add a typed API test that approves, completes parent settlement, then retries the same key and receives the original replayed response with no extra audit or control intent. Also cover receipt replay after the live plan/approval deadline while the request receipt remains valid, according to the retained replay contract.

### Minor

3. Normal cleanup waiting emits repeated ERROR logs.

   Location: `services/platform/orchestration/activities.go:146`.

   CleanupPending is expected workflow state but is returned as an Activity error for every observation. The real continuation evidence contains repeated `ERROR Activity error ... CleanupPending` entries, starting at `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-test-executor-final-live-can.log:5`. This makes passing test output noisy and produces production error-level noise during ordinary pending cleanup. Prefer a typed pending result, reserving errors for unavailable or failed operations. This is an application result-model change, not a request to test Temporal logging internals.

## Focused checks and evidence limits

- Read the complete frozen scoped diff sequentially, task/review briefs, referenced binding briefs, evidence map, implementer report, and task-reviewer template. Verified the supplied manifest and diff SHA256 values. A read-only hash check of all64 manifest paths returned zero mismatches. No test suite was rerun, no agents were dispatched, and no source, index, or branch state was changed.
- Cleanup risk: traced the new cleanup loop, product compensation reads, existing Activity error classifier, and pending fixture. The source establishes finding1 without a duplicate suite. The requested recovery test is missing evidence, not a claim that an existing test failed.
- Replay risk: checked the original approval receipt function and retained existing-test wrapper to establish the preexisting immutable-response contract. Revisited the new approval condition and its immediate replay fixture to locate the regression precisely.
- Automatic authority risk: traced inherited73 scheduling/admission and the original source/binding predicates, then74 takeover authorization. The source separates service authority from human execution membership. The live fixture schedules first and deactivates the creator afterward (`services/platform/apiserver/security_agent_temporal_test_live_fixture_test.go:260` and `:269`), so it proves post-admission execution independence, not admission with an already inactive creator. The shared scheduler still admits under its worker/source contract;74 service authority is enforced at takeover and subsequent execution boundaries. Do not describe that fixture as proving earlier service-authorized admission.
- Shutdown risk: checked borrowed-Activity tracking, runtime Close, and the enclosing production Close ordering. Clients are retained when drain times out, and the report's retry-after-join evidence supports that safety property. It does not prove a successful first Close within the configured deadline. See `services/platform/agentsec-worker/security_agent_temporal_runtime.go:76`, `services/platform/agentsec-worker/production_runtime.go:168`, and report lines144-147. First-attempt bounded shutdown remains a deployment gate, not an accepted completion claim.
- Performance risk: metadata construction at `services/platform/migrations/production_temporal_test_executor.go:45` recursively constructs predecessor release metadata. The final group needed501.409s after an earlier600.789s aggregate timeout; the successful live nested case took177.97s against180s. Those are whole-test timings, not individual production-request latency measurements. They do not establish that production query/start/drain budgets are met. Require per-operation readiness/SQL/metadata timing against configured budgets before deployment; do not dismiss the failed run or infer a measured production timeout from aggregate timings.
- Integration scope: the real Temporal/PostgreSQL evidence exercises the required two-tenant production composition, restart after preparation, typed decisions, and pre-IO revocation with controlled external IO. Real AWS/provider/container/OpenFGA operations are not proved. The adapter routing log explicitly skips `TestProductionAdapterOwnedRouting` because its owned fixture is absent; selected routing and live worker evidence must not be relabeled as that skipped end-to-end check.
- Historical migration preservation, exact65/66 compatibility projection, retained callers, and later retirement are distinct obligations. The diff is additive and the controller reports206 preserved historical SQL hashes and six predecessor artifacts. This review independently checked the64 changed-file hashes, not all historical hashes or all161 evidence hashes. No deployment activation or full P9 retirement was verified.

## Assessment

Task quality: Needs fixes. The ownership, effect, and receipt boundaries are carefully scoped, but cleanup progression and approval replay still have concrete failure paths. Fix the two important findings and provide their focused application tests before this task is accepted; keep deployment performance and bounded first-attempt shutdown evidence open.
