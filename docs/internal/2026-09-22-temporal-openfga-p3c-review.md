# P3C review: production startup still needs a fix

## Spec compliance

Issues found. The workflow, Activities, additive69 authority and local API-to-worker receipt path are implemented, but the production entry point still constructs a legacy-only repository before reaching the new worker. That misses the explicit P3C runtime-composition requirement. See Important 1.

I reviewed all 23 source paths in `p3c-scoped.diff`, once in consecutive chunks, against the captured pre-edit overlay at unchanged HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. This is the full P3C review, not a review of its final fix. The brief, parent P3 brief, integration rulings, implementation report and final evidence manifest were read. No source, index, database or branch changes; no test reruns.

## Strengths

The workflow has a small, inspectable control loop. `services/platform/orchestration/security_agent_workflow.go:34` observes product state before choosing its next action, and line 64 consumes signals only as wakeups. `services/platform/agentsec-worker/security_agent_temporal_product.go:137` refuses successor execution without the application receipt and satisfied dependency. The SDK ordering, refusal, hint and cleanup-failure tests exercise that loop in `services/platform/orchestration/security_agent_workflow_test.go:15`.

Cancellation has a real compensation path. `services/platform/orchestration/cleanup.go:9` creates a disconnected context with finite retry/time bounds. `services/platform/migrations/sql/0069_production_temporal_workflow.up.sql:103` binds stop authority to the retained start; the stop row and unresolved child stop share one transaction at lines 128-132. The copied stop helpers stay private, with only `stop(jsonb)` granted to compensation at line 156. `services/platform/apiserver/security_agent_temporal_workflow_postgres_test.go:119` checks private-call refusal and transaction rollback when the child cannot be stopped.

Signed cleanup isn't reduced to delivery acceptance. `services/platform/agentsec-worker/security_agent_temporal_product.go:332` consumes the existing source/delivery repository checks, and its completion branch requires `cleaned`. `services/platform/apiserver/security_agent_temporal_cleanup_consumer_postgres_test.go:18` exercises rotated-source, expired-replacement and changed-replacement recovery while preserving original source fields, effect count and prior signed bundles.

The new lifecycle code retains resources if draining fails. `services/platform/agentsec-worker/security_agent_temporal_runtime.go:72` starts worker shutdown, line 73 joins admitted Activities, and line 81 closes clients only after both joins. `services/platform/orchestration/activities.go:41` closes Activity admission under the same mutex as the active count. The two focused race tests cover active compensation and concurrent runtime Close.

Retained commands and history have explicit checks. `services/platform/agentsec-worker/security_agent_temporal_runtime.go:212` validates immutable product identity before acknowledging terminal starts without an engine call; line 222 validates committed decision identity. `services/platform/agentsec-worker/security_agent_temporal_workflow_integration_test.go:270` inspects actual workflow/Activity/signal payloads. The planner's detached recovery at `services/platform/agentsec-worker/security_agent_temporal_planning.go:68` is bounded and restricted to existing evidence, with a cancellation/deactivation fixture that checks one known charge and no admission.

## Issues

### Critical

None found in this scoped review.

### Important 1: the shipped constructor cannot reach the new worker on its required installation

P1, confidence 9/10. `services/platform/agentsec-worker/production_runtime.go:73` adds:

```go
temporalRuntime, err = buildTemporalSecurityAgentRuntime(ctx, config, services.Temporal)
```

But the same function first executes `dependencies, err := composeWorkerRuntime(connectCtx, config, database)` at line 53 and returns on failure. The security-agent branch reaches `composeSecurityAgentWorkerRuntime`, whose line 362 calls `apiserver.NewSecurityAgentWorkerRepository(database)` and rejects a failed constructor. That repository's configuration list at `services/platform/apiserver/security_agent_worker_repository.go:217` contains only public v21-v33 readiness paths; lines 227-232 return `ErrRepositoryConfiguration` if none succeeds.

Those are the deliberately superseded public readiness paths. `services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql:58` explicitly preserves public60 readiness so old binaries cannot use the evolved schema. Its underlying guard at `services/platform/migrations/sql/0060_production_discovery_schedule_replay.up.sql:170` requires `count(*)=60` and no version above60. The installed67/68 lineage required by69 has61 historical rows (`services/platform/migrations/sql/0067_production_temporal_domain.base.sql:35`), and67 forwards the62/65/66 entries, not these old worker entries (`services/platform/migrations/sql/0067_production_temporal_domain.up.sql:27`). P3C doesn't add a compatible legacy worker construction path.

So the old constructor rejects the installation before the Temporal constructor runs. The later `return previousReady(ctx)` at `services/platform/agentsec-worker/production_runtime.go:91` would retain the same readiness dependency even if construction alone were bypassed. This isn't a missing cloud credential or a deferred deployed-provider acceptance item.

The passing fixture doesn't exercise this path: `services/platform/agentsec-worker/security_agent_temporal_workflow_integration_test.go:149` calls `newTemporalSecurityAgentWorker` directly with an assembled product. And `services/platform/agentsec-worker/security_agent_temporal_runtime_test.go:19` passes a nil Temporal client into its incomplete-configuration check, so that test passes before any configured authority is considered. Neither proves the shipped entry point can register the worker on69.

Provide the exact installed-authority composition/legacy coexistence path at this boundary, preserving old principal checks and ownership fences. Don't relax historical public readiness. Add one focused installed69 test through the real worker entry point with controlled external dependencies; prove startup/readiness, task consumption and shutdown, including the supported manual path. Correct the report's completed-runtime claim until that passes.

### Minor: passing evidence still contains unasserted warning/error noise

P3, confidence 10/10. `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p3c-final-postgres.log:245` contains `WARN RecordActivityHeartbeat with error ... Error canceled`, followed by an Activity error; lines 277-278 repeat them because child output is logged again. The final unit log has expected cancellation/refusal ERROR records at lines 12, 44 and 66.

These accompany deliberate negative cases, not failed test results. Still, the task-reviewer contract requires reporting warning/noisy test output. Capture and assert expected diagnostic events in these fixtures, keep unexpected warnings/errors visible, and avoid printing the same child output twice. Don't suppress all SDK errors globally.

## Checks and limits

Named risk: a new stop could miss the accepted effect/send lock order. I inspected `services/platform/migrations/sql/0068_production_temporal_executor.up.sql:249`: `status` takes the schema fence, organization budget lock, budget-row lock and run-row lock before returning.69 `inspect` calls it before stop mutation, so those transaction locks carry through the stop and child operation. `services/platform/migrations/sql/0068_production_temporal_executor.settlement.sql:161` also confirms which reserved-stop predicate the private copy changes. The existing stop/send and child-rollback tests provide direct product evidence; no vendor concurrency suite was run.

Named risk: error wrapping could defeat permanent-error classification. I checked `services/platform/apiserver/postgres_database.go:453` and `:490`. Operation/not-found errors reach the new product classifier, CAS conflicts stay retryable repository conflicts, and wrapped permission errors retain SQLState. The Activity layer returns fixed redacted messages at `services/platform/orchestration/activities.go:134`.

Named risk: claimed signatures/readback could be bypassed by the new adapter. I inspected `services/platform/apiserver/security_agent_temporal_executor_repository.go:31` and `:193`, including its source and delivery response validation. The P3C caller uses those checked methods for signing, readback and acknowledgement. This check doesn't establish deployed gateway application.

Named risk: retained commands could resurrect completed work after history retention. I checked the unchanged `services/platform/orchestration/temporal_client.go:33` duplicate/history binding and the P3C retained wrapper. The wrapper handles verified terminal starts before reaching that history dependency. Cleanup-pending recovery after finite retry exhaustion still needs the operational gate below.

Named risk: startup could be blocked by the prior runtime. I inspected the unchanged constructor/readiness call chain and its historical SQL guards described in Important 1. The production-runtime diff begins mid-function, so I read its preceding construction block to establish ordering; the broader changed file was not re-reviewed.

The recorded final PostgreSQL group ends PASS547.935s at `p3c-final-postgres.log:313`, with12 top-level tests and16 owned-instance joins. `p3c-final-unit-runtime-cli.log:69`, `:111` and `:115` record the grouped passes. `p3c-final-runtime-fix.log:37` records the revised runtime check; `p3c-final-runtime-fix-race.log:3` and `:7` record the final focused race passes. These are inspected existing results, not tests I ran. `p3c-final-toolchain.log:1` says Go1.25.6, not the required release toolchain. The controller's full hash verification remains the source-freeze evidence; I did not repeat that audit.

Cannot verify from this diff: all728 original IDs and acceptance requirements, ledger classifications and final UI/release checks. No ledger/UI files are changed in this packet. The controller must reconcile the completed candidate with the authoritative ledger and run the final publication gates.

P3A/P3B owner exclusion, manual/ordered admission coexistence, complete current-authority/budget checks and stable-effect retry/restart evidence span prior packets. Their local acceptance isn't reproduced here. Preserve those accepted artifacts and resolve the new startup defect against the same installation, not separate predecessor fixtures.

Cannot verify active P7 OpenFGA revision enforcement, deployed Stytch/provider/AWS/signing/runner readiness, or P8/P10 acceptance. The local fixture explicitly supplies identity, planner transport, artifact storage and runner output (`services/platform/apiserver/security_agent_temporal_worker_postgres_test.go:19`; `services/platform/agentsec-worker/security_agent_temporal_workflow_integration_test.go:341`). Its actual SDK worker and SQL receipts are useful evidence, but those external gates stay open.

Cleanup retry exhaustion intentionally leaves pending/unknown state (`services/platform/orchestration/cleanup.go:14`). Monitoring and a reviewed recovery procedure, including closed-history cases, are named but not installed in `docs/internal/2026-09-22-temporal-openfga-p3c-report.md:162`. The controller must assign that operational acceptance; acknowledgement of a retained decision is not a cleanup receipt.

## Assessment

Task quality: Needs fixes.

The local workflow and authority work has substantive product tests, including actual worker consumption, cancellation and signed compensation. Fix the production constructor/readiness path and prove it on installed69 before accepting P3C.
