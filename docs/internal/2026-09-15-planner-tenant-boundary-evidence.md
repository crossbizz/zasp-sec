# Planner tenant-boundary evidence

M7A-94 remains component-only and unpublished. Local composed acceptance now
covers the original foreign-asset requirement through the actual planner,
processor and registered PostgreSQL repository. This is not live AI or deployed
production evidence. The initial database-only checkpoint is retained below.

## Initial database-boundary behavior

`TestProductionSecurityAgentAttackPathPostgresSchedulesOnceAndBindsPlannerToVerifiedPath`
now submits a real second tenant's environment ID through
`SecurityAgentWorkerRepository.AcceptSecurityAgentPlannerCandidate` using the
registered non-superuser, non-BYPASSRLS worker principal and schema v33.
Both tenants already have their own environments and attack paths, with matching
path IDs in distinct scopes. The rejected call must return no prepare result.
Whole-row snapshots of runs, plans, steps, approvals, effects, planner receipts,
controls, audit, environments and attack paths must remain unchanged. The same
live lease then accepts the authorized environment and reaches waiting_approval.

This catches removal of the SQL scoped-target check before preparation. A
temporary mutation probe replaced that comparison with false only inside the
owned disposable database. The test failed with `foreign target accepted` and
`State:waiting_approval` (tool result 34463d). The probe was removed; no production
SQL or runtime behavior was changed in that initial checkpoint. It added
regression coverage of existing behavior. The later composed test found a
separate planner defect, described below.

## Commands and outcomes

Run from `services/platform`, with local Go and PostgreSQL binaries on PATH,
`GOTOOLCHAIN=local GOPROXY=off`:

```sh
go test ./apiserver ./agentsec-worker -run '^(TestProductionSecurityAgentAttackPathPostgresSchedulesOnceAndBindsPlannerToVerifiedPath|TestSecurityAgentPlanner.*|TestSecurityAgentProcessor.*)$' -count=1 -v
```

Final grouped run b2115b: exit 0, nine top-level tests and seven nested cases
passed, no skips. The owned PostgreSQL server joined with normal exit. The
initial sandbox attempt failed at initdb (65f5f5); it was not a behavioral RED.
The authorized local-process rerun passed (0cf0ed), the deliberate mutation
failed (34463d), and the final unmutated group passed (b2115b).

## Composed planner/processor acceptance

`TestProductionSecurityAgentPlannerTenantIsolationThroughWorker` reuses the
registered two-tenant fixture and seeds a real inventory asset in the foreign
organization. It compiles one race-enabled worker test binary, runs three owned
child processes and joins each. `TestSecurityAgentPlannerWorkerOwnedPostgres`
uses the actual production planner, processor, PostgreSQL JSON adapter and worker
repository with the non-superuser/non-BYPASSRLS worker login. Only the external
AI HTTP transport is controlled; no live provider is contacted.

Cases: foreign asset, foreign environment of the same kind as the authorized
target, and authorized environment. The parent independently verifies durable
`planner_rejected`/failed receipts for both negatives, no plans/steps/approvals,
no effects/controls or foreign runs, unchanged asset/environment/attack-path
rows in both tenants, and no rejected target identifiers in failure audit data.
The positive control reaches waiting_approval with exactly one plan/step/approval.
The child also checks the actual outbound request's tenant, definition, action
and target authority. The child is intentionally skipped without a parent DSN;
the parent rejects a skipped/missing child acceptance.

### Defect found and fixed

The first composed run (085ae2) found that the planner expanded explicit SQL
target authority with environment/evidence IDs. SQL's later acceptance guard
still rejected unauthorized targets, but planner generation and validation were
too broad. `TestSecurityAgentPlannerDoesNotExpandExplicitTargetAuthority` then
failed all four cases (30f71e): evidence not authorized, environment not
authorized, missing authority, and empty authority. Production code now clones
only explicit `AllowedTargets` and rejects missing/empty lists before provider
I/O. Existing unit fixtures now supply the same explicit authority as production.

Grouped run 6dfab9 exited 0: both real PostgreSQL parent tests passed; all three
race-enabled composed children passed; planner and processor regressions passed,
including the four new target-authority cases. One standalone child invocation
skipped without its parent DSN, separately from the three verified executions.
Both owned PostgreSQL servers reported normal joined exits.

The independent review approved the composed harness and production fix with no
Critical or Important findings. It noted that the existing context-size counting
map's `targets` name could be clearer (optional Minor). Its other suggestion,
global plan/step/approval counts to catch wrong-run writes, was implemented;
the positive control now also reads back the stored plan target. The final
delta received independent approval with no Critical or Important findings.

The broader affected group passed after those assertion changes (ba08bf, exit 0):

```sh
go test -race ./apiserver ./agentsec-worker -run '^(TestProductionSecurityAgentPlannerTenantIsolationThroughWorker|TestProductionSecurityAgentAttackPathPostgresSchedulesOnceAndBindsPlannerToVerifiedPath|Test.*SecurityAgent.*)$' -count=1 -v
```

Package times: apiserver 29.177 seconds; worker 2.930 seconds. All three composed
child executions passed, with no skipped parent case. Two standalone opt-in
helpers skipped: combined E2E and the parent-owned planner worker. These skips
are not counted as executed acceptance. No race failure was reported. Owned
PostgreSQL processes joined normally. Ledger validation, formatting and diff
whitespace checks also passed. The reviewer inspected code and claims; root
executed the verification commands.

The existing CI API-test filter now includes `Test.*SecurityAgent`, so it runs
the parent fixture instead of only encountering the worker child's standalone
skip. The existing race/count/timeout controls and other selectors are unchanged.
The workflow contract first failed for the missing selector (5786a1), then all
248 contract tests passed after the workflow update (ee4eb4); ESLint exited 0.
Independent review approved this final selector change with no findings. CI
itself was not triggered, and Linux execution is not claimed.

Verified Go source SHA256 identities:

| File under services/platform | SHA256 |
| --- | --- |
| agentsec-worker/security_agent_planner.go | 356c15efe61255690e7d2fd2ecb090acce8c1bc79e2e58824f34bf612ae4eddb |
| agentsec-worker/security_agent_planner_test.go | 2c7eea27b19e16e8f43c2ea8f7dfe0c5ee78b5b0a62080658eba63ceb63e6081 |
| agentsec-worker/security_agent_planner_postgres_test.go | 07dff5379c932200a1c18e282923a14e22b5018807b70edc1d9f4635718fe01b |
| apiserver/security_agent_planner_worker_postgres_test.go | 15313d66eef032cb8a0873032a8ccdd79f95751c57bf3e15ad22cb2cdc7acd01 |
| apiserver/security_agent_attack_path_postgres_test.go | 6364bd95e6588772dd6be4635773abcd9dc7f5b2991148606684b1c7a9597a16 |

No hosted tenant, deployment, UI build, push or production promotion is claimed.
Release verification and shipping remain open; this local fixture is not live
production proof.

## Initial review record

Independent read-only review (`tenant_planner_review`) approved this incremental
diff with no Critical or Important findings. It traced the valid foreign target
through repository validation to SQL v33's target comparison before prepare.
One optional Minor remains: snapshot mismatch diagnostics could name the changed
table instead of reporting a generic mismatch. The reviewer did not rerun tests;
execution evidence above is from the root agent. The full batch retains its
original scope and release gates.
