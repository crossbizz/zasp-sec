# Final readiness expiry now has a timing test

The registered schema55 execution wrapper rejects lease and supervised approval
expiry during its final post-dispatch readiness call. Both cases passed on the
unchanged production wrapper, after the observer saw the worker blocked inside
readiness with actual dispatch writes already present in that transaction.

Scope is narrow. This uses the existing supervised `create_temporary_policy`
fixture, its real registered worker login, real preparation/claim and real SQL
dispatch. It does not cover every legacy action or the private run/rerun branch.
It closes the shared wrapper's distinct post-readiness timing gap, not all of
Task1 or the publication gates.

## What the test observes

The test captures the installed readiness and execution definitions with
`pg_get_functiondef`. Its owned-database readiness replacement returns true at
entry, then takes advisory lock895533 only when the real run is `running`.
Before that lock, it requires a scoped executing step, pending temporary-policy
effect, the exact new `effect_dispatched` audit, and three cleared parent lease
columns. The hook does not create any of those rows.

The separate blocker connection proves `pg_blocking_pids` points to itself and
that the worker has an ungranted advisory lock895533 before expiry. It keeps the
lock until `clock_timestamp()` passes the deadline returned by the database.
Lease and approval cases each get a fresh owned database.

After release, acceptance requires SQLSTATE40001 and the exact message
`existing test execution authority expired`. The combined existing dispatch and
acceptance snapshots must be unchanged. Those snapshots include full run,
step, plan, approval, planner-receipt and audit records, plus counts of effects,
reservations, links, test runs, outbox rows and request receipts.

Cleanup restores both original definitions, then checks the registered
`existing_tests_client_ready` entrypoint with the compiled pins. No grants are
added. The release check after restoration is a cleanup assertion; the replaced
readiness body during execution is timing instrumentation, not release identity,
fingerprint, ACL drift, or production-readiness proof.

## The RED was real

The `ZASP_EXISTING_TEST_FINAL_READINESS_CONTROL=without_final_guard` switch removes
exactly one final captured-deadline guard from the installed execution definition
in the disposable database. It does not edit migration source or compiled pins.
This is the break the test catches: allowing real dispatch writes to commit when
authority expires during final readiness, after the dispatcher cleared its lease.

API r1 first exposed the intended bad commit in both modes, but its cleanup also
failed: concatenated `pg_get_functiondef` results lacked a statement separator,
and its restoration check called private readiness as the worker (42501).
I fixed the helper to restore definitions with separate calls and check through
the registered client entrypoint. That first run is not the clean RED evidence.

API r2 clean RED: container exit1,15.86s. Relevant output:

```text
observed final-readiness waiter after effect, audit, executing step and cleared lease; lease deadline=2026-09-17T21:08:59.296267Z
final-readiness lease expiry did not roll back: <nil>
observed final-readiness waiter after effect, audit, executing step and cleared lease; approval deadline=2026-09-17T21:09:07.227826Z
final-readiness approval expiry did not roll back: <nil>
--- FAIL: TestSecurityAgentExistingTestFinalReadinessExpiryPostgres (15.86s)
    --- FAIL: TestSecurityAgentExistingTestFinalReadinessExpiryPostgres/lease (7.93s)
    --- FAIL: TestSecurityAgentExistingTestFinalReadinessExpiryPostgres/approval (7.93s)
FAIL
```

Both owned PostgreSQL processes joined normally. Neither restoration check
reported an error in this clean run.

## GREEN and its neighboring tests

Same API r2, no mutation switch: container exit0,15.65s.

```text
observed final-readiness waiter after effect, audit, executing step and cleared lease; lease deadline=2026-09-17T21:09:18.398131Z
database clock passed lease deadline; exact 40001 expiry and unchanged durable snapshot verified
observed final-readiness waiter after effect, audit, executing step and cleared lease; approval deadline=2026-09-17T21:09:26.130855Z
database clock passed approval deadline; exact 40001 expiry and unchanged durable snapshot verified
--- PASS: TestSecurityAgentExistingTestFinalReadinessExpiryPostgres (15.65s)
    --- PASS: TestSecurityAgentExistingTestFinalReadinessExpiryPostgres/lease (7.89s)
    --- PASS: TestSecurityAgentExistingTestFinalReadinessExpiryPostgres/approval (7.76s)
PASS
```

The neighboring grouped run also exited0:

```text
--- PASS: TestSecurityAgentExistingTestLegacyExecutionPostgres (14.86s)
    --- PASS: TestSecurityAgentExistingTestLegacyExecutionPostgres/prepare/fresh (3.74s)
    --- PASS: TestSecurityAgentExistingTestLegacyExecutionPostgres/prepare/expired (3.53s)
    --- PASS: TestSecurityAgentExistingTestLegacyExecutionPostgres/dispatch/fresh (3.96s)
    --- PASS: TestSecurityAgentExistingTestLegacyExecutionPostgres/dispatch/expired (3.63s)
--- PASS: TestSecurityAgentExistingTestFinalWriteExpiryPostgres (11.92s)
--- PASS: TestSecurityAgentExistingTestExecutionRouting (0.08s)
PASS
```

All owned databases in those runs logged `pg_ctl exit=0 server Wait exit=0
normal-exit`. No host database, external network, linked worker child, HTTPS
child, live provider, cloud queue or deployment was used. The parent task owns
the separate HTTPS regression. I did not repeat it here.

## Reproduce it

Working directory for the following commands:
`/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/budget-recovery-20260916`.

The compile ran successfully for r1, then for r2 after the two helper fixes.
The exact final compile command was:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test -C services/platform -c -o /private/tmp/zasp-execution-readiness-api-r2 ./apiserver
```

RED:

```sh
/usr/local/bin/docker run --rm --pull=never --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,mode=1777 --user postgres --mount type=bind,src=/private/tmp/zasp-execution-readiness-api-r2,dst=/zasp-api-tests,readonly --env ZASP_EXISTING_TEST_FINAL_READINESS_CONTROL=without_final_guard --entrypoint /zasp-api-tests postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExistingTestFinalReadinessExpiryPostgres$' -test.v -test.timeout=90s
```

GREEN:

```sh
/usr/local/bin/docker run --rm --pull=never --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,mode=1777 --user postgres --mount type=bind,src=/private/tmp/zasp-execution-readiness-api-r2,dst=/zasp-api-tests,readonly --entrypoint /zasp-api-tests postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExistingTestFinalReadinessExpiryPostgres$' -test.v -test.timeout=90s
```

Grouped regression:

```sh
/usr/local/bin/docker run --rm --pull=never --network none --read-only --tmpfs /tmp:rw,nosuid,nodev,mode=1777 --user postgres --mount type=bind,src=/private/tmp/zasp-execution-readiness-api-r2,dst=/zasp-api-tests,readonly --entrypoint /zasp-api-tests postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentExistingTest(FinalWriteExpiryPostgres|LegacyExecutionPostgres|ExecutionRouting)$' -test.v -test.timeout=120s
```

`gofmt -l` for the two changed Go files and `git diff --check` returned no output,
exit0. Binary SHA256:
`b4451ac609c40b462cd3102ebdaf6cb9f5001bd40fe93178683f0553f1b7196b`.

## Files changed here

New test helper:
`services/platform/apiserver/security_agent_existing_test_readiness_expiry_postgres_test.go`.
The existing `services/platform/apiserver/security_agent_budget_start_postgres_test.go`
now routes the explicit readiness-expiry fixture mode and skips irrelevant
prepare/expired-budget cases for that mode. This report is the only document
written by this subtask.

I did not change `security_agent_existing_test_execute_postgres_test.go`,
production source, pins, grants, the ledger, or task status. No commit, staging
or push. The production execution fragment SHA256 stayed
`0ff8aa8009a5c0e1074a320f7550fe13f05bcc91325383f23e7518ad7aecd710`;
`security_agent_existing_tests_release.go` stayed
`e10ace09e6836696d9f9c12d50ff882f7012d4a74052e0d968a9954c63599872`.

The parent task reported independent review by `existing_test_catalog_review`:
no Critical or Important issues, with agreement on this bounded scope.
