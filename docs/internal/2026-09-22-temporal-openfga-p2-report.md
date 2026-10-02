# P2 delivery is staged

Status: DONE_WITH_CONCERNS, pending controller review. No commits or pushes.

Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`, retained HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`.

I added transactional SQL command capture, the official Temporal SDK adapter, a small delivery relay, and the shipped `up-temporal-outbox` migration command. All new admissions still have `execution_owner='legacy'`. There is no runtime owner-change permission or function in P2.

This is not execution cutover. P3 Activities and the manual/ordered transition remain required before activation.

## The binding decision

The first combined SQL attempt exposed a predecessor constraint: registered61 deliberately leaves old public readiness checks unavailable. `0061_production_security_agent_multistep.promote.sql` says that old binaries must not use the evolved schema. Calling the existing manual authority after advancing its installation through61 returned `manual admission release unavailable`.

The controller approved two explicit P2 installation surfaces:

| Registered predecessor | What P2 proves |
| --- | --- |
| Exact legacy60 | Actual manual admission/cancellation, receipt replay, and atomic outbox capture |
| Registered61 plus public62 | Actual nested ordered admission, approval/cancel decisions, and atomic outbox capture |

Migration65 records `legacy60` or `ordered62` in its private registration and checks that exact authority on installation and readiness. It does not accept a mixed or malformed installation. `up-temporal-outbox` installs only65; it does not advance60 through61, change historical readiness, or install scheduler64.

P3/P4 must support all required manual and ordered flows on the upgraded Temporal deployment. Passing two separate predecessor tests does not prove coexistence, migration between these surfaces, or the final API-to-worker-to-receipt flow.

## What changed

`services/platform/orchestration/` now contains:

- `contracts.go`: canonical scoped run IDs, start/decision contracts, validation, and product-safe errors.
- The Temporal adapter uses the P1 official client. Starts name `SecurityAgentWorkflow`, use `security-agent/v1/<organization>/<workspace>/<environment>/<run>`, reject reused IDs, and fail conflicts. A duplicate response is accepted only after decoding and comparing the immutable first history event's original start input, including scope, definition version, and digest. Mutable memo is not the authority.
- `outbox.go` has a bounded relay and SQL store. SQL calls end before RPCs begin. Ack follows acceptance, retries remain safe, and failed delivery leaves the command pending. Each RPC has the configured finite timeout; a whole batch has a30-second limit and reads at most100 commands.
- Decisions use the `product-decision` signal. The message has scope/run references, event ID, kind, and the committed product request-receipt ID as `decision_id`; it carries no credentials, resource bodies, or artifacts.

Migration65 adds its own schema, registration, fingerprint, command table, and receipt-insert trigger. The trigger reads the persisted audit's run identity and validates the receipt's intent digest. Start digests come from persisted trigger evidence; decision digests come from their own committed intent. Approval capture requires a persisted approved/rejected approval, matching approver, decision time, and fresh-auth evidence.

The trigger runs inside the existing admission/decision SQL transaction. It captures one start even when `trigger_resource` invokes `trigger`; the original locks, authorization, budget admission, response receipts, and replay checks remain in charge. Rollback removes both the new product mutation and its command. The Go admission entry points document why no post-`QueryJSON` delivery write is allowed.

The API checks migration65 readiness when P1 runtime-service connections are enabled. It still returns its existing SQL receipt/status. The security-agent worker composes the relay with its existing processor and attempts both independently if either refuses work. Disabled service configuration remains disabled. Enabled delivery uses `services.Temporal` from P1's actual connection, not a fake client or an FGA readiness result.

SQL runtime roles have no direct command-table updates. API cannot acknowledge commands. Pending reads filter for Temporal ownership; approval/cancel delivery waits until the same scoped run's start is accepted. Ack matches organization, workspace, environment, run, and event, and is idempotent. It changes only delivery evidence, never run completion or cleanup state.

The new CLI command covers all three dispatch seams: `isForwardMigration`, `runReleaseMigration`, and `registerForwardRelease`. The production `registeredReleaseMigrationRunner` explicitly forwards the extension method instead of hiding it behind the older embedded interface. Down refuses to remove retained command evidence.

## RED, then GREEN

Commands below ran from `services/platform` in the retained worktree. SQL fixtures used disposable local PostgreSQL instances and joined their owned servers on cleanup. No shared database was deleted.

Initial SQL RED:

```text
go test ./apiserver -run '^TestTemporalOutbox' -count=1 -v
TestTemporalOutboxManualAtomicPostgres: transactional Temporal outbox migration missing
```

The first ordered helper attempted an already-applied predecessor and got `invalid migration state`. I fixed that test setup before continuing. Its isolated RED then reached the intended missing feature:

```text
go test ./apiserver -run '^TestTemporalOutboxOrdered' -count=1 -v
TestTemporalOutboxOrderedAtomicPostgres: transactional Temporal outbox migration missing
FAIL (8.04s)
```

Adapter and worker RED were compile failures on absent application contracts, not runtime assertions:

```text
go test ./orchestration -count=1
undefined: RunRef / StartRequest / Message / Command
FAIL [build failed]

go test ./agentsec-worker -run '^TestTemporalRelay' -count=1
undefined: temporalOutboxProcessor
FAIL [build failed]
```

Shipped-command RED:

```text
go test ./orchestration ./apiserver ./agentsec-migrate \
  -run '^Test(StartMapping|RelayAcceptance|TemporalOutbox)' -count=1 -v
TestTemporalOutboxShippedCommandPostgres:
  shipped outbox dispatch invalid release migration command
FAIL (7.77s)
```

The live SQL installation probes produced the catalog fingerprint used by the compiled migration. Intermediate failures were retained as diagnostics while the new SQL shape changed. Final fingerprint: `3efa037cc3a3fe795cdc5dab93452030827b8c330ecfd2d00eda1d7ee158ee2e`.

A focused RED caught the missing whole-batch deadline:

```text
go test ./orchestration -run '^TestRelayBounds' -count=1 -v
TestRelayBoundsWholeBatch: batch has no finite deadline orchestration unavailable
FAIL
```

Final grouped GREEN:

```sh
go test ./orchestration ./apiserver ./agentsec-migrate ./agentsec-api ./agentsec-worker \
  -run '^Test(StartMappingAndConflict|NotifyMappingAndValidation|RelayAcceptanceBeforeAckAndScope|RelayBoundsWholeBatch|Temporal.*|RuntimeServices.*|SecurityAgentManualHTTPPostgres|SecurityAgentRelease62PublicLifecyclePostgres)$' \
  -count=1 -v
```

```text
PASS orchestration: 4 tests, 0.711s
PASS apiserver: 5 tests, 73.904s
  SecurityAgentManualHTTPPostgres: 6.99s
  SecurityAgentRelease62PublicLifecyclePostgres: 11.55s
  TemporalOutboxManualAtomicPostgres: 8.19s
  TemporalOutboxOrderedAtomicPostgres: 11.59s
  TemporalOutboxApprovalAtomicPostgres: 34.45s
    nested real planning worker: PASS, provider_calls=1
PASS agentsec-migrate: 1 test, 10.081s
PASS agentsec-api: 1 test, 1.646s
PASS agentsec-worker: 3 tests, 2.490s
exit0; 14 top-level tests passed
```

Coverage includes manual admission rollback, ordered approval rollback, admission and decision replay, original receipts, conflicting input refusal, nested admission cardinality, committed approval and cancellation IDs, legacy ownership exclusion, tenant-mismatched ack refusal, unavailable-service preservation, acceptance-before-ack, duplicate ack, decision ordering, registration drift, disabled-trigger drift, and runtime ACL refusal. Ordered admission rollback was not directly exercised.

I then extended the command test to execute the real CLI (`go run . up-temporal-outbox`) with all configured principal bindings against the disposable database. It performs the first installation; the same test then verifies wrapper replays, readiness, canonical60 preservation, drift, and ACLs:

```text
go test ./agentsec-migrate -run '^TestTemporalOutboxShippedCommandPostgres$' -count=1 -v
--- PASS: TestTemporalOutboxShippedCommandPostgres (11.46s)
ok agentsec-migrate 12.226s
exit0
```

`git diff --check -- services/platform` passed. No unchanged broad suite was repeated. SDK boundary tests check our arguments, identity comparison, and acknowledgement behavior; they do not claim to test Temporal's persistence, scheduling, or deduplication internals. The unavailable-service SQL case uses an external-engine test double with a real SQL store and real product admission.

## Retained bytes and review scope

Before edits, I copied the complete26MB `services/platform` tree into:

`.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p2-baseline/platform/`

This preserves dirty predecessor work and P1 overlap bytes, not just HEAD. Review artifacts:

- `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p2-scoped.diff`
- Before/after SHA256 values for each of16 source/test paths are in `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p2-hashes.json`. A null before-hash means a new file.

Full-tree `diff -qr` found exactly the following P2 paths changed or added. All other platform bytes, including every historical SQL migration, P1 clients/configuration, and `go.mod`/`go.sum`, match that captured baseline.

```text
services/platform/orchestration/contracts.go
services/platform/orchestration/temporal_client.go
services/platform/orchestration/outbox.go
services/platform/orchestration/outbox_test.go
services/platform/migrations/production_temporal_outbox.go
services/platform/migrations/sql/0065_production_temporal_outbox.up.sql
services/platform/migrations/sql/0065_production_temporal_outbox.down.sql
services/platform/agentsec-migrate/main.go
services/platform/agentsec-migrate/bootstrap_release.go
services/platform/agentsec-migrate/temporal_outbox_test.go
services/platform/apiserver/security_agent_manual_start.go
services/platform/apiserver/security_agent_public62_repository.go
services/platform/apiserver/security_agent_temporal_outbox_postgres_test.go
services/platform/agentsec-api/production_runtime.go
services/platform/agentsec-worker/production_runtime.go
services/platform/agentsec-worker/temporal_outbox_test.go
```

This report and the review artifacts are new. Nothing was staged, committed, pushed, reset, or reverted.

## P3 handoff, still closed

P3 must bind these exact contracts before it enables execution:

1. Register `SecurityAgentWorkflow` with `orchestration.StartRequest` and accept `product-decision` messages. A hint must cause the Activity to read the scoped product receipt and its audit/approval/transition evidence. Revalidate current tenant and authorization rules. Expired or missing decision evidence must fail closed; duplicate hints must never authorize duplicate provider effects.
2. Supply a durable run-owner fence and change capture to derive each new command's owner from that fence. P2 deliberately defaults *every* start and decision to legacy, and has no public owner-change operation. Do not bulk-convert retained legacy commands or historical completed runs.
3. Exclude Temporal-owned runs at all old selection/claim authorities before any command becomes dispatchable. This includes `public.zasp_security_agent_claim_budgeted_runs`, private61 planning/action/recovery authorities under `zasp_sa_multistep_prior`, and worker63 `dispatch`/`worker` paths that select queued runs or claim their next transitions. Existing direct per-run tick entry points also need the same fence. P2 changed none of those selectors.
4. Complete the supported manual/ordered deployment transition, real Activities, API-to-worker-to-receipt tests, cleanup-pending behavior, and retained decision/history policy. P2 starts mean accepted, never business completion. Temporal retention and closed-execution signaling must be handled with the product's retained receipts before final acceptance.

Self-review found the predecessor split and the unbounded batch problem; both are now explicit and tested. Historical cancellation decisions use their own validated intent digest, so the capture path does not demand a new trigger receipt for an old run or invent a start command.

The release gates reported by the controller remain outside P2:26 host-Go advisories and73 predecessor commits on the retained branch. P5 authorization-model acceptance and P8 publication acceptance are still separate gates. Keep execution ownership disabled until P3/P4 prove the complete deployment path.

## Fix round1: failed rows no longer pin the polling window

Review found that the oldest100 failed commands could win every poll. I reproduced that case against the real SQL store: after three polls, the101st command from a healthy tenant still had no acceptance. Two slow rows also blocked a later tenant by consuming each poll's deadline.

The fix adds one private delivery field, `last_attempt_at`. Pending commands sort by `COALESCE(last_attempt_at,created_at)`, with scoped identity tie-breakers. The relay records a scoped SQL `attempt` before each RPC. That write commits independently, so an RPC timeout or process exit cannot erase the row's turn. Subsequent polls can reach later rows while the failed command stays present and unacknowledged. New arrivals enter the same time order; failed commands remain eligible for later turns.

This is outbox polling metadata. There is no workflow lease, retry policy, retry timer, or new execution scheduler. The100-row and30-second bounds remain. Attempt recording matches organization/workspace/environment/run/event, requires Temporal ownership and an unaccepted row, and uses the existing worker principal/readiness guard. If it fails, the relay does not dispatch or acknowledge. Pending decisions still require their same-scoped start's acceptance. Ownership defaults and both supported predecessor states are unchanged.

The unpublished65 SQL fingerprint is now `8c64101128b0b31cd4d12575480035ab1e30f157d92fa96c236babc7620de3f8`; this supersedes the initial P2 fingerprint recorded above. Historical migrations1-64 are byte-identical to the pre-fix snapshot.

The report's earlier rollback sentence now says exactly what the tests prove: manual admission rollback and ordered approval rollback. Ordered admission rollback was not directly tested.

### RED was the actual stuck queue

From `services/platform`:

```sh
go test ./orchestration ./apiserver \
  -run '^Test(RelayAdvancesBeforeDeadline|RelayAttemptFailurePreventsDispatch|TemporalOutboxFairPollingPostgres)$' \
  -count=1 -v
```

```text
FAIL TestRelayAdvancesBeforeDeadline:
  attempt not recorded before deadline; failed delivery must stay unacknowledged
FAIL TestRelayAttemptFailurePreventsDispatch:
  dispatch bypassed failed durable attempt <nil>
FAIL TemporalOutboxFairPollingPostgres/deadline_false:
  accepted=0 retained=101
FAIL TemporalOutboxFairPollingPostgres/deadline_true:
  accepted=0 retained=3
FAIL apiserver 19.431s; exit1
```

After implementing the polling turn, both unit cases passed. The live SQL probe produced the new fingerprint above; I updated the pin before the next group.

```sh
go test ./orchestration ./apiserver ./agentsec-migrate ./agentsec-worker \
  -run '^Test(StartMappingAndConflict|NotifyMappingAndValidation|Relay.*|Temporal.*)$' \
  -count=1 -v
```

That group passed all six orchestration tests, the100-conflict SQL prefix case, manual admission/cancellation, ordered admission/cancellation and tenant-bound acknowledgement/attempt checks, ordered approval rollback/replay, the real migration CLI, and worker independence. The group still exited1 because the150ms slow-case fixture budget expired before any RPC: a diagnostic rerun showed `last_attempt_at=NULL` on all three rows. That was not accepted as deadline evidence.

I changed only that test harness. It now gives real SQL a5-second guard and has the test engine cancel the poll with `context.DeadlineExceeded` as its cause after entering the RPC. After each failed prefix poll, SQL must show exactly one additional durable turn and zero accepted rows. The third bounded poll must accept the later tenant while retaining both failed rows. `TestRelayAdvancesBeforeDeadline` independently exercises an actual20ms timer deadline.

Final focused GREEN:

```sh
go test ./orchestration ./apiserver \
  -run '^Test(Relay.*|TemporalOutboxFairPollingPostgres)$' -count=1 -v
```

```text
PASS TestRelayBoundsWholeBatch
PASS TestRelayAcceptanceBeforeAckAndScope
PASS TestRelayAdvancesBeforeDeadline (0.02s)
PASS TestRelayAttemptFailurePreventsDispatch
ok orchestration 0.552s
PASS TemporalOutboxFairPollingPostgres/deadline_false (35.35s)
PASS TemporalOutboxFairPollingPostgres/deadline_true (9.76s)
PASS TestTemporalOutboxFairPollingPostgres (45.11s)
ok apiserver 45.933s
exit0
```

The fairness test seeds delivery rows and scoped run references directly; it tests our real SQL polling/attempt/ack logic, not admission or vendor internals. The existing admission and decision tests continue to use the actual product authorities. Those passed in the prior focused group with this same production code. The real CLI test also passed there in11.77s (package12.160s), and the worker test passed. No blanket rerun followed the harness-only change.

### Fix-only review artifacts

Pre-fix bytes were captured before editing under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p2-fix1-baseline/`. It contains the orchestration, migrations, and apiserver trees, plus this report's pre-fix bytes.

The fix-only diff is `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p2-fix1-scoped.diff`; before/after SHA256 values are in `p2-fix1-hashes.json` beside it. These artifacts cover six paths:

```text
services/platform/orchestration/outbox.go
services/platform/orchestration/outbox_test.go
services/platform/migrations/production_temporal_outbox.go
services/platform/migrations/sql/0065_production_temporal_outbox.up.sql
services/platform/apiserver/security_agent_temporal_outbox_postgres_test.go
docs/internal/2026-09-22-temporal-openfga-p2-report.md
```

`git diff --check` passed for the fix scope. Directory comparisons found no other edits within the captured source trees. The original P2 diff/hashes remain initial-review evidence; apply this fix-only overlay when assessing current bytes.

Status: DONE_WITH_CONCERNS, ready for scoped re-review. Fairness and precise rollback evidence are addressed. The unchanged concerns are the staged owner fence, P3/P4 execution/transition acceptance, and the later release gates. No commits, pushes, activation, or shared database changes.
