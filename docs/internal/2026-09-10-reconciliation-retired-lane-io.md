# Retired reconciliation lane I/O

Status: unresolved production scaling concern, separate from the schema-46
candidate-query correction. Next on the critical path before frozen candidates.

The added normal-planner candidate tests passed at provider cardinalities 25 and
101, but left `enable_seqscan` enabled for the following historical retirement
phase. That phase originally disabled sequential scans. Under the default
planner, its empty-catalog index-only scan fetched 100,101 heap tuples while
returning zero rows: 4,005 shared reads exceed the existing 2,048 bound. No spill
or candidate-query failure caused this result.

`/tmp/zasp-reconciliation46-normal-plan-repeats.log` records the expanded run's
failures (command exit 1, 145.045 seconds). The previous full API run passed in
346.830 seconds; that pass does not supersede the later failure.

An isolated diagnostic applied unchanged migrations 1 through 45, asserted
catalog version 45, and omitted schema 46. It retained the same 100,000 busy-lane
effects, 100 other lanes, and 100,000 historical lane retirements, then checked
the unchanged empty-catalog work bounds with the default planner. All three runs
failed with 4,005 reads and 100,101 heap fetches (133.323 seconds total).
`/tmp/zasp-reconciliation46-retirement-predecessor.log` retains the evidence.
This is exact predecessor database-version reproduction, not a clean-base Git
worktree claim. The temporary diagnostic file was removed after recording it.

The likely difference is how the preceding count scans retired tuples and marks
dead index entries. That cache/index interaction is an explanation to investigate,
not a proven complete mechanism. An empty logical table does not guarantee a
bounded physical scan before dead-tuple maintenance.

Independent review approved restoring `enable_seqscan=off` after the new normal
candidate checks to preserve the original retirement fixture's conditions. The
original workload, counts, index requirements and I/O bounds are unchanged.
Candidate checks still use the default planner at both cardinalities. There is
no added VACUUM, cache warming, relaxed bound or skipped test. A pass under restored
fixture conditions must not be described as fixing default-planner retirement.

## Remediation still needs a lock-safety proof

A transactionally maintained singleton counter can deadlock multi-statement
effect writers that lock effect rows and the counter in opposite orders.
Adding a late advisory lock in a trigger does not solve that. Review rejected
accepting such a counter without auditing every writer's lock order and testing
adversarial transactions.

Possible approaches include uniform lock ordering at all mutation entry points,
or a conservative empty hint with a separate, verified maintenance contract.
Neither is implemented or accepted. Any replacement of a raw-catalog assertion
must explicitly test the actual production operation and preserve its work bound;
it cannot silently discard this failure.

The read-only entrypoint audit found different lock orders in OAuth start,
consume, completion, remediation and security-agent connector revocation.
Uniform serialization must precede the first workflow/OAuth/effect lock in every
outer entrypoint, including schema-23 revocation preparation/completion. A lock
inside a private effect helper is too late. Review recommends first evaluating
a conservative dirty-generation hint with a separate maintenance contract:
sequence gaps and aborts must invalidate empty claims, maintenance must not wait
on application row locks, and writers must not upgrade shared locks to exclusive.
This is a design candidate, not an implemented fix or immediate-retirement bound.

Review permits bounded schema-46 shipping only after Chrome and required CI pass,
with this separate exception disclosed. This defect blocks any claim that the
product is fully production-ready. No original task credit is added.

## Scope check and next acceptance

The original plan's initial performance gates require standard API p95 at or
below 750 ms on reference load, bounded concurrency/queues and no silent drops.
M8-36a/b/c/36 require a bounded representative workload, an execution of at most
five minutes, deterministic percentiles/error rate linked to the reference
profile, and stored release evidence. The immediate 2,048-read raw-catalog bound
is an inherited test condition, not an explicit original microtask criterion.
Neither the original criterion nor the inherited failure can be erased by a
passing serial SQL timing sample.

Independent read-only review accepted evaluating PostgreSQL maintenance as the
next remediation direction. It did not accept it as implemented or complete.
A global counter or new generation-maintenance service is not justified before
this path has been measured. PostgreSQL documents table-specific autovacuum
thresholds and the need to reclaim dead tuples in its
[routine vacuuming guide](https://www.postgresql.org/docs/18/routine-vacuuming.html)
and [vacuum configuration](https://www.postgresql.org/docs/18/runtime-config-vacuum.html).

Acceptance before calling this concern resolved:

1. Migration-owned table policy, fingerprinted with upgrade, rollback and drift
   tests, if measured behavior requires table-specific settings.
2. Repeated retirement cycles with no test-issued VACUUM. Observe actual
   autovacuum completion and verify post-maintenance physical work, including
   heap fetches and total shared reads plus hits so a warm cache cannot hide work.
3. Actual claim/API reference workload under concurrent writers, recording
   pre-maintenance p50/p95/p99 and errors. Serial repository calls are not this.
4. A long-lived snapshot that prevents cleanup. Monitoring must report remaining
   maintenance debt; an incremented autovacuum counter alone is not success.
5. Production monitoring of maintenance debt/progress and a bounded escalation
   procedure, with no new application lock-order cycle or silent empty hint.
6. An explicit record that immediate post-retirement raw scans remain subject
   to MVCC cleanup. Any accepted maintenance-based contract must name this
   distinction and retain the original API/load requirements.

M8-36b and M8-36 still need the authorized reference deployment. The internal
scenario, evaluator and production maintenance work can proceed without that
external acceptance. No task is promoted by this design review.

## Default-autovacuum characterization

The retained opt-in `TestReconciliationRetirementAutovacuumDiagnostic` uses actual
schema 46, its trigger-maintained lane catalog, and registered discovery-worker
repository claims. It runs two cycles of 100,000 distinct lanes inserted and
retired, with the production database defaults untouched: autovacuum on, 1-minute
naptime, threshold 50, scale factor 0.2, no table storage overrides. It issues
ANALYZE after loading each cycle, but no VACUUM, planner override or preparatory
empty-catalog count. This isolates repeated retirement; it is not the earlier
201,000-effect skew fixture, a concurrent API workload, or a cloud measurement.

The first characterization run exited zero in 170.188 seconds under Go's race detector
(`/tmp/zasp-reconciliation-retirement-autovacuum-diagnostic.log`). Its measurements:

| Cycle | Raw pre-cleanup heap fetches / shared hits | 100 serial claims p50 / p95 / p99 | Cleanup observed after retirement | Post-cleanup heap fetches / shared hits |
| --- | --- | --- | --- | --- |
| 1 | 100,000 / 4,715 | 1.667 / 2.365 / 2.690 ms | 45.29 seconds | 0 / 12 |
| 2 | 100,000 / 4,716 | 2.160 / 2.971 / 11.850 ms | 64.48 seconds | 0 / 12 |

All raw scans returned zero rows and zero shared reads because the data was in
shared buffers. The combined hit/read assertion prevents that warm cache from
disguising the pre-cleanup physical work. The post-cleanup check also requires
zero heap fetches. Autovacuum counts increased, and dead-tuple estimates reached
zero before each post-cleanup check. Review found that a vacuum during fixture
setup could satisfy this count condition and that earlier index scans could mark
dead entries. These initial observations do not prove that cleanup occurred after
retirement committed. The corrected experiment also requires `last_autovacuum`
after a server-clock timestamp sampled after that commit. These timings do not
establish a production maintenance SLA or the missing
long-lived-snapshot/concurrent-load cases.

Reproduce on an isolated local PostgreSQL installation:

```sh
ZASP_RECONCILIATION_MAINTENANCE_DIAGNOSTIC=1 go test -C services/platform -race -count=1 -v -run '^TestReconciliationRetirementAutovacuumDiagnostic$' ./apiserver
```

The experiment has a 280-second context deadline and explicitly skips unless
enabled. Ordinary CI must not treat that skip as a maintenance pass. Its first
attempt failed a test-data idempotency-key length constraint before loading the
workload; the fixture key was corrected before the measured run. That setup
failure is not a red test for a production fix. No production change is included
in this characterization.

The corrected enabled run passed in 170.024 seconds, exit 0:
`/tmp/zasp-reconciliation-retirement-autovacuum-strict.log`. Cycle 1 observed
post-retirement autovacuum at 37.52 seconds, cycle 2 at 47.45 seconds. Both final
scans had zero heap fetches, zero shared reads and 12 shared hits. Serial claim
p50/p95/p99 were 2.637/3.405/4.462 ms and 2.743/4.411/9.709 ms, respectively;
all 200 claims returned the expected empty result without an error. This is the
accepted post-commit observation, not the earlier count-only runs.

Review confirmed the observation correction and conditionally approved this
evidence-only commit once the strict run passed. Full local `npm run verify`
also passed with exit 0 (`/tmp/zasp-reconciliation-maintenance-verify.log`):
196 test files / 1,179 tests, types, lint, API contracts, production build and
the unchanged 728-row ledger. No production code or UI changed. Secret scans
of the documentation diff and new test passed. PR 35 is already merged, with
main CI 34514152920 passed; this follow-on evidence commit's shipping is separate.
