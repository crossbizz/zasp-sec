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
