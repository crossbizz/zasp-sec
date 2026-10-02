# Existing-test stopped-parent cancellation batch

Next ownership batch: [claim generation and counter recovery](2026-09-17-existing-test-generation-plan.md).
Owned boundary regression834f7f reproduces issued version1000000 refusing release
in all four modes. The generation design has independent review; implementation
and passing acceptance remain open. No production status change.

Continuation of the approved existing-test design and settlement plan. Preserve
all original728 microtasks and the separately approved KIC scope. M7A-21 remains
component-only/disabled. Use Superpowers TDD and feature-batched verification;
the user's standing authorization permits implementation without another pause.

## Gap and authority

ReconcileOne currently releases queued/retryable work before considering parent
state. A stopped parent can leave that linked test pending forever. The current
cancel_core accepts human API or Red Team worker principals, not reconciliation
leases. Do not grant those roles to the reconciler or broaden those API routes.

Add a dedicated guarded reconciliation cancellation entrypoint with the same
scoped run/step/worker/token/version and compiled-pin arguments as Evidence.
It must hold the original reconciliation lease. Whitelist stopped parent states
cancelled, failed, inconclusive and needs_human. Active parent returns no-op;
terminal test returns no-op and retains its existing outcome/history.

Follow organization admission, parent, link, then test-run locking. Classify
all invocation attempts only after locking the test run: no journal means
cancelled_before_execution; completed-only journal means
cancelled_after_partial_execution; any started journal means outcome_unknown.
Unknown becomes failed/error outcome_unknown; known cancellation becomes
cancelled/error cancelled. Clear execution ownership, mark cancel_requested,
retain all journals and existing cancellation classification. Never require
a live execution lease or active-parent admission to revoke stopped work.

Factor only the private state-transition logic for reuse with existing human/
test-worker cancellation. Keep authorization at each guarded boundary, with no
new public/private-helper grants. Recheck registered principal, compiled
authority and original reconciliation deadline after writes and before every
no-op return. Expiry or drift during a wait must roll back all changes.

ReconcileOne invokes the guarded operation after heartbeat and before Evidence.
It then reads the fresh snapshot; never settle a pre-cancellation snapshot.
Existing cancelled/unknown proof classification and immutable settlement apply.

## Batch checklist

- [x] Reproduce stopped-parent queued stranding with the actual registered
  worker and owned database. Test added as
  TestSecurityAgentExistingTestStoppedQueuedPostgres: owner requires cancelled
  test, cleared execution ownership, cancelled-before-execution classification,
  settled link/cancelled proof, preserved parent/step, known-failure effect and
  no journal. A successful pending release must not satisfy it.
  Owned REDee0a7b failed all four modes16.62s: the child returned success after
  release, but the owner's durable cancellation assertion failed. DB joined.
- [x] Implement guarded authority and shared private transition, then client
  receipt validation and reconciliation ordering.
  Candidate source implemented; owned queued cancellation acceptance passes.
- [ ] Cover active-parent no-op, stopped queued/retryable, stopped leased with
  completed/started journals, terminal-state preservation and exact retries.
- [ ] Verify altered identity/token/version/pins and foreign tenant refusal;
  observed blocked-write expiry/drift rollback, and late callbacks retaining
  unknown history.
- [ ] Independently review; calibrate candidate migration only in the owned
  offline database; run grouped cancellation/settlement/artifact/release/race
  acceptance and ledger validation. UI/full release gates precede any push.

Independent design/test review found no new Important issue in this direction
and required the explicit no-op fences, all-attempt journal classification and
post-cancellation Evidence read above. The candidate now extracts a private
cancel_transition while retaining the original cancel_core authorization,
adds guarded reconcile_cancel_stopped and calls it before fresh Evidence.
No-op and mutation returns both check original deadline and compiled authority.

Owned calibrationf3bc1a observed candidate fingerprint
`083c6e89d4287f0f2e40b2a59b9412b61de10f535c77ca83167f33ba91084527`;
the compiled pin was updated from that owned result only. Independent source
review found no Critical/Important issue. A Minor contradictory no-op receipt
was reproduced by REDec898d and fixed by checking all non-null outcome/state
pairs, independent of changed. Re-review confirmed the fix.

Grouped worker/actual Node race2eabcc passed8.672s; migration race6d6edb
passed4.818s. The owned cancellation/compatibility/remediation/release group is
recorded after its terminal result. Stopped-leased and observed-expiry acceptance,
version exhaustion, production scheduling/restart and live gates remain open.
No production promotion, UI/full release gate, commit or push.

## Terminal queued-cancellation acceptance

The first grouped owned run passed the four stopped-queued subcases but failed
its enclosing test: the shared batch-limit helper still expected pending links
after those links had settled. This was a test-harness expectation failure, not
a passing batch. The helper now expects zero reclaimable links for the stopped
case and retains the original pending batch sizes, invalid-limit and busy-org
checks for the normal case. Independent re-review accepted that correction.

Final session75577 returned exit0 (output bb9020):
TestSecurityAgentExistingTestReconcileLeasePostgres passed16.59s and
TestSecurityAgentExistingTestStoppedQueuedPostgres passed16.39s, each across
run/rerun and supervised/autonomous modes. All eight registered-worker child
checks passed, and both owned PostgreSQL processes joined normally. These
tests use the candidate compiled fingerprint above and the corrected helper.

The earlier group also passed WorkerFinish with controlled artifact remediation,
InvocationTerminal, compiled fingerprint and release/rollback checks. Those
results do not establish human/API or Red Team worker cancellation compatibility:
the shared cancel_core call paths still need direct acceptance coverage after
the transition extraction. The queued result does not prove stopped-leased
journal classification, blocked-write expiry/drift, restart or live deployment.
The remaining checklist stays open; M7A-21 remains component-only/disabled.

## Cancellation boundary regression extension

The same owned fixture now calls guarded cancellation twice on an active parent
and asserts both its no-op receipt and durable queued test, cancel_requested=false,
null cancellation classification, leased reconciliation state and unchanged
ownership version. The refusal matrix exercises altered organization, workspace,
environment, parent, step, worker, token, version and both compiled pins, plus
an unregistered owner principal and an already expired reconciliation lease.
These checks catch accidental cancellation of active work or bypassed admission;
they do not simulate expiry during a blocked write. No production source changed.

Independent read-only review found no actionable findings in this extension.
Linux API test compilation passed (12a256). Owned session69620 returned exit0
(a25472/ccde07): normal reconciliation passed19.90s and stopped queued passed19.21s,
four modes each, with all eight registered child checks passing and both owned
PostgreSQL processes joined normally. This extends queued acceptance with the
active-parent no-op and cancellation authorization refusal checks above.

## Stopped leased and existing cancellation batch

A broader source search found existing human/API and Red Team worker acceptance
in red_team_linked_cancel_postgres_test.go. The earlier search was limited to
security_agent-prefixed files; direct coverage was not absent, only not yet
rerun against this candidate. TestSecurityAgentExistingTestCancellationPostgres
uses the public HTTP handler/repository and registered worker cancellation path,
including idempotent human replay, execution-lease expiry and late observations.

TestSecurityAgentExistingTestStoppedLeasedPostgres now reuses that invocation
fixture under an opt-in flag. The registered reconciler cancels three leased
cases and one queued case across cancelled, failed, inconclusive and needs_human
parents. Common assertions check known-partial versus unknown classification,
cleared execution ownership, unchanged journals and refusal of new invocations.
A second cancellation must return a no-op and preserve the exact test/link/parent
snapshot. The started-journal case retains unknown after a late observation.

For completed-only journal mode, an observed link-table write blocker holds
cancellation beyond its original reconciliation deadline. The call must return
40001 and restore the exact pre-call test/link/parent snapshot, including the
test mutation made before the blocked link write. Independent read-only review
found no actionable findings. No production source changed. The new grouped
owned execution is pending its terminal result; this acceptance does not cover
subsequent settlement, production scheduling or live runtime behavior.

Initial grouped session49741 ended exit1 (d3d57f/4cba96). Existing human/worker
cancellation passed28.93s. The new stopped test passed mode0 but mode1 retained
the parent lease expiry while assigning a terminal state, violating the existing
parent lease/state constraint. Later cases then encountered its unclaimed work.
The fixture now clears all parent lease fields when assigning the stopped state,
matching the production terminal transition. No schema constraint was weakened.
Corrected grouped session22034 ended exit0 (10cfaa/10e97b): existing human/worker
cancellation passed29.13s and stopped-parent cancellation passed29.28s, all four
modes each. Both owned PostgreSQL processes joined normally. Re-review found no
new findings. This proves the bounded SQL cancellation, unchanged terminal retry,
late-result compatibility and observed blocked-write expiry rollback described
above. Retryable-state coverage, blocked-write authority drift, subsequent leased
settlement/composition, version exhaustion, runtime scheduling/restart and live
gates remain open. No promotion, UI/full release gate, commit or push.

## Retryable and release-drift extension

The stopped fixture now uses a journal-free retryable attempt scheduled an hour
ahead for mode1; queued attempt-zero coverage remains in its separate batch.
Mode2 also changes the compiled release checksum after observing the cancellation
blocked on the link-table write, requires55000, and checks exact test/link/parent
rollback. The existing expiry case remains. Independent review found no initial
findings. No production code changed.

Initial extension session46269 ended exit1 (81fed7): the direct cancellation
group and drift case passed, but retryable mode1 failed the repository read.
The fixture had changed attempt0 to attempt1 without setting started_at, which
validRedTeamRun correctly requires. Its correction sets started_at=queued_at;
the production validator is unchanged. Independent re-review confirmed that
correction. Final session20833 exited0 (c47ebd/fd3d63): direct human/worker
cancellation passed29.99s and stopped leased/retryable cancellation passed31.16s,
four modes each, both owned PostgreSQL processes joined normally. Grouped worker
and actual Node race checks also passed9.859s (5a370d). This closes the bounded
retryable and observed release-drift rollback checks. Leased cancellation-to-
settlement composition, version exhaustion, runtime scheduling/restart and live
gates remain open. No production promotion or push.
