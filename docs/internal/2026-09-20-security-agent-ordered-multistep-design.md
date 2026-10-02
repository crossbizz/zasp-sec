# Security Agent ordered multi-step execution design

Status: implementation design, autonomously selected under the standing instruction to continue without an approval pause.

Original scope: M7A-03 and M7A-49, with the downstream M7A-95, M7A-96, and M7A-100 journeys left unchanged. This design does not reclassify any ledger row or claim live production proof.

## Current gap

The version-one domain plan already represents ordered typed steps, and the production tables already persist step indexes 0 through 99. The deployed planner/worker authority still narrows every run to one step:

- the repository accepts only one allowed action, target, evidence item, and `maximum_steps = 1`;
- planner submission is scalar and reconstructs one step;
- the worker rejects every candidate whose step count is not one;
- specialized export, existing-test, and Attack Lab authorities deliberately require one step;
- action completion paths can finalize the parent run, so merely removing the length checks could dispatch a successor after the run was already terminal.

Budget release 53 already provides per-step reservations, deadlines, token/cost accounting, Organization concurrency locking, and conservative handling of unknown provider usage. Those controls must be reused, not duplicated.

## Decision

Add a release-61 generic ordered-plan authority while preserving all specialized single-step paths unchanged. A generic ordered plan is a linear dependency chain. Step zero has no predecessor; every later step depends on the immediately preceding step. Linear ordering is the product contract for this release and avoids an unreviewed general DAG scheduler.

The first and only release-61 action sequence is a supervised `create_temporary_policy` step followed by `run_test`. This is the original containment-and-retest journey. Other combinations remain unavailable until their action-specific completion contracts are designed and verified.

The durable dependency record is an Organization-scoped table keyed by run and step. Each row binds one step to its predecessor and the exact typed receipt it must consume. The relation is derived and inserted in the same transaction as the immutable plan and step rows. JSON order or a mutable effect state alone is never sufficient authority.

For the first pair, step zero produces an immutable `temporary_policy_applied.v1` receipt. It binds tenant, run, plan hash, predecessor step and input digests, policy deployment/control identity and version, effect outcome/result digest, application time, and expiry. It is eligible only while the temporary control is authoritatively active and its effect is `cleanup_pending`. Pending application or verification waits; it is not terminal failure. Rejected, failed, expired-before-application, stopped, cancelled, and unknown application outcomes never satisfy the dependency.

Step one produces an immutable `existing_test_settled.v1` receipt with the linked test invocation, authoritative snapshot/proof digest, settlement generation, and outcome. A successful non-reproduction leaves the parent `contained` while the temporary control remains active. TTL cleanup is owned by the existing cleanup lane and moves the aggregate run to `remediated` only after the control is durably cleaned. Reproduction, unknown settlement, failed cleanup, or missing evidence moves the parent to the existing conservative `needs_human` or `failed` state and never suppresses required cleanup.

The new authority uses the existing plan version 1 because ordered indexes are already the published v1 contract. It adds no optional planner field that old validators could ignore. A multi-step candidate is accepted only when:

- its count is between 2 and the exact definition and budget maximum;
- indexes are contiguous from zero;
- every action is in the exact definition allowlist and every target is derived by server authority for that action;
- each step receives its own deterministic authorization result; an approval row is created only when that step becomes dependency-ready;
- step zero alone can become `authorized` or `waiting_approval`; later steps remain `blocked` until their predecessor has the exact valid typed receipt;
- plan, steps, dependencies, approvals, audit records, and budget linkage commit atomically under the current lease and tenant locks.

The executor claims only a ready step. Every release-61 claim, approval, cancellation, settlement, and progression path uses one audited lock order: Organization advisory/admission and budget authority first, then run, plan, step/dependency/receipt, approval, effect, and stable reservation. Release-61 paths do not call legacy approval or settlement functions whose lock order or parent-state behavior conflicts with this order.

Progression makes exactly one successor ready after validating its typed predecessor receipt and current control state. If the successor needs approval, progression creates its deterministic pending approval and leaves the parent `waiting_approval`; an approval cannot be decided while its step is blocked. The release-61 approval function records only the ready step's decision, rechecks dependency, authorization, expiry, stop, and budget state after lock waits, and never queues a different step. Failed, stopped, cancelled, expired, unknown-outcome, or definitively unverified predecessors block all descendants and move the parent to its existing conservative terminal state. A terminal parent can never be reopened by progression.

Existing idempotency remains `(organization, workspace, environment, run, step, action)`. Restarting a worker can reclaim the current ready step or observe its existing effect; it cannot create or authorize a duplicate successor.

## Compatibility boundaries

- Evidence export, existing-test, rerun-test, and Attack Lab definitions remain exact single-action definitions until their settlement functions are explicitly adapted to the progression authority.
- Public API validation may accept generic multi-action definitions only for action combinations whose adapters implement the progression receipt. Unsupported combinations fail at definition activation, not after a run begins.
- Release 60 remains immutable. Release 61 is additive and pins release 60 as its exact predecessor. Down succeeds only when no release-61 definition, plan, dependency, receipt, active run, or completed execution evidence exists and the schema has not drifted. Otherwise it refuses rollback; release-60 executors must never inherit incompatible work.
- No UI or API reports a multi-step run as production-available until the release-61 repository, worker, settlement, restart, cancellation, tenant-isolation, and UI build gates pass together.

## Verification cadence

Testing is grouped by behavior rather than repeated for every bookkeeping microtask:

1. Write one focused failing test for each observable contract before its implementation.
2. At each implementation packet boundary, run one affected Go/SQL/race batch and map its assertions to the original task IDs.
3. After independent review, rerun only affected cases plus checks invalidated by shared schema or contract changes.
4. Run the full release gate and UI build once on the reviewed push candidate. A failed external advisory or deployment gate remains an explicit external block and is never replaced by fixtures.

## Required proof

- A two-action generic definition produces two persisted steps and one exact dependency.
- The second step cannot be claimed before the first effect is durably verified.
- Approval, authorization, expiry, stop, cancellation, and budget checks are evaluated per step.
- A blocked approval cannot be decided early; mixed autonomous/approval-required steps and approval expiry while a predecessor runs remain fail closed.
- Failure or uncertain settlement of the first step creates no second-step effect.
- Worker restart and replay produce neither a duplicate effect nor a duplicate approval.
- Concurrent progression versus approval, cancellation, and budget admission follows the shared lock order and rechecks expiry after waits.
- Clean release-61 rollback passes; drift, active work, completed work, and retained receipts all refuse rollback.
- Cross-Organization reads, claims, progression, and cancellation fail.
- All legacy single-step action batches remain green.
