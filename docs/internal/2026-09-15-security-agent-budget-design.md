# Durable Security Agent budgets

Status: unpublished v53 migration/CLI candidate with local registered-worker
evidence; accounting, full lifecycle and production acceptance remain incomplete.
See the evidence checkpoint for its exact tested scope.
Scope: original M7A-49 and M7A-95, preserving the later M7A-96 responder flow.
Evidence: [reproduced gap](2026-09-15-security-agent-budget-gap.md).

## Decisions

Use PostgreSQL as the authority for limits, admission, reservations, usage and
stop state. A process-local manager or worker-local elapsed timer cannot survive
reclaim. Use the existing registered worker roles, scoped product IDs and
lease/CAS checks. No new provider call or cloud resource is authorized here.

The run gets an immutable limit snapshot and database start/deadline on first
admission to planning. Waiting for approval after admission consumes elapsed
time; an unstarted queued run does not consume execution duration. Reclaim does
not reset the start. Existing running rows must be conservatively backfilled
from their persisted creation timestamp during migration, not granted a fresh
deadline. If original limits or cost authority cannot be reconstructed, stop
new work with a visible needs_human reason. Existing cleanup remains eligible.

Legacy runs have no durable record of prior planner usage. Even a recoverable
definition is not evidence of unused allowance, so upgrade stores a sticky
budget_usage_unknown stop for previously started active work and revokes its
worker lease. Recover exact-version historical limits when available, otherwise
use the same-version current definition. Missing or malformed values remain
NULL only in stopped snapshots; a database constraint forbids activating such
an incomplete snapshot. Never substitute zero, a newer definition, or a fresh
start timestamp. Contained run results and existing control/effect records are
preserved; cleanup execution and old action-route fencing still need their own
acceptance. The migration must hold its cutover locks and backfill in one
transaction, failing immediately if legacy work prevents lock acquisition.

Keep a per-organization admission row locked before run/step rows, with a unique
scoped run admission receipt. Enforce the least applicable configured concurrency
ceiling across admitted runs and the incoming definition. Exact replay does not
consume another slot. Terminal completion releases a slot once; stale workers
cannot release or reopen another generation. Cleanup does not need a new slot.

Track step reservations by scoped run and stable step ID, not delivery attempt.
Check budget authority in the same transaction that permits the step/effect to
start. Recheck the deadline at actual apply/dispatch, including an approved run
that waited or restarted. Completion/reconciliation cannot authorize another
start. A rejected budget decision must commit the sticky stop before returning;
raising an exception that rolls back the stop is not acceptable.

Persist provider reservations before outbound planning, keyed by scoped run,
attempt and a canonical input digest. Retain unknown-outcome reservations across
process death. Settle valid usage once using the provider response digest;
conflicting settlement fails closed. Missing/malformed cost or token usage is
unknown, never zero. Paid dispatch needs a configured verifiable request-cost
upper bound; without it the run stops before the call. No guessed model prices,
price-preference-only guarantees, automatic key creation or new spending.

Use integer nano-credits for the current OpenRouter cost authority, with an
explicit `openrouter_credit` unit. A definition's new
`max_ai_cost_nano_credits` is between 1 and 1,000,000,000,000 inclusive. The
product exposes the unit; it does not label credits as dollars. Parse provider
decimal cost without float conversion, round upward to nano-credits, reject
negative/nonfinite/overflow values and reconcile prompt+completion=total tokens.
Request-cost upper-bound configuration must declare the same unit and model.
No inference is made that OpenRouter account charges include separate BYOK bills;
such a billing profile cannot pass the supported-cost-policy gate without
separate bound/accounting support.

Older definitions lacking explicit cost authority remain readable but cannot
activate new paid planning. Show budget configuration required in API/UI. Adding
a field is not permission to choose or spend a tenant's budget. All new run
snapshots bind the exact definition and cost-policy version. Changing a
definition cannot enlarge an existing run's allowance.

Budget stop closes new planning/authorization/apply while allowing settlement,
readback, rollback and expiry cleanup for already-started effects. Unknown
external effects remain inconclusive; a budget stop must not relabel them safe.
Keep supervised approval requirements for policy/session/revoke operations.

Public run detail includes an optional `budget_stop_reason` containing only one
of the five durable budget codes. Omission means no recorded stop or a legacy
server, never proof of unused budget. Project the scoped budget row through the
existing authorized run-detail query; do not expose worker lease, provider error
text or raw accounting payloads. Sticky reasons can coexist with retained
contained results and pending cleanup. UI guidance must not offer to reset the
run by editing its definition.

## Migration and compatibility

Include budget_stop_reason only when the caller sends exactly one
`X-Zasp-Budget-Details: v1` header. Absent, duplicate or unsupported versions
preserve the original seven-field response for cached strict clients. New clients
send the opt-in and accept legacy omission, allowing either client/server deploy
order. Validate repository data before applying the response projection; opt-in
never grants authority or resets limits. Keep all responses no-store. Verify the
mounted browser/auth/proxy path before release; transport and local handler
checks alone do not establish live rollout readiness.

Use a new forward migration after the currently reserved v52 audit migration;
do not edit historical v18-v33 SQL. Add schema/readiness metadata and tests for
new tables, functions, role grants and every guarded entry point. Old worker
entry points must fail closed or hit the same budget guard; merely adding a new
wrapper while leaving bypassable old execute functions is insufficient.
Up/down and readiness must explicitly handle changed inherited fingerprints.
Rollback refuses active reservations/admissions or unsettled effects that the
older runtime cannot account for. Cleanup remains possible throughout rollout.

## Acceptance

Independently exceed steps, duration, tokens and cost. Test equality and one-unit
overage, two definitions/environments in one organization, two organizations,
simultaneous workers, exact/conflicting replay, approval delay, expired lease,
process restart, missing usage, unknown response outcome and partial effects.
Check durable stop plus zero subsequent provider/action starts, with a working
positive control. Verify cleanup after stop on the actual gateway-policy path.
The existing failing claim test must use the persisted budget clock once the
new authority exists, not mutate an unrelated legacy timestamp.

Use focused RED/GREEN while implementing, one affected-suite/review checkpoint
per coherent batch, then full required UI/build/release gates before a push.
No local fixture earns live billing/provider/deployment proof. The two original
IDs remain component-only until their own requirements and publication are
verified. No automatic production promotion of dependent tasks.
