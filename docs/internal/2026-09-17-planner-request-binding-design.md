# Planner request binding: implementation prerequisite

Status: implemented in the isolated recovery worktree, with local component
race tests passing; independent review and owned-database crash acceptance are
still pending. This is not production acceptance. Full728 scope remains unchanged.
This extends the recorded production-pricing critical
path; it does not replace supported production pricing with synthetic limits.

## Decision and alternatives

Ruling: prepare an immutable provider request before budget reservation and
dispatch that same prepared value after the existing permit checks. The prior
flow built bytes inside Plan after reservation, while PlannerBudget took no
context. Prepare now owns the body string and cloned validation context before
reservation; the worker retains that same object through its permit checks.
Cost if wrong: interface and fixture adaptation; no billing authority is enabled.
The user's standing instruction authorizes routine design decisions without
another approval pause. Product activation and external spending are separate.

Keeping the current interface and adding configured maxima is rejected: neither
request binding nor authoritative charge bounds follow from operator numbers.
A new SQL policy registry is a later possible activation design, but doesn't
solve serialization after reservation and introduces migration scope before its
trust/distribution requirements are settled. Request preparation is required
under either eventual authority design.

## Contract

The production planner prepares once from the validated tenant/run context and
a single configuration snapshot. The prepared value owns immutable request
bytes, model, completion limit, data-policy identity and routing/endpoint
identity. Its body digest is distinct from the database's canonical input
digest. Never replace or relabel that canonical digest.

The production budget path requests verified limits for this prepared value.
An internal typed verified-bound result associates a pricing-policy identity,
model, billing unit/profile, validity and supported token/charge bounds with
the exact request identity. A bare descriptor or nonempty policy name is not
verified authority. The initial production authority supports no descriptors,
so missing authority continues through the existing durable unknown-budget stop
without an outbound call. Controlled authorities remain test-only. There is no
new environment flag, file of arbitrary prices or verified=true activation path.

Reservation retains stable run/attempt identity, canonical input digest, SQL
permit equality/version checks and expiry. The local prepared value is retained
across that reservation and consumed directly for dispatch. No second Prepare
or serialization is allowed afterward. A changed context, model, policy or
route cannot substitute a different body under the permit. Do not expose body
buffers to callers that can mutate them. Closing/cancelling the planner prevents
dispatch even if preparation already succeeded; credentials stay out of the
prepared value, hashes, logs and persisted evidence.

Keep existing deadline propagation, unknown-usage handling, no blind paid retry,
and durable settlement before result acceptance. A response received before
cancellation still uses the bounded settlement context. Unsupported preparation
or authority must not fall back to the old unbound production dispatch path.
Existing controlled fixtures must be adapted or explicitly isolated so their
declared caps cannot masquerade as production pricing support.

## Scope and acceptance

Expected implementation surface is the worker planner, budget runtime, focused
tests and a small internal policy-boundary type. No SQL fingerprint, UI,
deployment configuration, account/provider choice or production ACL change.
The implementation plan must resolve the exact interface shape against all
planner implementations before editing, including test fixture adapters.

Grouped executable acceptance must show preparation precedes reservation;
transport receives exactly the prepared bytes including schema/limits;
caller context mutation cannot change them; config/route drift cannot substitute
a request; permit mismatch/expiry/cancellation produce zero sends; missing,
unsupported, expired and wrong-model/unit/profile authority produce zero sends;
and unknown usage/settlement-before-accept remain unchanged. Use controlled
transports and synthetic authority only as component evidence. Retain the
existing owned-database durable-stop acceptance when that boundary is exercised.

## Implementation dependency map

The worker interface is now Prepare(context, contextValue) plus Close. The
returned prepared object has PlannerBudget and one-shot Dispatch. These
consumers were adapted in the same batch:

- security_agent_runtime_test.go: securityAgentPlannerStub records context and
  supplies controlled reservation limits. Keep its context and error assertions.
- security_agent_budget_runtime_test.go: budgetRuntimePlanner implements Prepare
  and returns an explicit dispatch wrapper that records ordering and cancels
  after response. Both hooks remain active without inherited method promotion.
- security_agent_budget_provider_postgres_test.go: budgetFixturePlanner embeds
  production but overrides declared limits only in tests. budgetCrashPlanner
  implements Prepare with an explicit dispatch wrapper that exits before send
  or after exactly one captured response.
  Adapting only the production method would bypass these process-loss boundaries.
  The hooks now run at prepared dispatch and retain exit86 semantics, exact
  provider-call counts and post-commit settlement crash behavior.
- production_combined_budget_fixture_test.go compares fixture limits with the
  production unknown-budget boundary. Update it to assert the corresponding
  prepared-request boundary, without installing fixture authority in production.

Local execution covers order/cancellation hooks, exact captured body bytes,
owned actions/targets/evidence/reference values, configuration drift, concurrent
dispatch, permit refusals, controlled-bound mismatch/expiry and production
unknown-budget reservation. ExistingTestReference has only scalar string/int64
fields today; its owned value copy is deep for that shape. The combined fixture
tests exercise all six action types. One owned-PostgreSQL helper selected by the
grouped regex skipped without its parent fixture, and is not acceptance evidence.
Root still owns the no-skip database and exit86 process-loss runs.

The internal cost-bound type has no production producer. Its consistency checks
do not verify price provenance. Only _test.go creates positive controlled bounds.
Dispatch admits at most one send after checking the current planner state and
identity; Close can still run during an already-admitted request without waiting
on network I/O. Plan remains a direct-call convenience over Prepare/Dispatch,
and the worker interface has no Plan fallback.

## Still required for the full product

This batch closes a missing implementation prerequisite only. Actual production
pricing still requires approved applicable account/model/route charges and
enforceable token bounds including framing, schema, reasoning and fees; policy
provenance, validity, distribution/revocation; and run-level policy pinning.
Those external and schema decisions remain explicit gates. No original task
is promoted merely because these component tests pass.

Source checked: security_agent_budget_runtime.go (planWithBudget),
security_agent_planner.go, security_agent_prepared_plan.go and
security_agent_cost_policy.go, together with the four adapted fixture files.
Exact commands, failures and source identities are in this batch's task report.
No SQL, UI, deployment, ACL, lease or full728 scope changed.
