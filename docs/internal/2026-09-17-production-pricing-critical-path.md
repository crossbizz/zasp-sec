# Production planner pricing: remaining critical path

Current implementation batch: request-binding design and executable plan are
recorded in2026-09-17-planner-request-binding-design.md and
2026-09-17-planner-request-binding-plan.md. /root/planner_request_binding owns
the coherent Prepare/reserve/Dispatch interface and all controlled crash-hook
adaptations. Root found database parent tests require Go inside execution;
explicit validated prebuilt-binary support is included for owned cached-PG
acceptance. No planner code is accepted yet, no positive production pricing
authority is enabled, and no component-only row is promoted.

Updated after isolated request-binding component verification. No availability promotion.

The remaining gap is both code and external authority. Production
prepared PlannerBudget still returns unknown caps for the durable stop before
a paid call. Prepare now builds and owns the exact request body before
reservation, and the worker dispatches that retained object once after the
existing permit checks. Local tests establish this component behavior; owned
database and crash acceptance remain controller-owned.
SQL validates worker-declared limits but does not look up an approved pricing
catalog. Policy identity is per reservation, not pinned to the run snapshot.

The request-binding prerequisite is implemented in the isolated worktree and
awaits independent review. Missing authority still reaches reservation with
unknown caps, without an outbound call. Positive typed bounds exist only in
_test.go wrappers. The internal type checks consistency against request identity,
model, billing unit, profile, policy, expiry and maxima; those checks do not
establish approved pricing provenance. Production constructors accept no test
authority or operator price override.

Production activation still needs approved exact-model/account/route
token and charge bounds, including framing/schema/reasoning and applicable fees,
policy provenance/validity, and a run-level policy-pinning decision. Arbitrary
operator maxima, public rate snapshots or a verified=true flag are not proof.
No paid/provider calls, new credentials or online evidence disclosure are
authorized by this local implementation plan.

Preserve original M7A-49/95/96 scope and component-only status. The preparatory
work is not a substitute for actual supported production pricing or end-to-end
production readiness. Full details and source references are retained in the
recovery SDD planner-pricing-gap-audit.md.
