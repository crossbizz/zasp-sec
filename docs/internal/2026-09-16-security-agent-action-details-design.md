# M7A-87 persisted action details design

Status: locally implemented with grouped component evidence; full acceptance,
release and production availability remain unproved. See the September16 release
checkpoint and implementation plan for verified coverage and remaining gaps.
Original requirement: show every step's state, redacted arguments, result,
TTL/rollback and verification. Protected arguments must never render.
This extends the real run-detail flow; it does not replace any original task.

## Original gap

`SecurityAgentExecutionStep` exposes step_id/action/state/version plus optional
outcome_id/result_digest. RunDetail renders action/state/outcome ID and a run-level
verification label. Neither that contract nor the UI supplies safe arguments or
per-step TTL/cleanup evidence. Approval TTL is insufficient: autonomous actions
can lack approvals, and approval expiry is not containment expiry.

Persisted authority already exists in `zasp_security_agent_plans.plan->steps`,
`zasp_security_agent_effects`, `zasp_security_agent_controls` and temporary/session
policy target rows. Plan producers in migrations18/21/22/23/24/33 use fixed action
keys and explicit target/TTL fields. API roles cannot directly read these tables.

## Decision

Add independently negotiated `X-Zasp-Action-Details: v1` and an optional top-level
`action_details` array on run detail. Missing, repeated or unsupported headers
preserve the existing response; negotiation is independent of budget and rationale
headers. Do not add unconditional fields to strict legacy execution-step objects.

Project from a private authority-owned SQL envelope after the existing authorized
full-scope read. Bind organization/workspace/environment/run, displayed plan hash,
step ID, index and action before assembling display fields. Refuse ambiguous
bindings, duplicate steps, unknown action keys and malformed selected values.
Do not fall back to an unrelated receipt, another tenant or a newer definition.

Keep schema53 unchanged. Because54 is still unpublished, extend that candidate's
private projection and recalibrate its compiled fingerprint as one action-details
feature batch. Repeat affected54 registration, trust, drift and rollback checks
against the new pin before publication. Earlier pin results remain historical,
not current-release evidence. If54 becomes published before implementation, stop
and use a new migration instead of rewriting a published release.

## Display contract

Each entry has a step_id matching exactly one existing execution/plan step, typed
arguments, persisted result state/IDs/digests, nullable TTL, rollback information
and separate verification evidence. Preserve plan order. Unknown or legacy
evidence is explicit unavailable data, never success or zero by default.

Arguments are a fixed allowlist per action, not arbitrary JSON rendered with a
generic pretty-printer:

| Action | Potential display fields, only when persisted and valid |
| --- | --- |
| update_finding_response | target_id, expected_version, target_status=under_review |
| create_temporary_policy | target_id, mode=block, scope, ttl_seconds |
| isolate_session | target_id, session_id, device_id, scope, ttl_seconds |
| revoke_integration_connection | target_id, integration_id |

IDs must be valid product IDs and retain the SQL binding to the authorized plan.
Versions are bounded positive integers; containment TTL is60..3600 seconds.
Unknown argument names are omitted at the private SQL boundary and never logged.
Credentials, tokens, authorization headers, credential references, provider URLs,
raw policy payloads, signatures and arbitrary model strings are never public.
Go validates the already-allowlisted projection before constructing public types.
Tests must place sentinel secrets in every discarded field and assert absence
from serialized HTTP, error text and rendered DOM.

Result state comes from the scoped effect row, with existing outcome ID and digest
when recorded. No effect is distinct from unknown_outcome. A digest alone is not
a successful result. Do not infer per-step verification from the run's aggregate
state. Direct verified effects provide verified evidence. Policy/session effects
also need matching durable apply/cleanup target evidence; a cleaned effect with
no applied target must not be presented as proof of successful containment.

TTL is the persisted step TTL, not current definition configuration and not the
approval deadline. Show control expiry separately when actual controls exist.
Rollback reports actual cleanup_pending/cleaned/cleanup_failed evidence and action
support. Connector revocation is not reversible; finding-state restoration must
not be advertised as automatic rollback merely because its catalog is reversible.
Missing cleanup evidence is unavailable/not started, not completed.

Implementation refinement: stopped partially applied work can enter
`cleanup_pending` without an outcome/digest pair. The public result preserves that
absence. A leased cleanup with existing cleanup targets is pending even when
application was never verified; application and cleanup evidence stay separate.
The assembled budget-aware claim path is exercised against owner-seeded histories,
not live gateway delivery.

## Verification required before acceptance

- Literal projection tests for all four actions, unknown fields, secrets, invalid
  IDs/scalars, duplicate steps, wrong plan hash and inconsistent effect identity.
- Real PostgreSQL/API tests with tenant/environment/step collisions, unauthorized
  principals, null legacy data, multiple steps and actual policy cleanup states.
- Exact-header compatibility tests with independent existing negotiation headers.
- Generated OpenAPI/types and strict client decoder checks, including omission on
  older servers and refusal of contradictory or extra public fields.
- Mounted UI tests for every display state, preserved ordering, unavailable
  evidence and protected-argument absence. Real browser/API display acceptance
  with honestly labeled fixture sources; no planner/provider execution claim.
- Affected schema54 release/consumer/rollback checks, grouped independent review,
  UI build, release gates and explicit publication. Component proof stays separate
  from live-provider, deployment, scale and operational acceptance.

No availability count or M7A-87 completion claim follows from this design.

## Source-audit refinements and binding prerequisite

The original requirement at plan lines4100-4103 remains the acceptance boundary.
Existing run-detail validation requires matching array lengths and step/action
membership but formerly permitted duplicate IDs. The repository decoder now
rejects duplicate plan IDs and duplicate execution references (RED c73724,
grouped race GREEN5d5ac0, independent source review with no blocking finding).
This establishes unique membership, not positional execution ordering: the UI
must join details by step ID and render in persisted plan order.

Policy target state `verified` is an authority-recorded result. The finish
functions in migrations22/24 validate stored envelope digests, credentials and
targets before persisting it; it must not be labeled as a newly observed gateway
decision or live provider proof. Show its evidence source explicitly. Derive
application verification only when there is at least one matching apply target
and every matching apply target is verified. A missing effect or target set is
unavailable evidence. A partial target set must never become overall verified.

Cleanup has a separate authority outcome: migrations22/24 can record `cleaned`
when no active gateway target remains, without a cleanup target envelope.
Display the recorded cleanup state without claiming a verified cleanup envelope
or prior successful application. If cleanup targets exist, expose their recorded
verification separately from the apply target evidence. Keep original TTL and
actual expiry distinct; `updated_at` is reused as scheduled cleanup time by these
workers and is not a generic verification timestamp.
