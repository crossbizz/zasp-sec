# M7A-86 run context and rationale design

Status: component implementation and registered54 database lifecycle verified;
actual repository/HTTP routing and controlled runtime composition verified.
CLI/audit-consumer rollout and final browser/production acceptance remain open.
Original scope: show trigger/evidence, AI rationale summary and ordered plan with
deterministic authorization labels; rationale must be visually distinct.

## Decision

Extend the existing run-detail flow with an explicitly requested v1 context
projection. Keep evidence, plan ordering and authorization server-owned. Preserve
the legacy response shape for clients that do not request the projection. The
user authorized autonomous implementation decisions and feature-batched tests.

Alternatives considered: adding fields unconditionally breaks strict old clients;
reading planner receipt tables directly from the API role violates the existing
database authority boundary. Use an authority-owned scoped read function and an
opt-in HTTP header, following the budget-detail compatibility pattern.

## Source and authority

The current Go detail type in apiserver/security_agent_handler.go has seven
original fields plus optional budget_stop_reason. getRun strips the budget field
unless X-Zasp-Budget-Details is exactly v1. Repository and browser decoding are
strict. SecurityAgentsView RunDetail already renders evidence, ordered steps and
authorization. The optional contract/UI now supports trigger and rationale, but
the production repository now projects them from persisted receipts after an
uncached compiled54 release check. The tracing decorator preserves this capability.

Migration32 stores accepted planner_summary in planner receipt.response. Its
validation bounds text but does not redact secrets. The existing aigateway
RedactApprovedFields covers email, SSN and ghp_/sk- patterns and rejects password=;
it is not sufficient by itself for a public arbitrary-provider-text boundary.
Planner receipts are authority-owned and deny direct API/worker table access.

The new read must first use the existing principal-authorized run read. Join
trigger receipts on organization/workspace/environment/run. Select only an
accepted planner receipt whose response.plan_hash equals the displayed durable
plan hash and response.run_id equals the run. Do not substitute a rejected,
budget-stopped or unrelated latest attempt. Multiple matching accepted receipts
must be treated as inconsistent authority, not silently resolved by timestamp.
Later execution attempts must not erase a still-matching accepted plan rationale.

## Public contract

Request header: X-Zasp-Run-Context: v1, exactly one value. Missing, duplicate or
unsupported values preserve the old shape, independently of budget negotiation.
Optional top-level run_context contains:

- trigger: null for a legacy run without a receipt, otherwise kind/id/version
  from the scoped persisted trigger receipt, validated against existing kinds
  (finding, attack_path, runtime_decision and manual),
  product IDs and version bounds.
- rationale: null without a matching accepted receipt, otherwise an object with
  state (available or withheld) and summary. available requires nonempty text;
  withheld requires an empty summary and the UI explains that redaction withheld
  it. No model, provider, raw response, target arguments or credentials are public.

Bound input and output to500 UTF-8 bytes, reject invalid UTF-8/control characters,
and never truncate before redaction. Replace recognized secret/PII spans with
[REDACTED]. Cover existing email/SSN/token patterns, authorization bearer/basic
values, credential assignments and credential-bearing URLs. Withhold the entire
summary for private-key blocks, malformed credential constructs, or invalid
bounded text. Test the exact policy; pattern-based redaction is not a guarantee
of recognizing every arbitrary secret. Do not use a model call to sanitize text.
Raw summaries must remain out of public errors and logs, including decode errors.

The SQL function returns a private repository envelope, not the public Go detail
type. Its planner text is decoded into a separate unexported internal type and
sanitized in Go before constructing run_context. Never embed the raw envelope
in SecurityAgentRunDetail or an error. A malformed envelope fails the repository
operation with its existing stable unavailable error; an isolated malformed,
oversized or unsafe rationale yields withheld while leaving valid scoped run
data usable. Post-redaction output over500 bytes is withheld, not truncated.
Credential assignments include password/passwd, token, access_token/refresh_token,
secret, api_key/api-key and access_key/secret_access_key values with colon or
equals separators, quoted or unquoted; token/key names also accept hyphens.
Credential URLs include userinfo and those query parameter names. Bearer/basic
credentials require complete value removal; malformed delimiters cause whole
summary withholding. Preserve ordinary prose only under the documented policy.

The browser requests this projection but accepts omission from older servers.
Strict browser decoding validates the complete optional object and all enums.
Render summary as React text, never HTML/Markdown links or executable content.
Separate headings: Trigger, Evidence, AI rationale, Plan, Authorization and
execution. Label rationale as AI-generated explanation, not authorization.
Missing and withheld states are explicit; do not fabricate explanatory content.

## Migration and rollout

Create a new54 release after the existing53 budget candidate, preserving all
existing52/53 SQL and their verified identities. Introduce a scoped detail
function for54, keeping the old function and ACLs intact. Include the new function
and privileges in the release fingerprint/readiness contract. Rollback removes
only54-owned changes and restores exact53 readiness. Register54 through migration
runner/CLI, API schema validation and deployment release configuration; do not
enable an unregistered ad-hoc SQL path. Old binary/new schema behavior must be
explicitly tested under the repository's fail-closed release rules.

Release-consumer inventory includes apiserver/repository.go,
apiserver/security_agent_budget_release_database.go,
apiserver/security_agent_budget_repository.go,
apiserver/security_agent_worker_repository.go,
apiserver/security_agent_action_repository.go,
runtimeevent/production_precise_ingest_repository.go, auditexportconfig and its
API/worker factories, migrations/production_audit_exports.go and the migration
CLI. Verify fresh and warmed API, runtime ingest, planner and action adapters,
plus audit configuration/registration against54. No53 compiled identity changes.
Unsupported old binary/new schema combinations fail closed; explicitly verify
this before upgrade and restore53 compatibility after rollback. A new detail
endpoint passing alone is not54 release acceptance.

Independent design review found no Critical issue and requested these two
clarifications: private sanitization location and all-consumer release coverage.
Both are now specified. Implementation tests and final diff review remain open.

## One feature batch, complete acceptance

Focused RED/GREEN: text redaction, absent/withheld data, strict Go/browser decode,
header negotiation and UI headings/order. Then grouped real PostgreSQL acceptance
through the registered release: tenant/environment/principal denial, receipt/plan
binding across retries, missing receipt, invalid summary, unchanged authorization,
upgrade/readiness and rollback. No direct-table privilege widening.

Run OpenAPI generation/checks, affected Go/browser tests and one independent
review on the frozen feature diff. Verify mounted browser visual separation with
the real product API. UI build and required release checks remain mandatory
before a push. Keep M7A-86 component-only until all its acceptance evidence and
publication requirements are met. Local provider fixtures cannot prove a live AI
provider call or deployment readiness. This design does not complete M7A-87.
