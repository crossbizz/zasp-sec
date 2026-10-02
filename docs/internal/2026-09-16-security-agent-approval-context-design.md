# Persisted approval context, M7A-88/89

Status: implemented locally with registered54 SQL/repository, client/UI, browser
display and three temporary-policy browser decision branches verified. Unpublished;
controlled-IdP fresh-auth prompting/refusal/recovery now passes; live identity and
external release gates remain open. See the authoritative
release checkpoint for bounded evidence. The original scope is unchanged.

Original gap: Protect/Approvals lacked action/agent/target/requester context and
explicit reason/risk detail. The implementation below adds those fields while
preserving existing expected effect, evidence, TTL and decision authority.

## Decision

Add optional `approval_context` to approval list/detail GETs only when exactly
one `X-Zasp-Approval-Context: v1` header is present. Preserve legacy response
shapes and decision receipts. After a decision, reload context through the
existing scoped GET only after the receipt resolves; never replace the retained
mutation's version or intent by preflight refetching.

The context contains `agent_id`, `action`, nullable `target_id`, `plan_hash`,
`catalog_version`, `requester` (`state: available|withheld`, nullable `id`),
`reason` (`code: operator_approval_required`, `source: persisted_step`),
`risk` (`class: low|containment|destructive`, `source: action_catalog`), and nullable
redacted `rationale` with the existing available/withheld semantics. Display the
reason as "This persisted plan step requires operator approval." It is not an
invented trigger diagnosis. AI rationale remains separately labeled and cannot
authorize a decision. Catalog risk is not a historical provider risk assessment.

Only valid product IDs can be public requester IDs. Scheduled runs store worker
labels, not necessarily user IDs; arbitrary requester text is withheld, never
classified as a user or system merely from its spelling. Do not expose emails,
provider names, tokens or arbitrary stored text. Target comes from the approval's
bound plan step, never inferred from the first evidence ID. Missing legacy
arguments yield target unavailable, not a fabricated identifier.

## Authority and compatibility

Reuse the registered54 run-context authority for exact full-scope/run/plan/step
validation and safe selected arguments. Bind the approval's stored plan hash to
that plan before projecting context. Validate approval id, run id, step id,
action, authorization, expected-effect compatibility and TTL. Fail closed on
duplicate/missing/mismatched bindings. Keep SQL page order, limit and cursor
unchanged. Return only the selected step, not every run step per approval.

New private functions use the `zasp_production_security_agent_run_context_`
prefix so54's existing function fingerprint includes their bodies, owners and
ACLs and rollback removes them. Grant only the API role entry points; no direct
table grants. Schema53 remains unchanged. Extend54 only while unpublished and
recalibrate its compiled pin; a published54 would require a new migration.

Unauthenticated/unauthorized identities must fail through actual HTTP middleware
and scoped repository paths. A database API login alone is not user-session
authorization evidence. No permissions or approval freshness rules change.

## Alternatives considered

Client-side joins were rejected: they introduce per-approval requests and cannot
read stored requester/approval-plan binding. Inferring target or risk from labels
was rejected because labels are not authoritative keys. A bounded SQL projection
keeps consistent snapshot semantics and allows the existing strict API decoder
to refuse malformed evidence before React renders it.

## Acceptance

Cover all four actions, old-server/header compatibility, page cursor ordering,
same-org environment collisions, altered approval plan hashes, withheld unsafe
requesters/rationale, unauthorized list/detail absence, and unchanged decision
freshness/idempotency. Mount the actual UI through the real API/client with owned
fixtures and mark it as display proof. Existing live-provider/advisory/deployment
gates remain external; local fixtures cannot promote either task to production.
