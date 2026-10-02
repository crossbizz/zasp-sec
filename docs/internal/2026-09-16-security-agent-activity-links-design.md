# M7A-90: scoped Security Agent activity links

Status: implementation in progress, component-only. No production completion claim.

## Required outcome

The original M7A-90 requires finding, attack-path, runtime-session and audit records to link to a Security Agent run and back. Exact IDs and organization/workspace/environment scope must survive navigation, reload and browser history. A list landing page is not an exact-record link. All four entity types remain required.

## Decisions

This is architectural work across route state, detail views and relationship reads. The user authorized autonomous decisions and feature-batched verification. No separate approval stop is required for these in-scope decisions.

Use typed, same-origin relative links with `entity_id`, `organization_id`, `workspace_id`, and `environment_id`. Routes determine entity kind: finding `/violations`, attack_path `/exposure/attack-paths`, session `/investigate/sessions`, audit `/administration/audit-log`, run `/protect/security-agents`. All IDs are canonical lowercase UUID-v4 Product IDs. Scope is an assertion against the authenticated session, never an instruction to switch it. Reject duplicate, missing, extra or invalid activity parameters; reject fragments, absolute URLs, protocol-relative URLs and path normalization tricks. A plain route remains a plain route.

Keep query state separately from pathname in the app shell. Capability checks still use the pathname. A mismatched or invalid activity link shows a safe error without fetching the requested record. Scope/session invalidation aborts detail requests and hides previous data synchronously. URL state does not authorize writes or bypass retained mutation locks.

Existing registered detail APIs should load findings, paths, sessions and runs directly by ID. Do not scan a first list page to locate the record. The audit browser currently has only an organization-wide page API; add an authorized exact audit-record read before enabling audit detail links. Preserve existing organization-wide audit browsing semantics. Activity relations themselves must match the full selected scope.

Server-authorized relationships are authoritative. A run's persisted trigger receipt can establish a finding/path/session trigger link. Validated action arguments can establish typed action targets. Generic evidence IDs cannot establish types. Reverse reads must query those persisted relationships under the same principal and scope checks as the run detail, with bounded cursor pagination and deterministic ordering. Audit relations must be established from known persisted run/step/approval receipt associations, not arbitrary metadata strings. Audit record disclosure requires audit.read. Missing, forbidden, ambiguous or unsupported relation authority stays unavailable, never guessed or silently empty.

The current public trigger enum is `finding | attack_path | runtime_decision | manual`, not the manual-run input enum. Registered migration `0024_security_agent_session_isolation.up.sql:162` writes the scoped session ID as the automatic runtime-decision receipt's trigger ID; lines 198 and 208 validate/persist the same session association for explicit runs. Canonical `runtime_decision` receipt IDs therefore link to runtime sessions. Manual trigger IDs do not establish an entity type and remain unlinked. The existing strict decoder rejects legacy non-Product-ID trigger values. Missing run rationale is `null`, not an invented `missing` variant.

Relation-query source check: migration `0022_security_agent_temporary_policy.up.sql:245` builds `create_temporary_policy.target_id` and `scope` from the environment ID, not a finding ID. Never classify that action target as a finding. Its finding association comes from the typed trigger receipt (same migration lines193–195). `update_finding_response` targets can establish finding links; `isolate_session` uses its validated session ID. Connector-revocation targets and environment targets must not be mislabeled as one of the four required entity kinds. The trigger table has a unique full-scope run association, but its primary index leads with definition ID before trigger ID; reverse-query indexing and bounded pagination require explicit attention.

### Candidate-query access paths

Candidate-query access paths in unpublished54 include a full-scope typed-trigger
B-tree and a JSON-path GIN index over retained plan documents. The GIN index
supports existing typed action containment; full tenant predicates and later
envelope validation remain required. Finding and session queries use separate
mutually exclusive UNION branches so generic plans can use containment access.
A global GIN index is not proof of constant
tenant-local work when many scopes share a target. High relation fan-out,
full-scope integrity coverage and nested envelope costs remain separate gates.

### Exact Security Agent audit authority

Security Agent audit rows live in `zasp_security_agent_audit`, outside the general audit source union in migration 52. Their `actor_id` can identify a worker, so it must not be cast to the general audit API's human Product ID. Preserve the general audit API and use a distinct Security Agent audit schema: `id`, `run_id`, `organization_id`, `workspace_id`, `environment_id`, `actor_reference`, `event_kind`, `correlation_id`, `occurred_at`. Do not expose `body`, digests or invented actor types.

The exact database lookup is `zasp_production_security_agent_run_context_audit(org, workspace, environment, principal, session_digest, csrf, audit_id)`. It belongs to unpublished migration 54, is owned by `zasp_discovery_authority`, denies PUBLIC execution and grants only `zasp_security_agent_api`. It checks pinned release readiness and the registered API principal, then reuses `zasp_audit_export_require_browser` for the exact browser session, active membership and current `view_audit` permission. Metadata supplies readiness arguments only; the readiness function compares them to compiled pins. This avoids a self-referential fingerprint in the new function body.

The lookup joins the exact audit row to a non-simulated run using all three scope IDs and the persisted `run_id`. Missing records return no rows. Malformed retained projection values fail closed. The application must retain its independently compiled v54 verifier before calling this SQL function; metadata-fed SQL checks do not replace that trust root against coherent replacement of SQL and metadata. This database contract is the first part of batch 2; HTTP/client wiring, paginated bidirectional relations and complete browser acceptance remain required.

The repository method is `GetSecurityAgentAuditEvent(ctx, identity, auditID, sessionDigest)`. It requires a browser identity, CSRF, `view_audit`, a canonical audit ID and a nonzero SHA-256 session digest. It probes the adapter's independently compiled v54 release before any record query, with no legacy fallback. Reads have a five-second deadline. Responses reject duplicate/extra fields, invalid Unicode scalars, foreign IDs/scope, invalid worker references and non-UTC or sub-microsecond timestamps. The planned public route is `GET /api/v1/security-agent-audit-events/{id}`, browser-only with `view_audit`; it must derive the digest from exactly one authenticated session cookie, accept neither a request body nor query parameters, and return `Cache-Control: no-store`.

## Alternatives considered

### Bidirectional relationship protocol

Use explicit per-kind reads so denied audit/session authority cannot look like an
empty authorized page: `GET /api/v1/security-agent-runs/{id}/activity/{kind}` and
`GET /api/v1/security-agent-activity/{kind}/{id}/runs`, with kind restricted to
`finding | attack_path | session | audit`. Both are browser-only, require current
`view`, and additionally require `investigate_sessions` for session relations or
`view_audit` for audit relations. Reauthorize the exact browser session, current
membership and effective scope in SQL. Do not rely only on cached capabilities.

Forward non-audit targets come from the validated v54 trigger/action projection;
audit targets come from exact scoped audit `run_id` rows. Reverse candidate reads
union matching typed trigger receipts, matching plan action targets and (only
for audit kind) the exact audit row. Candidate plan JSON is only a query filter,
not relationship proof: each selected run must pass v54 hash/step validation and
typed argument decoding before the requested association is returned. Ignore
manual triggers, generic evidence IDs, environment policy targets and integration
targets. Deduplicate runs and targets. Legacy missing arguments or trigger context
must produce explicit partial/unavailable coverage, never proven-empty authority.

Pages are bounded to100. Reverse ordering is `(created_at DESC, run_id DESC)`;
forward target ordering is canonical ID ascending. Signed cursors must bind the
operation, direction, entity kind/ID, full scope, principal, limit and position.
SQL receives only decoded positions. Add and verify reverse-lookup indexes and
query bounds before calling this feature production-ready; preserve rollback
and compiled fingerprint checks. All four kinds and both directions stay required.

Audit page access path: unpublished54 adds a B-tree over organization, workspace,
environment, run and audit IDs, matching the forward query's equality prefix and
page order. Fingerprint its owner/definition/validity flags and remove it on
rollback. The original audit primary key only leads with organization/audit ID.
The local10,000-row custom-plan test verifies indexed first/next pages, not
generic-plan or live capacity. Non-audit integrity coverage still scans scoped
run/plan authority in the worst case; index work alone does not close that gate.

Generic-plan cursor decision: a nullable `after IS NULL OR audit_id > after`
filter can lose the index range condition after PostgreSQL chooses a generic
plan. Use mutually exclusive first-page and cursor-page SELECT branches, each
ordered and limited to `limit+1`, then merge/order/limit the result. This preserves
the exact row set (including malformed retained IDs for fail-closed validation)
without a guessed sentinel cursor. Test the installed query text under forced
custom and generic plans for first/next pages; empty sorts for impossible
branches are harmless, sorting actual result records is not accepted here.

Client-side scanning of run lists is cheaper initially but misses paginated records and cannot prove a relationship. A generic evidence-ID link also guesses the entity type. Neither meets the original deliverable. Scope-free URLs depend on a mutable session selection and can open the wrong context after a scope change. Explicit scope assertions avoid that ambiguity without adding scope mutations.

## Verification and release

Group tests by the complete activity feature: URL contract, direct detail requests, relation API/SQL authority, UI interactions and browser navigation. Include all four record types, both directions, reload/back/forward, records outside the first page, foreign IDs, unauthorized capabilities, scope changes and stale responses. Keep focused red/green tests while implementing; do not repeat unchanged broad suites per field.

Use owned PostgreSQL and controlled browser fixtures for local integration evidence, labeled as such. Independent review occurs at the feature boundary. The UI must build before a push. Existing release/advisory/deployment gates remain required; this document does not relax them.

Self-review: all four original record types retained; no demo fallback or inferred relation; direct lookup distinguished from list presence; organization-wide audit browsing distinguished from scoped activity; local evidence distinguished from production proof.
