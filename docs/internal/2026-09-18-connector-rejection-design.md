# Connector override rejection auditing

## Authority and scope

Original M8-41 requires attempted Nango/proxy/provider URL overrides to be blocked
and audited. This design closes the durable product-path gap; it does not claim
live egress, cloud deployment or the preceding M8-40 release gate is verified.
The original728-task scope remains unchanged.

The active mounted RED is defined by connector-rejection-red-brief.md. Its
result must distinguish a missing audit from wrong test authentication, missing
connector capabilities or an unrelated query permission failure. No production
code precedes that observed RED.

## Chosen architecture

Use a narrow integration-rejection operation backed by a dedicated READ COMMITTED
transaction in PostgresJSONDatabase. The pgxpool driver supplies transactions;
tracedJSONDatabase forwards this specific capability. Reuse existing registered
API authority and zasp_admin_audit's rejected outcome. Add no privilege,
migration57, SQL function or general transaction API. Missing capability fails
closed. Preserve current readiness and compiled52/55/56 identities unchanged.

Observed legacy ACL correction: release10 grants the API role CRUD on preexisting
zasp_* tables, including zasp_admin_audit; release52 preserves that existing ACL.
The registered-role fixture confirmed inherited INSERT. This design does not
claim the existing API role lacks direct access. The new rejection path uses
only the guarded transaction and adds no direct table privileges. Revoking legacy
CRUD is a separate migration/compatibility concern and is not silently bundled
into this fix. Capability-denial tests prove this product boundary, not
that existing database privileges make the entire audit table tamper-proof.

Alternatives rejected: a general middleware audit sink lacks integration target
and effective write authority; unguarded INSERT lacks fresh authorization;
successful-workflow receipts persist intent and require a successful resource
version, which is false for rejection. A separate rejection receipt table is
unnecessary for per-attempt event semantics.

This changes the database adapter boundary. Prove production driver and tracing
decorator expose it to the mounted workflow repository. The earlier release57
proposal is superseded by observed privileges and existing pgxpool transaction
support. Avoiding57 removes migration risk, not authorization requirements.

## Request behavior

Only integration create/update is in scope. Existing authentication, exact
browser scope, Origin/CSRF, manage_workflows and request-size gates remain first.
No rejected values may be echoed in responses or diagnostic messages.

Detect forbidden configuration authority attempts using the existing connector
schema, without adding supported override fields or dispatching any provider.
Unknown configuration keys remain rejected. Preserve valid generic-webhook
destination_url and its existing destination/secret-reference validation.
The complete path must cover provider_url, proxy_url and nango_url attempts,
including requests containing secret-like fields that currently exit in
ReplayWorkflow before setup validation. Never remove the secret-field filter.

Keep existing success replay and conflict semantics. An attempted hostile
configuration reusing a successful key still cannot mutate or erase the original
receipt; its conflict/rejection status must be characterized and preserved.
Do not convert unrelated database failures into invalid-input success claims.
Malformed JSON, missing preconditions, unauthenticated/unauthorized requests,
foreign targets and CSRF failures are not authorized integration-rejection audit
requests. Their original nondisclosing error paths remain intact.

Every authorized rejection audit commits before the ordinary fixed rejection
response. If the audit cannot persist, return the existing fixed unavailable
response, with no mutation or provider dispatch. Do not silently skip auditing
when a repository lacks the new capability.

## Stored event and retries

Each authorized rejected HTTP attempt appends one event with a new server audit
ID. Repeated attempts append repeated events. Do not claim workflow idempotency
or browser receipt rows; a corrected request can reuse its key as before.

Persist only server-derived organization/workspace/environment, actor, audit
ID, fixed action, rejected outcome, bounded correlation ID, operation and a fixed
reason code. For update, target is the verified same-scope integration. For
create, target is the selected environment: no integration exists yet. Metadata
must explicitly describe an attempted integration setup, not a created object.
No submitted URL, arbitrary key name, name, configuration, canonical intent,
credential, body digest or raw idempotency key is stored in the rejection event.
Use current database time for occurred_at.

Ruling: per-attempt events are preferred over deduplication because they record
attempts without durable hostile intent or synthetic success receipts. Cost if
wrong: repeated requests create repeated events; existing request rate limits
and audit retention govern them.

## Transactional authorization

Pass the credential kind and digest, never its bearer value, together with the
server-derived principal and exact scope. These routes admit BrowserSession and
ProductAPIToken; cover both, including the token's permission intersection.
Validate current credential expiry/revocation, credential scope
and permissions, active membership and effective manage_workflows permission.
For update, verify the existing integration belongs to that exact scope; never
borrow a foreign target's identity for the event.

Authorization must be evaluated after blocking waits, with database-current
time and fresh READ COMMITTED statements. After insertion, lock current
membership, credential, a positive grant witness and update target through
commit. Recheck authority and clock after waits. Revocation during blocked
INSERT rolls back the audit. Use bounded cancellation/rollback and explicit
lock ordering, with observed blockers instead of sleeps.

Browser effective scopes union positive grants. Lock a direct scope witness, or
stabilize group authority using membership FOR SHARE plus contributing existing
mapping rows FOR SHARE and a fresh effective-scopes check. Release19's registered
group writers take membership FOR UPDATE; enumerate them and test that contention.
API cannot directly lock member-group rows under existing RLS. Add no grant to
work around this. New positive mappings cannot remove a locked existing grant;
do not take global table SHARE locks. Tokens retain existing direct-scope and
token-permission intersection. If another registered group writer bypasses the
membership lock, stop and revise this witness strategy. Owner/bypass tampering
is not a supported concurrent product writer; record that proof boundary.

Root source enumeration found only release19 resolve_session and
reconcile_deprovision mutate member-group rows. Both take membership FOR UPDATE
before credential revocation. Match that membership-before-credential order to
avoid an inversion deadlock. Tests must use observed blockers that do not also
prevent the competing revocation from committing its own audit event.

No revoked, expired, foreign or permission-removed request may append an event
under tenant authority it no longer has. Callers cannot invoke the capability
for an arbitrary principal by omitting its matching credential proof.

## Verification and release acceptance

Focused RED/GREEN includes mounted create/update with valid positive setup
controls, all three override names, inline-secret early rejection, repeated
attempts and reused successful keys. Verify exact scoped durable events, stable
public errors, absence of hostile data, and no workflow/typed integration,
connection, effect queue or success receipt mutation. Observe provider dispatch
at the actual transport boundary where available; document the scope of local
zero-egress proof honestly.

Cover absent cookie, wrong Origin/CSRF, stale expected scope, insufficient
permission, foreign update target, expired/revoked credential, direct forged
principal, audit persistence failure/cancellation and authority revoked during
an observed wait. Preserve positive generic-webhook configuration.

Test missing capability, closed database, commit/rollback/cancellation and
registered-role authority. Validate actual pgx and tracing paths, unchanged
predecessor readiness, and event visibility through the authorized audit read
API, not only owner SQL. No release upgrade/downgrade is introduced.

Run focused affected tests while editing, one connected integration/review
boundary for the feature, and full UI/types/lint/build before publication.
Reuse unchanged evidence only by verified source identity. An independent
reviewer checks the assembled HTTP/SQL/runtime delta. Keep M8-41 component-only
until evidence meets its requirement and any release dependency is recorded.
Local fixtures do not close live-provider or production gates.

## Execution constraints

Use the existing shipping worktree and preserve inherited changes. Capture
task-scoped BEFORE/AFTER and patch. No staging, commit or push before verified
publication gates. No host PostgreSQL, downloads, image pulls/builds, new live
infrastructure or advisory calls. Use cached owned isolated PostgreSQL and join
all resources. Root owns the ledger and independent review.
