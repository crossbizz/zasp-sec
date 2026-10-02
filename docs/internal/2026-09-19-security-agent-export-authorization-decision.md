# Run export authorization decision

This design decision supports original M7A-23. It is not implemented or
verified. Attack Lab Task1 remains the only active source implementation.
Read2026-09-19-security-agent-export-source-audit.md for the inspected source.

## Decision

Reuse the durable export engine with an explicit run-evidence job kind and
agent authorization origin. Preserve the existing compliance/browser kind.
Each kind has a closed request, snapshot, renderer and authorization policy.
Do not infer the kind from a missing session, a request field supplied by the
model or a worker-configured bypass. Admission selects it server-side.

Browser compliance jobs keep their non-null session binding and current
authorization checks. Agent-origin jobs have an explicit persisted authority
record bound to full scope, definition version, activation provenance, run,
plan hash, step, selected evidence manifest and current authorization principal.
The schema must enforce mutually exclusive valid origin fields. Do not insert
a dummy browser session or nullable fields without a corresponding invariant.

Two rejected approaches: using the current compliance endpoint directly would
collect controls evidence and require browser credentials; a second upload,
grant and cleanup engine would duplicate the existing lifecycle and depart
from the requirement to use the export service.

## Who authorizes an automatic export

Do not treat run.requested_by as an authenticated browser principal. Automatic
admission records a worker identifier there. The exact activated definition
version has persisted actor provenance in security_agent_definition_versions;
activation writes that actor, and the55 mutation path binds public edits to
their authenticated principal.

At activation of an export-capable definition, retain an explicit authority
binding for that exact version and the authenticated activation principal.
Require current manage_workflows and the permissions for the permitted source
kinds. The activation request already requires fresh browser authentication.
Reactivation or editing creates a new binding; never inherit broader authority
from another version or replace the original actor from a worker parameter.

This is standing authority for the configured scoped automation, not a stored
browser session. Expiration of the activation session alone must not disable
an otherwise authorized automatic job. Membership removal, permission removal,
definition deactivation and tenant execution stop must prevent new collection
or publication. An active worker lease alone never grants source permission.

Manual runs retain the same definition binding and also require the current
authenticated requester to possess the selected source permissions at admission.
If that requester loses authority before publication, refuse publication. Do
not silently switch from manual-origin checks to automatic-origin checks.

Supervised execution keeps its required plan approval. Autonomous export keeps
the action's existing low-risk/no-mandatory-floor classification, subject to
the explicit standing authority above. No unrelated approval-floor change.

## What is authorized

The selected run is the executing Security Agent run, not a caller-chosen
foreign run. Resolve each selected typed source through its persisted
association with that run in the same organization/workspace/environment.
Require a nonempty unique bounded selection and retain exact versions/digests.
Prefix checks, current tenant membership and a matching product ID are each
insufficient on their own.

Minimum permission rules follow the existing source reads: view for the run
and finding/attack-path metadata; investigate_sessions for selected session
material; view_audit for selected audit records. Additional kinds must declare
their source's actual permission before support is enabled. view_compliance
does not authorize unrelated run evidence. No arbitrary raw prompt, secret,
credential reference, storage locator or unfiltered private database object.

Select only fields in a versioned redacted export schema. Validate existing
test/Attack Lab proof through the checked public projection before retaining
it. Missing historical content, mismatched proof or an unresolved selected
member fails the requested selection atomically. Pending proof remains pending
in its exported description; export success does not change its meaning.

## Checks across the job lifecycle

Admission locks current authority and the immutable plan/evidence selection,
checks lease/stop/budget, then creates one deterministic action/export link and
job in a transaction. Full-intent replay returns the same job; conflicting
intent fails, including after public idempotency receipts expire.

Capture rechecks the recorded authority and freezes the exact selected bytes.
Recheck authorization after prerequisite lock waits, before artifact preparation
and before publishing completion. Use current wall-clock expiry checks. A
retry uses the retained selection and bytes, never a new scan of run evidence.

Reconciliation and cleanup may continue after authority is revoked to account
for already-written storage and remove exact versions. They must not publish
success, collect new source content or widen the selection. Keep existing
quota accounting and read-lease-aware cleanup while provider outcome is
unknown. Tenant stop cannot erase an unresolved storage obligation.

Retrieval is a separate browser-authorized operation: current full-scope
membership and every selected source permission are required. Keep the existing
single-use, session-bound, expiring download grant and immutable version/digest
checks. Another currently authorized user in that scope may retrieve the
package; possession of the job ID or original activation authority is not
download authority. Never return an unguarded object URL.

## Required connected tests

One feature batch must cover automatic execution after activation-session
expiry, definition-actor revocation, manual requester revocation, supervised
approval and autonomous execution. Test revocation while waiting on a real
database lock and after upload but before publication. Inspect unchanged
job/effect/outbox counts for pre-admission denials.

Use two runs in the same tenant, two scopes, forged prefixes, a shared finding
with distinct trigger versions and a same-tenant unassociated finding. Include
changed evidence after capture, repeated action dispatch, lost upload reply,
restarted export worker, expired grant, foreign user, native downloaded bytes
and exact-version cleanup. Existing compliance jobs must still require their
browser sessions and render their unchanged controls contract.

This decision must be incorporated into the complete M7A-23 design and plan
after M7A-22's connected implementation. It does not allocate a schema version,
enable a catalog entry, clear publication gates or establish live acceptance.
