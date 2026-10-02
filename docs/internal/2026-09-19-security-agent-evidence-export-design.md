# Security Agent run-scoped evidence export

Original task: M7A-23. Dependencies: M7A-22 and M7-40. Preserve all728 original
tasks. This design is preparation, not implementation or production acceptance.
Routine decisions follow the user's autonomous-execution instruction.

## Decision

Add an agent-run job origin to the existing durable export service. Reuse its
quota, leases, frozen snapshot/package, immutable storage receipt, uncertain
write reconciliation, download grants and cleanup. Add a run-evidence collector
and renderer; do not invent compliance mappings for arbitrary evidence.

The alternatives are unsuitable: calling the browser compliance endpoint needs
a real session and selects controls rather than run evidence; an independent
upload service duplicates the accepted lifecycle and fails the reuse requirement.

Current evidence: compliance_exports_repository.go requires a browser credential
and session digest. compliance_jobs.sql reauthorizes at capture, preparation and
publication. compliance_export_replay.go persists prepared bytes before Put and
treats every error after Put starts as an uncertain write. Preserve these rules.

## Membership and selection

An evidence ID prefix is never authority. Resolve each selected reference through
the full organization/workspace/environment/run relation and its retained
source identity, version and digest. The same finding may legitimately belong
to two runs. Check membership in the selected run, not global ID exclusivity.

The trusted selector must support the persisted run trigger/evidence association,
run-scoped audit records and linked test/Attack Lab evidence projections. It must
classify the underlying source kind for authorization. The implementation plan
must inventory every currently selectable source kind and its canonical reader;
an unrecognized or unresolvable selection is an explicit refusal, never omitted.

Selections are nonempty, unique and bounded to100 references, matching the
original action bound. Resolve the complete selection atomically. Preserve
original source IDs rather than manufacturing run-prefixed IDs. A caller cannot
supply source bytes, storage references, SQL filters, arbitrary URLs or new
evidence relationships. Planner output remains untrusted selection input.

Freeze authorized source records at their run-associated version. If only a
different current version exists and the retained version cannot be recovered
and verified, fail the selection explicitly. Never silently export the new
version. Use checked redacted linked-proof projections; their reference digests
do not authorize retrieval of private prompt, credential or artifact contents.

## Admission and authority

Agent admission uses the registered worker and current parent lease, action
step, plan/input digest, allowed action, scope, definition version, budget and
execution controls. Resolve an accountable principal from persisted run
authority, not a caller-chosen principal. Apply source-specific permissions.
Automatic execution remains available under the original action's approval
floor; this design does not require browser-session impersonation.

For scheduled runs, requested_by contains the worker label and is not a human
principal. Resolve the actor from the exact persisted definition version,
whose definition digest must match the run-bound definition; the existing
activation path records that actor and release55 binds mutation provenance.
Require a valid product principal, active membership and current full-scope
manage_workflows plus every selected source-read permission. Persist that
exact version/actor binding with agent-origin admission. Recheck the binding
and current permissions at later lifecycle boundaries. Never fall back to the
worker label or a newer definition's actor. A manual requester additionally
needs current source authority; it cannot borrow the definition actor's read
permissions. This is a design rule pending registered-database proof.

Keep browser-origin jobs on their existing session-bound authorization path.
Add an explicit checked origin discriminator and an agent binding; enforce that
exactly one origin's complete authority is present. Agent jobs have no fabricated
session digest. Existing compliance routes cannot create, retrieve or reinterpret
agent jobs merely because they share storage tables.

Include origin in the job idempotency namespace. The existing unique key is
scope/principal/idempotency_key; adding a prefix convention alone would allow
a browser request to collide with an agent job. Browser create/get/grant
queries must explicitly select browser origin, including replay. Agent action
links independently enforce one export per full-scope run/step/input digest.
An origin mismatch must not return a job, package, lease or grant.

At capture, preparation and publication, recheck the origin's current authority
and every selected source permission after blocking waits. Revocation cannot
publish a completed export. Reconciliation and cleanup may record storage facts
and drain existing objects after revocation, but never recollect evidence, upload
new bytes or restore publication authority.

## Durable execution and result

Admit exactly one export per full-scope parent step/input identity. Persist the
action/export link and receipt transactionally. Retried dispatch returns that
identity and cannot select additional evidence or reserve another job.

The existing worker distinguishes the closed job kind, captures an immutable
run-evidence snapshot, renders JSON/CSV/readable forms with a versioned schema,
and saves exact package bytes before provider I/O. Reuse existing size, quota,
attempt, retention and concurrency limits. Missing/overflow evidence fails
atomically; do not truncate silently. Preserve all browser export formats.

The manifest includes full scope, parent run/step, exact selected source kinds,
IDs, versions/digests, snapshot time and renderer revision. Escape spreadsheet
formula prefixes in CSV and untrusted text in readable output. Export completion
means the immutable package is available, not that a finding is safe/remediated.
Settled action proof binds the export ID, package checksum/version/size and
retention state. Pending, failed, expired and cleanup-pending states stay visible.

Parent stop fences new admission/capture/upload. Any already-started uncertain
storage operation retains its accounting and cleanup obligation. Replay uses
prepared bytes and the exact provider version. It never regenerates evidence or
issues a new Put from the reconciliation lane.

## Product reads and downloads

Expose tenant-scoped action detail and an explicit export status/download flow
using the existing artifact service. Browser retrieval requires current source
permissions for every record in the frozen manifest, including investigate
permissions for sessions and audit permission for audit records. A general
run-view permission alone is insufficient. Do not substitute view_compliance
for authorization to the selected sources.

Reuse short-lived, single-use native download grants and read-lease-aware exact
version cleanup. An expired or revoked grant cannot retrieve bytes. Do not leak
raw bucket keys, credentials or private source artifacts in public status.

The existing compliance download reader validates a controls-based JSON array
and compliance-envelope-v1. Keep that browser contract closed. Agent downloads
need the run-evidence decoder and exact run/step/selection binding, while
reusing immutable storage verification and grant/read-lease/consume mechanics.
Do not make the old reader accept an arbitrary JSON object to reuse its code.
Download package bytes are decoded, never regenerated from live source records.
Both grant issue and final consume require current permissions for the frozen
source set, so revocation during storage I/O prevents disclosure.

## Release and acceptance

Use a new additive release after57. Preserve prior SQL/pins and default release
behavior; expose the action only when its schema and required export runtime
are configured and ready. Existing compliance jobs must work unchanged before
and after the upgrade. Unused rollback restores predecessors; retained agent
job/action history blocks destructive downgrade.

Batch acceptance by this feature: focused RED/GREEN, one real registered
database/race batch, one composed browser/download/restart batch, then independent
spec/quality review of a frozen diff. Reuse unchanged accepted evidence. Required
cases include same-tenant different runs, shared findings/different versions,
foreign scope, forged prefixes, missing records, permission revocation during
waits, lost dispatch/upload/settlement replies, immutable native bytes, expiry,
parent stop, cleanup lag and unchanged browser-origin compliance behavior.

Update the original M7A-23 ledger row with evidence and limitations. Local
controlled storage is not live provider proof. Approved provider configuration,
hosted exact-source CI/advisory and deployment acceptance remain external gates.
No push may bypass the current publication gate. M7A-24 follows this task and
does not replace any remaining original work.
