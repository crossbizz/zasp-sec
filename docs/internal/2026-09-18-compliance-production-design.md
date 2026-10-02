# Production compliance evidence and exports

Status: design for implementation, not installed behavior. September 18, 2026.
User authorizes autonomous routine choices and feature-batched verification.
Original 728-task scope is unchanged. This design covers M7-08 through M7-15
including their current-source prerequisites; no existing task earns credit
from this document.

## Outcome and alternatives

Deliver a current, scope-authorized SOC 2 Security/HIPAA evidence view with
real evidence targets and a durable JSON/CSV/readable export stored in S3.
Evidence is for review; neither a fresh record nor a successful export proves
certification, control effectiveness, deployment enforcement or live-provider
acceptance.

Chosen: dedicated compliance SQL authority and leased durable jobs using the
existing worker polling and artifact-store primitives. A synchronous request
would tie upload completion to an HTTP connection and omit restart recovery.
Reusing audit-export jobs directly would confuse audit-only source semantics,
permissions and artifact types. Reuse lower-level storage and runtime code,
not audit job identities or audit permissions as compliance authority.

## Sources and authorization

Every query constrains the authenticated organization, workspace and environment
(S). Never infer S from an artifact locator, URL parameter or legacy organization
seed. The current migration0007 compliance seed tables are not current evidence
and must not be the production source for this batch.

Current source adapters:

| Source | Durable authority | Evidence timestamp and target |
| --- | --- | --- |
| administration/workflow/red-team audit | zasp_audit_export_public_source_v1, filtered by S and mapping eligibility; validate every eligible source_valid flag and fail collection if false | occurred_at, source_kind and audit ID |
| finding | zasp_risk_findings plus its scoped evidence associations | updated_at, finding ID/version; preserve associated evidence IDs as references only |
| policy | undeleted zasp_workflow_records kind policy | updated_at, policy ID/version; definition is not enforcement proof |
| red-team test | completed zasp_red_team_runs/attempts retaining recorded definition_id/definition_version; do not require that version in the mutable current definition table | completed_at, run ID/attempt and immutable evidence receipt |
| attack-lab test | completed zasp_attack_lab_runs/attempts | completed_at, run ID/attempt and immutable evidence receipt |
| configuration | zasp_data_controls | updated_at, environment/version; label migration_seeded explicitly |

Use allowlisted metadata only: source identity/version, scope, source time,
status/severity where applicable, evidence references and receipt digests.
Do not copy raw prompts, tool arguments, arbitrary audit metadata, secrets,
provider credentials or policy bodies into the export.

The full evidence surface requires view_compliance, view and view_audit.
The existing compliance_viewer role already has these permissions. A custom
scope missing any required permission gets a stable authorization error, not
a partial package mislabeled complete. SQL independently checks current browser
session, active membership and effective S permissions. Export creation also
requires fresh authentication, same-origin protection and CSRF. Recheck after
blocking locks and before publishing or downloading bytes. Worker authority
does not substitute for the requesting principal's current source permissions.

## Mapping, freshness and public evidence targets

Version the product evidence mappings for SOC 2 Security and HIPAA safeguards.
Mapping labels describe product evidence categories, not authoritative legal
interpretation or a checklist claiming complete standard coverage. Preserve all
five original source families; never substitute membership seeds for them.
Control definitions identify required source categories and maximum evidence
age explicitly. Missing required categories produce missing; old source times
produce stale. Capture time never refreshes an old source. Unavailable or
invalid source reads fail collection and are not silently discarded.

Extend the public evidence record with a typed target containing source_kind,
source_id and source_version (attempt for test records), retaining current
record ID/asset/source/time fields for compatibility. Source IDs need not be
pid identifiers: policy IDs use policy-* and audit IDs have their own source.
Get /api/v1/compliance/evidence/{sourceKind}/{id} resolves the exact indexed
source key under S. An expected version query protects a link rendered before
the record changed: respond with a stable source_changed conflict when it no
longer matches. Deleted/missing targets return not_found. Never redirect opaque
evidence references to an unrelated activity detail.

The /compliance/evidence UI owns a strict typed selector for this detail.
Require exact selected S and reject duplicated/unknown/foreign-scope parameters.
Show source identity, version, timestamp, freshness and safe metadata. Existing
finding/test links may be supplementary; generic audit IDs must never use the
Security Agent audit detail. Exported snapshots retain their captured metadata
even when current source details subsequently change.

## Durable job and artifact protocol

Add release56 after exact release55 without editing predecessor SQL/checksums.
Acceptance must exercise release55/API and predecessor readiness paths after
migration, not only the new release fingerprint.
Register checksum, semantic readiness, least-privilege API/worker bindings,
migration runner/CLI integration and compatibility in the normal release chain.
Downgrade refuses outstanding jobs, receipts or retained snapshots; it cannot
delete customer evidence to make a rollback pass.

Job key is (S, export_id); rows retain requester, idempotency key/request digest,
mapping revision, snapshot time/digest, artifact intent and immutable receipt.
Public states are pending, completed and failed; internal pending substates
queued/collecting/uploading are durable. IDs are server-created. The request
selects framework/control filters only, never bucket/key/provider coordinates.
Idempotent replay with the same request returns the same job; changed filters
under the same key return conflict.

POST creation checks authority and inserts the queued job atomically.
A dedicated registered worker claims bounded batches with expiring lease token
and generation. Capture all source families and insert the frozen snapshot in
one SQL statement so they share a PostgreSQL statement snapshot. Acquire job and
authorization locks before that statement; check current authorization afterward
in a new READ COMMITTED statement before committing the capture transaction.
If the authority check fails, roll back the snapshot. Rendering consumes only
this immutable snapshot. Before provider I/O, persist the exact rendered package
bytes, renderer revision, reference, size and digest. Retries load those stored
bytes without rerendering, including after a binary upgrade.
The worker uploads those exact bytes with artifactstore.NewExport.Put. Do not
call WriteComplianceExportArtifact for replay: it invokes the current renderer.
Initial preparation uses the formatter; reuse receipt validation without
reconstructing content. Downloads verify pinned bytes/digest and supported
envelope revision, not equality with the currently deployed renderer.

Use artifactstore.NewExport and s3driver.NewExport with operator-pinned bucket,
expected owner and KMS key. Conditional Put prevents overwrite. Existing
s3driver.Put can discover/verify the object after response loss; a planned
reference alone proves nothing. Completion requires a nonempty immutable
version receipt and exact scope/reference/size/hash/bytes, plus current lease
generation and source authorization. Expired workers cannot finalize a job.
Uncertain upload remains pending/retryable, never fabricated completed.

Bound the initial policy: at most 500 controls, 100 records per control,
4 MiB per rendered format, 8 MiB complete package, 2 active jobs per S,
100 active jobs per worker deployment, 5 attempts, 60-second renewable leases
and 30-second retry delay. Check one extra source row and fail explicitly on
overflow; never silently export a truncated first page. Tenant-fair ordering
must prevent a noisy scope from monopolizing all slots. Persisted policy
revisions may change limits only through trusted operator configuration.

Store exports for a configured 24-hour product retrieval period initially.
Expired jobs cannot issue download grants; retention/deletion work must track
exact immutable versions and must not imply that denial alone deletes S3 bytes.
Deployment must install the matching object lifecycle/retention policy before
production availability. Unknown write outcomes remain charged to retained
capacity until reconciled; quotas cannot be freed merely on HTTP timeout.

Reserve database snapshot and artifact capacity before capture: 12 MiB per new
job (4 MiB snapshot plus 8 MiB package), then reconcile downward to exact persisted
sizes only after preparation. Initial retained limits are 256 MiB and 100 jobs
per S; 16 GiB and 10,000 jobs deployment-wide across replicas. Grants are limited
to 5 outstanding per job and 20 per principal/S. Expired/used grants are pruned
under bounded maintenance; rows count until pruned. All limits are persisted
operator policy, not process counters.

After five upload attempts, report failed/storage_unresolved if the write outcome
is unknown, retain its intent/bytes and capacity, and move storage state to
reconcile_required. A leased reconciler checks the same immutable intent with
the pinned provider client. Verified receipt resolves storage state; public
failure is not retroactively changed to completed. Provider uncertainty remains
charged and visible, not treated as absence or retried by normal execution.

After retrieval expiry, cleanup leases the job only after its bounded active
read leases end. Use a separate least-privilege cleanup client restricted to the
stored object key/version and expected owner; generic artifactstore Delete is
immutable and must not be weakened. Confirm exact-version absence before freeing
storage quota or pruning snapshot/package. Timeout, denial, object lock or legal
hold keeps delete_pending charged and auditable. Lifecycle policy may remove the
object first, but configured-client verified absence is still required. Retain
deletion audit correlation in the normal audit store. Expired jobs awaiting
deletion count against retained capacity to bound outage accumulation.

GET status rechecks current S/permissions. Download uses an expiring single-use
grant scoped to principal/session/S/export and requested format. Resolve the
stored version, verify content, recheck authority, then consume the grant before
writing bytes. A lost response requires a newly authorized grant, not token
replay. No public bucket URL or reusable provider credentials reach the browser.
Grant expiry cannot exceed export retrieval expiry. Redemption atomically
checks both clocks and current authorization after artifact readback; an earlier
grant never extends export access. Read leases and request deadlines are bounded
by export expiry. Cleanup cannot delete a version while a valid read lease exists.
Use no-store headers and safe attachment filenames. Artifact integrity failure
returns an error and is audited, never successful empty output.

## UI and grouped acceptance

Keep existing reads runnable while the new release is unavailable. Production
routes/actions become available only with the complete registered service.
The UI supports framework/control filters, current evidence links, source times,
fresh/stale/missing labels, queued/completed/error export states, reload recovery
and authorized download. Errors leave deterministic evidence inspection usable.

Focused TDD checks cover changed behavior. One grouped SQL/API/storage acceptance
run covers all source kinds, authorization revocation, sibling S denial, paging
overflow, idempotency, concurrent claims, restart/response loss, stale lease
refusal, version/digest tampering, grant replay/expiry and source changes.
Include invalid eligible audit rows, completed tests after definition edits,
concurrent source changes during capture, renderer-upgrade restart, retained
quota exhaustion, unresolved-write reconciliation, blocked cleanup and grants
issued just before export expiry but redeemed afterward.
Independent review covers the connected feature. Before push run generated
contract checks, UI tests/typecheck/lint/build and composed browser flow.
Live AWS, deployed configuration, scale/reference-load and approved advisory
evidence remain distinct gates; local controlled services cannot close them.

## Implementation order

1. Register the release and implement scoped evidence reads/detail plus mapping
   and freshness, using the real durable tables above.
2. Add durable create/status/claim/capture/finish/retry authority and quotas.
3. Join the actual worker and versioned S3 store, including response-loss recovery.
4. Expose API/download lifecycle and typed generated client contracts.
5. Complete UI filter/detail/export and run the grouped end-to-end acceptance.

The formatter and versioned receipt helper are already component-verified; reuse
their unchanged-input evidence. No item above is marked complete by this design.
