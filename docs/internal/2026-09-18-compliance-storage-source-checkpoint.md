# Compliance storage integration and source map

September 18, 2026. Progress, not feature completion. All 728 original tasks
remain in scope. Current counts stay 532 production-available, 135 component-only
and 61 external gates.

## Versioned receipt fix

The real artifactstore.NewExport Put returns a locator with the immutable object
version added by its driver. WriteComplianceExportArtifact compared that whole
locator to the unversioned request and rejected successful versioned storage.
RED01157f reproduced this through the actual export store and a controlled
version-returning driver. The fix compares exact scope/reference separately and
validates the returned version using the existing store contract. Media type,
size, checksum and byte equality remain mandatory.

New negative tests reject changed scope/reference and invalid version strings.
Grouped local Go race run95757 passed sessioncontrol (2.000s), artifactstore
(1.856s) and artifactstore/s3driver (1.967s). Independent review reported no
Critical/Important/Minor findings and reran all three race groups successfully.

Command from services/platform: go test -race ./sessioncontrol ./artifactstore
./artifactstore/s3driver -count=1, using local Go, GOPROXY/GOSUMDB off and
GOCACHE=/private/tmp/zasp-budget-go-cache.

Verified Git blobs: sessioncontrol/sessioncontrol.go
70f6c0389e8babf9877faf5407a10e4d2218bade; new
sessioncontrol/compliance_export_version_test.go
627b8631a33730ce1fd611989fef604581db7c10. The earlier formatter checkpoint
records its predecessor. This does not prove live AWS, durable job composition,
download authorization or release readiness.

## Current source map

S means organization/workspace/environment. The following mapping comes from
read-only source inspection, not fresh runtime acceptance.

| Category | Durable identity and timestamp | Authorized product target and gap |
| --- | --- | --- |
| Audit | migration52 zasp_audit_export_public_source_v1 unions admin id/occurred_at, workflow audit_id/created_at and red-team mutation audit_id/created_at; each carries S | GET /api/v1/audit-events requires view_audit; current list is organization-wide. Filter S explicitly for compliance. No general audit-by-ID target. |
| Finding | zasp_risk_findings keyed S/id, version, created_at/updated_at | GET /api/v1/findings/{id}, view; /violations accepts scoped entity_id. Associated evidence IDs are not automatically downloadable artifacts. |
| Policy | zasp_workflow_records keyed S/kind/id, policy kind, version, created_at/updated_at, deleted_at | GET /api/v1/policies/{id}, view; /policies lacks ID selector. API hides timestamps. A policy definition is not deployment/enforcement proof. |
| Test | zasp_red_team_runs and completed attempts keyed S/run/attempt, completion time and versioned evidence receipt; Attack Lab has equivalent scoped run/attempt tables | GET /api/v1/test-runs/{id}, view; scoped /red-team/results target exists. Queued definitions are not completed test evidence. Attack Lab lacks URL run selector. |
| Config | zasp_data_controls keyed S, environment/version/updated_at, migration_seeded | GET /api/v1/settings/data-controls, view_compliance; /administration/data-retention is current-scope singleton. API hides timestamp; seeded defaults are not verified settings. |

Important: existing activityLink kind audit resolves Security Agent audit only,
through getSecurityAgentAuditEvent. Never route generic admin audit IDs there.
The existing /compliance/evidence page currently rejects arbitrary activity
selectors; an explicit detail contract is needed for source types without targets.

## Service design constraints established by inspection

Use the authenticated S, not caller-supplied scope or legacy organization-only
seed rows. Keep source identity/version/time separate from collection time.
view_compliance does not confer view_audit or view: validate source permissions
at creation, collection and retrieval, including revocation. Do not silently
report inaccessible categories as fresh or complete.

Reuse the existing artifact store's pinned bucket/owner/KMS, conditional writes
and immutable version reads. A planned object reference is not a write receipt.
Durable snapshot/job ownership, bounded leases/retries, recovery after response
loss, quotas, expiry and current authorization checks are still required.

Next implementation design must join current scoped source adapters, explicit
evidence-detail targets, durable export API/worker/storage and the filter/export
UI in one acceptance batch. Do not expose the legacy in-memory export handler.
S3/provider/deployment/advisory gates remain separate external requirements.
