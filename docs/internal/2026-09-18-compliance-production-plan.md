# Production compliance implementation plan

> For agentic workers: use superpowers:executing-plans or
> superpowers:subagent-driven-development. Track the checkboxes below.

Goal: deliver the original current-evidence, durable-export and composed UI
requirements, without promoting fixtures to production evidence.

Architecture: new release56 SQL authority reads current scoped source tables
and owns immutable snapshots and leased export jobs. Go API/worker adapters use
the existing authorization, runtime and versioned artifact-store boundaries.

Tech stack: PostgreSQL registered migrations, Go, S3 SDK/artifactstore,
OpenAPI-generated TypeScript client, React, existing owned composed runtime.

Spec: 2026-09-18-compliance-production-design.md. Read it and the original
M7-08..M7-15 requirements before execution. Independent design review approved
starting Task 1 after five design corrections. Its remaining Task 3 retry concern
is corrected below: upload persisted bytes directly, without current rerendering.
No checkbox is an implementation claim.

## Global constraints

- All 728 original tasks remain in scope; this is one connected feature batch.
- Never edit predecessor release55 SQL/checksum/fingerprint to accommodate56.
- Source authorization is selected organization/workspace/environment and current
  view_compliance + view + view_audit; recheck after waits and before disclosure.
- No raw evidence, prompts, secrets or arbitrary metadata in exports.
- Offline local Go/Node; cached owned Docker only. No host PostgreSQL or image
  pulls/builds, live provider calls, or advisory disclosure without authority.
- Keep inherited unrelated edits intact. No broad staging, reset or destructive
  database cleanup. No push before UI/release gates.
- User-requested batching overrides per-microtask suite/review repetition.
  Run focused RED/GREEN checks, then grouped acceptance and independent review.
- Keep component/live/external evidence distinct in the authoritative ledger.

## Task 1: registered current evidence surface

Files to create: migrations/compliance_release.go,
migrations/production_compliance.go, sql/0056_production_compliance.up.sql and
.down.sql (all under services/platform/migrations);
services/platform/apiserver/compliance_repository.go and its tests.
Modify migrations/migrations.go, agentsec-migrate/main.go and their release
tests. Add API composition only through the complete feature integration task.

Interface: ProductionCompliance() Metadata; ComplianceFingerprint() string;
Runner.UpProductionCompliance(ctx) and DownProductionCompliance(ctx). SQL
zasp_compliance_read(org,workspace,environment,principal,session_digest,operation,
parameters jsonb,expected_checksum,expected_fingerprint) returns JSON.
Operations are listControls, listEvidence and getEvidence. Parameters contain
bounded filters, cursor or typed source key/version, never scope overrides.

- [x] Write owned PostgreSQL fixtures for all five original source families,
  including both test families, same ID in sibling scopes, policy-* identity,
  legacy organization seed, seeded configuration, stale source and absent source.
  Include invalid eligible audit rows and completed tests after definition edits.
  Exercise real registered authority with revoked memberships and missing source
  permission. Assert exact IDs/versions/timestamps and no sibling records.
- [x] Run only these new failing tests using the existing offline owned-container
  pattern. Failure must be absent behavior, not a host initdb or missing image.
- [x] Implement release56 registration, predecessor guard, role/ACL/catalog
  readiness and refusal-safe rollback. Add typed bounded source projection
  functions and versioned control mapping from actual source tables in the spec.
  Keep source timestamp separate from collection time; never use migration seeds
  as current audit/finding/policy/test evidence.
  Reject invalid eligible audit rows, not filter them away. Historical completed
  tests use run-recorded definition versions, not current-definition version joins.
  Verify predecessor/API readiness after migrating55 to56.
- [x] Implement Go strict decoding and scoped typed repository adapter. SQL
  source-kind dispatch must use fixed branches, never interpolated table names.
  API/database source-ID grammar must agree, including non-pid policy IDs.
- [x] Verify keyset paging across more than one response page, exact version
  mismatch, unknown kind, deleted target, malformed/foreign cursor, sibling scope
  and authorization revocation. Record focused evidence; do not claim rollout.

## Task 2: durable job authority and frozen snapshots

Files: extend the unshipped release56 through sql/fragments/compliance_jobs.sql;
create services/platform/apiserver/compliance_exports_repository.go;
services/platform/agentsec-worker/compliance_export_database.go and tests.

SQL interfaces return JSON: zasp_compliance_export_create,
zasp_compliance_export_get, zasp_compliance_export_claim,
zasp_compliance_export_capture, zasp_compliance_export_prepare_artifact,
zasp_compliance_export_finish and zasp_compliance_export_retry.
Every public operation carries authenticated S/principal/session and release
pins. Every worker mutation carries job ID, S, worker ID, lease token/generation
and release pins. Tokens are hashed at rest and never returned in public JSON.

- [x] Write failing registered-database tests for same-key replay, changed-request
  conflict, two claimers, expired lease, lease theft, revoked requester, snapshot
  rollback, source overflow, full active quota and noisy-scope fairness.
- [x] Implement SQL ownership constraints, request digest/idempotency, fixed
  operator policy revisions, leased state transitions and atomic source capture.
  All source reads and snapshot insertion share one SQL statement snapshot.
  Acquire job/auth locks first; check fresh authority again in a later READ
  COMMITTED statement before committing. Freeze metadata/digest and mapping
  revision, then persist exact rendered package bytes before provider I/O.
- [x] Persist artifact intent before egress and finalize only with matching
  generation, scope/reference/version/size/hash and current requester authority.
  Unknown upload outcome retains capacity and immutable intent for recovery.
  Implement the spec's retained-byte/job/grant quotas, unresolved-write lane and
  exact-version cleanup states; never release capacity on public failure alone.
- [x] Verify source changes after capture do not alter a retry's bytes; source
  changes before capture appear in the snapshot. Test every state after process
  restart and refusal-safe downgrade with retained evidence.
  Include concurrent source changes and restart under a new renderer revision:
  retry uses prior persisted bytes without rerendering.

## Task 3: production worker and S3 storage

Files: services/platform/agentsec-worker/compliance_export_runtime.go,
compliance_export_production.go and owned storage/process tests; worker runtime
config and composition. Use the formatter only during initial preparation.
Upload stored package bytes directly through artifactstore.NewExport and
s3driver.NewExport; reuse receipt validation without rerendering. The existing
WriteComplianceExportArtifact invokes the current formatter and is not the
retry path.

Interface: composeComplianceExportWorkerRuntime(ctx,config,database,clients)
returns workerRuntimeDependencies for a dedicated compliance-export mode.
Initial preparation produces encoded package bytes and renderer revision;
upload consumes persisted bytes/reference/size/digest only.
Client construction uses operator bucket/owner/KMS pins. All provider operations
have context deadlines and one explicit attempt; SQL owns retry scheduling.

- [x] Write failing composed-worker tests for claim/capture/render/upload/finish,
  caller cancellation, lease loss and source authorization revoked during upload.
- [x] Implement processor using existing runWorkerPollingLoop lifecycle and
  registered SQL adapter. Heartbeat through bounded provider I/O. Join child
  goroutines and release owned resources on normal completion and SIGTERM.
- [x] Add controlled SDK fault cases: committed upload with lost response,
  different bytes at existing key, wrong version/owner/KMS/checksum, and timeout.
  Retry the same intent; allow completed only after verified immutable receipt.
  Test attempt exhaustion, unresolved reconciliation and expiry cleanup through
  a separate exact-version client. Locked/denied deletion retains capacity.
- [x] Run one grouped SQL/SDK/process test batch, including real process restart.
  Reuse unchanged formatter evidence. Record controlled-storage versus live S3
  boundaries explicitly.

## Task 4: production API, downloads and generated contract

Files: services/platform/apiserver/compliance_http.go,
compliance_download.go, compliance_production.go, composition.go, production
configuration; openapi/openapi.yaml; apps/web/api/generated.ts and compliance
decoders; docs/product/ui-api-map.yaml. Tests live next to handlers/decoders.

Routes: existing compliance controls/evidence reads; new typed evidence detail;
POST /api/v1/compliance/exports; GET /api/v1/compliance/exports/{id};
POST /api/v1/compliance/exports/{id}/download-grants;
POST /api/v1/compliance/exports/{id}/download (grant in body, not URL).
Public export statuses stay pending/completed/failed. Source filters are bounded
and canonicalized before idempotency hashing. Download format selects json, csv
or human from the verified package.

- [x] Write failing authorized-success and stable-error tests for each operation,
  covering source-version conflict, wrong S, CSRF/origin, freshness and expiry.
- [x] Mount the complete registered service without duplicate legacy handlers.
  SQL independently validates sessions/permissions; API error bodies contain no
  database diagnostics or provider coordinates.
- [x] Implement durable session/principal/S/job/format-bound single-use grants.
  Verify artifact before disclosure, then recheck authority and consume grant
  before bytes. Replay/expiry/revocation returns stable denial. A lost response
  can request a new grant only through current authorization.
  Cap grant expiry at export expiry and atomically check both on redemption
  after readback. Test an earlier valid grant redeemed after export expiry;
  bounded read leases prevent cleanup racing an authorized download.
- [x] Regenerate client from OpenAPI and run strict decoder/contract tests.
  Verify no-store headers, attachment filename safety, malformed body handling
  and no grant leakage into browser URLs/history/logs.

## Task 5: UI and full feature acceptance

Files: app/features/sessions/SessionsComplianceView.tsx and tests;
app/domain/activity-links.ts or a dedicated compliance-links.ts with strict
selector tests; app/components/ZaspProductionApp.tsx; composed runtime fixture
and scripts/production-combined-e2e.mjs assertions. Preserve other surfaces.

- [x] Write failing UI tests for typed source targets, timestamps, missing/stale
  states, framework/control filters, queued/completed/failed jobs, reload, denied
  permissions, expiry and download failures while evidence remains readable.
- [x] Implement real API bindings and strict source selector. Never use generic
  audit IDs in Security Agent detail or silently switch selected S from a URL.
- [x] Add composed PostgreSQL/API/worker/versioned storage/browser acceptance
  through actual requests and user actions. Assert cross-tenant and same-org
  sibling-scope denial, restart recovery, exact exported records, changed source
  handling and download grant replay refusal.
- [x] Run grouped feature tests and independent review. Then verify UI test
  suite, typecheck, lint, build and the relevant composed browser flow once for
  this assembled candidate. Preserve exact command/source/result evidence.
- [ ] Update original-ID ledger attribution without interpreting local fixtures
  as live proof. Commit only scoped reviewed files and push to main only when
  the approved release/advisory and runnable-UI gates are satisfied.

## Completion check

Task5's local checks above are independently accepted after fix1; see
compliance-ui-task5-20260918/task-5-fix-1-review.md. Publication remains unchecked.
Both deferred API findings are locally closed after final-fix2 independent
review. CI browser wiring is also independently approved, with a fresh local
compliance browser run against the final backend revision. Connected final
review and publication remain separate. Local review does not satisfy hosted
Linux execution, live deployment or external advisory gates.

All five tasks must be implemented and integrated for this feature batch.
External production gates remain separately open until actual evidence exists.
An adapter, migration fixture, passing mock or this plan alone cannot complete
M7-12/13/14/15d/15. Keep all other original milestone obligations active.
