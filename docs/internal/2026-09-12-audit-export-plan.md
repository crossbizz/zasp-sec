# Audit export implementation plan

> For the implementing agent: use Superpowers TDD and verification-before-completion.
> Root approved implementation under the user's autonomous full-scope request.
> Every unchecked step still needs tests, verification and independent review.

**Goal:** Implement M2-41/M2-42 through actual production HTTP, registered PostgreSQL
job/snapshot authority and immutable retrievable S3 contents, preserving the full
original storage architecture and enabling the later M7-36 UI action.

**Architecture:** Atomic create/idempotency/audit/outbox, asynchronous frozen DB
snapshot, bounded deterministic JSON chunks plus a small manifest in S3, exact
version/digest receipts, authenticated paged GET on the existing route.

**Tech:** Go, pgx/PostgreSQL 18, compiled migration 52, existing ArtifactStore/S3 SDK,
JobQueue/SQS, current API middleware/OpenAPI and release test harnesses.

Source design: [audit-export design](2026-09-12-audit-export-design.md).
Earlier DB-only plan is superseded.
Only verified prerequisite steps are checked below. Existing source IDs/pins 1-51 stay immutable.
Root decisions: POST 201 including exact idempotent replay; current view_audit and
exact three export-capable roles; browser/fresh POST; cursor binding to selected
scope/principal/operation/export/manifest/ordinal. Configurable defaults: 1 GiB
per export, 10 GiB retained/org, two in-flight/org, 120-second capture capped by
remaining lease/context, 1 MiB and 1,000 events/chunk. No silent truncation.
The approved design's shared-source correction supersedes the initial admin-only
assumption: exact policy/test mutation families join administration for both list
and export. Preserve retained IDs/times and exact SSO action case, no broad audit
union or raw domain bodies. M7-36 remains component-only until original filters,
complete export saving and actual four-family mutation E2E pass.
Read [schema52 audit](2026-09-12-audit-export-schema52-audit.md) fully before Task 3;
it is part of this plan.

## Proposed interfaces to settle before implementation

New audit/export.go owns pure versioned codecs and public descriptors, not SQL:

~~~go
type ExportState string // queued, processing, ready, failed
type ExportDescriptor struct { /* ID, scope, request/capture times, state,
    totals, manifest digest, stable failure reason; no credentials or raw locator */ }
type ExportChunk struct { /* schema, export ID, ordinal, first/last event,
    previous chain, exact frozen events */ }
type ExportManifest struct { /* fixed-size identity, format, totals, chain root */ }
func EncodeExportChunk(ExportChunk) ([]byte, error)
func DecodeExportChunk([]byte) (ExportChunk, error)
~~~

New apiserver/audit_export_repository.go owns API authority:

~~~go
type AuditExportRepository interface {
    Ready(context.Context) error
    Create(context.Context, AuditExportCreate) (audit.ExportDescriptor, error)
    Get(context.Context, AuditExportRead) (AuditExportReadAuthority, error)
}
~~~

Create carries authenticated scope/principal/session digest, idempotency key,
generated job/audit IDs and canonical empty-request digest, never a caller-selected
SQL source. Read carries authenticated identity, export ID and validated cursor.
ReadAuthority is private: exact stored scope, immutable manifest/selected chunk
locator/version/hash/size and public descriptor. HTTP never accepts these locators.

New worker authority separates durable state from external I/O:

~~~go
type AuditExportAuthority interface {
    Ready(context.Context) error
    Claim(context.Context, ClaimRequest) (ExportLease, error)
    Capture(context.Context, ExportLease) error
    ReadFrozenPage(context.Context, ExportLease, int64) (FrozenPage, error)
    PrepareChunk(context.Context, ExportLease, ChunkIntent) (ChunkIntent, error)
    RecordChunk(context.Context, ExportLease, ChunkReceipt) error
    Heartbeat(context.Context, ExportLease) (ExportLease, error)
    Finish(context.Context, ExportLease, ManifestReceipt) error
    RetryOrFail(context.Context, ExportLease, Failure) error
}
~~~

All operations use exact lease generation/attempt/token and fresh 52 readiness.
Types are proposed shapes, not permission to expose arbitrary raw JSON authority.
Chunk intent is deterministically validated against frozen rows in SQL, not just
trusted because a registered worker supplied it.

## Task 1: Contract and pure immutable codec

Files: new services/platform/audit/export.go and export_test.go;
openapi/openapi.yaml; component audit/store.go and identity/http.go only as needed
to align semantics after root accepts the async contract.

- [ ] RED: round-trip actual event identities/scope/metadata/time; ready requires
  a manifest and exact count coverage, not count-only metadata.
- [x] Implement closed versioned chunk/manifest formats, deterministic order,
  redacted projection, bounded event/chunk decoding, chain calculation.
- [x] RED/GREEN: malformed/duplicate/unknown fields, alias keys, foreign scope,
  ordinal/count/digest mismatch, oversized event/chunk, empty-export manifest.
- [x] Correct retained action compatibility: existing lowercase grammar plus the
  exact five published identity-provider actions in Go, SQL and public/reserved
  schemas. Actual schema19 producers must capture and retrieve unchanged bytes;
  generic emitter rules and published migrations remain unchanged.
- [ ] Write POST/GET path schemas: queued/processing/ready/failed, 201 create,
  idempotent status behavior, same-route cursor retrieval and stable errors.
  No presigned URLs, CSV or extra download endpoint.
- [x] Define unused closed async descriptor and same-route read-envelope
  components, including empty/nonempty content cases, and regenerate client types.
  Keep both routes absent and UI mapping planned until Task5 mounts the actual
  durable lifecycle; existing absence checks are not weakened.

Command: cd services/platform && go test -race ./audit ./identity
Exit criterion: codec and agreed API contract, not production completion.

The codec prerequisite passed independent specification/quality review and the
full audit-package race run (11.673s). The API contract and ready-state global
coverage proof remain unchecked. See the implementation evidence for exact
RED/GREEN results and the SQL serialization boundary.

## Task 2: Export-prefix ArtifactStore integration

Files: services/platform/artifactstore/store.go and store_test.go;
artifactstore/s3driver/driver.go and driver_test.go; bucketlayout/layout_test.go
if a narrow reuse assertion is needed.

- [x] RED: export store + S3 SDK fixture rejects current /artifacts/ hardcoding.
- [x] Add explicit typed export constructors/profile in both store and driver;
  use bucketlayout.ClassExport. Keep every current default artifact key unchanged.
  Do not add a caller-controlled raw-key or arbitrary namespace option.
- [x] GREEN: exact scoped export key, owner/KMS/version/hash/body verification.
  Wrong org/workspace/environment, traversal, wrong prefix and mixed store/driver
  profile refuse before provider I/O.
- [x] Reuse real conditional-Put discovery: object stored then response lost,
  differing existing bytes, wrong version, missing checksum, cancellation.
  No new multipart or presigned implementation.

Command: cd services/platform && go test -race ./artifactstore/...

Task2's bounded storage prerequisite passed independent specification/quality
review and final normal/race verification39133. See
[evidence](2026-09-12-audit-export-evidence.md). This does not complete M2-41/42.

## Task 3: Compiled migration 52 and registered authority

Files: new migrations/sql/0052_production_audit_exports.up.sql/.down.sql;
migrations/production_audit_exports.go/_test.go;
new apiserver/audit_export_repository.go/_test.go and
audit_export_postgres_test.go; narrow existing readiness/database registration
integration files identified before edits.

- [ ] First RED: naive 52 installation rejects live 51 consumers. Add exact new
  compatibility bridge without modifying published SQL/checksums 1-51.
- [ ] Add scoped headers, immutable snapshot rows, intents/receipts, lease/outbox
  tables and required org/time/id scan index. Register fixed API/outbox/executor
  roles. No broad direct-table write grants.
- [ ] Create atomically persists request audit, idempotency, job and outbox;
  recheck stored browser auth after waits. One successful key returns one job.
- [ ] Capture all visible source rows in one statement snapshot; persist projected
  bytes, ordinals and totals. Serialize quota admission. Cancel/error yields no
  partial capture or false ready state.
- [ ] Implement the approved private shared administration/policy/test projection
  for both full-source listing and capture. Exact families, validated summary
  metadata, preserved IDs/times and no mutable-resource/expiring-receipt joins.
  Refuse same-org cross-source ID collisions even across different timestamps;
  no dedup, silent invalid-row exclusion or source-based public ID rewrite.
  Pin view definition/security options and dependent source ACL/RLS/catalogs.
  Capture portion: implemented and independently approved at930e21e1, including
  all three cross-source collision pairs and real mutation history. This item
  stays open until the shared-source public list is implemented and verified.
- [ ] Add the bounded current-authorized full-source page authority and explicit52
  composition selection. No raw view/red-team source grants or admin-only fallback
  on the selected path. Exact server filters and principal/query-bound pagination
  must preserve all matching rows with bounded transport; prove serializer bounds
  and record the initial legacy-jsonb detoast limitation honestly.
- [ ] Capture holds job/org fences: derive its deadline from confirmed remaining
  lease, context and 120-second bound with finalization margin. Do not assume a
  blocked heartbeat extends the lease. Recheck wall-clock expiry and fresh 52
  readiness after INSERT before commit. Actual PG expiry/drift and contending
  admission tests require zero partial snapshot/counter effects.
- [ ] Frozen-page SQL limits serialized bytes AND rows before JSON aggregation,
  including envelope/separator overhead. Large-event fixtures (1,000 near-limit
  rows), exact-byte boundary and oversized-first-event controls prove bounded
  response allocation, contiguous next ordinal and no silently skipped events.
  Repository decoding independently enforces the response-byte ceiling.
- [ ] Claim/heartbeat/prepare/record/finish fence generation/attempt/token/scope;
  finish validates complete contiguous coverage, totals and immutable manifest.
  Exact retry succeeds once; different replay refuses without partial rows.
- [ ] Actual registered-role PG tests: all persisted event fields, concurrent
  source writes/backdated arrivals, same-key races, tenant/scope/auth revocation,
  expiry/stale lease/wrong receipt, count gaps, SQL drift/malformed readiness.
- [ ] Extend the four exact >51 predecessor guards identified by the schema52 audit,
  save/restore their original definitions and preserve production-recovery-v1
  API marker. Cover changed predecessor graph and new objects in the 52 fingerprint,
  avoiding recursive compatibility checks. Preserve all published pins.
- [ ] Same database 51 -> 52 proves existing registered runtime/search/API
  readiness and calls still work. Unknown 53 and mixed states refuse.
- [ ] No-export guarded down with real retained runtime-51 evidence restores exact
  51 and preserves bytes; later 51 -> 50 still refuses incompatible precision.
  Empty down/reinstall also passes. Any retained export
  authority/intent refuses rollback, including failed and orphan-recovery states.
- [ ] Include the minimal exact52 migration-command and render compatibility
  checks from Task6 in this publication unit. Adding embedded52 while leaving
  the latest-release gate and renderer at51 would break `npm run verify`.
  Keep export capabilities disabled until their real API/worker wiring passes;
  preserve default49 and both existing precision phase selections. This is
  source compatibility, not permission to activate a live deployment.

Commands: PG18 on PATH, go test -race ./migrations ./apiserver with scoped tests
first, then full affected packages. Reuse existing disposable PG fixtures; never
point acceptance at an arbitrary existing DSN.

## Task 4: Worker, outbox and restart-safe S3 execution

Files: new agentsec-worker/audit_export_runtime.go/_test.go,
audit_export_database.go/_test.go, audit_export_outbox.go/_test.go,
audit_export_production.go; narrow runtime_config.go/production_runtime.go
composition and existing background topic registration. Reuse jobqueue and
recovery_outbox_runtime.go patterns, not its unrelated principal/topic.

- [ ] RED: actual composed worker cannot execute a queued export before wiring.
- [ ] Add closed audit-export topic and explicit worker/outbox mode selection;
  fresh 52 readiness before each authority operation, no schema fallback.
- [ ] Bounded frozen-row reads, deterministic <=1 MiB chunks, intent before Put,
  exact receipt after verified provider result. Renew leases under bounded context.
- [ ] Never renew concurrently as a substitute for the capture transaction's
  confirmed lease budget; SQL enforces byte bounds before Go sees a frozen page.
- [ ] Finish only after all chunks and final manifest verified. Stable failures
  and retries retain evidence; no silent skipping or automatic artifact deletion.
- [ ] Restart matrix with actual PG and real SDK controlled provider: crash after
  capture; saved Put/lost response; receipt committed/lost response; stale worker;
  final manifest saved/finish lost; duplicate queue delivery and outbox publish.
  New process resumes exact contents and one terminal audit without metadata-only
  shortcuts. Queue acknowledgement never substitutes for durable finish.
- [ ] Controlled SQS/S3 integration uses existing provider harness patterns.
  Label controlled transport evidence honestly; add actual local provider run
  where existing harness supports required checksum/version behavior.

Commands: go test -race ./agentsec-worker ./jobqueue/... ./artifactstore/...
Run focused behavior RED before implementation and retain exact terminal logs.

## Task 5: Actual API routes and retrieval composition

Files: new apiserver/audit_export_http.go/_test.go,
audit_export_production_test.go; narrow composition.go, production.go and
production_runtime.go dependency ownership/cleanup; OpenAPI/client decoder tests.

- [ ] RED through actual production router/factory, not component-only handler:
  POST unavailable, GET cannot retrieve durable bytes.
- [ ] Mount browser-only operations, current role set, fresh POST, CSRF/origin,
  exact empty body/idempotency and scope rules. No PAT or caller scope bypass.
- [ ] Current session rechecked each GET. Resolve stored manifest/chunk authority
  then pinned S3 read, verify bytes before response. Signed cursor binds export,
  selected scope/principal/operation/export, ordinal and immutable manifest. No caller-selected provider key/version.
- [ ] Real composed HTTP -> registered PG -> worker -> S3 SDK -> HTTP full traversal,
  including >64 MiB total, empty source, >100,001 events and bounded peak memory.
- [ ] Source append/change after capture does not alter retrieved snapshot.
  Restart API/worker; revoke membership between pages; foreign IDs/cursors,
  drift/missing S3 versions/digest corruption/timeouts return stable errors.
- [ ] Factory Close closes owned DB/provider transports; partial construction
  cleans up. No capability-erasing readiness cache or in-memory fallback.

Commands: go test -race ./apiserver ./agentsec-api and applicable generated
OpenAPI/client contract tests. Record full responses/fields assertions without
logging credentials or exported sensitive fixture payloads.

## Task 6: CLI and release 52 compatibility

Files: agentsec-migrate/main.go/main_test.go plus new actual binary PG acceptance;
deploy/production release-contract modules/tests; deploy/staging/product worker/API
configuration/templates; exact scoped IAM changes in deploy/staging/main.tf/tests.

- [ ] Built binary explicit up-to-52, principal registration and ready API/worker;
  old commands/defaults unchanged. Bad mixed state and rollback guard refuse.
- [ ] Test warmed 51 application instances against 52, including workflow/risk,
  HTTP/reconciliation, outbox/delivery, all five stages and target2 APIs. Old
  migration binaries may deliberately refuse unknown 52. Test drift after cache
  warmup and behind lock waits with no effects; preserve the fixed50 cutover refusal. Preserve schema-50 cutover and precision selectors.
- [ ] Evaluated IAM: executor writes only export prefix + KMS needed to write/read;
  API reads exact export prefix/version, no Put/Delete; outbox only queue authority.
  Preserve all legacy grants, avoid new wildcard broadening.
- [ ] Rendering/validation requires migration/principals before enabling export
  capabilities. No deployment or live activation inferred from a rendered flag.
- [ ] CI includes new packages and actual PG/SDK acceptance, with dependency pins.

No 52 rollout policy is settled by this proposal. Root approval is required before
editing compatibility/deployment contracts.

## Task 7: Acceptance report and later UI dependency

- [ ] Fresh full affected Go race suites, actual PG binary/registered-role tests,
  controlled provider and size/restart tests, OpenAPI/release/IAM tests.
- [ ] Record exact commands, fixtures, byte/event counts, memory bounds, RED/GREEN,
  source hashes, independent review and live-provider limitations.
- [ ] Update existing setup/API docs and ui-api-map to api_available only after
  route evidence. No original ledger credit by inference.
- [ ] M7-36 follow-up: actual whole-audit server filtering/First+Next browsing,
  start/poll/retrieve and complete canonical-bundle saving, progress/failure/reauth
  states and real API browser tests. Execute actual SSO/config/policy/test
  mutations and verify their persisted IDs in filtered views and full export.
  Explicit tested-browser saving support and bounded memory are required; no
  capped client-list export or first-page-only substitute. API work does not
  complete UI. Preserve the reviewed destination/finalization semantics.

Pure codec (1) and typed storage profile (2) may proceed independently. Freeze
reviewed codec/SQL interfaces before authority (3), then worker (4), API (5),
release integration (6) and acceptance. Keep compatibility
review early in Task 3, not after a large feature has assumed 52 works.
# Execution update: grouped verification (September 14)

The user explicitly requested faster implementation through grouped testing.
Execute related changes as coherent batches. Keep focused TDD checks during
implementation; run affected integration gates once on the frozen batch, then
one independent SPEC/QUALITY review. Reuse unchanged verified dependencies;
repeat expensive tests only when changed code or a concrete finding invalidates
their evidence. Keep each original microtask's own evidence/status mapping.
Read-only reviews may overlap independent implementation. Tenant isolation,
authorization, migrations, recovery and UI-runnable publication gates remain
mandatory. This changes execution granularity, not the original 728-task scope.
