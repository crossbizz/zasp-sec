# Audit export: frozen jobs and immutable S3 contents

Status: root approved implementation, 2026-09-12. No acceptance credit yet. This revision
supersedes the initial PostgreSQL-only recommendation because it omitted the
original S3 export requirement. This records design decisions, not completed
product or migration work.
The execution branch is codex/audit-export-api. Current implementation evidence
and availability are in the status ledger; dated implementation facts below
describe the initial design checkpoint unless explicitly revised.

## Requirements and existing implementation

The original Technical Implementation Plan v1.5 §6 assigns transactional export
state to Neon and export artifacts to S3. M1-34 requires scoped export prefixes
and KMS. M2-41/M2-42 require authorized POST /api/v1/audit-exports and GET
/api/v1/audit-exports/{id} with stable product errors. M7-36 requires a filterable
audit page and export action, with actual SSO/config/policy/test mutation E2E.
No CSV, one-time download grant or presigned URL is
required to implement these routes.

Initial implementation facts, followed by the approved source correction below:

- audit/store.go counts in-memory events and saves ready/count metadata only.
- identity/http.go has component-only export routes: POST export_evidence plus
  fresh authentication; GET view_audit. Production composition excludes both.
- Production view_audit reaches the same organization-admin, security-admin
  and compliance-viewer roles as component export_evidence. Preserve this role
  set, browser-only access and fresh POST rather than adding unrelated privileges.
- The initial reader/capture uses zasp_admin_audit alone, organization-wide,
  ordered occurred_at DESC/id DESC, with rejected mapped to denied. Source tracing
  found that this omits the original required policy/test mutation records. The
  exact shared-source correction below supersedes that admin-only assumption.
- OpenAPI has unused empty input/ready-only descriptor schemas but no production
  routes. ui-api-map marks both planned.
- artifactstore.Store bounds individual bodies to 64 MiB. s3driver.Put already
  implements IfNoneMatch *, one attempt, ambiguous-Put discovery and pinned
  readback/content verification. Reuse it.
- bucketlayout.Layout.Key(scope, ClassExport, reference) implements scoped
  /exports/ keys and KMS configuration. Store and S3 driver locator validation
  currently hardcode /artifacts/. A typed export-prefix integration is needed
  in BOTH layers; existing artifact constructors/paths must remain unchanged.

## Approved correction: the exact public audit source

Real policy mutations persist in zasp_workflow_audit; test definition/run/cancel
mutations persist in zasp_red_team_audit. They are absent from admin-only list
and capture. The final shared source must include administration plus these exact
families, with one typed private projection used by both full-source listing and
export capture. This is required original M7-36 coverage, not permission to expose
all subsystem audit tables or raw event bodies.

Map create/update/delete/rollout/disablePolicy to policy.create/update/delete/
rollout/disable. Map the four red-team mutation kinds to test.create, test.update,
test.run.queued and test.run.cancel_requested. Outcomes describe committed
mutations, not passed tests, terminated executions or converged enforcement.
Preserve original audit ID, actor, scope, target and timestamp. Small validated
metadata retains source operation/event kind, correlation, version or
receipt/digest provenance. No joins to mutable resources or expiring receipts
may erase retained history; no raw provider/domain body is public metadata.

Existing admin actions retain their exact bytes. The public/export action grammar
accepts the existing lowercase grammar plus exactly these published exceptions:
identity_provider.createSSOConnection, identity_provider.deleteSSOConnection,
identity_provider.testSSOConnection, identity_provider.createSCIMConnection and
identity_provider.deleteSCIMConnection. Generic emitter validation stays unchanged.
Do not normalize retained action names or rewrite published migrations1-51.

Use a private authority-owned typed projection with no new raw API/worker grants.
The new page authority checks compiled52/discovery readiness and current browser
view_audit before reading and after waits, without importing storage policy into
its read authorization. The existing explicit AuditExports configuration selects
this full-source composition. A selected new path fails closed without falling
back to the admin-only source. Legacy composition cannot claim new completeness.

IDs must be unique across eligible sources within an organization, including
records at different timestamps. Listing probes all eligible sources for each
bounded candidate ID without filter/time restrictions. Capture detects collisions
across its complete one-statement snapshot. Raise explicit refusal, never dedup,
rename IDs, filter malformed required records away or skip a cursor record.
Pin the view definition/security options and dependent catalog/ACL/RLS structure
in52 readiness. Empty rollback restores51 while preserving policy/test history.

This source correction has independent design approval, not implementation or
production acceptance. It must pass actual producer-based list/capture tests,
tenant/current-auth controls, collision/drift/rollback tests and the original
browser mutation/filter/export E2E. A shared read projection includes retained
records without mirror writes or a separate history backfill.

## Recommendation

Durable PostgreSQL job and frozen event projection; resumable worker; bounded
immutable JSON chunks plus a small final manifest in S3; the two original
routes return status and actual version-pinned contents.

POST -> atomic job/idempotency/request-audit/outbox
     -> background queue wakeup -> DB-authorized worker snapshot
     -> bounded S3 chunks + immutable exact receipts -> final S3 manifest
     -> atomic ready + completion audit
GET -> current browser authorization -> persisted authority -> pinned S3 contents

| Alternative | Decision |
| --- | --- |
| One bounded DB blob | Reject: omits S3 and excludes larger organizations. |
| Paged DB final export | Reject as final architecture; useful snapshot machinery but violates §6. |
| Whole-file/multipart S3 | Defer: introduces extra upload/recovery machinery or large local buffers. |
| DB snapshot + chunked S3 | Recommend: complete contents, bounded operations, existing provider recovery. |

### Complete snapshot and scale

POST durably queues work. It does not claim a snapshot at HTTP arrival. The
worker's first successful capture freezes every organization audit row visible
to one PostgreSQL statement snapshot. Record requested_at separately from
captured_at. Timestamp is descriptive, not a later membership predicate.
Backdated rows committed after capture are excluded. Retries use frozen bytes
and ordinals, never requery live audit pages.

Use one INSERT ... SELECT in a transaction to freeze the public audit projection
with deterministic order, count and byte totals. Go does not load the whole
export. Cancellation/failure rolls back the complete capture. This is a real,
potentially substantial DB transaction, not constant-time or paged MVCC.
Paging the live source across transactions is not an acceptable substitute.

Capture holds the job and organization admission fences. A heartbeat cannot be
assumed to extend a lease locked by that transaction. Before capture, compute
the deadline from confirmed lease expiry, caller deadline and the 120-second
capture limit, leaving transaction-finalization margin. Refuse insufficient
remaining lease. After INSERT and before commit, recheck wall-clock lease expiry
and fresh 52 readiness; expiry/drift rolls back every snapshot row and admission
counter change. Contenders cannot bypass the organization capacity fence.

Process frozen ordinals into proposed <=1 MiB, <=1,000-event JSON chunks.
Preserve identity/scope/action/target/outcome/timestamps and deterministic
metadata redaction. Freeze the projected bytes. An invalid or oversized single
event explicitly fails the export; never silently skip it.

Frozen-page SQL itself bounds BOTH serialized response bytes and row count before
JSON aggregation/transport. Limit cumulative event bytes plus exact envelope and
separator overhead, not merely LIMIT 1000 followed by Go chunk packing. Return
only a bounded prefix and next ordinal; reject an oversized first event. Otherwise
1,000 near-1-MiB rows could allocate almost 1 GiB in Go before chunking. Enforce
the same response-byte limit in the repository decoder as defense in depth.

There is no 64 MiB whole-export cap or tiny-organization row cap. Root selected
configurable defaults: 1 GiB/export, 10 GiB retained bytes/organization, two
in-flight exports/organization and a 120-second capture deadline capped by the
remaining lease/context. Chunk limits are 1 MiB and 1,000 events. These are
resource bounds, not smaller functional scope. Serialize quota admission per organization; check actual
totals before capture commits. Capacity failure is a stable failed descriptor,
never ready metadata. Benchmark >64 MiB total and >=100,001 events with bounded
Go memory. If production-scale capture cannot fit the agreed DB budget, durable
append-sequence/snapshot evolution is a prerequisite, not permission to truncate.
Retain failure evidence and do not silently delete snapshots via existing jobs.

### API contract

POST input remains exact {} with Idempotency-Key. Browser membership, export-
capable role set, freshness, origin and CSRF checks remain required. Root selected
HTTP 201 for the created job resource, including exact idempotent replay. The
descriptor can be queued, processing, ready or failed; preserve the successful
POST status instead of introducing 202/200. Keep the existing error envelope: invalid request 400, authentication
401, authorization 403, scoped not-found 404, idempotency conflict 409,
provider unavailable 503. Do not expose foreign export existence.

GET without cursor returns status/descriptor. Ready responses additionally return
the first actual bounded chunk and an opaque next cursor; the same GET route
retrieves remaining chunks. Queued/processing/failed descriptors have no contents
or download cursor. Every page rechecks current view_audit membership. GET does
not require fresh authentication beyond current production read semantics.
Cursor uses the existing authenticated cursor protocol and binds selected scope,
principal, operation, export ID, immutable manifest digest and next ordinal.
Caller-supplied object keys/versions and latest-object fallback are forbidden.

Each page includes format, ordinal, exact chunk digest, immutable manifest digest,
total events/chunks and contents. The small final S3 manifest contains export/
capture IDs, scope, format, counts/bytes and an ordered chunk-chain root, not an
unbounded array. PostgreSQL retains immutable exact per-chunk locator/version/
digest/range receipts. Chunks bind export, ordinal, event interval and previous
chain value. Full traversal verifies count/order/chain coverage. Empty captures
produce an explicit zero-count manifest, no fake event.

Org-wide audit visibility is preserved. Physical export artifact scope is the
authorized request's workspace/environment and never changes on another member's
GET. GET validates stored manifest and selected chunk before releasing contents.
No presigned URL, new download endpoint or browser-side 2,000-row audit-list export.

### Authority, delivery and recovery

Migration 52 adds scoped headers, snapshot rows, chunk intents/receipts, leases
and outbox records. Fixed security-definer functions and registered API/outbox/
executor identities enforce tenant isolation and least privilege. Every customer
table carries organization_id; use existing RLS/grant patterns. API calls remain
pooled single-function transactions, migration owner uses the direct connection.

Create atomically commits idempotency, queued job, request audit and outbox.
Recheck persisted browser session/current membership/freshness after SQL lock
waits, not only Go flags. Later requester revocation blocks reads but does not
retroactively invalidate an already-authorized background capture. Queue payload
is a wakeup hint bound to job/scope, never source SQL or artifact authority.

Reuse JobQueue/SQS and recovery outbox lease patterns with a closed new
audit-export topic on the existing background transport. This still requires
new dispatch/codec/worker/repository wiring; no current worker already implements
it. Separate claim/heartbeat/checkpoint/finish functions validate scope, worker,
token, generation, attempt and fresh compiled-52 readiness on each operation.
Do not broaden runtime topics or borrow a runtime principal.

Deterministic packing and codec version produce stable chunk IDs. Persist each
expected intent before Put. Existing conditional Put + pinned readback reconciles
saved-object/lost-response cases. Persist exact version/hash/size/range only after
verification. Restart resumes the first uncommitted ordinal with a fresh lease;
stale and duplicate deliveries cannot rewrite receipts. After exact snapshot
coverage, write/read back the final manifest, then atomically mark ready and append
one completion audit. Lost finish response retries return the same result.

No DB/S3 atomic transaction is claimed. A crash after Put leaves a recoverable
intent/object; permanent failure remains explicit and retains reconciliation
authority. No automatic provider deletion or pretend rollback. Retention/GC must
understand these records before removing either DB authority or S3 versions.

### Migration 52 compatibility

Published release-51 readiness rejects versions above 51. Simply inserting 52
would disable existing precision services. Leave SQL/checksums 1-51 unchanged.
Install an exact compiled-52 compatibility bridge covering old/new identities,
grants and readiness chains; reject mixed metadata, unknown 53 and semantic drift.
Test warmed old application instances explicitly; a SQL bridge alone does not
guarantee it. Old migration binaries may correctly refuse unknown release 52.

The [schema52 audit](2026-09-12-audit-export-schema52-audit.md) identifies four
further >51 predecessor guards:
zasp_workflow_mutate, zasp_risk_mutate,
zasp_production_security_agent_attack_path_security_ready and
zasp_production_workflow_compatibility_security_ready. Extend them exactly with
saved original definitions and a reviewed 52 identity, not blanket replacement.
The 52 fingerprint covers the changed predecessor graph plus all export objects,
without recursion through the replaced 51 endpoint. Preserve published 51 metadata
and global API marker production-recovery-v1 for warmed repositories; exports
have a separate fresh 52 capability.

Add explicit up-to-52 and export-principal registration. Preserve existing
48/49/50/51 commands/defaults and schema-50 cutover authorization. Release-52
configuration must explicitly select export API/worker capabilities while retaining
current precision selectors. Do not claim a manifest or flag authorizes rollout.

Proposed down-to-51 refuses ANY retained export job/snapshot/receipt/artifact
intent, since SQL cannot erase external effects. Empty rollback restores exact
51 readiness and allows reinstall. Existing runtime-51 evidence alone MUST NOT
block 52 -> 51: preserve its bytes, while the subsequent 51 -> 50 guard still
refuses incompatible precision work. Include retained export audit evidence in
52 rollback refusal. The fixed schema-50 cutover controller still refuses 52.

## Decision and completion boundary

Root accepted the asynchronous contract with POST 201, typed export constructors,
JSON chunks plus small manifest, current view_audit with the exact three export-
capable roles and background transport reuse. Initial bounds are above; tune
from measured results. Independent design review and exact migration/rollout
implementation remain prerequisites to product changes.

M2 acceptance requires actual production HTTP composition, registered PostgreSQL
authority and real S3 SDK create/worker/restart/full-retrieval tests. Controlled
SDK fixtures are not a live AWS claim. M7-36 remains component-only until the real
audit page filters the full approved source and starts, polls and saves complete
exports in a browser test showing actual SSO/config/policy/test mutations. No ledger credit,
live rollout or completion claim follows from this proposal.
