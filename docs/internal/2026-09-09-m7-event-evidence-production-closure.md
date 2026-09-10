# M7-07b: canonical event rows and evidence metadata

Status: implementation, composed pipeline, full browser verification and final
local gates passed. Shipping gates are pending. No M7-07b production credit yet.

The original criterion is unchanged: tool, runtime, network, file, credential
and policy rows must each render a deterministic label and evidence link.
M7-07c's Probable/Exact display fixture and M7-07's mixed-evidence session remain
separate, incomplete tasks.

## Implemented boundary

Schema 44, `production_runtime_session_evidence`, adds the exact scoped event
metadata reader and permits the six canonical classes with closed source/action
pairs. OTLP supplies tool/invoke, credential/use and policy/allow/monitor/block.
Tetragon supplies process/exec/exit, file/read/write and network/connect/accept.
Credential observations require an observed credential reference; policy
observations require a matching observed decision. Neither accepts raw content.
These claims do not prove credential ownership or policy enforcement and do not
change the existing correlation algorithm.

Fingerprint:
`4e72e5fbd7ba47641d5241a9392e58956c94611bcbb36de5b0341868b3a5fe33`.
Shipped migrations 1 through 43 are unchanged. Downgrade takes the event-table
lock before checking retained semantic rows and refuses destructive rollback.
Real PostgreSQL tests cover concurrent insertion, retained rows, fresh permission
denial, exact scope/investigation/event matching, direct-table denial and upgrade
readiness.

`GET /api/v1/sessions/{id}/events/{eventId}` uses the browser's expected scope
and fresh `investigate_sessions` permission. It returns eleven canonical metadata
fields with `Cache-Control: no-store`. It does not expose raw S3 content, a signed
download URL or provider credentials. The generated-client UI verifies the
returned event, evidence and investigation identities, aborts stale requests,
and opens a nested evidence-metadata dialog from each row's link.

## Evidence so far

Superpowers test-first and verification/review practices use the official
upstream skill text because an installed Superpowers plugin was unavailable.
Independent read-only review found no blocker in the adapter, migration, API,
UI or six-class proof source. After completed Chrome and final verification,
independent review accepted M7-07b conditionally on shipping/main CI.

- Adapter and projection tests first rejected the newly supported semantic
  observations, then passed their canonical archive/replay and invalid-input
  cases. Schema, CLI, API, decoder and evidence-UI tests had corresponding
  failing-first checks.
- Five focused UI/decoder files passed 83 tests. The evidence component's own
  two-file selection passed 14 tests, including wrong returned identities,
  stale responses, six labels/links and distinct Probable/Exact badge tones.
- The actual owned PostgreSQL/SQS/S3-KMS/OpenSearch proof passed on schema 44.
  Twenty-six reverse-ingress kernel events retain their original canonical
  timestamps and evidence IDs, now including file and network rows. A separately
  enrolled OTLP source sends three semantic classes through all five workers
  and the session search outbox. Canonical rows, confidence, receipt linkage and
  replay stability are checked, without inserting session-table fixtures.
- The first semantic readback assertion failed because it queried a nonexistent
  event-table batch column. Joining the existing projection receipt's event IDs
  corrected the test; the five stages had already succeeded.
- Adding the API exposed stale exact operation inventories. Their expected
  surface now includes 147 public operations and 153 UI-map actions, of which
  141 are available, six API-only and six planned. No checks were removed.
- Chart schema expectation was still 41. The chart, staging identity gate and
  production release's exact job/annotation expectations now agree on 44.
  A positive test compares the chart with the highest embedded migration.
  The initial release gate rejected the mismatched job identity; focused
  release checks passed after the correction.

The pipeline uses explicit graph-store fixtures. Neo4j, real cloud IAM,
deployed-provider behavior and a live production rollout are NOT RUN. Local
proof and green shipping CI do not establish live launch readiness.

The full Chrome run passed with the generated client and real product API:
all six event types opened their exact canonical evidence metadata; wrong
investigation, tenant scope and freshly revoked permission were denied.
It also passed nested modal focus, responsive outer-layout checks, the original
reverse-ingress 25-plus-1 timeline, discovery/connector/Red Team/recovery flows,
durable reload and owned-process cleanup. Staged secrets passed. Privacy review
found eleven MEDIUM matches, all fixed fixture AWS account/ProductIDs or public
CI run identifiers, with zero HIGH findings.

## Final local gates

The full Node 22 verification passed: 195 frontend test files / 1,172 tests,
generated OpenAPI, typecheck, lint, rendered release validation, compiled UI
build/import boundaries and the 728-row ledger. Complete API race tests passed
in 287.227s. The final runtime-event/projection/correlation/session-search and
migration race suites passed; the complete migration CLI suite passed in
60.142s. Ledger/harness/staging contracts passed 47 tests with two explicitly
gated runtime tests skipped. The production source release gate passed; its
built-image, remote CI, provider and DNS/TLS gates are still distinct.

## Next-task correlation gap

Independent inspection confirmed that current production ingestion cannot
produce Strong or Probable correlation. Tetragon drops all correlation lineage;
OTLP preserves sandbox only. The correlation matcher requires two matching
lineage fields, and its candidate set comes only from identified records in the
same single-source archive.

M7-07c's narrower visual criterion can use honest production-row fixtures to
compare Probable with Exact. That is not evidence of production correlation
reachability. M7-07 needs a provenance-backed, tenant-scoped candidate source
across batches, bounded observed lineage, event-time/host/boot identity and
receipt-bound replay behavior. Bare process IDs or unqualified cgroups cannot
authorize attribution. Ambiguous evidence must retain null authoritative
agent/session IDs. This work remains in the original critical path.
