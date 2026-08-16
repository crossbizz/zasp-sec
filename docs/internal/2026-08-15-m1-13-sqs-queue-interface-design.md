# M1-13 SQS Queue Interface Design

## Decision

Add a dependency-free `services/platform/jobqueue` package that owns the
product batch-job contract and delegates transport to a narrow typed driver.
Keep AWS SDK, queue URL/ARN, LocalStack endpoint, provider credentials, redrive
configuration, and disposable provider lifecycle in `proofs/localstack-sqs`.

This continues the product/provider boundary established by M1-11 and M1-12:
product code owns scope, product job identity, bounded batches, canonical
envelopes, receipts, deadlines, and fixed errors; provider adapters own SQS
requests and strict response parsing. Importing AWS types into
`services/platform` or treating the existing proof `main` package as a product
dependency is rejected.

## Product interface

The package exports a `JobQueue` interface with `PublishBatch`, `ConsumeBatch`,
and `AcknowledgeBatch`. A concrete `Queue` is constructed from a narrow
`Driver` and a `Config` containing:

- one positive operation timeout no greater than 30 seconds;
- a maximum batch count from 1 through 10;
- a positive maximum message size no greater than 1,048,576 bytes; and
- a positive maximum aggregate batch size no greater than 1,048,576 bytes.

These limits match the current official SQS batch APIs while allowing a caller
to choose stricter product limits. M1-13 has no local retry buffer and does not
split oversized input into hidden provider calls.

Every `Job` carries a validated `domain.Scope`, a nonzero product `JobID`, an
allowlisted kind token, and a nonempty bounded JSON payload. The initial kind
grammar is lowercase `[a-z][a-z0-9._-]{0,62}`. Product code constructs one
deterministic UTF-8 JSON envelope with exactly:

`version`, `job_id`, `organization_id`, `workspace_id`, `environment_id`,
`kind`, and `payload`.

Version is exactly `1`. Scope and job IDs use their canonical product strings.
The payload is opaque valid JSON for the later type-specific consumer, but the
outer envelope is strict: exact lowercase keys, no duplicates, no unknown
members, no trailing data, and no mismatched body/scope/job/kind state. The
same `JobID` cannot appear twice in one batch.

`PublishBatch` returns product job IDs only after the driver reports exactly
one success per requested job and zero failures. `ConsumeBatch` requests a
bounded count and returns `Delivery` values containing defensive job copies
and opaque `Receipt` values. A receipt exposes only its product job ID; the
provider message ID and receipt handle remain unexported product state.
`AcknowledgeBatch` accepts one through ten distinct receipts returned by this
queue, requires exact driver success for every job ID, and rejects partial,
duplicate, zero, or forged receipts.

The product `Driver` boundary uses typed `DriverMessage`, `DriverPublished`,
`DriverDelivery`, and `DriverReceipt` values. Driver messages carry the exact
canonical body plus typed scope/job/kind/digest fields so an adapter can map
provider metadata without parsing customer payload semantics. Driver returns
must exactly match the requested or decoded product state before the product
operation succeeds. No queue name, URL, ARN, message ID, receipt handle,
provider error, or credential crosses the public `JobQueue` interface.

## Failure, ownership, and concurrency behavior

Each operation validates all input before driver I/O, applies one total
configured deadline, contains driver panics, and returns only a fixed product
error: configuration, job validation, publish, consume, or acknowledge.
Product code does not retry. Timeout, cancellation, driver error, panic,
partial batch success, duplicate or foreign IDs, malformed envelopes,
mismatched metadata, and invalid receipts fail closed without exposing bodies
or provider state.

The queue is safe for concurrent independent operations. Caller and
driver-owned byte slices are defensively copied. A consumed job is never
acknowledged implicitly: the caller must finish its durable work and pass the
opaque receipt to `AcknowledgeBatch`. This preserves the PRD rule that required
archive/index/correlation work precedes SQS acknowledgement. M1-13 does not add
a worker loop, automatic visibility extension, retry policy, queue definitions,
or a DLQ consumer.

## SQS adapter and LocalStack proof

The existing exact-pinned AWS SDK SQS client gains a narrow `sqsJobDriver`.
It maps a product batch to one `SendMessageBatch` request, using the canonical
product job ID as the entry ID and exact string message attributes for
organization, workspace, environment, job ID, kind, and body SHA-256. It
requires all requested entries to succeed even when SQS returns HTTP success.

Receive uses bounded long polling with at most ten messages. The adapter
requires a nonempty message ID and receipt handle, exact attributes, an exact
body digest, and an outer envelope matching those attributes before returning
typed driver deliveries. Acknowledge uses one `DeleteMessageBatch` request and
requires exactly the requested entry IDs with no failed entries. Definitive
provider rejection is never reconciled or adopted. Only thrown/signaled or
malformed-success mutation outcomes may enter bounded exact-state
reconciliation.

The M1-13 live lifecycle creates one uniquely named Standard queue and one DLQ
under a new `zasp-m1-13-<marker>` namespace, proves exact URL/ARN/name/account,
atomic proof tags, `RedrivePolicy`, and `RedriveAllowPolicy`, then publishes,
consumes, and acknowledges exactly two scoped jobs through the product
`JobQueue`. It proves the source empty before reverse cleanup. Cleanup retains
candidate authority immediately after each create attempt, uses an independent
bounded context, freshly re-proves ownership before source-then-DLQ deletion,
and requires prefix-wide absence. Cleanup failure wins.

The existing M0-06 default proof remains byte-for-byte compatible. The hardened
disposable LocalStack runner adds an M1-13 mode with only SQS enabled, an exact
image digest, unique name/labels, loopback-only publication, bounded readiness,
offline Go build, fixed output, full-ID candidate retention, and exact
container/temp cleanup. It reads no dotenv, cloud profile, proxy, real
credential, or ambient Docker authentication and never selects the shared
development LocalStack container.

The fixed success line is:

`LocalStack job queue passed: publish=2 consume=2 acknowledge=2 scoped=true redrive=true empty=true cleanup=true audit=true container_cleanup=true.`

LocalStack evidence proves supported local SQS behavior only. It does not claim
real-AWS IAM, durability, availability, encryption, or release parity.

## Tests and completion

Hermetic product tests cover configuration, job/scope/kind/payload validation,
canonical envelope bytes, duplicate IDs, exact driver forwarding and return
state, defensive copies, opaque receipts, partial results, fixed errors,
deadlines, cancellation, panics, and concurrent use. Adapter tests cover exact
SQS body/attributes/digest mapping, partial publish/delete rejection, strict
receive parsing, definitive versus ambiguous mutation classification, and
foreign or malformed state. Lifecycle tests cover exact queue/DLQ ownership,
redrive policies, two-job round trip, reverse cleanup, cleanup precedence,
prefix-wide audit, cancellation, panic, and collision non-adoption. Existing
M0-06 SQS behavior and M1-12 artifact regressions remain green.

Root commands are `npm run job:queue:test` and `npm run job:queue:run`. M1-13
may move to Complete only after tests-first RED/GREEN evidence, six focused
passes, all affected Go and pinned repository gates, the exact disposable live
proof, post-live zero-resource audit, unchanged shared-container fingerprint,
secret scans, zero-finding independent review, push, and exact-SHA Runnable UI
success. M1-14 remains Pending throughout.
