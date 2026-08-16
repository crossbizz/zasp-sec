# M1-14 OpenSearch EventStore Design

## Decision

Add a dependency-free `services/platform/eventstore` package that owns the
product event indexing and search contract. Adapt the existing hardened
`proofs/opensearch-event` REST boundary and disposable OpenSearch lifecycle to
that product contract instead of importing proof or provider types into the
platform module.

This follows the M1-12 and M1-13 boundary: product code owns scope, identity,
event semantics, limits, deadlines, fixed errors, and defensive copies;
provider code owns index names, mappings, HTTP transport, OpenSearch response
parsing, lifecycle ownership, and credentials. Promoting the M0-08 `main`
package into product code or building a second OpenSearch lifecycle is
rejected.

## Product interface

The package exports an `EventStore` interface with `Index` and `Search`. A
concrete `Store` is constructed from a narrow `Driver` and a `Config` containing
a positive operation timeout no greater than 30 seconds and a maximum result
count from 1 through 100.

Every operation receives a validated `domain.Scope` as a separate mandatory
argument. `Index` also receives an `Event`; `Search` receives a `Filter`. The
store requires the supplied scope to equal the event scope and includes the
Organization, Workspace, and Environment IDs in every driver document and
query. A caller cannot construct an unscoped query or request raw provider DSL.

An `Event` contains:

- one validated product `EventID`, `SessionID`, and `AgentID`;
- the validated Organization, Workspace, and Environment scope;
- an allowlisted source, event class, action, and decision;
- one bounded source event ID; and
- one canonical UTC timestamp with millisecond precision.

The M1-14 skeleton supports the proven runtime-gateway tool-invocation event:
source `runtime_gateway`, class `tool`, action `invoke`, and decisions
`allowed`, `monitored`, or `blocked`. Strings are bounded, valid UTF-8, contain
no control characters, and are never copied into fixed error output. Prompt,
response, arbitrary customer payload, provider metadata, and raw search text
are outside this task.

`Filter` requires one nonzero session ID and a result limit within the configured
maximum. Search ordering is deterministic: event time ascending, then event ID
ascending. Every returned event must match the exact requested scope and
session, be valid independently, and have a unique event ID. The product
boundary copies driver slices before returning them.

The driver receives only typed product state:

- `DriverDocument` with canonical string IDs and event fields;
- `DriverQuery` with exact Organization, Workspace, Environment, session, limit,
  and ordering fields; and
- an exact `DriverIndexed` acknowledgement containing the requested event ID.

No index name, OpenSearch document metadata, query DSL, provider error,
endpoint, or credential crosses the public `EventStore` interface.

## Failure, deadline, and concurrency behavior

Input validation happens before driver I/O. Each operation creates one total
configured deadline, contains driver panics, performs exactly one driver call,
and returns only fixed product errors: configuration, event, filter, index, or
search failure. Product code does not retry.

Index succeeds only when the driver acknowledgement exactly matches the event
ID. Search rejects partial, duplicate, foreign-scope, foreign-session,
unordered, malformed, oversized, or aliased driver results. Cancellation,
deadline expiry, driver error, panic, nil or typed-nil dependencies, and
malformed success all fail closed. Independent calls are safe for concurrent
use.

## OpenSearch adapter and disposable proof

The existing exact-pinned `proofs/opensearch-event` module gains a narrow
adapter implementing `eventstore.Driver` over its strict loopback REST backend.
The adapter converts product documents to the current strict mapping, uses
create-only document indexing with a deterministic document ID, and emits a
structured `bool.filter` query with mandatory exact terms for Organization,
Workspace, Environment, and session. It requests the configured bounded size
and deterministic event-time/event-ID sorting. Provider responses are parsed
strictly and converted back to typed product events before the product store
validates them again.

The M0-08 lifecycle remains compatible. The M1-14 lifecycle creates one exact
disposable index, indexes one Organization-A event through the product
`EventStore`, finds it through an Organization-A scoped search, proves the same
session under Organization B returns zero hits, and then performs the existing
exact ownership cleanup and prefix-wide absence audit. The shared development
OpenSearch or LocalStack targets are never selected or changed.

The disposable runner retains the exact image digest, unique name and labels,
loopback-only publication, bounded readiness/build/proof phases, fixed output,
candidate-aware cleanup, and exact container/temp absence. It reads no dotenv,
cloud profile, proxy, real credential, or ambient Docker authentication.

The fixed success line is:

`OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true container_cleanup=true.`

This proves disposable OpenSearch compatibility only. It does not claim AWS
OpenSearch Service IAM, durability, availability, encryption, index-template,
retention, rebuild, or release parity.

## Tests and completion

Hermetic product tests cover configuration, mandatory scope, typed IDs,
allowlists, timestamp and string bounds, exact driver forwarding, result
ordering, defensive copies, fixed errors, cancellation, deadlines, panics,
malformed state, and concurrent use. Adapter tests cover exact create-only
indexing, mandatory four-term scoped queries, bounded sorting/results, strict
response parsing, foreign-hit rejection, and safe-read versus mutation retry
rules. Lifecycle tests cover A-hit/B-zero isolation, exact index/document
ownership, ambiguous mutations, collision non-adoption, cleanup precedence,
prefix-wide audit, and disposable runner containment.

Root commands are `npm run event:store:test` and
`npm run event:store:run`. M1-14 may move to Complete only after genuine
tests-first RED/GREEN evidence, six focused passes, all affected Go and pinned
repository gates, the exact disposable live proof, post-live zero-resource
audit, unchanged shared-target fingerprint, license and vulnerability checks,
secret scans, zero-finding independent review, push, and exact-SHA Runnable UI
success. M1-15 remains Pending throughout.
