# M1-39 OpenSearch Organization Scope Guard Design

## Decision

Harden the existing dependency-free `services/platform/eventstore` boundary
with explicit internal index-document and search-query builders. Both builders
take one validated `domain.Scope`; neither can produce driver state without the
canonical Organization, Workspace, and Environment IDs from that scope.

M1-14 already proved the correct end-to-end shape: the product `Store` accepts
typed scope and events, while the proof-owned adapter converts the resulting
driver values into strict OpenSearch requests. M1-39 preserves that public
interface and provider adapter. A second EventStore, OpenSearch client, raw DSL
API, index-name API, or ambient tenant context would duplicate authority and is
rejected.

## Scoped builders

`buildDriverDocument(scope, event)` validates the supplied scope, requires the
event to carry the identical complete scope, and emits one `DriverDocument`
whose `OrganizationID` is the canonical Organization string from the supplied
scope. It also preserves all existing event-ID, session, agent, allowlist,
source-event-ID, and UTC-millisecond validation.

`buildDriverQuery(scope, filter, maximumResults)` validates the supplied scope,
requires one nonzero session ID and a limit within the configured maximum, and
emits one `DriverQuery` with the same canonical Organization, Workspace, and
Environment IDs. Its sort slice is newly allocated and fixed to event time,
then event ID.

`Store.Index` and `Store.Search` call those builders before creating a deadline
or invoking the driver. Invalid or zero Organization scope therefore reaches
neither OpenSearch nor any injected driver. Builder results are per-operation
values; the store retains no Organization, document, query, index, credential,
endpoint, or provider state.

## Cross-Organization containment

The driver query always includes the requested Organization ID. Product code
does not trust that filter alone: every returned document is independently
required to match the exact requested Organization, Workspace, Environment,
and session before conversion. An Organization-A query that receives an
otherwise valid Organization-B fixture fails closed with no returned events.
The same-session negative case is explicit because session IDs are not tenant
authorization boundaries.

The proof adapter continues to own the strict four-term OpenSearch bool filter
and M1-14 remains the provider-compatibility authority. M1-39 makes no new
claim about OpenSearch IAM, index aliases, mappings, durability, availability,
retention, rebuilds, or AWS release parity.

## Failure and concurrency behavior

The existing fixed errors remain authoritative: invalid index state maps to
`ErrEvent` or `ErrIndex`; invalid query state maps to `ErrFilter` or
`ErrSearch`. Driver errors and panics stay contained. Cancellation and timeout
remain one total operation boundary. No customer or provider value is copied
into an error.

Independent builder and store calls allocate fresh query slices and results.
Concurrent Organization-A and Organization-B calls cannot share or mutate
tenant state.

## Verification and completion

Tests directly cover exact builder output, zero and malformed scope rejection,
scope/event mismatch, fresh sort allocation, and the same-session
Organization-A/Organization-B fixture. A hostile driver returning the B
document to the A query must be rejected after exactly one A-scoped driver
call. Existing M1-14 adapter and store regressions remain green.

M1-39 may move to Complete after genuine tests-first RED/GREEN evidence, six
race-enabled focused passes, the full platform and pinned repository gates,
redacted secret scans, zero-finding review, push, and exact-SHA Runnable UI
success. M1-38 remains Complete and M1-40 remains Pending.
