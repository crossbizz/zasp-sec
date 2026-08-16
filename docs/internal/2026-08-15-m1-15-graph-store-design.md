# M1-15 GraphStore Interface Design

## Decision

Add a dependency-free `services/platform/graphstore` package that owns the
product graph contract and delegates persistence to a narrow typed driver.
M1-15 defines and proves this boundary with a hermetic fake driver. M1-16 owns
the Neo4j adapter and its disposable provider proof.

This keeps the product independent of Neo4j labels, Cypher, element IDs,
sessions, transactions, endpoints, credentials, and errors. Reusing the
Cartography proof schema as the product interface, accepting raw graph queries,
or importing a Neo4j client into `services/platform` is rejected.

## Product interface

The package exports a `GraphStore` interface with `Upsert` and `Read`. A
concrete `Store` is constructed from a narrow `Driver` and a `Config` containing
a positive operation timeout no greater than 30 seconds, maximum node and edge
counts, and a maximum traversal depth. Product limits are capped at 1,000 nodes,
2,000 edges, and depth 8.

Every operation receives a separate validated `domain.Scope`. Every `Node` and
`Edge` repeats that exact Organization, Workspace, and Environment scope so a
caller cannot submit an unscoped or mixed-scope projection. Nodes contain only
a nonzero canonical product node ID and a product kind. Edges contain only a
nonzero canonical product edge ID, product kind, and nonzero source and target
product IDs. Source/vendor identifiers, arbitrary properties, customer text,
and provider labels are not graph primary keys or product graph fields.

Node and edge kinds use the product grammar `[a-z][a-z0-9_]{0,62}` and reject
provider-native vocabulary such as `aws`, `github`, `cartography`, and `neo4j`
as token segments. The initial interface therefore supports product kinds such
as `cloud_account`, `identity_role`, `contains_identity`, and
`owns_repository` without freezing a provider-specific allowlist.

`Projection` contains bounded node and edge slices. Upsert requires at least
one node, unique node and edge IDs, unique semantic edges, no self-edge, and
every edge endpoint to exist in the same projection. The store sorts defensive
copies by canonical product ID before calling the driver. Success requires an
exact acknowledgement containing every requested node and edge ID once and no
other ID. Replaying the same canonical projection is therefore an explicit
idempotent driver contract; partial success never becomes product success.

`ReadRequest` is a structured internal traversal request containing one
canonical root node ID, direction (`outgoing`, `incoming`, or `both`), depth,
and node/edge limits no greater than the configured maxima. Depth zero reads
only the root. No caller can submit Cypher, predicates, labels, arbitrary
property filters, or provider query text.

Read results are deterministic: nodes are strictly ordered by node ID and
edges by edge ID. Every returned record must have the exact requested scope,
valid product IDs and kinds, unique identities, same-result endpoints, and
bounded counts. An empty result is valid for a missing root. A nonempty result
must contain the root, and every other node must be reachable from it within
the requested depth and direction. This prevents a driver from returning an
unrelated or foreign subgraph while still allowing a bounded partial
projection when a caller chooses limits.

## Driver boundary

The driver receives only provider-neutral typed state:

- `DriverNode` and `DriverEdge` with canonical string product IDs and all three
  scope IDs;
- `DriverProjection` containing deterministic bounded slices;
- `DriverQuery` containing exact scope, root, direction, depth, result limits,
  and fixed node/edge ordering; and
- `DriverUpserted` containing exact acknowledged product IDs.

The public `GraphStore` interface never exposes driver structs. No Neo4j
database, label, relationship type, query, record, element ID, bookmark,
transaction, endpoint, credential, or error crosses the boundary. M1-16 may
translate the driver kinds into an internal fixed Neo4j representation, but it
must convert back to these product-owned values before returning.

## Failure, deadline, and concurrency behavior

Input validation completes before driver I/O. Each operation creates one total
configured deadline, contains driver panics, invokes the driver exactly once,
and returns only fixed product errors: configuration, projection, read request,
upsert, or read failure. Product code does not retry.

Cancellation, timeout, error, panic, typed-nil dependency, malformed success,
partial acknowledgement, foreign scope, duplicate or unordered state,
dangling edge, unreachable node, and oversized result all fail closed. Caller
and driver slices are defensively copied. Independent calls are safe for
concurrent use; the store retains no mutable graph state.

## M1-15 verification and M1-16 boundary

Hermetic contract tests use a deterministic fake driver to prove exact
forwarding, canonical ordering, idempotent replay acknowledgement, bounded
structured reads, scope isolation, reachability, defensive copies, fixed
errors, cancellation, deadlines, panics, malformed state, and concurrent use.
The root command is `npm run graph:store:test` and performs the focused Go race
gate without Docker or provider access.

M1-15 may move to Complete only after genuine compiler RED/GREEN evidence, six
focused stability passes, full affected Go and pinned repository gates,
dependency and secret scans, zero-finding review, push, and exact-SHA Runnable
UI success. It does not run Neo4j or claim provider compatibility. M1-16 remains
Pending throughout and must implement the minimal scoped Neo4j upsert/read
adapter against this frozen product boundary.
