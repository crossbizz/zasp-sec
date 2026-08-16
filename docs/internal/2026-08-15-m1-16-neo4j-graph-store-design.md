# M1-16 Neo4j GraphStore Design

## Decision

Implement a minimal Neo4j adapter in
`services/platform/graphstore/neo4jstore` behind the completed M1-15
`graphstore.Driver` boundary. The adapter uses the official Neo4j Go driver
v6.2.0, fixed internal labels and relationship types, parameterized Cypher,
explicit single-attempt transactions, and strict conversion back to M1-15
driver records.

The selected live fixture is the multi-platform exact image
`neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357`.
It is a disposable compatibility target, not an approved product packaging or
redistribution choice. Neo4j Community server licensing remains a separate
release decision; only the Apache-2.0 Go driver enters the deployable platform
module.

M1-16 changes no product `GraphStore` type. It does not expose Neo4j nodes,
relationships, element IDs, sessions, transactions, bookmarks, Cypher,
credentials, endpoints, labels, or errors outside the adapter and live proof.

## Alternatives considered

### Official driver behind a narrow adapter — selected

Use the official current Go driver, but isolate it in a child package that
implements the provider-neutral M1-15 driver. This gives supported Bolt
behavior, context cancellation, exact transactions, and typed record handling
without contaminating product callers. The additional runtime dependency is
small, exact-pinned, Apache-2.0, and recorded in the product dependency lock.

### Neo4j transactional HTTP endpoint — rejected

A standard-library HTTP adapter would avoid a Go module dependency, but it
would duplicate authentication, connection, transaction, response, and error
semantics already owned by the official driver. It also increases the chance
of accepting ambiguous or partially consumed provider results.

### Custom Bolt client or raw query interface — rejected

A custom Bolt implementation is unjustified protocol work. Accepting raw
Cypher from product callers would violate the M1-15 boundary, prevent complete
scope enforcement, and create an injection and result-shape trust boundary.

## Package boundary and construction

The adapter package exports:

```go
type Adapter struct { /* provider state only */ }

func New(driver neo4j.Driver, database string) (*Adapter, error)
func EnsureSchema(context.Context, neo4j.Driver, string) error
func (adapter *Adapter) Upsert(context.Context, graphstore.DriverProjection) (graphstore.DriverUpserted, error)
func (adapter *Adapter) Read(context.Context, graphstore.DriverQuery) (graphstore.DriverProjection, error)
```

`New` is side-effect free. It rejects nil and typed-nil drivers and accepts
only the exact database name `neo4j`; application bootstrap remains responsible
for constructing and closing the official driver with credentials from the
typed configuration layer. `EnsureSchema` is an explicit startup operation and
creates only two named version-1 uniqueness constraints. It does not run from
ordinary reads or writes.

The package uses small unexported session, transaction, and result interfaces
around the official driver. Unit tests use deterministic fakes for those narrow
interfaces. The public constructor still accepts only the official driver, so
no fake or raw query executor becomes product API.

## Fixed provider schema

Every product node uses the one fixed label `ZaspGraphNode`. Every product edge
uses the one fixed relationship type `ZASP_GRAPH_EDGE`. Product kinds remain
the validated `kind` property; they never become labels or relationship types.

Nodes contain exactly these adapter-owned properties:

- `organization_id`
- `workspace_id`
- `environment_id`
- `node_id`
- `kind`
- `schema_version`, fixed to integer `1`

Relationships contain exactly the same scope and schema properties plus
`edge_id`, `kind`, and their graph endpoints. Provider element IDs are ignored.

The named constraints are:

```cypher
CREATE CONSTRAINT zasp_graph_node_identity_v1 IF NOT EXISTS
FOR (node:ZaspGraphNode)
REQUIRE (node.organization_id, node.workspace_id, node.environment_id, node.node_id) IS UNIQUE

CREATE CONSTRAINT zasp_graph_edge_identity_v1 IF NOT EXISTS
FOR ()-[edge:ZASP_GRAPH_EDGE]-()
REQUIRE (edge.organization_id, edge.workspace_id, edge.environment_id, edge.edge_id) IS UNIQUE
```

These property-uniqueness constraints are supported by the selected Neo4j 5.26
LTS fixture. The adapter fails closed if schema creation, inspection, or exact
name/type/property verification differs. It does not use Enterprise-only
existence, type, or key constraints.

## Upsert transaction

The adapter independently validates every driver record before opening a
session: canonical product IDs, exact repeated scope, deterministic ordering,
valid product kinds, unique IDs and semantic edges, no self-edge, and complete
same-projection endpoints. Direct adapter calls therefore cannot bypass the
M1-15 checks.

One write session and one explicit transaction execute fixed parameterized
statements in this order:

1. merge the requested nodes by all four identity properties;
2. set version and kind only on create, then reject any matched node whose
   stored version, kind, or exact property set differs;
3. match both exact-scoped endpoints and merge requested relationships by the
   four relationship identity properties;
4. set version and kind only on create, then reject any matched relationship
   whose stored endpoints, version, kind, or exact property set differs; and
5. re-read and return exactly the canonical requested node and edge IDs.

No caller value is interpolated into Cypher. The fixed label, relationship
type, property names, ordering, and constraint names are source constants.
Upsert does not retry. An ambiguous commit returns failure; the canonical
projection is explicitly replay-safe because `MERGE` plus the uniqueness
constraints and exact-state checks accept only the same state.

The transaction candidate is retained before any begin result is interpreted.
Every non-commit path, including malformed begin output, error, cancellation,
timeout, or panic, attempts one independent bounded rollback and closes the
session. A rollback or close failure cannot turn the operation into success.

## Bounded read

The adapter independently validates the exact scope, canonical root, direction,
depth 0 through 8, positive node and edge limits within 1,000/2,000, and fixed
sort fields before provider I/O.

One explicit read transaction performs deterministic breadth-first traversal.
It first reads the exact root. A missing root returns exact empty slices. For
each depth level it runs one of three fixed adjacency statements for outgoing,
incoming, or both direction. Parameters contain only the current canonical
frontier, exact scope, and remaining limits. Results are ordered by edge ID and
bounded before they leave Neo4j.

The adapter validates every record before retaining it. It accepts only the
fixed label/type, exact property-key set and value types, schema version 1,
exact scope, canonical IDs and kinds, correct direction, same-result endpoints,
and unique identities. It stops deterministically at the requested node/edge
limits, sorts the final driver slices by product ID, and commits the read
transaction only after complete result consumption. The M1-15 store then
performs its independent full result validation and reachability check.

No arbitrary predicate, label, relationship type, property list, query text,
or customer string affects Cypher structure. Maximum depth is selected from a
fixed source table of nine query forms rather than interpolated.

## Error, deadline, and concurrency behavior

The adapter returns only `ErrConfiguration`, `ErrSchema`, `ErrUpsert`, or
`ErrRead`. Provider messages and values never cross the package. Input failures
occur before provider I/O.

The M1-15 store supplies the total operation context. The adapter creates no
longer main deadline and performs no retry. Independent two-second cleanup
contexts cover rollback and session close after cancellation. Provider panics
are contained inside the adapter so transactions and sessions are still
settled before the fixed error returns.

The official driver is concurrency-safe; each operation creates its own
session and transaction. The adapter retains only the immutable driver and
database name. It holds no mutable graph or bookmark state.

## Verification strategy

### Hermetic adapter tests

Tests first prove exact query constants and parameters, schema constraints,
canonical upsert acknowledgement, idempotent replay, all three read directions,
depth zero, deterministic limits, and empty-root behavior. Hostile cases cover
foreign scope, invalid IDs/kinds/order, partial and extra acknowledgement,
missing endpoints, duplicate and self edges, wrong labels/types/properties,
numeric/string aliases, schema-version drift, unconsumed result errors,
begin/run/consume/commit/rollback/close errors, cancellation, timeout, panic,
typed-nil dependencies, and concurrent calls.

The tests also prove one explicit transaction, no implicit or managed retry,
rollback on every uncommitted path, and complete record consumption before
commit.

### Disposable compatibility proof

A dedicated `proofs/neo4j-graphstore` runner starts one generated, labeled,
exact-owned Neo4j 5.26.28 Community container on random numeric-loopback HTTP
and Bolt ports using an owned empty Docker configuration. It accepts no dotenv,
profile, proxy, provider credential, or shared-service input.

After semantic readiness, a Go proof uses the official driver v6.2.0, verifies
connectivity, creates and re-proves the two exact constraints, and constructs
the product `graphstore.Store` over the adapter. It upserts one three-node,
two-edge Organization A projection, replays it, and proves:

- outgoing, incoming, both, and depth-zero reads;
- exact canonical IDs, kinds, edges, and ordering;
- a same-root Organization B read returns zero state; and
- direct provider audit contains only the expected exact-scoped fixture.

Cleanup deletes only the exact fixture data, re-proves its absence, removes the
exact unchanged container and intrinsic volumes, and performs prefix-wide
container/volume/temp absence checks. A shared development Neo4j service, if
present, is fingerprinted read-only before and after and is never targeted.
Success and failures use fixed one-line output with no endpoint, credential,
provider identifier, Cypher, or provider error.

## Dependency and licensing boundary

`github.com/neo4j/neo4j-go-driver/v6` is pinned to v6.2.0 and recorded as an
Apache-2.0 `platform-data` runtime dependency. Module verification, license
inventory, production audit, and secret scans are required.

The disposable Neo4j Community image is proof-only. The report records its
exact image/source metadata and license evidence, but M1-16 does not approve
embedding, redistributing, or packaging the server in AgentSec. The existing
PRD licensing risk remains open for the later deployment decision.

## Completion boundary

M1-16 may move to Complete only after tests-first implementation, six focused
passes, a current-code disposable live success, exact cleanup and shared-target
non-mutation, full affected Go and pinned repository gates, dependency/license
and secret scans, zero-finding whole-range review, push, and exact-SHA Runnable
UI success. M1-17 remains Pending throughout.

Primary references used for the selected boundary:

- https://neo4j.com/docs/go-manual/current/
- https://pkg.go.dev/github.com/neo4j/neo4j-go-driver/v6
- https://neo4j.com/docs/cypher-manual/5/constraints/syntax/
- https://hub.docker.com/_/neo4j
