# M1-42 Graph Organization Scope Guard Design

## Decision

Harden the existing dependency-free `services/platform/graphstore` product
boundary in place. Every graph write continues to accept one complete
`domain.Scope` plus nodes and edges carrying that exact scope. Every bounded
read continues to accept one complete scope and emits one driver query whose
Organization, Workspace, and Environment fields come only from that scope.

M1-42 does not add a second graph interface, an ambient tenant variable, or a
long-lived Organization-bound store. The current per-call scope is the narrow
authority established by M1-04 and already consumed by M1-15/M1-16.

## Explicit scoped builders

The product store uses two internal builders:

- `buildDriverProjection(scope, projection, config)` validates the supplied
  scope, requires every node and edge to carry that identical scope, requires
  all edge endpoints to name admitted nodes, and emits canonical driver nodes
  and edges with the Organization, Workspace, and Environment copied only
  from the supplied scope.
- `buildDriverQuery(scope, request, config)` validates the supplied scope and
  the bounded root, direction, depth, node, and edge limits, then emits the
  fixed Organization-scoped driver query with deterministic sort fields.

Both builders complete before driver I/O. Missing, malformed, or foreign
Organization scope therefore cannot reach either `Driver.Upsert` or
`Driver.Read`. Builder values are fresh per call and retain no caller slice or
tenant state.

## Cross-Organization read containment

The driver query includes the exact requested Organization as well as the
Workspace and Environment. Product code does not trust the provider filter by
itself: every returned node and edge is independently required to match the
exact requested scope before conversion. Edge endpoints must resolve only to
the admitted same-scope node set, and the returned graph must be reachable
from the requested root within the requested direction and depth.

A stateful hermetic driver fixture stores otherwise identical Organization-A
and Organization-B node/edge paths. An A-scoped bounded read must return only
the A path. A hostile driver that returns any B node, B edge, or cross-scope
endpoint to the A request must fail closed with no projection returned.

This is product-boundary evidence, not a database authorization claim. M1-16
remains the exact Neo4j adapter and disposable Community compatibility
authority. Its fixed Cypher, provider dependencies, image, license evidence,
live command, and cleanup behavior remain unchanged.

## Failure, concurrency, and privacy

Existing fixed errors remain authoritative: invalid write state maps to
`ErrProjection` or `ErrUpsert`; invalid read state maps to `ErrReadRequest` or
`ErrRead`. Driver errors and panics remain contained, and one bounded context
covers each provider operation. No Organization ID, node, edge, query,
provider message, or panic value enters an error.

The store retains only the immutable driver and configuration. Builder and
result slices are fresh per operation. Concurrent alternating Organization-A
and Organization-B writes and reads must not share scope or mutable state.

## Verification and status boundary

Tests directly bind exact scoped builder output, reject zero and foreign scope
before I/O, exercise a stateful two-Organization graph, and prove bounded A
paths cannot traverse B fixtures. Mutation evidence must show that removing
the Organization predicate or result-scope check makes the binding fixture
fail. Existing graphstore and Neo4j adapter/proof hermetic regressions remain
green; no live Neo4j or Docker lifecycle is required.

Starting M1-42 changes the source counts to 641 Pending / 1 In progress / 83
Complete / 3 Blocked and M1 to 8 / 1 / 59 / 0. Completion changes them to
641 / 0 / 84 / 3 overall and 8 / 0 / 60 / 0 within M1. M1-41 remains Complete,
M1-43 remains Pending, and M0-09, M0-18, and M0-19 remain the exact blockers.

Completion requires tests-first RED/GREEN evidence, six focused race passes,
the platform race/tidy-diff/module-verify/vet matrix, inherited M1-16 hermetic
gates without its live command, pinned repository verification, audit,
whitespace and redacted secret scans, zero-finding review, push, and exact-SHA
Runnable UI success.

## Alternatives rejected

- A retained Organization on `Store` would create a second authority and risk
  cross-request tenant state where the existing typed per-call scope suffices.
- Trusting only driver-side predicates would make malformed or hostile
  provider results an authorization bypass.
- Parsing or accepting raw Cypher would bypass the fixed structured driver
  boundary and duplicate M1-16.
- Re-running the live Neo4j lifecycle would test provider compatibility, not
  this product-only Organization guard.
