# M1-42 Graph Organization Scope Guard Implementation Plan

**Goal:** Require exact Organization scope on graph node/edge writes and
bounded graph reads, and prove an Organization-A path cannot traverse
Organization-B fixture state.

**Architecture:** Harden the existing dependency-free product `GraphStore` in
place with explicit scoped projection/query builders and a stateful hermetic
two-Organization driver. Preserve the M1-16 Neo4j adapter and provider proof.

**Tech Stack:** Go 1.25, dependency-free platform package, Node 22.23.1/npm
10.9.8 repository contracts, Go race detector, pinned Gitleaks 8.30.1.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED first.
- M1-41 remains Complete; M1-43 remains Pending until this plan closes.
- Start counts are overall `641/1/83/3` and M1 `8/1/59/0`.
- Completion counts are overall `641/0/84/3` and M1 `8/0/60/0`.
- Complete canonical scope is required before every graph driver call.
- Returned nodes, edges, endpoints, reachability, direction, and depth remain
  independently validated against the requested scope.
- M1-16's Neo4j adapter, Cypher, live lifecycle, image, license, and cleanup
  authority remain unchanged.
- No Organization ID, graph content, provider value, or panic enters errors.
- No Docker, Neo4j, shared resource, or provider mutation is required.

## Task 1: Start M1-42 with an exact repository contract

- [x] Add a focused contract binding the source task, design, plan, exact
  status arithmetic, M1-41 Complete, and M1-43 absent.
- [x] Run it before status edits and retain the intended Pending-state RED.
- [x] Move only M1-42 to In progress at the exact start counts; update README
  and affected current-count contracts.
- [x] Run focused/full pinned gates, scan the exact change, update ignored
  evidence, and commit the start transition atomically.

## Task 2: Specify cross-Organization graph behavior first

- [x] Add exact direct tests for scoped write-projection and bounded-query
  construction, including zero and foreign Organization denial before I/O.
- [x] Add one stateful driver containing otherwise identical A and B fixture
  paths and prove an A query returns only the A path.
- [x] Add hostile B-node, B-edge, cross-scope endpoint, direction, depth,
  duplicate, bound, and malformed-result cases with no returned projection.
- [x] Add alternating concurrent A/B writes and reads with independent state.
- [x] Run the focused package and retain a genuine RED at the absent explicit
  builder or binding behavior before production implementation.

## Task 3: Implement and review the product guard

- [x] Route writes through `buildDriverProjection` and reads through
  `buildDriverQuery`, with complete validation before driver I/O.
- [x] Preserve exact result-scope, endpoint, topology, bound, ordering, panic,
  deadline, defensive-copy, and fixed-error enforcement.
- [x] Run the binding mutation and prove removing Organization filtering or
  result validation makes the A/B fixture fail before restoring GREEN.
- [x] Run six focused race passes, package coverage, and full platform
  race/tidy-diff/module-verification/vet.
- [x] Run inherited M1-16 graph/Neo4j hermetic gates without invoking the live
  command, then pinned repository verify, audit, and whitespace checks.
- [x] Scan and review the exact implementation for scope omission, tenant
  retention, provider-result trust, path traversal, and concurrency; resolve
  every Critical, Important, and Minor finding tests-first.

## Task 4: Complete, ship, and close M1-42

- [x] Change the focused contract first and retain the intended completion RED.
- [x] Move only M1-42 to Complete at the exact completion counts; keep M1-43
  Pending and all three blockers unchanged.
- [x] Re-run every final gate/scan, commit, push, and require exact-SHA
  Runnable UI success before claiming completion.
- [x] Check these 19 execution steps, commit plan closure, push, require a
  second exact-SHA Runnable UI success, reconcile refs/evidence, and proceed
  directly to M1-43.
