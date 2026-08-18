# M1-39 OpenSearch Organization Scope Guard Implementation Plan

**Goal:** Make the existing EventStore index and query builders explicitly
Organization-scoped and lock the Organization-A/Organization-B containment
boundary with direct product tests.

**Architecture:** Keep `eventstore.Store` and its M1-14 driver interface as the
only product boundary. Add two unexported, scope-mandatory builders inside that
package, route `Index` and `Search` through them before driver I/O, and preserve
the proof-owned OpenSearch adapter without provider or lifecycle changes.

**Tech Stack:** Go 1.25 language/toolchain 1.26.5, dependency-free platform
package, Node 22.23.1/npm 10.9.8 repository contracts, Go race detector, pinned
Gitleaks 8.30.1.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED first.
- M1-38 remains Complete; M1-40 remains Pending until this plan closes.
- Start counts are overall `644/1/80/3` and M1 `11/1/56/0`.
- Completion counts are overall `644/0/81/3` and M1 `11/0/57/0`.
- Both builders require one complete canonical `domain.Scope` before driver I/O.
- Index scope must equal event scope; query scope cannot be inferred from a
  session, document, provider response, global value, or retained store state.
- The driver interface, OpenSearch adapter, M1-14 disposable proof, mappings,
  index names, and fixed product errors remain unchanged.
- No raw OpenSearch DSL, endpoint, credential, provider error, or index name
  enters the public product API or fixed output.
- No live Docker, OpenSearch, AWS, or shared-resource mutation is required for
  this product-only guard.

## Task 1: Start M1-39 with an exact repository contract

- [x] Add a focused quality contract binding the source task, this design and
  plan, exact status arithmetic, M1-38 Complete, and M1-40 absent.
- [x] Run it before status edits and retain the intended Pending-state RED.
- [x] Move only M1-39 to In progress at `644/1/80/3` overall and
  `11/1/56/0` for M1; update README and affected exact-count contracts.
- [x] Run the focused and full pinned gates, scan the exact change, update the
  ignored report/ledger, and commit the start transition atomically.

## Task 2: Add scope-mandatory EventStore builders

- [x] Add direct tests for exact scoped document/query output, fresh sort
  allocation, zero scope, mismatched event scope, and invalid filters.
- [x] Add the same-session A-query/B-document hostile fixture and require one
  A-scoped driver call, zero returned events, and fixed `ErrSearch`.
- [x] Mutate the inherited builder path to omit Organization scope and retain
  the focused tests-only RED before production edits.
- [x] Implement `buildDriverDocument` and `buildDriverQuery`; route `Index` and
  `Search` through them before deadline construction or driver I/O.

## Task 3: Verify and review the product boundary

- [x] Run the focused package with the race detector six consecutive times.
- [x] Run full platform race, tidy-diff, module verification, vet, and package
  statement coverage; preserve all M1-14 adapter and proof tests.
- [x] Run pinned repository tests, typecheck, lint, build, production audit,
  whitespace checks, and scoped redacted secret scans.
- [x] Review the exact start-to-implementation range for scope bypass,
  aliasing, panic/error leakage, concurrency, and unsupported provider claims;
  resolve every Critical, Important, and Minor finding tests-first.

## Task 4: Complete, ship, and close M1-39

- [x] Change the focused contract first and retain the intended completion RED.
- [x] Move only M1-39 to Complete at `644/0/81/3` overall and `11/0/57/0`
  for M1; keep M1-40 Pending and all three blockers unchanged.
- [x] Re-run all final gates and scans, commit, push, and require exact-SHA
  Runnable UI success before claiming completion.
- [x] Check these 16 execution steps, commit plan closure, push, require a
  second exact-SHA Runnable UI success, reconcile refs/evidence, and proceed
  directly to M1-40.
