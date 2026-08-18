# M1-40 S3 Organization Artifact Prefix Implementation Plan

**Goal:** Make the existing ArtifactStore driver locator explicitly
Organization-scoped and lock cross-Organization artifact denial with a direct
same-session product test.

**Architecture:** Preserve the M1-12 product/driver interface and S3 adapter.
Add one unexported scope-mandatory locator builder inside `artifactstore`, route
all three operations through it before driver I/O, and leave M1-34's separate
bucket-layout package unchanged.

**Tech Stack:** Go 1.25 language/toolchain 1.26.5, dependency-free platform
package, Node 22.23.1/npm 10.9.8 repository contracts, Go race detector, pinned
Gitleaks 8.30.1.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED first.
- M1-39 remains Complete; M1-41 remains Pending until this plan closes.
- Start counts are overall `643/1/81/3` and M1 `10/1/57/0`.
- Completion counts are overall `643/0/82/3` and M1 `10/0/58/0`.
- `buildDriverLocator(scope, reference)` requires one complete canonical scope
  and evidence reference before deadline construction or driver I/O.
- Put, Get, and Delete derive Organization scope only from their current typed
  request; no session, global, provider, document, or retained store state may
  supply or override it.
- The public ArtifactStore and Driver interfaces, canonical key bytes, M1-12
  S3 adapter/proof, and M1-34 bucket-layout package remain unchanged.
- No raw key, bucket, S3/KMS identity, credential, provider error, or payload
  enters a public error or new API.
- No live Docker, LocalStack, S3, KMS, AWS, or shared-resource mutation is
  required for this product-only guard.

## Task 1: Start M1-40 with an exact repository contract

- [ ] Add a focused quality contract binding the source task, design, plan,
  exact status arithmetic, M1-39 Complete, and M1-41 absent.
- [ ] Run it before status edits and retain the intended Pending-state RED.
- [ ] Move only M1-40 to In progress at `643/1/81/3` overall and
  `10/1/57/0` for M1; update README and affected exact-count contracts.
- [ ] Run the focused and full pinned gates, scan the exact change, update the
  ignored report/ledger, and commit the start transition atomically.

## Task 2: Add the scope-mandatory artifact locator

- [ ] Add direct tests for exact locator/key output, zero and invalid inputs,
  typed field equality, and unchanged canonical bytes.
- [ ] Add one same-session fixture that writes Organization B and proves an
  otherwise identical Organization A read issues only A's key and returns
  fixed `ErrGet` without the B object.
- [ ] Mutate the inherited builder path to omit Organization scope and retain
  the focused tests-only RED before production edits.
- [ ] Implement `buildDriverLocator(scope, reference)` and route Put, Get, and
  Delete through it before deadline construction or driver I/O.

## Task 3: Verify and review the product boundary

- [ ] Add concurrent alternating A/B coverage that rejects retained tenant
  state, key aliasing, caller mutation, and cross-call contamination.
- [ ] Run the focused package with the race detector six consecutive times.
- [ ] Run full platform race, tidy-diff, module verification, vet, EventStore
  and ArtifactStore root regressions, and package statement coverage.
- [ ] Run pinned repository tests, typecheck, lint, build, production audit,
  whitespace checks, and scoped redacted secret scans.
- [ ] Review the exact start-to-implementation range for scope bypass,
  aliasing, panic/error leakage, concurrency, and unsupported provider claims;
  resolve every Critical, Important, and Minor finding tests-first.

## Task 4: Complete, ship, and close M1-40

- [ ] Change the focused contract first and retain the intended completion RED.
- [ ] Move only M1-40 to Complete at `643/0/82/3` overall and `10/0/58/0`
  for M1; keep M1-41 Pending and all three blockers unchanged.
- [ ] Re-run all final gates and scans, commit, push, and require exact-SHA
  Runnable UI success before claiming completion.
- [ ] Check these 17 execution steps, commit plan closure, push, require a
  second exact-SHA Runnable UI success, reconcile refs/evidence, and proceed
  directly to M1-41.
