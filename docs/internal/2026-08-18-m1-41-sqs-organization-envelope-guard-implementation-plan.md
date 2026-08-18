# M1-41 SQS Organization Envelope Guard Implementation Plan

**Goal:** Reject missing or foreign Organization scope in all three product
queue envelope families before a worker handler can perform side effects.

**Architecture:** Extend the dependency-free M1-13 `jobqueue` package with one
immutable Organization-bound consumer. Strict call-local JSON validation
constructs a canonical scope and gates a typed handler; the existing JobQueue,
SQS adapter, queue definitions, receipts, and live lifecycle remain unchanged.

**Tech Stack:** Go 1.25, dependency-free platform package, Node 22.23.1/npm
10.9.8 repository contracts, Go race detector, pinned Gitleaks 8.30.1.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED first.
- M1-40 remains Complete; M1-42 remains Pending until this plan closes.
- Start counts are overall `642/1/82/3` and M1 `9/1/58/0`.
- Completion counts are overall `642/0/83/3` and M1 `9/0/59/0`.
- The retained worker Organization is the only authorization authority.
- Background, runtime-event, and test envelopes have exactly their seven
  M1-13/M1-33 top-level fields and version `1`.
- Validation and Organization equality complete before handler entry.
- The M1-13 JobQueue/Driver interfaces, opaque receipt ordering, provider
  adapter, live lifecycle, and M1-33 definition bytes remain unchanged.
- No payload, provider identity, credential, queue identifier, receipt, or raw
  error enters the fixed product errors.
- No Docker, LocalStack, SQS, shared-resource, or real-AWS mutation is required.

## Task 1: Start M1-41 with an exact repository contract

- [ ] Add a focused contract binding the source task, design, plan, exact
  status arithmetic, M1-40 Complete, and M1-42 absent.
- [ ] Run it before status edits and retain the intended Pending-state RED.
- [ ] Move only M1-41 to In progress at `642/1/82/3` overall and
  `9/1/58/0` for M1; update README and affected exact-count contracts.
- [ ] Run focused/full pinned gates, scan the exact change, update ignored
  evidence, and commit the start transition atomically.

## Task 2: Specify the Organization-bound consumer tests first

- [ ] Add exact positive background, runtime-event, and test envelopes.
- [ ] Add the binding Organization-B-to-Organization-A fixture and prove the
  handler side-effect counter remains zero.
- [ ] Cover missing/mismatched Organization, exact schema drift, duplicate
  keys, invalid identities, version/types, UTF-8, size, and trailing data.
- [ ] Cover canceled context, handler error/panic, defensive copies, zero
  projections, and concurrent alternating A/B calls.
- [ ] Run the focused package and retain compile RED only at the absent
  consumer symbols before production implementation.

## Task 3: Implement and review the product guard

- [ ] Add fixed kinds, errors, immutable projection, consumer constructor, and
  the strict duplicate-safe bounded decoder.
- [ ] Gate the handler on complete validation and exact retained Organization
  equality, with panic containment and call-local defensive state.
- [ ] Run focused race tests six consecutive times, package coverage, and full
  platform race/tidy-diff/module verification/vet.
- [ ] Run inherited M1-13 JobQueue/LocalStack hermetic and M1-33 definition
  regressions; do not invoke either live command.
- [ ] Run pinned repository tests/typecheck/lint/build, production audit,
  whitespace checks, and scoped redacted secret scans.
- [ ] Review the exact implementation range for scope bypass, handler-before-
  validation, JSON ambiguity, state retention, panic leakage, and concurrency;
  resolve every Critical, Important, and Minor finding tests-first.

## Task 4: Complete, ship, and close M1-41

- [ ] Change the focused contract first and retain the intended completion RED.
- [ ] Move only M1-41 to Complete at `642/0/83/3` overall and `9/0/59/0`
  for M1; keep M1-42 Pending and all three blockers unchanged.
- [ ] Re-run every final gate/scan, commit, push, and require exact-SHA
  Runnable UI success before claiming completion.
- [ ] Check these 19 execution steps, commit plan closure, push, require a
  second exact-SHA Runnable UI success, reconcile refs/evidence, and proceed
  directly to M1-42.
