# M1-43 Tenant Quota Primitive Implementation Plan

**Goal:** Define exact Organization-scoped concurrency keys and an immediate
quota counter for connectors, graph queries, tests, and AI requests.

**Architecture:** Add one dependency-free `services/platform/tenantquota`
package. Complete M1-04 scopes produce immutable Organization-plus-kind keys;
one mutex-protected counter admits or rejects requests against constructor-
injected M1-07-style typed limits.

**Tech Stack:** Go 1.25, dependency-free platform package, Node 22.23.1/npm
10.9.8 repository contracts, Go race detector, pinned Gitleaks 8.30.1.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED first.
- M1-42 remains Complete; M1-44 remains Pending until this plan closes.
- Start counts are overall `640/1/84/3` and M1 `7/1/60/0`.
- Completion counts are overall `640/0/85/3` and M1 `7/0/61/0`.
- Keys retain exactly canonical Organization plus one fixed workload kind.
- All four limits are explicit, positive, and at most 1024.
- Over-limit admission is immediate, deterministic, and state preserving.
- No ambient configuration, provider, network, filesystem, clock, goroutine,
  credential, or customer-value error output is added.

## Task 1: Start M1-43 with an exact repository contract

- [ ] Add a focused contract binding the source task, design, plan, exact
  status arithmetic, M1-42 Complete, and M1-44 absent.
- [ ] Run it before status edits and retain the intended Pending-state RED.
- [ ] Move only M1-43 to In progress at the exact start counts; update README
  and affected current-count contracts.
- [ ] Run focused/full pinned gates, scan the exact change, update ignored
  evidence, and commit the start transition atomically.

## Task 2: Specify keys and two-Organization admission first

- [ ] Add exact direct tests for all four keys, same-Organization cross-scope
  equality, different-Organization inequality, and invalid/direct key states.
- [ ] Add complete limit validation and one two-Organization fixture at limit
  one: A succeeds, A's second request is predictably rejected, and B succeeds.
- [ ] Add kind independence, usage observation, release recovery, copied,
  concurrent, double, and forged release denial, plus zero-count deletion tests.
- [ ] Add bounded concurrent admission proving exactly the configured number of
  permits succeeds for one Organization while another remains independent.
- [ ] Run the focused package and retain a genuine compiler RED at the absent
  product API before implementation.

## Task 3: Implement and review the primitive

- [ ] Implement opaque comparable keys, strict typed limits, synchronized
  counters, copy-safe shared permit state, and fixed sentinel errors.
- [ ] Validate every request before state change; increment only below limit;
  release exactly once and delete the final inactive key.
- [ ] Run a binding mutation that removes Organization from key equality and
  prove the A/B fixture fails before restoring GREEN.
- [ ] Run six focused race passes, package coverage, and full platform
  race/tidy-diff/module-verification/vet.
- [ ] Run pinned repository verify, audit, and whitespace checks without any
  provider or live command.
- [ ] Scan and review exact scope/key equality, count overflow/underflow,
  admission/release races, forged state, retention, privacy, and API misuse;
  resolve every Critical, Important, and Minor finding tests-first.

## Task 4: Complete, ship, and close M1-43

- [ ] Change the focused contract first and retain the intended completion RED.
- [ ] Move only M1-43 to Complete at the exact completion counts; keep M1-44
  Pending and all three blockers unchanged.
- [ ] Re-run every final gate/scan, commit, push, and require exact-SHA
  Runnable UI success before claiming completion.
- [ ] Check these 19 execution steps, commit plan closure, push, require a
  second exact-SHA Runnable UI success, reconcile refs/evidence, and proceed
  directly to M1-44.
