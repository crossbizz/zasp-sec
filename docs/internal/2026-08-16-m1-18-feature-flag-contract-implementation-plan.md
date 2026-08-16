# M1-18 Feature Flag Contract Implementation Plan

## Goal

Implement, review, ship, and close the dependency-free scoped feature-flag
contract. Every flag evaluation carries an explicit code default and exact
cache metadata; optional driver failure safely returns that default. M1-19
remains Pending throughout.

## Stack and fixed boundaries

- Go 1.25 language/toolchain 1.26.5 in `services/platform`.
- Product package: `services/platform/featureflags`.
- Existing `services/platform/domain.Scope`; no provider type or dependency.
- Node 22.23.1/npm 10.9.8 repository contracts and Vitest.
- Pinned Gitleaks 8.30.1.
- Design commit: `0f76fb1dd6363a227b8172ce7428df934ecbfe42`.
- Start counts: overall `677/1/47/3`; M1 `68/44/1/23/0`.
- Completion counts: overall `677/0/48/3`; M1 `68/44/0/24/0`.
- M1-17 remains Complete; M1-19 remains Pending; M0-09, M0-18, and
  M0-19 remain Blocked.
- No Docker, network, cloud, database, provider, credential, cache, or
  shared-resource I/O.
- Every behavior change follows a witnessed tests-only RED before production.

## Task 1: Start M1-18 with an exact repository contract

**Files**

- Create `app/quality/feature-flag-contract.test.ts`.
- Modify `README.md`.
- Modify `docs/internal/implementation_status_v1.5.md`.
- Modify affected current aggregate contracts under `app/quality/`.
- Create ignored Task 1 report and append-only progress ledger.

- [x] Write source/design/status assertions before status edits.

  Bind the authoritative source section to dependency M1-17, the exact
  `FeatureFlags` deliverable, explicit code default, cache metadata, and fake
  outage verification. Require the design package/boundary. Assert M1-18 is
  the only In-progress row, M1-17 remains Complete, M1-19 is absent,
  blockers are unchanged, and counts equal `677/1/47/3` plus
  `68/44/1/23/0`.

- [x] Capture the focused Pending-state RED.

  Run the new contract under pinned Node before changing README/tracker.
  Only stale M1-18 status/count assertions may fail.

- [x] Move only M1-18 to In progress and run GREEN.

  Update current aggregate fixtures mechanically while preserving historical
  mutation fixtures. Run the focused contract, all quality contracts, full
  pinned repository verification, 8-target build, production audit,
  whitespace, and staged/evidence secret scans.

- [x] Commit exact Task 1 scope.

  Commit message: `docs: start M1-18 feature flags`.

## Task 2: Implement the scoped evaluator tests-first

**Files**

- Create `services/platform/featureflags/featureflags_test.go` first.
- Create `services/platform/featureflags/featureflags.go` only after compiler
  RED.
- Update ignored Task 2 report and progress ledger.

- [x] Capture genuine compiler RED.

  Tests name the wished-for `FeatureFlags`, `Request`, `Decision`,
  `CacheMetadata`, `DriverRequest`, `DriverDecision`, `Driver`, `Config`, and
  fixed errors before any production/package/dependency edit.

- [x] Implement construction and exact request validation.

  Reject nil/typed-nil driver, timeout outside `(0,30s]`, maximum cache age
  outside `(0,24h]`, nil context, unusable receiver, invalid scope, and keys
  outside the exact 1..127-byte ASCII grammar before driver I/O.

- [x] Implement one bounded evaluation and safe fallback.

  Forward exact Organization/Workspace/Environment/key once, excluding the
  code default. Accept only exact echoed ownership plus coherent cache
  metadata. On pre-cancellation, driver error/panic/timeout/cancellation,
  malformed success, scope/key drift, cache miss with nonzero age, negative
  age, or over-age hit, return the exact request default with
  `UsedDefault=true` and zero cache metadata. No retry.

- [x] Add adversarial and concurrency coverage.

  Prove provider true/false values, provider value equal to default, both
  outage defaults, every missing/malformed key class, acknowledgement drift,
  cache boundaries, typed nil, panic, deadline, cancellation, receiver misuse,
  defensive value behavior, and parallel per-call default isolation.

- [x] Run focused verification and commit.

  Require six consecutive focused race passes, 100 focused repetitions,
  statement coverage with every production function exercised, full platform
  race/tidy-diff/module verification/vet, whitespace, staged/evidence secret
  scans, and exact two-file source/test commit.

  Commit message: `feat: add scoped feature flag contract`.

## Task 3: Expose the hermetic root contract

**Files**

- Modify `package.json`.
- Modify `README.md`.
- Modify `app/quality/feature-flag-contract.test.ts`.
- Update plan checkboxes and ignored Task 3 evidence.

- [x] Capture root-wiring RED.

  Require script `featureflags:test` to equal
  `go test -C services/platform -race -count=1 ./featureflags`. Require a
  README `## Feature flag contract` section naming exact scope, per-call code
  default, cache hit/age metadata, safe outage fallback, one attempt, fixed
  product errors, hermetic fake driver, non-security-critical boundary, and
  deferred provider/cache behavior.

- [x] Add minimal script/docs and run GREEN.

  Run the root command, focused repository contract, full platform gates,
  pinned repository verification, 8-target build, production audit,
  whitespace, and secret scans.

- [x] Commit exact root-wiring scope.

  Commit message: `docs: expose feature flag contract`.

## Task 4: Whole-range independent review and fixes

**Files**

- Review exact M1-18 base-to-head range against source, PRD, design, plan,
  implementation, tests, docs, and status contracts.
- Modify only finding-related files through separate tests-first commits.
- Update ignored Task 4 report and progress ledger.

- [ ] Run a strict pre-landing review.

  Prioritize implicit/default ambiguity, driver authority, cache-state
  contradictions, scope drift, timeout/cancellation semantics, raw provider
  leakage, retry, concurrency, and use in security-critical decisions.

- [ ] Fix every finding tests-first.

  Record genuine focused RED, minimal GREEN, affected/full gates, separate
  atomic fix commit, and re-review until Critical/Important/Minor are all zero.

- [ ] Run final implementation gates.

  Require six root race cycles, 100 focused repetitions, coverage, full
  platform gates, full pinned repository verification, 8-target build,
  zero-vulnerability audit, whitespace, staged/range/full-history/evidence
  secret scans, and a clean tracked tree.

## Task 5: Complete, push, verify CI, and close M1-18

**Files**

- Modify `README.md`, tracker, current aggregate status contracts, and this
  plan's checkboxes.
- Update ignored Task 5 and authoritative M1-18 reports/ledgers.

- [ ] Capture the completion transition RED.

  Require exactly one M1-18 Complete row, M1-17 Complete, M1-19 absent,
  unchanged blockers, overall `677/0/48/3`, and M1 `68/44/0/24/0` before
  changing status sources.

- [ ] Move only M1-18 to Complete and repeat all final local gates.

  Commit message: `docs: complete M1-18 feature flags`.

- [ ] Push and watch exact completion SHA to Runnable UI success.

  Require local/upstream/remote/run/job SHA identity and terminal success.

- [ ] Record plan-only closure without advancing M1-19.

  Commit message: `docs: close M1-18 feature flags`. Push and watch that exact
  closure SHA to terminal success, then prove synchronized clean state.
