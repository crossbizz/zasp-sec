# M1-02 Dependency Lock Implementation Plan

**Goal:** Add a reviewed exact dependency lock for every direct product runtime
and enforce it in the existing CI verification path.

## Invariants

- Every behavior or status change has a witnessed tests-only RED first.
- The lock covers direct product runtime dependencies only; proof, development,
  optional peer, and transitive dependencies remain outside this microtask.
- Every locked dependency has an exact version, SPDX license, internal owner,
  runtime scope, and explicit approved review state.
- Unreviewed runtime entries and prohibited copyleft licenses fail closed.
- Validation is local, bounded, deterministic, and performs no installation,
  download, provider, Docker, credential, or network operation.
- Existing M0 blockers and R-03/R-11 status remain unchanged.
- M1-03 remains Pending until M1-02 completes and exact-SHA CI passes.

### Task 1: Start M1-02

- [x] Add a repository contract binding the source, design, plan, completed
  M1-01, initial dependency inventory, unique active status, arithmetic, and
  retained blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-02 to In progress at `693/1/31/3` overall and M1
  `68/60/1/7/0`; document the dependency-check command and scope.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-02 dependency lock`.

### Task 2: Implement the lock and validator tests-first

- [x] Add hermetic validator tests before production, lock data, or package
  wiring exists; capture genuine missing-module/file/script RED.
- [x] Add `build/dependencies.lock.yaml`, the bounded validator, and the root
  dependency-check command; prepend it to the existing CI `verify` path.
- [x] Cover exact schema, sorted uniqueness, manifest completeness, npm lock
  version/license agreement, owner/review policy, copyleft rejection, fixed
  output, and hostile mutations.
- [x] Run the real dependency check, six focused passes, root build, product
  regressions, full repository gates, audit, whitespace, and scans; commit
  `feat: enforce reviewed dependency lock`.

### Task 3: Review the dependency boundary

- [x] Audit YAML/manifest parsing, fail-closed behavior, exact package-lock
  binding, product-manifest completeness, CI ordering, output, and scope.
- [x] Add tests-first fixes for every Critical, Important, or Minor finding in
  separate commits and rerun all affected gates.
- [x] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-02

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-02 to Complete at `693/0/32/3` and M1
  `68/60/0/8/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-02 dependency lock`, push, and
  watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-03.
