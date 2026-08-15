# M1-04 Scope Model Implementation Plan

**Goal:** Define one strict Organization/Workspace/Environment scope value for
later product security entities and authorization boundaries.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- Organization, Workspace, and Environment are product IDs and all are required.
- Missing, partial, or duplicate hierarchy levels fail closed with fixed errors.
- The model is dependency-free, immutable by value, bounded, and local.
- M1-05 remains Pending until M1-04 completes and exact-SHA CI passes.
- Existing M0 blockers and R-03/R-11 boundaries remain unchanged.

### Task 1: Start M1-04

- [x] Add a repository contract binding the source, PRD hierarchy, design,
  plan, completed M1-03, unique active status, arithmetic, and blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-04 to In progress at `691/1/33/3` overall and M1
  `68/58/1/9/0`; document the scope boundary.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-04 scope model`.

### Task 2: Implement Scope tests-first

- [x] Add Go tests before production and capture genuine missing-symbol RED.
- [x] Implement opaque strict Scope construction, validation, zero detection,
  and read-only product-ID accessors.
- [x] Cover missing and duplicate levels, partial/zero internals, equality, and
  raw-vendor-ID exclusion.
- [x] Run six focused passes, platform/service/worker/root regressions, full
  repository gates, audit, whitespace, and scans; commit
  `feat: add product scope model`.

### Task 3: Review the scope boundary

- [x] Audit hierarchy requirements, zero/partial values, duplicate levels,
  accessor types, comparability, error secrecy, API misuse paths, and tests.
- [x] Add tests-first fixes for every concrete finding and rerun affected gates.
- [x] Record a zero-finding review before completion.

### Task 4: Complete, push, and close M1-04

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-04 to Complete at `691/0/34/3` and M1
  `68/58/0/10/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-04 scope model`, push, and
  watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-05.
