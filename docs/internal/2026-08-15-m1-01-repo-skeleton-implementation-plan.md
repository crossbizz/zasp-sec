# M1-01 Repository Skeleton Implementation Plan

Date: August 15, 2026

## Objective

Add a tested root `npm run build:repo` command that invokes the eight existing
service, worker, web, and CLI targets without downloading dependencies or adding
runtime product behavior.

## Invariants

- Every behavior or status change has a witnessed tests-only RED first.
- The exact eight-target inventory is fixed and no package-manager install or
  provider command is permitted.
- Go builds disable network and automatic toolchain download and write only to
  the platform null device.
- Worker output, child output, arguments, deadlines, and final output are
  bounded and fixed; Python creates no bytecode artifacts.
- The existing Runnable UI `verify` command remains unchanged.
- M1-02 remains Pending until M1-01 completes and exact-SHA CI passes.
- M0 blockers and R-03/R-11 status remain unchanged.

### Task 1: Start M1-01

- [x] Add a repository contract binding the source, design, plan, exact target
  inventory, completed M1-01c, unique active status, arithmetic, and blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-01 to In progress at `694/1/30/3` overall and M1
  `68/61/1/6/0`; document the root build and no-download scope.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-01 repo skeleton`.

### Task 2: Implement the root build tests-first

- [ ] Add hermetic orchestrator tests before production or package wiring.
- [ ] Capture genuine RED on the missing production module/root script.
- [ ] Implement exact bounded target execution and fixed output.
- [ ] Run the real root build and prove no repository build artifacts.
- [ ] Run six focused passes, all target regressions, full repository gates,
  audit, whitespace, and scans; commit `feat: add root repository build`.

### Task 3: Review the repository build boundary

- [ ] Audit target completeness, offline/no-install behavior, environment,
  output/deadline bounds, artifact absence, fail-fast behavior, and tests.
- [ ] Reproduce and fix every concrete finding tests-first.
- [ ] Run fresh root-build/target/repository/audit/scan gates and record zero
  findings.

### Task 4: Complete, push, and close M1-01

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-01 to Complete at `694/0/31/3` and M1
  `68/61/0/7/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-01 repo skeleton`, push, and
  watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-02.
