# M1-36b M1 Schema Check Implementation Plan

Date: August 18, 2026

## Objective

Add and execute one hermetic five-target database/event/domain schema gate, then
record only the bounded M1-36b evidence and status transition.

## Invariants

- Use genuine tests-first RED/GREEN for every tracked behavior or status change.
- Reuse the five reviewed schema-owning Go packages; add no duplicate schema.
- Accept no arguments and emit only fixed success or failure output.
- Give each child an exact environment allowlist, hard deadline, and output cap.
- Perform no file generation, provider/network/database/container mutation, or
  customer-state access.
- Keep M1-36a Complete exactly once, M1-36c Pending, and the exact three source
  blockers unchanged.
- Completion requires zero open Critical, Important, or Minor findings, pinned
  local gates/scans, push, and exact-SHA Runnable UI success.

## Task 1: Start M1-36b with exact contract coverage

### Files

- Create: `app/quality/m1-schema-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

- [ ] **Step 1: Write the failing source/design/status contract**

  Bind the exact source row, M1-36a dependency, design, five-target inventory,
  root command, fixed output, no-side-effect boundary, M1-36c Pending state,
  arithmetic, and exact blockers.

- [ ] **Step 2: Witness focused status RED**

  Run the new contract while M1-36b is still absent/Pending. Require failure
  only at the missing In-progress documentation/status expectations.

- [ ] **Step 3: Move only M1-36b to In progress**

  Change overall counts to `650/1/74/3` and M1 to `68/17/1/50/0`. Add exactly
  one current M1-36b row and bounded README section. Preserve M1-36a Complete,
  absent M1-36c, and exact blockers.

- [ ] **Step 4: Run status GREEN and commit**

  Run focused/full quality tests, whitespace, audit, and staged secret scan.
  Commit the exact status/contract/docs slice as `docs: start M1-36b schema check`.

## Task 2: Implement the hermetic schema runner tests-first

### Files

- Create: `scripts/check-m1-schemas.test.mjs`
- Create: `scripts/check-m1-schemas.mjs`
- Modify: `package.json`

- [ ] **Step 1: Write behavior-first runner RED**

  Require exact package order/argv, offline environment, deadlines/output caps,
  fail-fast result handling, no forbidden targets, no arguments, fixed output,
  and a root `schema:check` script. Witness failure because production is absent.

- [ ] **Step 2: Implement the minimal five-target runner**

  Add only the bounded synchronous orchestrator and package wiring needed to
  make the focused contract pass. Do not change any owning schema package.

- [ ] **Step 3: Add hostile result and environment coverage**

  Reject thrown, signaled, timed-out, malformed, oversized, or nonzero child
  results; missing environment authority; ambient credential/proxy/Node-option
  leakage; unexpected arguments; and output-sink failures.

- [ ] **Step 4: Run six focused passes and the real root gate**

  Run the focused runner suite six consecutive times under pinned Node 22.23.1,
  then run `npm run schema:check` with Go 1.25.6 and require the exact five-target
  success line and no tracked-source change.

## Task 3: Review and final verification

### Files

- Review the exact pre-M1-36b base through the evidence-ready head.
- Record ignored evidence under
  `.superpowers/sdd/2026-08-18-m1-36b-m1-schema-check-implementation-plan/`.

- [ ] **Step 1: Run the full local verification matrix**

  Run six focused schema-runner passes, the real schema gate, all four Go-module
  race/tidy-diff/verify/vet matrices, pinned full repository verification,
  dependency validation, production audit, and whitespace checks.

- [ ] **Step 2: Perform whole-range review**

  Audit schema completeness, existing-authority reuse, fixed output, environment
  isolation, result bounds, no-side-effect claims, status arithmetic, and
  successor boundaries. Fix every concrete finding tests-first in a separate
  scoped commit.

- [ ] **Step 3: Run pinned redacted secret scans**

  Scan staged content, every M1-36b commit, the exact range, tracked HEAD,
  reachable history, and ignored evidence. Require zero findings without new
  suppressions.

## Task 4: Complete, push, and close M1-36b

### Files

- Modify: `app/quality/m1-schema-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current status fixtures
- Modify last: this plan

- [ ] **Step 1: Write completion-contract RED**

  Change only M1-36b expectations to overall `650/0/75/3`, M1
  `68/17/0/51/0`, no active task, exactly one completed M1-36a and M1-36b,
  absent M1-36c, and exact blockers. Witness failure while status is In progress.

- [ ] **Step 2: Transition only M1-36b to Complete**

  Update README, tracker, and current fixtures mechanically. Run focused GREEN
  and the full pinned matrix. Commit as `docs: complete M1-36b schema check`.

- [ ] **Step 3: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [ ] **Step 4: Close the plan and verify closure**

  Change all 15 checkboxes to `[x]`, commit only this plan as
  `docs: close M1-36b schema check plan`, push it, require a second exact-SHA
  Runnable UI success, update ignored evidence, and continue directly to M1-36c.
