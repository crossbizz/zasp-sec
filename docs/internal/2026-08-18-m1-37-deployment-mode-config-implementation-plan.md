# M1-37 Deployment Mode Configuration Implementation Plan

Date: August 18, 2026

## Objective

Add one strict typed deployment-mode group to the completed platform
configuration loader so SaaS starts without an Organization pin and
single-tenant mode cannot start without one canonical product Organization ID.

## Invariants

- Every behavior and status change has a witnessed tests-only RED first.
- `AGENTSEC_DEPLOYMENT_MODE` is required and accepts only exact `saas` or
  `single_tenant`; there is no implicit/default deployment mode.
- `AGENTSEC_SINGLE_TENANT_ORGANIZATION_ID` is absent in SaaS and required in
  single-tenant mode as one canonical M1-03 product ID.
- The source lookup remains injected, snapshots every known key exactly once,
  and reads no ambient process, file, profile, metadata, provider, or secret
  state.
- Returned values remain opaque, immutable, comparable, and revalidated;
  fixed errors never include rejected values.
- Preserve every M1-07 required/optional dependency behavior and add no command
  wiring, authorization, topology, image, schema, API, or provider behavior.
- Keep M1-36e Complete exactly once, M1-38 Pending, and the exact three source
  blockers unchanged.
- Completion requires zero open Critical, Important, or Minor findings, pinned
  local gates/scans, push, and exact-SHA Runnable UI success.

## Task 1: Start M1-37 with exact contract coverage

### Files

- Create: `app/quality/m1-deployment-mode-config-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

- [ ] **Step 1: Write the source/design/status contract**

  Bind the exact source row, M1-07 dependency, selected design, two source
  keys, exact mode/pin matrix, deferred M2-49 enforcement, M1-36e/M1-38
  boundaries, arithmetic, blockers, and exactly 16 plan steps.

- [ ] **Step 2: Witness focused status RED**

  Run the new contract while M1-37 is still absent/Pending. Require failure
  only at the missing In-progress README/tracker boundary.

- [ ] **Step 3: Move only M1-37 to In progress**

  Change overall counts to `646/1/78/3` and M1 to `68/13/1/54/0`. Add exactly
  one current M1-37 row and a bounded README section. Preserve M1-36e Complete,
  absent M1-38, R-03/R-11, and the exact blockers.

- [ ] **Step 4: Run status GREEN and commit**

  Run focused/full pinned quality tests, audit, whitespace, and staged secret
  scan. Commit the exact status/contract/docs slice as
  `docs: start M1-37 deployment mode config`.

## Task 2: Implement the typed deployment boundary tests-first

### Files

- Modify tests first: `services/platform/config/config_test.go`
- Modify after RED: `services/platform/config/config.go`

- [ ] **Step 1: Capture missing deployment API RED**

  Add tests for the exact keys, enum/parser, SaaS configuration, valid
  single-tenant pin, accessors, comparability, and known-key single reads. Run
  the focused package and require compile failure at the absent API.

- [ ] **Step 2: Implement the minimal valid modes and accessors**

  Add the opaque enum, deployment value, Config accessor, exact source
  snapshot, conditional pin parsing, and whole-value validation. Reuse
  `domain.ParseProductID`; do not create a second ID grammar.

- [ ] **Step 3: Add hostile matrix RED/GREEN**

  Cover missing/empty/unknown/case/whitespace modes, present SaaS pins,
  absent/empty/malformed single-tenant pins, canonical-ID drift, direct invalid
  state, error secrecy, and source read counts. Require each new behavior to
  fail before its minimal production correction.

- [ ] **Step 4: Run focused stability and commit**

  Run six consecutive race-enabled config package passes plus platform module
  tidy-diff/module-verify/vet and retained M1-07 contract tests. Scan and commit
  the exact source/test slice as `feat: add deployment mode configuration`.

## Task 3: Review and harden the boundary

### Files

- Review: `services/platform/config/config.go`
- Review: `services/platform/config/config_test.go`
- Record ignored evidence under
  `.superpowers/sdd/2026-08-18-m1-37-deployment-mode-config-implementation-plan/`.

- [ ] **Step 1: Audit source and value integrity**

  Review lookup calls, snapshot immutability, enum aliases, zero/direct state,
  ProductID canonicalization, comparability, accessors, errors, and accidental
  source-value exposure.

- [ ] **Step 2: Audit mode/pin combinations and scope**

  Prove the complete truth table, no ignored SaaS pin, no inferred Organization,
  no M1-07 regression, and no premature command, topology, or authorization
  behavior.

- [ ] **Step 3: Fix every concrete finding tests-first**

  Capture a focused RED for each finding, implement the smallest fail-closed
  fix in a separate commit, and rerun the affected and inherited gates.

- [ ] **Step 4: Record zero-finding review**

  Require Critical 0 / Important 0 / Minor 0 before status completion. Record
  exact commits, RED/GREEN evidence, gates, scans, and any bounded concern.

## Task 4: Complete, push, and close M1-37

### Files

- Modify: `app/quality/m1-deployment-mode-config-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current status fixtures
- Modify last: this plan

- [ ] **Step 1: Write completion-contract RED**

  Change only M1-37 expectations to overall `646/0/79/3`, M1
  `68/13/0/55/0`, no active task, exactly one completed M1-36e and M1-37,
  absent M1-38, and exact blockers. Witness failure while status is In progress.

- [ ] **Step 2: Transition only M1-37 to Complete**

  Update README, tracker, and current fixtures mechanically. Run focused GREEN,
  six race passes, full platform and pinned repository gates, audit, whitespace,
  and scans. Commit as `docs: complete M1-37 deployment mode config`.

- [ ] **Step 3: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [ ] **Step 4: Close the plan and continue**

  Change all 16 checkboxes to `[x]`, commit only this plan as
  `docs: close M1-37 deployment mode config plan`, push it, require a second
  exact-SHA Runnable UI success, update ignored evidence, and continue directly
  to M1-38.
