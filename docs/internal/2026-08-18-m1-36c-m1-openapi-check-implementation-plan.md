# M1-36c M1 OpenAPI Check Implementation Plan

Date: August 18, 2026

## Objective

Execute the existing exact-pinned OpenAPI generator and generated-client drift
gate, then record only the bounded M1-36c evidence and status transition.

## Invariants

- Use genuine tests-first RED/GREEN for every tracked status or contract change.
- Reuse the reviewed M1-23/M1-24 generator, source, output, flags, and pins; add
  no wrapper, duplicate schema, generated copy, dependency, or API operation.
- Run the supported writer and require no path-scoped generated-client diff.
- Independently run the official non-writing `--check` drift mode.
- Permit no install, network, provider, database, container, Kubernetes,
  LocalStack, customer-environment, or customer-state operation.
- Keep M1-36b Complete exactly once, M1-36d Pending, and the exact three source
  blockers unchanged.
- Completion requires zero open Critical, Important, or Minor findings, pinned
  local gates/scans, push, and exact-SHA Runnable UI success.

## Task 1: Start M1-36c with exact contract coverage

### Files

- Create: `app/quality/m1-openapi-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

- [x] **Step 1: Write the failing source/design/status contract**

  Bind the exact source row, M1-36b dependency, design, pinned generator and
  commands, generated path, no-drift boundary, M1-36d Pending state, arithmetic,
  exact blockers, and exactly 15 plan steps in either open or closed state.

- [x] **Step 2: Witness focused status RED**

  Run the new contract while M1-36c is still absent/Pending. Require failure
  only at the missing In-progress documentation/status expectations.

- [x] **Step 3: Move only M1-36c to In progress**

  Change overall counts to `649/1/75/3` and M1 to `68/16/1/51/0`. Add exactly
  one current M1-36c row and bounded README section. Preserve M1-36b Complete,
  absent M1-36d, and the exact blockers.

- [x] **Step 4: Run status GREEN and commit**

  Run focused/full quality tests, whitespace, audit, and staged secret scan.
  Commit the exact status/contract/docs slice as `docs: start M1-36c OpenAPI check`.

## Task 2: Execute the existing generator and drift gate

### Files

- Verify: `openapi/openapi.yaml`
- Verify: `openapi/internal-health.yaml`
- Verify: `apps/web/api/generated.ts`
- Verify: `openapi/generated-client.test.mjs`
- Verify: `package.json`

- [x] **Step 1: Establish the exact clean input/output baseline**

  Require a clean tracked tree, regular non-symlink generated client, exact
  locked generator version and flags, local-only source, and record the generated
  file bytes before execution.

- [x] **Step 2: Run the supported writer and prove no diff**

  Run `npm run openapi:generate` under pinned Node/npm, require byte equality
  with the recorded output, and require `git diff --exit-code --
  apps/web/api/generated.ts` plus a clean tracked tree.

- [x] **Step 3: Run strict validation and six drift checks**

  Run `npm run openapi:test` and `npm run openapi:lint`, then run
  `npm run openapi:check` six consecutive times. Require every check to pass
  without rewriting the generated client or changing tracked source.

- [x] **Step 4: Re-prove hostile drift behavior and scope**

  Run the existing generated-client suite that proves changed and missing
  outputs reject without rewriting them. Confirm the task added no wrapper,
  dependency, schema copy, API operation, UI/API availability, or live I/O.

## Task 3: Review and final verification

### Files

- Review the exact M1-36b closure through the evidence-ready M1-36c head.
- Record ignored evidence under
  `.superpowers/sdd/2026-08-18-m1-36c-m1-openapi-check-implementation-plan/`.

- [x] **Step 1: Run the full local verification matrix**

  Re-run the exact writer/no-diff sequence, six drift checks, OpenAPI tests and
  lint, M1-36b schema gate, all four Go-module matrices, pinned full repository
  verification, dependency validation, production audit, and whitespace checks.

- [x] **Step 2: Perform whole-range review**

  Audit command and pin identity, byte-for-byte drift evidence, no-write check
  behavior, local-only inputs, no duplicated authority, clean-tree preservation,
  status arithmetic, and successor boundaries. Fix every concrete finding
  tests-first in a separate scoped commit.

- [x] **Step 3: Run pinned redacted secret scans**

  Scan staged content, every M1-36c commit, the exact range, tracked HEAD,
  reachable history, and ignored evidence. Require zero findings without new
  suppressions.

## Task 4: Complete, push, and close M1-36c

### Files

- Modify: `app/quality/m1-openapi-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current status fixtures
- Modify last: this plan

- [x] **Step 1: Write completion-contract RED**

  Change only M1-36c expectations to overall `649/0/76/3`, M1
  `68/16/0/52/0`, no active task, exactly one completed M1-36b and M1-36c,
  absent M1-36d, and exact blockers. Witness failure while status is In progress.

- [x] **Step 2: Transition only M1-36c to Complete**

  Update README, tracker, and current fixtures mechanically. Run focused GREEN
  and the full pinned matrix. Commit as `docs: complete M1-36c OpenAPI check`.

- [x] **Step 3: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [x] **Step 4: Close the plan and verify closure**

  Change all 15 checkboxes to `[x]`, commit only this plan as
  `docs: close M1-36c OpenAPI check plan`, push it, require a second exact-SHA
  Runnable UI success, update ignored evidence, and continue directly to M1-36d.
