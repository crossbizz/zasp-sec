# M1-36d M1 UI/API Coverage Check Implementation Plan

Date: August 18, 2026

## Objective

Execute the existing strict UI/API traceability validator, then record only the
bounded M1-36d evidence and status transition.

## Invariants

- Use genuine tests-first RED/GREEN for every tracked status or contract change.
- Reuse the reviewed M1-25/M1-26 map, OpenAPI source, validator, commands, and
  fixed output; add no wrapper, duplicate map, report, dependency, or operation.
- Keep planned, available, public, and internal lifecycle semantics exact.
- Permit no write, install, network, provider, database, container, Kubernetes,
  LocalStack, customer-environment, or customer-state operation.
- Keep M1-36c Complete exactly once, M1-36e Pending, and the exact three source
  blockers unchanged.
- Completion requires zero open Critical, Important, or Minor findings, pinned
  local gates/scans, push, and exact-SHA Runnable UI success.

## Task 1: Start M1-36d with exact contract coverage

### Files

- Create: `app/quality/m1-ui-api-coverage-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

- [x] **Step 1: Write the failing source/design/status contract**

  Bind the exact source row, M1-36c dependency, design, validator inputs and
  commands, fixed output, lifecycle semantics, no-side-effect boundary, M1-36e
  Pending state, arithmetic, blockers, and 15 open-or-closed plan steps.

- [x] **Step 2: Witness focused status RED**

  Run the new contract while M1-36d is still absent/Pending. Require failure
  only at the missing In-progress documentation/status expectations.

- [x] **Step 3: Move only M1-36d to In progress**

  Change overall counts to `648/1/76/3` and M1 to `68/15/1/52/0`. Add exactly
  one current M1-36d row and bounded README section. Preserve M1-36c Complete,
  absent M1-36e, and the exact blockers.

- [x] **Step 4: Run status GREEN and commit**

  Run focused/full quality tests, whitespace, audit, and staged secret scan.
  Commit the exact status/contract/docs slice as
  `docs: start M1-36d UI API coverage check`.

## Task 2: Execute the existing traceability validator

### Files

- Verify: `docs/product/ui-api-map.yaml`
- Verify: `openapi/openapi.yaml`
- Verify: `scripts/check-ui-api-coverage.mjs`
- Verify: `scripts/check-ui-api-coverage.test.mjs`
- Verify: `package.json`

- [x] **Step 1: Establish the exact input and command baseline**

  Require regular non-symlink fixed inputs, exact package wiring, five planned
  map entries, zero available entries, zero current public/internal operations,
  and a clean tracked tree.

- [x] **Step 2: Run the hostile validator suite**

  Run `npm run ui-api:test` under pinned Node/npm. Require all current, future,
  removal, unmapped, internal, duplicate, representation, file-boundary, fixed-
  output, and package-wiring cases to pass.

- [x] **Step 3: Run six consecutive real checks**

  Run `npm run ui-api:check` six times. Require the exact aggregate success line
  on every run, empty stderr, exit zero, and no tracked-source change.

- [x] **Step 4: Re-prove traceability scope**

  Confirm every present public operation would require one available mapping,
  every planned mapping remains absent, internal operations remain unmapped,
  and the task added no operation, availability change, wrapper, dependency,
  output artifact, or live I/O.

## Task 3: Review and final verification

### Files

- Review the exact M1-36c closure through the evidence-ready M1-36d head.
- Record ignored evidence under
  `.superpowers/sdd/2026-08-18-m1-36d-m1-ui-api-coverage-check-implementation-plan/`.

- [x] **Step 1: Run the full local verification matrix**

  Re-run the hostile suite and six real checks, M1-36b schema and M1-36c OpenAPI
  gates, all four Go-module matrices, pinned full repository verification,
  dependency validation, production audit, and whitespace checks.

- [x] **Step 2: Perform whole-range review**

  Audit exact inputs/commands, planned/available/public/internal coverage,
  parser and file bounds, fixed output, no-side-effect claims, absence of new
  product surface, status arithmetic, and successor boundaries. Fix every
  concrete finding tests-first in a separate scoped commit.

- [x] **Step 3: Run pinned redacted secret scans**

  Scan staged content, every M1-36d commit, the exact range, tracked HEAD,
  reachable history, and ignored evidence. Require zero findings without new
  suppressions.

## Task 4: Complete, push, and close M1-36d

### Files

- Modify: `app/quality/m1-ui-api-coverage-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current status fixtures
- Modify last: this plan

- [x] **Step 1: Write completion-contract RED**

  Change only M1-36d expectations to overall `648/0/77/3`, M1
  `68/15/0/53/0`, no active task, exactly one completed M1-36c and M1-36d,
  absent M1-36e, and exact blockers. Witness failure while status is In progress.

- [x] **Step 2: Transition only M1-36d to Complete**

  Update README, tracker, and current fixtures mechanically. Run focused GREEN
  and the full pinned matrix. Commit as `docs: complete M1-36d UI API coverage check`.

- [x] **Step 3: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [x] **Step 4: Close the plan and verify closure**

  Change all 15 checkboxes to `[x]`, commit only this plan as
  `docs: close M1-36d UI API coverage check plan`, push it, require a second
  exact-SHA Runnable UI success, update ignored evidence, and continue directly
  to M1-36e.
