# M1-36a M1 Build Check Implementation Plan

Date: August 18, 2026

## Objective

Prove from an isolated clean checkout that the reviewed eight-target repository
build still succeeds, then record only the bounded M1-36a evidence/status change.

## Invariants

- Use genuine tests-first RED/GREEN for every tracked contract or status change.
- Reuse only `npm run build:repo`; do not add a duplicate runner or target.
- The clean checkout is a detached local clone of one exact reviewed commit and
  contains no source copied from ignored or untracked workspace state.
- Dependency installation is lockfile-exact under Node 22.23.1/npm 10.9.8 with
  no ambient npm configuration, credential, proxy, dotenv, or provider input.
- Build success is the exact fixed line `Repository build passed: targets=8`.
- The eight target names, order, commands, environment allowlists, timeouts, and
  output bounds remain owned by the reviewed M1-01 build orchestrator.
- The evidence run performs no Docker, Kubernetes, LocalStack, database, cloud,
  or customer-state operation.
- M1-35 remains Complete exactly once; M1-36b remains Pending; the exact three
  blocked source tasks and PROV-01 boundary remain unchanged.
- Completion requires zero open Critical, Important, or Minor review findings,
  final local gates, pinned secret scans, and exact-SHA Runnable UI success.

## Task 1: Start M1-36a with exact contract coverage

### Files

- Create: `app/quality/m1-build-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

- [x] **Step 1: Write the failing source/design/status contract**

  Bind the exact M1-36a source row, M1-35 dependency, selected design, exact
  eight-target inventory, root command, fixed result, clean-checkout protocol,
  M1-36b Pending boundary, arithmetic, and exact blockers.

- [x] **Step 2: Witness focused status RED**

  Run the new contract with M1-35. Require failure only because M1-36a is still
  absent/Pending and overall status remains `652/0/73/3`.

- [x] **Step 3: Move only M1-36a to In progress**

  Change overall counts to `651/1/73/3` and M1 to `68/18/1/49/0`. Add exactly
  one current M1-36a row and a bounded README statement. Preserve one completed
  M1-35, absent M1-36b, and exact blockers.

- [x] **Step 4: Run status GREEN and commit**

  Run focused and full quality tests, whitespace, audit, and staged secret scan.
  Commit the exact status/contract/docs slice as `docs: start M1-36a build check`.

## Task 2: Execute the clean-checkout build evidence

### Files

- Verify: `scripts/build-repo.mjs`
- Verify: `scripts/build-repo.test.mjs`
- Verify: `package.json`
- Record ignored evidence under `.superpowers/sdd/2026-08-18-m1-36a-m1-build-check-implementation-plan/`

- [x] **Step 1: Re-prove the hermetic orchestrator contract**

  Run `node --test scripts/build-repo.test.mjs` six consecutive times. Require
  every pass to bind all eight targets, no-download/provider exclusions, fixed
  output, fail-fast behavior, exact worker output, and bounded child execution.

- [x] **Step 2: Create one exact detached clean checkout**

  Create a unique owned temporary root, locally clone the repository without
  hardlinks, detach at the committed M1-36a implementation SHA, require exact
  HEAD equality, and require empty checkout status before dependency install.

- [x] **Step 3: Install only locked web dependencies**

  Under pinned Node/npm, isolate HOME, npm cache, and `NPM_CONFIG_USERCONFIG`;
  run the same lockfile install boundary used by CI with
  `SHARP_IGNORE_GLOBAL_LIBVIPS=1`. Do not pass credentials, proxies, dotenv, or
  provider configuration.

- [x] **Step 4: Run the exact eight-target build**

  Execute `npm run build:repo` with the explicit Node, Go 1.25.6, Python 3.13,
  and system-tool path. Require exit zero and only the exact success line.

- [x] **Step 5: Prove source stability and remove evidence artifacts**

  Require the detached checkout's tracked source to remain clean after the
  build. Record only redacted counts/result evidence, then remove the exact owned
  temporary clone/cache/root and prove no task prefix remains.

## Task 3: Review and final verification

### Files

- Review the exact pre-M1-36a base through the evidence-ready head.
- Update ignored task report and append-only progress ledger.

- [x] **Step 1: Run the full local verification matrix**

  Run six build-orchestrator test passes, one current-worktree `build:repo`, full
  pinned `npm run verify`, dependency validation, production audit, all relevant
  Go module verification, and whitespace checks.

- [x] **Step 2: Perform whole-range review**

  Audit clean-checkout isolation, exact target completeness, fixed output,
  environment authority, no-download/provider behavior, source stability,
  cleanup, status arithmetic, and successor boundaries. Fix every concrete
  finding tests-first in a separate scoped commit.

- [x] **Step 3: Run pinned redacted secret scans**

  Scan staged content, every M1-36a commit, the exact task range, tracked HEAD,
  reachable history, and ignored evidence. Require zero findings without new
  suppressions.

## Task 4: Complete, push, and close M1-36a

### Files

- Modify: `app/quality/m1-build-check-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current status fixtures
- Modify last: this plan

- [x] **Step 1: Write completion-contract RED**

  Change only the M1-36a status expectations to overall `651/0/74/3`, M1
  `68/18/0/50/0`, no active task, exactly one completed M1-35 and M1-36a,
  absent M1-36b, and exact blockers. Witness failure while status is In progress.

- [x] **Step 2: Transition only M1-36a to Complete**

  Update README, tracker, and current count/status fixtures mechanically. Run
  focused GREEN and the full pinned matrix. Commit as
  `docs: complete M1-36a build check`.

- [x] **Step 3: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [x] **Step 4: Close the plan and verify closure**

  Change every checkbox in this plan to `[x]`, commit only this plan as
  `docs: close M1-36a build check plan`, push it, require a second exact-SHA
  Runnable UI success, update ignored evidence, and continue directly to M1-36b.
