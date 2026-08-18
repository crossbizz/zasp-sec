# M1-36e M1 Local Infrastructure Smoke Implementation Plan

Date: August 18, 2026

## Objective

Execute the existing disposable assembled Kubernetes and LocalStack target,
prove required dependencies healthy and exact cleanup complete, then record
only the bounded M1-36e evidence and status transition.

## Invariants

- Use genuine tests-first RED/GREEN for every tracked status or contract change.
- Reuse the reviewed M1-30 assembled entrypoint, manifests, pins, lifecycle,
  commands, fixed output, and cleanup authority; add no smoke wrapper,
  duplicate manifest, dependency, image, port, or provider behavior.
- Never target an ambient kubeconfig, shared Kubernetes cluster, or shared
  LocalStack service. Never delete or retag a pre-existing shared image.
- Require exact pre/post owned-prefix absence and unchanged shared and ambient
  fingerprints around the one live command.
- Keep M1-36d Complete exactly once, M1-37 Pending, and the exact three source
  blockers unchanged.
- Completion requires a source-timebox-compliant live success, zero open
  Critical, Important, or Minor findings, pinned local gates/scans, push, and
  exact-SHA Runnable UI success.

## Task 1: Start M1-36e with exact contract coverage

### Files

- Create: `app/quality/m1-local-infrastructure-smoke-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

- [ ] **Step 1: Write the failing source/design/status contract**

  Bind the exact source row, M1-36d dependency, design, existing target and
  command, six canonical manifests, exact output, live/no-shared-state safety,
  M1-37 Pending state, arithmetic, blockers, and exactly 15 plan steps in
  either open or closed state.

- [ ] **Step 2: Witness focused status RED**

  Run the new contract while M1-36e is still absent/Pending. Require failure
  only at the missing In-progress documentation and tracker boundaries.

- [ ] **Step 3: Move only M1-36e to In progress**

  Change overall counts to `647/1/77/3` and M1 to `68/14/1/53/0`. Add exactly
  one current M1-36e row and bounded README section. Preserve M1-36d Complete,
  absent M1-37, and the exact blockers.

- [ ] **Step 4: Run status GREEN and commit**

  Run focused/full quality tests, whitespace, audit, and staged secret scan.
  Commit the exact status/contract/docs slice as
  `docs: start M1-36e local infrastructure smoke`.

## Task 2: Prove the reviewed smoke boundary locally

### Files

- Verify: `deploy/local/start.mjs`
- Verify: `deploy/local/start.test.mjs`
- Verify: `deploy/local/aws-emulator-run.mjs`
- Verify: `package.json`

- [ ] **Step 1: Establish the exact clean assembly baseline**

  Require a clean tracked tree, exact local-start target/profile/dependencies,
  six regular canonical manifests, 22-resource exposure projection, pinned
  runtimes, and zero proof-owned M1-30d residue.

- [ ] **Step 2: Run hostile and inherited hermetic suites**

  Run the focused assembly suite and complete AWS-emulator suite under pinned
  Node/npm. Require all composition, exposure, provider, mutation, deadline,
  cleanup, license, and prior-profile regressions to pass.

- [ ] **Step 3: Run six consecutive focused assembly checks**

  Run `node --test deploy/local/start.test.mjs` six times. Require exact test
  counts, empty unexpected output, exit zero, and no tracked-source change.

- [ ] **Step 4: Capture the independent live preflight**

  Record exact ambient Docker and kubeconfig fingerprints, pre-existing shared
  image identities/aliases/consumers, current Docker context, and zero owned
  containers, networks, volumes, images, and temp roots. Stop before mutation
  on any unowned or ambiguous proof-prefix candidate.

## Task 3: Run the exact live smoke and audit cleanup

### Files

- Execute: `npm run local:start`
- Record ignored evidence under
  `.superpowers/sdd/2026-08-18-m1-36e-m1-local-infrastructure-smoke-implementation-plan/`.

- [ ] **Step 1: Run one exact env-isolated live command**

  Execute only the reviewed root command with pinned Node/npm and the approved
  host environment. Require exit zero, the sole fixed success line, empty
  stderr, and measured smoke time within the source task's 15-minute target.

- [ ] **Step 2: Prove exact post-live absence and non-interference**

  Require zero owned containers, networks, volumes, images, labels, aliases,
  and temporary roots. Require every retained shared-image/consumer, ambient
  Docker-object, Docker-context, and kubeconfig fingerprint to match preflight.

- [ ] **Step 3: Run the full local verification matrix and review**

  Re-run focused/hermetic local suites, schema/OpenAPI/UI-API gates, all four
  Go-module matrices, pinned full repository verification, production audit,
  whitespace, clean-tree, and pinned scans. Perform whole-range review and fix
  every concrete finding tests-first in a separate scoped commit.

## Task 4: Complete, push, and close M1-36e

### Files

- Modify: `app/quality/m1-local-infrastructure-smoke-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current status fixtures
- Modify last: this plan

- [ ] **Step 1: Write completion-contract RED**

  Change only M1-36e expectations to overall `647/0/78/3`, M1
  `68/14/0/54/0`, no active task, exactly one completed M1-36d and M1-36e,
  absent M1-37, and exact blockers. Witness failure while status is In progress.

- [ ] **Step 2: Transition only M1-36e to Complete**

  Update README, tracker, and current fixtures mechanically. Run focused GREEN
  and the full pinned matrix. Commit as
  `docs: complete M1-36e local infrastructure smoke`.

- [ ] **Step 3: Push and require exact-SHA Runnable UI success**

  Push the reviewed completion commit, prove local/origin/tracking SHAs equal,
  and wait for terminal Runnable UI success at that exact SHA.

- [ ] **Step 4: Close the plan and continue**

  Change all 15 checkboxes to `[x]`, commit only this plan as
  `docs: close M1-36e local infrastructure smoke plan`, push it, require a
  second exact-SHA Runnable UI success, update ignored evidence, and continue
  directly to the next Pending task.
