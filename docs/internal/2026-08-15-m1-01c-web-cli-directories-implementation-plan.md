# M1-01c Web and CLI Directories Implementation Plan

Date: August 15, 2026

## Objective

Create the `apps/web` package/deployable boundary around the existing runnable
UI and the independent `cmd/agentsecctl` Go skeleton with an exact version
command. Add no preflight, recovery, diagnostic, provider, credential,
deployment, listener, network, or customer-data behavior.

## Invariants

- Every behavior or status change has a witnessed tests-only RED first.
- `apps/web` delegates only to the locked root production build; it has no
  dependency graph or lockfile of its own.
- `cmd/agentsecctl` is an independent service-local Go module and emits only
  exact bounded version output.
- No environment, dotenv, credential, profile, proxy, endpoint, provider,
  Kubernetes, AWS, Stytch, Neon, listener, or network input is added.
- M1-01 remains Pending until M1-01c completes and exact-SHA CI passes.
- M0 blockers and R-03/R-11 status remain unchanged.

### Task 1: Start M1-01c

- [x] Add a repository contract binding source/deployable ownership,
  design/plan, completed M1-01b, unique active status, exact arithmetic,
  Pending M1-01, and unchanged blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-01c to In progress at `695/1/29/3` overall and M1
  `68/62/1/5/0`; document the web delegation and no-I/O CLI scope.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-01c web and CLI directories`.

### Task 2: Implement web and CLI boundaries tests-first

- [x] Create the web package descriptor and CLI tests/module before CLI
  production.
- [x] Capture genuine CLI compile RED on only the missing production symbols.
- [x] Implement the minimal CLI version command and run focused GREEN.
- [x] Prove the exact delegated web build and artifact-free default/injected CLI
  executions.
- [x] Run six focused passes, race/tidy/module/vet, retained worker/service
  regressions, full repository gates, audit, whitespace, and scans; commit
  `feat: add web and agentsecctl boundaries`.

### Task 3: Review both deployable boundaries

- [x] Audit web delegation, dependency/lock ownership, CLI module ownership,
  exact argument/version/output/error behavior, no-I/O scope, and tests.
- [x] Reproduce and fix every concrete finding tests-first.
- [x] Run fresh web/CLI/repository/audit/scan gates and record zero findings.

### Task 4: Complete, push, and close M1-01c

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-01c to Complete at `695/0/30/3` and M1
  `68/62/0/6/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-01c web and CLI directories`,
  push, and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-01.
