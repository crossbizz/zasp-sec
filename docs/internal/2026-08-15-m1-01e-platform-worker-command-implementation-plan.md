# M1-01e Platform Worker Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans and superpowers:test-driven-development. Every
> behavior or status change must have a witnessed tests-only RED before GREEN.

**Goal:** Add the minimal platform worker command beside the completed API
command, prove its exact build version, review it, and complete M1-01e.

**Architecture:** Reuse the existing `services/platform` Go module and add one
independent `agentsec-worker` main package. It prints a bounded compile-time
version and has no worker loop or runtime dependency.

## Global constraints

- M1-01e depends on completed M1-01d and is the only active source-plan task.
- Starting status is `699/1/25/3` overall and `68/66/1/1/0` in M1.
- Completion status is `699/0/26/3` overall and `68/66/0/2/0` in M1.
- M0 stays `27/0/0/24/3`; all existing blocked tasks and risks stay unchanged.
- M1-01f remains Pending until M1-01e completes and exact-SHA CI passes.
- No environment, dotenv, credential, profile, proxy, endpoint, file, listener,
  provider, queue, or worker-loop input is added.

### Task 1: Start M1-01e

- [x] Add a repository contract binding source, design, plan, unique active
  status, exact arithmetic, completed M1-01d, Pending M1-01f, and M0 blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-01e to In progress and document its no-I/O skeleton scope.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-01e platform worker command`.

### Task 2: Implement the worker command tests-first

- [x] Create `agentsec-worker/main_test.go` before production and cover exact
  output, bounded grammar, invalid values, nil output, and writer failure.
- [x] Capture genuine compile RED on only the missing worker symbols.
- [x] Implement `agentsec-worker/main.go` and run focused GREEN.
- [x] Prove artifact-free build plus exact default and injected execution.
- [x] Run five focused passes, race, both platform command builds/tests,
  tidy-diff, module verify, vet, full pinned gates, audit, whitespace, and scans;
  commit `feat: add platform worker command`.

### Task 3: Review the complete command

- [ ] Audit module ownership, duplication boundary, version grammar, output,
  link-time injection, error behavior, no-I/O scope, tests, and status evidence.
- [ ] Reproduce and fix every concrete finding tests-first.
- [ ] Run fresh Go/repository/audit/scan gates and record zero findings.

### Task 4: Complete, push, and close M1-01e

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-01e to Complete at `699/0/26/3` and M1
  `68/66/0/2/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-01e platform worker command`,
  push, and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-01f.
