# M1-01f Event Ingest Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans and superpowers:test-driven-development. Every
> behavior or status change must have a witnessed tests-only RED before GREEN.

**Goal:** Add the minimal standalone event-ingest Go command, prove its exact
build version, review it, and complete M1-01f.

**Architecture:** Create one service-local Go module at `services/event-ingest`
with a single main package. It prints a bounded compile-time version and has no
listener, normalization, batching, or provider dependency.

## Global constraints

- M1-01f depends on completed M1-01e and is the only active source-plan task.
- Starting status is `698/1/26/3` overall and `68/65/1/2/0` in M1.
- Completion status is `698/0/27/3` overall and `68/65/0/3/0` in M1.
- M0 stays `27/0/0/24/3`; all existing blocked tasks and risks stay unchanged.
- M1-01a remains Pending until M1-01f completes and exact-SHA CI passes.
- No environment, dotenv, credential, profile, proxy, endpoint, file, listener,
  provider, queue, SQS, normalization, batching, or ingest input is added.

### Task 1: Start M1-01f

- [x] Add a repository contract binding source, deployable ownership, design,
  plan, unique active status, exact arithmetic, completed M1-01e, Pending
  M1-01a, and M0 blockers.
- [x] Capture focused RED at the still-Pending README/tracker state.
- [x] Move only M1-01f to In progress and document its no-I/O skeleton scope.
- [x] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-01f event ingest command`.

### Task 2: Implement the event-ingest command tests-first

- [x] Create `services/event-ingest/main_test.go` and `go.mod` before production
  and cover exact output, bounded grammar, invalid values, nil output, and
  writer failure.
- [x] Capture genuine compile RED on only the missing command symbols.
- [x] Implement `services/event-ingest/main.go` and run focused GREEN.
- [x] Prove artifact-free build plus exact default and injected execution.
- [x] Run five focused passes, race, retained platform command regressions,
  tidy-diff, module verify, vet, full pinned gates, audit, whitespace, and scans;
  commit `feat: add event ingest command`.

### Task 3: Review the complete command

- [x] Audit deployable/module ownership, version grammar, output, link-time
  injection, error behavior, no-I/O scope, tests, and status evidence.
- [x] Reproduce and fix every concrete finding tests-first.
- [x] Run fresh Go/repository/audit/scan gates and record zero findings.

### Task 4: Complete, push, and close M1-01f

- [x] Change only completion expectations and capture focused RED.
- [x] Move only M1-01f to Complete at `698/0/27/3` and M1
  `68/65/0/3/0`; preserve M0 and all blockers.
- [x] Run final gates, commit `docs: complete M1-01f event ingest command`,
  push, and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-01a.
