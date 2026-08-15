# M1-01d Platform API Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans and superpowers:test-driven-development. Every
> behavior or status change must have a witnessed tests-only RED before GREEN.

**Goal:** Create the minimal platform API Go command, prove its exact build
version output, review it, complete M1-01d, and preserve every M0 provider
blocker.

**Architecture:** Add one service-local Go module at `services/platform` and
one `agentsec-api` main package. Its only behavior is deterministic build
version output from a bounded compile-time value. It has no runtime dependency,
network listener, configuration input, or product API claim.

**Tech stack:** Go 1.25.0, Go 1.25.6 toolchain, TypeScript, Vitest, Node.js
22.23.1, npm 10.9.8, GitHub Actions Runnable UI, Gitleaks 8.30.1.

## Global constraints

- M1-01d depends on completed M0-23 and is the only source-plan task started.
- Starting status is `700/1/24/3` overall and `68/67/1/0/0` in M1.
- Completion status is `700/0/25/3` overall and `68/67/0/1/0` in M1.
- M0 stays `27/0/0/24/3`; M0-09, M0-18, M0-19, and PROV-01 stay Blocked;
  R-03 and R-11 remain unpassed.
- The command does not load environment, dotenv, credentials, profiles,
  proxies, endpoints, Git state, files, or network state.
- M1-01e remains Pending until M1-01d completes and exact-SHA CI passes.

---

### Task 1: Start M1-01d and bind the command boundary

**Files:**
- Create: `app/quality/platform-api-command-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Update ignored task report and both progress ledgers.

- [ ] Write a repository contract requiring the exact source dependency,
  design/plan boundary, unique M1-01d In-progress row, exact global/M0/M1
  arithmetic, M1-01e still Pending, and unchanged M0 blockers.
- [ ] Run focused RED against the still-Pending status.
- [ ] Move only M1-01d to In progress and document its no-I/O skeleton scope.
- [ ] Run focused/full pinned GREEN, audit, whitespace, and secret scans; commit
  `docs: start M1-01d platform API command`.

### Task 2: Implement the minimal Go command tests-first

**Files:**
- Create: `services/platform/go.mod`
- Create: `services/platform/agentsec-api/main_test.go`
- Create: `services/platform/agentsec-api/main.go`
- Modify: `app/quality/platform-api-command-contract.test.ts`
- Update ignored task report and progress ledgers.

- [ ] Add tests for default/injected exact output, bounded version grammar,
  multiline/control rejection, and writer failure before production exists.
- [ ] Run genuine compile RED on the missing command symbols.
- [ ] Implement the minimum command and run focused GREEN.
- [ ] Build a temporary binary with an injected version and require exact
  output `agentsec-api build 0.1.0-test.1`.
- [ ] Run five fresh Go test passes, race, build, tidy-diff, module verify, vet,
  full pinned repository verification, audit, whitespace, and redacted scans;
  commit `feat: add platform API command`.

### Task 3: Review and fix the complete command

- [ ] Audit exact scope, version grammar, output, link-time injection,
  environment independence, write failure, module ownership, tests, and status
  evidence.
- [ ] Reproduce every finding tests-first and fix only demonstrated defects.
- [ ] Run fresh focused/stability/race/build/module/vet/full/audit/scan gates and
  record a zero-finding result.

### Task 4: Complete, push, and close M1-01d

- [ ] Change only completion expectations first and capture focused RED.
- [ ] Move only M1-01d to Complete at `700/0/25/3` and M1 to
  `68/67/0/1/0`; preserve the complete M0 gate and all blockers.
- [ ] Run all final gates, commit `docs: complete M1-01d platform API command`,
  push, and watch Runnable UI to success for the exact SHA.
- [ ] Close every plan checkbox, record run/job IDs, commit/push the plan close,
  watch exact-SHA CI, then start M1-01e.
