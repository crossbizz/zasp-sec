# M1-38 Neon Organization Scope Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Add a dependency-free repository guard that rejects customer-data
queries without one canonical product Organization ID before SQL execution.

**Architecture:** A new `services/platform/repository` package wraps the
existing `database.Pool`-shaped query interface. Each call validates a trusted
Organization ID, prepends its canonical string as SQL argument `$1`, copies the
remaining arguments, and maps downstream failures to fixed errors without
retaining tenant state.

**Tech Stack:** Go 1.25 source compatibility, Go 1.25.6 toolchain, standard
library only, existing `services/platform/domain` and `database` packages,
Vitest repository contracts, Node.js 22.23.1, npm 10.9.8.

**Spec:** `docs/internal/2026-08-18-m1-38-neon-organization-scope-guard-design.md`

## Global Constraints

- The exact source dependency is M1-04 plus M1-10; both remain Complete.
- M1-37 remains Complete exactly once and M1-39 remains Pending.
- Start counts are `645/1/79/3` overall and M1 `68/12/1/55/0`; completion
  counts are `645/0/80/3` overall and M1 `68/12/0/56/0`.
- Missing, zero, malformed, or noncanonical Organization IDs fail before the
  queryer is invoked.
- A valid call prepends the canonical Organization string as argument zero and
  never mutates or retains the caller argument slice.
- Fixed errors never expose Organization IDs, SQL, arguments, destinations,
  driver messages, or panic values.
- Add no SQL parser, dynamic statement builder, environment read, schema or
  provider mutation, transaction context, pgx dependency, command, or live run.
- M1-45a remains responsible for transaction-local tenant context; M1-45b and
  M1-45c remain responsible for database RLS and cross-Organization proof.
- M0-09, M0-18, and M0-19 remain Blocked; R-03 remains incomplete; R-11
  remains Not run.
- Every behavior and status change has a witnessed tests-only RED first.

---

## Task 1: Start M1-38 with exact contract coverage

**Files:**
- Create: `app/quality/m1-neon-organization-scope-guard-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures

**Interfaces:**
- Consumes: authoritative M1-38 source row, M1-04/M1-10 completion rows,
  committed design, this plan, and M1-37 completion.
- Produces: one unique M1-38 In-progress row, exact arithmetic, and a bounded
  README statement of the call-boundary guarantee.

- [x] **Step 1: Write the source/design/status contract**

  Require the source dependency/deliverable/verification text, exact public
  helper signatures, argument-zero behavior, fixed error boundary, deferred
  RLS tasks, M1-37/M1-39 status, blockers, arithmetic, and exactly 16 execution
  steps.

- [x] **Step 2: Witness focused status RED**

  Run:

  ```bash
  PATH=/Users/manishmaheshwari/.nvm/versions/node/v22.23.1/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
    npx vitest run app/quality/m1-neon-organization-scope-guard-contract.test.ts
  ```

  Require failure only because README/tracker still leave M1-38 Pending.

- [x] **Step 3: Move only M1-38 to In progress**

  Change overall counts to `645/1/79/3` and M1 to `68/12/1/55/0`. Add one
  current M1-38 row and one README section. Preserve M1-37 Complete, absent
  M1-39, R-03/R-11, and the exact blockers.

- [x] **Step 4: Run status GREEN and commit**

  Run the focused contract, predecessor/status contracts, pinned full
  repository verification, production audit, whitespace, and staged redacted
  scan. Commit the exact status slice as
  `docs: start M1-38 Neon Organization scope guard`.

---

## Task 2: Implement the stateless repository guard

**Files:**
- Create: `services/platform/repository/repository_test.go`
- Create: `services/platform/repository/repository.go`

**Interfaces:**
- Consumes:

  ```go
  type Queryer interface {
      QueryRow(context.Context, string, []any, ...any) error
  }
  ```

- Produces:

  ```go
  var ErrConfiguration = errors.New("repository configuration rejected")
  var ErrQuery = errors.New("repository query rejected")
  func New(Queryer) (*Guard, error)
  func (*Guard) QueryRow(context.Context, domain.ProductID, string, []any, ...any) error
  ```

- [x] **Step 1: Capture missing repository API RED**

  Add one valid-call test that constructs a guard, passes a canonical
  Organization ID, statement, two caller arguments, and one destination, then
  requires the queryer to receive the exact statement, destination, and
  `[]any{organizationID.String(), callerArg0, callerArg1}`. Run:

  ```bash
  /opt/homebrew/bin/go test -C services/platform ./repository -count=1
  ```

  Require compiler failure only on the absent package API.

- [x] **Step 2: Implement the minimal valid boundary**

  Add `Queryer`, private `Guard.queryer`, fixed errors, `New`, and `QueryRow`.
  Validate the Organization by exact parse/string round-trip, allocate a fresh
  argument slice, prepend the canonical string, forward once, and map any
  downstream non-nil error to `ErrQuery`.

- [x] **Step 3: Add hostile admission and isolation RED/GREEN**

  Add table tests for zero and malformed direct-state IDs, nil/canceled
  context, empty/whitespace/NUL/invalid-UTF-8/oversized statements, no
  destination, nil and typed-nil queryer, zero guard, downstream error/panic,
  fixed-error secrecy, caller-slice mutation, and two concurrent Organizations.
  Every rejected precondition must leave the queryer call count at zero.

- [x] **Step 4: Run focused stability and commit**

  Run six consecutive
  `/opt/homebrew/bin/go test -C services/platform -race -count=1 ./repository`
  passes, then the full platform race/tidy-diff/module-verify/vet matrix,
  whitespace, and staged scan. Commit only the package as
  `feat: add Neon Organization scope guard`.

---

## Task 3: Review the complete M1-38 range

**Files:**
- Review: `services/platform/repository/repository.go`
- Review: `services/platform/repository/repository_test.go`
- Modify only confirmed finding code/tests
- Create ignored evidence:
  `.superpowers/sdd/2026-08-18-m1-38-neon-organization-scope-guard-implementation-plan/task-3-report.md`
- Create ignored evidence:
  `.superpowers/sdd/2026-08-18-m1-38-neon-organization-scope-guard-implementation-plan/progress.md`

**Interfaces:**
- Consumes: exact design-to-head diff and fresh local gate evidence.
- Produces: zero open Critical, Important, or Minor findings before completion.

- [x] **Step 1: Audit authorization and data-flow boundaries**

  Trace every call from public admission to the queryer. Require canonical
  Organization validation before execution, exact position-zero insertion,
  no caller slice mutation, no stored tenant state, and no queryer path that
  bypasses the guard after admission.

- [x] **Step 2: Audit hostile runtime behavior**

  Probe nil/typed-nil and malformed interfaces, direct invalid ProductID
  state, canceled contexts, downstream errors and panics, stateful arguments,
  concurrent Organizations, and rejected-value secrecy. Confirm `database.Pool`
  satisfies `Queryer` at compile time without adapter code.

- [x] **Step 3: Fix every concrete finding tests-first**

  For each finding, add the smallest regression test, witness the intended
  failure, implement the minimal correction, and rerun focused plus affected
  gates. Keep each correction in a separate atomic commit.

- [x] **Step 4: Record zero-finding review**

  Require Critical 0 / Important 0 / Minor 0 and Implementation Ready Yes.
  Record exact ranges, RED/GREEN counts, commands, and fixed scope in ignored
  evidence without staging those files.

---

## Task 4: Complete, push, and close M1-38

**Files:**
- Modify: `app/quality/m1-neon-organization-scope-guard-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify mechanically: current `app/quality/*-contract.test.ts` status fixtures
- Modify after successful completion CI: this plan
- Update ignored evidence: Task 3 report and progress ledger

**Interfaces:**
- Consumes: reviewed implementation, fresh local gates/scans, exact CI result.
- Produces: M1-38 Complete, closed plan, synchronized local/origin/tracking refs,
  and M1-39 still Pending.

- [x] **Step 1: Write completion-contract RED**

  Change only M1-38 expectations to `645/0/80/3`, M1
  `68/12/0/56/0`, no active task, exactly one completed M1-37 and M1-38,
  absent M1-39, and exact blockers. Witness failure while status is In
  progress.

- [x] **Step 2: Transition only M1-38 to Complete**

  Update README, tracker, and current status fixtures mechanically. Run focused
  GREEN, six race passes, full platform and pinned repository gates, audit,
  whitespace, staged scan, and exact-range scan. Commit as
  `docs: complete M1-38 Neon Organization scope guard`.

- [x] **Step 3: Push and require exact-SHA Runnable UI success**

  Push `codex/zasp-implementation`, locate Runnable UI by the exact completion
  SHA, and watch its exact job to terminal success. Record the run/job URL and
  IDs in ignored evidence.

- [x] **Step 4: Close the plan and continue**

  Change all 16 execution checkboxes to `[x]`, commit only this plan as
  `docs: close M1-38 Neon Organization scope guard plan`, push it, require a
  second exact-SHA Runnable UI success, run final range/per-commit/history/
  evidence/tracked-archive scans, prove clean synchronized refs, move only
  M1-38 task-owned temporary files recoverably to Trash, and continue directly
  to M1-39.
