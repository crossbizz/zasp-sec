# M1-22 SecurityEvent Envelope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the canonical versioned, scoped SecurityEvent value with
closed source, time, evidence, and correlation fields.

**Architecture:** Add one dependency-free Go package that composes existing
reviewed domain and observability values. It defines no transport, parser,
adapter, storage, or external I/O.

**Tech Stack:** Go standard library, existing platform `domain` and
`observability` packages, Vitest repository contracts, npm root command wiring.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED before its
  production or source edit.
- Version is exactly 1; unknown versions fail closed.
- Scope is exact Organization/Workspace/Environment product scope.
- Source is one closed catalog value: runtime gateway, OTLP, Tetragon, or
  Attack Lab.
- Time is nonzero canonical UTC millisecond precision.
- Evidence and product/trace/span correlation use existing typed reviewed
  values. Raw evidence, payloads, prompts, tool arguments, secrets, arbitrary
  metadata, and vendor IDs are not envelope fields.
- There is no parser, OpenAPI, queue, archive, index, graph, SDK, exporter,
  network, credential, environment, filesystem, database, Docker, provider,
  clock, random, or shared-resource I/O.
- M1-23 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.

---

### Task 1: Start M1-22 with a repository contract

**Files:**

- Create: `app/quality/security-event-envelope-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current aggregate status fixtures under `app/quality`
- Create ignored task report and append-only progress ledger under
  `.superpowers/sdd/2026-08-16-m1-22-security-event-envelope-implementation-plan/`

- [x] **Step 1: Write source/design/status assertions and capture RED**

  Bind the source M1-22 section, prerequisite M1-21, successor M1-23, PRD
  Organization scope, runtime flow, design fields/catalogs, exact blockers, and
  expected active arithmetic. Require overall `673/1/51/3` and M1
  `68/40/1/27/0`. The focused RED must fail only stale README/tracker state.

  RED was 1 intended failure and 1 pass, solely at stale M1-22 status.

- [x] **Step 2: Move only M1-22 to In progress**

  Update README, tracker, and only the current aggregate fixtures. Keep M1-21
  Complete, M1-23 Pending, and all three blockers unchanged.

  Only M1-22 is active at overall `673/1/51/3` and M1 `68/40/1/27/0`.

- [x] **Step 3: Verify focused and complete quality GREEN**

  ```bash
  npx vitest run app/quality/security-event-envelope-contract.test.ts
  npx vitest run app/quality
  git diff --check
  ```

  GREEN is 2/2 focused and 55 quality files/245 tests; whitespace passes.

- [x] **Step 4: Record, scan, and commit**

  ```bash
  git commit -m "docs: start M1-22 SecurityEvent envelope"
  ```

---

### Task 2: Implement the closed event value tests-first

**Files:**

- Create first: `services/platform/securityevent/securityevent_test.go`
- Create after compiler RED: `services/platform/securityevent/securityevent.go`
- Modify this plan; append ignored task/progress evidence

**Public API:**

```go
type Version uint8
const Version1 Version = 1

type Source string
const (
    SourceRuntimeGateway Source = "runtime_gateway"
    SourceOTLP Source = "otlp"
    SourceTetragon Source = "tetragon"
    SourceAttackLab Source = "attack_lab"
)

type SecurityEvent struct {
    Version Version
    Scope domain.Scope
    Source Source
    Time time.Time
    Evidence domain.EvidenceRef
    Correlation observability.Correlation
}

func New(Version, domain.Scope, Source, time.Time, domain.EvidenceRef, observability.Correlation) (SecurityEvent, error)
func (SecurityEvent) Validate() error
```

- [x] **Step 1: Write exact happy-path tests and capture compiler RED**

  Construct distinct canonical scope IDs, evidence ID, product correlation ID,
  trace/span IDs, exact source, and `2026-08-16T09:30:00.123Z`. Require the
  exact comparable value and `Validate()` success. Run:

  ```bash
  go test -C services/platform ./securityevent
  ```

  The RED must name only absent public symbols before production exists.

  RED named only the absent `New`, `Version1`, `SecurityEvent`, `Source`, and
  four source constants before any production file existed.

- [x] **Step 2: Implement minimal happy-path GREEN**

  Add `ErrEvent = errors.New("security event rejected")`. Construct the exact
  value, validate it, and return zero plus the sentinel for rejection.

  Exact construction and all four catalog sources passed.

- [x] **Step 3: Add adversarial RED/GREEN coverage**

  Reject zero and unknown versions; zero/forged/duplicate scope; zero/unknown
  source; zero/local/fixed-offset/sub-millisecond time; zero/forged evidence;
  zero/malformed correlation; and every partial direct state. Prove fixed error
  text, exact immutability/comparability, and concurrent race safety.

  Behavioral RED proved `time.Time.Equal` incorrectly admitted hidden
  monotonic state. GREEN uses exact comparable representation equality and
  rejects all malformed construction and direct-state cases.

- [x] **Step 4: Run stability, platform, and coverage gates**

  ```bash
  for run in 1 2 3 4 5 6; do go test -C services/platform -race -count=1 ./securityevent; done
  go test -C services/platform -count=100 ./securityevent
  go test -C services/platform -race -count=1 ./...
  go test -C services/platform -coverprofile=/tmp/m1-22-cover.out ./securityevent
  go -C services/platform tool cover -func=/tmp/m1-22-cover.out
  go -C services/platform mod tidy -diff
  go -C services/platform mod verify
  go -C services/platform vet ./...
  ```

  Require 100% production statement coverage.

  Six race runs, 100 repetitions, full platform race, tidy-diff, module
  verification, vet, and 100% statement coverage all passed.

- [x] **Step 5: Record, scan, and commit**

  ```bash
  git commit -m "feat: add canonical SecurityEvent envelope"
  ```

---

### Task 3: Expose the hermetic root contract

**Files:** `package.json`, `README.md`, repository contract, this plan, ignored
task/progress evidence.

- [x] **Step 1: Add missing root/docs assertions and capture RED**

  Require exact script
  `go test -C services/platform -race -count=1 ./securityevent`, the six
  envelope fields, exact source catalog, version/time/evidence/correlation
  boundaries, no-I/O statement, and M1-23 Pending.

  RED was 2 intended failures and 2 passes, solely at the absent root command
  and README section.

- [x] **Step 2: Add only the root script and README boundary**

  Do not add OpenAPI, JSON, transport, adapter, storage, or provider behavior.

  The root race command and exact six-field documentation boundary are present.

- [x] **Step 3: Run root, focused, full pinned, build, audit, and diff gates**

  ```bash
  npm run securityevent:test
  npx vitest run app/quality/security-event-envelope-contract.test.ts
  npm run verify
  npm run build:repo
  npm audit --omit=dev
  git diff --check
  ```

  Root race and 4/4 focused passed. Pinned verification passed 59 files/267
  tests plus typecheck, lint, and production build; all eight repository build
  targets, zero-vulnerability production audit, and whitespace passed.

- [x] **Step 4: Record, scan, and commit**

  ```bash
  git commit -m "docs: expose SecurityEvent envelope"
  ```

---

### Task 4: Review the complete M1-22 range

- [x] **Step 1: Perform an exact whole-range read-only review**

  Review source, PRD, M1-21 dependency, design, plan, implementation, tests,
  docs, root wiring, status arithmetic, typed identity integrity, time
  canonicalization, direct states, concurrency, privacy, and no-I/O authority.

  The exact `e3165be..8c88f86` range received independent read-only review.

- [x] **Step 2: Reproduce every valid finding tests-first**

  Add the smallest tests-only RED before each production fix. If no finding
  survives, record Critical 0, Important 0, Minor 0 without manufacturing work.

  Review found two Minor repository-contract gaps. Mutation RED was 2/6 for a
  duplicate active/Complete row and README command drift; re-review found the
  initial substring assertion admitted a suffix alias, reproduced at 1/6.
  Exact status-section and complete command-line assertions closed all three
  cases in separate commit `6e879a5`.

- [x] **Step 3: Repeat affected and full gates after separate fixes**

  Finish at zero findings and all focused/platform/root/repository/audit/scan
  gates green.

  Final re-review is Critical 0, Important 0, Minor 0, Ready Yes. Focused is
  6/6; pinned verification is 59 files/269 tests plus typecheck/lint/build;
  full platform race/tidy/verify/vet, 100% package coverage, production audit,
  whitespace, and staged secret scans passed.

- [x] **Step 4: Record the plan-only final review commit**

  ```bash
  git commit -m "docs: record M1-22 review"
  ```

---

### Task 5: Complete, push, and close M1-22

- [x] **Step 1: Change only completion assertions and capture RED**

  Require exactly one M1-22 Complete row, no active source task, M1-21
  Complete, M1-23 absent, unchanged blockers, overall `673/0/52/3`, and M1
  `68/40/0/28/0`. The RED must be only stale status sources.

  RED was 1 intended failure and 5 passes, solely at stale README/tracker state.

- [x] **Step 2: Move only M1-22 to Complete and run final gates**

  Repeat six race cycles, 100 repetitions, full platform race/tidy/verify/vet,
  100% coverage, root and pinned repository verification, all build targets,
  production audit, formatting, and staged/history/evidence secret scans.

  Only M1-22 moved to Complete at `673/0/52/3` overall and
  `68/40/0/28/0` for M1. Six race runs, 100 repetitions, full platform
  race/tidy/verify/vet, 100% coverage, root race, 59 files/269 tests,
  typecheck/lint/build, eight repository targets, audit zero, and whitespace
  passed before the completion commit.

- [x] **Step 3: Commit, push, and require exact completion-SHA CI success**

  ```bash
  git commit -m "docs: complete M1-22 SecurityEvent envelope"
  git push origin codex/zasp-implementation
  ```

  Prove local/upstream/remote equality and terminal Runnable UI success.

  Completion commit `8b88c345cc8ece019c1193a605f350e32d72446a`
  was pushed with exact local/upstream/remote equality. Runnable UI run
  `31939659916`, job `95146887854`, completed successfully for that exact SHA.

- [x] **Step 4: Commit/push the plan-only closure and require exact CI success**

  ```bash
  git commit -m "docs: close M1-22 SecurityEvent envelope"
  git push origin codex/zasp-implementation
  ```

  Record both run/job IDs, scan final history/evidence, prove clean synchronized
  state, and leave M1-23 Pending.

  This plan-only closure records the completed implementation, zero-finding
  review, completion-SHA CI success, final counts, and unchanged successor and
  blocker boundaries. Closure-SHA CI and final synchronization evidence are
  appended to ignored reports after the remote run reaches terminal success.
