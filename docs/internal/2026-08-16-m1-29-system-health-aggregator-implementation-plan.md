# M1-29 System Health Aggregator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one strict shared Go model that represents component health and
aggregates required and optional components without hiding degradation.

**Architecture:** Extend the dependency-free `services/health` module with a
pure comparable `Component` value and deterministic `Aggregate` function. Keep
HTTP probes, dependency polling, storage, configuration, and deployment
behavior unchanged; the existing root health race gate automatically covers
the new model.

**Tech Stack:** Go 1.25.0 standard library, Node 22.23.1, npm 10.9.8, Vitest
4.1.10, Gitleaks 8.30.1, GitHub Actions Runnable UI.

## Global Constraints

- Work only on M1-29. M1-30a remains Pending.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Add no Go or npm dependency and change no lockfile.
- Keep the public product OpenAPI, internal health OpenAPI, generated client,
  four command listeners, and `/healthz`/`/readyz` behavior unchanged.
- Perform no file, environment, clock, provider, credential, subprocess,
  database, Docker, or network I/O.
- Accept only exact status and requirement constants, strict product-owned
  names/reason codes, and canonical UTC millisecond last-success values.
- Optional failures must remain visible as Degraded; required Unavailable must
  make the aggregate Unavailable; invalid input must fail closed.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.
- Do not mark M1-29 Complete before whole-range review is Critical 0,
  Important 0, Minor 0, Ready Yes.
- Completion requires exact-SHA Runnable UI success for both the completion
  commit and the plan-only closure commit.

---

### Task 1: Start M1-29 with an exact repository contract

**Files:**
- Create: `app/quality/system-health-aggregator-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current aggregate/status contract fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-29 source row, committed design, and M1-28 Complete state.
- Produces: exact M1-29 In-progress status at overall `662/1/62/3` and M1
  `68/29/1/38/0`.

- [ ] **Step 1: Write the failing source/design/status contract**

Create a Vitest contract that parses tracker tables structurally and asserts:

```ts
expect(sourceSection).toContain("Depends on: `M1-28`");
expect(sourceSection).toContain(
  "Define component status Healthy/Degraded/Unavailable with reason and last success",
);
expect(sourceSection).toContain(
  "Aggregation test handles required vs optional dependencies",
);
expect(active.filter(([task]) => task === "M1-29")).toHaveLength(1);
expect(complete.filter(([task]) => task === "M1-29")).toHaveLength(0);
expect(complete.filter(([task]) => task === "M1-28")).toHaveLength(1);
expect([...active, ...complete].filter(([task]) => task === "M1-30a")).toHaveLength(0);
expect(tracker).toContain("`662/1/62/3`");
expect(milestoneM1).toEqual(["M1", "68", "29", "1", "38", "0"]);
expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
expect(readmeSection).toContain("M1-29 is In progress");
expect(readmeSection).toContain("M1-30a remains Pending");
```

Bind the design's selected shared-module architecture, exact public API,
component invariants, aggregation precedence, no-I/O boundary, and start/final
arithmetic. Reject duplicate M1-29 rows, concurrent M1-30a activation, an
M1-29 Complete row, changed blockers, and aggregate-count drift.

- [ ] **Step 2: Run the focused test and witness stale-status RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/system-health-aggregator-contract.test.ts
```

Expected: source/design assertions pass and only stale README/tracker/package
boundary assertions fail.

- [ ] **Step 3: Move only M1-29 to In progress**

Update overall arithmetic from `663/0/62/3` to `662/1/62/3` and M1 from
`68/30/0/38/0` to `68/29/1/38/0`. Add exactly one M1-29 In-progress row.
Preserve M1-28 in Complete, keep M1-30a outside active/complete, and retain the
three exact blocker rows. Add the README M1-29 boundary without claiming the
model is implemented.

- [ ] **Step 4: Run focused and complete quality GREEN**

Run the focused contract and all `app/quality` tests under pinned Node. Require
exact 728-task arithmetic and zero weakened historical fixtures.

- [ ] **Step 5: Scan and commit the start transition**

Run `git diff --check` and pinned redacted Gitleaks scans over staged content
and ignored task evidence. Commit only the status contract, README, tracker,
and mechanical current-state fixtures as:

```text
docs: start M1-29 health aggregation
```

---

### Task 2: Implement the strict component value

**Files:**
- Create: `services/health/aggregate_test.go`
- Create: `services/health/aggregate.go`

**Interfaces:**
- Produces: `Status`, `Requirement`, `Component`, `ErrInvalidComponent`, and
  `NewComponent(...) (Component, error)` plus `Component.Validate() error`.
- Consumes: the existing package-private service-name grammar from
  `services/health/health.go` without changing its accepted values.

- [ ] **Step 1: Write construction and direct-state tests before production**

Add these tests in package `health`:

```go
func TestComponentConstructionAndValidation(t *testing.T)
func TestComponentRejectsInvalidState(t *testing.T)
func TestComponentIsComparableAndConcurrent(t *testing.T)
```

The valid table must cover required/optional, all three statuses, zero
last-success only for nonhealthy never-success state, and canonical UTC
millisecond timestamps. The invalid table must cover zero/unknown constants,
invalid names, Healthy with a reason or zero time, nonhealthy without a reason,
reason length/grammar/control/non-ASCII failures, local/fixed-offset/sub-
millisecond/monotonic/non-four-digit times, and every invalid direct struct
state. Verify the returned error is exactly `ErrInvalidComponent` and the
returned component is zero.

- [ ] **Step 2: Run the focused module test and witness compiler RED**

Run:

```bash
go test -C services/health -race -count=1 -run '^TestComponent'
```

Expected: compile failures only for absent `Status`, `Requirement`,
`Component`, constants, constructor, and sentinel.

- [ ] **Step 3: Add the exact public types and constructor**

Create `aggregate.go` with the API from the design:

```go
type Status string
type Requirement string

type Component struct {
    Name        string
    Requirement Requirement
    Status      Status
    Reason      string
    LastSuccess time.Time
}

func NewComponent(
    name string,
    requirement Requirement,
    status Status,
    reason string,
    lastSuccess time.Time,
) (Component, error)
```

Construct the value, call `Validate`, and return `Component{}` plus the exact
sentinel on failure. Do not retain pointers or collections.

- [ ] **Step 4: Implement exact validation**

Reuse `validService` for `Name`. Add closed switches for requirement/status,
a 1-64 lowercase snake-case `validReason`, and a package-local canonical time
validator using layout `2006-01-02T15:04:05.000Z`. Healthy requires empty
reason and nonzero canonical time. Degraded/Unavailable require a reason and
accept zero or canonical time.

- [ ] **Step 5: Run focused GREEN and six race passes**

Run the focused tests once, then six consecutive full module race passes:

```bash
for run in 1 2 3 4 5 6; do
  go test -C services/health -race -count=1 ./...
done
```

Require all passes with deterministic values and no race.

---

### Task 3: Implement fail-closed aggregation

**Files:**
- Modify: `services/health/aggregate_test.go`
- Modify: `services/health/aggregate.go`

**Interfaces:**
- Consumes: validated `[]Component` values.
- Produces: `ErrInvalidAggregation` and
  `Aggregate(components []Component) (Status, error)`.

- [ ] **Step 1: Write the aggregation matrix before production**

Add:

```go
func TestAggregateRequiredOptionalPrecedence(t *testing.T)
func TestAggregateRejectsInvalidSets(t *testing.T)
func TestAggregateDoesNotMutateInputAndIsConcurrent(t *testing.T)
```

The matrix must prove all healthy => Healthy; required Degraded => Degraded;
optional Degraded => Degraded; optional Unavailable => Degraded; required
Unavailable => Unavailable; and required Unavailable wins regardless of other
ordering. Invalid cases must cover nil/empty, no required component, duplicate
names in any order, and each invalid direct component. Seed input-order
permutations and prove the input slice is byte/value unchanged.

- [ ] **Step 2: Run focused tests and witness compiler RED**

Run:

```bash
go test -C services/health -race -count=1 -run '^TestAggregate'
```

Expected: compile failures only for absent `Aggregate` and
`ErrInvalidAggregation`.

- [ ] **Step 3: Implement deterministic aggregation**

Validate nonempty input, every component, at least one required component, and
unique names using a local map. Track two booleans without sorting or mutating:
required Unavailable and any nonhealthy. Return Unavailable first, then
Degraded, then Healthy. On invalid input return `""` and exact
`ErrInvalidAggregation`.

- [ ] **Step 4: Run focused and full GREEN**

Run both focused groups, full module race, five additional stability passes,
`go mod tidy -diff`, `go mod verify`, and `go vet ./...` in `services/health`.

---

### Task 4: Document and verify the integrated model

**Files:**
- Modify: `README.md`
- Modify: `app/quality/system-health-aggregator-contract.test.ts`
- Modify: ignored Task 4 report and append-only progress ledgers

**Interfaces:**
- Consumes: the exact public Go API and existing `health:contract:test` script.
- Produces: a user-visible model boundary and root regression evidence without
  a new command or dependency.

- [ ] **Step 1: Extend the quality contract before README changes**

Require an exact `## System health aggregation model` section containing
`services/health`, the three statuses, required/optional precedence,
product-owned reason codes, canonical last-success behavior, the statement
that readiness is unchanged, `npm run health:contract:test`, M1-29 In progress,
and M1-30a Pending. Require the existing root health command string to remain
unchanged and include `go test -C services/health -race -count=1 ./...`.

- [ ] **Step 2: Witness README RED, then add the exact section**

Run the focused Vitest contract before editing README. Add only the documented
model and command boundary; do not claim dependency polling or HTTP exposure.

- [ ] **Step 3: Run integrated health and repository gates**

Run six `npm run health:contract:test` passes, all four relevant Go module
tidy/verify/vet gates, focused Vitest, and complete `app/quality`.

- [ ] **Step 4: Run final local gates and commit implementation atomically**

Under pinned Node run `npm run verify`, eight `npm run build:repo` passes,
dependency tests plus CLI, `npm audit --omit=dev`, `git diff --check`, and
pinned redacted Gitleaks staged/evidence/history scans. Commit the model,
tests, README, and quality contract as:

```text
feat: add system health aggregation model
```

---

### Task 5: Complete independent review

**Files:**
- Modify only tests-first fixes accepted from review.
- Append: ignored Task 5 report and progress ledgers.

**Interfaces:**
- Consumes: the exact design-to-implementation range.
- Produces: Critical 0 / Important 0 / Minor 0 / Ready Yes.

- [ ] **Step 1: Request whole-range read-only review**

Review source task, PRD degraded rules, design, plan, complete diff, public API,
validation, aggregation matrix, tests, README/status boundaries, and evidence.
Run only safe non-live gates.

- [ ] **Step 2: Resolve every finding tests-first**

For each accepted finding, add a focused test and witness RED before production
changes. Implement the smallest fix, run focused/full gates, and commit each
review wave separately without rewriting history.

- [ ] **Step 3: Repeat review to zero findings**

Do not begin completion until independent review reports Critical 0,
Important 0, Minor 0, Ready Yes on current HEAD.

---

### Task 6: Complete, ship, and close M1-29

**Files:**
- Modify: `app/quality/system-health-aggregator-contract.test.ts`
- Modify: `README.md`
- Modify: current aggregate/status contract fixtures under `app/quality/`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify last: this implementation plan's checklist only

**Interfaces:**
- Produces: M1-29 Complete at overall `662/0/63/3` and M1
  `68/29/0/39/0`; leaves M1-30a Pending.

- [ ] **Step 1: Capture stale completion RED**

Change completion expectations first and require exactly one M1-29 Complete
row, no M1-29 active row, unchanged blockers, M1-30a absent from
active/complete, README Complete wording, and exact final arithmetic. Run the
focused contract and witness only stale-state failures.

- [ ] **Step 2: Move only M1-29 to Complete**

Update tracker, README, and current aggregate fixtures mechanically while
preserving every historical-state helper. Run focused and full quality suites.

- [ ] **Step 3: Verify, scan, commit, push, and watch exact SHA**

Run final health/module/repository/dependency/audit/build/whitespace gates and
redacted staged/evidence/history scans. Commit the completion package, push,
and require Runnable UI success for that exact SHA.

- [ ] **Step 4: Close the checked plan separately**

Change only the checklist markers below in a one-file closure commit. Scan,
push, require exact-SHA Runnable UI success, and prove local/origin/upstream SHA
equality, 0/0 divergence, clean tracked tree/index, and final history/evidence
scans.

## Closure checklist

- [ ] Task 1 exact M1-29 start contract and status transition pass.
- [ ] Task 2 strict component value is tests-first GREEN.
- [ ] Task 3 required/optional aggregation is tests-first GREEN.
- [ ] Task 4 integrated docs and all local gates pass.
- [ ] Task 5 independent review is zero-finding and Ready Yes.
- [ ] Task 6 completion, exact-SHA CI, synchronization, and closure pass.
