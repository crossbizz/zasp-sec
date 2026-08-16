# M1-28a Shared Health Handler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one dependency-free shared Go handler for exact service liveness,
readiness, version, and bounded metrics responses.

**Architecture:** A standalone `services/health` Go module exposes a concrete
concurrency-safe `http.Handler`. It owns only validated service/build metadata
and an atomic readiness bit; later M1-28b through M1-28d tasks own command
wiring, listeners, dependency checks, and shutdown.

**Tech Stack:** Go 1.25.0 standard library, `net/http`, `httptest`, atomics,
Node.js 22.23.1, npm 10.9.8, Vitest 4.1.10.

## Global Constraints

- Work only on M1-28a. M1-28b remains Pending.
- M0-09, M0-18, and M0-19 remain Blocked.
- The package lives in standalone module `services/health` with import path
  `github.com/zasp-ai/zasp-sec/services/health`.
- Add no Go or npm dependency and do not change any lockfile.
- Open no listener and perform no file, environment, provider, credential,
  subprocess, database, Docker, or network I/O.
- Expose only exact `/healthz`, `/readyz`, `/version`, and `/metrics` routes.
- Readiness starts false and changes only through atomic `SetReady`.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.
- Do not mark M1-28a Complete before whole-range review is Critical 0,
  Important 0, Minor 0, Ready Yes.
- Completion requires exact-SHA Runnable UI success for both the completion
  commit and the plan-only closure commit.

---

### Task 1: Start M1-28a with an exact status contract

**Files:**
- Create: `app/quality/shared-health-handler-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`

**Interfaces:**
- Consumes: the M1-28a source row and M1-27 Complete state.
- Produces: exact M1-28a In-progress status at overall `667/1/57/3` and M1
  `68/34/1/33/0`.

- [x] **Step 1: Write the failing status/source/design contract**

Create a Vitest contract that parses tracker tables structurally and asserts:

```ts
expect(active.filter(([task]) => task === "M1-28a")).toHaveLength(1);
expect(complete.filter(([task]) => task === "M1-28a")).toHaveLength(0);
expect(complete.filter(([task]) => task === "M1-27")).toHaveLength(1);
expect([...active, ...complete].filter(([task]) => task === "M1-28b")).toHaveLength(0);
expect(tracker).toContain("`667/1/57/3`");
expect(milestoneM1).toEqual(["M1", "68", "34", "1", "33", "0"]);
expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
expect(readme).toContain("M1-28a is In progress");
expect(readme).toContain("M1-28b remains Pending");
```

Bind the source row's dependency, deliverable, and verification sentence plus
the design's standalone module, four exact paths, atomic readiness, no-listener
boundary, and final arithmetic.

- [x] **Step 2: Run the focused test and witness RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/shared-health-handler-contract.test.ts
```

Expected: the source/design case passes and only stale README/tracker assertions
fail.

- [x] **Step 3: Move only M1-28a to In progress**

Update tracker arithmetic to `667/1/57/3` overall and `68/34/1/33/0` for M1.
Add exactly one M1-28a In-progress row. Preserve M1-27 in Complete, M1-28b
outside active/complete, and the three blocker rows. Update README with M1-28a
In progress and M1-28b Pending.

- [x] **Step 4: Run focused and complete quality GREEN**

Run the focused contract, the M1-27 contract, and all `app/quality` tests under
pinned Node. Require zero failures and exact 728-task arithmetic.

- [x] **Step 5: Scan and commit the start transition**

Run `git diff --check` and a pinned redacted Gitleaks staged scan. Commit the
contract, README, tracker, and mechanical aggregate fixtures as:

```text
docs: start M1-28a shared health handler
```

---

### Task 2: Implement the shared handler module

**Files:**
- Create: `services/health/go.mod`
- Create: `services/health/health_test.go`
- Create: `services/health/health.go`
- Modify: `package.json`
- Modify: `app/quality/shared-health-handler-contract.test.ts`

**Interfaces:**
- Produces: `New(Config) (*Handler, error)`, `(*Handler).SetReady(bool)`, and
  `(*Handler).ServeHTTP(http.ResponseWriter, *http.Request)`.
- Produces: `LivenessPath`, `ReadinessPath`, `VersionPath`, `MetricsPath`, and
  `ErrInvalidConfig`.
- Produces: root command `npm run health:test`.

- [x] **Step 1: Add the module/test boundary before production code**

Create `go.mod`:

```go
module github.com/zasp-ai/zasp-sec/services/health

go 1.25.0
```

Create `health_test.go` in package `health`. Add tests named:

```go
func TestHandlerDistinguishesLivenessReadinessVersionAndMetrics(t *testing.T)
func TestHandlerExactMethodsPathsHeadersAndHead(t *testing.T)
func TestNewRejectsInvalidConfiguration(t *testing.T)
func TestHandlerConcurrentReadiness(t *testing.T)
```

The first test must require the exact JSON bodies/statuses and the exact metrics
body from the design. The second must cover HEAD with GET-equivalent
`Content-Length`, POST 405 plus `Allow`, trailing/unknown/escaped/query paths
404, and empty rejection bodies. The invalid table must include empty,
oversized, uppercase/space/slash/double-or-edge-hyphen service names plus empty,
oversized, leading punctuation, whitespace/control/non-ASCII version values.
The concurrency test must issue requests while multiple goroutines toggle
readiness and accept only the two exact readiness projections.

- [x] **Step 2: Run the focused module test and witness compiler RED**

Run:

```bash
go test -C services/health -race -count=1 ./...
```

Expected: compile failures only for the absent production API (`New`, `Config`,
paths, and `ErrInvalidConfig`).

- [x] **Step 3: Implement strict configuration and atomic state**

Create `health.go` with:

```go
type Config struct {
    Service string
    Version string
}

type Handler struct {
    service string
    version string
    ready   atomic.Bool
}

func New(config Config) (*Handler, error)
func (handler *Handler) SetReady(ready bool)
```

Validate the exact design grammars before construction. Start readiness false.
Do not retain caller-owned collections, callbacks, writers, requests, or
configuration pointers.

- [x] **Step 4: Implement exact response routing**

Implement `ServeHTTP` using only local immutable strings and `ready.Load()`.
Reject nonempty `RawPath` or `RawQuery`; match exact paths before methods;
accept only GET/HEAD. Set exact content type, cache, nosniff, Allow when needed,
and content length before writing. HEAD writes no body. Use the exact design
JSON and Prometheus bytes, with only validated service/version substitutions.

- [x] **Step 5: Run focused GREEN and six race passes**

Run the focused test once, then six consecutive times:

```bash
for run in 1 2 3 4 5 6; do
  go test -C services/health -race -count=1 ./...
done
```

Require every run to pass with no race, nondeterministic body, or goroutine.

- [x] **Step 6: Wire the root hermetic command tests-first**

Extend the quality contract to require:

```ts
expect(packageJson.scripts?.["health:test"]).toBe(
  "go test -C services/health -race -count=1 ./...",
);
```

Run it before changing `package.json` and witness the missing-script RED. Add
the exact command without changing `verify`, dependencies, or any lockfile.

- [x] **Step 7: Run module and repository gates, then commit**

Run `npm run health:test`, `go mod tidy -diff`, `go mod verify`, `go vet ./...`
inside `services/health`, full pinned `npm run verify`, `npm run build:repo`,
production/development audits, syntax/diff checks, and package-lock non-change.
Run pinned staged/history/evidence secret scans. Commit the exact module,
command, and contract as:

```text
feat: add shared Go health handler
```

---

### Task 3: Document and independently review M1-28a

**Files:**
- Modify: `README.md`
- Modify: `app/quality/shared-health-handler-contract.test.ts`
- Modify: this implementation plan
- Create ignored evidence under
  `.superpowers/sdd/2026-08-16-m1-28a-shared-health-handler-implementation-plan/`

**Interfaces:**
- Produces: documented handler semantics, exact root command, deferred wiring,
  and explicit internal-endpoint boundary.

- [x] **Step 1: Write the README contract before prose**

Require one extracted README section to contain the four exact paths, initial
not-ready state, atomic `SetReady`, exact standalone command, no-listener/no-
dependency-I/O boundary, M1-28a In progress, and M1-28b Pending.

- [x] **Step 2: Witness documentation RED, write prose, and reach GREEN**

Run the focused contract before editing README and require only the absent
section to fail. Add bounded prose and rerun the M1-27/M1-28a contracts.

- [x] **Step 3: Review the whole design-to-head range**

Audit every changed file against the source row and design. Re-run invalid
config, exact route/method/query/raw-path, HEAD/body/length, readiness
transition, concurrent race, metrics-label, module-isolation, root command,
lockfile non-change, and status cases. Record Critical/Important/Minor counts
and Ready Yes/No.

- [x] **Step 4: Fix every valid finding tests-first**

For each finding, add a focused failing case, witness RED, make the minimal
production change, and rerun focused/adjacent/full gates. Repeat until review is
Critical 0, Important 0, Minor 0, Ready Yes.

- [x] **Step 5: Record and commit review evidence**

Run six final focused race passes, all module/service/repository gates, audits,
syntax/diff/lockfile checks, and redacted staged/history/evidence scans. Update
ignored reports and commit tracked README/contract/plan changes as:

```text
docs: record M1-28a shared health review
```

---

### Task 4: Complete, push, and close M1-28a

**Files:**
- Modify: `README.md`
- Modify: `app/quality/shared-health-handler-contract.test.ts`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: this implementation plan
- Update ignored task and authoritative reports.

- [x] **Step 1: Capture completion status RED**

Change only contract expectations to `667/0/58/3` overall and
`68/34/0/34/0` for M1, M1-28a exactly once in Complete and absent from active,
and M1-28b Pending. Run before README/tracker changes and require only stale
status assertions to fail.

- [x] **Step 2: Move only M1-28a to Complete and run final gates/scans**

Update README/tracker and exact aggregate fixtures. Run six focused race and
completion passes, module/service/full pinned verification, repository builds,
audits, syntax/diff/lockfile checks, and redacted staged/history/evidence scans.
Commit as:

```text
docs: complete M1-28a shared health handler
```

- [x] **Step 3: Push completion and require exact-SHA Runnable UI success**

Push `codex/zasp-implementation`, locate the Runnable UI run whose `headSha`
equals the completion commit, and wait for its job to finish successfully.
Record run ID, job ID, URL, and exact SHA.

- [x] **Step 4: Push the plan-only closure and require exact-SHA CI success**

Mark every plan checkbox complete, commit only this plan as
`docs: close M1-28a shared health handler`, push, and require a second
successful Runnable UI run for that exact SHA. Finish with local/upstream/origin
equality, clean tracked state, all-history/evidence scans, M1-28b Pending,
overall `667/0/58/3`, and M1 `68/34/0/34/0`.
