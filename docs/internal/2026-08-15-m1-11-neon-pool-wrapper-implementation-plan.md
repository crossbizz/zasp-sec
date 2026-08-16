# M1-11 Neon Pool Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dependency-free product pool wrapper with bounded queries,
health statistics, and clean close semantics, then prove it through the existing
strict Neon/pgx boundary.

**Architecture:** `services/platform/database` owns a driver-neutral lifecycle
and telemetry contract. `proofs/neon-pooled` adapts its already validated pgx
pool and runs the live contention proof without moving credentials, URLs, TLS,
or provider errors into the product package.

**Tech Stack:** Go 1.25 source compatibility, Go 1.26.5 toolchain, standard
library synchronization/context primitives, pgxpool only in the proof module,
Vitest repository contracts, pinned Node 22.23.1/npm 10.9.8.

## Global Constraints

- M1-10 must remain Complete; M1-12 remains Pending until this plan closes.
- Overall start counts are `684/1/40/3`; M1 start counts are
  `68/51/1/16/0`.
- Product errors never expose SQL, arguments, DSNs, provider messages, or panic
  values.
- Query and health timeouts are positive and at most 30 seconds.
- Product code remains dependency-free and imports no pgx type.
- The live proof reads only `DATABASE_URL`, performs no branch/schema mutation,
  and emits one fixed line.
- M0-09, M0-18, and M0-19 stay Blocked; R-03 stays incomplete; R-11 stays Not
  run.

---

### Task 1: Start M1-11

**Files:**
- Create: `app/quality/neon-pool-wrapper-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: existing aggregate-count contract tests under `app/quality/`

**Interfaces:**
- Consumes: authoritative M1-11 source, committed design, this plan, completed
  M1-10 tracker row.
- Produces: unique M1-11 In-progress row and exact `684/1/40/3` contract.

- [ ] **Step 1: Write the status and source contract before changing docs**

```ts
expect(sourceSection).toContain("pooled application DB wrapper");
expect(sourceSection).toContain("query timeout and health stats");
expect(readme).toContain("M1-11 is In progress");
expect(m1Row).toEqual(["M1", "68", "51", "1", "16", "0"]);
```

- [ ] **Step 2: Run the focused test and record the Pending-state RED**

Run: `PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npx vitest run app/quality/neon-pool-wrapper-contract.test.ts`

Expected: FAIL only because M1-11 is not yet In progress and the README section
does not exist.

- [ ] **Step 3: Move only M1-11 to In progress**

Update the tracker to `684/1/40/3`, M1 to `68/51/1/16/0`, add exactly one
M1-11 row, document the driver-neutral boundary, and mechanically update every
aggregate-count contract while preserving historical fixtures.

- [ ] **Step 4: Run focused and full pinned repository verification**

Run the focused contract, `npm run verify`, `npm audit --omit=dev`, and
`git diff --check` under pinned Node.

- [ ] **Step 5: Scan and commit the start transition**

```bash
git commit -m "docs: start M1-11 Neon pool wrapper"
```

---

### Task 2: Implement the dependency-free pool wrapper

**Files:**
- Create: `services/platform/database/pool_test.go`
- Create: `services/platform/database/pool.go`

**Interfaces:**
- Consumes: standard `context`, `sync`, `time`, `unicode/utf8`.
- Produces:
  `New(Driver, Config) (*Pool, error)`,
  `(*Pool).QueryRow(context.Context, string, []any, ...any) error`,
  `(*Pool).Health(context.Context) (Stats, error)`,
  `(*Pool).Stats() (Stats, error)`, and
  `(*Pool).Close() error`.

- [ ] **Step 1: Add missing-symbol tests for the public contract**

```go
type Row interface { Scan(...any) error }
type Driver interface {
    QueryRow(context.Context, string, ...any) Row
    Ping(context.Context) error
    Stats() DriverStats
    Close()
}
```

Test valid construction/query/stats/health/close first, then nil and typed-nil
drivers, invalid timeouts, invalid statement/destinations, caller cancellation,
timeout, driver/scan errors and panics, malformed stats, close ordering,
concurrent close, idempotency, and post-close calls.

- [ ] **Step 2: Run the focused Go test and record compiler RED**

Run: `go test -C services/platform ./database -count=1`

Expected: compile failure only on absent package symbols.

- [ ] **Step 3: Implement fixed types and validation**

Use fixed exported errors `ErrConfiguration`, `ErrQuery`, `ErrHealth`,
`ErrStats`, `ErrClosed`, and `ErrClose`. Validate statements as trimmed,
nonempty, UTF-8, NUL-free values no larger than 64 KiB. Validate stats with:

```go
stats.InUse >= 0 && stats.Idle >= 0 && stats.Constructing >= 0 &&
stats.Total == stats.InUse+stats.Idle+stats.Constructing &&
stats.Total <= stats.Maximum && stats.WaitCount >= 0 &&
stats.CanceledWaitCount >= 0 && stats.WaitDuration >= 0
```

- [ ] **Step 4: Implement timeout and lifecycle behavior**

Hold an `RWMutex` read lock through query+scan and health+snapshot. Use
`context.WithTimeout` inside each call. `Close` takes the write lock, calls the
driver once, validates an exact zero-connection final snapshot, stores its
stable result, and rejects later work. Recover driver panics only as fixed
errors.

- [ ] **Step 5: Run focused race and six stability passes**

Run: `go test -C services/platform -race -count=1 ./database`

Then repeat `go test -C services/platform ./database -count=1` six times and
run the complete platform race/tidy/verify/vet gates.

- [ ] **Step 6: Commit the product package**

```bash
git commit -m "feat: add bounded application pool wrapper"
```

---

### Task 3: Adapt pgx and prove live contention

**Files:**
- Create: `proofs/neon-pooled/product_pool.go`
- Create: `proofs/neon-pooled/product_pool_test.go`
- Create: `proofs/neon-pooled/run-pool-wrapper.mjs`
- Modify: `proofs/neon-pooled/main.go`
- Modify: `proofs/neon-pooled/go.mod`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/neon-pool-wrapper-contract.test.ts`

**Interfaces:**
- Consumes: `database.Driver`, the retained validated pgx connection, and the
  existing pgxpool module dependency.
- Produces: proof mode `pool-wrapper`, root commands `db:pool:test` and
  `db:pool:run`, and the exact fixed success summary.

- [ ] **Step 1: Write adapter and runner tests before implementation**

Require exact pgx stats mapping, fixed pool configuration with two maximum
connections, ten successful reads, a snapshot observing both wait and in-use,
zero in-use after readers finish, zero total after close, fixed failure output,
and unchanged legacy M0-04/M1-10 modes.

- [ ] **Step 2: Run focused tests and capture the missing adapter/mode RED**

Run: `go test -C proofs/neon-pooled -run 'ProductPool|Main' -count=1`

- [ ] **Step 3: Implement the narrow adapter and proof mode**

Map pgxpool `AcquiredConns`, `IdleConns`, `ConstructingConns`, `TotalConns`,
`MaxConns`, `EmptyAcquireCount`, `CanceledAcquireCount`, and
`EmptyAcquireWaitTime` into `database.DriverStats`. Poll only product stats
under the proof deadline until contention is observed.

- [ ] **Step 4: Add stable root commands and documentation**

```json
"db:pool:test": "go test -C services/platform -race -count=1 ./database && go test -C proofs/neon-pooled -race -count=1 ./...",
"db:pool:run": "node --env-file=.env proofs/neon-pooled/run-pool-wrapper.mjs"
```

- [ ] **Step 5: Run hermetic gates, then the exact live command**

Run `npm run db:pool:test`, all dependent Go gates, and pinned repository
verification. Then run `npm run db:pool:run` through the ignored dotenv
boundary and require exactly:

`Neon pool wrapper passed: reads=10 waited=true in_use=true acquired=0 closed=true.`

- [ ] **Step 6: Scan and commit the adapter/proof**

```bash
git commit -m "feat: prove bounded Neon application pool"
```

---

### Task 4: Review, complete, push, and close

**Files:**
- Modify: product/proof tests and code only for confirmed review findings.
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: aggregate quality contracts.
- Modify: this plan only when the exact completion/close runs succeed.

**Interfaces:**
- Consumes: exact design-to-head diff, live evidence, all gate results.
- Produces: zero-finding review, M1-11 Complete, exact-SHA CI, closed plan.

- [ ] **Step 1: Request independent read-only review**

Audit timeout scope, context lifetime through scan, stat arithmetic, panic and
error secrecy, close/query races, adapter mapping, live contention evidence,
and regression preservation. Fix every confirmed issue tests-first and rerun
affected live/local gates until review reports zero findings.

- [ ] **Step 2: Capture completion RED and move only M1-11 to Complete**

Change counts to `684/0/41/3` and M1 `68/51/0/17/0`; keep M1-12 Pending and
all blockers unchanged.

- [ ] **Step 3: Run final gates and scans**

Run six focused passes, every affected Go race/tidy/verify/vet gate, the
eight-target build, pinned `npm run verify`, production audit, diff check, and
pinned redacted Gitleaks staged/exact/history/evidence scans.

- [ ] **Step 4: Commit, push, and watch exact-SHA CI**

```bash
git commit -m "docs: complete M1-11 Neon pool wrapper"
git push origin codex/zasp-implementation
```

Require Runnable UI success for the exact completion SHA.

- [ ] **Step 5: Close the plan and verify the close SHA**

Mark this checklist complete, record run/job IDs in ignored evidence, commit
`docs: close M1-11 Neon pool wrapper`, push, and require exact-SHA Runnable UI
success before starting M1-12.
