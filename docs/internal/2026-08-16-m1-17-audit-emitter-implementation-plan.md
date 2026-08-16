# M1-17 AuditEmitter Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dependency-free, fully scoped product `AuditEmitter` whose
required actor/action/target/outcome contract passes strict fake-driver tests.

**Architecture:** `services/platform/audit` owns the canonical security
mutation, closed outcome enum, strict action grammar, exact tenant scope,
bounded one-attempt append, exact acknowledgement, and fixed errors. A narrow
provider-neutral driver is the only persistence boundary; M1-17 uses only a
hermetic fake and adds no provider implementation.

**Tech Stack:** Go 1.25 language/toolchain 1.26.5, dependency-free platform
package, Node 22.23.1/npm 10.9.8 repository contracts, Vitest, Go race detector,
and pinned Gitleaks 8.30.1.

## Global Constraints

- Design commit is `2815ab41a1eaf270f3f28c3765118ba712d93a46`.
- M1-16 remains Complete; M1-18 remains Pending throughout.
- Start counts are overall `678/1/46/3` and M1 `68/45/1/22/0`.
- Completion counts are overall `678/0/47/3` and M1 `68/45/0/23/0`.
- Product code imports no database, queue, HTTP, cloud, provider, credential,
  serialization, or event-store type and performs no retry.
- Every operation receives exact validated Organization, Workspace, and
  Environment scope.
- Actor and target are canonical nonzero `domain.ProductID` values. They may be
  equal; provider IDs and customer display text never enter the contract.
- Action is 1-127 ASCII bytes matching
  `[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*`.
- Outcome is exactly `succeeded`, `failed`, or `denied`.
- Every invalid field fails before driver I/O. Every valid append invokes the
  driver exactly once under one total timeout no greater than 30 seconds.
- Success requires an exact seven-field acknowledgement. Partial, altered,
  foreign-scope, empty, error, panic, cancellation, or timeout results fail.
- M1-17 performs no Docker, network, provider, credential, database, or
  shared-resource I/O.

---

### Task 1: Start M1-17 with an exact repository contract

**Files:**
- Create: `app/quality/audit-emitter-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Create ignored evidence under
  `.superpowers/sdd/2026-08-16-m1-17-audit-emitter-implementation-plan/`

**Interfaces:**
- Consumes: authoritative M1-17 source task, M1-16 Complete row, design commit
  `2815ab41a1eaf270f3f28c3765118ba712d93a46`, and current count contracts.
- Produces: exactly one M1-17 In-progress row and assertions that keep M1-16
  Complete, M1-18 absent, and all blocker rows unchanged.

- [x] **Step 1: Write the source/status contract before changing docs**

Create helpers that parse markdown rows by section, then assert:

```ts
expect(sourceSection).toContain("Depends on: `M1-16`");
expect(sourceSection).toContain("Define AuditEmitter interface and required mutation fields");
expect(sourceSection).toContain("rejects security mutation without actor/action/target/outcome");
expect(design).toContain("services/platform/audit");
expect(readme).toContain("M1-17 is In progress");
expect(tracker).toContain("| Pending | 678 |");
expect(tracker).toContain("| In progress | 1 |");
expect(tracker).toContain("| Complete | 46 |");
expect(tracker).toContain("| Blocked | 3 |");
expect(tracker).toContain("`678/1/46/3`");
expect(m1).toEqual(["M1", "68", "45", "1", "22", "0"]);
expect(active.map(([task]) => task)).toEqual(["M1-17"]);
expect(complete.filter(([task]) => task === "M1-16")).toHaveLength(1);
expect([...active, ...complete].filter(([task]) => task === "M1-18")).toHaveLength(0);
expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
```

- [x] **Step 2: Run the focused contract and record Pending-state RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/audit-emitter-contract.test.ts
```

Expected: only the still-Pending M1-17 status assertions fail.

- [x] **Step 3: Move only M1-17 to In progress**

Update README/tracker and every current aggregate fixture to `678/1/46/3`
overall and M1 `68/45/1/22/0`. Add exactly one M1-17 In-progress row dated
August 16, 2026. Preserve all historical fixtures, M1-16 Complete, M1-18
Pending, and the three blocked rows.

- [x] **Step 4: Run focused/full pinned gates, scan, and commit**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
git commit -m "docs: start M1-17 audit emitter"
```

---

### Task 2: Implement the dependency-free AuditEmitter

**Files:**
- Create: `services/platform/audit/emitter_test.go`
- Create: `services/platform/audit/emitter.go`

**Interfaces:**
- Consumes: `context.Context`, `domain.Scope`, `domain.ProductID`, and
  `time.Duration`.
- Produces: `AuditEmitter`, `Emitter`, `Driver`, `Config`, `Mutation`,
  `Outcome`, `DriverMutation`, `DriverAppended`, `New`, and fixed errors.

- [x] **Step 1: Add missing-symbol tests before production**

Compile tests against these exact public shapes before `emitter.go` exists:

```go
type Config struct { OperationTimeout time.Duration }

type Outcome string
const (
    OutcomeSucceeded Outcome = "succeeded"
    OutcomeFailed Outcome = "failed"
    OutcomeDenied Outcome = "denied"
)

type Mutation struct {
    Actor domain.ProductID
    Action string
    Target domain.ProductID
    Outcome Outcome
}

type DriverMutation struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    Actor string
    Action string
    Target string
    Outcome string
}

type DriverAppended struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    Actor string
    Action string
    Target string
    Outcome string
}

type Driver interface {
    Append(context.Context, DriverMutation) (DriverAppended, error)
}

type AuditEmitter interface {
    Emit(context.Context, domain.Scope, Mutation) error
}

func New(Driver, Config) (*Emitter, error)
```

The happy fake records one call, requires a live context, and returns an exact
acknowledgement copied from the received mutation. Assert the concrete emitter
satisfies `AuditEmitter`.

- [x] **Step 2: Run genuine compiler RED**

```bash
go test -C services/platform ./audit -run '^TestEmitter' -count=1
```

Expected: compilation fails only because package production symbols do not yet
exist. Record the command, missing symbols, and exit code before adding
`emitter.go`.

- [x] **Step 3: Implement construction and the exact happy path**

Add these fixed errors and limits:

```go
const (
    maximumOperationTimeout = 30 * time.Second
    maximumActionBytes = 127
)

var (
    ErrConfiguration = errors.New("audit emitter configuration rejected")
    ErrMutation = errors.New("audit mutation rejected")
    ErrEmit = errors.New("audit emission failed")
)
```

`New` rejects nil/typed-nil drivers and timeouts outside `(0, 30s]`. `Emit`
validates the receiver, context, scope, and mutation before I/O; derives the
seven canonical driver fields; creates one configured child deadline; invokes
`Driver.Append` once through a panic-containing helper; and requires exact
field-for-field acknowledgement before returning nil.

- [x] **Step 4: Run focused happy-path GREEN**

```bash
go test -C services/platform ./audit -run '^TestEmitter' -count=1
```

Expected: exact forwarding and acknowledgement tests pass.

- [x] **Step 5: Add adversarial validation tests and capture RED if needed**

Use table-driven cases that zero each required field independently and reject
all malformed actions:

```go
[]string{
    "", "A", "policy create", ".policy", "policy.", "policy..create",
    "policy__create", "policy--create", "policy/+create", "policé.create",
    strings.Repeat("a", 128),
}
```

Also cover zero/malformed scope, unknown/zero outcome, nil context, nil and
typed-nil driver, zero/negative/over-limit timeout, zero-value/nil receiver,
and actor equal to target as a valid self-mutation. Every input rejection must
leave the fake call count at zero.

- [x] **Step 6: Add driver-boundary and failure tests**

For each of the seven acknowledgement fields, return a zero or altered value
and require `ErrEmit`. Cover driver error with provider-bearing text, panic,
already-cancelled context, deadline overrun, malformed success, exact
single-attempt behavior, and fixed error strings that never include provider
data. Add 32 concurrent valid calls under `go test -race` and require one exact
append per call.

- [x] **Step 7: Run focused GREEN six times and platform gates**

```bash
for run in 1 2 3 4 5 6; do
  go test -C services/platform -race -run '^TestEmitter' -count=1 ./audit
done
go test -C services/platform -race -count=1 ./...
go -C services/platform mod tidy -diff
go -C services/platform mod verify
go -C services/platform vet ./...
```

Expected: every command exits zero with no dependency change.

- [x] **Step 8: Review the exact task diff, scan, and commit**

Check action grammar, exact field copying, pre-I/O validation, one-attempt
semantics, panic containment, deadlines, typed nil, acknowledgement equality,
fixed errors, concurrency, and absence of provider imports. Run whitespace and
pinned redacted secret scans, then commit:

```bash
git add services/platform/audit/emitter.go services/platform/audit/emitter_test.go
git commit -m "feat: add scoped audit emitter contract"
```

---

### Task 3: Expose the hermetic root command and documentation

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/audit-emitter-contract.test.ts`

**Interfaces:**
- Consumes: the Task 2 `services/platform/audit` contract.
- Produces: root `audit:emitter:test` command and an explicit product/provider
  boundary for users and CI.

- [x] **Step 1: Extend the contract and capture RED**

Assert the root script is exactly:

```ts
expect(packageJson.scripts["audit:emitter:test"]).toBe(
  "go test -C services/platform -race -count=1 ./audit",
);
```

Require a README `## AuditEmitter contract` section that names the four
required fields, exact tenant scope, fixed errors, one-attempt append,
hermetic-only boundary, and M1-18 Pending. Run the focused test before wiring;
expect only script/docs assertions to fail.

- [x] **Step 2: Add script and README section, then run GREEN**

Add the script without reordering unrelated scripts. Document:

```bash
npm run audit:emitter:test
```

State that it uses a fake driver, performs no provider/database/network I/O,
and does not yet prove persistence, retention, export, or a generic event
envelope. Run focused, root, full platform, and full pinned repository gates.

- [x] **Step 3: Scan and commit root wiring**

```bash
git add package.json README.md app/quality/audit-emitter-contract.test.ts
git commit -m "docs: expose audit emitter contract"
```

---

### Task 4: Whole-range review and final local verification

**Files:**
- Review exact M1-17 base-to-head range.
- Modify only files required by tests-first review fixes.
- Update ignored report and append-only progress ledger.

**Interfaces:**
- Consumes: all M1-17 commits and evidence.
- Produces: zero unresolved Critical, Important, or Minor findings.

- [x] **Step 1: Review exact scope read-only**

Audit against the authoritative task, PRD, approved design, this plan, domain
identity/scope contracts, public API, action/outcome grammar, pre-I/O rejection,
one-attempt append, exact acknowledgement, deadlines, panic containment,
concurrency, fixed errors, docs, status boundaries, and evidence.

- [x] **Step 2: Reproduce and fix every finding tests-first**

For each real finding, add the smallest hostile regression and capture genuine
RED before production edits. Apply the minimal fix in a separate atomic commit,
then repeat review until Critical, Important, and Minor counts are all zero.

- [x] **Step 3: Run final local gates**

```bash
for run in 1 2 3 4 5 6; do
  PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run audit:emitter:test
done
go test -C services/platform -race -count=1 ./...
go -C services/platform mod tidy -diff
go -C services/platform mod verify
go -C services/platform vet ./...
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
```

Run pinned redacted Gitleaks scans over staged content, exact commits, new
paths, ignored evidence, and full history. M1-17 has no live provider gate.

---

### Task 5: Complete, push, verify CI, and close M1-17

**Files:**
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Modify: this plan's checkboxes.
- Update ignored reports and append-only ledgers.

**Interfaces:**
- Consumes: zero-finding reviewed implementation and final evidence.
- Produces: truthful M1-17 Complete status and exact-SHA shipped branch.

- [x] **Step 1: Write completion assertions and capture RED**

Require exactly one M1-17 Complete row, M1-16 Complete, M1-18 absent,
unchanged blockers, overall `678/0/47/3`, and M1 `68/45/0/23/0`. Run focused
RED while the tracker still says In progress.

- [x] **Step 2: Move only M1-17 to Complete and repeat final local gates**

Update README/tracker/current aggregate fixtures, preserve historical fixtures,
and repeat focused/root/full/audit/whitespace/secret gates. Commit:

```bash
git commit -m "docs: complete M1-17 audit emitter"
```

- [ ] **Step 3: Push and watch exact-SHA Runnable UI to success**

Require local HEAD, upstream, remote branch, workflow run, and workflow job to
reference the same completion SHA. Watch the Runnable UI workflow to terminal
success; do not infer success from an older run.

- [ ] **Step 4: Record closure without advancing M1-18**

Append exact commits, RED/GREEN counts, gates, scans, workflow URL/job, and
synchronized clean tree. Commit/push plan-only closure wording if tracked
checkboxes change and watch that exact closure SHA too. M1-18 remains Pending.
