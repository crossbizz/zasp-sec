# M1-16 Neo4j GraphStore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and live-prove the minimal exact-scoped Neo4j adapter behind
the completed provider-neutral product GraphStore.

**Architecture:** A new `graphstore/neo4jstore` child package wraps the official
Neo4j Go driver v6.2.0 with fixed internal schema, parameterized statements,
single-attempt explicit transactions, and strict provider-record conversion.
A separate proof module runs the product store against one exact-owned
disposable Neo4j 5.26.28 Community target, then removes exact fixture state and
all owned runtime resources.

**Tech Stack:** Go 1.25 module syntax with the repository Go 1.26.5 toolchain,
official Neo4j Go driver v6.2.0, Neo4j 5.26.28 Community exact OCI index,
Node.js 22.23.1/npm 10.9.8, Vitest, Node test runner, Docker CLI, Gitleaks 8.30.1.

## Global Constraints

- Follow `docs/internal/2026-08-15-m1-16-neo4j-graph-store-design.md` exactly.
- Do not change the M1-15 public `graphstore.GraphStore` or driver types.
- The adapter uses only `ZaspGraphNode`, `ZASP_GRAPH_EDGE`, fixed property names,
  fixed statement templates, and parameter maps; caller text never becomes
  Cypher structure.
- Validate exact Organization, Workspace, and Environment scope at the adapter
  boundary even though the product store already validates it.
- Use one explicit transaction and no automatic retry for each upsert/read.
- Retain any returned transaction before interpreting a malformed begin result;
  rollback and session close use independent two-second contexts.
- Product/provider errors are fixed and contain no query, endpoint, credential,
  record, element ID, bookmark, provider error, or caller value.
- Pin `github.com/neo4j/neo4j-go-driver/v6` exactly to v6.2.0 and record its
  Apache-2.0 runtime approval in `build/dependencies.lock.yaml`.
- Pin the proof image exactly to
  `neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357`.
- The Community image is proof-only. Do not mark Neo4j server packaging,
  redistribution, or commercial licensing approved.
- No dotenv, cloud/provider credential, profile, proxy, ambient Docker auth,
  shared-service mutation, raw customer graph query, or host-wide cleanup.
- M1-16 remains In progress until live proof, exact cleanup, six final passes,
  full gates/scans, zero-finding review, push, and exact-SHA CI succeed.
- M1-17 remains Pending throughout.

---

### Task 1: Start M1-16 with an exact status contract

**Files:**
- Create: `app/quality/neo4j-graph-store-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Update ignored progress/report evidence.

**Interfaces:**
- Consumes: authoritative M1-16 source task, approved design and this plan.
- Produces: exact M1-16 In-progress status boundary and completion contract.

- [x] **Step 1: Write the status test before changing README or tracker**

Create a contract that parses the tracker tables and requires:

```ts
expect(readme).toContain("M1-16 is In progress");
expect(tracker).toContain("| Pending | 679 |");
expect(tracker).toContain("| In progress | 1 |");
expect(tracker).toContain("| Complete | 45 |");
expect(tracker).toContain("| Blocked | 3 |");
expect(tracker).toContain("`679/1/45/3`");
expect(m1).toEqual(["M1", "68", "46", "1", "21", "0"]);
expect(active.map(([task]) => task)).toEqual(["M1-16"]);
expect(complete.filter(([task]) => task === "M1-15")).toHaveLength(1);
expect([...active, ...complete].filter(([task]) => task === "M1-17")).toHaveLength(0);
expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
```

Also bind the source text `Implement minimal Neo4j node/edge upsert/read
contract`, the approved design path, the v6.2.0 driver, the exact image digest,
the proof-only server-license boundary, and M1-17 Pending.

- [x] **Step 2: Run focused RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npm exec vitest -- run app/quality/neo4j-graph-store-contract.test.ts
```

Expected: only the status/readme test fails because M1-16 is still Pending.

- [x] **Step 3: Move only M1-16 to In progress**

Update overall counts to `679/1/45/3`, M1 to `68/46/1/21/0`, add exactly one
M1-16 In-progress row, keep M1-15 Complete, keep M1-17 absent, and preserve the
three blockers. Add a concise README boundary that explicitly says no Neo4j
adapter/live claim exists yet.

Mechanically update every aggregate current-status fixture, preserving any
historical mutation fixture's original counts and active row.

- [x] **Step 4: Run focused and full status GREEN**

Run the focused contract, all status contracts, then pinned `npm run verify`.
Require exact M1-16 one-row uniqueness and no M1-17 active/complete row.

- [x] **Step 5: Commit the start transition**

```bash
git add README.md app/quality docs/internal/implementation_status_v1.5.md
git commit -m "docs: start M1-16 Neo4j GraphStore"
```

---

### Task 2: Add the strict official-driver and schema boundary

**Files:**
- Create: `services/platform/graphstore/neo4jstore/adapter.go`
- Create: `services/platform/graphstore/neo4jstore/adapter_test.go`
- Modify: `services/platform/go.mod`
- Modify: `services/platform/go.sum`
- Modify: `build/dependencies.lock.yaml`

**Interfaces:**
- Consumes: `graphstore.Driver`, `DriverProjection`, `DriverQuery`, and
  `DriverUpserted`; official `neo4j.Driver` v6.2.0.
- Produces: `New`, `EnsureSchema`, fixed adapter errors, immutable adapter, and
  unexported narrow session/transaction/result interfaces used by Tasks 3-4.

- [x] **Step 1: Write compiler-RED adapter tests**

Tests must require these exact declarations before production exists:

```go
var _ graphstore.Driver = (*Adapter)(nil)

adapter, err := New(driver, "neo4j")
err = EnsureSchema(ctx, driver, "neo4j")
```

Cover nil/typed-nil driver, any database other than `neo4j`, nil context,
driver/session panic, and fixed errors that never contain seeded provider text.
Require the two exact constraint statements from the design and strict
`SHOW CONSTRAINTS` verification of names, types, entity types, labels/types,
properties, and owned index names with no missing, duplicate, or extra owned
constraint.

- [x] **Step 2: Run genuine compiler RED**

```bash
go test -C services/platform ./graphstore/neo4jstore -run '^TestAdapter|^TestEnsureSchema' -count=1
```

Expected: compile fails only on the absent package API.

- [x] **Step 3: Pin the official driver and lock record**

From `services/platform` run:

```bash
go get github.com/neo4j/neo4j-go-driver/v6@v6.2.0
go mod tidy
```

Add this exact lock entry:

```yaml
  - ecosystem: go
    manifest: services/platform/go.mod
    name: github.com/neo4j/neo4j-go-driver/v6
    version: v6.2.0
    license: Apache-2.0
    owner: platform-data
    scope: runtime
    review: approved
```

- [x] **Step 4: Implement the narrow wrapper and schema verification**

Use fixed errors:

```go
var (
    ErrConfiguration = errors.New("neo4j graph store configuration rejected")
    ErrSchema        = errors.New("neo4j graph store schema rejected")
    ErrUpsert        = errors.New("neo4j graph store upsert failed")
    ErrRead          = errors.New("neo4j graph store read failed")
)
```

Keep these source constants exact:

```go
const databaseName = "neo4j"
const nodeLabel = "ZaspGraphNode"
const edgeType = "ZASP_GRAPH_EDGE"
const nodeConstraint = "zasp_graph_node_identity_v1"
const edgeConstraint = "zasp_graph_edge_identity_v1"
const schemaVersion int64 = 1
const cleanupTimeout = 2 * time.Second
```

Wrap the official session and explicit transaction with unexported interfaces.
Record a non-nil transaction candidate before checking the begin error. On any
uncommitted return or panic, attempt rollback and close with
`context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)`.

Use these exact testable internal boundaries; the official-driver wrapper maps
its richer result and summary types into them:

```go
type accessMode uint8

const (
    accessRead accessMode = iota + 1
    accessWrite
)

type sessionConfig struct {
    Database string
    Access   accessMode
}

type sessionProvider interface {
    NewSession(context.Context, sessionConfig) graphSession
}

type graphSession interface {
    Begin(context.Context) (graphTransaction, error)
    Close(context.Context) error
}

type graphTransaction interface {
    Run(context.Context, string, map[string]any) (graphResult, error)
    Commit(context.Context) error
    Rollback(context.Context) error
}

type graphResult interface {
    Keys() ([]string, error)
    Next(context.Context) bool
    Record() graphRecord
    Err() error
    Consume(context.Context) error
}

type graphRecord struct {
    Keys   []string
    Values []any
}
```

`EnsureSchema` creates exactly the two design constraints, consumes both
results fully, runs one strict `SHOW CONSTRAINTS`, and accepts only the two exact
owned rows. No ordinary adapter operation creates schema.

- [x] **Step 5: Run focused schema GREEN and module gates**

```bash
go test -C services/platform -race -run '^TestAdapter|^TestEnsureSchema' -count=1 ./graphstore/neo4jstore
go -C services/platform mod tidy -diff
go -C services/platform mod verify
go -C services/platform vet ./graphstore/neo4jstore
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run dependencies:check
```

- [x] **Step 6: Commit the schema boundary**

```bash
git add services/platform/graphstore/neo4jstore services/platform/go.mod services/platform/go.sum build/dependencies.lock.yaml
git commit -m "feat: add Neo4j GraphStore schema boundary"
```

---

### Task 3: Implement atomic exact-scoped upsert

**Files:**
- Create: `services/platform/graphstore/neo4jstore/upsert.go`
- Create: `services/platform/graphstore/neo4jstore/upsert_test.go`
- Modify: `services/platform/graphstore/neo4jstore/adapter.go`
- Test: `services/platform/graphstore/store_test.go`

**Interfaces:**
- Consumes: canonical `graphstore.DriverProjection` and Task 2 transaction
  wrapper.
- Produces: `Adapter.Upsert` returning an exact canonical
  `graphstore.DriverUpserted` acknowledgement.

- [x] **Step 1: Write exact upsert RED tests**

Require sorted nodes/edges and exact parameter maps with only these keys:

```go
map[string]any{
    "organization_id": organizationID,
    "workspace_id": workspaceID,
    "environment_id": environmentID,
    "nodes": []any{ /* node_id and kind only */ },
    "edges": []any{ /* edge_id, kind, source_id, target_id only */ },
    "schema_version": int64(1),
}
```

Prove one begin, fixed node merge, fixed edge merge, exact-state re-read, full
result consumption, and one commit. Replaying the same projection must produce
the same exact acknowledgement.

Hostile subtests must cover malformed direct calls, foreign/mixed scope,
invalid IDs/kinds/order, duplicate IDs, duplicate semantic edge, self-edge,
dangling endpoints, wrong property keys/types/version/kind/endpoints,
zero/multiple/extra result rows, partial/extra acknowledgement, begin returning
transaction plus error, run/consume/commit failures, cancellation, timeout,
panic, rollback failure, close failure, and caller/result slice mutation.

- [x] **Step 2: Run focused RED**

```bash
go test -C services/platform ./graphstore/neo4jstore -run '^TestUpsert' -count=1
```

Expected: tests fail on the absent upsert implementation, not fixture setup.

- [x] **Step 3: Implement one-attempt transactional upsert**

Use fixed statement constants only. `MERGE` nodes by exact scope plus node ID,
then relationships by exact scope plus edge ID between exact endpoints. Set
`kind` and `schema_version` only on create. Reject stored state unless its full
property-key set and values match exactly. Consume the exact readback inside the
same transaction, sort IDs, require exact acknowledgement, then commit once.

Do not use `ExecuteWrite`, `ExecuteQuery`, string formatting, dynamic labels,
or driver-managed transaction retries.

- [x] **Step 4: Run upsert GREEN and regression gates**

```bash
go test -C services/platform -race -run '^TestUpsert' -count=1 ./graphstore/neo4jstore
go test -C services/platform -race -run '^TestStoreUpsert|^TestStoreConcurrent' -count=10 -shuffle=on ./graphstore
```

- [x] **Step 5: Commit upsert**

```bash
git add services/platform/graphstore/neo4jstore
git commit -m "feat: upsert scoped Neo4j graph projections"
```

---

### Task 4: Implement bounded deterministic traversal reads

**Files:**
- Create: `services/platform/graphstore/neo4jstore/read.go`
- Create: `services/platform/graphstore/neo4jstore/read_test.go`
- Modify: `services/platform/graphstore/neo4jstore/adapter.go`

**Interfaces:**
- Consumes: validated `graphstore.DriverQuery` and Task 2 transaction wrapper.
- Produces: `Adapter.Read` returning canonical strictly sorted
  `graphstore.DriverProjection` state.

- [ ] **Step 1: Write traversal RED tests**

Cover outgoing, incoming, both, depth zero, missing root, a cycle, converging
paths, repeated provider rows, deterministic node/edge truncation, and exact
sort order. Assert exactly three fixed one-hop adjacency statements, a bounded
Go loop for depth 0 through 8, and prohibit `fmt.Sprintf`, caller query text,
dynamic label/type, or unbounded result calls.

Every record test must enforce exact keys, `int64(1)` schema version, exact
scope, canonical IDs, valid kinds, fixed label/type, valid direction, unique
edge identity, and endpoints retained in the same result. Include wrong scalar
types, extra/missing keys, provider element IDs, extra labels, foreign scope,
unordered rows, depth drift, edge-limit drift, result error after iteration,
begin/run/consume/commit/rollback/close failures, cancellation, timeout, panic,
and concurrent calls.

- [ ] **Step 2: Run focused RED**

```bash
go test -C services/platform ./graphstore/neo4jstore -run '^TestRead' -count=1
```

- [ ] **Step 3: Implement strict breadth-first read**

Read the exact root first. Missing root returns non-nil empty node/edge slices.
Depth zero returns only the root. For each remaining level, select one immutable
one-hop outgoing/incoming/both statement, pass only the canonical frontier,
exact scope, and remaining limits, consume every bounded row, validate it before
retention, and derive the next sorted frontier.

Deduplicate only exact duplicate provider rows; any conflicting duplicate is
failure. Stop at requested limits, sort final records by product ID, validate
same-result endpoints, then commit the read transaction. Do not use managed
retry or retain bookmarks.

- [ ] **Step 4: Run read and full product GREEN**

```bash
go test -C services/platform -race -run '^TestRead' -count=1 ./graphstore/neo4jstore
go test -C services/platform -race -count=1 ./graphstore/...
go test -C services/platform -race -count=1 ./...
go -C services/platform vet ./...
```

- [ ] **Step 5: Commit read support**

```bash
git add services/platform/graphstore/neo4jstore
git commit -m "feat: read bounded Neo4j graph projections"
```

---

### Task 5: Add the disposable exact-image compatibility proof

**Files:**
- Create: `proofs/neo4j-graphstore/go.mod`
- Create: `proofs/neo4j-graphstore/go.sum`
- Create: `proofs/neo4j-graphstore/main.go`
- Create: `proofs/neo4j-graphstore/main_test.go`
- Create: `proofs/neo4j-graphstore/run.mjs`
- Create: `proofs/neo4j-graphstore/run.test.mjs`
- Create: `proofs/neo4j-graphstore/licenses.json`
- Create: `proofs/neo4j-graphstore/license-audit.mjs`
- Create: `proofs/neo4j-graphstore/license-audit.test.mjs`

**Interfaces:**
- Consumes: product `graphstore.Store`, `neo4jstore.Adapter`, exact official
  driver, and exact Neo4j image.
- Produces: hermetic proof tests and fixed live command boundary.

- [ ] **Step 1: Write Go proof tests before production**

The wished-for CLI reads only `NEO4J_GRAPHSTORE_URI=bolt://127.0.0.1:<port>`
from the exact child environment. It uses `neo4j.NoAuth()`, verifies
connectivity, calls `EnsureSchema`, constructs the adapter and product store,
then runs one fixed projection:

```text
three nodes: cloud_account, identity_role, agent_runtime
two edges: contains_identity, permits_runtime
```

Require upsert, exact replay, outgoing/incoming/both/depth-zero reads,
Organization B zero state, exact direct-provider audit, exact fixture deletion,
and post-delete absence. Success is exactly:

```text
Neo4j GraphStore proof passed: nodes=3 edges=2 replay=true scoped=true cross_organization_zero=true cleanup=true audit=true.
```

Failures are one fixed line:

```text
Neo4j GraphStore proof failed: <configuration|provider|ownership|operation|cleanup> rejected.
```

- [ ] **Step 2: Run Go compiler RED**

```bash
go test -C proofs/neo4j-graphstore -count=1 ./...
```

- [ ] **Step 3: Write Node lifecycle and license tests before production**

Require the exact image, generated prefix/marker labels, owned empty
`DOCKER_CONFIG`, no ambient credential/profile/proxy input, numeric-loopback
7474/7687 publication, semantic HTTP `RETURN 1` readiness, exact image/runtime
reproof, fixed child environment, a 300-second hard SIGKILL supervisor, combined
4 KiB child-output cap, 120-second main and 60-second cleanup phases, mutation
journal/join, candidate-aware ambiguous create/remove reconciliation, exact
intrinsic-volume retention, reverse cleanup, prefix/label/temp absence, and
cleanup precedence.

Hostile tests must cover definitive versus ambiguous Docker outcomes, delayed
mutation settlement, candidate replacement, image/env/entrypoint/cmd/label/
network/port/security/mount/volume drift, readiness timeout/duplicate JSON/
oversize/error rows, stdout/stderr pipe errors, output overflow, uncooperative
child, symlink/inode/realpath temp replacement, cleanup-time volume presence,
and shared-container non-targeting.

The license audit must bind the exact image/source version and the exact
official Go driver module/version/license while stating that the Community
server is proof-only and not approved in the product dependency lock.

- [ ] **Step 4: Run Node/Python-free compiler RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  node --test proofs/neo4j-graphstore/run.test.mjs proofs/neo4j-graphstore/license-audit.test.mjs
```

Expected: module-not-found failures for the absent runner/audit.

- [ ] **Step 5: Implement the Go proof and Node lifecycle**

Use the exact-image and ownership patterns already proved in
`proofs/cartography-scope`, but keep this module independent and limited to one
Neo4j target plus one Go child. Do not import Cartography, fixture graphs, or
M0-10 result types. All cleanup authorization must be based on retained full
IDs plus fresh exact metadata reproof.

- [ ] **Step 6: Run hermetic GREEN six times**

```bash
for run in 1 2 3 4 5 6; do
  go test -C proofs/neo4j-graphstore -race -count=1 ./...
  PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
    node --test proofs/neo4j-graphstore/run.test.mjs proofs/neo4j-graphstore/license-audit.test.mjs
done
```

- [ ] **Step 7: Run the exact live lifecycle and audit zero state**

After local GREEN and a read-only prefix/shared-target preflight, run the exact
environment-isolated command once. Require the fixed success line, exact Go
product result, both constraints, three nodes/two edges, Organization B zero,
fixture deletion, container/intrinsic-volume/temp absence, global proof-prefix
absence, and unchanged shared target fingerprint.

- [ ] **Step 8: Commit the proof**

```bash
git add proofs/neo4j-graphstore
git commit -m "feat: prove scoped Neo4j GraphStore"
```

---

### Task 6: Expose root commands and documentation

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/neo4j-graph-store-contract.test.ts`

**Interfaces:**
- Consumes: Tasks 2-5 adapter and proof commands.
- Produces: documented root hermetic/live/license commands and repository
  contract coverage.

- [ ] **Step 1: Extend the contract before wiring commands**

Require exact scripts:

```json
"graph:neo4j:test": "go test -C services/platform -race -count=1 ./graphstore/... && go test -C proofs/neo4j-graphstore -race -count=1 ./... && node --test proofs/neo4j-graphstore/run.test.mjs proofs/neo4j-graphstore/license-audit.test.mjs",
"graph:neo4j:run": "node proofs/neo4j-graphstore/run.mjs",
"graph:neo4j:license": "node proofs/neo4j-graphstore/license-audit.mjs"
```

Require README commands, exact success line, local-only compatibility boundary,
driver/image pins, no raw Cypher/customer query, no shared target, and explicit
server-packaging risk. Run focused RED before changing scripts/docs.

- [ ] **Step 2: Add scripts and README section, then run GREEN**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run graph:neo4j:test
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run graph:neo4j:license
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npm exec vitest -- run app/quality/neo4j-graph-store-contract.test.ts
```

- [ ] **Step 3: Commit root wiring**

```bash
git add package.json README.md app/quality/neo4j-graph-store-contract.test.ts
git commit -m "docs: expose Neo4j GraphStore proof"
```

---

### Task 7: Whole-range review, fixes, and final local verification

**Files:**
- Review exact M1-16 base-to-head range.
- Modify only files required by tests-first review fixes.
- Update ignored report and append-only progress ledger.

**Interfaces:**
- Consumes: all M1-16 commits and evidence.
- Produces: zero unresolved Critical, Important, or Minor findings.

- [ ] **Step 1: Review exact scope read-only**

Audit against the authoritative task, PRD, design, plan, M1-15 driver contract,
official driver semantics, exact Cypher, transaction lifecycle, strict record
conversion, ownership, cleanup, license boundary, fixed output, and evidence.
Run only non-live gates during review.

- [ ] **Step 2: Reproduce every finding tests-first**

For each finding, add the smallest hostile regression and capture genuine RED
before production edits. Do not accept a suggestion until code and primary
documentation confirm its premise. Fix findings in separate atomic commits.

- [ ] **Step 3: Repeat review until zero findings remain**

Require an explicit zero-finding verdict for Critical, Important, and Minor.

- [ ] **Step 4: Run final gates**

```bash
for run in 1 2 3 4 5 6; do
  PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run graph:neo4j:test
done
go test -C services/platform -race -count=1 ./...
go -C services/platform mod tidy -diff
go -C services/platform mod verify
go -C services/platform vet ./...
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run graph:neo4j:license
git diff --check
```

Re-run the exact live lifecycle on final code and re-prove all owned state zero
and any shared target unchanged. Run pinned redacted Gitleaks scans over staged
content, new paths, ignored evidence, exact commits, and full history.

---

### Task 8: Complete, push, verify CI, and close M1-16

**Files:**
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Modify: this plan's checkboxes.
- Update ignored reports and append-only ledgers.

**Interfaces:**
- Consumes: zero-finding reviewed implementation and final evidence.
- Produces: truthful M1-16 Complete status and exact-SHA shipped branch.

- [ ] **Step 1: Write completion assertions and capture RED**

Require exactly one M1-16 Complete row, M1-15 Complete, M1-17 absent, unchanged
blockers, overall `679/0/46/3`, and M1 `68/46/0/22/0`. Run focused RED while
the tracker still says In progress.

- [ ] **Step 2: Move only M1-16 to Complete and run final local gates**

Update README/tracker/current aggregate fixtures, preserve historical fixtures,
and repeat focused/root/full/license/audit/whitespace/secret gates. Commit:

```bash
git commit -m "docs: complete M1-16 Neo4j GraphStore"
```

- [ ] **Step 3: Push and watch exact-SHA Runnable UI to success**

Require local HEAD, upstream, remote branch, workflow run, and workflow job to
reference the same completion SHA. Watch the Runnable UI workflow to terminal
success; do not infer success from an older run.

- [ ] **Step 4: Record closure without advancing M1-17**

Append exact commits, RED/GREEN counts, live result, cleanup/shared-target
audit, gates, license/secret scans, workflow URL/job, and synchronized clean
tree. Commit/push plan-only closure wording if tracked checkboxes change, and
watch that exact closure SHA too. M1-17 remains Pending.
