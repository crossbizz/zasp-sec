# M1-15 GraphStore Interface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dependency-free, fully scoped product `GraphStore` whose
provider-neutral upsert/read contract passes strict fake-driver tests.

**Architecture:** `services/platform/graphstore` owns canonical product node
and edge identities, full Organization/Workspace/Environment scope, bounded
structured traversal, deterministic projections, deadlines, fixed errors, and
defensive copies. A narrow provider-neutral driver is the only persistence
boundary. M1-15 uses a hermetic fake driver; M1-16 will implement Neo4j without
changing the public product interface.

**Tech Stack:** Go 1.25 language/toolchain 1.26.5, dependency-free platform
module, Node 22.23.1/npm 10.9.8 repository contracts, Vitest, Go race detector,
and pinned Gitleaks 8.30.1.

## Global Constraints

- Design commit is `580b5442c120ec3f7d0740102faffc98d0fb11b2`.
- M1-14 remains Complete; M1-16 remains Pending until this plan closes.
- Start counts are overall `680/1/44/3` and M1 `68/47/1/20/0`.
- Completion counts are overall `680/0/45/3` and M1 `68/47/0/21/0`.
- Product code imports no Neo4j, Cypher, HTTP, or provider type and performs no
  retry.
- Every operation and every node/edge carries the exact validated
  Organization/Workspace/Environment scope.
- Nodes and edges use canonical `domain.ProductID` values; source/vendor IDs
  never become graph primary keys or public graph fields.
- Read accepts only a bounded structured root/direction/depth/limit request;
  arbitrary customer graph queries, predicates, labels, properties, and Cypher
  are not exposed.
- Projections contain at most 1,000 nodes and 2,000 edges; traversal depth is at
  most 8; all driver and result slices are defensively copied.
- M1-15 performs no Docker, Neo4j, provider, credential, or shared-target I/O.
- M1-15 completion proves the product/fake contract only. Neo4j compatibility,
  persistence, transactions, availability, packaging, and licensing belong to
  M1-16 and later provider gates.

---

### Task 1: Start M1-15 with an exact repository contract

**Files:**
- Create: `app/quality/graph-store-interface-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Create ignored evidence under
  `.superpowers/sdd/2026-08-15-m1-15-graph-store-implementation-plan/`

**Interfaces:**
- Consumes: authoritative M1-15 source task, M1-14 Complete row, design commit
  `580b5442c120ec3f7d0740102faffc98d0fb11b2`, and current count contracts.
- Produces: exactly one M1-15 In-progress row and assertions that keep M1-14
  Complete, M1-16 absent, and all blocker/risk rows unchanged.

- [x] **Step 1: Write the source/status contract before changing docs**

Assert the exact dependency, deliverable, fake verification, design path,
current count tables, one active M1-15 row, one completed M1-14 row, no M1-16
active/complete row, and stable blocker/risk rows.

- [x] **Step 2: Run the focused contract and record Pending-state RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/graph-store-interface-contract.test.ts
```

Expected: only the still-Pending M1-15 status assertions fail.

- [x] **Step 3: Move only M1-15 to In progress**

Update README/tracker and affected count fixtures to `680/1/44/3` overall and
M1 `68/47/1/20/0`. Do not change any other task or risk status.

- [x] **Step 4: Run focused/full pinned gates, scan, and commit**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
git commit -m "docs: start M1-15 GraphStore interface"
```

---

### Task 2: Implement the dependency-free GraphStore

**Files:**
- Create: `services/platform/graphstore/store_test.go`
- Create: `services/platform/graphstore/store.go`

**Interfaces:**
- Consumes: `domain.Scope`, `domain.ProductID`, Go contexts, and durations.
- Produces: `GraphStore`, `Store`, `Driver`, `Config`, `Node`, `Edge`,
  `Projection`, `Direction`, `ReadRequest`, `DriverNode`, `DriverEdge`,
  `DriverProjection`, `DriverQuery`, `DriverUpserted`, and fixed errors.

- [x] **Step 1: Add missing-symbol tests before production**

Compile tests against these public shapes before `store.go` exists:

```go
type Config struct {
    OperationTimeout time.Duration
    MaximumNodes int
    MaximumEdges int
    MaximumDepth int
}

type Node struct {
    Scope domain.Scope
    NodeID domain.ProductID
    Kind string
}

type Edge struct {
    Scope domain.Scope
    EdgeID domain.ProductID
    Kind string
    SourceID domain.ProductID
    TargetID domain.ProductID
}

type Projection struct { Nodes []Node; Edges []Edge }
type Direction uint8
const (DirectionOutgoing Direction = iota + 1; DirectionIncoming; DirectionBoth)

type ReadRequest struct {
    RootID domain.ProductID
    Direction Direction
    MaximumDepth int
    MaximumNodes int
    MaximumEdges int
}

type DriverNode struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    NodeID string
    Kind string
}

type DriverEdge struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    EdgeID string
    Kind string
    SourceID string
    TargetID string
}

type DriverProjection struct { Nodes []DriverNode; Edges []DriverEdge }
type DriverUpserted struct { NodeIDs []string; EdgeIDs []string }

type DriverQuery struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    RootID string
    Direction string
    MaximumDepth int
    MaximumNodes int
    MaximumEdges int
    NodeSort string
    EdgeSort string
}

type Driver interface {
    Upsert(context.Context, DriverProjection) (DriverUpserted, error)
    Read(context.Context, DriverQuery) (DriverProjection, error)
}

type GraphStore interface {
    Upsert(context.Context, domain.Scope, Projection) error
    Read(context.Context, domain.Scope, ReadRequest) (Projection, error)
}
```

Cover one canonical two-node/one-edge upsert and outgoing read, exact fake
driver state, deterministic ordering, idempotent replay acknowledgement, and
defensive result copies.

- [x] **Step 2: Run compiler RED**

```bash
go test -C services/platform ./graphstore -count=1
```

Expected: compilation fails only on missing GraphStore symbols; no production
or dependency edit may precede it.

- [x] **Step 3: Implement strict configuration and projections**

Validate nil/typed-nil driver, positive timeout through 30 seconds, limits,
exact repeated scope, nonzero IDs, product-neutral kind grammar, unique IDs and
semantic edges, no self/dangling edge, deterministic sorting, defensive copies,
and exact all-or-nothing driver acknowledgement.

- [x] **Step 4: Implement bounded structured reads**

Validate one canonical root, direction, depth, and result limits before I/O.
Send exact scope and fixed ID ordering to the fake driver. Reject foreign,
malformed, duplicate, unordered, dangling, oversized, or unreachable results.
Allow an empty missing-root result and require every nonempty node to be
reachable within the requested directed depth.

- [x] **Step 5: Expand adversarial RED/GREEN coverage**

Cover invalid configuration and requests; zero/mismatched scope and IDs;
invalid/provider-native kinds; duplicate IDs/semantic edges; self/dangling
edges; exact acknowledgement failures; empty/nonempty reads; all directions;
depth zero; limit overflow; foreign, duplicate, unordered, dangling, or
unreachable driver results; cancellation; deadline; errors; panics; aliasing;
typed-nil interfaces; and 32 concurrent independent calls.

- [x] **Step 6: Run race and six stability passes**

```bash
go test -C services/platform -race -count=1 ./graphstore
for run in 1 2 3 4 5 6; do
  go test -C services/platform -count=1 ./graphstore
done
test -z "$(cd services/platform && go mod tidy -diff)"
(cd services/platform && go mod verify)
(cd services/platform && go vet ./...)
```

- [x] **Step 7: Scan and commit the product package**

```bash
git diff --check
git commit -m "feat: add scoped GraphStore interface"
```

---

### Task 3: Expose the hermetic contract gate

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/graph-store-interface-contract.test.ts`

**Interfaces:**
- Produces: root `graph:store:test` command that runs the package race gate and
  documentation that clearly separates M1-15 fake evidence from M1-16 Neo4j.

- [x] **Step 1: Write root-command and documentation assertions first**

Require an exact non-live root command, the exported product method/type names,
full-scope/no-Cypher boundaries, explicit fake-only evidence, and M1-16 Pending.

- [x] **Step 2: Run focused RED, add minimal wiring, and reach GREEN**

Add only the script and documentation required by the contract. Run the root
command and focused Vitest file under pinned Node.

- [x] **Step 3: Run affected repository gates, scan, and commit**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run graph:store:test
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
git commit -m "docs: expose GraphStore contract"
```

---

### Task 4: Whole-task review and fix loop

**Files:**
- Inspect exact M1-15 range.
- Modify only files required by reproduced findings.
- Append ignored report and ledger evidence.

- [x] **Step 1: Review source task, design, plan, diff, and tests read-only**

Audit provider independence, scope and ID binding, structured query bounds,
deterministic ordering, graph reachability, defensive copies, deadlines,
panic containment, concurrency, docs, and status boundaries.

- [x] **Step 2: Reproduce every finding with tests-first RED**

Do not accept or reject a review item by assertion alone. Add the smallest
hostile regression proving impact and preserve its failing output.

- [x] **Step 3: Fix one item at a time and rerun focused/full gates**

Keep fixes in separate atomic commits. Repeat review until Critical, Important,
and Minor findings are all zero.

- [x] **Step 4: Run final six-pass and repository verification**

```bash
for run in 1 2 3 4 5 6; do
  PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run graph:store:test
done
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
```

---

### Task 5: Complete, ship, and close M1-15

**Files:**
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Update ignored reports and append-only ledgers.

- [x] **Step 1: Write completion assertions and record In-progress RED**

Require exactly one M1-15 Complete row, M1-14 Complete, M1-16 absent, unchanged
blockers, overall `680/0/45/3`, and M1 `68/47/0/21/0`.

- [x] **Step 2: Move only M1-15 to Complete and run final local gates**

Update status/docs/count fixtures, run focused/root/full pinned gates, audit,
license inventory, whitespace, and pinned redacted Gitleaks scans. Commit the
completion transition separately.

- [x] **Step 3: Push and watch exact-SHA Runnable UI to success**

Push only after clean review and local verification. Require local HEAD,
upstream, remote branch, workflow run, and workflow job to reference the same
completion SHA. Watch the Runnable UI run to terminal success.

- [x] **Step 4: Record closure without advancing M1-16**

Append exact commits, RED/GREEN counts, gates, scan results, workflow URL/job,
clean/synchronized tree, and remaining status to authoritative and ignored
evidence. Commit/push only the closure wording if tracked files require it;
otherwise keep the completion SHA authoritative. M1-16 remains Pending.
