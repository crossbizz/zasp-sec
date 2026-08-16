# M1-14 OpenSearch EventStore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dependency-free scoped `EventStore` and prove its strict
OpenSearch adapter against the exact disposable OpenSearch lifecycle.

**Architecture:** `services/platform/eventstore` owns validated product events,
mandatory Organization/Workspace/Environment search scope, bounded structured
filters, deadlines, fixed errors, and defensive results. The existing
`proofs/opensearch-event` module owns index names, mappings, strict HTTP,
provider mutation reconciliation, and the exact disposable lifecycle; it gains
a narrow product driver and a separate M1-14 CLI mode without changing M0-08.

**Tech Stack:** Go 1.25 language/toolchain 1.26.5, dependency-free platform
package, strict standard-library OpenSearch REST adapter, Node 22.23.1/npm
10.9.8 orchestration/contracts, OpenSearch 3.8.0 exact digest, Vitest, Go race
detector, pinned Gitleaks 8.30.1.

## Global Constraints

- Design commit is `b64229a80e32707eb0694c03c88400a557f2510a`.
- M1-13 remains Complete; M1-15 remains Pending until this plan closes.
- Start counts are overall `681/1/43/3` and M1 `68/48/1/19/0`.
- Completion counts are overall `681/0/44/3` and M1 `68/48/0/20/0`.
- Product code imports no OpenSearch, AWS, HTTP, or provider type and performs
  no retry.
- Every index and search operation receives a separate validated
  Organization/Workspace/Environment scope; no raw query DSL is accepted.
- Search is bounded to at most 100 events and has deterministic event-time,
  event-ID ordering.
- Index names, provider IDs, errors, endpoints, credentials, payloads, proof
  names, and query DSL never enter public product results or fixed output.
- The M0-08 default proof remains byte-for-byte compatible; shared development
  OpenSearch and LocalStack targets are never selected, changed, or removed.
- Live evidence proves disposable OpenSearch compatibility only, not AWS
  OpenSearch Service IAM, durability, availability, encryption, or parity.

---

### Task 1: Start M1-14 with an exact repository contract

**Files:**
- Create: `app/quality/opensearch-event-store-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Create ignored evidence under
  `.superpowers/sdd/2026-08-15-m1-14-opensearch-event-store-implementation-plan/`

**Interfaces:**
- Consumes: authoritative M1-14 source task, M1-13 Complete row, design commit
  `b64229a80e32707eb0694c03c88400a557f2510a`, and current count contracts.
- Produces: exactly one M1-14 In-progress row and assertions that keep M1-13
  Complete, M1-15 absent, and all blocker/risk rows unchanged.

- [ ] **Step 1: Write the source/status contract before changing docs**

Assert the exact dependency, deliverable, scoped fixture verification, design
path, current count tables, one active M1-14 row, one completed M1-13 row, no
M1-15 active/complete row, and stable blocker rows.

- [ ] **Step 2: Run the focused contract and record Pending-state RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/opensearch-event-store-contract.test.ts
```

Expected: only the still-Pending M1-14 status assertions fail.

- [ ] **Step 3: Move only M1-14 to In progress**

Update README/tracker and shared count fixtures to `681/1/43/3` overall and M1
`68/48/1/19/0`. Do not change any other task or risk status.

- [ ] **Step 4: Run focused/full pinned gates, scan, and commit**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
git commit -m "docs: start M1-14 OpenSearch EventStore"
```

---

### Task 2: Implement the dependency-free EventStore

**Files:**
- Create: `services/platform/eventstore/store_test.go`
- Create: `services/platform/eventstore/store.go`

**Interfaces:**
- Consumes: `domain.Scope`, `domain.ProductID`, Go contexts and `time.Time`.
- Produces: `EventStore`, `Store`, `Driver`, `Config`, `Event`, `Filter`,
  `DriverDocument`, `DriverQuery`, `DriverIndexed`, and fixed errors.

- [ ] **Step 1: Add missing-symbol tests before production**

Compile tests against these public shapes before `store.go` exists:

```go
type Config struct {
    OperationTimeout time.Duration
    MaximumResults int
}

type Event struct {
    Scope domain.Scope
    EventID domain.ProductID
    SessionID domain.ProductID
    AgentID domain.ProductID
    Source string
    SourceEventID string
    Class string
    Action string
    Decision string
    EventTime time.Time
}

type Filter struct {
    SessionID domain.ProductID
    Limit int
}

type DriverDocument struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    EventID string
    SessionID string
    AgentID string
    Source string
    SourceEventID string
    Class string
    Action string
    Decision string
    EventTime string
}

type DriverQuery struct {
    OrganizationID string
    WorkspaceID string
    EnvironmentID string
    SessionID string
    Limit int
    Sort []string
}

type DriverIndexed struct { EventID string }

type Driver interface {
    Index(context.Context, DriverDocument) (DriverIndexed, error)
    Search(context.Context, DriverQuery) ([]DriverDocument, error)
}

type EventStore interface {
    Index(context.Context, domain.Scope, Event) error
    Search(context.Context, domain.Scope, Filter) ([]Event, error)
}
```

Cover one exact index and scoped search happy path, the exact driver query,
event-time/event-ID sorting, and defensive result copies.

- [ ] **Step 2: Run compiler RED**

```bash
go test -C services/platform ./eventstore -count=1
```

Expected: compilation fails only on missing EventStore symbols; no production
or dependency edit may precede it.

- [ ] **Step 3: Implement strict configuration and event validation**

Require a non-nil driver, one positive timeout through 30 seconds, maximum
results 1 through 100, exact scope equality, nonzero IDs, source
`runtime_gateway`, class `tool`, action `invoke`, decision in
`allowed|monitored|blocked`, source event ID 1 through 256 bytes, valid UTF-8,
no control characters, and a UTC millisecond timestamp whose canonical form is
`2006-01-02T15:04:05.000Z`.

- [ ] **Step 4: Implement bounded index and search operations**

Each operation validates before I/O, creates one total timeout, contains driver
panics, invokes the driver once, and maps only to fixed errors. Index requires
an exact acknowledgement event ID. Search requires every document to match the
requested scope/session, validates strict ascending `(event_time,event_id)`
order and unique event IDs, enforces the requested limit, and returns newly
allocated product events.

- [ ] **Step 5: Expand adversarial RED/GREEN coverage**

Cover nil/typed-nil driver, invalid configuration, zero/mismatched scope, zero
IDs, wrong allowlists, empty/control/invalid-UTF8/oversized source event IDs,
non-UTC/impossible/non-millisecond timestamps, invalid filters, malformed or
foreign driver documents, duplicate/unsorted/oversized results, errors,
cancellation, deadline, panic, aliasing, and 32 concurrent independent calls.

- [ ] **Step 6: Run race and six stability passes**

```bash
go test -C services/platform -race -count=1 ./eventstore
for run in 1 2 3 4 5 6; do
  go test -C services/platform -count=1 ./eventstore
done
test -z "$(cd services/platform && go mod tidy -diff)"
(cd services/platform && go mod verify)
(cd services/platform && go vet ./...)
```

- [ ] **Step 7: Scan and commit the product package**

```bash
git commit -m "feat: add scoped event store"
```

---

### Task 3: Adapt strict OpenSearch indexing and scoped search

**Files:**
- Modify: `proofs/opensearch-event/go.mod`
- Create: `proofs/opensearch-event/event_store.go`
- Create: `proofs/opensearch-event/event_store_test.go`
- Create: `proofs/opensearch-event/event_store_proof.go`
- Create: `proofs/opensearch-event/event_store_proof_test.go`
- Modify: `proofs/opensearch-event/http_store.go`
- Modify: `proofs/opensearch-event/http_store_test.go`
- Modify: `proofs/opensearch-event/main.go`
- Modify: `proofs/opensearch-event/main_test.go`

**Interfaces:**
- Consumes: product `eventstore.Driver`, exact existing `httpBackend`, M0-08
  index ownership and strict JSON/transport helpers.
- Produces: `openSearchEventDriver`, `RunEventStoreProof`, and the separate
  `event-store` executable mode.

- [ ] **Step 1: Write adapter/lifecycle tests before code**

Require create-only indexing at the deterministic product event ID, exact
canonical document JSON, and one structured query with exact term filters for
`organization_id`, `workspace_id`, `environment_id`, and `session_id`, plus
exact size and ascending event-time/event-ID sorting. Require A-scope one hit,
B-scope zero hits, exact cleanup, and the unchanged legacy M0-08 flow.

- [ ] **Step 2: Capture missing adapter/mode RED**

```bash
go test -C proofs/opensearch-event -run 'EventStore|Main' -count=1
```

Expected: compile failures only for absent product driver/proof/mode symbols.

- [ ] **Step 3: Add the local product module dependency**

Add:

```go
require github.com/zasp-ai/zasp-sec/services/platform v0.0.0
replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform
```

Run `go mod tidy` only after the tests-first RED is recorded.

- [ ] **Step 4: Implement the strict product driver**

Convert product driver documents to the existing strict mapping without
accepting provider-controlled fields. Index with `_create`, one attempt, and an
exact created acknowledgement. Search with safe-read bounded retry, exact
four-term scope, bounded size, deterministic sorting, complete hit validation,
and no raw query input. Non-2xx mutation rejection is definitive; transport,
stream, and malformed/unexpected-success outcomes are ambiguous and reconcile
only exact state.

- [ ] **Step 5: Implement the product-backed proof mode**

Generate fixed valid product IDs for Organization A/B, workspace, environment,
event, session, and agent. Create one exact disposable index, construct the
product store, index the A event, require one exact A result and zero B results,
then use the existing independent exact cleanup and prefix-wide audit. Preserve
legacy no-argument M0-08 output; accept only one exact `event-store` argument
for M1-14.

- [ ] **Step 6: Add lifecycle uncertainty and cleanup regressions**

Cover definitive index/document rejection, ambiguous and malformed success,
delayed visibility, exact-looking collisions, foreign scope, duplicate hits,
cleanup panic, cancellation, cleanup precedence, and prefix-wide extra-index
rejection. All cleanup reads use an independent bounded context.

- [ ] **Step 7: Run proof-module race and stability gates**

```bash
go test -C proofs/opensearch-event -race -count=1 ./...
for run in 1 2 3 4 5 6; do
  go test -C proofs/opensearch-event -count=1 ./...
done
test -z "$(cd proofs/opensearch-event && go mod tidy -diff)"
(cd proofs/opensearch-event && go mod verify)
(cd proofs/opensearch-event && go vet ./...)
```

---

### Task 4: Expose the exact disposable product proof

**Files:**
- Modify: `proofs/opensearch-event/run.mjs`
- Modify: `proofs/opensearch-event/run.test.mjs`
- Create: `proofs/opensearch-event/event-store-run.test.mjs`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/opensearch-event-store-contract.test.ts`
- Modify: `app/quality/opensearch-event-proof-contract.test.ts`

**Interfaces:**
- Consumes: exact M0-08 disposable target and M1-14 executable mode.
- Produces: `event:store:test`, `event:store:run`, exact M1-14 output, and
  retained byte-for-byte M0-08 commands/output.

- [ ] **Step 1: Add mode/orchestrator contracts before production**

Require only zero arguments for M0-08 or `--event-store` for M1-14; exact
proof-child argv; distinct exact success/failure lines; combined bounded child
output; hard deadline; exact temp identity reproof before removal; full-ID
container ownership and absence; and cleanup precedence. Reject any extra mode,
environment, provider target, or shared-target name.

- [ ] **Step 2: Capture focused Node RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  node --test proofs/opensearch-event/event-store-run.test.mjs
```

Expected: failures only for absent M1-14 mode/output/script behavior.

- [ ] **Step 3: Implement minimal mode-aware orchestration**

Pass `event-store` only to the product proof child, validate its exact fixed
line, and return the M1-14 container-cleanup line only after exact removal and
absence. Keep the existing no-argument M0-08 code path and output unchanged.

- [ ] **Step 4: Add root commands and supported-boundary documentation**

Add:

```json
"event:store:test": "go test -C services/platform -race -count=1 ./eventstore && go test -C proofs/opensearch-event -race -count=1 ./... && node --test proofs/opensearch-event/run.test.mjs proofs/opensearch-event/event-store-run.test.mjs",
"event:store:run": "node proofs/opensearch-event/run.mjs --event-store"
```

Document exact commands, mandatory scope, disposable-only support, prohibited
ambient configuration, and the non-parity boundary.

- [ ] **Step 5: Run six hermetic passes and all local gates**

```bash
for run in 1 2 3 4 5 6; do
  PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run event:store:test
done
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run proof:opensearch:event:test
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
```

- [ ] **Step 6: Run the exact live proof and audit cleanup**

Record the shared-target fingerprint read-only, require zero M1-14 proof
containers/temp directories before the run, execute exactly:

```bash
env -i HOME="$HOME" \
  PATH="$HOME/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" \
  npm run event:store:run
```

Require exit 0 and exactly:

```text
OpenSearch event store passed: index=true search=true scoped=true cross_organization_zero=true cleanup=true audit=true container_cleanup=true.
```

Then prove zero name/label/temp candidates and the shared fingerprint unchanged.

- [ ] **Step 7: Scan and commit the adapter/lifecycle package**

```bash
git commit -m "feat: prove scoped OpenSearch event store"
```

---

### Task 5: Review, complete, push, and close M1-14

**Files:**
- Modify only files required by review findings.
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/internal/2026-08-15-m1-14-opensearch-event-store-implementation-plan.md`
- Modify: completion-sensitive aggregate contracts under `app/quality/`
- Append ignored task and authoritative evidence ledgers.

**Interfaces:**
- Consumes: exact design-to-head diff, live evidence, all local gates, and an
  independent read-only review.
- Produces: zero-finding reviewed code, one M1-14 Complete row, no active task,
  M1-15 Pending, exact count transition, synchronized branch, and exact-SHA CI.

- [ ] **Step 1: Obtain independent review before status completion**

Review the exact design base through implementation head for product/provider
separation, mandatory scope, strict parsing, mutation reconciliation, deadline
and panic containment, candidate cleanup, fixed output, and evidence accuracy.
Every Critical, Important, and Minor finding receives a genuine tests-only RED,
minimal GREEN, full gates, a separate fix commit, and re-review.

- [ ] **Step 2: Capture completion-contract RED**

Change only the focused contract to require M1-14 Complete, overall
`681/0/44/3`, M1 `68/48/0/20/0`, no active task, and M1-15 Pending. Run it and
record failure against the still-In-progress docs.

- [ ] **Step 3: Transition only M1-14 to Complete**

Update README/tracker/evidence without changing blockers or later tasks. Mark
the 30 plan steps checked only after their evidence exists.

- [ ] **Step 4: Run final fresh verification and redacted scans**

Run six hermetic passes, all affected Go race/tidy/verify/vet gates, legacy
M0-08, full pinned repository verify/build, production audit, diff checks,
license inventory, exact live proof if production changed after the prior run,
and Gitleaks 8.30.1 across staged content, exact commits, all history, reports,
and ledgers.

- [ ] **Step 5: Commit, push, and watch exact-SHA CI**

```bash
git commit -m "docs: complete M1-14 OpenSearch EventStore"
git push origin codex/zasp-implementation
```

Require local HEAD, tracking, origin, and the Runnable UI run head SHA to
match; wait for terminal success. Then close the checked implementation plan in
a separate commit, push it, and require the closing exact-SHA CI success before
moving to M1-15.
