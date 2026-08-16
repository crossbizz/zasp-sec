# M1-21 Observability Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define exact bounded-cardinality common OTLP resource attributes and
a typed product/trace/span correlation context helper.

**Architecture:** Add one dependency-free Go package with a closed resource
attribute representation and closed correlation value. It emits no telemetry
and performs no I/O; adapters may consume only validated copies in later work.

**Tech Stack:** Go standard library, existing platform `domain` values,
Vitest repository contracts, npm root command wiring.

## Global constraints

- Every behavior and status change has a witnessed tests-only RED before its
  production or source edit.
- Resource output has exactly seven ordered string attributes and no arbitrary
  attribute map.
- Service and deployment values come only from fixed source catalogs; release
  versions use the exact bounded grammar in the design.
- Raw prompt/response text, tool arguments, secrets, evidence, stack traces,
  URLs, provider payloads, arbitrary customer content, and correlation IDs are
  prohibited as resource attributes.
- Correlation requires a typed product correlation ID plus exact nonzero
  lowercase 32-character trace and 16-character span IDs.
- Correlation replacement fails closed; the exact same context attachment is
  idempotent.
- There is no OpenTelemetry SDK/exporter, Collector, remote backend, network,
  credential, environment, filesystem, database, Docker, provider, or shared
  resource I/O.
- M1-22 remains Pending throughout M1-21. M0-09, M0-18, and M0-19 remain
  Blocked.

---

### Task 1: Start M1-21 with a repository contract

**Files:**

- Create: `app/quality/observability-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current aggregate status fixtures under `app/quality`
- Create ignored evidence:
  `.superpowers/sdd/2026-08-16-m1-21-observability-contract-implementation-plan/task-1-report.md`
- Create ignored append-only ledger:
  `.superpowers/sdd/2026-08-16-m1-21-observability-contract-implementation-plan/progress.md`

**Interfaces:**

- Consumes: authoritative M1-21 source task, PRD observability/privacy rules,
  M0-13/M0-22 proof names, design, and this plan.
- Produces: exact repository status and documentation contract used by every
  later M1-21 task.

- [x] **Step 1: Write the failing status/source contract**

  Add three Vitest cases. Bind the source section from M1-21 through M1-22;
  require the exact deliverable and raw-content verification. Bind the PRD
  metadata-first and observability prohibitions, the seven design keys, M0-13/
  M0-22 compatibility, M1-20 Complete, M1-22 absent, exact blocker rows, and
  the expected active arithmetic.

  ```ts
  expect(tracker).toContain("| Pending | 674 |");
  expect(tracker).toContain("| In progress | 1 |");
  expect(tracker).toContain("| Complete | 50 |");
  expect(m1).toEqual(["M1", "68", "41", "1", "26", "0"]);
  expect(active.filter(([task]) => task === "M1-21")).toHaveLength(1);
  expect(complete.filter(([task]) => task === "M1-20")).toHaveLength(1);
  expect([...active, ...complete].some(([task]) => task === "M1-22")).toBe(false);
  ```

  The first tests-only run exposed one incorrect expectation about which
  M0-13 file carries the service keys. After correcting the test to bind the
  executable normalizer, the genuine RED was 1 pass/1 intended fail solely at
  stale M1-21 README/tracker status.

- [x] **Step 2: Run the focused test and verify the intended RED**

  Run from repository root with pinned Node 22.23.1/npm 10.9.8:

  ```bash
  npx vitest run app/quality/observability-contract.test.ts
  ```

  Expected: source/design checks pass and only stale README/tracker status
  assertions fail. A syntax, path, or fixture failure is not the required RED.

- [x] **Step 3: Move only M1-21 to In progress**

  Add one M1-21 In-progress row and README boundary. Change aggregate counts to
  overall `674/1/50/3` and M1 `68/41/1/26/0`. Update only aggregate fixtures
  whose exact current-count assertions become stale. Keep M1-20 Complete,
  M1-22 Pending, and all three blockers unchanged.

  Only M1-21 is active at overall `674/1/50/3` and M1
  `68/41/1/26/0`. All current aggregate fixtures require exactly that active
  row, not merely a one-row count.

- [x] **Step 4: Verify focused and complete quality GREEN**

  ```bash
  npx vitest run app/quality/observability-contract.test.ts
  npx vitest run app/quality
  git diff --check
  ```

  Expected: zero failures and arithmetic equal to 728 source tasks.

  GREEN is 2/2 focused, 5/5 with the M1-20 predecessor contract, and 54
  quality files/242 tests.

- [x] **Step 5: Record evidence and commit**

  Record exact RED/GREEN counts and touched paths in ignored evidence. Scan the
  staged diff and evidence with pinned redacted Gitleaks v8.30.1, then commit:

  ```bash
  git commit -m "docs: start M1-21 observability contract"
  ```

---

### Task 2: Implement the closed observability values tests-first

**Files:**

- Create first: `services/platform/observability/observability_test.go`
- Create only after compiler RED:
  `services/platform/observability/observability.go`
- Modify: this plan's Task 2 checkboxes
- Append ignored Task 2 report and progress evidence

**Interfaces:**

- Consumes: `domain.Scope`, `domain.CorrelationID`, and Go `context.Context`.
- Produces:

  ```go
  type Service string
  const ServiceAPI Service = "agentsec-api"
  const ServiceWorker Service = "agentsec-worker"

  type Deployment string
  const DeploymentDevelopment Deployment = "development"
  const DeploymentTest Deployment = "test"
  const DeploymentStaging Deployment = "staging"
  const DeploymentProduction Deployment = "production"

  type StringAttribute struct { Key, Value string }
  type ResourceAttributes struct { values [7]StringAttribute }
  func NewResourceAttributes(domain.Scope, Service, string, Deployment) (ResourceAttributes, error)
  func (ResourceAttributes) OTLP() []StringAttribute
  func ValidateResourceAttributes([]StringAttribute) error

  type Correlation struct {
      correlationID domain.CorrelationID
      traceID       string
      spanID        string
  }
  func NewCorrelation(domain.CorrelationID, string, string) (Correlation, error)
  func (Correlation) Validate() error
  func (Correlation) CorrelationID() domain.CorrelationID
  func (Correlation) TraceID() string
  func (Correlation) SpanID() string
  func WithCorrelation(context.Context, Correlation) (context.Context, error)
  func CorrelationFromContext(context.Context) (Correlation, bool)
  ```

- [ ] **Step 1: Write the wished-for API and happy-path tests**

  Construct three distinct canonical product IDs, one scope, one correlation
  ID, service API, version `1.2.3`, and deployment test. Assert exact ordered
  output:

  ```go
  []StringAttribute{
      {Key: "service.namespace", Value: "agentsec"},
      {Key: "service.name", Value: "agentsec-api"},
      {Key: "service.version", Value: "1.2.3"},
      {Key: "deployment.environment.name", Value: "test"},
      {Key: "organization.id", Value: scope.OrganizationID().String()},
      {Key: "workspace.id", Value: scope.WorkspaceID().String()},
      {Key: "environment.id", Value: scope.EnvironmentID().String()},
  }
  ```

  Assert a correlation with trace ID
  `0123456789abcdef0123456789abcdef` and span ID `0123456789abcdef`
  attaches to and reads from context exactly.

- [ ] **Step 2: Run and verify genuine compiler RED**

  ```bash
  go test -C services/platform ./observability
  ```

  Expected: compile failure only on absent `observability` public symbols. No
  production file or dependency edit may precede this run.

- [ ] **Step 3: Implement minimal happy-path GREEN**

  Store the seven attributes in a fixed internal array; return a copied slice.
  Validate service/deployment by exact switch, version byte-by-byte, product
  IDs through `domain.ParseProductID` plus `domain.NewScope`, and correlation
  IDs through their typed accessors. Use one unexported context-key type.

  ```go
  var (
      ErrResource    = errors.New("observability resource rejected")
      ErrCorrelation = errors.New("observability correlation rejected")
  )
  ```

  Run the focused test and require the exact happy tests to pass.

- [ ] **Step 4: Add resource adversarial RED/GREEN coverage**

  Reject zero/forged scope, unknown service/deployment, empty/oversized/
  Unicode/control/leading/trailing/adjacent-separator versions, missing keys,
  reordered keys, duplicates, wrong product-scope order, and unknown/aliased/
  extra keys. Explicitly reject `prompt.text`, `response.text`,
  `tool.arguments`, `secret.value`, `raw_evidence`, `stack_trace`, `url`,
  `customer.content`, and `correlation.id`. Prove the returned slice does not
  mutate the retained value.

- [ ] **Step 5: Add correlation adversarial RED/GREEN coverage**

  Reject zero/forged product correlation, empty/short/long/uppercase/non-hex/
  all-zero trace and span IDs, nil context, invalid stored values, and
  replacement with a different correlation. Prove exact reattachment is
  idempotent, missing/nil reads return false, context siblings do not share
  values, and concurrent independent context trees are race-safe.

- [ ] **Step 6: Run focused stability, platform, and coverage gates**

  ```bash
  for run in 1 2 3 4 5 6; do go test -C services/platform -race -count=1 ./observability; done
  go test -C services/platform -count=100 ./observability
  go test -C services/platform -race -count=1 ./...
  go test -C services/platform -coverprofile=/tmp/m1-21-cover.out ./observability
  go tool cover -func=/tmp/m1-21-cover.out
  go mod tidy -diff -C services/platform
  go mod verify -C services/platform
  go vet -C services/platform ./...
  ```

  Expected: all commands exit zero and production statement coverage is 100%.

- [ ] **Step 7: Record evidence and commit**

  Scan exact new paths, staged diff, and ignored evidence with pinned redacted
  Gitleaks, then commit:

  ```bash
  git commit -m "feat: add bounded observability contract"
  ```

---

### Task 3: Expose the hermetic root contract

**Files:**

- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/observability-contract.test.ts`
- Modify: this plan's Task 3 checkboxes
- Append ignored Task 3 report and progress evidence

**Interfaces:**

- Consumes: the Task 2 Go package and race suite.
- Produces: root command `observability:test` and exact documentation boundary.

- [ ] **Step 1: Add the missing-wiring assertions and capture RED**

  Require:

  ```ts
  expect(packageJson.scripts["observability:test"])
    .toBe("go test -C services/platform -race -count=1 ./observability");
  ```

  Require a README `## Observability contract` section naming all seven keys,
  fixed service/deployment catalogs, raw-content prohibition, typed
  correlation/context behavior, hermetic scope, and M1-22 Pending. Run the
  focused contract; expected failure is only absent script/docs.

- [ ] **Step 2: Add the root command and README section**

  Make the smallest package/README edits satisfying the exact contract. Do not
  add an OTLP SDK, exporter, adapter, backend, credential, or environment
  wiring.

- [ ] **Step 3: Run root, focused, full pinned, audit, and formatting gates**

  ```bash
  npm run observability:test
  npx vitest run app/quality/observability-contract.test.ts
  npm run verify
  npm audit --omit=dev
  git diff --check
  ```

  Also run `npm run build:repo` and require its exact eight repository build
  targets to pass. Require zero production vulnerabilities.

- [ ] **Step 4: Record evidence and commit**

  Scan the staged diff and evidence, then commit:

  ```bash
  git commit -m "docs: expose observability contract"
  ```

---

### Task 4: Review the complete M1-21 range

**Files:**

- Review: exact pre-design base through Task 3 head
- Modify tests and production only for independently reproduced findings
- Modify: this plan's Task 4 checkboxes
- Append ignored Task 4 report and progress evidence

**Interfaces:**

- Consumes: source task, PRD, M0-13/M0-22 evidence, design, plan, code, tests,
  root wiring, README, status, and evidence.
- Produces: zero-finding readiness verdict or separate tests-first fix commits.

- [ ] **Step 1: Perform an end-to-end read-only review**

  Check exact attribute keys/order/value grammars, raw-content rejection,
  scope integrity, correlation identity/context replacement, copy isolation,
  zero/forged direct states, concurrency, root/docs/status arithmetic, and
  absence of adapter/I/O authority.

- [ ] **Step 2: Reproduce every finding with tests-only RED**

  For each valid finding, add the smallest adversarial test first and run it
  against the current implementation. Do not edit production until the
  intended failure is observed. If no finding survives, record Critical 0,
  Important 0, Minor 0 without manufacturing a fix.

- [ ] **Step 3: Fix one finding at a time and repeat all affected gates**

  Each fix must be minimal, independently GREEN, and committed separately.
  Repeat focused race, full platform, root, full pinned repository, audit,
  diff, and redacted secret gates after the final fix.

- [ ] **Step 4: Record the final review boundary**

  When no tracked fix is required in the last review round, check the plan and
  commit only its tracked review record:

  ```bash
  git commit -m "docs: record M1-21 review"
  ```

---

### Task 5: Complete, push, and close M1-21

**Files:**

- Modify first for RED: `app/quality/observability-contract.test.ts`
- Modify after RED: `README.md`
- Modify after RED: `docs/internal/implementation_status_v1.5.md`
- Modify after RED: current aggregate status fixtures under `app/quality`
- Modify: this plan's completion/closure checkboxes
- Append ignored Task 5, authoritative M1-21, and progress evidence

**Interfaces:**

- Consumes: zero-finding Task 4 verdict and every required green gate.
- Produces: exact completion commit, exact-SHA CI success, and plan-only closure.

- [ ] **Step 1: Change only the completion assertions and capture RED**

  Require exactly one M1-21 Complete row, no active source task, M1-20
  Complete, M1-22 absent, unchanged blockers, overall `674/0/51/3`, and M1
  `68/41/0/27/0`. Run the focused contract. Expected: only stale In-progress
  README/tracker/count assertions fail.

- [ ] **Step 2: Move only M1-21 to Complete and obtain GREEN**

  Update README, tracker, and aggregate fixtures. Run focused/quality tests,
  six root race cycles, 100 repetitions, full platform race/tidy/module/vet,
  100% coverage, pinned full repository verification, all build targets,
  production audit, diff checks, and pinned staged/history/evidence secret
  scans.

- [ ] **Step 3: Commit, push, and verify completion CI**

  ```bash
  git commit -m "docs: complete M1-21 observability contract"
  git push origin codex/zasp-implementation
  ```

  Prove local/upstream/remote equality, locate the Runnable UI run for the
  exact completion SHA, and wait to terminal success. Record run and job IDs
  in all ignored evidence files.

- [ ] **Step 4: Commit and push the plan-only closure**

  Check the remaining plan boxes without advancing M1-22, scan, then commit:

  ```bash
  git commit -m "docs: close M1-21 observability contract"
  git push origin codex/zasp-implementation
  ```

  Wait for exact closure-SHA Runnable UI success. Record its run/job IDs, scan
  all history and evidence, and prove local/upstream/remote equality plus a
  clean tracked tree and index.
