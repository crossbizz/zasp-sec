# M1-13 SQS Queue Interface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dependency-free Organization-scoped `JobQueue` and prove its
strict SQS batch adapter against an exact disposable LocalStack lifecycle.

**Architecture:** `services/platform/jobqueue` owns validated product jobs,
canonical scoped envelopes, bounded batches, opaque receipts, deadlines, and
fixed errors. `proofs/localstack-sqs` owns AWS SDK types, queue/DLQ identity,
redrive policies, strict SQS mapping, and the product-backed live lifecycle;
the existing hardened LocalStack runner gains an isolated M1-13 mode.

**Tech Stack:** Go 1.25 language/toolchain 1.26.5, dependency-free platform
package, current pinned AWS SDK for Go v2/SQS in the proof module, Node
22.23.1/npm 10.9.8 orchestration/contracts, LocalStack Community 4.7.0 exact
digest, Vitest, Go race detector, pinned Gitleaks 8.30.1.

## Global Constraints

- M1-12 must remain Complete; M1-14 remains Pending until this plan closes.
- Start counts are overall `682/1/42/3` and M1 `68/49/1/18/0`.
- Completion counts are overall `682/0/43/3` and M1 `68/49/0/19/0`.
- Product code imports no AWS SDK/provider type and performs no retry.
- Every job carries one validated Organization/Workspace/Environment scope.
- Batch count is 1 through 10; individual and aggregate bodies never exceed
  1,048,576 bytes; no hidden batch splitting or local queue is allowed.
- SQS provider identifiers, receipt handles, errors, endpoints, credentials,
  payloads, and proof names never enter public product results or fixed output.
- The M0-06 default proof remains compatible and the shared development
  LocalStack container is never selected, reconfigured, stopped, or removed.
- Live evidence proves LocalStack compatibility only, not real-AWS IAM,
  durability, availability, encryption, or release parity.

---

### Task 1: Start M1-13 with an exact repository contract

**Files:**
- Create: `app/quality/sqs-job-queue-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: affected aggregate status contracts under `app/quality/`
- Create ignored evidence under
  `.superpowers/sdd/2026-08-15-m1-13-sqs-queue-interface-implementation-plan/`

**Interfaces:**
- Consumes: authoritative M1-12 Complete row, M1-13 source task, design commit
  `2124637bf3c0db1a2996d80f85099176d463308d`, and current count contracts.
- Produces: exactly one M1-13 In-progress row and repository assertions that
  keep M1-12 Complete, M1-14 absent, and all blocker/risk rows unchanged.

- [x] **Step 1: Write the source/status contract before changing docs**

Assert the exact dependency, deliverable, LocalStack batch verification,
design path, current count tables, one active M1-13 row, one completed M1-12
row, no M1-14 active/complete row, and stable blocker/risk rows.

- [x] **Step 2: Run the focused contract and record Pending-state RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/sqs-job-queue-contract.test.ts
```

Expected: only the still-Pending M1-13 status assertion fails.

- [x] **Step 3: Move only M1-13 to In progress**

Update README/tracker and shared fixtures to `682/1/42/3` overall and M1
`68/49/1/18/0`. Do not change any other task or risk status.

- [x] **Step 4: Run focused/full pinned gates, scan, and commit**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run verify
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm run build:repo
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm audit --omit=dev
git diff --check
git commit -m "docs: start M1-13 SQS queue interface"
```

---

### Task 2: Implement the dependency-free JobQueue

**Files:**
- Create: `services/platform/jobqueue/queue_test.go`
- Create: `services/platform/jobqueue/queue.go`

**Interfaces:**
- Consumes: `domain.Scope`, `domain.ProductID`, Go contexts, JSON, SHA-256.
- Produces: `JobQueue`, `Queue`, `Driver`, `Config`, `Job`, `Delivery`,
  `Receipt`, `PublishResult`, `DriverMessage`, `DriverPublished`,
  `DriverDelivery`, `DriverReceipt`, and fixed errors.

- [x] **Step 1: Add missing-symbol tests before production**

Compile tests against these public shapes before `queue.go` exists:

```go
type Config struct {
    OperationTimeout time.Duration
    MaximumBatchMessages int
    MaximumMessageBytes int64
    MaximumBatchBytes int64
}

type Job struct {
    Scope domain.Scope
    JobID domain.ProductID
    Kind string
    Payload []byte
}

type PublishResult struct { JobIDs []domain.ProductID }
type Delivery struct { Job Job; Receipt Receipt }
type Receipt struct { jobID domain.ProductID; driver DriverReceipt }
func (receipt Receipt) JobID() domain.ProductID

type DriverMessage struct {
    EntryID string
    Scope domain.Scope
    JobID domain.ProductID
    Kind string
    Body []byte
    SHA256 [sha256.Size]byte
}

type DriverPublished struct { EntryID string; JobID domain.ProductID; MessageID string }
type DriverDelivery struct { Message DriverMessage; MessageID string; ReceiptHandle string }
type DriverReceipt struct { EntryID string; JobID domain.ProductID; MessageID string; ReceiptHandle string }

type JobQueue interface {
    PublishBatch(context.Context, []Job) (PublishResult, error)
    ConsumeBatch(context.Context, int) ([]Delivery, error)
    AcknowledgeBatch(context.Context, []Receipt) error
}

type Driver interface {
    PublishBatch(context.Context, []DriverMessage) ([]DriverPublished, error)
    ConsumeBatch(context.Context, int) ([]DriverDelivery, error)
    AcknowledgeBatch(context.Context, []DriverReceipt) ([]domain.ProductID, error)
}
```

Cover a two-job happy path, exact canonical bodies/metadata, exact publish IDs,
consume decoding, opaque receipts, exact acknowledge IDs, and defensive copies.

- [x] **Step 2: Run compiler RED**

```bash
go test -C services/platform ./jobqueue -count=1
```

Expected: compile failure only on missing JobQueue symbols; no production or
dependency edit may precede it.

- [x] **Step 3: Implement configuration, jobs, and canonical envelopes**

Implement fixed limits, exact kind grammar, full scope/nonzero job ID checks,
valid nonempty JSON payloads, duplicate-ID rejection, deterministic version-1
outer JSON, body SHA-256, exact body-size/aggregate limits, and defensive copies.

- [x] **Step 4: Implement bounded operations and opaque receipts**

Each public call validates before I/O, creates one total deadline, contains
driver panics, performs one driver call, and rejects partial/foreign/duplicate
results. `Receipt` retains provider state only in unexported fields and exposes
only `JobID() domain.ProductID`.

- [x] **Step 5: Expand adversarial RED/GREEN coverage**

Cover invalid/typed-nil drivers, zero/overlong configuration, invalid scope,
zero job ID, invalid kind, invalid/empty/oversized JSON, aggregate overflow,
11 jobs, duplicate IDs/receipts, malformed or mismatched driver state,
partial results, timeout, canceled context, errors, panics, aliasing, hostile
outer JSON keys/duplicates/trailing data, and 32 concurrent independent calls.

- [x] **Step 6: Run race and six stability passes**

```bash
go test -C services/platform -race -count=1 ./jobqueue
for run in 1 2 3 4 5 6; do
  go test -C services/platform -count=1 ./jobqueue
done
test -z "$(cd services/platform && go mod tidy -diff)"
(cd services/platform && go mod verify)
(cd services/platform && go vet ./...)
```

- [x] **Step 7: Scan and commit the product package**

```bash
git commit -m "feat: add scoped job queue"
```

---

### Task 3: Implement the SQS adapter and exact disposable lifecycle

**Files:**
- Modify: `proofs/localstack-sqs/go.mod`
- Modify: `proofs/localstack-sqs/go.sum`
- Modify: `proofs/localstack-sqs/sdk.go`
- Modify: `proofs/localstack-sqs/sdk_test.go`
- Modify: `proofs/localstack-sqs/proof.go`
- Modify: `proofs/localstack-sqs/proof_test.go`
- Modify: `proofs/localstack-sqs/main.go`
- Create: `proofs/localstack-sqs/job_queue.go`
- Create: `proofs/localstack-sqs/job_queue_test.go`
- Create: `proofs/localstack-sqs/job_queue_proof.go`
- Create: `proofs/localstack-sqs/job_queue_proof_test.go`
- Create: `proofs/localstack-sqs/run-job-queue.mjs`
- Create: `proofs/localstack-sqs/job-run.test.mjs`
- Modify: `proofs/localstack-storage/run.mjs`
- Modify: `proofs/localstack-storage/run.test.mjs`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/sqs-job-queue-contract.test.ts`
- Modify: `app/quality/localstack-sqs-proof-contract.test.ts`

**Interfaces:**
- Consumes: product `jobqueue.Driver`, exact-pinned `sdkQueueClient`, M0-06
  queue identity/redrive/strict-JSON helpers, hardened disposable runner.
- Produces: `sqsJobDriver`, M1-13 queue/DLQ lifecycle, `job-queue` CLI mode,
  hermetic/live root commands, and exact fixed product-proof output.

- [x] **Step 1: Write adapter/lifecycle/orchestrator tests before code**

Require one `SendMessageBatch` with two exact entries and six exact string
attributes per entry; strict receive body/attribute/digest matching; one
two-entry `DeleteMessageBatch`; exact publish/consume/ack product state; exact
redrive policies; source-then-DLQ cleanup; prefix-wide absence; and retained
M0-06 behavior.

- [x] **Step 2: Capture missing adapter/mode RED**

Run focused Go tests and `node --test proofs/localstack-sqs/job-run.test.mjs`.
Expected failures are only missing adapter/lifecycle/mode exports.

- [x] **Step 3: Add current product module and batch SDK operations**

Add local platform module replacement. Keep official SDK pins unchanged.
Implement multi-entry send/delete methods that preserve exact entry ordering,
return every success/failure ID, reject malformed output, and classify
definitive nonzero provider rejection separately from ambiguous transport or
malformed-success outcomes.

- [x] **Step 4: Implement the strict SQS product driver**

Map `DriverMessage` bodies and typed fields into exact SQS entries/attributes.
Reject any entry or aggregate batch whose body plus attribute names, data types,
and values exceeds the SQS 1 MiB quota.
On receive, require exact attributes/body digest/message ID/receipt handle and
return only validated typed deliveries. Publish and acknowledge accept only
exact full success sets; definitive rejection is never adopted or reconciled.

- [x] **Step 5: Implement the M1-13 queue/DLQ lifecycle**

Use a `zasp-m1-13-<marker>` namespace and atomic `m1-13` tags. Retain cleanup
authority after every create attempt; reconcile only typed ambiguity/malformed
success under an independent bounded context; prove redrive state, perform the
two-job product round trip by collecting distinct Standard-queue deliveries
across bounded calls without assuming order or a full batch, prove empty, clean
source then DLQ, and require a global M1-13 prefix audit. Cleanup failure wins
and later cleanup continues.

- [x] **Step 6: Add the disposable SQS runner mode**

Extend the reviewed runner configuration with SQS-only services, the
localstack-sqs build directory, separate name/labels/temp/executable, 150-second
child budget, full-ID candidates, and the exact child/outer lines:

```text
LocalStack job queue passed: publish=2 consume=2 acknowledge=2 scoped=true redrive=true empty=true cleanup=true audit=true.
LocalStack job queue passed: publish=2 consume=2 acknowledge=2 scoped=true redrive=true empty=true cleanup=true audit=true container_cleanup=true.
```

- [x] **Step 7: Add root commands and documentation**

```json
"job:queue:test": "go test -C services/platform -race -count=1 ./jobqueue && go test -C proofs/localstack-sqs -race -count=1 ./... && node --test proofs/localstack-sqs/job-run.test.mjs proofs/localstack-storage/run.test.mjs",
"job:queue:run": "node proofs/localstack-sqs/run-job-queue.mjs"
```

- [x] **Step 8: Run hermetic gates, then exact live proof**

Require the exact outer success line, zero pre/post M1-13 container-name and
proof-label counts, zero M1-13 temp paths, zero M1-13 queue-prefix results, and
an unchanged separately identified shared LocalStack fingerprint.

- [x] **Step 9: Scan and commit adapter/proof**

Run six root hermetic passes, both affected Go race/tidy/verify/vet gates,
retained M0-06 and M1-12 regressions, pinned full verification/build/audit,
diff checks, and pinned staged/history/evidence scans before:

```bash
git commit -m "feat: prove scoped LocalStack job queue"
```

---

### Task 4: Review, complete, push, and close

**Files:**
- Modify product/proof code and tests only for confirmed review findings.
- Modify README/tracker/aggregate contracts for completion.
- Modify this checklist only after exact completion CI succeeds.

**Interfaces:**
- Consumes: complete base-to-head M1-13 diff, live evidence, task report/ledger.
- Produces: zero-finding review, M1-13 Complete transition, pushed exact-SHA CI
  evidence, and a fully checked close commit.

- [x] **Step 1: Run independent whole-range review**

Audit scope/envelope identity, batch cardinality/bytes, payload ownership,
opaque receipts, deadlines, partial results, provider ambiguity, queue/DLQ and
redrive ownership, cleanup authorization, prefix-wide absence, runner fencing,
and retained M0-06/M1-12 behavior. Fix every finding tests-first until review is
zero-finding.

- [x] **Step 2: Capture completion RED and move only M1-13 to Complete**

Set overall counts to `682/0/43/3` and M1 to `68/49/0/19/0`. Keep M1-14
Pending and all blockers/risk rows unchanged.

- [x] **Step 3: Run final gates and scans**

Run six completion passes, all affected Go race/tidy/verify/vet gates, retained
proof regressions, exact live proof if review changed runtime code, the
eight-target build, pinned `npm run verify`, production audit, diff check, and
pinned staged/exact/history/evidence secret scans.

- [x] **Step 4: Commit, push, and watch exact completion SHA**

```bash
git commit -m "docs: complete M1-13 SQS queue interface"
git push origin codex/zasp-implementation
```

Require Runnable UI success for the exact completion SHA.

- [x] **Step 5: Close the plan and verify the close SHA**

Mark every checkbox complete, record exact completion run/job evidence, commit
`docs: close M1-13 SQS queue interface`, push, and require exact-SHA Runnable UI
success before starting M1-14.
