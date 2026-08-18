# M1-33 SQS Queue Definitions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the three exact product SQS queues and paired DLQs with closed message-schema metadata and bounded baseline settings, then prove all six against one disposable exact-pinned LocalStack lifecycle.

**Architecture:** A dependency-free `services/platform/queuedefinition` package owns immutable provider-neutral definitions and deterministic JSON. The existing reviewed M1-13 LocalStack runner gains an isolated `queue-definitions` mode whose child provisions, re-reads, and exactly cleans all six resources without targeting shared state.

**Tech Stack:** Go 1.25.6 standard library, existing AWS SDK for Go v2 proof module, LocalStack 4.7.0 exact digest, Node.js 22.23.1, npm 10.9.8, Vitest/Node test, pinned Gitleaks 8.30.1, GitHub Runnable UI.

**Spec:** `docs/internal/2026-08-18-m1-33-sqs-queue-definitions-design.md`

## Global constraints

- Preserve M1-32 exactly once in Complete and keep M1-34 Pending.
- Keep blockers exactly M0-09, M0-18, and M0-19.
- Define only the three source names and their exact `-dlq` pairs.
- Keep every queue Standard and all configuration explicit.
- Use 345600-second source retention, 1209600-second DLQ retention, 20-second wait, 262144-byte messages, five receives, and exact per-kind visibility.
- Freeze schema metadata only; do not implement M1-41 Organization-envelope authorization or M2 consumers.
- Do not add production encryption/IAM/alarm/hardening claims before M8-03 or Terraform before M1A-04.
- The live proof must use one exact-owned disposable LocalStack container and leave all queue, container, and temp prefixes absent.
- Never read `.env`, profiles, IMDS, real AWS credentials, proxy values, shared Docker authentication, or a shared LocalStack endpoint.
- Every mutation is one attempt; only genuinely ambiguous results enter bounded exact reconciliation.
- Cleanup failure wins, later cleanup continues, and destructive cleanup requires fresh exact ownership.
- Use genuine tests-first RED/GREEN for production behavior and every review fix.
- Keep the UI runnable at every push and require exact-SHA Runnable UI success before closure.

---

### Task 1: Start M1-33 with exact source and status contracts

**Files:**
- Create: `app/quality/sqs-queue-definitions-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current status/count fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-33 source row, committed design, M1-32 Complete state, and exact blocker set.
- Produces: exact M1-33 In-progress status at overall `654/1/70/3` and M1 `68/21/1/46/0`.

- [ ] **Step 1: Write the failing source, design, and status contract**

Parse the exact M1-33 source section and require its dependency, deliverable,
verification, and timebox literals. Bind the selected package, all six names,
three schema IDs, exact settings, strict live-proof namespace, M1-41/M1A-04/
M8-03 deferrals, and no real AWS or shared LocalStack authority.

Require M1-33 as the sole active row, M1-32 exactly once in Complete, M1-34
absent from active and complete rows, and blockers exactly M0-09, M0-18, and
M0-19.

- [ ] **Step 2: Witness focused status RED**

Run:

```sh
npm exec vitest run \
  app/quality/sqs-queue-definitions-contract.test.ts \
  app/quality/event-index-template-contract.test.ts
```

Expected: the new contract fails only because M1-33 is absent, counts remain
`655/0/70/3`, and README does not name active M1-33. M1-32 stays green.

- [ ] **Step 3: Move only M1-33 to In progress**

Change overall `655/0/70/3` to `654/1/70/3` and M1 `68/22/0/46/0` to
`68/21/1/46/0`. Add exactly one current row:

```markdown
| M1-33 | August 18, 2026 | Defining the three exact product SQS queues and paired DLQs with closed schema metadata, bounded baseline settings, and disposable LocalStack verification. |
```

Update only current count/status fixtures mechanically. Preserve historical
mutation fixtures, M1-32 Complete, M1-34 Pending, and every blocker.

- [ ] **Step 4: Run focused and full quality GREEN**

Require exact 728-task arithmetic, active rows `['M1-33']`, 70 complete rows,
one completed M1-32, no active/complete M1-34, and exact blockers. Run the
focused pair and full pinned `npm test`.

- [ ] **Step 5: Scan and commit the start transition**

Run staged whitespace and pinned redacted Gitleaks checks. Commit only the
status/README/quality slice as:

```text
docs: start M1-33 SQS queue definitions
```

---

### Task 2: Build immutable product definitions tests-first

**Files:**
- Create: `services/platform/queuedefinition/definitions_test.go`
- Create: `services/platform/queuedefinition/definitions.go`

**Interfaces:**
- Consumes: the exact architecture queue names and existing M1-13 background envelope.
- Produces: immutable `Definition`, copied schema fields/settings, exact `Definitions`, and deterministic `JSON`.

- [ ] **Step 1: Write compiler-failing public contract tests**

Create `definitions_test.go` first. Require three valid definitions in exact
background/runtime-events/tests order. Assert exact kinds, source/DLQ names,
schema IDs, seven required fields, source/DLQ retention, visibility, wait,
message bytes, and max receive count.

Also require the exact zero source/DLQ delay and distinct 30-second DLQ
visibility. Require `Definition{}` accessors to return zero values and
`Validate` to return exact `ErrDefinitions`.

- [ ] **Step 2: Witness absent-package RED**

Run:

```sh
go test -C services/platform ./queuedefinition -count=1
```

Expected: FAIL because every requested production API is absent. Record the
exact compiler failure before creating `definitions.go`.

- [ ] **Step 3: Add independent exact JSON and copy tests**

Pin compact JSON plus one newline with exact top-level keys and the three exact
definitions. Decode it with a duplicate-key-rejecting test helper. Mutate every
returned definition, field slice, settings copy, and JSON byte and prove later
calls remain canonical. Run the same public calls concurrently under race.

- [ ] **Step 4: Add hostile definition mutations**

In the package test, forge every private field independently. Cover zero and
unknown kind, source/DLQ name or suffix drift, schema drift, missing/extra/
reordered/duplicate/dotted/control/invalid-UTF8/oversized required fields, and
every numeric-setting drift. Require only exact `ErrDefinitions`, never wrapped
or content-bearing errors.

- [ ] **Step 5: Implement the minimal immutable value**

Use one private `[7]string` field array in each comparable `Definition` and a
function that creates a fresh canonical `[3]Definition`. `Definitions` returns
a copied slice. Validation compares each candidate against the canonical value
at the same kind. Accessors validate first and return copied values.

Use private JSON structs and `json.Marshal`; append one newline to fresh bytes.
No provider package, map, caller-supplied configuration, environment, I/O,
clock, or random boundary belongs in production.

- [ ] **Step 6: Run focused stability and full platform gates**

Run six focused race passes, full platform race, tidy-diff, module verification,
and vet. Confirm `services/platform/go.mod` and `go.sum` remain unchanged.

- [ ] **Step 7: Review and commit the package slice**

Review exact schema/settings/bytes, zero and forged state, fresh copies, fixed
errors, concurrency, and every hostile field. Add tests-first fixes for any
gap, scan, and commit exactly the two files as:

```text
feat: define product SQS queues and DLQs
```

---

### Task 3: Add the exact six-queue LocalStack child lifecycle

**Files:**
- Create: `proofs/localstack-sqs/queue_definitions_proof_test.go`
- Create: `proofs/localstack-sqs/queue_definitions_proof.go`
- Modify: `proofs/localstack-sqs/main.go`
- Create: `proofs/localstack-sqs/main_test.go`
- Modify: `proofs/localstack-sqs/sdk.go`
- Modify: `proofs/localstack-sqs/sdk_test.go`
- Modify: `proofs/localstack-sqs/job_queue_proof.go`
- Modify: `proofs/localstack-sqs/job_queue_proof_test.go`
- Modify: `proofs/localstack-sqs/go.mod`
- Modify: `proofs/localstack-sqs/go.sum`

**Interfaces:**
- Consumes: `queuedefinition.Definitions`, existing strict dynamic-port SDK boundary, exact JSON policy parser, and mutation classification.
- Produces: `RunQueueDefinitionsProof`, fixed child mode/output, exact six-resource cleanup/audit result.

- [ ] **Step 1: Write lifecycle/compiler RED with a complete fake**

Add a complete fake implementing the real queue client's list/create/read/tag/
set/delete effects. Require DLQ-before-source creation for each definition,
exact source scalar attributes/redrive policy, exact DLQ scalar attributes and
paired `byQueue` allow policy, and one exact read-back of all six names, URLs,
ARNs, tags, attributes, and Standard-queue state.

Run the focused test before production. Expected: compiler failure for absent
`RunQueueDefinitionsProof` and public result/options types while existing SQS
tests remain green.

- [ ] **Step 2: Add exact mutation classification RED**

Cover definitive rejection with no adoption; thrown, timeout/signaled, and
malformed-success create reconciled through bounded exact visibility; delayed
application; empty/transient list; foreign tag/ARN/URL/attribute replacement;
duplicate names; and unexpected extra exact-name candidates.

Arm candidate authority before result interpretation. A first absent read is
not final proof for an ambiguous mutation; poll within the retained bounded
context.

- [ ] **Step 3: Add cleanup and audit RED**

Require independent cleanup context, source-first then DLQ reverse dependency
order, fresh ownership before each deletion, exact absence after acknowledged or
ambiguous deletion, later cleanup after failure/panic, cleanup failure
precedence, and final exact six-name plus global M1-33 namespace absence.

Include delayed-applied create during main cancellation, re-arm panic, foreign
replacement, and one target refusing cleanup while all later targets are still
attempted.

- [ ] **Step 4: Implement minimal child lifecycle**

Use the exact three product definitions; do not duplicate constants in the proof.
Create one retained target per source/DLQ, with exact marker/proof/role/kind/
schema/pair tags. Use one-attempt mutations and bounded read reconciliation.
Keep source redrive and DLQ allow policies duplicate-key-safe and exact.

Return only fixed internal categories. Extend `main.go` with the exact
`queue-definitions` argument and child success:

```text
LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true.
```

Failures are exactly:

```text
LocalStack queue definitions failed: <category> rejected.
```

- [ ] **Step 5: Run all proof-module gates**

Run the new focused tests six times, then the full proof module with race,
tidy-diff, module verification, and vet. Confirm existing M0-06/M1-13 behavior
remains green. Align the proof module's existing AWS SDK requirements with the
already-pinned platform module patch versions; require tidy-diff and module
verification after that deterministic dependency-file update.

- [ ] **Step 6: Review and commit the child slice**

Review every authoritative field, mutation result, retained candidate, cleanup
branch, fixed line, and cross-definition relationship. Add tests-first fixes,
scan, and commit only the child implementation, tests, and aligned module files
as:

```text
feat: provision exact LocalStack queue definitions
```

---

### Task 4: Wire the disposable runner, root commands, docs, and live proof

**Files:**
- Create: `proofs/localstack-sqs/run-queue-definitions.mjs`
- Create: `proofs/localstack-sqs/queue-definitions-run.test.mjs`
- Modify: `proofs/localstack-storage/run.mjs`
- Modify: `proofs/localstack-storage/run.test.mjs`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/sqs-queue-definitions-contract.test.ts`

**Interfaces:**
- Consumes: the reviewed LocalStack container supervisor and new child mode.
- Produces: hermetic `sqs:definitions:test`, opt-in `sqs:definitions:run`, exact live evidence, and bounded operator documentation.

- [ ] **Step 1: Write runner-mode RED**

Require a distinct `QUEUE_DEFINITIONS_MODE`, exact `zasp-m1-33-<marker>` name,
`zasp.proof=m1-33`, SQS-only service list, explicit dynamic endpoint strategy,
new child argument/executable/deadline/success/failure lines, and unchanged
storage/artifact/job-queue modes. Test unknown mode rejection.

- [ ] **Step 2: Add ownership/deadline/cleanup RED**

Use complete Docker fixtures. Require exact image ID/ref, labels, environment,
loopback-only port, no ambient credential/proxy/profile, hard-kill child bound,
combined bounded output, exact temp identity/revalidation, ambiguous container
create reconciliation, fresh cleanup ownership, absence, and cleanup precedence.

- [ ] **Step 3: Implement the minimal runner mode**

Add only the new immutable mode configuration and thin entry point. Reuse the
reviewed supervisor rather than forking it. The outer success is exactly:

```text
LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true container_cleanup=true.
```

- [ ] **Step 4: Write root/documentation RED**

Extend the quality contract to require exact scripts:

```json
"sqs:definitions:test": "go test -C services/platform -race -count=1 ./queuedefinition && go test -C proofs/localstack-sqs -race -count=1 ./... && node --test proofs/localstack-sqs/queue-definitions-run.test.mjs proofs/localstack-storage/run.test.mjs",
"sqs:definitions:run": "node proofs/localstack-sqs/run-queue-definitions.mjs"
```

Require a README section with all six names, schema IDs, exact settings,
hermetic/live commands, fixed output, disposable-only authority, M1-41/M1A-04/
M8-03 deferrals, M1-32 Complete, and M1-34 Pending.

- [ ] **Step 5: Add wiring and run hermetic GREEN**

Add scripts and docs, then run the new root test, focused quality contract, full
proof/platform gates, dependency validation, full pinned repository verify,
production audit, syntax/lint, and diff checks.

- [ ] **Step 6: Run the exact live lifecycle**

Preflight exact M1-33 queue/container/temp prefixes and record any known shared
LocalStack fingerprint without changing it. Run only:

```sh
env -i PATH="$PATH" HOME="$HOME" npm run sqs:definitions:run
```

Require exit 0 and the sole fixed success line. Immediately prove all six exact
queue names absent through a fresh isolated audit, M1-33 container/temp prefixes
zero, and any known shared LocalStack fingerprint unchanged.

- [ ] **Step 7: Review and commit runner/root/docs slices**

Keep production runner/tests in one atomic commit if review fixes are required;
keep root/docs/quality wiring separate. Run staged scans and commit the final
wiring as:

```text
docs: expose SQS queue definitions proof
```

---

### Task 5: Review, complete, push, and close M1-33

**Files:**
- Modify only for review fixes: exact M1-33 range files
- Modify: `app/quality/sqs-queue-definitions-contract.test.ts`
- Modify: current count/status fixtures under `app/quality/`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/internal/2026-08-18-m1-33-sqs-queue-definitions-implementation-plan.md`
- Create ignored evidence under `.superpowers/sdd/2026-08-18-m1-33-sqs-queue-definitions-implementation-plan/`

**Interfaces:**
- Consumes: the entire reviewed M1-33 range and exact live evidence.
- Produces: zero-finding implementation, exact Complete status, successful exact-SHA CI, and a closed plan.

- [ ] **Step 1: Obtain zero-finding whole-range review**

Review source/design/plan/package/proof/runner/root/docs/tracker and evidence.
Focus on mutable aliases, schema or settings drift, provider attributes,
definitive-versus-ambiguous mutations, eventual consistency, cleanup authority,
foreign replacement, output secrecy, ambient authority, shared-resource safety,
false Organization/encryption/production claims, and weak test doubles.

For every verified finding, add a focused failing regression, witness RED, make
the minimal fix, run GREEN, commit separately, and repeat until Critical 0,
Important 0, Minor 0.

- [ ] **Step 2: Run the final matrix**

Run six product/proof focused race passes; full platform and proof race/tidy/
verify/vet; runner/root/focused/full pinned Node tests; typecheck/lint/build;
dependency validation; production audit; exact live proof and cleanup audit;
diff checks; and pinned Gitleaks over range, each commit, tracked HEAD/history,
and ignored evidence. Require clean tracked tree/index.

- [ ] **Step 3: Write completion-contract RED**

Change only the M1-33 contract to require overall `654/0/71/3`, M1
`68/21/0/47/0`, no active row, 71 Complete rows, exactly one completed M1-32
and M1-33, M1-34 absent from active/complete, and exact blockers. Run focused
RED against the still-In-progress tracker.

- [ ] **Step 4: Transition only M1-33 to Complete**

Move the exact row, update current arithmetic/README/fixtures mechanically, and
repeat focused/full gates. Commit as:

```text
docs: complete M1-33 SQS queue definitions
```

- [ ] **Step 5: Push completion and verify exact-SHA CI**

Push `codex/zasp-implementation`, prove local/origin/tracking equality, and
watch Runnable UI for the exact completion SHA to terminal success. Record run
and job URLs. Do not close the plan before success.

- [ ] **Step 6: Close, push, and verify the plan**

Mark all plan checkboxes complete in one plan-only commit:

```text
docs: close M1-33 SQS queue definitions plan
```

Push and require exact-SHA Runnable UI success. Prove final refs equal, status
`654/0/71/3`, M1 `68/21/0/47/0`, M1-34 Pending, exact blockers, complete plan,
zero scan findings, and clean tracked tree/index before continuing.
