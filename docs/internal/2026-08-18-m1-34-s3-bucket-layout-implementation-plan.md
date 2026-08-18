# M1-34 S3 Bucket Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define one immutable provider-neutral S3 bucket layout with exact evidence, export, and policy key prefixes plus a strict same-account/same-Region customer-managed SSE-KMS contract.

**Architecture:** A dependency-free `services/platform/bucketlayout` package validates deployment-owned bucket/KMS identity and constructs keys only from the existing opaque `domain.Scope` and `domain.ProductID` values. It performs no provider I/O. Root documentation and one hermetic command expose the contract; M1A-03 and M8-02 remain responsible for AWS resources and hardening.

**Tech Stack:** Go 1.25.6 standard library, existing `services/platform/domain`, Node.js 22.23.1, npm 10.9.8, Vitest, pinned Gitleaks 8.30.1, GitHub Runnable UI.

**Spec:** `docs/internal/2026-08-18-m1-34-s3-bucket-layout-design.md`

## Global constraints

- Preserve M1-33 exactly once in Complete and keep M1-35 Pending.
- Keep blockers exactly M0-09, M0-18, and M0-19.
- Use only the three exact class segments `evidence`, `exports`, and `policies`.
- Build every object key beneath the exact Organization/Workspace/Environment hierarchy from existing opaque product IDs.
- Accept no raw key, suffix, path, filename, URL encoding, provider-native ID, or arbitrary segment.
- Require exact bucket name form `zasp-product-data-<32-lowercase-hex>`.
- Require one fully qualified customer-managed KMS key ARN whose partition, Region, and account match validated configuration.
- Fix encryption to `aws:kms` with S3 Bucket Key enabled; do not accept algorithm or boolean overrides.
- Do not provision S3/KMS, add an AWS SDK, read the environment, or perform network I/O.
- Do not modify the M1-12 ArtifactStore before M1-40's cross-Organization integration task.
- Do not claim Terraform, IAM, versioning, retention/lifecycle, symmetric/enabled key state, or production hardening before M1A-03/M8-02.
- Use genuine tests-first RED/GREEN for production behavior and every review fix.
- Keep the UI runnable at every push and require exact-SHA Runnable UI success before closure.

---

### Task 1: Start M1-34 with exact source, design, and status contracts

**Files:**
- Create: `app/quality/s3-bucket-layout-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current status/count fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-34 source row, this design, M1-33 Complete state, and exact blocker set.
- Produces: exact M1-34 In-progress status at overall `653/1/71/3` and M1 `68/20/1/47/0`.

- [x] **Step 1: Write the failing source, design, and status contract**

Parse the exact M1-34 source section and require its dependency, deliverable,
verification, and timebox literals. Bind the selected package, exact three
prefixes, workspace-root grammar, bucket name grammar, KMS relationship,
fixed encryption, M1-40/M1A-03/M8-02 deferrals, no provider command, and no raw
key input.

Require M1-34 as the sole active row, M1-33 exactly once in Complete, M1-35
absent from active and complete rows, and blockers exactly M0-09, M0-18, and
M0-19.

- [x] **Step 2: Witness focused status RED**

Run:

```sh
npm exec vitest run \
  app/quality/s3-bucket-layout-contract.test.ts \
  app/quality/sqs-queue-definitions-contract.test.ts
```

Expected: the new contract fails only because M1-34 is absent, counts remain
`654/0/71/3`, and README does not name active M1-34. M1-33 stays green.

- [x] **Step 3: Move only M1-34 to In progress**

Change overall `654/0/71/3` to `653/1/71/3` and M1 `68/21/0/47/0` to
`68/20/1/47/0`. Add exactly one current row:

```markdown
| M1-34 | August 18, 2026 | Defining one immutable Organization/Workspace/Environment S3 layout with exact evidence, export, and policy prefixes plus a strict customer-managed SSE-KMS configuration contract. |
```

Update only current count/status fixtures mechanically. Preserve historical
mutation fixtures, M1-33 Complete, M1-35 Pending, and every blocker.

- [x] **Step 4: Run focused and full quality GREEN**

Require exact 728-task arithmetic, active rows `['M1-34']`, 71 complete rows,
one completed M1-33, no active/complete M1-35, and exact blockers. Run the
focused pair and full pinned `npm test`.

- [x] **Step 5: Scan and commit the start transition**

Run staged whitespace and pinned redacted Gitleaks checks. Commit only the
status/README/quality slice as:

```text
docs: start M1-34 S3 bucket layout
```

---

### Task 2: Build the immutable layout tests-first

**Files:**
- Create: `services/platform/bucketlayout/layout_test.go`
- Create: `services/platform/bucketlayout/layout.go`

**Interfaces:**
- Consumes: `domain.Scope`, `domain.ProductID`, and explicit deployment configuration.
- Produces: validated immutable `Layout`, exact prefixes/keys, copied configuration, and fixed `Encryption`.

- [x] **Step 1: Write compiler-failing public contract tests**

Create `layout_test.go` first. Require `New`, `Validate`, `Configuration`,
`Encryption`, `WorkspacePrefix`, `Prefix`, and `Key`. Pin one exact valid
commercial-partition configuration, all three class prefixes, and all three
keys byte-for-byte.

Require the workspace root and full class prefix to end in `/`, while an object
key does not. Split each output independently and require exact segment count,
canonical IDs, requested class, no empty segment, no period-only segment, and
length at most 1,024 bytes.

- [x] **Step 2: Witness absent-package RED**

Run:

```sh
go test -C services/platform ./bucketlayout -count=1
```

Expected: FAIL because the requested package/API is absent. Record the exact
compiler or package-not-found failure before creating `layout.go`.

- [x] **Step 3: Add configuration and KMS hostile tests**

Reject empty, short, long, uppercase, non-hex, customer/prose-bearing, extra-
suffix, whitespace, Unicode, dotted, underscored, ARN-shaped, and IP-shaped
bucket names. Reject malformed account and Region forms, unsupported
partitions, services other than KMS, aliases, bare IDs, malformed/uppercase key
UUIDs, trailing data, and every account/Region mismatch.

Require only the exact fixed encryption value: `aws:kms`, the validated ARN,
and `BucketKeyEnabled=true`. Prove copied return state cannot mutate the layout.

- [x] **Step 4: Add key-escape and forged-state tests**

Reject zero/forged layout, scope, class, and object reference; object/scope ID
collisions; every alternate class spelling; and internal hostile construction
using slash, backslash, `.`, `..`, percent-encoding, control bytes, Unicode
separators, empty segments, prefixes, suffixes, or output over 1,024 bytes.

Because the public API accepts no raw key text, also mutate every private field
independently inside the package test and require exact `ErrLayout`. Error text
must never contain the rejected value.

- [x] **Step 5: Implement the minimal immutable value**

Use fixed ASCII construction, strict regular expressions created at package
initialization, private validated state, direct concatenation, and one final
exact-output validator. Do not call `path.Join`, `filepath`, URL encoders,
environment lookups, clocks, randomness, or provider APIs.

Every invalid boundary returns exactly `ErrLayout`. Accessors on invalid state
return zero values. Build results only after validating the layout, scope,
class, reference, ID distinctness, exact prefix, segment grammar, and byte
limit.

- [x] **Step 6: Run focused stability and full platform gates**

Run the focused package under race six times. Then run full platform race,
tidy-diff, module verification, vet, package coverage, and concurrent calls.
Require no dependency-file change.

- [x] **Step 7: Review and commit the package slice**

Review every validation branch, returned byte, error path, copy boundary, and
test mutation. Add tests-first fixes, scan, and commit only the package and
tests as:

```text
feat: define scoped S3 bucket layout
```

---

### Task 3: Expose the exact hermetic contract

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/s3-bucket-layout-contract.test.ts`

**Interfaces:**
- Consumes: the reviewed `bucketlayout` package.
- Produces: one exact hermetic root command and bounded documentation.

- [x] **Step 1: Write root/documentation RED**

Require exactly one `s3:bucket-layout:test` command:

```text
go test -C services/platform -race -count=1 ./bucketlayout
```

Require no `s3:bucket-layout:run` or provider command. Require README to state
the exact key grammar, three classes, bucket name, fixed SSE-KMS result,
provider/IAM/retention deferrals, M1-33 Complete, and M1-35 Pending.

- [x] **Step 2: Add wiring and run hermetic GREEN**

Add only the exact package script and README section. Run focused Vitest, the
root command, full pinned repository verification, production audit,
dependency validation, and whitespace checks.

- [x] **Step 3: Review and commit wiring/docs**

Review for unsupported provider, isolation, encryption, and privacy claims.
Scan staged content and commit only the exact wiring/docs/test delta as:

```text
docs: expose S3 bucket layout contract
```

---

### Task 4: Review, complete, push, and close M1-34

**Files:**
- Modify: `app/quality/s3-bucket-layout-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current status/count fixtures under `app/quality/`
- Modify after successful completion CI: `docs/internal/2026-08-18-m1-34-s3-bucket-layout-implementation-plan.md`

**Interfaces:**
- Consumes: the complete M1-34 range and all retained evidence.
- Produces: zero-finding review, exact Complete transition, exact-SHA CI evidence, and a closed plan.

- [x] **Step 1: Obtain zero-finding whole-range review**

Review from the exact pre-M1-34 base through implementation head. Resolve every
Critical, Important, and Minor finding tests-first in separate commits. Do not
advance status while any finding remains.

- [x] **Step 2: Run the final matrix**

Run six fresh focused race passes, full platform race/tidy-diff/module-verify/
vet, package coverage, root layout command, full pinned repository verification,
production audit, dependency validation, diff checks, exact range/per-commit/
history secret scans, and ignored-evidence scan. No provider/live command is
part of M1-34.

- [x] **Step 3: Write completion-contract RED**

Change only the M1-34 status test to expect overall `653/0/72/3`, M1
`68/20/0/48/0`, no active row, exactly one completed M1-33 and M1-34, M1-35
absent from active/complete, and exact blockers. Witness failure while the
tracker remains In progress.

- [x] **Step 4: Transition only M1-34 to Complete**

Update README, tracker, and all current status/count fixtures mechanically.
Run focused GREEN and full pinned verification. Commit only the completion
transition as:

```text
docs: complete M1-34 S3 bucket layout
```

- [x] **Step 5: Push completion and verify exact-SHA CI**

Push only after local green and scans. Require local, origin, and tracking SHAs
to match; locate Runnable UI for the exact completion SHA; and wait for terminal
success. Failure or SHA mismatch blocks closure.

- [x] **Step 6: Close, push, and verify the plan**

Only after completion CI success, change every plan checkbox to `[x]` in a
separate `docs: close M1-34 S3 bucket layout plan` commit. Push it, require
exact-SHA Runnable UI success again, and prove final local/origin/tracking
agreement, `653/0/72/3`, M1 `68/20/0/48/0`, M1-35 Pending, exact blockers,
complete plan, clean tree, and final scans.
