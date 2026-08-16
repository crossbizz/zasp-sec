# M1-12 S3 Artifact Interface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans and implement this checklist tests-first.

**Goal:** Add a dependency-free Organization-scoped ArtifactStore and prove its
exact Put/Get/Delete behavior through the retained strict S3/KMS LocalStack
boundary.

**Architecture:** `services/platform/artifactstore` owns canonical product
scope, artifact identity, checksum, content, timeout, and fixed-error semantics.
`proofs/localstack-storage` adapts the exact-pinned AWS SDK and owns disposable
bucket/KMS/container lifecycle, provider reconciliation, and cleanup.

**Tech Stack:** Go 1.25 source compatibility, Go 1.26.5 toolchain, standard
library context/SHA-256 primitives, existing AWS SDK v2 pins only in the proof
module, Vitest repository contracts, pinned Node 22.23.1/npm 10.9.8.

## Global constraints

- M1-11 must remain Complete; M1-13 remains Pending until this plan closes.
- Overall start counts are `683/1/41/3`; M1 start counts are
  `68/50/1/17/0`.
- Product code imports no AWS SDK type and accepts no bucket, provider key,
  ETag, KMS identifier, credential, endpoint, tag map, or raw object key.
- Every operation uses canonical Organization/Workspace/Environment scope,
  canonical artifact identity, one total deadline, defensive copies, and fixed
  errors.
- The live proof accepts no real credential/profile/proxy/dotenv input, uses
  only a loopback disposable LocalStack target, and emits one fixed line.
- M0-09, M0-18, and M0-19 stay Blocked; R-03 stays incomplete; R-11 stays Not
  run.

---

### Task 1: Start M1-12

**Files:**
- Create: `app/quality/s3-artifact-interface-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: existing aggregate-count contracts under `app/quality/`

**Interfaces:**
- Consumes: authoritative M1-12 source, committed design/plan, completed M1-11.
- Produces: unique M1-12 In-progress row and exact `683/1/41/3` contract.

- [ ] **Step 1: Write the source/status contract before changing docs**

Require the exact M1-11 dependency, ArtifactStore/S3 deliverable, LocalStack
Put/Get/Delete verification, design boundary, M1-12 active row, M1-13 absence,
and unchanged blocker/risk rows.

- [ ] **Step 2: Run the focused contract and record Pending-state RED**

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/s3-artifact-interface-contract.test.ts
```

Expected: source/design/plan assertions pass; README/status fail only because
M1-12 remains Pending.

- [ ] **Step 3: Move only M1-12 to In progress**

Set overall counts to `683/1/41/3` and M1 to `68/50/1/17/0`. Add exactly one
M1-12 row and document the product/provider boundary. Mechanically update
aggregate fixtures while retaining duplicate/concurrent-row rejection.

- [ ] **Step 4: Run focused/full pinned gates, scan, and commit**

Run focused quality tests, `npm run verify`, `npm audit --omit=dev`, the
eight-target build, diff check, and pinned redacted secret scans.

```bash
git commit -m "docs: start M1-12 S3 artifact interface"
```

---

### Task 2: Implement the dependency-free ArtifactStore

**Files:**
- Create: `services/platform/artifactstore/store_test.go`
- Create: `services/platform/artifactstore/store.go`

**Interfaces:**
- Consumes: `domain.Scope`, `domain.EvidenceRef`, standard context/SHA-256.
- Produces: `ArtifactStore`, `Store`, `Driver`, `Config`, `Locator`,
  `PutRequest`, `Artifact`, `DriverObject`, and fixed errors.

- [ ] **Step 1: Add missing-symbol tests before production**

Cover valid construction and Put/Get/Delete first. Then add nil/typed-nil
drivers; timeout and size bounds; zero/malformed scope/reference; media/content
validation; exact key derivation; defensive copies; checksum and metadata
mismatch; driver errors/panics; timeout/cancellation; and concurrent calls.

- [ ] **Step 2: Run compiler RED**

```bash
go test -C services/platform ./artifactstore -count=1
```

Expected: compilation fails only on the absent package API.

- [ ] **Step 3: Implement the strict product contract**

Use a positive operation timeout no greater than 30 seconds and a positive
maximum size no greater than 64 MiB. Derive the canonical key exclusively from
validated product scope/reference. Allow exactly JSON, octet-stream, gzip, and
plain text media types. Compute SHA-256 in product code and validate every
driver-returned field/body before returning a defensive copy.

- [ ] **Step 4: Implement fixed deadline/error/panic behavior**

Apply one `context.WithTimeout` to each operation, reject already-canceled
contexts before driver I/O, contain driver panics, and map failures only to
`ErrConfiguration`, `ErrPut`, `ErrGet`, `ErrDelete`, or `ErrArtifact`.

- [ ] **Step 5: Run race and six stability passes**

Run the focused race test, repeat the complete artifactstore package six times,
then run the platform module race/tidy/verify/vet gates.

- [ ] **Step 6: Scan and commit the product package**

```bash
git commit -m "feat: add scoped artifact store"
```

---

### Task 3: Add the S3 adapter and exact LocalStack lifecycle

**Files:**
- Create: `proofs/localstack-storage/artifact_store.go`
- Create: `proofs/localstack-storage/artifact_store_test.go`
- Create: `proofs/localstack-storage/run-artifact-store.mjs`
- Modify: `proofs/localstack-storage/main.go`
- Modify: `proofs/localstack-storage/proof.go`
- Modify: `proofs/localstack-storage/run.mjs`
- Modify: `proofs/localstack-storage/run.test.mjs`
- Modify: `proofs/localstack-storage/go.mod`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/s3-artifact-interface-contract.test.ts`

**Interfaces:**
- Consumes: product `artifactstore.Driver`, existing sdkS3/KMS/bucket helpers,
  exact LocalStack image/runtime.
- Produces: product-backed S3 adapter, `artifact-store` proof mode, root test/run
  commands, fixed success line, exact reverse cleanup and audit.

- [ ] **Step 1: Write adapter/lifecycle/orchestrator tests before code**

Require exact key/body/media/scope/checksum metadata, SSE-KMS identity,
proof-marker tags, success/ambiguous reconciliation, collision rejection,
pre-delete ownership, exact absence, cleanup precedence, fixed CLI output, and
unchanged default M0-07 behavior.

- [ ] **Step 2: Capture missing adapter/mode RED**

Run focused Go and Node tests before production symbols/mode exist.

- [ ] **Step 3: Implement the S3 driver and product proof**

Map only typed product fields to S3. Re-fetch and validate exact content,
metadata, tags, encryption, size, and checksum after Put. Retain an expected
object cleanup candidate before mutation. Get must reject any provider drift;
Delete must re-prove exact scoped state and then prove absence.

- [ ] **Step 4: Extend the exact disposable runner**

Keep default M0-07 mode byte-for-byte compatible. Add an M1-12 configuration
with its own name prefix/labels, S3+KMS service set, Go mode, child success line,
outer success line, bounded temp prefix, loopback endpoint, and exact cleanup.

- [ ] **Step 5: Add root commands and documentation**

```json
"artifact:store:test": "go test -C services/platform -race -count=1 ./artifactstore && go test -C proofs/localstack-storage -race -count=1 ./... && node --test proofs/localstack-storage/run.test.mjs",
"artifact:store:run": "node proofs/localstack-storage/run-artifact-store.mjs"
```

- [ ] **Step 6: Run hermetic gates, then exact live proof**

Require:

`LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true container_cleanup=true.`

Then prove zero exact M1-12 containers/temp paths and do not address any shared
development target.

- [ ] **Step 7: Scan and commit adapter/proof**

```bash
git commit -m "feat: prove scoped LocalStack artifact store"
```

---

### Task 4: Review, complete, push, and close

**Files:**
- Modify product/proof code and tests only for confirmed review findings.
- Modify README/tracker/aggregate contracts for completion.
- Modify this checklist only after exact completion CI succeeds.

- [ ] **Step 1: Run independent whole-range review**

Audit scope/key derivation, byte ownership, deadline lifetime, checksum/media
validation, fixed errors, provider ambiguity, encryption identity, cleanup
authorization, exact absence, runner fencing, and retained M0-07 behavior. Fix
every finding tests-first until review is zero-finding.

- [ ] **Step 2: Capture completion RED and move only M1-12 to Complete**

Set overall counts to `683/0/42/3` and M1 to `68/50/0/18/0`. Keep M1-13
Pending and all blockers/risk rows unchanged.

- [ ] **Step 3: Run final gates and scans**

Run six focused passes, all affected Go race/tidy/verify/vet gates, retained
M0-07 regressions, the eight-target build, pinned `npm run verify`, production
audit, diff check, and pinned staged/exact/history/evidence secret scans.

- [ ] **Step 4: Commit, push, and watch exact completion SHA**

```bash
git commit -m "docs: complete M1-12 S3 artifact interface"
git push origin codex/zasp-implementation
```

Require Runnable UI success for the exact completion SHA.

- [ ] **Step 5: Close the plan and verify the close SHA**

Mark every checkbox complete, record exact completion run/job evidence, commit
`docs: close M1-12 S3 artifact interface`, push, and require exact-SHA Runnable
UI success before starting M1-13.
