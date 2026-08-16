# M1-23 OpenAPI Root Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the exact OpenAPI 3.1 document root, authentication
alternatives, cursor pagination vocabulary, and stable product error schema.

**Architecture:** Add one local YAML root plus a pinned standard linter and
strict repository tests. The document deliberately has no operations; M1-24
generates the first TypeScript client from this reviewed root.

**Tech Stack:** OpenAPI 3.1.0, JSON Schema 2020-12/OAS dialect, exact-pinned
Redocly CLI 2.43.1, existing exact-pinned js-yaml 4.1.1, Node test runner,
Vitest repository contracts.

## Global constraints

- Every source/status behavior has a witnessed tests-only RED before its
  production/source edit.
- The root is self-contained and has no remote `$ref`, operation, callback,
  webhook, server, example customer data, provider name, or credential.
- Global auth is exactly an OR between Stytch-backed session JWT bearer and
  product API-token bearer. No anonymous alternative exists.
- Pagination is bounded, opaque, and internally consistent.
- Product error JSON exactly mirrors the reviewed M1-06 four-field envelope.
- Redocly telemetry and update checks are disabled; lint uses only locked local
  dependencies and files.
- M1-24 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.

---

### Task 1: Start M1-23 with a repository contract

**Files:**

- Create: `app/quality/openapi-root-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current aggregate status fixtures under `app/quality`
- Create ignored task/progress evidence under
  `.superpowers/sdd/2026-08-16-m1-23-openapi-root-implementation-plan/`

- [x] **Step 1: Write source/design/status assertions and capture RED**

  Bind M1-23, prerequisite M1-22, successor M1-24, public API constraints,
  design file/path/auth/pagination/error decisions, exact blockers, and active
  arithmetic. Require overall `672/1/52/3` and M1 `68/39/1/28/0`. Focused RED
  must fail only stale README/tracker state.

- [x] **Step 2: Move only M1-23 to In progress**

  Update README, tracker, and only current aggregate fixtures. Keep M1-22
  Complete, M1-24 Pending, and all three blockers unchanged.

- [x] **Step 3: Verify focused and complete quality GREEN**

  ```bash
  npx vitest run app/quality/openapi-root-contract.test.ts
  npx vitest run app/quality
  git diff --check
  ```

- [x] **Step 4: Record, scan, and commit**

  ```bash
  git commit -m "docs: start M1-23 OpenAPI root"
  ```

---

### Task 2: Add the strict root and pinned linter tests-first

**Files:**

- Create first: `openapi/openapi.test.mjs`
- Create after RED: `openapi/openapi.yaml`, `redocly.yaml`
- Modify after RED: `package.json`, `package-lock.json`, this plan
- Append ignored task/progress evidence

- [x] **Step 1: Write exact root tests and capture missing-file RED**

  Parse with locked `js-yaml` in strict mode. Require exact root, security,
  schema, parameter, and response shapes. Before source/dependency edits, run:

  ```bash
  node --test openapi/openapi.test.mjs
  ```

  RED must be only the absent OpenAPI root/config/lint command.

- [x] **Step 2: Add minimal OpenAPI/linter GREEN**

  Create the self-contained root and recommended Redocly config, install
  `@redocly/cli@2.43.1` exactly as a development dependency, and add:

  ```json
  "openapi:lint": "REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true redocly lint openapi/openapi.yaml --config redocly.yaml"
  ```

- [x] **Step 3: Add hostile schema and linter RED/GREEN coverage**

  Reject duplicate/unknown keys, wrong OpenAPI/dialect/info version, paths,
  remote references, anonymous or AND auth, query/cookie tokens, pagination
  contradictions/bounds, ProductID/code/error drift, examples, and prohibited
  customer/provider strings. Require lint output with zero warnings.

- [x] **Step 4: Run stability and repository gates**

  ```bash
  for run in 1 2 3 4 5 6; do node --test openapi/openapi.test.mjs; npm run openapi:lint; done
  npm run verify
  npm run build:repo
  npm audit --omit=dev
  npm audit
  git diff --check
  ```

- [x] **Step 5: Record, scan, and commit**

  ```bash
  git commit -m "feat: add strict OpenAPI 3.1 root"
  ```

---

### Task 3: Expose the public documentation boundary

**Files:** `README.md`, repository contract, this plan, ignored evidence.

- [ ] **Step 1: Add missing README assertions and capture RED**

  Require the exact lint command, document path, OpenAPI version, auth OR,
  pagination/error vocabulary, empty-operation boundary, self-contained/no-I/O
  statement, the two justified root-only linter exceptions, and M1-24 Pending.

- [ ] **Step 2: Add only the README boundary**

  Do not add operations, handlers, generated code, auth implementation, or UI
  mapping.

- [ ] **Step 3: Run focused/root/full pinned gates**

  ```bash
  npm run openapi:lint
  node --test openapi/openapi.test.mjs
  npx vitest run app/quality/openapi-root-contract.test.ts
  npm run verify
  npm run build:repo
  npm audit --omit=dev
  git diff --check
  ```

- [ ] **Step 4: Record, scan, and commit**

  ```bash
  git commit -m "docs: expose OpenAPI root"
  ```

---

### Task 4: Review the complete M1-23 range

- [ ] **Step 1: Perform an exact whole-range read-only review**

  Review source/PRD, M1-22 dependency, design/plan, YAML/config/lock, strict
  parser tests, linter output, auth semantics, pagination/error parity,
  self-containment, dependency/license boundary, docs, and tracker arithmetic.

- [ ] **Step 2: Reproduce every valid finding tests-first**

  Add the smallest hostile RED before each fix. Finish at Critical 0,
  Important 0, Minor 0, Ready Yes.

- [ ] **Step 3: Repeat affected and full gates after separate fixes**

  Re-run strict parser stability, lint stability, full repository gates,
  audits, diff, and secret scans.

- [ ] **Step 4: Record the plan-only final review commit**

  ```bash
  git commit -m "docs: record M1-23 review"
  ```

---

### Task 5: Complete, push, and close M1-23

- [ ] **Step 1: Change only completion assertions and capture RED**

  Require exactly one M1-23 Complete row, no active source task, M1-22
  Complete, M1-24 absent, unchanged blockers, overall `672/0/53/3`, and M1
  `68/39/0/29/0`.

- [ ] **Step 2: Move only M1-23 to Complete and run final gates**

  Repeat six strict-parser/lint cycles, full repository verification and build
  targets, production/full dependency audit, formatting, and staged/history/
  evidence secret scans.

- [ ] **Step 3: Commit, push, and require exact completion-SHA CI success**

  ```bash
  git commit -m "docs: complete M1-23 OpenAPI root"
  git push origin codex/zasp-implementation
  ```

- [ ] **Step 4: Commit/push the plan-only closure and require exact CI success**

  ```bash
  git commit -m "docs: close M1-23 OpenAPI root"
  git push origin codex/zasp-implementation
  ```

  Record completion and closure run/job IDs, scan final history/evidence, prove
  clean synchronized state, and leave M1-24 Pending.
