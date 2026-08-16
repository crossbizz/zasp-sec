# M1-26 UI API Coverage CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a reusable CI validator that keeps interactive public OpenAPI
operations and the checked-in UI action map complete and bidirectionally
consistent.

**Architecture:** A dependency-light Node module strictly reads the fixed map
and OpenAPI files, extracts unique `/api/v1` and `/internal/v1` operation
inventories, and enforces the planned/available lifecycle plus exact public
mapping coverage. A fixed-output CLI is exposed as `ui-api:check` and runs in
the existing root `verify` chain.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, `js-yaml` 4.1.1, built-in Node test
runner, Vitest repository contracts.

## Global constraints

- Every behavior or status change has a witnessed tests-only RED.
- Read only the fixed bounded regular non-symlink map and OpenAPI files.
- Fail closed on YAML representation/schema drift, operation ambiguity,
  unclassified paths, lifecycle mismatch, missing mappings, or extra mappings.
- Emit only the fixed aggregate success line or fixed rejection line.
- Add no OpenAPI operation, HTTP path/method, UI call, client method, server,
  credential, provider, database, Docker, or external network operation.
- M1-27 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.

---

### Task 1: Start M1-26 with a repository contract

**Files:** create the M1-26 quality contract; update README/tracker/current
aggregate fixtures; create ignored task/progress evidence.

- [ ] **Step 1: Capture source/design/status RED**
- [ ] **Step 2: Move only M1-26 to In progress**
- [ ] **Step 3: Run focused and complete quality GREEN**
- [ ] **Step 4: Scan and commit `docs: start M1-26 UI API coverage CI`**

---

### Task 2: Implement the validator tests-first

**Files:** create `scripts/check-ui-api-coverage.mjs` and its Node tests; update
`package.json`; extend ignored evidence.

- [ ] **Step 1: Require the absent module/command and capture RED**
- [ ] **Step 2: Implement strict bounded map and OpenAPI input parsing**
- [ ] **Step 3: Enforce planned/available and public/internal coverage rules**
- [ ] **Step 4: Add fixed-output CLI and root verification wiring**
- [ ] **Step 5: Cover deliberate removal, unmapped public, malformed, and file-boundary failures**
- [ ] **Step 6: Run six focused passes and full pinned gates/audits/scans**
- [ ] **Step 7: Commit `feat: enforce UI API coverage`**

---

### Task 3: Document and review the M1-26 range

- [ ] **Step 1: Capture README command/boundary RED and document the validator**
- [ ] **Step 2: Review source/design/plan/diff/parser/coverage/CLI/CI boundaries**
- [ ] **Step 3: Fix every valid finding tests-first; finish 0/0/0 Ready Yes**
- [ ] **Step 4: Repeat full gates/scans and record review commits**

---

### Task 4: Complete, push, and close M1-26

- [ ] **Step 1: Capture completion status RED**
- [ ] **Step 2: Move only M1-26 to Complete and run final gates/scans**
- [ ] **Step 3: Push completion commit and require exact-SHA Runnable UI success**
- [ ] **Step 4: Push plan-only closure and require exact-SHA Runnable UI success**

Final completion requires overall `669/0/56/3`, M1 `68/36/0/32/0`, clean
local/upstream/origin equality, final all-history/evidence scans, and M1-27
remaining Pending.
