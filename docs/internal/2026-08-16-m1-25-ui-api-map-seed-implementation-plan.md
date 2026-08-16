# M1-25 UI API Map Seed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Seed the strict product UI-to-API map with honest planned Home and
System Health actions that future OpenAPI coverage can resolve.

**Architecture:** A minimal strict YAML artifact contains only stable product
screen/action identity and canonical operation IDs. A hermetic contract rejects
representation or inventory drift and proves the complete forward-reference
set resolves against a synthetic future OpenAPI operation inventory.

**Tech Stack:** YAML 1.2 JSON schema parsing through existing `js-yaml` 4.1.1,
Vitest, pinned Node 22.23.1/npm 10.9.8.

## Global constraints

- Every artifact or status behavior change has a witnessed tests-only RED.
- No OpenAPI path/operation, HTTP method, API URL, client method, UI call,
  authentication behavior, server, or provider integration is added.
- The artifact is strict, duplicate-safe, alias/merge-free, deterministic, and
  contains only the two source-plan seed screens and five planned operations.
- M1-26 remains Pending. M0-09, M0-18, and M0-19 remain Blocked.

---

### Task 1: Start M1-25 with a repository contract

**Files:** create quality contract; update README/tracker/current fixtures;
create ignored task/progress evidence.

- [x] **Step 1: Capture source/design/status RED**
- [x] **Step 2: Move only M1-25 to In progress**
- [x] **Step 3: Run focused and complete quality GREEN**
- [x] **Step 4: Scan and commit `docs: start M1-25 UI API map seed`**

---

### Task 2: Add the strict map tests-first

**Files:** create `docs/product/ui-api-map.yaml`; extend quality contract and
ignored evidence.

- [x] **Step 1: Require absent exact map and capture RED**
- [x] **Step 2: Add exact schema and five planned action mappings**
- [x] **Step 3: Add hostile representation/inventory and resolution cases**
- [x] **Step 4: Run six focused passes and full pinned gates/audits**
- [x] **Step 5: Scan and commit `feat: seed UI API map`**

---

### Task 3: Document and review the M1-25 range

- [x] **Step 1: Capture README-boundary RED and document the artifact**
- [x] **Step 2: Review source/design/plan/diff, parser, map, and future coverage boundary**
- [x] **Step 3: Fix every valid finding tests-first; finish 0/0/0 Ready Yes**
- [x] **Step 4: Repeat full gates/scans and record review commits**

---

### Task 4: Complete, push, and close M1-25

- [x] **Step 1: Capture completion status RED**
- [x] **Step 2: Move only M1-25 to Complete and run final gates/scans**
- [ ] **Step 3: Push completion commit and require exact-SHA Runnable UI success**
- [ ] **Step 4: Push plan-only closure and require exact-SHA Runnable UI success**

Final completion requires overall `670/0/55/3`, M1 `68/37/0/31/0`, clean
local/upstream/origin equality, final all-history/evidence scans, and M1-26
remaining Pending.
