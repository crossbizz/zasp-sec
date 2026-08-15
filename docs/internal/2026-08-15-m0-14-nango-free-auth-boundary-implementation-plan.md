# M0-14 Nango Free Auth Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record the validated free self-hosted Nango MVP boundary as Auth plus
the still-pending Proxy surface while explicitly excluding Functions,
Webhooks, MCP, RBAC, observability, and Enterprise features.

**Architecture:** Treat the completed M0-14a boot, M0-14b OAuth, and M0-14c
API-key proofs as immutable evidence inputs. Add one deterministic repository
contract over the source plan, PRD, design, README, and authoritative tracker;
do not add a new runtime, Docker lifecycle, provider call, or credential path.

**Tech Stack:** Markdown, TypeScript, Vitest, Node.js 22.23.1, npm 10.9.8.

## Global Constraints

- Nango remains exact-pinned at v0.70.5/source commit
  `7faf2c303bbb0322333f526e9ca31c0fe95ef58e` through the completed proofs.
- Accepted MVP scope is long-tail Auth plus Proxy; M0-15 must still prove the
  Proxy GET before R-08 can advance.
- Functions, Webhooks, MCP, RBAC, full observability, and Enterprise features
  are out of scope, not claimed absent from every image route or source module.
- M0-09 and PROV-01 remain Blocked; R-03 remains incomplete.
- No Docker, network, provider, credential, or generated artifact is permitted
  in the M0-14 contract path.
- Use tests-first RED/GREEN, exact count arithmetic, pinned local gates,
  redacted secret scans, and atomic commits.

---

### Task 1: Start and record the free Auth boundary

**Files:**
- Create: `app/quality/nango-free-auth-boundary-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Use: `docs/internal/2026-08-15-m0-14-nango-free-auth-boundary-design.md`
- Use: `docs/internal/2026-08-15-m0-14-nango-free-auth-boundary-implementation-plan.md`

**Interfaces:**
- Consumes: the M0-14 source-plan block, PRD section 13.2, three completed
  Nango proof rows, and R-08 status.
- Produces: one active M0-14 tracker row at 710/1/15/1 overall and
  27/9/1/15/1 in M0, plus one README boundary section and a deterministic
  Vitest contract.

- [x] **Step 1: Write the missing-boundary failing contract**

  Add a Vitest file that reads only tracked repository files and requires:

  ```ts
  expect(sourceSection).toContain("Record the validated Nango free feature boundary for MVP");
  expect(sourceSection).toContain("Functions, Webhooks and MCP as out of scope");
  expect(prd).toContain("Nango free self-hosted for Auth + Proxy only");
  expect(readmeSection).toContain("M0-14 is In progress");
  expect(readmeSection).toContain("Functions, Webhooks, and MCP are out of scope");
  expect(tracker).toContain("| Pending | 710 |");
  expect(tracker).toContain("| In progress | 1 |");
  expect(tracker).toContain("| Complete | 15 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 9 \| 1 \| 15 \| 1 \|/);
  ```

  The test must also require M0-14a/b/c uniquely Complete, M0-15 absent from
  active/completed rows, R-08 exactly `Not run`, M0-09/PROV-01 Blocked, and
  R-03 incomplete.

- [x] **Step 2: Run focused RED**

  Run:

  ```bash
  npx --yes -p node@22.23.1 -p npm@10.9.8 npm exec -- \
    vitest run app/quality/nango-free-auth-boundary-contract.test.ts
  ```

  Expected: failures only for the absent README M0-14 section and missing
  active M0-14 tracker transition; source/PRD/design assertions pass.

- [x] **Step 3: Add the minimal boundary record**

  Add a README section that states:

  ```markdown
  M0-14 is In progress. The accepted free self-hosted Nango MVP boundary is
  long-tail Auth plus the Proxy surface pending M0-15. Functions, Webhooks,
  MCP, RBAC, full observability, and Enterprise features are out of scope.
  ```

  Move exactly M0-14 from Pending to In progress in the tracker, set overall
  counts to 710/1/15/1 and M0 counts to 27/9/1/15/1, preserve every other
  status, and describe this as an evidence-only boundary record with no new
  live/provider claim.

- [x] **Step 4: Run focused and affected GREEN**

  Run the new test plus all status-sensitive Nango/Cartography/LocalStack/
  Prowler/Tetragon/OTLP contracts. Expected: every file and test passes under
  pinned Node/npm.

- [x] **Step 5: Run the pinned repository gate and commit**

  Run `npm run verify`, `npm audit --omit=dev`, `git diff --check`, and pinned
  redacted Gitleaks over the staged diff. Commit only the scoped tracked files:

  ```bash
  git commit -m "docs: record M0-14 Nango auth boundary"
  ```

---

### Task 2: Review, complete, and deliver M0-14

**Files:**
- Modify: `app/quality/nango-free-auth-boundary-contract.test.ts`
- Modify: status-sensitive files under `app/quality/*-proof-contract.test.ts`
  only where exact aggregate counts require it
- Modify: `README.md`
- Modify: `docs/internal/2026-08-15-m0-14-nango-free-auth-boundary-implementation-plan.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Create ignored: `.superpowers/sdd/2026-08-15-m0-14-nango-free-auth-boundary-implementation-plan/task-2-report.md`
- Append ignored: `.superpowers/sdd/2026-08-15-m0-14-nango-free-auth-boundary-implementation-plan/progress.md`
- Create ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-14-report.md`
- Append ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`

**Interfaces:**
- Consumes: Task 1's exact active row and deterministic boundary contract.
- Produces: one uniquely Complete M0-14 row, overall counts 710/0/16/1, M0
  counts 27/9/0/16/1, zero active rows, clean review, pushed exact SHA, and
  successful exact-SHA Runnable UI evidence.

- [ ] **Step 1: Perform a read-only boundary review**

  Compare the source M0-14 requirement, PRD section 13.2, design, README,
  tracker, and contract. Reject any claim that the excluded surfaces were
  proved unreachable, any premature Proxy success, any R-08 advancement, or
  any loss of the completed M0-14a/b/c evidence chain.

- [ ] **Step 2: Add hostile completion-contract cases and capture RED**

  Require exactly zero active rows and exactly one M0-14 Complete row. Add
  mutations that duplicate M0-14, start M0-15 concurrently, change R-08 from
  `Not run`, claim MCP support, or change aggregate counts. Run the focused
  test and expect only the stale In progress/count/README assertions to fail.

- [ ] **Step 3: Apply the exact completion transition**

  Change the README to `M0-14 is Complete`. Move only M0-14 from In progress
  to Complete; set overall counts to 710/0/16/1 and M0 counts to
  27/9/0/16/1. Keep M0-15 Pending, R-08 Not run, M0-09/PROV-01 Blocked, and
  R-03 incomplete. Mark this plan's completed steps checked only after their
  evidence exists.

- [ ] **Step 4: Run all verification**

  Run the focused contract six times, the three Nango proof suites, all
  status-sensitive contracts, full pinned `npm run verify`, production audit,
  production license inventory, syntax/whitespace checks, and redacted staged,
  history, and exact evidence scans. Expected: zero failures, vulnerabilities,
  prohibited licenses, whitespace errors, or findings.

- [ ] **Step 5: Record evidence and commit**

  Write the ignored scoped and authoritative reports, append both ledgers, and
  commit the exact tracked completion transition:

  ```bash
  git commit -m "docs: complete M0-14 Nango auth boundary"
  ```

- [ ] **Step 6: Push and watch exact-SHA CI**

  Push `codex/zasp-implementation`, prove local/tracking/origin equality, select
  the Runnable UI run whose `headSha` equals the completion SHA, and watch it
  to terminal success. Append the immutable run/job evidence, then begin
  M0-15 without changing R-08 until its own proof succeeds.
