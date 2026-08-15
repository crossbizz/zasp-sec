# M0-23 Technical Proof Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record one auditable architecture decision for every M0 proof boundary, preserve unresolved real-provider blockers, complete M0-23, and open the dependency boundary for M1 foundation work.

**Architecture:** Add one strict evidence-only M0 gate record backed by the existing risk register and retained proof reports. A repository contract parses all fourteen decisions, requires twelve evidence-backed PASS rows and two explicit BLOCKED rows, and protects status arithmetic and downstream blocker consequences. No provider or container proof is rerun.

**Tech Stack:** Markdown decision records, TypeScript, Vitest, Node.js 22.23.1, npm 10.9.8, GitHub Actions Runnable UI, Gitleaks 8.30.1.

## Global Constraints

- M0-23 performs no Docker, Kubernetes, cloud-provider, credential, dotenv, profile, or proxy operation.
- Exactly R-01 through R-14 appear once and in order.
- Exactly twelve outcomes are `PASS`; R-03 and R-11 are exactly `BLOCKED`.
- R-03 remains Not run in the risk register and continues to block real-AWS IAM parity and dependent M1A/M3 claims.
- R-11 remains Not run in the risk register and continues to block EKS Fargate strong-isolation and egress claims.
- LocalStack, fixture-only, source-review, or harness-only evidence cannot advance R-03 or R-11.
- Starting status is `701/1/23/3` overall and `27/0/1/23/3` in M0.
- Completion status is `701/0/24/3` overall and `27/0/0/24/3` in M0.
- M1-01d stays Pending until M0-23 is complete, pushed, and its exact-SHA Runnable UI gate succeeds.
- Every behavior or status change follows a witnessed tests-only RED.

---

### Task 1: Start M0-23 and bind the source boundary

**Files:**
- Create: `app/quality/m0-gate-contract.test.ts`
- Create: `docs/internal/2026-08-15-m0-23-gate-implementation-plan.md`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Create/update ignored: `.superpowers/sdd/2026-08-15-m0-23-gate-implementation-plan/task-4-report.md`
- Create/update ignored: `.superpowers/sdd/2026-08-15-m0-23-gate-implementation-plan/progress.md`
- Append ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`

**Interfaces:**
- Consumes: source task `M0-23`, the approved M0-23 design, the current `702/0/23/3` tracker state, and the M0-22 exact-SHA close evidence.
- Produces: one repository contract plus the unique M0-23 In-progress row at `701/1/23/3` overall and `27/0/1/23/3` in M0.

- [x] **Step 1: Write the start-status contract before changing status**

Add a Vitest case that reads the source plan, design, implementation plan,
README, and tracker. Require the exact dependency on M0-22, the deliverable,
the unresolved-proof rule, design outcome `PROCEED WITH BLOCKED PATHS`, M0-23
In progress exactly once, M1-01d absent from active/complete rows, and the exact
start arithmetic.

- [x] **Step 2: Run the focused RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" \
  npx vitest run app/quality/m0-gate-contract.test.ts
```

Expected: FAIL only because README and tracker still show M0-23 Pending and the
start counts are absent.

- [x] **Step 3: Make the minimal start transition**

Move only M0-23 from Pending to In progress. Set the global summary to
`701/1/23/3`, set M0 to `27/0/1/23/3`, add one active row, and document that
the gate is evidence-only. Keep M0-09, M0-18, and M0-19 Blocked; keep R-03 and
R-11 unpassed; do not start M1-01d.

- [x] **Step 4: Verify GREEN and commit**

Run the focused contract, full pinned `npm run verify`, production audit, and
`git diff --check`. Scan staged and exact ignored evidence with Gitleaks, then
commit:

```bash
git commit -m "docs: start M0-23 technical proof gate"
```

---

### Task 2: Record all fourteen proof decisions

**Files:**
- Modify: `app/quality/m0-gate-contract.test.ts`
- Create: `docs/decisions/m0-technical-proof-gate.md`
- Modify: `docs/decisions/mvp-risk-register.md`
- Modify: `README.md`
- Update ignored M0-23 report and both progress ledgers.

**Interfaces:**
- Consumes: the fourteen risk rows, retained proof reports, exact reviewed heads, and the three authoritative blocked task rows.
- Produces: `12 PASS / 2 BLOCKED / 0 FAIL / 0 unclassified`, plus the exact architecture decision for every risk.

- [x] **Step 1: Extend the contract as RED**

Add an `assertGate` helper that parses the gate table and requires exact keys:
`Risk`, `Outcome`, `Proofs`, `Evidence`, and `Architecture decision`. Require
exactly fourteen ordered unique rows, twelve PASS rows, and only R-03/R-11 as
BLOCKED. Require each PASS evidence cell to contain a retained report path and
a proof head. Require each blocked row to name its blocked task(s), unavailable
fixture, prohibited substitution, downstream claim, and resume condition.

Require these four risk-register transitions exactly:

```text
R-01 PASS — M0-02/M0-03 — task-M0-02-report.md @ da1323050a9875bde17190e6d84afa7fa4651a13; task-M0-03-report.md @ 5ddf9b23b9b781499281610da2ac153663ff42b8
R-02 PASS — M0-04/M0-05 — task-M0-04-report.md @ e8a8f5fc56ace9570a23476771c8c48377cd4db3; task-M0-05-report.md @ 37d638f22d8e9e5b8075cc9aab755b6589084b07
R-04 PASS — M0-06/M0-08 — task-M0-06-report.md @ ba02323b83618e096c67cb2380f5a4cbaf9c9086; task-M0-08-report.md @ 959f033c9f6b5d26e0c57b0e01dbb539358c7a09
R-05 PASS — M0-10 — task-6-report.md @ 23b759b793e02aba91c24b846651ed64018a9a03
```

- [x] **Step 2: Run the decision-record RED**

Run the focused contract. Expected: FAIL because the gate record is absent and
the four historical risk rows still say Not run.

- [x] **Step 3: Create the strict gate record and update only proven rows**

Create the fourteen-row table. Preserve every existing evidence-backed PASS.
Update only R-01, R-02, R-04, and R-05 from Not run to PASS with the exact
retained evidence above. Keep R-03 and R-11 as Not run in the risk register and
BLOCKED in the gate record.

The architecture decisions must state:

- adopt Stytch local/remote JWT validation and Neon pooled/direct connection split;
- retain SQS as durable batch transport and OpenSearch as an Organization-scoped rebuildable projection;
- adopt product-owned Organization-scoped Cartography normalization only under its fixture boundary;
- retain the evidence-backed Prowler, Tetragon observation, Nango Auth+Proxy, Promptfoo, embedded OPA, Collector, PostHog allowlist, and bounded AI planner boundaries;
- allow M1 foundation work to start;
- block real-AWS IAM parity-dependent M1A/M3 claims on R-03;
- block Fargate strong-isolation/egress-dependent claims on R-11.

- [x] **Step 4: Add hostile table mutations**

Before changing the validator, add cases for duplicate/missing/extra risk rows,
reordered IDs, PASS on R-03/R-11, BLOCKED on a proven row, missing proof head,
fake local evidence for a real-provider blocker, weakened downstream consequence,
wrong summary counts, and an extra active M1 task. Run them and capture the
expected failures, then make the minimum assertion changes needed for GREEN.

- [x] **Step 5: Run focused GREEN and commit**

Run the focused test six consecutive times, full repository verification,
production audit, whitespace, and redacted staged/evidence scans. Commit:

```bash
git commit -m "docs: record M0 technical proof decisions"
```

---

### Task 3: Review the complete gate evidence

**Files:**
- Modify only the M0 gate record, contract, risk register, README, or design/plan if the review identifies a concrete defect.
- Update ignored M0-23 report and progress ledgers.

**Interfaces:**
- Consumes: the entire M0-23 range plus all linked retained reports.
- Produces: a zero-finding evidence-consistency review or tests-first fixes followed by a fresh review.

- [x] **Step 1: Audit source-to-gate completeness**

Compare every R-01 through R-14 criterion, current risk status, gate outcome,
linked proof task, retained report/head, architecture consequence, blocker,
and resume condition. Confirm no PASS depends on an unrun command or on a
provider substitution outside its approved boundary.

- [x] **Step 2: Audit gate arithmetic and dependency state**

Require 728 global tasks, 27 M0 tasks, one active M0-23 row, three blocked M0
rows, no active M1 row, and unchanged R-03/R-11 blocker state.

- [x] **Step 3: Fix every finding tests-first**

For each finding, add the smallest focused mutation that passes incorrectly,
run it to capture RED, apply one minimal documentation/contract fix, and rerun
focused GREEN. Do not rerun live proofs unless retained evidence itself is
changed or invalidated.

- [x] **Step 4: Run final local gates**

Run six focused passes, `npm run verify`, `npm audit --omit=dev`, syntax and
whitespace checks, and pinned Gitleaks over the task range, exact gate/risk
files, ignored evidence, and history. Record exact counts and review outcome.

---

### Task 4: Complete, ship, and close M0-23

**Files:**
- Modify: `app/quality/m0-gate-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/internal/2026-08-15-m0-23-gate-implementation-plan.md`
- Update ignored M0-23 report and both progress ledgers.

**Interfaces:**
- Consumes: the reviewed fourteen-row gate record and green local gates.
- Produces: M0-23 Complete at `701/0/24/3`, exact-SHA successful Runnable UI evidence, and a closed tracked plan. M1-01d remains Pending for the next sequential task.

- [x] **Step 1: Write completion expectations first**

Change only the completion test to require M0-23 Complete exactly once,
no active source-plan task, `701/0/24/3` overall, `27/0/0/24/3` in M0,
the unchanged `12 PASS / 2 BLOCKED` gate result, and M1-01d Pending.

- [x] **Step 2: Run completion RED**

Run the focused contract. Expected: FAIL only on the still-In-progress tracker
and README boundary.

- [x] **Step 3: Apply the completion transition**

Move only M0-23 to Complete, update the two status summaries, preserve all
three blocked task rows and both gate blockers, and add the final gate evidence
to README/tracker/report/ledgers.

- [ ] **Step 4: Verify, scan, commit, push, and watch exact SHA**

Run focused and full pinned gates, audit, whitespace, staged/evidence/history
Gitleaks scans, then commit:

```bash
git commit -m "docs: complete M0 technical proof gate"
git push origin codex/zasp-implementation
```

Require local, tracking, and remote SHAs to match. Find the Runnable UI run for
that exact SHA and watch it to `completed/success`.

- [ ] **Step 5: Close the tracked plan**

Mark every plan checkbox complete, record the completion run/job IDs in ignored
evidence, run the focused contract and secret scan, and commit:

```bash
git commit -m "docs: close M0 technical proof gate plan"
git push origin codex/zasp-implementation
```

Watch Runnable UI to success for the exact close SHA before starting M1-01d.
