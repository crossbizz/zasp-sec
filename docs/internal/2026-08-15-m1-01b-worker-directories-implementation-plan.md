# M1-01b Worker Directories Implementation Plan

Date: August 15, 2026

## Objective

Create the independent Python security-worker and Node redteam-worker package
skeletons with exact no-op health commands. Preserve the approved deployable
boundaries and add no adapter, provider, queue, graph, prompt, finding,
configuration, credential, listener, or network behavior.

## Invariants

- Every behavior or status change has a witnessed tests-only RED before the
  corresponding production or tracker edit.
- `workers/security-python` and `workers/redteam-node` remain independent
  standard-runtime-only package boundaries.
- Success output is exact and contains no runtime, host, provider, or customer
  detail. Invalid invocations emit no stdout.
- No environment, dotenv, credential, profile, proxy, endpoint, provider,
  queue, graph, prompt, finding, listener, or network input is added.
- M1-01c remains Pending until M1-01b completes and exact-SHA CI passes.
- M0 blockers and R-03/R-11 status remain unchanged.

### Task 1: Start M1-01b

- [ ] Add a repository contract binding the source task, deployable ownership,
  approved design/plan, unique active status, exact arithmetic, completed
  M1-01a, Pending M1-01c, and unchanged blockers.
- [ ] Capture focused RED at the still-Pending README/tracker state.
- [ ] Move only M1-01b to In progress at `696/1/28/3` overall and M1
  `68/63/1/4/0`; document the no-I/O worker skeleton scope.
- [ ] Run focused/full pinned GREEN, audit, whitespace, and scans; commit
  `docs: start M1-01b worker directories`.

### Task 2: Implement both health commands tests-first

- [ ] Create Python and Node package metadata and tests before production
  command modules.
- [ ] Capture genuine RED for only the missing health-command APIs/modules.
- [ ] Implement the minimal Python and Node commands and run focused GREEN.
- [ ] Prove exact direct success, invalid invocation failure, no output on
  rejection, and writer-error propagation.
- [ ] Run six focused passes, Python compile/tests without bytecode, pinned Node
  tests, retained Go command regressions, full repository gates, audit,
  whitespace, and scans; commit `feat: add worker health commands`.

### Task 3: Review the worker boundaries

- [ ] Audit package/deployable ownership, exact output, argument grammar, error
  behavior, standard-runtime-only dependencies, no-I/O scope, and tests.
- [ ] Reproduce and fix every concrete finding tests-first.
- [ ] Run fresh worker/repository/audit/scan gates and record zero findings.

### Task 4: Complete, push, and close M1-01b

- [ ] Change only completion expectations and capture focused RED.
- [ ] Move only M1-01b to Complete at `696/0/29/3` and M1
  `68/63/0/5/0`; preserve M0 and all blockers.
- [ ] Run final gates, commit `docs: complete M1-01b worker directories`, push,
  and watch exact-SHA Runnable UI to success.
- [ ] Close the plan, record run/job IDs, commit/push the close SHA, watch CI,
  then start M1-01c.
