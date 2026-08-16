# M1-28c Event-Ingest Health Wiring Implementation Plan

> Execute test-first in the isolated implementation worktree. Every behavior,
> dependency-policy, documentation, and status transition requires a witnessed
> tests-only RED before production changes. Do not start M1-28d.

**Goal:** Make `event-ingest` expose the exact shared health contract and prove
that liveness and readiness are distinct states.

**Architecture:** Keep event-ingest standalone. Add one local bounded server
lifecycle around the M1-28a shared handler, then wire the existing command to a
fixed internal `:8081` listener and SIGINT/SIGTERM shutdown. Expand only the
exact repository-owned shared-health dependency policy.

**Toolchain:** Go 1.25, standard-library `net/http`, standalone
`services/health`, Node 22.23.1, npm 10.9.8, Vitest, Gitleaks 8.30.1, GitHub
Actions Runnable UI.

## Scope and invariants

- Work only on M1-28c. M1-28d remains Pending.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Use the exact shared handler; add no ingest route, queue loop, provider call,
  default mux, public ingress, environment intake, or third-party dependency.
- Construct and validate before listener/output; close every retained listener
  on failure and contain panics.
- Liveness is independent of readiness. Ready is true only during serving and
  false before bounded independent shutdown.
- Preserve the exact build-version grammar and output line.
- Use only injected or numeric-loopback listeners in tests.

## Task 1: Design, plan, and start M1-28c

1. Commit this design and plan separately.
2. Add one exact repository contract for source/dependency/scope/status/docs.
3. Capture stale-status RED, then move only M1-28c In progress at
   `665/1/59/3` overall and `68/32/1/35/0` for M1.
4. Keep M1-28b Complete, M1-28d Pending, and blockers unchanged.

## Task 2: Capture genuine runtime and dependency RED

1. Add lifecycle and command smoke/failure tests before production changes.
2. Require liveness 200/readiness 503 before serving and readiness 200 only
   during serving.
3. Add dependency tests for the exact event-ingest shared-health edge and all
   hostile consumer/version/replacement/indirect variants.
4. Run focused tests and record missing symbols/policy as genuine RED.

## Task 3: Implement the bounded local lifecycle

1. Add the exact shared-health requirement/replacement to event-ingest.
2. Expand the validator to the exact two-consumer allowlist.
3. Implement exact server bounds, private mux, atomic single-use fence,
   readiness transitions, independent five-second shutdown, joined cleanup,
   typed-nil/direct-state rejection, and fixed errors.
4. Reach focused GREEN, six race passes, and 100% lifecycle statements.

## Task 4: Wire the production command

1. Construct first, reject cancellation, bind `:8081`, emit the exact existing
   build line, and serve under the production signal context.
2. Close retained candidates on every failure and contain panics.
3. Prove the bounded numeric-loopback smoke and failure/cleanup matrix.
4. Build and run a linked production binary, poll all routes, terminate it, and
   prove exact output/no stderr/no retained process.

## Task 5: Integrate docs and full gates

1. Add `event-ingest:health:test` to root scripts and document the exact internal
   boundary, distinction, command, exclusions, and M1-28d Pending state.
2. Prove package-lock and third-party inventory unchanged.
3. Run module/full race, six focused passes, coverage, tidy-diff, verify, vet,
   dependency validation, full pinned verify, eight builds, audit, whitespace,
   source audit, and redacted staged/history/evidence scans.
4. Commit implementation atomically.

## Task 6: Independent review and fixes

1. Request read-only whole-range Critical/Important/Minor review.
2. Reproduce every accepted finding with tests-only RED and commit minimal
   fixes separately.
3. Repeat until Critical 0 / Important 0 / Minor 0 / Ready Yes.

## Task 7: Complete, ship, and close

1. Capture stale completion RED for `665/0/60/3` overall and
   `68/32/0/36/0` for M1.
2. Move only M1-28c Complete; keep M1-28d Pending and blockers unchanged.
3. Run final gates/scans, commit, push, and require exact-SHA Runnable UI
   success.
4. Check every closure box in a separate one-file commit, push it, require its
   exact-SHA CI success, and prove local/upstream/origin equality, 0/0
   divergence, clean tree, and final evidence scans.

## Closure checklist

- [ ] Task 1 design/plan/status transition passes.
- [ ] Task 2 genuine runtime/dependency RED is recorded.
- [ ] Task 3 bounded lifecycle is GREEN at 100% statements.
- [ ] Task 4 linked real-listener command smoke passes.
- [ ] Task 5 full repository gates, audits, scans, and docs pass.
- [ ] Task 6 independent review is zero-finding and Ready Yes.
- [ ] Task 7 completion, exact-SHA CI, synchronization, and closure pass.
