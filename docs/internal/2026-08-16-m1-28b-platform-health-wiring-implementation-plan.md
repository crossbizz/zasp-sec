# M1-28b Platform Health Wiring Implementation Plan

> Execute test-first in the isolated implementation worktree. Every behavior,
> dependency-policy, documentation, and status transition requires a witnessed
> tests-only RED before production changes. Do not start M1-28c.

**Goal:** Make `agentsec-api` and `agentsec-worker` expose the exact shared
health contract over real bounded HTTP listeners with graceful readiness and
shutdown behavior.

**Architecture:** Add one platform-local `healthserver` lifecycle package that
uses the standalone M1-28a handler. Both commands retain their exact build line
and delegate listener serving to the same single-use runtime. Production binds
`:8081`; tests inject numeric loopback listeners and process boundaries.

**Toolchain:** Go 1.25, standard-library `net/http`, standalone
`services/health`, Node 22.23.1, npm 10.9.8, Vitest, Gitleaks 8.30.1, GitHub
Actions Runnable UI.

## Scope and invariants

- Work only on M1-28b. M1-28c remains Pending.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Use the exact shared handler; do not duplicate route or payload logic.
- Add no third-party dependency, default mux registration, provider call,
  product route, worker loop, public ingress, or customer-derived value.
- Construct and validate before opening a listener or emitting output.
- Use finite server and shutdown bounds and join shutdown before return.
- Set readiness true only for the serving lifetime and false before drain.
- Keep the exact existing build-version grammar and output line.
- Test only on numeric loopback or injected listeners; no provider or shared
  service may be contacted.

## Task 1: Start M1-28b with repository contracts

**Files**

- Create: `app/quality/platform-health-wiring-contract.test.ts`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `README.md`

1. Add a quality contract that binds the source row, this design/plan, exact
   two-command scope, shared-handler import, `:8081`, four paths, no third-party
   dependency, and M1-28c Pending boundary.
2. Require the starting arithmetic `666/1/58/3` overall and
   `68/33/1/34/0` for M1, exactly one M1-28b In-progress row, M1-28a Complete,
   and no M1-28b Complete row.
3. Run the focused test before README/tracker edits and record the exact stale
   assertions as RED.
4. Update README/tracker only, rerun GREEN, scan, and commit the transition.

## Task 2: Capture runtime and dependency-policy RED

**Files**

- Create: `services/platform/healthserver/server_test.go`
- Create or modify: `scripts/validate-dependencies.test.mjs`
- Modify: `services/platform/agentsec-api/main_test.go`
- Modify: `services/platform/agentsec-worker/main_test.go`

1. Write `healthserver` tests before the package exists. Require exact finite
   `http.Server` settings, four-route real-listener behavior, ready lifecycle,
   independent graceful shutdown, nil/canceled/repeated/concurrent rejection,
   serve/shutdown error precedence, no default mux, and 100% statements.
2. Add command smoke tests before wiring exists. Each must use a numeric
   loopback listener, wait through an explicit started boundary, GET all four
   routes, assert exact service/version content, cancel, and prove termination.
3. Add command failure tests for construction-before-listen/output, listen
   failure, writer failure with exact listener close, and canceled startup.
4. Add dependency-validator tests proving only the exact repository-owned
   `services/health v0.0.0 => ../health` replacement is excluded from the
   third-party lock; wrong module, version, path, missing target manifest,
   remote-looking path, or extra replacement fails.
5. Run focused Go/Node tests and record the missing-package/symbol and policy
   failures as genuine RED. Production/module files must still be untouched.

## Task 3: Implement the bounded shared runtime

**Files**

- Create: `services/platform/healthserver/server.go`
- Modify: `services/platform/go.mod`
- Modify: `scripts/validate-dependencies.mjs`

1. Add the exact local `services/health` requirement and replacement.
2. Teach dependency collection the exact canonical internal replacement rule,
   without weakening normal direct-dependency inventory.
3. Implement `healthserver.New` and single-use `Serve` with the M1-28a handler,
   exact server settings, atomic use fencing, readiness transitions, an
   independent five-second shutdown context, joined shutdown, and fixed errors.
4. Run focused tests until GREEN, then add hostile malformed interface/direct
   state, early-cancel, close-before-serve, and blocked-request drain tests.
5. Run six fresh race passes and a coverage profile requiring 100% statements.

## Task 4: Wire both production commands

**Files**

- Modify: `services/platform/agentsec-api/main.go`
- Modify: `services/platform/agentsec-worker/main.go`
- Modify: the two command test files

1. Add injectable listen and serve boundaries without environment or flag
   intake. Construct first, listen on `:8081`, emit the preserved exact build
   line, serve, and close on every failure.
2. Production `main` uses one `SIGINT`/`SIGTERM` context and fixed nonzero exit
   on any error without logging details.
3. Prove both real-listener smoke tests and every failure/cleanup case GREEN.
4. Build both commands and run exact link-time version smoke processes under
   bounded cancellation, proving all four endpoints rather than a print-only
   process.

## Task 5: Integrate documentation and root gates

**Files**

- Modify: `README.md`
- Modify: `package.json`
- Modify: `build/dependencies.lock.yaml` only if the validator's exact internal
  rule does not keep the third-party inventory unchanged
- Modify: `app/quality/platform-health-wiring-contract.test.ts`

1. Add `platform:health:test` running the platform healthserver and both command
   packages with the race detector.
2. Document the internal `:8081` boundary, exact endpoints, readiness lifetime,
   preserved build line, local command, and M1-28c Pending status.
3. Prove package-lock bytes and third-party dependency count unchanged.
4. Run focused contracts, six race passes, 100% coverage, both command builds,
   `go mod tidy -diff`, `go mod verify`, `go vet ./...`, dependency validation,
   full pinned `npm run verify`, production audit, whitespace, and source audit.
5. Run pinned redacted Gitleaks scans over the scoped diff, staged bytes, all
   history, and ignored evidence. Commit atomically.

## Task 6: Independent review and fixes

1. Prepare the exact base-to-head package plus design, plan, source row, shared
   handler contract, runtime, commands, tests, dependency policy, README,
   tracker, and gate evidence.
2. Request a read-only whole-range review for Critical, Important, and Minor
   findings. The reviewer must run only non-live gates.
3. Reproduce every accepted finding with tests-only RED, apply the smallest
   fix, rerun focused/full gates, and commit fixes separately.
4. Repeat review until zero findings and Ready Yes.

## Task 7: Complete, ship, and close

1. Add a completion contract RED requiring `666/0/59/3` overall,
   `68/33/0/35/0` for M1, exactly one M1-28b Complete row, no active row,
   M1-28c Pending, and exact README completion wording.
2. Update tracker, README, authoritative report, task reports, and append-only
   ledgers; run focused GREEN and every final local gate/scanner again.
3. Commit the completion transition, push the exact branch, and wait for the
   Runnable UI workflow for that exact SHA to finish successfully.
4. Mark all plan boxes complete in a separate closure commit, push, and verify
   the closure SHA in a second exact-SHA Runnable UI run.
5. Require local, upstream, and origin SHA equality; zero behind/ahead; clean
   tracked/index state; all-history/evidence scans; M1-28c Pending; and no
   blocker/status drift before declaring completion.

## Closure checklist

- [x] Task 1 status transition is complete.
- [x] Task 2 genuine runtime/dependency RED is recorded.
- [x] Task 3 shared runtime is implemented and 100% statement-covered.
- [x] Task 4 both platform commands pass real-listener smoke tests.
- [x] Task 5 full repository gates, audits, scans, and docs pass.
- [x] Task 6 independent whole-range review is zero-finding and Ready Yes.
- [x] Task 7 completion, exact-SHA CI, synchronization, and plan closure pass.
