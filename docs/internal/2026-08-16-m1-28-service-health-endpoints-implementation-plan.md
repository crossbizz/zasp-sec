# M1-28 Service Health Endpoints Implementation Plan

> Execute test-first in the isolated implementation worktree. Every contract,
> documentation, command, and status transition requires a witnessed tests-only
> RED before production changes. Do not start M1-29.

**Goal:** Register one exact internal health OpenAPI/service contract and prove
that every wired Go command exposes the same endpoint semantics.

**Architecture:** Keep the public product OpenAPI and generated client
unchanged. Add one separate self-contained OpenAPI 3.1 internal-health document,
one four-command service matrix, and one root gate over the strict document plus
all existing Go health race suites.

**Toolchain:** Go 1.25, Node 22.23.1, npm 10.9.8, OpenAPI 3.1, exact-pinned
js-yaml/Redocly, Vitest, Gitleaks 8.30.1, GitHub Actions Runnable UI.

## Scope and invariants

- Work only on M1-28. M1-29 remains Pending.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Do not change Go runtime behavior, the public product OpenAPI paths, generated
  TypeScript client, UI/API map, product authentication, or deployment state.
- Document exactly four root paths, GET/HEAD, closed response schemas and
  headers, four service labels, and the reviewed readiness lifecycle.
- Keep the internal-health document self-contained, serverless, provider-free,
  customer-free, and outside the public client/data-plane namespace.
- Root verification must execute the strict document/matrix test and every Go
  command health race suite.

## Task 1: Design, plan, and start M1-28

1. Commit the design and this plan separately.
2. Add an exact repository contract for source/dependency/scope/status/docs.
3. Capture stale-status RED, then move only M1-28 In progress at
   `663/1/61/3` overall and `68/30/1/37/0` for M1.
4. Keep M1-28d Complete, M1-29 Pending, and blockers unchanged.

## Task 2: Capture genuine contract RED

1. Add the strict internal OpenAPI/service-matrix test before its files exist.
2. Require exact paths/methods/statuses/media types/headers/schemas/service
   catalog and lifecycle prose.
3. Add hostile document and matrix mutations, including duplicate YAML keys.
4. Run focused tests and record missing files/command as genuine RED.

## Task 3: Implement the internal OpenAPI contract

1. Add `openapi/internal-health.yaml` as a self-contained OpenAPI 3.1 document.
2. Define only the exact four root probe paths with GET and HEAD.
3. Define closed liveness/readiness/version schemas, bounded metrics text, and
   reusable exact response-header components.
4. Extend pinned Redocly lint and strict OpenAPI testing without changing the
   public generated-client input or UI/API map.

## Task 4: Register the service matrix and root gate

1. Add `docs/internal/service-health-endpoints.md` with exactly four commands,
   service labels, fixed listener, paths, lifecycle, and deployment boundary.
2. Add `health:contract:test` for the strict Node contract and all existing Go
   health race suites.
3. Wire the command into root verification and document it in README.
4. Prove public OpenAPI generation and UI/API coverage remain byte/semantically
   unchanged.

## Task 5: Full verification and implementation commit

1. Run six fresh health-contract passes, each Go module's tidy/verify/vet,
   strict OpenAPI tests/lint/check, UI/API coverage, and generated-client drift.
2. Run full pinned repository verify, eight repository builds, production
   audit, license/dependency checks, whitespace, and redacted scans.
3. Commit the implementation atomically.

## Task 6: Independent review and fixes

1. Request read-only whole-range Critical/Important/Minor review.
2. Reproduce every accepted finding with tests-only RED and commit minimal
   fixes separately.
3. Repeat until Critical 0 / Important 0 / Minor 0 / Ready Yes.

## Task 7: Complete, ship, and close

1. Capture stale completion RED for `663/0/62/3` overall and
   `68/30/0/38/0` for M1.
2. Move only M1-28 Complete; keep M1-29 Pending and blockers unchanged.
3. Run final gates/scans, commit, push, and require exact-SHA Runnable UI
   success.
4. Check every closure box in a separate one-file commit, push it, require its
   exact-SHA CI success, and prove local/upstream/origin equality, 0/0
   divergence, clean tree, and final evidence scans.

## Closure checklist

- [ ] Task 1 design/plan/status transition passes.
- [ ] Task 2 genuine OpenAPI/service-matrix RED is recorded.
- [ ] Task 3 strict internal OpenAPI contract is GREEN.
- [ ] Task 4 exact service matrix and root cross-command gate pass.
- [ ] Task 5 full repository gates, audits, scans, and docs pass.
- [ ] Task 6 independent review is zero-finding and Ready Yes.
- [ ] Task 7 completion, exact-SHA CI, synchronization, and closure pass.
