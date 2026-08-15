# M0-15 Nango Proxy Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Apply
> superpowers:test-driven-development, systematic-debugging,
> receiving-code-review, and verification-before-completion at their named
> boundaries.

**Goal:** Prove one authenticated provider GET through exact-pinned free
self-hosted Nango while product code retains no raw provider token.

**Architecture:** Build a new `proofs/nango-proxy` module with the reviewed
M0-14c four-container private topology. A strict two-request TLS fixture proves
credential verification followed by a distinct proxied provider GET. A
product wrapper creates the API-key connection, calls Nango Proxy, and returns
only scoped opaque references plus two normalized event fields. A disposable
Docker orchestrator owns every resource under the `zasp-m0-15-` namespace,
reconciles only genuinely ambiguous mutations, and proves global absence.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, exact-pinned Nango v0.70.5,
PostgreSQL 16.0-alpine, Docker CLI, Node test runner, Vitest, Markdown.

## Global constraints

- Use Nango source commit `7faf2c303bbb0322333f526e9ca31c0fe95ef58e`
  and the immutable image/config/manifest pins already accepted by M0-14a-c.
- Use no real provider credential, public provider endpoint, host-published
  port, dotenv file, ambient AWS/provider credential, proxy variable, or
  shared Docker config.
- The provider fixture accepts exactly verification then one proxied GET;
  connection success alone cannot pass.
- Product-retained output contains no provider key, Nango environment key,
  connect token, database password, encryption key, TLS content, Docker ID,
  or native response body.
- Docker mutations are single-attempt. Returned nonzero outcomes are
  definitive; only thrown, signaled, and malformed-success outcomes reconcile
  exact post-state.
- Main and cleanup work are bounded, phase-fenced, journaled, joined, and use
  independent cleanup authority with cleanup-error precedence.
- Cleanup may mutate only freshly re-proved full identities and must prove
  global prefix/proof-label/current-marker/temp absence before removing the
  retained workspace.
- M0-09 and PROV-01 remain Blocked; R-03 remains incomplete; M0-16 remains
  Pending. R-08 advances only after final live success and clean review.
- Use tests-first RED/GREEN, exact count arithmetic, atomic scoped commits,
  pinned local gates, redacted secret scans, exact-SHA push, and exact-SHA CI.

---

### Task 1: Start M0-15 and lock its repository contract

**Files:**
- Create: `app/quality/nango-proxy-proof-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Use: `docs/internal/2026-08-15-m0-15-nango-proxy-proof-design.md`
- Use: this plan

**Interfaces:**
- Source task: M0-15 depends on M0-14; deliver one authenticated proxied GET;
  verify provider success and no persisted raw provider token.
- Active status: 709 Pending / 1 In progress / 16 Complete / 1 Blocked;
  M0 is 27 / 8 / 1 / 16 / 1.
- R-08 stays exactly `Not run — M0-14a through M0-15`.

- [x] Write a deterministic filesystem-only Vitest contract that binds the
  source task, PRD Auth-plus-Proxy boundary, design, plan, scripts/README
  placeholders, exact one-row status, aggregate arithmetic, M0-14 Complete,
  M0-16 Pending, R-08 Not run, M0-09/PROV-01 Blocked, and R-03 incomplete.
- [x] Add hostile mutations for duplicate M0-15, concurrent M0-16, early
  R-08 PASS, excluded-surface claims, and count drift.
- [x] Run focused RED before changing README/tracker. Expected failures are
  only the absent M0-15 README section and active row/count transition.
- [x] Add the minimal README In-progress statement and move only M0-15 from
  Pending to In progress.
- [x] Run focused and affected status-contract GREEN under pinned Node/npm.
- [x] Run diff and redacted staged scans; commit exact scoped files as
  `docs: start M0-15 Nango proxy proof`.

---

### Task 2: Implement the exact private provider fixture

**Files:**
- Create: `proofs/nango-proxy/fixture_provider.test.mjs`
- Create: `proofs/nango-proxy/fixture_provider.mjs`

**Interfaces:**
- Input environment: fixed hostname, generated provider key, and exact TLS
  key/certificate paths.
- Request 1: exact `GET /api/v2/auth/introspect`.
- Request 2: exact `GET /api/v2/events?limit=1`.
- Output: fixed readiness line only; response 2 is canonical bounded JSON with
  one deterministic event.

- [ ] Write tests first for the exact two-request happy path, ordered state,
  exact Host/Accept/Authorization/body/query, one-use semantics, canonical
  response, and fixed output.
- [ ] Add hostile cases for replay, out-of-order calls, wrong/missing/duplicate
  headers, wrong method/path/query, redirect-like paths, extra body, partial
  body, oversized stream, invalid TLS/file boundary, logger/stream leakage,
  panic, timeout, and primitive/hostile coercion.
- [ ] Capture module-absent RED, then implement the minimal bounded HTTPS
  fixture without provider/network access in tests.
- [ ] Run the fixture tests six consecutive times.

---

### Task 3: Implement the product Proxy wrapper

**Files:**
- Create: `proofs/nango-proxy/product_wrapper.test.mjs`
- Create: `proofs/nango-proxy/product_wrapper.mjs`

**Interfaces:**
- Input: private Nango URL, dev environment, synthetic Organization/end-user,
  exact integration key, generated provider key, and forbidden-value set.
- Nango calls: environment key read, integration create, connect-session
  create, API-key authorization, exact connection re-read, then
  `GET /proxy/api/v2/events?limit=1`.
- Output: exact Organization/integration/connection references plus event ID
  and action; fixed failure line only.

- [ ] Write tests first for all exact request methods, paths, query strings,
  authorization headers, connection/provider headers, redirect policy, body
  bounds, response content type, and official v0.70.5 response shapes.
- [ ] Require strict duplicate-key JSON parsing, exact object keys, valid UTC
  timestamps, exact Organization/end-user tags, UUIDs, and deterministic event
  schema.
- [ ] Prove raw provider key, environment key, connect token, database
  password, and encryption key never enter retained/serialized product state.
- [ ] Add hostile response, arbitrary prose, extra-key, alias, duplicate-key,
  invalid-calendar, primitive, coercion, abort, timeout, oversize, and stream
  failure cases.
- [ ] Capture absent-module RED, implement minimal GREEN, and run six focused
  passes.

---

### Task 4: Implement workspace, manifest, and disposable orchestration

**Files:**
- Create: `proofs/nango-proxy/boundary.test.mjs`
- Create: `proofs/nango-proxy/boundary.mjs`
- Create: `proofs/nango-proxy/manifest.test.mjs`
- Create: `proofs/nango-proxy/manifest.mjs`
- Create: `proofs/nango-proxy/run.test.mjs`
- Create: `proofs/nango-proxy/run.mjs`

**Interfaces:**
- Prefix/label: `zasp-m0-15-` / `zasp.dev/proof=m0-15`.
- Roles: database, Nango, fixture, wrapper, and one internal network.
- Success: `Nango proxy proof passed: get=true response=true product_state_safe=true cleanup=true.`
- Main/cleanup budgets: finite named budgets with margin over child operations.

- [ ] Write boundary RED for absent workspace APIs, then implement exact
  direct-child mkdtemp ownership, 0700 Docker config, TLS identities/digests,
  pre/post-command reproof, cleanup-time dev/inode/canonical reproof, and
  global prefix absence.
- [ ] Write manifest RED for absent runtime spec, then implement exact pins,
  names, environments, user/security/resource bounds, mounts, internal
  network, two-request fixture command, and proxy-wrapper command.
- [ ] Write orchestrator RED for absent runtime and cover image resolution,
  full-ID candidate retention, definitive-vs-ambiguous create/start/schema/
  remove behavior, exact metadata, current network peers, output parsing,
  mutation settlement, phase fencing, cleanup continuation/precedence, and
  global absence.
- [ ] Include rejected/ambiguous Docker reads, stdout/stderr pipe errors,
  output caps, SIGKILL deadlines, late continuations, replacement resources,
  mount/env order, intrinsic volumes, generic-vs-exact missing responses,
  stale other-marker resources, and workspace replacement cases.
- [ ] Run the entire new proof suite six consecutive times, then run all
  M0-14a/b/c regression suites.

---

### Task 5: Expose commands and operator documentation

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/nango-proxy-proof-contract.test.ts`

**Interfaces:**
- `proof:nango:proxy:test`: hermetic only, no Docker/provider.
- `proof:nango:proxy:run`: exact disposable live lifecycle.

- [ ] Extend the repository contract tests first and capture RED for the
  absent scripts/documentation.
- [ ] Add exact root scripts and README commands, private-boundary statement,
  fixed success line, output/secrecy guarantee, Docker prerequisite, and
  current In-progress/R-08 Not-run status.
- [ ] Prove the hermetic command leaves no generated bytecode/cache/temp
  artifact and performs no Docker/provider call.
- [ ] Run focused GREEN, root proof tests, full pinned repository verification,
  production audit, license inventory, syntax/lint, and diff checks.
- [ ] Commit the scoped implementation as atomic reviewed task commits.

---

### Task 6: Run live proof, review, complete R-08, and deliver

**Files:**
- Modify: proof source/tests only for evidence-backed live/review fixes
- Modify: `README.md`
- Modify: `app/quality/nango-proxy-proof-contract.test.ts`
- Modify: aggregate-count assertions in affected quality contracts
- Modify: `docs/internal/2026-08-15-m0-15-nango-proxy-proof-implementation-plan.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/decisions/mvp-risk-register.md`
- Create ignored: `.superpowers/sdd/2026-08-15-m0-15-nango-proxy-proof-implementation-plan/task-6-report.md`
- Append ignored: `.superpowers/sdd/2026-08-15-m0-15-nango-proxy-proof-implementation-plan/progress.md`
- Create ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-15-report.md`
- Append ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`

**Interfaces:**
- Completion status: 709 Pending / 0 In progress / 17 Complete / 1 Blocked;
  M0 is 27 / 8 / 0 / 17 / 1.
- R-08 becomes `PASS — M0-15 — <exact evidence path and delivery SHA>` only
  after its whole multi-task criterion is evidenced.

- [ ] Prove preflight zero for every M0-15 prefix/label/network/temp selector
  and fingerprint any shared Nango/PostgreSQL targets without mutation.
- [ ] Run the exact clean-environment root command. Diagnose every failure
  from sanitized phase/boolean evidence; capture a focused RED before each
  production fix; re-prove and remove only exact-owned retained candidates.
- [ ] Obtain two consecutive final-code live passes. After each, prove zero
  containers/networks/temp roots and unchanged shared fingerprints.
- [ ] Capture a product-fields-only result proving one exact provider event,
  the expected Organization/reference linkage, and absence of all raw keys,
  connect tokens, native labels, Docker values, and provider body aliases.
- [ ] Run six hermetic passes, all Nango regressions, full pinned repository
  verify, production audit, exact license inventory, whitespace/syntax, and
  pinned redacted Gitleaks over proof tree, staged content, exact evidence,
  exact commits, and full history.
- [ ] Perform a whole-range read-only review and fix every Critical,
  Important, and Minor finding tests-first. Re-run live lifecycle after any
  ownership, mutation, timing, or cleanup change.
- [ ] Add hostile completion/status tests and capture RED for the stale active
  row/R-08 Not-run state. Move only M0-15 to Complete, advance only R-08 to
  PASS, preserve M0-16 Pending and all blocked/incomplete boundaries, then run
  focused GREEN and all final gates.
- [ ] Record exact evidence, commit, push `codex/zasp-implementation`, prove
  local/tracking/origin SHA equality, and watch the Runnable UI run for that
  exact SHA to terminal success.
