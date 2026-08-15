# M0-14b Nango OAuth proof implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove one complete OAuth authorization-code connection through the
exact free self-hosted Nango v0.70.5 runtime and return only a durable product
connection reference.

**Architecture:** Extend the proven private Nango/PostgreSQL boundary with a
generated-CA TLS OAuth fixture and a one-shot product wrapper. Reuse M0-14a's
strict parsers and ownership primitives, retain a distinct M0-14b resource
graph, and clean every exact-owned resource under an independent deadline.

**Tech Stack:** Node.js 22.23.1 host tests; exact Nango image Node 22.22.2 for
the live fixture/wrapper; Docker; PostgreSQL 16.0 Alpine; OpenSSL-generated
per-run CA/certificate; Vitest and `node:test`.

## Global constraints

- Use only the immutable Nango/PostgreSQL pins in the approved design.
- No real provider credential, dotenv/profile/proxy input, host port, or public
  network dependency.
- The fixture provider receives only private-network traffic for `github.com`.
- Product output contains only Organization ID, integration key, and connection
  ID; seeded secrets/codes/tokens are forbidden.
- Mutations are single-attempt; only ambiguous outcomes reconcile exact state.
- Main/cleanup are 360s/90s; every child is output-bounded, SIGKILLed, and reaped.
- R-08 remains Not run through M0-15.

---

### Task 1: Start M0-14b and bind the approved design

**Files:**
- Create: `app/quality/nango-oauth-proof-contract.test.ts`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: prior status contract tests that bind aggregate tracker counts
- Verify: `docs/internal/2026-08-14-m0-14b-nango-oauth-proof-design.md`
- Verify: `docs/internal/2026-08-14-m0-14b-nango-oauth-proof-implementation-plan.md`

**Interfaces:**
- Consumes: completed M0-14a status and source-plan task M0-14b.
- Produces: exactly one M0-14b In progress row and counts 712/1/13/1.

- [ ] Write a contract test requiring the exact design/pins, source dependency,
  R-08 Not run, M0-14a Complete, M0-14b In progress, counts 712/1/13/1, and no
  M0-14c row.
- [ ] Run the focused contract and record RED for the missing transition.
- [ ] Move only M0-14b to In progress; update aggregate/M0 counts and historical
  status contracts without changing M0-09, PROV-01, R-03, or R-08.
- [ ] Run focused and full pinned repository verification.
- [ ] Commit as `docs: start M0-14b Nango OAuth proof`.

### Task 2: Implement the strict product-wrapper boundary

**Files:**
- Create: `proofs/nango-oauth/product_wrapper.mjs`
- Create: `proofs/nango-oauth/product_wrapper.test.mjs`

**Interfaces:**
- Consumes: `{baseUrl, organizationId, integrationKey, clientId, clientSecret}`
  plus injected bounded HTTP and fixed generated-value configuration.
- Produces: `runOAuthConnection(input, dependencies): Promise<{organizationId:
  string, integrationKey: string, connectionId: string}>` and fixed CLI output.

- [ ] Write failing tests for strict environment/dashboard-key responses,
  integration creation, connect-session creation, exact manual redirects,
  callback completion, exact-one connection polling, and reference-only output.
- [ ] Add hostile tests for duplicate/unknown JSON keys, malformed UTF-8,
  redirect host/path drift, oversized/stalled responses, secret/token leakage,
  cancellation, and thrown/coercion values.
- [ ] Run the focused test and record missing-module RED.
- [ ] Implement a bounded HTTP client and the exact eight-step wrapper flow from
  the design. Use M0-14a `parseBoundedUniqueJson`; never stringify an error or
  response body.
- [ ] Require the final object keys in exact order and reject every seeded
  sensitive value in serialized product output.
- [ ] Run six consecutive focused passes and M0-14a parser regressions.
- [ ] Commit as `feat: add Nango OAuth product wrapper`.

### Task 3: Implement the single-use TLS fixture provider

**Files:**
- Create: `proofs/nango-oauth/fixture_provider.mjs`
- Create: `proofs/nango-oauth/fixture_provider.test.mjs`

**Interfaces:**
- Consumes exact generated `{clientId, clientSecret, code, accessToken,
  callbackUrl}` and TLS key/certificate paths.
- Produces: `createFixtureProvider(configuration, dependencies)` with
  `GET /login/oauth/authorize` and `POST /login/oauth/access_token` only.

- [ ] Write failing tests for exact authorize redirect and token JSON behavior,
  including state, callback, code challenge/verifier, client credentials, and
  single-use transitions.
- [ ] Add hostile tests for wrong host/method/path/content type, duplicate form
  members, extra query keys, callback drift, replay, invalid PKCE, oversized
  bodies, disconnects, and fixed empty logs.
- [ ] Run the focused test and record missing-module RED.
- [ ] Implement the HTTPS server with bounded request bodies, fixed response
  bytes, `timingSafeEqual` comparisons for generated values, no redirects of its
  own, and no dynamic logging.
- [ ] Run six consecutive focused passes.
- [ ] Commit as `feat: add private OAuth fixture provider`.

### Task 4: Define the M0-14b runtime manifest and workspace

**Files:**
- Create: `proofs/nango-oauth/manifest.mjs`
- Create: `proofs/nango-oauth/manifest.test.mjs`
- Create: `proofs/nango-oauth/boundary.mjs`
- Create: `proofs/nango-oauth/boundary.test.mjs`

**Interfaces:**
- Consumes M0-14a `PINS` and strict JSON parser.
- Produces: `buildOAuthRuntimeSpec(input)`, exact Docker specs for `database`,
  `nango`, `fixture`, and `wrapper`, and `createOAuthWorkspace(...)` with
  retained dev/inode identities and TLS paths.

- [ ] Write missing-module RED tests for exact prefix/labels, internal network,
  zero host ports, exact image reuse, `github.com` alias, read-only mounts,
  resource limits, synthetic grammar, and deep isolation.
- [ ] Write workspace RED tests for canonical direct-child identity, empty
  Docker config, generated-value uniqueness, certificate/key permissions,
  post-mkdtemp authority, replacement resistance, and cleanup precedence.
- [ ] Implement the immutable manifest without accepting user URLs or image
  references.
- [ ] Implement injected OpenSSL commands that create one CA and one SAN-limited
  `github.com` fixture certificate under the owned workspace; validate regular
  non-symlink files, permissions, and unchanged identities before every mount.
- [ ] Run six combined Task 2-4 passes and M0-14a's 46-case regression suite.
- [ ] Commit as `feat: isolate Nango OAuth runtime`.

### Task 5: Orchestrate the exact disposable Docker lifecycle

**Files:**
- Create: `proofs/nango-oauth/run.mjs`
- Create: `proofs/nango-oauth/run.test.mjs`
- Reuse: `proofs/nango-free-boot/run.mjs`

**Interfaces:**
- Consumes `buildOAuthRuntimeSpec`, `createOAuthWorkspace`, M0-14a bounded-child,
  projection parser, and identity validators.
- Produces: `DockerNangoOAuthRuntime`, `orchestrate(runtime)`, and `runMain()`.

- [ ] Write missing-module RED tests for exact image resolution, network/create
  argv, complete container/network/mount identities, peer transitions, wrapper
  artifact parsing, and the fixed output line.
- [ ] Add adversarial RED tests for definitive versus ambiguous create/start/
  remove, delayed mutations, incoherent cleanup snapshots, service exit races,
  CA/workspace replacement, phase revocation, pipe errors, output overflow,
  cleanup continuation/precedence, and global prefix/label/marker absence.
- [ ] Implement a single mutation settlement journal and exact resource graph in
  dependency order database -> Nango -> fixture -> wrapper.
- [ ] Implement wrapper start/attach parsing and verify the reference-only JSON
  before cleanup.
- [ ] Implement reverse exact-owned cleanup and workspace removal only after
  global Docker absence.
- [ ] Run six consecutive complete hermetic passes plus M0-14a 46/46.
- [ ] Commit as `feat: orchestrate disposable Nango OAuth proof`.

### Task 6: Expose root commands and documentation

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/nango-oauth-proof-contract.test.ts`

**Interfaces:**
- Produces: `proof:nango:oauth:test` and `proof:nango:oauth:run`.

- [ ] Extend the contract with exact scripts, fixed success line, prerequisites,
  no-credential/no-host-port boundary, reference-only output, and R-08 Not run.
- [ ] Run focused RED for missing scripts/docs.
- [ ] Add root scripts and a concise README section that distinguishes M0-14b
  OAuth evidence from M0-14a boot and future M0-14c/M0-15 work.
- [ ] Run root hermetic proof, full pinned verification, and production audit.
- [ ] Commit as `docs: expose Nango OAuth proof`.

### Task 7: Run live proof, review, completion, and ship

**Files:**
- Modify only files justified by live TDD or review findings.
- Modify: `docs/internal/implementation_status_v1.5.md` after all gates pass.
- Modify: `app/quality/nango-oauth-proof-contract.test.ts` for completion RED.

**Interfaces:**
- Produces exact fixed live evidence and the M0-14b Complete transition.

- [ ] Prove preflight zero M0-14b containers/networks/temp roots; do not touch
  shared development resources.
- [ ] Run the exact clean-environment live command. For every incompatibility,
  capture a focused RED before the minimal fix and re-prove exact cleanup.
- [ ] Run two consecutive final-code live passes and prove global zero resources
  after each.
- [ ] Run six final hermetic passes, M0-14a regressions, full pinned repository
  verification, production audit, exact dependency/license inventory, whitespace,
  and redacted staged/full-history/evidence Gitleaks scans.
- [ ] Obtain independent read-only review and fix every finding through focused
  RED/GREEN until zero Critical, Important, and Minor findings remain.
- [ ] Capture completion-contract RED; move only M0-14b to Complete at
  712/0/14/1, keep R-08 Not run and M0-14c pending, then rerun all gates.
- [ ] Commit, push `codex/zasp-implementation`, and watch Runnable UI for the
  exact final SHA to success.

## Completion checklist

- [ ] exact Nango v0.70.5 OAuth authorization-code flow
- [ ] private generated-CA TLS fixture with exact provider hostname
- [ ] exact PostgreSQL/Nango dependency boundary and no host port
- [ ] product-owned one-shot wrapper
- [ ] one durable Organization-scoped connection reference
- [ ] no generated provider or Nango secret in product output
- [ ] complete exact ownership and bounded mutation settlement
- [ ] reverse cleanup and prefix/label/marker zero-resource audit
- [ ] two consecutive final-code live runs
- [ ] M0-14a regression and full pinned gates/scans
- [ ] zero-finding independent review
- [ ] completion transition and exact-SHA CI success
