# M0-14c Nango API-key Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete one real private API-key connection through exact-pinned free self-hosted Nango and return only a durable product connection reference.

**Architecture:** Reuse the reviewed M0-14b private PostgreSQL/Nango/TLS-fixture/wrapper topology under a separate namespace. The wrapper drives Nango's real public API-key endpoint; the built-in `1password-events` verification hook calls a single-use private TLS fixture, while the product artifact contains only three reference fields.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, Nango v0.70.5, PostgreSQL 16.0 Alpine, Docker CLI, Vitest, Node test runner.

## Global constraints

- Follow Tests-first RED before every production behavior change.
- Use only the exact image/source/provider pins in the approved M0-14c design.
- Treat Docker, HTTP, filesystem, process, and provider output as hostile input.
- Accept no dotenv, ambient credentials, proxy, profile, Docker authentication,
  host publication, or real provider endpoint.
- The raw provider key may exist only in generated proof memory, fixture state,
  Nango transport, and Nango encrypted credential storage; never product state.
- Use one single mutation settlement journal and require global
  prefix/label/marker absence before workspace removal and completion.
- Do not advance R-08 or start M0-14/M0-15 before their source-plan tasks.
- Keep M0-09 and PROV-01 Blocked and R-03 incomplete.

---

### Task 1: Start contract, design, and authoritative status

**Files:**
- Create: `app/quality/nango-api-key-proof-contract.test.ts`
- Create: `docs/internal/2026-08-15-m0-14c-nango-api-key-proof-design.md`
- Create: `docs/internal/2026-08-15-m0-14c-nango-api-key-proof-implementation-plan.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: status-sensitive contracts under `app/quality/`

**Interfaces:**
- Consumes: source M0-14c and R-08 boundaries.
- Produces: exact design, task plan, and unique active-task status.

- [x] Add the repository contract and run focused Vitest to capture the three
  intended missing-design/missing-plan/stale-status failures.
- [x] Record the selected fixture architecture, exact pins, resource graph,
  wrapper flow, privacy boundary, mutation taxonomy, and completion gates.
- [x] Move only M0-14c to In progress at 711/1/14/1 overall and
  27/10/1/14/1 in M0; preserve all complete, blocked, and risk rows.
- [x] Run focused related contracts, full pinned verification, audit,
  whitespace, and redacted secret scans.
- [x] Commit exactly the Task 1 files with message
  `docs: start M0-14c Nango API-key proof`.

### Task 2: Owned workspace and single-use TLS fixture

**Files:**
- Create: `proofs/nango-api-key/boundary.test.mjs`
- Create: `proofs/nango-api-key/boundary.mjs`
- Create: `proofs/nango-api-key/fixture_provider.test.mjs`
- Create: `proofs/nango-api-key/fixture_provider.mjs`

**Interfaces:**
- Consumes: marker, proof source path, canonical temp parent, bounded command
  executor, random byte source.
- Produces: `createApiKeyWorkspace`, `reproveApiKeyWorkspace`,
  `removeApiKeyWorkspace`, `validateApiKeyTemporaryPrefixEntries`, and a strict
  single-use HTTPS fixture handler/server.

- [x] Write boundary tests for exact workspace grammar, generated CA/server
  files, `events.1password.com` SAN, synthetic provider key, identity reproof,
  replacement safety, cleanup precedence, and global stale-prefix rejection.
- [x] Run the boundary tests and require missing-module/symbol RED.
- [x] Implement only the owned workspace and TLS boundary needed by the tests.
- [x] Write fixture tests for exact TLS host/method/path/query/body/authorization,
  one accepted request, replay rejection, malformed configuration, bounded
  output, and fixed failure behavior; capture RED.
- [x] Implement the minimal single-use fixture and run both suites GREEN six
  consecutive times before the scoped commit.

### Task 3: Strict API-key product wrapper

**Files:**
- Create: `proofs/nango-api-key/product_wrapper.test.mjs`
- Create: `proofs/nango-api-key/product_wrapper.mjs`

**Interfaces:**
- Consumes: fixed environment configuration and a bounded HTTP request
  dependency.
- Produces: `runApiKeyConnection`, `configurationFromEnvironment`,
  `boundedRequest`, `runMain`, and exactly one reference-only JSON artifact.

- [x] Write tests for exact Nango API-key discovery, `1password-events`
  integration creation, scoped connect session, one
  `/api-auth/api-key/<integration>` request, exact provider verification result,
  credential-free connection read, and reference-only output; capture RED.
- [x] Add hostile response tests for duplicate/unknown/malformed/oversized JSON,
  status/header/key/timestamp/Organization drift, redirects, cancellation,
  timeout, retries, and secret leakage; keep them RED.
- [x] Implement the strict wrapper with one mutation attempt per mutation and
  bounded read-only retries only.
- [x] Run focused GREEN six times and commit the exact wrapper slice.

### Task 4: Immutable manifest and runtime ownership

**Files:**
- Create: `proofs/nango-api-key/manifest.test.mjs`
- Create: `proofs/nango-api-key/manifest.mjs`
- Modify only if a proved shared defect exists: `proofs/nango-free-boot/*` or
  `proofs/nango-oauth/*` with their full regressions.

**Interfaces:**
- Consumes: validated workspace identity and generated synthetic values.
- Produces: `buildApiKeyRuntimeSpec`, exact image/platform/resource definitions,
  and deep immutable role specifications.

- [x] Write tests for marker/platform/path/key grammar, exact four-role graph,
  private network, no host ports, exact environment/commands/mounts/security,
  fixture alias, product secret denylist, and deep isolation; capture RED.
- [x] Implement the minimal immutable manifest using reviewed shared pins.
- [x] Run manifest, boundary, fixture, wrapper, M0-14b, and M0-14a regressions
  GREEN before the scoped commit.

### Task 5: Disposable Docker orchestration

**Files:**
- Create: `proofs/nango-api-key/run.test.mjs`
- Create: `proofs/nango-api-key/run.mjs`

**Interfaces:**
- Consumes: workspace, immutable runtime specification, Docker command runner,
  filesystem boundary, phase signals, and mutation journal.
- Produces: exact image/network/container lifecycle, schema readiness, wrapper
  artifact validation, reverse cleanup, global absence, fixed CLI output.

- [x] Write hermetic lifecycle tests for image resolution, exact network and
  four-container ownership, database/Nango/fixture readiness, schema creation,
  wrapper completion, artifact parsing, and exact success; capture RED.
- [x] Add hostile tests for definitive versus ambiguous pull/create/start/remove,
  delayed mutation settlement, candidate retention, complete metadata drift,
  coherent network-peer changes, phase revocation, cleanup continuation and
  precedence, filesystem replacement, output cap, and global absence.
- [x] Implement one bounded main phase, one independent cleanup phase, a single
  mutation settlement journal, exact fresh reproof before mutation, and fixed
  top-level output.
- [x] Run the full proof suite six times, both predecessor proof suites, syntax,
  lint, and repository verification before commit.

### Task 6: Root commands and operator documentation

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/nango-api-key-proof-contract.test.ts`

**Interfaces:**
- Consumes: hermetic and live runner entry points.
- Produces: `proof:nango:api-key:test`, `proof:nango:api-key:run`, exact fixed
  output documentation, and retained status/risk boundaries.

- [x] Add contract assertions for missing scripts and README and capture focused
  RED.
- [x] Add the exact root scripts and document prerequisites, images, private
  fixture, API-key verification, reference-only state, cleanup, fixed output,
  and non-claims.
- [x] Require the hermetic root command to make no Docker/provider call and leave
  no generated artifact.
- [x] Run focused/full gates, production audit, license inventory, diff, and
  secret scans; commit the exact documentation slice.

### Task 7: Live proof, review, completion, and delivery

**Files:**
- Modify only files justified by live TDD or review findings.
- Modify: `docs/internal/implementation_status_v1.5.md` after every gate passes.
- Update ignored task/authoritative reports and append-only ledgers.

**Interfaces:**
- Consumes: exact root live command and all retained proof invariants.
- Produces: reviewed live evidence, completion state, pushed exact SHA, and
  successful Runnable UI evidence.

- [x] Prove preflight global absence and run the exact clean-environment live
  command. For every mismatch, gather bounded nonsecret evidence, write the
  focused failing test, implement the minimal fix, and rerun local gates.
- [x] Obtain two consecutive final-code live passes and zero global
  prefix/proof-label/run-marker/temp resources after each.
- [x] Run six final hermetic passes, M0-14a/M0-14b regressions, full pinned
  repository verification, production audit, exact license inventory,
  whitespace, and redacted staged/history/evidence scans.
- [x] Perform independent read-only review and fix every Critical, Important,
  and Minor finding through focused RED/GREEN until zero findings remain.
- [x] Capture completion-contract RED, move only M0-14c to Complete at
  711/0/15/1 overall and 27/10/0/15/1 in M0, retain R-08 Not run, and do not
  start M0-14.
- [x] Commit, push `codex/zasp-implementation`, and watch Runnable UI for the
  exact final SHA through terminal success.

## Completion checklist

- [x] exact Nango v0.70.5 API-key authorization route
- [x] single-use generated-key private TLS fixture verification
- [x] exact PostgreSQL/Nango dependency boundary and no host port
- [x] one Organization/end-user/integration-scoped durable connection reference
- [x] zero raw provider key in product state and fixed output
- [x] exact mutation reconciliation and reverse cleanup
- [x] global zero-resource audit after two final live passes
- [x] six final hermetic passes and predecessor regressions
- [x] repository verification, audit, license, whitespace, and secret gates
- [x] zero-finding independent read-only review
- [x] exact completion commit, remote synchronization, and successful exact-SHA CI
