# M0-16 Promptfoo Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Apply
> superpowers:test-driven-development, systematic-debugging,
> receiving-code-review, requesting-code-review, and
> verification-before-completion at their named boundaries.

**Goal:** Run one exact-pinned Promptfoo direct prompt-injection case against a
local fake agent and normalize it to an objective, verdict, and evidence
reference.

**Architecture:** Add an isolated `proofs/promptfoo-redteam` module. A strict,
intentionally vulnerable fake agent and a one-shot official Promptfoo 0.121.19
runner share one disposable internal Docker network with no host ports or
external egress. Promptfoo writes one bounded JSON artifact. A strict
product-owned adapter validates the exact case/result and retains only an
objective slug, product verdict, and content-addressed evidence reference. A
phase-fenced Docker orchestrator owns, reconciles, cleans, and globally audits
every per-run resource and temporary directory.

**Tech stack:** Node.js 22.23.1, npm 10.9.8, official Promptfoo 0.121.19
container, Docker CLI, Node test runner, Vitest, Markdown.

## Global constraints

- Pin source commit `1ede17aaed940e6dff04f71d24e4ecc011809dae`,
  source tree `8c8043c046e3ad5d09f456dcf0db9ae4344521be`, npm integrity
  `sha512-5YebsCED/bmR9JktH9YNU62Tr1m3ncFMlM2tKrguI8vFFUfvqxhNzUBa3Z6huG7OvDKbi69UpamU4CLtYLDezQ==`,
  and official image index digest
  `sha256:50d3a796710e4db7a5ede90bf27dc28146ef022a7ebb83914c5105608396fd96`.
- Use no model/provider credential, Promptfoo Cloud, hosted generation,
  external target, `.env`, host-published port, ambient proxy/profile/auth
  state, shared Docker config, or shared service mutation.
- Run exactly one curated direct injection through Promptfoo's real HTTP
  provider and assertion engine; a simulated Promptfoo artifact cannot satisfy
  live completion.
- Retain exactly objective, verdict, and evidence reference. Raw prompt,
  response, canary, Promptfoo/Docker IDs, paths, native labels, and engine
  errors are forbidden in product state and fixed output.
- Docker mutations are single-attempt. Returned nonzero results are definitive;
  only thrown, signaled, overflow, deadline, and malformed-success outcomes may
  enter bounded exact-state reconciliation.
- Main and cleanup work are finite, phase-fenced, journaled, joined, and use
  independent cleanup authority with cleanup-error precedence.
- Cleanup may mutate only freshly re-proved full identities. Global prefix,
  proof-label, current-marker, network-peer, and temp-root absence must pass
  before workspace deletion and success.
- Use behavior-first tests with hand-derived fixtures. Capture genuine RED
  before every production slice and every review/live fix.
- Keep M0-09 and PROV-01 Blocked, R-03 incomplete, M0-17 Pending, and R-09 Not
  run until final completion evidence.
- Use atomic scoped commits, pinned local gates, redacted secret scans,
  exact-SHA push, and exact-SHA Runnable UI CI.

---

### Task 1: Start M0-16 and bind repository status

**Files:**
- Create: `app/quality/promptfoo-redteam-proof-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Use: `docs/internal/2026-08-15-m0-16-promptfoo-proof-design.md`
- Use: this plan

**Interfaces:**
- Source task: M0-16 depends on M0-15; run one prompt-injection case against a
  local fake agent; normalize objective, verdict, and evidence reference.
- Active aggregate: 708 Pending / 1 In progress / 17 Complete / 1 Blocked.
- Active M0: 27 total / 7 Pending / 1 In progress / 17 Complete / 1 Blocked.
- R-09 stays exactly `Not run — M0-16`.

- [ ] Write deterministic filesystem-only Vitest contracts for the exact source
  task, PRD Red Team boundary, design/plan decisions, future root scripts and
  README section, exact one-row status, aggregate arithmetic, M0-15 Complete,
  M0-17 Pending, R-09 Not run, and blocked/incomplete boundaries.
- [ ] Add hostile mutations for duplicate M0-16, concurrent M0-17, premature
  R-09 PASS, simulated-engine wording, credential/external-target claims, and
  aggregate drift.
- [ ] Run focused RED before changing README or tracker. Expected failures are
  only the absent M0-16 README section and active row/count transition.
- [ ] Add the minimal README In-progress statement and move only M0-16 from
  Pending to In progress.
- [ ] Run focused and affected status-contract GREEN under pinned Node/npm.
- [ ] Run diff and redacted staged scans; commit exact scoped files as
  `docs: start M0-16 Promptfoo proof`.

---

### Task 2: Implement the strict fake agent and product normalizer

**Files:**
- Create: `proofs/promptfoo-redteam/fake_agent.test.mjs`
- Create: `proofs/promptfoo-redteam/fake_agent.mjs`
- Create: `proofs/promptfoo-redteam/normalizer.test.mjs`
- Create: `proofs/promptfoo-redteam/normalizer.mjs`

**Interfaces:**
- Agent health: exact `GET /health` and canonical readiness bytes.
- Agent evaluation: exact one-use `POST /v1/agent` with one-key JSON body and
  canonical canary response.
- Normalizer input: one bounded Promptfoo version-3 JSON export.
- Normalizer output: exact three-key product record.

- [ ] Write fake-agent behavior tests first for readiness, one exact injection,
  method/path/query/Host/header/body bounds, duplicate JSON keys, canonical
  bytes, one-use ordering, timeout, abort, stream error, panic, and fixed output.
- [ ] Capture absent-module RED, then implement the minimal strict local server.
- [ ] Write normalizer tests first using an independently hand-derived complete
  Promptfoo 0.121.19 artifact. Bind exact result counts, test metadata, provider,
  assertion, raw canary, dynamic-ID/timestamp grammar, byte digest, and exact
  normalized record.
- [ ] Add hostile missing/extra/alias/duplicate-key, multiple-result,
  pass/error/score drift, invalid calendar/ID, primitive/coercion, raw-data
  leakage, oversized file, symlink, replacement, and read-race cases.
- [ ] Capture absent-API RED, implement descriptor-level bounded strict GREEN,
  and prove normalized serialization excludes every forbidden raw/native value.
- [ ] Run the complete Task 2 suite six consecutive times.

---

### Task 3: Implement owned workspace and exact runtime manifest

**Files:**
- Create: `proofs/promptfoo-redteam/boundary.test.mjs`
- Create: `proofs/promptfoo-redteam/boundary.mjs`
- Create: `proofs/promptfoo-redteam/manifest.test.mjs`
- Create: `proofs/promptfoo-redteam/manifest.mjs`

**Interfaces:**
- Prefix/label: `zasp-m0-16-` / `zasp.dev/proof=m0-16`.
- Owned files: fake-agent source bind, generated exact Promptfoo YAML, writable
  output directory, empty Docker config.
- Roles: agent, runner, network.

- [ ] Write workspace tests first for direct-child creation, retained untrusted
  post-mkdtemp candidates, canonical-parent portability, regular/non-symlink
  files, modes, dev/inode identity, pre/post-command reproof, output admission,
  cleanup-time replacement, and prefix-wide absence.
- [ ] Capture absent-boundary RED and implement the minimum owned workspace.
- [ ] Write manifest tests first for the exact image/source/license pins,
  Promptfoo YAML, fake-agent command, runner eval argv, environment allowlists,
  non-root/read-only/cap-drop/no-new-privileges/resource bounds, internal
  network, mounts/tmpfs, and zero host ports.
- [ ] Add hostile platform/image/config/env/entrypoint/cmd/mount/security/port
  variants and duplicate/set-order cases.
- [ ] Capture absent-manifest RED, implement minimal GREEN, and run six focused
  passes.

---

### Task 4: Implement disposable orchestration and fixed CLI boundary

**Files:**
- Create: `proofs/promptfoo-redteam/run.test.mjs`
- Create: `proofs/promptfoo-redteam/run.mjs`

**Interfaces:**
- Success line:
  `Promptfoo red-team proof passed: objective=true verdict=vulnerable evidence=true cleanup=true.`
- One internal network, one long-running agent, one one-shot Promptfoo runner.
- Finite named main, cleanup, child, readiness, and outer-supervisor budgets.

- [ ] Write tests first for image resolution, exact create/start/readiness/eval,
  artifact normalization, full-ID candidate retention, exact ownership and
  current peer projections, reverse cleanup, global absence, fixed output, and
  failure categories.
- [ ] Cover definitive versus ambiguous pull/create/start/exec/remove results,
  two-attempt reads, malformed/duplicate Docker JSON, delayed mutation
  settlement, phase fencing, uncooperative children, stdout/stderr pipe errors,
  combined output caps, SIGKILL/reap, late continuation, cleanup continuation
  and precedence.
- [ ] Cover replacement resources, peer transitions, exited runner, mount/env
  set order, extra labels/security/ports/networks, generic versus exact missing,
  other-marker stale resources, temp identity swaps, and workspace retention
  when Docker absence is unproved.
- [ ] Capture absent-runtime RED, implement minimal GREEN one slice at a time,
  and run the full proof suite six consecutive times.
- [ ] Run every completed M0 proof's hermetic root command whose status/count
  contract is affected.

---

### Task 5: Expose root commands, documentation, and license audit

**Files:**
- Create: `proofs/promptfoo-redteam/adapter-license.json`
- Create: `proofs/promptfoo-redteam/license-audit.test.mjs`
- Create: `proofs/promptfoo-redteam/license-audit.mjs`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/promptfoo-redteam-proof-contract.test.ts`

**Interfaces:**
- `proof:promptfoo:test`: hermetic only; no Docker/provider/network mutation.
- `proof:promptfoo:run`: exact disposable live lifecycle.
- `proof:promptfoo:license`: immutable official source/image/license audit.

- [ ] Extend the repository contract first and capture RED for missing scripts,
  docs, and license inventory.
- [ ] Add root commands and the README boundary: exact pin, local-only target,
  fixed success line, normalized fields, raw-data exclusion, Docker
  prerequisite, In-progress status, and R-09 Not-run state.
- [ ] Add a strict tracked license inventory and a read-only audit that verifies
  exact official repo/tag commit/tree, npm integrity, image index digest/config,
  and MIT license artifact/hash without trusting mutable tags alone.
- [ ] Prove the hermetic root command performs no Docker/provider mutation and
  leaves no cache, database, log, or temporary artifact.
- [ ] Run focused GREEN, root proof tests, full pinned repository verification,
  production audit, license audit, syntax/lint, and diff checks.
- [ ] Commit the implementation in small scoped task commits.

---

### Task 6: Run live proof, review, complete R-09, and ship

**Files:**
- Modify: proof source/tests only for evidence-backed live/review fixes
- Modify: `README.md`
- Modify: `app/quality/promptfoo-redteam-proof-contract.test.ts`
- Modify: affected aggregate-count quality contracts
- Modify: this plan
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/decisions/mvp-risk-register.md`
- Create ignored: `.superpowers/sdd/2026-08-15-m0-16-promptfoo-proof-implementation-plan/task-6-report.md`
- Append ignored: `.superpowers/sdd/2026-08-15-m0-16-promptfoo-proof-implementation-plan/progress.md`
- Create ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-16-report.md`
- Append ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/progress.md`

**Interfaces:**
- Completion aggregate: 708 Pending / 0 In progress / 18 Complete / 1 Blocked.
- Completion M0: 27 total / 7 Pending / 0 In progress / 18 Complete / 1 Blocked.
- R-09 becomes
  `PASS — M0-16 — <exact evidence path and reviewed proof SHA>` only after its
  whole criterion passes.

- [ ] Prove preflight zero for all M0-16 name/label/marker/network/temp selectors
  and fingerprint any shared Docker resources without mutation.
- [ ] Run the exact clean-environment root command. Diagnose failures from only
  sanitized phase/boolean evidence, capture focused RED before every production
  fix, and remove only freshly re-proved exact-owned retained candidates.
- [ ] Obtain two consecutive final-code live passes. After each, prove zero
  containers, networks, anonymous volumes, config/output directories, and temp
  roots plus unchanged shared-resource fingerprints.
- [ ] Capture a product-fields-only result proving the exact objective slug,
  `vulnerable` verdict, one SHA-256 evidence reference, exact three-key shape,
  and absence of raw prompt/response/canary/native labels/engine/Docker fields.
- [ ] Run six hermetic passes, exact image compatibility, all affected proof
  regressions, full pinned repository verify, production audit, immutable
  license audit, whitespace/syntax, and pinned redacted Gitleaks over the proof
  tree, staged content, evidence, exact commits, and full history.
- [ ] Perform a whole-range review against source task, PRD, design, plan,
  official 0.121.19 source, and live evidence. Fix every Critical, Important,
  and Minor finding tests-first; rerun live after ownership, mutation, timing,
  normalization, or cleanup changes.
- [ ] Add hostile completion/status tests and capture RED for stale M0-16/R-09
  state. Move only M0-16 to Complete and R-09 to PASS; preserve M0-17 Pending
  and every blocked/incomplete boundary. Run focused GREEN and all final gates.
- [ ] Record exact evidence, commit, push `codex/zasp-implementation`, prove
  local/tracking/origin SHA equality, and watch Runnable UI for that exact SHA
  to terminal success before continuing to M0-17.
