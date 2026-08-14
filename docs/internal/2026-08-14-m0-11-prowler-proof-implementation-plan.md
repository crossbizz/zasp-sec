# M0-11 Prowler Evidence Proof Implementation Plan

> **Execution rule:** Follow Superpowers executing-plans, subagent-driven
> development, test-driven development, systematic debugging, review, and
> verification-before-completion. Preserve genuine RED evidence before every
> production behavior change.

**Goal:** Execute one exact-pinned Prowler AWS check against a disposable
synthetic fixture and normalize its single relevant finding into a canonical
Organization-scoped product resource and evidence record.

**Source of truth:**

- `docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md`, M0-11.
- `docs/internal/agent_security_platform_PRD_v1.5.md`, Sections 4.2, 5, 7, and 8.
- `docs/internal/2026-08-14-m0-11-prowler-proof-design.md`.
- `docs/internal/implementation_status_v1.5.md`.
- `docs/decisions/mvp-risk-register.md`, R-06.

**Non-goals:** real-AWS authorization or parity; completing M0-09, PROV-01, or
R-03; the production M3-16 runner; M4-32 relevance filtering; persistence,
API/UI, workflow, compliance mapping, risk scoring, or full Prowler catalog.

## Task 1: Start M0-11 and lock contracts

**Files:**

- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `README.md`
- Modify: `app/quality/cartography-scope-proof-contract.test.ts`
- Modify: `app/quality/localstack-iam-compat-proof-contract.test.ts`
- Create: `app/quality/prowler-evidence-proof-contract.test.ts`

Add tests first that require the M0-11 In progress row, counts `717/1/9/1`, M0
counts `16/1/9/1`, exact design/image/check commands, and unchanged blocked
boundaries. Capture RED, update the tracker and README, run the focused pinned
Node tests, full `npm run verify`, and commit:

```text
docs: start M0-11 Prowler proof
```

## Task 2: Implement canonical resource and evidence normalization

**Files:**

- Create: `proofs/prowler-evidence/scoped_id.mjs`
- Create: `proofs/prowler-evidence/normalizer.mjs`
- Create: `proofs/prowler-evidence/normalizer.test.mjs`
- Modify: `proofs/cartography-scope/normalizer.mjs`
- Modify: `proofs/cartography-scope/normalizer.test.mjs`

Extract or share the M0-10 canonical scoped-source-ID grammar without changing
its outputs. Tests must first fail for the absent Prowler normalizer, then cover
the exact positive record, Organizations A/B separation, deterministic IDs,
M0-10 ID parity, and strict rejection of missing/null/extra/case-aliased/
duplicate keys, malformed UTF-8, trailing JSON, depth/size overflow, unknown
schema/check/status/severity/resource/region, ARN/account mismatch, arbitrary
upstream prose, scope mismatch, and evidence/resource-link mismatch.

Run focused Node tests six times, M0-10 regressions, lint/check, and commit:

```text
feat: normalize Prowler evidence
```

## Task 3: Execute the built-in Prowler check through a fixture bridge

**Files:**

- Create: `proofs/prowler-evidence/fixture_runner.py`
- Create: `proofs/prowler-evidence/fixture_runner_test.py`
- Create: `proofs/prowler-evidence/fixture.json`

Tests first define a narrow bridge that loads Prowler `5.39.0` from its own
image runtime, executes only
`iam_role_cross_service_confused_deputy_prevention` against the exact synthetic
role state, and emits a single official JSON-OCSF 1.5.0 finding. The bridge
must not handcraft a Prowler-like output; it must import and execute the tagged
check and official OCSF transformation path. It accepts only one fixed regular
fixture path, bounded UTF-8 JSON, fixed argv/environment, and a hard deadline.

Cover provider/check/schema drift, multiple/no findings, malformed fixture,
unexpected network/client call, timeout, panic, and fixed-output behavior. Run
Python tests six times, compile checks, and commit:

```text
feat: run pinned Prowler fixture check
```

## Task 4: Build the disposable runtime orchestrator

**Files:**

- Create: `proofs/prowler-evidence/run.mjs`
- Create: `proofs/prowler-evidence/run.test.mjs`

Tests first define exact image resolution and metadata, Docker-config temp
ownership, network/LocalStack/Prowler names and labels, full IDs, exact IAM
fixture creation, internal-only networking, synthetic environment, read-only
scanner filesystem, dropped capabilities, no-new-privileges, bounded resources,
exact output mount, exit-code-3 semantics, bounded artifact read, normalizer
handoff, reverse-order cleanup, prefix-wide absence, and one fixed line.

Cover definitive and ambiguous Docker/provider mutations, replacement
resources, generic versus exact missing responses, delayed temp creation,
deadline/panic/output overflow, cleanup continuation and precedence, volume/
mount mutations, and no ambient credential/profile/proxy/dotenv input. Run the
Node suite six times and commit:

```text
feat: orchestrate disposable Prowler proof
```

## Task 5: Expose repository commands and documentation

**Files:**

- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/prowler-evidence-proof-contract.test.ts`

Add root commands:

```text
proof:prowler:test
proof:prowler:run
```

Document Docker and pinned Node prerequisites, exact fixture-only boundary,
fixed success line, cleanup behavior, no credential/network input, and explicit
negative parity claims. Capture focused RED/GREEN, then run full pinned Node
verification and commit:

```text
docs: expose Prowler evidence proof
```

## Task 6: Live proof, review, completion, and push

**Files:**

- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/decisions/mvp-risk-register.md`
- Modify: `README.md`
- Modify: `app/quality/prowler-evidence-proof-contract.test.ts`
- Create/update ignored SDD task report and progress ledger

Run the exact root live command in an allowlisted environment. Require the
fixed success line, exactly one normalized finding linked to the expected M0-10
resource ID, zero container/network/output/temp prefixes, and no shared-target
mutation. Run six hermetic passes, Python compile/tests, root/full pinned Node
verification, production dependency/license audit, whitespace checks, and
pinned redacted Gitleaks.

Leave M0-11 In progress while an independent reviewer checks the complete
M0-11 range. Fix every Critical, Important, and Minor finding with TDD and
scoped re-review. Only after a zero-finding verdict:

- move M0-11 to Complete;
- set global counts to `717/0/10/1` and M0 to `16/0/10/1`;
- set R-06 to PASS with retained M0-11 evidence;
- keep M0-09/PROV-01 Blocked and R-03 incomplete;
- commit `docs: complete M0-11 Prowler proof`;
- push `codex/zasp-implementation`;
- require remote `Runnable UI` success at the exact pushed SHA.

Do not report M0-11 complete before the exact-SHA workflow succeeds.
