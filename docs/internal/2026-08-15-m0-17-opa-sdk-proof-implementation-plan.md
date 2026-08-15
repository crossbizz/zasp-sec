# M0-17 OPA SDK Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove deterministic in-process OPA Go SDK Allow and Block decisions
with 100 warm-ups, 1,000 measured evaluations per decision, and decision-specific
p95 latency at or below 10 ms.

**Architecture:** An independent Go module embeds one fixed Rego v1 policy,
prepares one `data.zasp.runtime.allow` query, validates strict primitive-boolean
results, and measures only prepared-query evaluation. A fixed CLI exposes no
policy or timing details. Root scripts add hermetic, live, and immutable-license
gates; repository contracts control M0-17/R-10 transitions.

**Tech Stack:** Go 1.25 semantics with toolchain go1.26.5, official
`github.com/open-policy-agent/opa` v1.17.0, Node.js 22.23.1/npm 10.9.8 for
repository contracts and license audit, Vitest, Gitleaks 8.30.1.

## Global constraints

- OPA tag v1.17.0 resolves exactly to
  `64a3625d33bc6ad8e7c40df03b76ce2fb3ab4d21`.
- Go module sum is exactly
  `h1:TMm6bCyb3CEL4wjXsXn1d/kBSBbjF+5sEIyzQvbJiEw=`.
- Apache-2.0 license SHA-256 is exactly
  `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08`.
- Production performs 100 warm-ups and 1,000 measurements for each of the
  Allow and Block inputs and requires both p95 values to be `<= 10ms`.
- No OPA server, subprocess, customer Rego, bundle, network call, environment
  configuration, external credential, or customer-visible OPA identifier.
- Every behavior or bug fix follows a witnessed RED before production changes.
- M0-09 and PROV-01 remain Blocked, R-03 remains incomplete, and M0-18 remains
  Pending throughout M0-17.

---

### Task 1: Start M0-17 and bind the repository status boundary

**Files:**
- Create: `app/quality/opa-sdk-proof-contract.test.ts`
- Modify: affected `app/quality/*-proof-contract.test.ts` aggregate assertions
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Use: `docs/decisions/mvp-risk-register.md`

**Interfaces:**
- Produces the sole active row `M0-17`, counts `707/1/18/1`, M0 counts
  `27/6/1/18/1`, and exact R-10 state `Not run — M0-17`.
- Preserves M0-16 Complete and R-09 PASS.

- [x] **Step 1: Write the status-contract RED**

Add assertions equivalent to:

```ts
expect(activeRows).toEqual([["M0-17", "August 15, 2026", expect.stringContaining("OPA")]]);
expect(tracker).toContain("| Pending | 707 |");
expect(tracker).toContain("| In progress | 1 |");
expect(tracker).toContain("| Complete | 18 |");
expect(tracker).toMatch(/\| M0 \| 27 \| 6 \| 1 \| 18 \| 1 \|/);
expect(r10Rows).toHaveLength(1);
expect(r10Rows[0]?.[5]).toBe("Not run — M0-17");
```

Include hostile duplicate M0-17, concurrent M0-18, premature R-10 PASS,
external OPA service/customer-Rego wording, and aggregate-drift mutations.

- [x] **Step 2: Run focused RED**

Run:

```bash
PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$PATH" npm exec vitest run app/quality/opa-sdk-proof-contract.test.ts
```

Expected: only the absent README row and stale 708/0/18/1 tracker boundary fail.

- [x] **Step 3: Apply the minimal start transition**

Add a README section that says M0-17 is In progress and proves an embedded
in-process OPA Go SDK fast path. Move only M0-17 from Pending to In progress;
do not advance R-10.

- [x] **Step 4: Run focused and affected GREEN**

Run the new contract plus every historical contract that binds the current
aggregate and active-row cardinality. Expected: all pass under pinned Node.

- [x] **Step 5: Verify and commit**

Run full pinned repository verify, production audit, whitespace, and staged
redacted Gitleaks. Commit as:

```bash
git commit -m "docs: start M0-17 OPA SDK proof"
```

---

### Task 2: Implement the strict prepared-query evaluator

**Files:**
- Create: `proofs/opa-sdk/go.mod`
- Create: `proofs/opa-sdk/go.sum`
- Create: `proofs/opa-sdk/policy.rego`
- Create: `proofs/opa-sdk/proof_test.go`
- Create: `proofs/opa-sdk/proof.go`

**Interfaces:**
- Produces `DecisionInput`, `ProofOptions`, `ProofResult`, and
  `RunProof(context.Context, ProofOptions) (ProofResult, error)`.
- The production query factory prepares exactly `data.zasp.runtime.allow` once.

- [x] **Step 1: Write the absent-API test**

The first happy-path test calls:

```go
result, err := RunProof(context.Background(), ProductionOptions())
if err != nil { t.Fatal(err) }
if !result.AllowMatched || !result.BlockMatched || !result.Deterministic {
    t.Fatalf("unexpected result: %#v", result)
}
if result.WarmupPerDecision != 100 || result.MeasuredPerDecision != 1000 {
    t.Fatalf("unexpected counts: %#v", result)
}
```

Add a separate fake prepared-query boundary test that records one preparation,
200 warm-up calls, and 2,000 measured calls.

- [x] **Step 2: Run genuine compile RED**

Run:

```bash
cd proofs/opa-sdk && go test -run '^TestRunProof' -count=1
```

Expected: compilation fails only because the wished-for proof types/functions
do not exist; no production/module file precedes this RED.

- [x] **Step 3: Add the exact module and embedded policy**

Use:

```go
module github.com/zasp-ai/zasp-sec/proofs/opa-sdk

go 1.25.0

toolchain go1.26.5

require github.com/open-policy-agent/opa v1.17.0
```

The Rego policy is default Block and allows only all six exact synthetic input
fields defined in the design. Import `rego.v1`; no dynamic source or bundle.

- [x] **Step 4: Implement minimal prepared-query GREEN**

Prepare once with `rego.New(rego.Query("data.zasp.runtime.allow"),
rego.Module("zasp_runtime.rego", embeddedPolicy)).PrepareForEval(ctx)`. Convert
the typed input through JSON to a string-keyed OPA document, evaluate with
`rego.EvalInput`, and accept exactly one result/expression containing primitive
`bool` equal to the expected decision.

- [x] **Step 5: Add adversarial evaluator RED/GREEN cycles**

Cover undefined, zero/multiple result, zero/multiple expression, non-boolean,
wrong boolean, preparation error/panic, evaluation error/panic, context
cancellation, mutated input, and nondeterministic sequences. Each test names the
production change it would catch before implementation.

- [x] **Step 6: Verify and commit**

Run focused tests five times, full module race, tidy-diff, module verify, and
vet. Commit as:

```bash
git commit -m "feat: evaluate embedded OPA decisions"
```

---

### Task 3: Add exact latency measurement and fixed CLI output

**Files:**
- Modify: `proofs/opa-sdk/proof_test.go`
- Modify: `proofs/opa-sdk/proof.go`
- Create: `proofs/opa-sdk/main_test.go`
- Create: `proofs/opa-sdk/main.go`

**Interfaces:**
- `nearestRankP95([]time.Duration) (time.Duration, error)` sorts a copy and
  uses index `ceil(0.95*n)-1`.
- CLI success is exactly:
  `OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.`

- [ ] **Step 1: Write timing RED**

Use an injected monotonic clock to prove sample boundaries, original-slice
immutability, nearest rank at n=1/20/1000, exactly 10 ms acceptance, 10 ms plus
1 ns rejection, and independent Allow/Block p95 gates.

- [ ] **Step 2: Implement timing GREEN**

Measure each `PreparedEvalQuery.Eval` only. Copy and sort samples; reject empty,
negative, mismatched-count, or over-threshold data. Never round durations before
comparison.

- [ ] **Step 3: Write fixed-process-boundary RED**

Exercise main through injected writer/runner boundaries. Require one success
line, empty stderr, and one fixed failure line for each configuration, policy,
evaluation, latency, deadline, and panic category. Reject raw errors, policy,
input, timings, environment, paths, or stack data in either stream.

- [ ] **Step 4: Implement minimal CLI GREEN**

Use a 30-second context and top-level panic containment. Return numeric exit
codes; write only the fixed selected line. Production options cannot be changed
by arguments or environment.

- [ ] **Step 5: Run real proof stability and commit**

Run six consecutive race-enabled module passes and two consecutive direct CLI
runs. Both CLI runs must emit the exact success line and exit zero. Commit as:

```bash
git commit -m "feat: prove OPA decision latency"
```

---

### Task 4: Expose root commands, documentation, and immutable license audit

**Files:**
- Create: `proofs/opa-sdk/adapter-license.json`
- Create: `proofs/opa-sdk/license-audit.test.mjs`
- Create: `proofs/opa-sdk/license-audit.mjs`
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/opa-sdk-proof-contract.test.ts`

**Interfaces:**
- `proof:opa:test`: race-enabled Go proof tests only.
- `proof:opa:run`: direct in-process proof CLI.
- `proof:opa:license`: immutable official tag/module/license audit.

- [ ] **Step 1: Write repository/license RED**

Require the three root scripts, exact success line, embedded-only boundary,
sample counts/threshold, exact dependency inventory, and R-10 Not-run wording.
The license test injects bounded command/fetch boundaries and rejects tag,
commit, module version/sum, repository, artifact, license, hash, unknown-key,
duplicate-key, malformed, redirect, timeout, and oversized drift.

- [ ] **Step 2: Implement strict license audit GREEN**

Bind the official repo/tag commit, Go module proxy metadata and sum, and the
commit-addressed Apache-2.0 LICENSE bytes/hash. Runtime output is fixed counts
only and contains no fetched content or host paths.

- [ ] **Step 3: Wire root commands and README**

Add:

```json
"proof:opa:test": "cd proofs/opa-sdk && go test -race -count=1 ./...",
"proof:opa:run": "cd proofs/opa-sdk && go run .",
"proof:opa:license": "node proofs/opa-sdk/license-audit.mjs"
```

Document exact pin, in-process/no-server boundary, 100/1,000 counts, 10 ms p95
gate, fixed line, and no customer-facing Rego.

- [ ] **Step 4: Run full local gates and commit**

Run root proof, license, full pinned repository verify, production audit,
module tidy-diff/verify/vet, syntax, whitespace, and staged secret scan. Commit
as:

```bash
git commit -m "docs: expose OPA SDK proof"
```

---

### Task 5: Whole-range review and final-code proof evidence

**Files:**
- Modify: proof source/tests only for tests-first review fixes
- Create ignored: `.superpowers/sdd/2026-08-15-m0-17-opa-sdk-proof-implementation-plan/task-5-report.md`
- Append ignored: `.superpowers/sdd/2026-08-15-m0-17-opa-sdk-proof-implementation-plan/progress.md`

**Interfaces:**
- Reviewed implementation range begins at the M0-16 completion SHA
  `feececf44bbe48d053f7fceeb52a9fb91acbd324`.
- Proof evidence includes decision counts and safe p95 values but no raw inputs,
  policy, OPA result internals, or host paths.

- [ ] **Step 1: Review source, dependency, and proof boundaries**

Inspect query preparation cardinality, strict result parsing, input conversion,
clock/sample arithmetic, deadline/panic handling, fixed output, dependency
integrity, and whether tests exercise the real OPA SDK rather than only fakes.

- [ ] **Step 2: Fix every finding tests-first**

For each Critical, Important, or Minor issue: add one focused regression, run
it RED, implement the minimum correction, run GREEN, then rerun the real direct
proof because evaluator/timing/output changes affect R-10 evidence.

- [ ] **Step 3: Capture final-code evidence**

Run two consecutive direct root proofs and record safe decision-specific p95
durations from the internal result boundary. Run six fresh full module passes,
root proof/license, full pinned repository verify, production audit, module
gates, whitespace, and redacted scans. Require zero review findings.

---

### Task 6: Complete M0-17, advance R-10, push, and verify CI

**Files:**
- Modify: `app/quality/opa-sdk-proof-contract.test.ts`
- Modify: affected aggregate-count quality contracts
- Modify: `README.md`
- Modify: `docs/internal/2026-08-15-m0-17-opa-sdk-proof-implementation-plan.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/decisions/mvp-risk-register.md`
- Create ignored: `.superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-17-report.md`
- Append ignored: both M0-17 and authoritative progress ledgers

**Interfaces:**
- Completion counts: `707/0/19/1`; M0 `27/6/0/19/1`.
- R-10 becomes `PASS — M0-17 — <exact report path and reviewed proof SHA>`.

- [ ] **Step 1: Write completion RED**

Reject stale active state, missing/duplicate Complete row, concurrent M0-18,
premature or unbound R-10 PASS, count drift, customer-Rego/server claims, and
changes to either blocked/incomplete boundary.

- [ ] **Step 2: Apply minimal completion GREEN**

Move only M0-17 to Complete, bind R-10 to the exact report and reviewed proof
SHA, retain M0-18 Pending, and update all affected historical aggregate tests.

- [ ] **Step 3: Verify, scan, commit, and push**

Run all final proof/module/repository/audit/license/whitespace/secret gates.
Commit as `docs: complete M0-17 OPA SDK proof`, push
`codex/zasp-implementation`, and prove local/tracking/origin SHA equality.

- [ ] **Step 4: Watch exact-SHA Runnable UI**

Find the Runnable UI run whose `headSha` equals the completion SHA, watch it to
terminal success, record run/job URLs, and only then proceed to M0-18.

## Plan self-review

- Every design requirement maps to an explicit task and test gate.
- All production APIs, inputs, sample counts, percentile math, thresholds,
  outputs, dependency fingerprints, status counts, and commands are exact.
- No placeholder, future implementation, or unexplained "similar" step exists.
- The plan implements only the M0-17 proof and repository wiring, not the later
  runtime-gateway product service.
