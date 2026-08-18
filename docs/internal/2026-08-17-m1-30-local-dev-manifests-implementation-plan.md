# M1-30 Local Development Manifests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` (recommended) or
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one canonical repository-root start target for the exact assembled
M1-30a through M1-30d local environment and prove it publishes no vendor
dashboard outside the disposable cluster.

**Architecture:** Add a small `deploy/local/start.mjs` boundary that constructs
and validates the complete fixed manifest exposure projection, then delegates
exactly once to the reviewed M1-30d lifecycle. Do not copy the runtime or chain
four separate clusters. Preserve every completed profile byte, provider trace,
fixed output, license boundary, ownership rule, deadline, and cleanup path.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, Node test runner, Vitest 4.1.10,
Docker 29.4.0, kind 0.32.0, Kubernetes node 1.35.5, Go 1.25.6, Gitleaks
8.30.1, GitHub Actions Runnable UI.

**Spec:** `docs/internal/2026-08-17-m1-30-local-dev-manifests-design.md`

## Global constraints

- Work only on M1-30. M1-31 remains Pending and product AWS client wiring is
  out of scope.
- Preserve M1-30a, M1-30b, M1-30c, and M1-30d Complete, including exact
  manifests, images, license inventories, default profile behavior, command
  traces, fixed output, deadlines, and cleanup.
- Add exactly one start target: `npm run local:start`, implemented by
  `node deploy/local/start.mjs`.
- Reuse the exact `m1-30d` assembled lifecycle. Do not add an `m1-30` provider
  profile, second cluster, second mutation journal, or shell command chain.
- Treat dashboard exposure as zero Ingress, NodePort, LoadBalancer,
  ExternalName, external IP, host network/PID/IPC, container host port,
  host-path volume, Docker socket mount, or Docker-published node port.
- Internal ClusterIP health surfaces remain allowed. Do not claim that vendor
  UI code is absent inside its image.
- Read no ambient kubeconfig, Docker configuration, dotenv, cloud credential,
  proxy, provider, or customer state beyond the existing reviewed runtime.
- Preserve the sole success line
  `Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.`
  and the existing fixed failure categories.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1 and npm 10.9.8 for repository gates.
- Do not mark M1-30 Complete before exact live assembled evidence and a
  zero-finding whole-range review.
- Completion requires exact-SHA Runnable UI success for both the completion
  and plan-closure commits.

---

### Task 1: Start M1-30 with an exact repository contract

**Files:**
- Create: `app/quality/local-start-target-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-30 source row, committed design, M1-30d Complete state, and
  exact blocker set.
- Produces: exact M1-30 In-progress status at overall `657/1/67/3` and M1
  `68/24/1/43/0`.

- [x] **Step 1: Write the failing source, design, and status contract**

Create `app/quality/local-start-target-contract.test.ts`. Read the source plan,
design, tracker, README, and package file. Require the exact source row:

```ts
expect(section).toContain("Depends on: `M1-30d`");
expect(section).toContain("Deliverable: Add one local start target for the assembled manifests.");
expect(section).toContain("Verify: Local environment starts without vendor dashboards exposed.");
expect(section).toContain("Timebox: <=15 minutes.");
```

Bind the selected thin-delegation approach, `npm run local:start`, exact
M1-30d profile reuse, zero external exposure categories, disposable cleanup,
and M1-31 deferral. Require one active M1-30 row, no complete M1-30 row, one
complete row for each M1-30a through M1-30d, no other active row, blocker rows
exactly `M0-09`, `M0-18`, and `M0-19`, and exact start arithmetic.

- [x] **Step 2: Witness stale-status RED**

Run:

```sh
npx vitest run app/quality/local-start-target-contract.test.ts \
  app/quality/local-aws-emulator-manifest-contract.test.ts
```

Expected: the new contract fails only because M1-30 is absent, counts are
`658/0/67/3`, M1 is `68/25/0/43/0`, and README says M1-30 is Pending. The
M1-30d dependency contract remains green.

- [x] **Step 3: Move only M1-30 to In progress**

Change overall `658/0/67/3` to `657/1/67/3` and M1 `68/25/0/43/0` to
`68/24/1/43/0`. Add exactly:

```markdown
| M1-30 | August 17, 2026 | Adding one canonical assembled local start target over the reviewed M1-30d lifecycle, with exact prior-profile preservation, zero external vendor-dashboard exposure, disposable ownership, and fixed output. |
```

Update README current-state prose to `M1-30 is In progress`. Update only
current aggregate/status fixtures mechanically; do not rewrite historical
evidence or completed-task rows.

- [x] **Step 4: Run focused and all-quality GREEN**

Run the new contract, all four local-profile contracts, and `npm test`. Require
728-task arithmetic, active rows exactly `["M1-30"]`, complete count 67,
M1-30a through M1-30d each exactly once in Complete, no M1-30 complete row,
and the exact blocker set.

- [x] **Step 5: Scan and commit the start transition**

Run staged whitespace and pinned redacted Gitleaks checks. Commit only the
status, README, and quality-contract slice as:

```text
docs: start M1-30 local dev manifests
```

---

### Task 2: Implement the exact assembled start boundary

**Files:**
- Create: `deploy/local/start.test.mjs`
- Create: `deploy/local/start.mjs`

**Interfaces:**
- Consumes: `buildProductResources()`, `buildGraphResources()`,
  `buildObservabilityResources()`, `buildAwsEmulatorResources()`,
  `buildAwsEmulatorProfile()`, `awsEmulatorApplyPlan()`,
  `AWS_EMULATOR_SUCCESS_LINE`, `AWS_EMULATOR_FAILURE_CATEGORIES`, and
  `runAwsEmulatorMain(runtime?, options?)`.
- Produces: frozen `LOCAL_START_TARGET`,
  `projectLocalStartExposure(value)`, `validateLocalStartAssembly()`, and
  `runLocalStartMain(runtime?, options?)`.

- [x] **Step 1: Write absent-module and exact-target tests first**

Create `deploy/local/start.test.mjs`. Before production exists, require import
failure, then define tests for this exact target projection:

```js
{
  command: "npm run local:start",
  dependencies: ["m1-30a", "m1-30b", "m1-30c", "m1-30d"],
  entrypoint: "node deploy/local/start.mjs",
  failureCategories: [
    "build", "cleanup", "configuration", "deadline", "normalization",
    "ownership", "panic", "provider", "readiness",
  ],
  manifests: [
    "product-stubs.yaml", "graph.yaml", "observability.yaml",
    "observability-span.yaml", "aws-emulator.yaml",
    "aws-emulator-s3.yaml",
  ],
  profile: "m1-30d",
  successLine: "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.",
}
```

Require a plain deeply frozen object with exact data descriptors and no caller
input.

- [x] **Step 2: Witness missing start-boundary RED**

Run:

```sh
node --test deploy/local/start.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `deploy/local/start.mjs`; no
existing local-profile test is changed or failing.

- [x] **Step 3: Add strict exposure-projection tests**

Build the canonical 22-resource array from the four reviewed builders. Require:

```js
{
  clusterIPServices: 7,
  configMaps: 2,
  dashboardsPublished: 0,
  deployments: 7,
  externalServices: 0,
  hostNamespaces: 0,
  hostPathVolumes: 0,
  hostPorts: 0,
  ingresses: 0,
  jobs: 3,
  persistentVolumeClaims: 1,
  persistentVolumes: 1,
  resources: 22,
}
```

Clone the canonical values and independently add an Ingress, change a Service
to NodePort/LoadBalancer/ExternalName, add `externalIPs`, `loadBalancerIP`,
`externalTrafficPolicy`, set hostNetwork/hostPID/hostIPC, add `hostPort`, add a
hostPath or Docker socket mount, replace an array/object prototype, add a
symbol, add an accessor, add an alias, and add a cycle. Each case must throw
without invoking a getter or coercion method.

- [x] **Step 4: Implement immutable target and strict projection**

In `deploy/local/start.mjs`, import only the reviewed builders and M1-30d
runtime surface. Define `LOCAL_START_TARGET` from fixed literals and imported
fixed output values. Implement a recursive snapshot that reads only own
enumerable data descriptors from plain arrays and plain objects, rejects
symbols/accessors/prototypes/aliases/cycles, and accepts only primitive leaves.

Implement `projectLocalStartExposure(value)` by scanning the strict snapshot.
Count all resource kinds, then inspect every Service and pod template for the
forbidden exposure keys. Return a deeply frozen summary. Do not coerce keys or
values and do not accept a caller-supplied success line, command, manifest,
profile, or provider target.

- [x] **Step 5: Implement fixed assembly validation**

`validateLocalStartAssembly()` accepts no arguments. Build and concatenate:

```js
const resources = [
  ...buildProductResources(),
  ...buildGraphResources(),
  ...buildObservabilityResources(),
  ...buildAwsEmulatorResources(),
];
```

Require the exact exposure summary from Step 3. Require
`buildAwsEmulatorProfile()` to use proof `m1-30d` and the exact six target
manifest names represented by `LOCAL_START_TARGET`. Require
`awsEmulatorApplyPlan()` to retain base
`["graphManifest", "observabilityCoreManifest", "awsEmulatorCoreManifest"]`
and staged `["observabilitySpanManifest", "awsEmulatorS3Manifest"]`. Return the
frozen exposure summary.

- [x] **Step 6: Implement one exact runtime delegation**

Implement:

```js
export async function runLocalStartMain(runtime = undefined, options = {}) {
  validateLocalStartAssembly();
  return await runAwsEmulatorMain(runtime, options);
}
```

The direct-entrypoint block calls `runLocalStartMain()` once. Tests use a fake
runtime implementing the reviewed lifecycle methods and prove one initialize,
preflight, build, network, cluster, load, apply, readiness, settlement,
cleanup, and absence call; the exact composite result succeeds; main failure
and cleanup failure retain M1-30d output and precedence; and runtime/options
objects reach the delegate unchanged.

- [x] **Step 7: Run six focused passes and commit**

Run six consecutive `node --test deploy/local/start.test.mjs` passes, then the
complete product, graph, observability, and AWS-emulator suites, syntax,
focused ESLint, diff-check, and pinned staged Gitleaks. Commit only the two
start-boundary files as:

```text
feat: add assembled local start target
```

---

### Task 3: Expose and document the canonical root target

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/local-start-target-contract.test.ts`

**Interfaces:**
- Produces: root script `local:start` and bounded operator guidance.
- Consumes: Task 2 `deploy/local/start.mjs` and the existing complete
  `local:aws-emulator:test` regression command.

- [x] **Step 1: Write root-command and documentation RED**

Extend the quality contract to require exactly:

```ts
expect(scripts["local:start"]).toBe("node deploy/local/start.mjs");
```

Require a README section headed `## Assembled local development target` that
contains the pinned Node/npm prerequisites, `npm run local:start`, the sole
success and fixed failure lines, all four completed dependency profiles, one
disposable cluster, internal-only exposure, no vendor dashboard publication,
no ambient authority, reverse cleanup, exact license reuse, M1-30 In progress,
and M1-31 deferral. Reject claims of a persistent cluster, host dashboard,
production parity, product AWS client wiring, or shared-resource mutation.

- [x] **Step 2: Witness command/documentation RED**

Run:

```sh
npx vitest run app/quality/local-start-target-contract.test.ts
```

Expected: FAIL only for absent `local:start` and absent assembled-target README
section.

- [x] **Step 3: Add the exact script and README section**

Add `"local:start": "node deploy/local/start.mjs"` without changing existing
script values. Document that the command is an opt-in, disposable
start-and-verify target. State that the graph HTTP surface, Collector, and
LocalStack remain ClusterIP-only and no Ingress, NodePort, LoadBalancer, or
host workload port is created. State that product AWS client consumption
belongs to M1-31.

- [x] **Step 4: Run focused, root, and full GREEN**

Run the quality contract, `node --test deploy/local/start.test.mjs`,
`npm run local:aws-emulator:test`, all four local-profile quality contracts,
and pinned `npm run verify`. Run `npm audit --omit=dev`, dependency validation,
syntax, ESLint, whitespace, and pinned redacted secret scans.

- [x] **Step 5: Commit the command and documentation slice**

Commit only `package.json`, README, and the quality contract as:

```text
docs: expose assembled local start target
```

---

### Task 4: Run live assembly, review, completion, and closure

**Files:**
- Modify only in-scope files required by a witnessed tests-first live or review
  finding
- Modify completion status only after exact live and zero-finding review
- Update ignored reports and ledger under
  `.superpowers/sdd/2026-08-17-m1-30-local-dev-manifests-implementation-plan/`

**Interfaces:**
- Produces: exact live assembled evidence, zero-finding review, M1-30 Complete
  transition, pushed exact-SHA CI success, and checked plan closure.

- [x] **Step 1: Establish exact live preconditions**

Require zero M1-30d proof labels, names, node-local owned image aliases,
volumes, and temporary roots. Fingerprint the exact shared graph,
observability, LocalStack, Docker, and kubeconfig state read-only. Do not remove
or retag a shared image or target an ambient Kubernetes context.

- [x] **Step 2: Run the exact assembled command**

Run only:

```sh
env -i PATH="$HOME/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/usr/bin:/bin" \
  HOME="$HOME" LANG=C.UTF-8 npm run local:start
```

Require exit zero and only:

```text
Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.
```

Require exact product readiness, graph persistence, one observability span,
one endpoint-bound S3 request, internal-only Services, no Docker-published node
port, zero proof-owned residue, and unchanged selected shared state.

- [x] **Step 3: Fix live findings only through TDD**

For each real mismatch, isolate the exact representation or lifecycle cause,
write a focused failing hermetic regression, implement the narrow fix, rerun
every affected profile, and repeat the exact live command. Do not weaken
profile immutability, exposure, output, provider, license, or cleanup rules.

- [x] **Step 4: Run the final gate matrix**

Require six assembled/AWS-emulator suite passes; product, graph, and
observability regressions; all four product Go race/tidy-diff/module-verify/vet
matrices; all three immutable license audits; pinned full repository
verify/typecheck/lint/build; production audit zero; dependency validation;
diff-check; and pinned redacted Gitleaks over the range, each commit, tracked
HEAD, full history, and ignored evidence.

- [x] **Step 5: Obtain a zero-finding whole-range review**

Review the source row, design, plan, exact command, resource projection,
strict input handling, M1-30a through M1-30d compatibility, exposure evidence,
live evidence, ownership, cleanup, docs, status arithmetic, and scans. Fix
every Critical, Important, and Minor finding tests-first in a separate commit,
repeat affected gates and exact live verification, and re-review to zero.

- [x] **Step 6: Transition M1-30 to Complete**

Write completion-contract RED, then change overall `657/1/67/3` to
`657/0/68/3` and M1 `68/24/1/43/0` to `68/24/0/44/0`. Move exactly one M1-30
row from In progress to Complete. Preserve M1-30a through M1-30d Complete,
M1-31 Pending, and the exact blockers. Run focused and full gates, then commit:

```text
docs: complete M1-30 local dev manifests
```

- [x] **Step 7: Push completion and verify exact-SHA CI**

Push from a clean tracked tree and index. Require equal local, origin, and
tracking SHAs. Watch Runnable UI to terminal success for the exact completion
SHA and record run/job URLs in ignored evidence.

- [x] **Step 8: Close, push, and verify the plan**

Mark every plan checkbox complete only after completion CI succeeds. Commit
only this plan as:

```text
docs: close M1-30 local dev manifests plan
```

Push again, require exact-SHA Runnable UI success, then perform final SHA-sync,
status arithmetic, blocker, Gitleaks, zero-residue, shared-state, and clean-tree
audits.
