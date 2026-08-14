# M0-12 Tetragon Signal Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that exact-pinned Tetragon observes process, file, and outbound
TCP activity for one disposable Kubernetes workload with shared identity and
explicit healthy capability/drop state.

**Architecture:** A Node orchestrator creates an exact-owned single-node kind
cluster, installs the exact Tetragon Helm chart, applies generated fixture and
TracingPolicy manifests, captures bounded event and metrics payloads, and
passes them to a strict product-owned normalizer. Cleanup is independent,
reverse-order, ownership-gated, and followed by prefix-wide absence proof.

**Tech Stack:** Node.js 22.23.1, Node test runner, Docker/OrbStack, kind 0.32.0,
Kubernetes 1.35.5, Helm 3, kubectl, Tetragon 1.7.0, BusyBox 1.37.0.

## Global Constraints

- Follow `docs/internal/2026-08-14-m0-12-tetragon-proof-design.md` exactly.
- Source requirements are M0-12 in the authoritative implementation plan and
  R-07 in `docs/decisions/mvp-risk-register.md`.
- The proof is observation-only: no enforcement, plaintext, internet-egress,
  production-kernel, or semantic-source-of-truth claim.
- Do not load `.env`, cloud credentials, profiles, proxy variables, ambient
  kubeconfig, or Docker authentication.
- Reads are bounded and at most two-attempt. Mutations are single-attempt;
  only thrown, signaled, or malformed-zero outcomes may reconcile.
- Preserve genuine tests-first RED output before every production change.
- Keep M0-09 and PROV-01 Blocked, R-03 incomplete, and R-07 Not run until the
  reviewed exact live proof passes.
- Do not mark M0-12 Complete or push before zero-finding independent review.

---

## File structure

- `proofs/tetragon-signal/normalizer.mjs`: strict event/metrics input boundary
  and shared-workload proof result.
- `proofs/tetragon-signal/normalizer.test.mjs`: adversarial parser and semantic
  proof tests.
- `proofs/tetragon-signal/manifests.mjs`: exact kind, workload, service, and
  TracingPolicy manifest generation.
- `proofs/tetragon-signal/manifests.test.mjs`: immutable pins and generated
  topology tests.
- `proofs/tetragon-signal/run.mjs`: disposable runtime, phase fencing, capture,
  fixed output, cleanup, and absence audit.
- `proofs/tetragon-signal/run.test.mjs`: injected hermetic orchestration tests.
- `app/quality/tetragon-signal-proof-contract.test.ts`: repository status,
  commands, documentation, and completion contracts.

---

### Task 1: Start M0-12 and lock repository contracts

**Files:**

- Create: `app/quality/tetragon-signal-proof-contract.test.ts`
- Modify: `app/quality/prowler-evidence-proof-contract.test.ts`
- Modify: `app/quality/cartography-scope-proof-contract.test.ts`
- Modify: `app/quality/localstack-iam-compat-proof-contract.test.ts`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `README.md`

**Interfaces:**

- Consumes: final M0-11 counts `717/0/10/1` and M0 counts `16/0/10/1`.
- Produces: exact M0-12 In progress counts `716/1/10/1`, M0 counts
  `15/1/10/1`, and an unchanged R-07 `Not run — M0-12` boundary.

- [ ] **Step 1: Write the failing status and documentation contracts**

Create tests that parse the status tables structurally and require exactly one
M0-12 row, no M0-13 row, exact six-cell R-07 state, immutable runtime pins,
and explicit observation-only language. Include decoy rows so substring-only
checks cannot pass.

```ts
expect(overall).toEqual({ pending: 716, inProgress: 1, complete: 10, blocked: 1 })
expect(m0).toEqual({ pending: 15, inProgress: 1, complete: 10, blocked: 1 })
expect(exactRows("M0-12", statusTable)).toEqual([["M0-12", "Tetragon proof", "In progress"]])
expect(riskRow("R-07", riskRegister).status).toBe("Not run — M0-12")
```

- [ ] **Step 2: Run the focused RED gate**

Run under pinned Node 22.23.1:

```bash
npx vitest run app/quality/tetragon-signal-proof-contract.test.ts app/quality/prowler-evidence-proof-contract.test.ts
```

Expected: only the new M0-12 status/count/documentation requirements fail.

- [ ] **Step 3: Apply the minimal tracker and README transition**

Move only M0-12 to In progress, update the two count rows, retain M0-11
Complete, and leave both blockers and R-03 unchanged.

- [ ] **Step 4: Verify and commit**

Run the focused tests and full `npm run verify`, then commit exactly the scoped
files:

```bash
git commit -m "docs: start M0-12 Tetragon proof"
```

---

### Task 2: Normalize Tetragon events and sensor evidence

**Files:**

- Create: `proofs/tetragon-signal/normalizer.mjs`
- Create: `proofs/tetragon-signal/normalizer.test.mjs`

**Interfaces:**

- Consumes:
  `normalizeTetragonProof({ organizationId, expected, events, metricsBefore, metricsAfter }): TetragonProofResult`,
  where all three captured payloads are bounded `Uint8Array` values.
- Produces:
  `{ process, file, network, identity, capability, drops, workload, sensor }`,
  where every event references the same exact normalized workload ID. The
  orchestrator adds the separately proved cleanup result.

- [ ] **Step 1: Define strict failing event tests**

Use literal fixtures for one `process_exec`, one file kprobe
`security_file_permission`, and one network kprobe `tcp_connect`. Require exact
namespace, pod UID/name, container ID/name, workload labels, node, binary,
file path, destination IP/port, policy name, and sensor version.

```js
const result = normalizeTetragonProof({
  organizationId: "org_aaaaaaaaaaaaaaaa",
  expected: exactExpectedFixture,
  events: Buffer.from([execEvent, fileEvent, connectEvent].map(JSON.stringify).join("\n")),
  metricsBefore: Buffer.from(healthyMetrics),
  metricsAfter: Buffer.from(healthyMetrics),
})
assert.deepEqual(result.classes, ["process", "file", "network"])
assert.equal(new Set(result.events.map(event => event.workloadId)).size, 1)
```

Add adversarial cases for missing/null/extra/case-aliased/duplicate keys,
invalid UTF-8, trailing JSON, depth/line/count/aggregate overflow, duplicate or
foreign candidates, wrong policy/path/destination, inconsistent workload
identity, boolean-as-number values, malformed timestamps, and arbitrary
provider prose.

- [ ] **Step 2: Define strict failing Prometheus tests**

Require one build-info sample, both policies loaded, service health, and
numeric baseline/final samples for observer ring-buffer loss/errors, event
queue loss, notification overflow, and export rate-limit drops. Reject missing
families, duplicate label sets, non-finite/negative values, counter reset, and
any nonzero interval delta.

- [ ] **Step 3: Run genuine RED**

```bash
node --test proofs/tetragon-signal/normalizer.test.mjs
```

Expected: module-not-found or missing exported API before production exists.

- [ ] **Step 4: Implement the minimal strict boundary**

Export only these public functions:

```ts
export function parseTetragonEvents(text: string, limits: EventLimits): TetragonEvent[]
export function parseTetragonMetrics(text: string, expected: SensorExpectation): SensorEvidence
export function normalizeTetragonProof(input: TetragonProofInput): TetragonProofResult
```

Implement a duplicate-key-aware bounded JSON parser, a line-oriented bounded
Prometheus parser, exact schema validators, deterministic SHA-256 workload ID,
and the three-class/shared-identity/zero-drop proof.

- [ ] **Step 5: Verify stability and commit**

Run the focused suite six consecutive times, `node --check`, focused ESLint,
and full repository verification. Commit:

```bash
git commit -m "feat: normalize Tetragon signals"
```

---

### Task 3: Generate exact fixture and policy manifests

**Files:**

- Create: `proofs/tetragon-signal/manifests.mjs`
- Create: `proofs/tetragon-signal/manifests.test.mjs`

**Interfaces:**

- Consumes: a validated lowercase hexadecimal marker and the resolved host
  platform.
- Produces:
  `buildFixture({ marker, platform }): { pins, names, kindConfig, resources }`.

- [ ] **Step 1: Write tests for immutable pins and topology**

Require the exact kind, node, chart, Tetragon, operator, and BusyBox index plus
arm64/amd64 descriptors from the design. Require `/proc` to `/procHost`, Helm
`tetragon.hostProcPath=/procHost`, metrics on port 2112, and no enforcement.

```js
const fixture = buildFixture({ marker: "0123456789abcdef", platform: "linux/arm64" })
assert.equal(fixture.pins.tetragon.indexDigest, "sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527")
assert.deepEqual(fixture.kindConfig.nodes[0].extraMounts, [
  { hostPath: "/proc", containerPath: "/procHost" },
])
```

- [ ] **Step 2: Write tests for the exact fixture resources**

Require a fixed-label namespace, a BusyBox sink, a long-running BusyBox
workload, ClusterIP-only service port `18080`, a file policy for the exact
fixture path, and a `tcp_connect` policy for destination port `18080`. Reject
mutable tags, host ports, privileged fixture pods, service accounts, secrets,
cloud environment, enforcement actions, wildcards, and extra resources.

- [ ] **Step 3: Run genuine RED**

```bash
node --test proofs/tetragon-signal/manifests.test.mjs
```

Expected: module-not-found or missing `buildFixture`.

- [ ] **Step 4: Implement exact JSON manifest generation**

Use JSON objects rather than hand-built YAML. Freeze the returned structure
and expose no mutation helpers:

```ts
export const PINS: Readonly<{
  kind: { version: "v0.32.0", darwinArm64Sha256: "dca67911095a110c2b5c36e26df6cac860c602033e456c0db47be498cdef1ebb" },
  node: { reference: "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95" },
  tetragon: { version: "1.7.0", indexDigest: "sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527" },
  operator: { indexDigest: "sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82" },
  busybox: { indexDigest: "sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0" },
}>
export function validateMarker(marker: string): string
export function buildFixture(input: { marker: string, platform: "linux/arm64" | "linux/amd64" }): Fixture
```

- [ ] **Step 5: Verify and commit**

Run both Task 2 and Task 3 suites six times, syntax/lint/full gates, then:

```bash
git commit -m "feat: define disposable Tetragon fixture"
```

---

### Task 4: Orchestrate the disposable kind and Tetragon lifecycle

**Files:**

- Create: `proofs/tetragon-signal/run.mjs`
- Create: `proofs/tetragon-signal/run.test.mjs`

**Interfaces:**

- Consumes: `buildFixture`, `normalizeTetragonProof`, injected filesystem,
  process, HTTP, clock, random, and hashing boundaries.
- Produces:
  `orchestrate(runtime): Promise<TetragonProofResult>` and
  `runMain(runtime): Promise<number>`.

- [ ] **Step 1: Write failing preflight and ownership tests**

Cover official kind binary checksum verification, chart archive checksum,
platform image descriptor resolution, exact kind node container and Docker
network metadata, owned kubeconfig/temp identities, prefix/label global audit,
and rejection of replacement, foreign, duplicate, extra-peer, mount, image,
label, network, or security metadata.

- [ ] **Step 2: Write failing lifecycle and capture tests**

Cover exact kind create, Helm install values, API readiness, Tetragon pod and
policy readiness, baseline metrics, workload trigger, bounded log/metrics
capture, normalizer handoff, and the fixed success line:

```text
Tetragon signal proof passed: process=true file=true network=true identity=true capability=true drops=0 cleanup=true.
```

All failures map to fixed categories `configuration`, `ownership`,
`capability`, `provider`, `normalization`, `cleanup`, or `operation`.

- [ ] **Step 3: Write failing uncertainty, phase, and cleanup tests**

Cover definitive create rejection with no adoption; thrown, signaled, and
malformed-zero create reconciliation; delayed apply; mutation settlement
journal join; deadline/cancellation fencing; stdout/stderr aggregate overflow;
cleanup continuation/precedence; reverse dependency order; and exact cluster,
container, network, kubeconfig, chart, namespace, policy, and temp absence.

- [ ] **Step 4: Run genuine RED**

```bash
node --test proofs/tetragon-signal/run.test.mjs
```

Expected: module-not-found before `run.mjs` exists.

- [ ] **Step 5: Implement the minimal runtime**

Use an injected class with narrow methods and a single settlement journal:

```ts
export interface TetragonRuntime {
  preflight(): Promise<void>
  createCluster(): Promise<void>
  installTetragon(): Promise<void>
  runFixture(): Promise<void>
  captureEvidence(): Promise<TetragonProofInput>
  cleanup(): Promise<void>
  auditAbsence(): Promise<void>
}
export class DockerKindRuntime implements TetragonRuntime
export function orchestrate(runtime: TetragonRuntime): Promise<TetragonProofResult>
export function runMain(runtime: TetragonRuntime): Promise<number>
```

Every subprocess gets a fixed allowlisted environment. Use async spawn with
SIGKILL deadlines and one combined output cap. Retain candidates before result
interpretation, re-prove ownership immediately before cleanup, and wait for
all issued mutations to settle before cleanup/audit.

- [ ] **Step 6: Verify stability and commit**

Run the complete proof suite six times, syntax/lint, and full repository gates.
Commit:

```bash
git commit -m "feat: orchestrate disposable Tetragon proof"
```

---

### Task 5: Expose root commands and documentation

**Files:**

- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/tetragon-signal-proof-contract.test.ts`

**Interfaces:**

- Produces root commands `proof:tetragon:test` and `proof:tetragon:run`.

- [ ] **Step 1: Extend the repository contract as RED**

Require exact scripts, pinned Node/Docker/kind/Helm/kubectl prerequisites,
fixed output, observation-only boundary, no ambient credentials/network,
cleanup guarantees, and R-07 completion conditions.

- [ ] **Step 2: Run focused RED**

```bash
npx vitest run app/quality/tetragon-signal-proof-contract.test.ts
```

- [ ] **Step 3: Add scripts and documentation**

The hermetic command runs all three Node suites and makes no Docker/Kubernetes
mutation. The live command runs only `run.mjs`.

```json
{
  "proof:tetragon:test": "node --test proofs/tetragon-signal/*.test.mjs",
  "proof:tetragon:run": "node proofs/tetragon-signal/run.mjs"
}
```

- [ ] **Step 4: Verify and commit**

Run the focused contract, root proof test, and full pinned verification. Commit:

```bash
git commit -m "docs: expose Tetragon signal proof"
```

---

### Task 6: Run live proof, review, complete, and ship

**Files:**

- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: `docs/decisions/mvp-risk-register.md`
- Modify: `README.md`
- Modify: `app/quality/tetragon-signal-proof-contract.test.ts`
- Create/update ignored SDD task report and append-only progress ledger.

**Interfaces:**

- Consumes: all prior proof modules and the exact live Docker capability.
- Produces: retained R-07 evidence, M0-12 Complete state, pushed exact SHA,
  and successful exact-SHA `Runnable UI` workflow.

- [ ] **Step 1: Run the exact live command**

Run from a clean prefix with explicit Node 22.23.1 tool paths and an empty
owned HOME/Docker/Kubernetes boundary. Require exit zero and the one fixed
success line. Capture product fields only: three classes, one workload ID,
sensor version/policy/capability state, exact zero drop counters, and cleanup.

- [ ] **Step 2: Prove cleanup and shared-state preservation**

Require zero proof-prefixed/labeled kind containers, networks, kubeconfigs,
chart files, and temp directories. Prove any pre-existing shared Docker and
Kubernetes targets retain the same full ID/start/restart/image/context
fingerprints.

- [ ] **Step 3: Run final local gates**

Run six hermetic proof passes, full pinned `npm run verify`, production audit,
license inventory, syntax/lint/whitespace checks, and pinned redacted Gitleaks
over the diff, proof paths, evidence, and full history.

- [ ] **Step 4: Obtain zero-finding independent review**

Keep M0-12 In progress and R-07 Not run while the complete M0-12 range is
reviewed. Reproduce every Critical, Important, and Minor finding with a genuine
test-first RED, fix it, rerun live when runtime behavior changes, and obtain a
zero-finding scoped re-review.

- [ ] **Step 5: Transition completion as TDD**

Write completion contracts first and capture RED. Then move M0-12 to Complete,
set global counts to `716/0/11/1`, set M0 to `15/0/11/1`, and set R-07 to PASS
with retained M0-12 evidence. Keep M0-09/PROV-01 Blocked and R-03 incomplete.

- [ ] **Step 6: Commit, push, and verify the exact SHA**

```bash
git commit -m "docs: complete M0-12 Tetragon proof"
git push origin codex/zasp-implementation
```

Require local, tracking, and remote SHAs to match. Watch `Runnable UI` to a
successful terminal conclusion for that exact SHA. Do not report M0-12
complete before the workflow succeeds.
