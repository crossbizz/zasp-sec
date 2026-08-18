# M1-30c Local Observability Manifest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an exact-pinned OpenTelemetry Collector with a local
file-backed test sink to the disposable local cluster, and prove one fixed
synthetic span reaches that sink without a network exporter.

**Architecture:** Preserve the completed M1-30a product runner and M1-30b
graph runner. Add a separate strict observability overlay whose Collector core
is applied and proved Ready before a separately rendered one-shot span Job is
created. Compose both through one M1-30c profile that retains exact image,
Kubernetes, span, sink, cleanup, and prior-profile authority.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, `js-yaml` 4.1.1, Docker 29.4.0,
kind 0.32.0, Kubernetes node 1.35.5, OpenTelemetry Collector Contrib 0.158.0
exact OCI index, BusyBox 1.36.1-1 exact OCI index, Node test runner, Vitest
4.1.10, Gitleaks 8.30.1, GitHub Actions Runnable UI.

## Global constraints

- Work only on M1-30c. M1-30d remains Pending.
- Preserve M1-30a and M1-30b Complete, including their manifest bytes,
  default profile behavior, provider command traces, fixed output, and tests.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Use the exact Collector and BusyBox OCI indexes and selected-platform
  identities; never use a tag-only or mutable workload reference.
- Define “no egress” only as the exact Collector pipeline having no network
  exporter, remote endpoint, credential, proxy, or backend. Do not claim kind's
  default CNI enforces NetworkPolicy.
- Publish no observability workload port to the host and create no Ingress,
  NodePort, LoadBalancer, external IP, host network, host PID, or host IPC.
- Pass no credential, token, proxy, cloud profile, Docker override, ambient
  kubeconfig, customer value, or provider value into the cluster.
- Apply the one-shot span Job only after exact Collector Deployment, pod,
  Service, and EndpointSlice readiness. Perform exactly one trace POST.
- Store the sink artifact only in one exact pod `emptyDir`, cap it at 64 KiB,
  and validate one trace/span through the retained read-only sidecar.
- Treat mutations as single-attempt. Reconcile only genuinely ambiguous
  outcomes through exact immutable state; never adopt a definitive rejection
  or name-only match.
- Journal and join mutations, use independent reverse cleanup, re-prove
  ownership immediately before deletion, continue cleanup after failures, and
  give cleanup failure precedence.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.
- Do not mark M1-30c Complete before exact live span/sink/cleanup evidence and
  a zero-finding whole-range review.
- Completion requires exact-SHA Runnable UI success for the completion and
  plan-closure commits.

---

### Task 1: Start M1-30c with an exact repository contract

**Files:**
- Create: `app/quality/local-observability-manifest-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-30c source row, committed design, and M1-30b Complete state.
- Produces: exact M1-30c In-progress status at overall `659/1/65/3` and M1
  `68/26/1/41/0`.

- [x] **Step 1: Write the failing source/design/status contract**

Require the exact source dependency, deliverable, verification, and timebox;
one active M1-30c row; no complete M1-30c row; one complete M1-30b row; no
M1-30d active or complete row; the exact blocker set; start arithmetic; and
README language that says M1-30c is In progress and M1-30d remains Pending.
Bind the selected four-resource overlay, split core/Job application, exact
images, internal Service, local file sink, M1-21 resource attributes,
configuration-level no-egress boundary, licensing, cleanup, and fixed output.

- [x] **Step 2: Witness stale-status RED**

Run the focused contract under pinned Node 22.23.1. Require failures only for
the stale M1-30c status, counts, and README state. Existing local-product and
local-graph contracts must remain green.

- [x] **Step 3: Move only M1-30c to In progress**

Change overall `660/0/65/3` to `659/1/65/3` and M1 `68/27/0/41/0` to
`68/26/1/41/0`. Add one active M1-30c row. Preserve M1-30a and M1-30b
Complete, M1-30d Pending, and the exact blockers. Update only current-state
fixtures mechanically.

- [x] **Step 4: Run focused and all-quality GREEN**

Run the new contract, the two prior local-manifest contracts, and all
`app/quality` tests. Require exact 728-task arithmetic, one active row, no
duplicate task row, and no weakened historical contract.

- [x] **Step 5: Scan and commit the start transition**

Run whitespace and pinned redacted Gitleaks scans over the exact staged patch.
Commit only the status, README, and quality-contract slice as:

```text
docs: start M1-30c local observability manifest
```

---

### Task 2: Define the exact observability overlay and license inventory

**Files:**
- Create: `deploy/local/observability-manifest.test.mjs`
- Create: `deploy/local/observability-manifest.mjs`
- Create: `deploy/local/observability.yaml`
- Create: `deploy/local/observability-span.yaml`
- Create: `deploy/local/observability-license-audit.test.mjs`
- Create: `deploy/local/observability-license-audit.mjs`
- Create: `deploy/local/observability-licenses.json`

**Interfaces:**
- Produces: `COLLECTOR_IMAGE`, `OBSERVABILITY_CONSTANTS`,
  `buildObservabilityResources()`, `buildObservabilityCoreResources()`,
  `buildObservabilitySpanResources()`, `validateObservabilityResources(value)`,
  `parseObservabilityManifest(text, stage)`,
  `renderObservabilityCoreManifest(value)`,
  `renderObservabilitySpanManifest(value)`, `buildSyntheticObservabilitySpan()`,
  `parseObservabilitySink(bytes)`, and `auditObservabilityLicenses()`.
- Consumes: direct `js-yaml` 4.1.1, the M1-21 seven-attribute contract, exact
  Collector/BusyBox pins, and pinned public source/license evidence.

- [x] **Step 1: Write manifest, span, sink, and inventory tests first**

Require exactly one ConfigMap, Deployment, ClusterIP Service, and Job. The core
renderer must contain only the first three; the span renderer must contain only
the Job. Assert exact labels, namespace, configuration keys/bytes, images,
commands, environment, ports, probes, resources, security, volumes, restart
policies, deadlines, and absence of public/host exposure. The Job must set
`backoffLimit: 0`, `parallelism: 1`, `completions: 1`,
`podReplacementPolicy: Failed`, and pod `restartPolicy: Never`; reject every
defaulted, missing, drifted, or extra controller retry/replacement value.

Require the Collector configuration to contain one OTLP/HTTP receiver on
4318, one unpublished health extension on 13133, memory limiter, one-span
batch, file exporter under `/sink`, error-only logs, disabled metrics, and no
network exporter, remote endpoint, credential, proxy, environment expansion,
or backend. Bind BusyBox `wget` to one bounded `-t 1 -T 5` POST. Require the
exact OTLP request, exact response bytes, seven ordered
M1-21 resource attributes, one fixed trace/span, and no events, links, metrics,
logs, baggage, raw customer content, or unknown attributes.

Reject duplicate YAML/JSON keys or documents; aliases/tags; unknown keys;
missing/extra/reordered resources; selector/image/config/command/port drift;
credential/proxy injection; host namespace/port/path; external Service;
extra container; writable reader root; privilege/capability/seccomp drift;
remote exporters; multiple spans; malformed IDs/times; arbitrary coercion;
and prototype-bearing values.

Require exact Collector version/index/config/platform/source/license
fingerprints and exact reuse of the already audited BusyBox identity. Reject
missing, prohibited, mutable, mismatched, or drifted evidence.

Exercise the real exported license-fetch boundary, not only injected hashes:
require exact method/URL/header/redirect policy and order; chunked success with
known hashes; and rejection of redirect, non-200, missing/malformed body,
declared/actual length mismatch, empty/oversized content, reader failure, and
shared timeout. On every early rejection, require abort, bounded cancel, reader
release, and timer cleanup, including a cancellation promise that never
settles.

- [x] **Step 2: Witness absent-module RED**

Run the manifest/license tests before production modules, YAML, or inventory
exist. Require missing modules/files/exports only; the M1-30a/M1-30b manifest
and license suites remain green.

- [x] **Step 3: Implement strict models, renderers, and parsers**

Build exact plain objects with no caller input. Parse one bounded UTF-8 YAML
document under the JSON schema, reject duplicate keys/aliases/tags, recursively
require exact keys/types/values, deep-freeze validated copies, and require
byte-exact deterministic re-rendering. Bind stage values to exact `core` or
`span` resource sets; a complete or mixed manifest must fail either parser.

Build the canonical JSON request with fixed IDs/times and parse sink bytes with
recursive duplicate-key rejection, 64-KiB cap, complete OTLP-shape validation,
and exact normalized output. No parser may call string coercion on hostile
input.

- [x] **Step 4: Add canonical YAML and license records**

Write `observability.yaml` from the core renderer and
`observability-span.yaml` from the Job renderer. Record immutable upstream
Collector/image/license artifacts and the explicit local/no-backend boundary.
The license audit must use one shared deadline, exact URLs/order/hashes, bounded
stream reads, abort/cancel/release on rejection, and one fixed summary without
raw source/provider output.

- [x] **Step 5: Run six focused passes and commit**

Run six manifest/span/sink/license passes plus M1-30a/M1-30b manifest and
license regressions, syntax, ESLint, diff-check, and pinned secret scans.
Commit only this slice as:

```text
feat: add local observability Kubernetes manifest
```

---

### Task 3: Extend the disposable runtime for the observability profile

**Files:**
- Create: `deploy/local/observability-run.test.mjs`
- Create: `deploy/local/observability-run.mjs`
- Modify: `deploy/local/run.mjs`
- Modify: `deploy/local/run.test.mjs`
- Modify: `deploy/local/graph-run.mjs`
- Modify: `deploy/local/graph-run.test.mjs`

**Interfaces:**
- Produces: `OBSERVABILITY_SUCCESS_LINE`,
  `OBSERVABILITY_FAILURE_CATEGORIES`, `ObservabilityFailure`,
  `LocalObservabilitySystem`, `DockerKindObservabilityRuntime`,
  `runObservabilityMain()`, exact Collector OCI/containerd projections, staged
  manifest descriptors, and fixed observability output.
- Consumes: the reviewed product/graph lifecycles, Task 2 models, and the exact
  `m1-30c` profile containing `graph.yaml`, `observability.yaml`, then
  `observability-span.yaml`.

`OBSERVABILITY_FAILURE_CATEGORIES` is exactly `build`, `cleanup`,
`configuration`, `deadline`, `normalization`, `ownership`, `panic`, `provider`,
and `readiness`. Any unknown or forged category must normalize to `panic` in
the fixed public failure line.

- [x] **Step 1: Write profile and Collector-runtime tests before production**

Require exact host/node platform resolution, owned Docker configuration,
Collector index/config/manifest/rootfs/runtime inspection, shared-image
admission, immutable pull, kind load, containerd content proof and aliases,
fresh descriptors, profile-specific PID authority, environment allowlist,
fixed output, and exact cleanup. Prove M1-30a default bytes/trace and M1-30b
bytes/trace remain unchanged.

Cover unsupported platforms; absent/malformed image metadata; tag/config/
platform/rootfs/runtime drift; duplicate JSON keys; image collision;
definitive/ambiguous pull/load/tag/apply results; delayed application; partial
alias mutation; node replacement; descriptor/path replacement; signal/output
cap; cancellation; panic; forged/unknown failure categories; and cleanup
retry/precedence.

- [x] **Step 2: Witness missing observability-runtime RED**

Run focused observability tests before production exports exist. Require only
the new tests to fail. Require the complete product suite and graph suite to
remain green at their exact existing counts.

- [x] **Step 3: Add narrow profile-composition hooks**

Generalize only the reviewed profile hooks needed by M1-30c: allow exactly the
three canonical additional manifest descriptors, treat M1-30b and M1-30c as
the only PID-bound profiles, expose profile-specific product/graph selectors,
and permit graph image loading to retain one additional Collector plan without
changing the M1-30b two-image expectation. Reject every other proof name,
manifest name/order/path key, duplicate, extra, or byte drift.

- [x] **Step 4: Implement exact Collector image preparation**

Resolve and retain Collector index, config, selected-platform, rootfs,
environment, entrypoint, command, exposed-port, volume, label, user, and
working-directory metadata. Admit a pre-existing exact shared image only with
its complete alias and zero-consumer baseline. Otherwise pull once by immutable
identity. Load and content-prove it in the retained kind node, create only the
required node-local aliases, and retain the complete inventory before apply.

- [x] **Step 5: Implement staged descriptors and reverse cleanup**

Write and retain separate core and Job paths. Apply only product, graph, and
observability core during the base apply phase. The Job descriptor must remain
unapplied until Task 4's exact Collector-ready gate. Join all mutation
settlements before cleanup; re-prove cluster/node/network, image inventories,
shared baselines, descriptors, and temporary-root identities immediately
before deletion. Keep the recovery root when global absence is unproved.

- [x] **Step 6: Run six focused passes and commit**

Run six observability/product/graph runtime passes, syntax, ESLint, diff-check,
and pinned secret scans. Commit the new runtime and only the necessary narrow
composition refactor as:

```text
feat: prepare disposable local observability runtime
```

---

### Task 4: Prove the internal Collector and one local sink span

**Files:**
- Modify: `deploy/local/observability-run.test.mjs`
- Modify: `deploy/local/observability-run.mjs`

**Interfaces:**
- Produces: strict observability provider normalization, Collector-ready gate,
  staged Job apply/completion, bounded sink read, exact span normalization,
  unchanged product/graph proof, and reverse cleanup.
- Consumes: Task 2 exact resources/span parser and Task 3 retained image,
  cluster, descriptor, product, and graph identities.

- [x] **Step 1: Write provider and lifecycle tests before implementation**

Require exact ConfigMap data/resource version; Deployment/ReplicaSet/pod
lineage; both container images/security/resources/commands/mounts/status;
Service/EndpointSlice identity; absent external exposure; and an exact
Completed Job/Job pod with fixed response marker. Cross-bind every UID, owner,
node, imageID, selector, endpoint target, condition, start/finish time, and
container state.

Prove no Job apply command occurs before exact Collector core readiness. After
the gate, require exactly one Job apply, one successful POST marker, one stable
bounded sink artifact, one normalized trace/span, and unchanged product/graph
snapshots. Reject a second Job, retrying POST, multiple artifacts, stale sink,
or normalization before Job completion. Treat any failed, terminating,
replacement, duplicate, or controller-recreated Job pod as terminal rejection;
none may become authority for another POST.

Cover duplicate/unknown/missing provider keys; extra/missing resources;
resource-version/UID/owner/selector/node/image/mount/endpoint/condition drift;
malformed timestamps; container restart; alternate Service peer; external
exposure; premature/failed/replaced Job; empty/oversized/malformed/duplicate
sink JSON; extra trace/span/attribute; and response/log drift.

- [x] **Step 2: Witness lifecycle RED**

Run the new readiness/Job/sink/orchestration tests before implementing the
provider path. Require failures only at the absent observability behavior;
product and graph provider tests remain green.

- [x] **Step 3: Implement bounded exact Collector readiness**

Apply the core through its fresh descriptor. Read bounded raw JSON with
recursive duplicate-key rejection and poll within the main phase until the
Collector ConfigMap, Deployment, ReplicaSet, pod, Service, and EndpointSlice
form one complete exact provider snapshot. Re-prove product readiness, graph
health/persistence state, active PID authority, image inventory, and the core
descriptor before advancing.

- [x] **Step 4: Apply and prove the one-shot span Job**

Only after Step 3, journal one exact Job apply. Definitive rejection fails;
ambiguous results reconcile through exact Job absence or exact-owned state.
Poll for one exact successful Job/Job pod and fixed response marker. Do not
recreate or retry the Job and do not submit from the host.

- [x] **Step 5: Read and normalize the sink evidence**

Use fixed `kubectl exec` argv against the retained Collector pod and exact
`sink-reader` container. Re-prove the pod/container/volume identity, require a
regular non-symlink artifact, read at most 64 KiB plus one byte through bounded
child output, and require stable metadata around the read. Normalize exactly
one M1-21 span and re-prove the complete provider/product/graph snapshot.

- [x] **Step 6: Harden timeout, ambiguity, and cleanup cases**

Test delayed Collector/EndpointSlice/Job/sink state, thrown/signaled/malformed
apply or exec, main cancellation before and after Job apply, late-applied Job,
uncooperative child, provider panic, cleanup panic, resource replacement,
cleanup continuation/precedence, and global absence failure. Require mutation
settlement before cleanup and no late mutation after audit.

- [x] **Step 7: Run six focused passes and commit**

Run six combined observability suites plus original product/graph regressions,
syntax, ESLint, diff-check, and pinned secret scans. Commit as:

```text
feat: prove local observability span delivery
```

---

### Task 5: Expose the hermetic and live commands

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/local-observability-manifest-contract.test.ts`

**Interfaces:**
- Produces: `local:observability:test`, `local:observability:run`, and
  `local:observability:license` root commands plus exact operator guidance.

- [x] **Step 1: Write root-command and documentation RED**

Require exact scripts, pinned Node usage, fixed success/failure lines, staged
Job semantics, internal-only Service, local file sink, one M1-21 span,
configuration-level no-egress wording, no credentials/provider data,
disposable ownership/cleanup, licensing scope, M1-30c In progress, and M1-30d
Pending. Reject claims of ambient kubeconfig, host OTLP access, enforced
NetworkPolicy, remote backend delivery, production packaging, or shared-image
cleanup.

- [x] **Step 2: Add scripts and concise README guidance**

Add these exact scripts:

```json
"local:observability:test": "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs deploy/local/graph-manifest.test.mjs deploy/local/graph-run.test.mjs deploy/local/graph-license-audit.test.mjs deploy/local/observability-manifest.test.mjs deploy/local/observability-run.test.mjs deploy/local/observability-license-audit.test.mjs",
"local:observability:run": "node deploy/local/observability-run.mjs",
"local:observability:license": "node deploy/local/observability-license-audit.mjs"
```

Document prerequisites, fixed output, cluster-internal OTLP Service, staged
single span, ephemeral sink, no-network-export configuration, exact image and
license scope, cleanup behavior, and later M1-30d/M1-30 deferrals.

- [x] **Step 3: Run focused, root, and full GREEN**

Run the contract, root hermetic observability suite, license audit, original
product and graph suites, and full pinned repository verification. Run
production npm audit, dependency checks, whitespace, and secret scans.

- [x] **Step 4: Commit the command/documentation slice**

Commit only `package.json`, README, and the quality contract as:

```text
docs: expose local observability manifest proof
```

---

### Task 6: Run live proof, independent review, and completion

**Files:**
- Modify only in-scope files required by a witnessed tests-first live or review
  finding; runtime findings ordinarily remain under `deploy/local/`
- Modify completion status only after every implementation gate is green
- Update ignored reports/ledger under
  `.superpowers/sdd/2026-08-16-m1-30c-local-observability-manifest-implementation-plan/`

**Interfaces:**
- Produces: exact live Collector/span/sink/cleanup evidence, zero-finding
  independent review, M1-30c Complete transition, push, exact-SHA CI success,
  and checked plan closure.

- [x] **Step 1: Establish clean live preconditions**

Require zero M1-30c prefix/label resources and temporary roots. Fingerprint
shared Docker/Kubernetes state read-only. Confirm exact image/platform and
owned capacity without deleting a shared image, volume, container, network,
or cache.

- [x] **Step 2: Run the exact live command**

Run only:

```sh
env -i PATH="$HOME/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/usr/bin:/bin" \
  HOME="$HOME" LANG=C.UTF-8 npm run local:observability:run
```

Require exit zero and exactly:

```text
Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.
```

Require one exact span in the local sink, unchanged product/graph state, final
zero exact-owned containers, networks, local image aliases, cluster resources,
and temporary roots, with shared/ambient state unchanged.

- [x] **Step 3: Fix live findings only through TDD**

For each real mismatch, isolate the exact provider representation, write a
focused failing hermetic regression, implement the narrow fix, rerun all
affected gates, and rerun the full exact lifecycle. Never weaken image,
no-network-export, internal-only, one-span, prior-profile, output, license, or
cleanup requirements.

- [x] **Step 4: Run the final local gate matrix**

Require six observability-suite passes, original product and graph suites, all
four product Go race/tidy/verify/vet gates, exact graph and observability
license audits, full pinned repository verify/typecheck/lint/build, production
audit zero, dependency/license checks, diff-check, and pinned redacted
Gitleaks scans.

- [x] **Step 5: Obtain a zero-finding independent review**

Review the complete range against the source row, design, plan, M1-21,
M0-13/M0-22, M1-30a/M1-30b compatibility, manifests, licenses, production
runtime, tests, live evidence, cleanup, status arithmetic, and secrets. Address
every Critical, Important, and Minor finding through a separate tests-first
commit and repeat review.

- [x] **Step 6: Transition M1-30c to Complete**

Write completion-contract RED, then change overall `659/1/65/3` to
`659/0/66/3` and M1 `68/26/1/41/0` to `68/26/0/42/0`. Move exactly one M1-30c
row from In progress to Complete. Preserve M1-30a/M1-30b Complete, M1-30d
Pending, and the exact blockers. Run focused/full gates and commit:

```text
docs: complete M1-30c local observability manifest
```

- [x] **Step 7: Push completion and verify exact-SHA CI**

Push from a clean tracked tree/index, require equal local/origin/tracking SHAs,
and watch Runnable UI to terminal success for the exact completion SHA. Record
the run and job URLs in ignored evidence before closing the plan.

- [x] **Step 8: Close, push, and verify the plan**

Mark every plan checkbox complete only after the completion CI succeeds.
Commit only this plan with:

```text
docs: close M1-30c local observability manifest plan
```

Push again, require exact-SHA Runnable UI success, then perform final SHA-sync,
status-arithmetic, blocker, Gitleaks, zero-residue, and clean-tree audits.
