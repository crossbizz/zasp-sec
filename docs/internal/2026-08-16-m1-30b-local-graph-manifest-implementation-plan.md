# M1-30b Local Graph Manifest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checked-box (`- [x]`) syntax for completed work.

**Goal:** Add an exact-pinned Neo4j service with a bound persistent test volume
to the disposable local cluster, and prove graph health is reachable only
inside that cluster.

**Architecture:** Preserve the completed M1-30a product manifest and runner.
Add a separate strict graph overlay containing a local PV/PVC, Neo4j
Deployment, internal Service, and one-shot health Job. Compose it with the
existing disposable kind lifecycle through an M1-30b runner that proves exact
image/provider state, cluster-only reachability, marker persistence across pod
replacement, independent cleanup, and global absence.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, `js-yaml` 4.1.1, Docker 29.4.0,
kind 0.32.0, Kubernetes node 1.35.5, Neo4j Community 5.26.28 exact OCI index,
BusyBox 1.36.1-1 exact OCI index, Node test runner, Vitest 4.1.10, Gitleaks
8.30.1, GitHub Actions Runnable UI.

## Global constraints

- Work only on M1-30b. M1-30c remains Pending.
- Preserve M1-30a Complete and its byte-exact nine-resource product proof.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Use the exact Neo4j and BusyBox indexes and selected-platform digests; never
  use a tag-only or mutable image reference.
- Treat Neo4j Community and BusyBox as opt-in local development targets under
  their recorded licenses. Do not claim packaging or redistribution approval.
- Publish no graph workload port and create no Ingress, NodePort,
  LoadBalancer, external IP, host network, host PID, or host IPC.
- Pass no credential, token, proxy, cloud profile, Docker override, ambient
  kubeconfig, customer value, or provider value into the cluster.
- Store graph test data only in an exact node-local path inside the disposable
  kind node and bind it through one exact PV/PVC.
- Treat mutations as single-attempt. Reconcile only genuinely ambiguous
  outcomes through exact immutable state; never adopt a definitive rejection
  or name-only match.
- Journal and join mutations, use independent reverse cleanup, re-prove
  ownership immediately before deletion, continue cleanup after failures, and
  give cleanup failure precedence.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.
- Do not mark M1-30b Complete before exact live health/persistence/cleanup and
  a zero-finding whole-range review.
- Completion requires exact-SHA Runnable UI success for the completion and
  plan-closure commits.

---

### Task 1: Start M1-30b with an exact repository contract

**Files:**
- Create: `app/quality/local-graph-manifest-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-30b source row, committed design, and M1-30a Complete state.
- Produces: exact M1-30b In-progress status at overall `660/1/64/3` and M1
  `68/27/1/40/0`.

- [x] **Step 1: Write the failing source/design/status contract**

Require exact source dependency/deliverable/verification text, one active
M1-30b row, no complete M1-30b row, one complete M1-30a row, absent M1-30c
rows, exact blocker set, exact start arithmetic, and README language that says
M1-30b is In progress and M1-30c remains Pending. Bind the selected overlay,
five resources, exact images, internal-only health, persistent marker,
licensing, cleanup, and fixed-output boundaries.

- [x] **Step 2: Witness stale-status RED**

Run the focused contract under pinned Node. Require failures only for stale
M1-30b status/count/README state.

- [x] **Step 3: Move only M1-30b to In progress**

Change overall `661/0/64/3` to `660/1/64/3` and M1 `68/28/0/40/0` to
`68/27/1/40/0`. Add one active M1-30b row. Preserve M1-30a Complete, M1-30c
Pending, and the exact blockers. Update only current-state fixtures
mechanically.

- [x] **Step 4: Run focused and all-quality GREEN**

Run the new contract and all `app/quality` tests. Require 728-task arithmetic
and no weakened historical contract.

- [x] **Step 5: Scan and commit the start transition**

Run whitespace and pinned redacted secret scans. Commit the exact scoped
transition as:

```text
docs: start M1-30b local graph manifest
```

---

### Task 2: Define the exact graph overlay and license inventory

**Files:**
- Create: `deploy/local/graph-manifest.test.mjs`
- Create: `deploy/local/graph-manifest.mjs`
- Create: `deploy/local/graph.yaml`
- Create: `deploy/local/graph-license-audit.test.mjs`
- Create: `deploy/local/graph-license-audit.mjs`
- Create: `deploy/local/graph-licenses.json`

**Interfaces:**
- Produces: immutable graph/image constants, `buildGraphResources()`,
  `validateGraphResources(value)`, `parseGraphManifest(text)`,
  `renderGraphManifest(value)`, and exact license audit.
- Consumes: direct `js-yaml` 4.1.1 and pinned public source/license evidence.

- [x] **Step 1: Write manifest and inventory tests before production**

Require exactly one PV, PVC, Deployment, ClusterIP Service, and health Job.
Assert exact labels, namespace, storage class, node affinity, capacity/access,
claim binding, images, environment, ports, commands, probes, resources,
security, volumes, restart policies, deadlines, and no public/host exposure.

Reject duplicate YAML keys/documents/resources; aliases/tags; unknown keys;
missing/extra resources; selector/owner/image/node/storage drift; alternate
commands or environment; credential/proxy injection; host paths other than
the exact disposable-node data path; host ports/namespaces; external Services;
extra containers; writable health root; privilege/capability/seccomp drift;
and arbitrary coercion/prototype values.

Require exact Neo4j/BusyBox version, index/config/platform/source/license
fingerprints and the explicit opt-in local-development/no-redistribution
scope. Reject missing, prohibited, mutable, or drifted evidence.

- [x] **Step 2: Witness absent-module RED**

Run both focused Node test files before adding production modules or YAML.
Require missing exports/files only.

- [x] **Step 3: Implement strict models and parsers**

Build exact plain objects with the fixed local data path and proof-only node
label; accept no caller input. Parse one bounded UTF-8 YAML document under the
JSON schema, reject duplicate keys/aliases/tags, recursively require exact
keys/types/values, deep-freeze the validated copy, and require byte-exact
deterministic re-rendering.

- [x] **Step 4: Add canonical YAML and license records**

Commit the exact rendered `graph.yaml` and immutable upstream/image/license
records. The audit must fetch or inject exact bounded artifacts, verify hashes,
and emit one fixed summary without raw source or provider output.

- [x] **Step 5: Run six focused passes and commit**

Run six graph-manifest/license passes, syntax/lint, diff-check, and pinned
secret scans. Commit only this exact slice as:

```text
feat: add local graph Kubernetes manifest
```

---

### Task 3: Extend the disposable runtime for graph images and storage

**Files:**
- Create: `deploy/local/graph-run.test.mjs`
- Create: `deploy/local/graph-run.mjs`
- Modify: `deploy/local/run.mjs`
- Modify: `deploy/local/run.test.mjs`

**Interfaces:**
- Produces: graph lifecycle adapter, exact OCI/image projections, node-local
  storage preparation, descriptor-safe graph apply/read boundaries, and fixed
  graph output.
- Consumes: the reviewed M1-30a lifecycle and Task 2 graph model.

- [x] **Step 1: Write graph runtime tests before production**

Test exact host/platform image resolution, owned Docker configuration, pulls,
complete image inspection, kind load, containerd import, node-local directory
creation/ownership, manifest descriptors, environment allowlist, and fixed
output. Require the original product runner to remain byte/behavior compatible.

Cover unsupported platform, absent/malformed image metadata, tag/config/
platform/rootfs drift, duplicate JSON keys, image collision, definitive and
ambiguous pull/load/exec/apply results, delayed application, node replacement,
filesystem replacement, signal/output cap, cancellation, and panic.

- [x] **Step 2: Witness missing graph-runtime RED**

Run focused graph tests before production exports exist. Keep all original
M1-30a tests green.

- [x] **Step 3: Add narrow reusable lifecycle hooks**

Refactor only what graph composition requires from `LocalProductSystem`:
retained extra-image plans, extra owned manifest descriptor, exact node exec,
and graph verification hooks. The default product profile must still execute
the original phase order, fixed output, nine resources, and cleanup behavior.

- [x] **Step 4: Implement exact graph image and storage preparation**

Resolve and retain Neo4j/BusyBox index, config, selected-platform, rootfs,
environment, entrypoint, command, exposed-port, and intrinsic-volume metadata.
Configure the disposable kind node with one exact `KubeletConfiguration`
patch containing `podPidsLimit: 512`, and require the active kubelet config to
retain that exact projection at every node-identity proof.
Apply and re-prove the fixed `zasp.dev/graph-node=m1-30b` label only on the
retained kind node. Prepare only the fixed path in that node with UID/GID
7474. Journal each mutation and reconcile ambiguity only through exact
node/label/path state. Load both images by immutable identity and verify
containerd state.

- [x] **Step 5: Implement independent reverse cleanup**

Join settlements before cleanup. Re-prove the retained cluster/node/network,
images, node path, descriptors, and temporary root immediately before each
destructive action. Retain recovery material when absence is unproved, and
require prefix-wide final absence.

- [x] **Step 6: Run focused GREEN and commit**

Run both local runners' tests six times plus syntax/lint/diff/secret gates.
Commit only the graph runtime and necessary narrow product-runner refactor as:

```text
feat: prepare disposable local graph runtime
```

---

### Task 4: Prove cluster-internal health and persistent graph state

**Files:**
- Modify: `deploy/local/graph-run.test.mjs`
- Modify: `deploy/local/graph-run.mjs`

**Interfaces:**
- Produces: strict graph provider-state normalization, internal health proof,
  marker write, pod replacement, marker read, and reverse cleanup.
- Consumes: exact graph resources and retained image/node/storage identities.

- [x] **Step 1: Write provider/lifecycle tests before implementation**

Require exact PV/PVC Bound state, Deployment/ReplicaSet/pod lineage, pod
security/images/volumes, Service/EndpointSlice identity, Job ownership/status,
and fixed Job log marker. Require no Ingress, NodePort, LoadBalancer,
external IP, host port, or host-network projection.

Cover duplicate/unknown/missing provider keys; extra/missing resources;
resource-version, UID, owner, selector, node, image, volume, claim, endpoint,
condition, restart, Job, and log drift; malformed timestamps; alternate peer;
and host/public exposure.

- [x] **Step 2: Witness lifecycle RED**

Run the new provider and orchestration tests. Require failures at missing graph
apply/readiness/persistence behavior only.

- [x] **Step 3: Implement bounded exact readiness**

Apply product and graph manifests through separate fresh descriptors. Read raw
bounded JSON with duplicate-key rejection. Poll within the main phase until
the four product pods and exact graph resources form one cross-correlated
provider snapshot and the health Job completes with its fixed log marker.

- [x] **Step 4: Implement the persistence sequence**

Use fixed `kubectl exec`/`cypher-shell` argv to merge one synthetic marker.
Delete only the exact retained Neo4j pod, reconcile ambiguous deletion,
require a different replacement pod UID with the same PVC/PV lineage, then
query exactly one marker and re-prove internal health. Journal and join every
mutation.

- [x] **Step 5: Harden timeout, ambiguity, and cleanup cases**

Test delayed pod/PVC/Job state, thrown/signaled/malformed mutations, main
cancellation during marker write or pod delete, late-applied mutation,
uncooperative child, provider panic, cleanup panic, resource replacement,
cleanup continuation/precedence, and absence failure. Require no late mutation
after audit.

- [x] **Step 6: Run six focused passes and commit**

Run six combined local suites plus original M1-30a regressions, syntax/lint,
diff-check, and pinned secret scans. Commit as:

```text
feat: prove local graph health and persistence
```

---

### Task 5: Expose the hermetic and live commands

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/local-graph-manifest-contract.test.ts`

**Interfaces:**
- Produces: `local:graph:test`, `local:graph:run`, and
  `local:graph:license` root commands plus exact operator documentation.

- [x] **Step 1: Write root-command/docs RED**

Require exact scripts, pinned Node usage, fixed success/failure lines,
cluster-only Service boundary, persistence semantics, no credentials/provider
data, disposable ownership/cleanup, licensing scope, M1-30b In progress, and
M1-30c Pending. Reject documentation that suggests ambient kubeconfig, host
port access, production packaging approval, or shared-resource cleanup.

- [x] **Step 2: Add scripts and concise README guidance**

Add:

```json
"local:graph:test": "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs deploy/local/graph-manifest.test.mjs deploy/local/graph-run.test.mjs deploy/local/graph-license-audit.test.mjs",
"local:graph:run": "node deploy/local/graph-run.mjs",
"local:graph:license": "node deploy/local/graph-license-audit.mjs"
```

Document prerequisites, expected fixed line, cluster-only health, ephemeral
cluster versus pod-persistent data, and the opt-in GPL boundary.

- [x] **Step 3: Run focused/root/full GREEN and commit**

Run the contract, root hermetic graph suite, graph license audit, original
product suite, and full pinned repository verification. Run production npm
audit, whitespace, and secret scans. Commit as:

```text
docs: expose local graph manifest proof
```

---

### Task 6: Run live proof, independent review, and completion

**Files:**
- Modify only after tests-first live/review findings under `deploy/local/`
- Modify completion status only after every gate is green
- Update ignored reports/ledger under
  `.superpowers/sdd/2026-08-16-m1-30b-local-graph-manifest-implementation-plan/`

**Interfaces:**
- Produces: exact live health/persistence/cleanup evidence, zero-finding
  independent review, M1-30b Complete transition, push, exact-SHA CI success,
  and checked plan closure.

- [x] **Step 1: Establish clean live preconditions**

Require zero M1-30b prefix/label resources and temporary roots. Fingerprint
shared Docker/Kubernetes state read-only. Confirm exact images/platforms and
owned capacity without deleting a shared image, volume, container, network,
or cache.

- [x] **Step 2: Run the exact live command**

Run only:

```sh
env -i PATH="$HOME/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/usr/bin:/bin" \
  HOME="$HOME" LANG=C.UTF-8 npm run local:graph:run
```

Require exit zero and exactly:

```text
Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.
```

Require final zero exact-owned containers, networks, graph aliases, node data
paths, and temporary roots, with shared state unchanged.

- [x] **Step 3: Fix live findings only through TDD**

For each real mismatch, isolate the exact provider representation, write a
focused failing hermetic regression, implement the narrow fix, rerun all
affected gates, and rerun the full exact lifecycle. Never weaken identity,
internal-only exposure, persistence, license, output, or cleanup requirements.

- [x] **Step 4: Run the final local gate matrix**

Require six graph-suite passes, original product suite, all four product Go
race/tidy/verify/vet gates, exact graph license audit, full pinned repository
verify/typecheck/lint/build, production audit zero, dependency/license checks,
diff-check, and pinned redacted Gitleaks scans.

- [x] **Step 5: Obtain a zero-finding independent review**

Review the complete range against the source row, design, plan, M1-30a
boundary, graph/license contracts, production runtime, tests, live evidence,
cleanup, status arithmetic, and secrets. Address every Critical, Important,
and Minor finding through a separate tests-first commit and repeat review.

- [x] **Step 6: Transition M1-30b to Complete**

Write completion-contract RED, then change overall `660/1/64/3` to
`660/0/65/3` and M1 `68/27/1/40/0` to `68/27/0/41/0`. Move exactly one M1-30b
row from In progress to Complete. Preserve M1-30a Complete, M1-30c Pending,
and the exact blockers. Run focused/full gates and commit:

```text
docs: complete M1-30b local graph manifest
```

- [x] **Step 7: Push and close the plan**

Completion commit `3a1ba867ff8839d2bc4cc48602878aa6fe77b2a6` was pushed
from a clean tracked tree/index with equal local, origin, and tracking SHAs.
Runnable UI run `31995062272` completed successfully for that exact SHA. This
checked plan-only commit records closure as:

```text
docs: close M1-30b local graph manifest plan
```

Its required post-commit transport gate is a second push followed by exact-SHA
Runnable UI success and final SHA-sync, status-arithmetic, secret-scan,
zero-residue, and clean-tree audits recorded in the ignored Task 6 evidence.
