# M1-30a Local Product Manifests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the four existing Go product commands as hardened,
cluster-internal pods and prove all four become Ready in an exact-owned local
Kubernetes cluster.

**Architecture:** Define one canonical tracked Kubernetes manifest set for a
namespace, four Deployments, and four ClusterIP Services. Host-build static Go
binaries, package them in dependency-free `scratch` images, and load them into
an exact-pinned disposable kind cluster. A strict Node boundary validates every
manifest/runtime invariant, supervises the lifecycle, and proves reverse
cleanup without reading or mutating the ambient Kubernetes context.

**Tech Stack:** Go 1.25.6 standard library, Node.js 22.23.1, npm 10.9.8,
`js-yaml` 4.1.1, Docker 29.4.0, kind 0.32.0, Kubernetes node 1.35.5, Node test
runner, Vitest 4.1.10, Gitleaks 8.30.1, GitHub Actions Runnable UI.

## Global constraints

- Work only on M1-30a. M1-30b remains Pending.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Deploy the actual `agentsec-api`, `agentsec-worker`, `event-ingest`, and
  `runtime-gateway` commands; do not substitute shell fixture pods.
- Add no production Go or npm dependency and change no lockfile.
- Publish no host port and create no Ingress, NodePort, LoadBalancer, external
  IP, host network, host PID, host IPC, or host path.
- Pass no credential, token, proxy, kubeconfig, cloud profile, or provider
  environment value into a build or pod.
- Use only an exact-owned disposable kind cluster and owned kubeconfig; never
  target the ambient OrbStack context.
- Every pod is non-root, read-only, capability-free, service-account-token
  free, resource-bounded, and exposes only the shared health listener.
- Treat mutations as single-attempt. Reconcile only genuinely ambiguous
  outcomes through exact immutable identity; never adopt a definitive
  rejection or name-only match.
- Journal mutations, join settlements, run independent reverse cleanup,
  re-prove ownership immediately before deletion, continue cleanup after
  failures, and give cleanup failure precedence.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1/npm 10.9.8 for all repository gates.
- Do not mark M1-30a Complete before exact live readiness/cleanup and a
  zero-finding whole-range review.
- Completion requires exact-SHA Runnable UI success for both the completion
  commit and the plan-only closure commit.

---

### Task 1: Start M1-30a with an exact repository contract

**Files:**
- Create: `app/quality/local-product-manifests-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-30a source row, committed design, and M1-29 Complete state.
- Produces: exact M1-30a In-progress status at overall `661/1/63/3` and M1
  `68/28/1/39/0`.

- [x] **Step 1: Write the failing source/design/status contract**

Create a Vitest contract that parses tracker tables structurally and requires:

```ts
expect(sourceSection).toContain("Depends on: `M1-29`");
expect(sourceSection).toContain(
  "Create local Kubernetes manifests for product API, worker, event-ingest and runtime-gateway stubs",
);
expect(sourceSection).toContain("All four pods become Ready in local Kubernetes");
expect(active.filter(([task]) => task === "M1-30a")).toHaveLength(1);
expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(0);
expect(complete.filter(([task]) => task === "M1-29")).toHaveLength(1);
expect([...active, ...complete].filter(([task]) => task === "M1-30b")).toHaveLength(0);
expect(tracker).toContain("`661/1/63/3`");
expect(milestoneM1).toEqual(["M1", "68", "28", "1", "39", "0"]);
expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
expect(readmeSection).toContain("M1-30a is In progress");
expect(readmeSection).toContain("M1-30b remains Pending");
```

Bind the selected real-command/kind architecture, nine-resource manifest,
cluster-internal boundary, pod security, exact image recipe, ownership rules,
fixed output, live gate, and start/final arithmetic. Reject duplicate M1-30a
rows, concurrent M1-30b activation, an M1-30a Complete row, changed blockers,
or aggregate-count drift.

- [x] **Step 2: Witness stale-status RED**

Run the focused contract under pinned Node. Require the source/design/M1-29
assertions to pass and only the expected M1-30a status/README/count assertions
to fail.

- [x] **Step 3: Move only M1-30a to In progress**

Update overall arithmetic from `662/0/63/3` to `661/1/63/3` and M1 from
`68/29/0/39/0` to `68/28/1/39/0`. Add exactly one active M1-30a row and the
matching README boundary. Preserve M1-29 Complete, M1-30b Pending, and the
three exact blockers. Update only current-state fixture literals mechanically.

- [x] **Step 4: Run focused and all-quality GREEN**

Run the new contract and all `app/quality` tests under pinned Node. Require
exact 728-task arithmetic and no weakened historical contract.

- [x] **Step 5: Scan and commit the start transition**

Run whitespace and pinned redacted secret scans. Commit only the contract,
README, tracker, and mechanical count fixtures as:

```text
docs: start M1-30a local product manifests
```

---

### Task 2: Define and validate the exact manifests

**Files:**
- Create: `deploy/local/manifests.test.mjs`
- Create: `deploy/local/manifests.mjs`
- Create: `deploy/local/product-stubs.yaml`

**Interfaces:**
- Produces: immutable `PRODUCTS`, `buildProductResources()`,
  `validateProductResources(value)`, `parseProductManifest(text)`, and
  `renderProductManifest(value)`.
- Consumes: direct `js-yaml` 4.1.1 only for YAML parsing/rendering.

- [x] **Step 1: Write exact manifest tests before production**

Cover one namespace, four Deployments, and four Services with exact names,
labels, selectors, images, single replicas/containers, internal ports, three
health probes, resources, service-account token disablement, DNS policy, and
pod/container security. Require deep immutability and deterministic rendering.

Hostile tables must reject duplicate YAML keys/documents/resources; aliases;
unknown keys; missing/extra resources; selector drift; cross-component image,
label, or service routing; replicas other than one; mutable image pull;
command/argument/environment injection; host namespaces/ports/paths; external
services; extra containers/init/ephemeral containers; writable root; root UID;
capability/privilege/seccomp drift; resource/probe drift; and arbitrary YAML
tags or anchors.

- [x] **Step 2: Witness absent-module RED**

Run `node --test deploy/local/manifests.test.mjs`. Require failure only because
the production module and canonical YAML are absent.

- [x] **Step 3: Implement the structured model and strict parser**

Build exact plain objects with no caller input. Parse one bounded UTF-8 YAML
document under the JSON schema, reject duplicate keys/aliases/tags before
conversion, recursively require exact keys and primitive types, then deep
freeze the validated copy. Do not permit JavaScript coercion or prototype
members.

- [x] **Step 4: Add the canonical tracked YAML**

Render `product-stubs.yaml` from the model with stable key order, indentation,
line endings, and final newline. Require byte-exact round-trip equality in the
tests so hand edits cannot silently diverge from the executable model.

- [x] **Step 5: Run six focused passes and commit**

Run six consecutive manifest test passes, syntax/lint, diff-check, and pinned
secret scans. Commit only the three manifest files as:

```text
feat: add local product Kubernetes manifests
```

---

### Task 3: Build exact dependency-free service images

**Files:**
- Create: `deploy/local/Dockerfile`
- Create: `deploy/local/run.test.mjs`
- Create: `deploy/local/run.mjs`

**Interfaces:**
- Produces: fixed Dockerfile contract, `buildServicePlan(product, paths)`,
  strict process results, retained immutable image identities, and exact image
  cleanup.
- Consumes: the four reviewed Go command modules and the Task 2 product model.

- [x] **Step 1: Write build-boundary tests first**

Require exact Go package/cwd/output mapping, `CGO_ENABLED=0`, `GOENV=off`,
`GOWORK=off`, `-trimpath`, stripped symbols, exact build version, owned caches,
and no ambient credential/proxy/profile input. Require one owned context per
binary and the exact `scratch`, UID/GID 65532, port, and entrypoint Dockerfile.

Cover subprocess timeout, cancellation, panic, signal, output overflow,
malformed success, partial context, filesystem replacement, compiler failure,
Docker build rejection/ambiguity, exact image reinspection, reference
collision, image-label mismatch, delayed application, and cleanup precedence.

- [x] **Step 2: Witness absent-runtime RED**

Run the focused build tests before adding `Dockerfile` or `run.mjs`. Require
missing production exports/files only.

- [x] **Step 3: Implement bounded build and image ownership**

Create a runtime with injected process/filesystem boundaries. Journal every
directory/file/image mutation. Retain canonical path/device/inode for every
owned root and immutable image ID/reference/labels/config/rootfs projection
for each image. Use async spawned children, one combined output cap, abort
fencing, SIGKILL, and reap/join.

- [x] **Step 4: Implement fail-closed image cleanup**

Before `docker image rm`, re-inspect the exact retained ID and require its
single expected reference, proof/run labels, scratch config, non-root user,
entrypoint, port, and zero unexpected layers/config. A changed or unproved
image is retained and cleanup fails; no name-only deletion is allowed.

- [x] **Step 5: Run focused GREEN and commit**

Run the build-focused tests six times plus syntax/lint/diff/secret gates.
Commit the exact Dockerfile/runtime/test slice as:

```text
feat: build local product runtime images
```

---

### Task 4: Orchestrate disposable kind readiness and cleanup

**Files:**
- Modify: `deploy/local/run.test.mjs`
- Modify: `deploy/local/run.mjs`

**Interfaces:**
- Produces: `orchestrate(runtime)`, numeric `runMain(runtime)`, fixed success
  and failure lines, disposable cluster ownership, strict Kubernetes reads,
  and independent cleanup.
- Consumes: exact kind/node pins, Task 2 manifest, and Task 3 images.

- [x] **Step 1: Write lifecycle/adversarial tests before orchestration**

Test the full phase order with injected fakes: environment/preflight, owned
temp admission, kind download/checksum, four builds, cluster create, image
load, apply, readiness, service/internal-exposure proof, reverse deletion,
image cleanup, temp cleanup, global absence, and fixed output.

Cover unsupported host/platform, bad checksum, absent/malformed Docker
metadata, cluster/container/network replacement, partial and delayed creates,
definitive versus ambiguous results, thrown/signaled mutations, stale other-run
prefixes, malformed/duplicate Kubernetes JSON, extra/missing/unready/restarted
pods, image-ID drift, Deployment status drift, service/selector/endpoint drift,
external exposure, cancellation at every boundary, uncooperative child, late
mutation, cleanup panic, cleanup continuation/precedence, and output cap.

- [x] **Step 2: Witness missing lifecycle RED**

Run the focused lifecycle group and require failures only for the wished-for
cluster/Kubernetes APIs.

- [x] **Step 3: Implement exact kind and Kubernetes boundaries**

Reuse the repository-reviewed kind 0.32.0 official asset URLs/checksums and
kindest/node 1.35.5 index/platform digests. Create a unique marker cluster with
numeric-loopback API binding and owned kubeconfig. Route every kind/kubectl
call through explicit paths and environment allowlists. Validate bounded JSON
with duplicate-key rejection and exact resource projections.

- [x] **Step 4: Implement phase fencing and reverse cleanup**

Bound main at 600 seconds and cleanup at 180 seconds with a 60-second
settlement margin. Journal mutations before interpretation and join all
settlements before cleanup/audit. Delete namespace/cluster dependencies in
reverse order through exact retained identities; then remove exact images and
temp roots. Require final global prefix/label/reference absence.

- [x] **Step 5: Run focused GREEN and six stability passes**

Run all `deploy/local` Node tests six consecutive times. Then run all four Go
health command race suites, module tidy-diff/verify/vet, syntax, lint, and
diff-check. Commit the orchestration slice as:

```text
feat: verify local product pods in disposable kind
```

---

### Task 5: Expose commands and prove the live lifecycle

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/local-product-manifests-contract.test.ts`
- Create: ignored task report/ledger files under `.superpowers/sdd/`

**Interfaces:**
- Produces: `npm run local:product:test` and `npm run local:product:run`.
- Consumes: Task 2-4 exact artifacts and the existing pinned runtime tools.

- [x] **Step 1: Write command/documentation tests first**

Require exact package scripts and one bounded README section naming all four
services, cluster-internal exposure, required Docker/network prerequisites,
hermetic versus live commands, fixed success line, cleanup behavior, and
explicit M1-30b deferral. Reject stale or substitute commands.

- [x] **Step 2: Witness wiring RED and add only the documented boundary**

Run the focused contract, then add the scripts and README text. The test
command must remain hermetic and make no Docker/Kubernetes/network call.

- [x] **Step 3: Run all local GREEN gates before live**

Require six `local:product:test` passes, all four Go race suites,
tidy-diff/verify/vet for all involved modules, full pinned `npm run verify`,
production audit zero, syntax/lint, whitespace, and pinned redacted secret
scans.

- [x] **Step 4: Run the exact live proof once from zero state**

Fingerprint the ambient OrbStack context read-only, require zero proof-prefixed
resources/images/temp roots, then run exactly:

```bash
env -i PATH="$PATH" HOME="$HOME" LANG=C.UTF-8 \
  npm run local:product:run
```

Require exit zero and only:

```text
Local product manifests passed: pods=4 ready=4 services=4 internal=true cleanup=true.
```

Immediately require zero exact-owned clusters, node containers, networks,
images, kubeconfigs, and temp roots, plus an unchanged ambient-context
fingerprint. On failure, stop new mutation, re-prove exact retained ownership,
clean only proven resources, write tests-first regression coverage, and repeat
all affected gates before another live attempt.

- [x] **Step 5: Record evidence and commit wiring**

Record RED/GREEN/live/cleanup/audit evidence without identifiers or secrets.
Commit only root scripts, README, and quality contract as:

```text
docs: expose local product manifests
```

---

### Task 6: Review, complete, push, and close M1-30a

**Files:**
- Modify as review findings require, tests first.
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`
- Modify: this plan only after shipped completion evidence exists.

- [x] **Step 1: Run independent whole-range review**

Review from the pre-M1-30a base through the preparation head. Require source,
design, manifest, build, lifecycle, security, ownership, cleanup, fixed-output,
live evidence, dependency/license, docs, status, and package consistency. Fix
every Critical, Important, and Minor finding tests-first in separate commits
until review reports zero findings and Ready Yes.

- [x] **Step 2: Witness completion-contract RED**

Change only the status contract to require M1-30a Complete, no active M1-30a,
M1-30b Pending, overall `661/0/64/3`, M1 `68/28/0/40/0`, unchanged blockers,
and README live-ready wording. Require failures only for stale status/docs.

- [x] **Step 3: Complete only M1-30a and run final gates**

Update tracker/README/current fixtures, then rerun six hermetic passes, four Go
race suites, live readiness/cleanup if behavior changed, full pinned repository
verification, production audit, dependency/license checks, whitespace, and
all-history/evidence secret scans.

- [x] **Step 4: Commit, push, and verify exact-SHA CI**

Commit the exact completion transition as:

```text
docs: complete M1-30a local product manifests
```

Push only after a clean synchronized tree. Require the Runnable UI workflow to
finish successfully for the exact completion SHA.

- [x] **Step 5: Close the plan atomically**

Check every plan box only after its evidence exists, commit only this plan as:

```text
docs: close M1-30a local product manifests plan
```

Push and require exact-SHA Runnable UI success again. Final state must be clean,
local/origin/tracking SHAs equal, M1-30a Complete, M1-30b Pending, and the three
existing blockers unchanged.
