# M1-30d Local AWS Emulator Manifest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:executing-plans` to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an exact-pinned, internal-only LocalStack S3 overlay to the
disposable local cluster and prove one staged client Job uses the fixed local
AWS endpoint contract.

**Architecture:** Preserve the completed M1-30a product, M1-30b graph, and
M1-30c observability profiles. Add one strict AWS-emulator core containing an
endpoint ConfigMap, LocalStack Deployment, and ClusterIP Service; prove that
core Ready before applying a separately rendered one-shot S3 Job. Compose the
overlay through an exact M1-30d profile with retained image, Kubernetes,
endpoint, prior-profile, cleanup, and license authority.

**Tech Stack:** Node.js 22.23.1, npm 10.9.8, `js-yaml` 4.1.1, Docker 29.4.0,
kind 0.32.0, Kubernetes node 1.35.5, LocalStack Community 4.7.0 exact OCI
index, Node test runner, Vitest 4.1.10, Gitleaks 8.30.1, GitHub Actions
Runnable UI.

**Spec:** `docs/internal/2026-08-17-m1-30d-local-aws-emulator-manifest-design.md`

## Global constraints

- Work only on M1-30d. M1-30 remains Pending and M1-31 remains unstarted.
- Preserve M1-30a, M1-30b, and M1-30c Complete, including exact manifest
  bytes, default profile behavior, command traces, fixed output, and tests.
- Preserve M0-09, M0-18, and M0-19 as the only Blocked source tasks.
- Use only
  `localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c`.
- Enable only S3, disable persistence, and publish no LocalStack port to the
  host. Create no Ingress, NodePort, LoadBalancer, external IP, host network,
  host PID, host IPC, host path, Docker socket, or service-account token.
- Pass only fixed synthetic local credentials and exact ConfigMap-backed
  endpoint variables to the staged client Job. Read no ambient AWS, proxy,
  dotenv, Docker, or Kubernetes configuration.
- Apply the S3 Job only after exact LocalStack Deployment, pod, Service,
  EndpointSlice, and S3 capability readiness. Perform one explicit endpoint-
  bound list-buckets request and emit only the fixed marker.
- Do not inject endpoint variables into product Deployments or add the product
  client factory. That work belongs to M1-31.
- Treat mutations as single-attempt. Reconcile only genuinely ambiguous
  outcomes through exact immutable state; never adopt a definitive rejection
  or name-only match.
- Journal and join mutations, use independent reverse cleanup, re-prove
  ownership immediately before deletion, continue cleanup after failures, and
  give cleanup failure precedence.
- Every behavior or status change requires a witnessed tests-only RED first.
- Use pinned Node 22.23.1/npm 10.9.8 for repository gates.
- Do not mark M1-30d Complete before exact live S3/cleanup evidence and a
  zero-finding whole-range review.
- Completion requires exact-SHA Runnable UI success for the completion and
  plan-closure commits.

---

### Task 1: Start M1-30d with an exact repository contract

**Files:**
- Create: `app/quality/local-aws-emulator-manifest-contract.test.ts`
- Modify: `README.md`
- Modify: `docs/internal/implementation_status_v1.5.md`
- Modify: current count/status fixtures under `app/quality/`

**Interfaces:**
- Consumes: the M1-30d source row, committed design, and M1-30c Complete state.
- Produces: exact M1-30d In-progress status at overall `658/1/66/3` and M1
  `68/25/1/42/0`.

- [x] **Step 1: Write the failing source/design/status contract**

Require the exact source dependency, deliverable, verification, and timebox;
one active M1-30d row; no complete M1-30d row; one complete M1-30c row; no
M1-30 active or complete row; the exact blocker set; start arithmetic; and
README language that says M1-30d is In progress and M1-30 remains Pending.
Bind the selected three-resource core plus staged Job, exact image, internal
Service, ConfigMap endpoint keys, fixed synthetic credentials, explicit S3
endpoint argument, profile preservation, license boundary, cleanup, and fixed
public output.

- [x] **Step 2: Witness stale-status RED**

Run:

```sh
npx vitest run app/quality/local-aws-emulator-manifest-contract.test.ts \
  app/quality/local-observability-manifest-contract.test.ts
```

Require failures only for stale M1-30d status, counts, and README state. The
M1-30c contract must remain green.

- [x] **Step 3: Move only M1-30d to In progress**

Change overall `659/0/66/3` to `658/1/66/3` and M1 `68/26/0/42/0` to
`68/25/1/42/0`. Add one active M1-30d row. Preserve M1-30a, M1-30b, and
M1-30c Complete, M1-30 Pending, and the exact blockers. Update only
current-state fixtures mechanically.

- [x] **Step 4: Run focused and all-quality GREEN**

Run the new contract, all three prior local-manifest contracts, and every
`app/quality` test. Require exact 728-task arithmetic, one active row, no
duplicate task row, and no weakened historical contract.

- [x] **Step 5: Scan and commit the start transition**

Run `git diff --cached --check` and pinned redacted Gitleaks over the exact
staged patch. Commit only the status, README, and quality-contract slice as:

```text
docs: start M1-30d local AWS emulator manifest
```

---

### Task 2: Define the exact AWS-emulator overlay and license inventory

**Files:**
- Create: `deploy/local/aws-emulator-manifest.test.mjs`
- Create: `deploy/local/aws-emulator-manifest.mjs`
- Create: `deploy/local/aws-emulator.yaml`
- Create: `deploy/local/aws-emulator-s3.yaml`
- Create: `deploy/local/aws-emulator-license-audit.test.mjs`
- Create: `deploy/local/aws-emulator-license-audit.mjs`
- Create: `deploy/local/aws-emulator-licenses.json`

**Interfaces:**
- Produces: `LOCALSTACK_IMAGE`, `AWS_EMULATOR_CONSTANTS`,
  `buildAwsEmulatorResources()`, `buildAwsEmulatorCoreResources()`,
  `buildAwsEmulatorS3Resources()`, `validateAwsEmulatorResources(value)`,
  `parseAwsEmulatorManifest(text, stage)`,
  `renderAwsEmulatorCoreManifest(value)`,
  `renderAwsEmulatorS3Manifest(value)`, and
  `auditAwsEmulatorLicenses()`.
- Consumes: `js-yaml` 4.1.1, the design's exact LocalStack index, endpoint
  contract, and immutable upstream source/license evidence.

- [x] **Step 1: Write manifest, endpoint, Job, and inventory tests first**

Require exactly one ConfigMap, Deployment, ClusterIP Service, and Job. The
core renderer contains only the first three; the S3 renderer contains only the
Job. Assert exact labels, namespace, endpoint data, image, command, env,
ConfigMap refs, service settings, ports, probes, resources, security,
volumes, restart policies, deadlines, and no host/public exposure.

The Job must set `backoffLimit: 0`, `parallelism: 1`, `completions: 1`,
`podReplacementPolicy: Failed`, and pod `restartPolicy: Never`. Its command
must use the image-owned AWS wrapper with explicit
`--endpoint-url "$AWS_ENDPOINT_URL_S3"`, one `s3api list-buckets` operation,
an exact zero-bucket result, suppressed provider output, and only
`localstack-s3-endpoint-ready` on stdout.

Reject duplicate YAML/JSON keys or documents; aliases/tags; unknown keys;
missing, extra, or reordered resources; selector/image/command/env/port drift;
credential, token, profile, proxy, or host-endpoint injection; host namespaces
or paths; external Service; extra container; privilege/capability/seccomp
drift; persistent LocalStack state; alternate services; client retry or second
S3 call; and prototype-bearing or coercive input.

Require exact LocalStack version/index/config/platform/runtime/source/license
fingerprints. Reject missing, prohibited, mutable, mismatched, or drifted
evidence. Exercise the real exported license-fetch boundary: exact
method/URL/header/no-redirect/order, chunked success, status/redirect/length/
empty/oversize/hash/timeout/read failures, and abort plus bounded cancel plus
release on every early rejection.

- [x] **Step 2: Witness absent-module RED**

Run:

```sh
node --test deploy/local/aws-emulator-manifest.test.mjs \
  deploy/local/aws-emulator-license-audit.test.mjs
```

Require missing modules, files, and exports only. Existing product, graph, and
observability manifest/license suites must remain green.

- [x] **Step 3: Implement strict models, renderers, and parsers**

Build exact plain objects with no caller input. Parse one bounded UTF-8 YAML
document under `JSON_SCHEMA`, reject duplicate keys, aliases, and tags,
recursively require exact keys, types, and values, deep-freeze validated
copies, and require byte-exact deterministic re-rendering. Bind stage values
to exact `core` or `s3` resource sets; a complete or mixed manifest fails
either parser. No parser may call string coercion on hostile input.

- [x] **Step 4: Add canonical YAML and license records**

Generate `aws-emulator.yaml` from the core renderer and
`aws-emulator-s3.yaml` from the Job renderer. Record LocalStack Community
`v4.7.0`, its annotated tag object, source commit, Apache-2.0 license,
supplemental terms, source manifest, exact image metadata, and the bundled-
dependency boundary. The audit uses one shared deadline, bounded stream
reads, deterministic abort/cancel/release, and a fixed summary.

- [x] **Step 5: Run six focused passes and commit**

Run six manifest/Job/license passes plus the M1-30a/b/c manifest and license
regressions, syntax, ESLint, diff-check, and pinned secret scans. Commit only
this slice as:

```text
feat: add local AWS emulator Kubernetes manifest
```

---

### Task 3: Extend the disposable runtime for the M1-30d profile

**Files:**
- Create: `deploy/local/aws-emulator-image.mjs`
- Create: `deploy/local/aws-emulator-run.test.mjs`
- Create: `deploy/local/aws-emulator-run.mjs`
- Modify: `deploy/local/run.mjs`
- Modify: `deploy/local/run.test.mjs`
- Modify: `deploy/local/graph-run.mjs`
- Modify: `deploy/local/graph-run.test.mjs`
- Modify: `deploy/local/observability-run.mjs`
- Modify: `deploy/local/observability-run.test.mjs`

**Interfaces:**
- Produces: `buildLocalStackImagePlan(platform)`,
  `AWS_EMULATOR_SUCCESS_LINE`, `AWS_EMULATOR_FAILURE_CATEGORIES`,
  `AwsEmulatorFailure`, `buildAwsEmulatorProfile()`,
  `awsEmulatorApplyPlan()`, `LocalAwsEmulatorSystem`,
  `DockerKindAwsEmulatorRuntime`, and `runAwsEmulatorMain()`.
- Consumes: the reviewed product/graph/observability lifecycles, Task 2 models,
  and the exact five-manifest M1-30d profile.

`AWS_EMULATOR_FAILURE_CATEGORIES` is exactly `build`, `cleanup`,
`configuration`, `deadline`, `normalization`, `ownership`, `panic`,
`provider`, and `readiness`. Unknown or forged categories normalize to
`panic` in the fixed public failure line.

- [x] **Step 1: Write profile and LocalStack-runtime tests before production**

Require exact host/node platform resolution, LocalStack index/config/manifest/
rootfs/runtime inspection, shared-image admission, immutable pull, kind load,
containerd content proof and aliases, fresh descriptors, inherited PID
authority, environment allowlist, fixed output, and exact cleanup. Prove
M1-30a default bytes/trace, M1-30b bytes/trace, and M1-30c bytes/trace remain
unchanged.

Cover unsupported platforms; absent/malformed image metadata; tag/config/
platform/rootfs/runtime drift; duplicate JSON keys; image collision;
definitive or ambiguous pull/load/tag/apply outcomes; delayed application;
partial alias mutation; node replacement; descriptor/path replacement;
signal/output cap; cancellation; panic; forged categories; and cleanup retry,
continuation, and precedence.

- [x] **Step 2: Witness missing AWS-emulator-runtime RED**

Run the focused AWS-emulator tests before production exports exist. Require
only new tests to fail and the complete product, graph, and observability
suites to retain their exact counts.

- [x] **Step 3: Add narrow profile-composition hooks**

Allow exactly the five canonical additional manifest descriptors for
`m1-30d`. Keep M1-30b, M1-30c, and M1-30d as the only PID-bound profiles.
Permit graph/observability image loading to retain one additional LocalStack
plan without changing earlier profile expectations. Validate manifest object
data descriptors once, snapshot their exact canonical values, and reject
accessors, duplicates, alternate proof names, order/path drift, or byte drift.

- [x] **Step 4: Implement exact LocalStack image preparation**

Resolve and retain the LocalStack index, config, selected-platform, rootfs,
environment, entrypoint, command, exposed-port, volume, label, user, and
working-directory metadata. Admit a pre-existing exact shared image only with
its complete alias and consumer baseline. Otherwise pull once by immutable
identity. Load and content-prove it in the retained kind node, create only
required node-local aliases, and retain the complete inventory before apply.

- [x] **Step 5: Implement staged descriptors and reverse cleanup**

Write and retain separate AWS core and Job paths. Apply product, graph,
observability core/span, and AWS core during their existing staged lifecycle;
the S3 Job stays unapplied until Task 4's exact LocalStack-ready gate. Join all
mutation settlements before cleanup, re-prove every cluster, image,
descriptor, shared baseline, and root identity before deletion, and retain
the recovery root when global absence is unproved.

- [x] **Step 6: Run six focused passes and commit**

Run six AWS-emulator/product/graph/observability runtime passes, syntax,
ESLint, diff-check, and pinned secret scans. Commit the runtime and only the
narrow composition changes as:

```text
feat: prepare disposable local AWS emulator runtime
```

---

### Task 4: Prove internal LocalStack readiness and one S3 request

**Files:**
- Modify: `deploy/local/aws-emulator-run.test.mjs`
- Modify: `deploy/local/aws-emulator-run.mjs`

**Interfaces:**
- Produces: strict AWS provider normalization, exact LocalStack-ready gate,
  staged Job apply/completion, fixed S3 evidence, unchanged prior-provider
  snapshots, and reverse cleanup.
- Consumes: Task 2 exact resources and Task 3 retained image, cluster,
  descriptor, product, graph, and observability identities.

- [x] **Step 1: Write provider and lifecycle tests before implementation**

Require exact ConfigMap data/resource version; Deployment/ReplicaSet/pod
lineage; complete container image/security/resources/command/env/mount/status;
Service/EndpointSlice identity; absent external exposure; and an exact
Completed Job and Job pod. Cross-bind every UID, owner, node, image ID,
selector, endpoint target, condition, ConfigMap ref, start/finish time, and
container state.

Prove no S3 Job apply occurs before exact LocalStack S3 readiness. After the
gate, require exactly one Job apply, one endpoint argument, one list-buckets
command, exact completion marker, and unchanged product/graph/observability
snapshots. Reject Job recreation, provider retry, alternate endpoint, second
S3 call, provider output, or normalization before Job completion.

Cover duplicate/unknown/missing provider keys; extra/missing resources;
resource-version/UID/owner/selector/node/image/mount/endpoint/condition drift;
malformed timestamps; container restart; alternate Service peer; public
exposure; ConfigMap replacement; premature/failed/replaced Job; log drift;
and terminal controller state.

- [x] **Step 2: Witness lifecycle RED**

Run the new readiness, Job, S3, and orchestration tests before implementing
the provider path. Require failures only at absent AWS-emulator behavior;
product, graph, and observability provider tests remain green.

- [x] **Step 3: Implement bounded exact LocalStack readiness**

Apply the AWS core through its fresh descriptor. Read bounded raw Kubernetes
JSON with recursive duplicate-key rejection and poll within the main phase
until the ConfigMap, Deployment, ReplicaSet, pod, Service, and EndpointSlice
form one complete exact snapshot and the retained S3 readiness command is
successful. Re-prove every prior profile snapshot, PID authority, image
inventory, and descriptor before advancing.

- [x] **Step 4: Apply and prove the one-shot S3 Job**

Only after Step 3, journal one exact Job apply. Definitive rejection fails;
ambiguous outcomes reconcile through exact absence or exact-owned state. Poll
for one exact successful Job/pod and the fixed marker. Never recreate or retry
the Job and never issue the S3 request from the host.

- [x] **Step 5: Harden timeout, ambiguity, and cleanup cases**

Test delayed Deployment/EndpointSlice/Job state, thrown/signaled/malformed
apply and logs, main cancellation before and after Job apply, late-applied Job,
uncooperative child, provider panic, cleanup panic, resource replacement,
cleanup continuation and precedence, and global absence failure. Require
mutation settlement before cleanup and no late mutation after audit.

- [x] **Step 6: Run six focused passes and commit**

Run six combined AWS-emulator suites plus unchanged product, graph, and
observability regressions, syntax, ESLint, diff-check, and pinned secret scans.
Commit as:

```text
feat: prove local AWS emulator S3 endpoint
```

---

### Task 5: Expose the hermetic and live commands

**Files:**
- Modify: `package.json`
- Modify: `README.md`
- Modify: `app/quality/local-aws-emulator-manifest-contract.test.ts`

**Interfaces:**
- Produces: `local:aws-emulator:test`, `local:aws-emulator:run`, and
  `local:aws-emulator:license` root commands plus exact operator guidance.

- [x] **Step 1: Write root-command and documentation RED**

Require exact scripts, pinned Node usage, fixed output, staged Job semantics,
internal-only Service, ConfigMap endpoint keys, synthetic credentials, one S3
request, no product factory wiring, disposable ownership, license scope,
M1-30d In progress, and M1-30 Pending. Reject claims of ambient kubeconfig,
host LocalStack access, production AWS parity, persistent emulator state,
shared LocalStack mutation, or completed M1-31 behavior.

- [x] **Step 2: Add scripts and concise README guidance**

Add these exact scripts:

```json
"local:aws-emulator:test": "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs deploy/local/graph-manifest.test.mjs deploy/local/graph-run.test.mjs deploy/local/graph-license-audit.test.mjs deploy/local/observability-manifest.test.mjs deploy/local/observability-run.test.mjs deploy/local/observability-license-audit.test.mjs deploy/local/aws-emulator-manifest.test.mjs deploy/local/aws-emulator-run.test.mjs deploy/local/aws-emulator-license-audit.test.mjs",
"local:aws-emulator:run": "node deploy/local/aws-emulator-run.mjs",
"local:aws-emulator:license": "node deploy/local/aws-emulator-license-audit.mjs"
```

Document prerequisites, fixed output, internal Service, exact endpoint
ConfigMap, staged one-shot S3 Job, synthetic-only credentials, immutable image
and license scope, cleanup, and later M1-30/M1-31 boundaries.

- [x] **Step 3: Run focused, root, and full GREEN**

Run the contract, root AWS-emulator suite, license audit, original product,
graph, and observability suites, and full pinned repository verification. Run
production npm audit, dependency checks, whitespace, and secret scans.

- [x] **Step 4: Commit the command/documentation slice**

Commit only `package.json`, README, and the quality contract as:

```text
docs: expose local AWS emulator manifest proof
```

---

### Task 6: Run live proof, independent review, and completion

**Files:**
- Modify only in-scope files required by a witnessed tests-first live or review
  finding; runtime findings ordinarily remain under `deploy/local/`
- Modify completion status only after every implementation gate is green
- Update ignored reports and ledger under
  `.superpowers/sdd/2026-08-17-m1-30d-local-aws-emulator-manifest-implementation-plan/`

**Interfaces:**
- Produces: exact live LocalStack/S3/cleanup evidence, zero-finding independent
  review, M1-30d Complete transition, push, exact-SHA CI success, and checked
  plan closure.

- [x] **Step 1: Establish clean live preconditions**

Require zero M1-30d prefix/label resources and temporary roots. Fingerprint
shared Docker/Kubernetes state read-only. Confirm exact image/platform and
owned capacity without deleting a shared image, volume, container, network,
or cache.

- [x] **Step 2: Run the exact live command**

Run only:

```sh
env -i PATH="$HOME/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/usr/bin:/bin" \
  HOME="$HOME" LANG=C.UTF-8 npm run local:aws-emulator:run
```

Require exit zero and exactly:

```text
Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.
```

Require one exact S3 Job marker, unchanged product/graph/observability state,
zero exact-owned containers, networks, image aliases, cluster resources, and
temporary roots, with shared and ambient state unchanged.

- [x] **Step 3: Fix live findings only through TDD**

For each real mismatch, isolate the exact provider representation, write a
focused failing hermetic regression, implement the narrow fix, rerun every
affected gate, and rerun the exact lifecycle. Never weaken immutable image,
internal-only, one-request, endpoint, credential, prior-profile, output,
license, or cleanup requirements.

- [x] **Step 4: Run the final local gate matrix**

Require six AWS-emulator-suite passes; original product, graph, and
observability suites; all four product Go race/tidy/verify/vet gates; exact
graph, observability, and AWS-emulator license audits; full pinned repository
verify/typecheck/lint/build; production audit zero; dependency checks;
diff-check; and pinned redacted Gitleaks scans.

- [x] **Step 5: Obtain a zero-finding independent review**

Review the complete range against the source row, design, plan, M1-30a/b/c
compatibility, manifests, image/license evidence, production runtime, tests,
live evidence, cleanup, status arithmetic, and secret scans. Address every
Critical, Important, and Minor finding through a separate tests-first commit
and repeat review.

- [x] **Step 6: Transition M1-30d to Complete**

Write completion-contract RED, then change overall `658/1/66/3` to
`658/0/67/3` and M1 `68/25/1/42/0` to `68/25/0/43/0`. Move exactly one
M1-30d row from In progress to Complete. Preserve M1-30a/b/c Complete,
M1-30 Pending, and the exact blockers. Run focused and full gates, then commit:

```text
docs: complete M1-30d local AWS emulator manifest
```

- [x] **Step 7: Push completion and verify exact-SHA CI**

Push from a clean tracked tree and index, require equal local/origin/tracking
SHAs, and watch Runnable UI to terminal success for the exact completion SHA.
Record the run and job URLs in ignored evidence before closing the plan.

- [x] **Step 8: Close, push, and verify the plan**

Mark every plan checkbox complete only after completion CI succeeds. Commit
only this plan with:

```text
docs: close M1-30d local AWS emulator manifest plan
```

Push again, require exact-SHA Runnable UI success, then perform final SHA-sync,
status-arithmetic, blocker, Gitleaks, zero-residue, and clean-tree audits.
