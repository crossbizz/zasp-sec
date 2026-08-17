# M1-30b Local Graph Manifest Design

## Goal and boundary

M1-30b adds an opt-in local Neo4j service and persistent test-volume
configuration to the disposable local Kubernetes environment delivered by
M1-30a. The verification boundary proves that Neo4j becomes healthy, is
reachable through a `ClusterIP` Service from inside the cluster, has no host
or public workload exposure, and preserves one synthetic graph marker across
a pod replacement on the same bound claim.

M1-30a remains a complete, independently runnable four-product proof. This
task does not add observability, LocalStack, credentials, provider calls,
customer data, public ingress, NodePort or LoadBalancer Services, an ambient
Kubernetes dependency, or the final assembled `M1-30` start target. Those
remain M1-30c, M1-30d, and M1-30. M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Add a separate graph overlay and combined disposable runner (selected).**
   Keep the completed product manifest byte-exact, add a graph-only resource
   set, and compose both sets only in the M1-30b live command. This preserves
   the product-only contract while proving the real graph dependency.
2. **Fold Neo4j into the M1-30a manifest and runner.** This would make the four
   product stubs depend on a larger licensed runtime and rewrite a completed
   task's nine-resource boundary.
3. **Use a Neo4j Helm chart or operator.** This adds a broad unreviewed
   dependency and obscures the exact security, storage, image, and exposure
   projection required by the source task.
4. **Publish Neo4j on numeric loopback.** Loopback is safer than a wildcard
   host binding, but the source verification is stronger: graph health must be
   reachable only inside the local cluster, so no workload port is published.

The selected approach is additive, exact, cluster-internal, and removable
without touching an ambient Docker or Kubernetes resource.

## Repository layout

Add this tracked boundary under `deploy/local`:

```text
deploy/local/
  graph-manifest.mjs
  graph-manifest.test.mjs
  graph.yaml
  graph-run.mjs
  graph-run.test.mjs
  graph-licenses.json
  graph-license-audit.mjs
  graph-license-audit.test.mjs
```

The existing `manifests.mjs`, `product-stubs.yaml`, and product runner remain
the canonical M1-30a boundary. `graph-manifest.mjs` owns a separate structured
model, strict validator, parser, and deterministic renderer. `graph.yaml` is a
byte-exact rendering of that model. `graph-run.mjs` composes the already
reviewed product lifecycle with graph-specific image, node-storage,
Kubernetes-state, persistence, and cleanup checks; it does not accept a
caller-supplied manifest, image, path, namespace, command, or endpoint.

## Exact images and license boundary

Neo4j is pinned to the already verified immutable Community image:

```text
neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357
```

The internal health probe uses the already reviewed multi-platform BusyBox
index and exact selected-platform digest:

```text
registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9
```

The graph license inventory reuses and revalidates the immutable upstream
source/license evidence established by M1-16: Neo4j Community is
GPL-3.0-only, and BusyBox is GPL-2.0-only. Both are opt-in local development
targets. AgentSec does not embed, redistribute, sublicense, or approve either
server image for production packaging. Their bundled dependencies retain
their own terms. M1-30b is not a commercial Neo4j licensing decision.

## Exact Kubernetes resources

The graph overlay contains exactly five resources:

1. one cluster-scoped `PersistentVolume` named `zasp-local-neo4j`;
2. one `PersistentVolumeClaim` named `neo4j-data` in `zasp-local`;
3. one single-replica `Deployment` named `neo4j` in `zasp-local`;
4. one internal `ClusterIP` `Service` named `neo4j` in `zasp-local`; and
5. one one-shot `Job` named `neo4j-health` in `zasp-local`.

Every resource has exact `app.kubernetes.io/part-of=zasp`,
`app.kubernetes.io/component=graph`, and `zasp.dev/environment=local` labels.
Names, selectors, images, storage class, capacities, access mode, commands,
ports, probes, resources, and security settings are fixed.

The PV is one GiB, `ReadWriteOnce`, `Retain`, and uses the fixed local path
`/var/lib/zasp/m1-30b/neo4j-data` inside the disposable kind node. Its node
affinity requires the exact proof-only label `zasp.dev/graph-node=m1-30b`.
The runner applies and re-proves that label only on its retained node before
applying the graph overlay, so the byte-exact tracked manifest contains no
random node name and cannot bind elsewhere. The PVC names that PV directly,
uses the same capacity/access mode/storage class, and must be `Bound` to the
retained PV before Neo4j is accepted. The runner creates and owns the
node-local directory before applying the manifest and removes it only by
deleting the exact disposable node container with the cluster.

Neo4j runs as UID/GID 7474 with service-account token mounting disabled,
`RuntimeDefault` seccomp, no privilege escalation, no added capabilities, and
bounded CPU and memory. The disposable kind node uses an exact
`KubeletConfiguration` patch with `podPidsLimit: 512`; the runner re-proves
that exact active kubelet projection whenever it verifies the retained node,
so Neo4j and every other proof pod run inside the same per-pod PID bound. The
exact upstream entrypoint requires its
normal writable runtime projection; only `/data` is persistent and `/logs` is
an `emptyDir`. The container receives only these fixed synthetic settings:

```text
NEO4J_AUTH=none
NEO4J_db_tx__log_preallocate=false
NEO4J_db_tx__log_rotation_size=128K
```

No credential, proxy, cloud, Docker, Kubernetes, or customer value enters the
pod. HTTP 7474 and Bolt 7687 are container and Service ports only. The
manifest forbids `hostNetwork`, `hostPort`, Ingress, external IPs, NodePort,
and LoadBalancer exposure.

The health Job uses the exact BusyBox image, never restarts, mounts no volume,
and performs one fixed HTTP request to the in-cluster Service DNS name. It is
non-root, read-only, capability-free, service-account-token free, and
resource-bounded. Exact successful completion and its fixed log marker prove
cluster-internal reachability. No host-side request to either workload port is
used or possible.

## Persistence proof

Readiness alone does not prove that the PVC is the active data boundary. After
the Deployment, Service, EndpointSlice, PV, PVC, and health Job are exact and
healthy, the runner executes a fixed `cypher-shell` statement inside the
retained Neo4j pod to create one synthetic marker node. It then deletes only
that exact pod, waits for a new exact-owned pod UID from the same Deployment,
re-proves the PV/PVC binding and Service endpoint, and queries the marker.

The marker contains no customer or provider value. Its exact count of one
proves that `/data` survived pod replacement through the bound claim. The
entire volume still lives only inside the disposable kind node and disappears
when that exact cluster is deleted.

## Disposable lifecycle and provider evidence

`npm run local:graph:run` uses a random `zasp-m1-30b-<16-hex>` marker, an
owned Docker configuration, an owned kubeconfig, and one exact-pinned kind
cluster. It never reads the ambient kubeconfig/current context and never
targets an existing cluster.

The main lifecycle is:

1. prove prefix-wide absence for M1-30b temporary roots, proof labels,
   cluster/node/network names, and graph image aliases;
2. create the owned runtime root and M1-30a product images;
3. resolve Neo4j and BusyBox index/config/platform digests and retain their
   complete immutable image projections;
4. create and re-prove the disposable kind cluster, exact active
   `podPidsLimit: 512`, fixed proof-only node label, and node-local data path;
5. load the four product images plus the exact graph images into containerd
   and re-prove index/config/platform/rootfs identities;
6. apply the canonical product manifest and canonical graph overlay through
   fresh descriptors and only the owned kubeconfig;
7. prove the original four products Ready and their Services internal;
8. prove exact graph PV/PVC, Deployment, pod, Service, EndpointSlice, and Job
   state, including complete labels, owners, image IDs, security, ports,
   volumes, node affinity, endpoints, conditions, and absence of extra
   resources or exposure;
9. create the synthetic graph marker, replace the exact pod, and prove the
   marker and health again; and
10. join all mutation settlements, delete the exact cluster, remove only
    exact-owned local image aliases/IDs and runtime roots, and perform final
    global absence checks.

Kubernetes reads use bounded raw JSON with duplicate-key rejection. Expected
resources are cross-correlated by UID, owner UID, node name, image ID,
selector, endpoint target UID, PV/PVC binding, volume name, and pod UID. A
syntactically valid but incomplete provider projection is not evidence.

## Mutation, ownership, and timeout rules

Every filesystem, Docker, kind, node-directory, Kubernetes apply/delete, pod
delete, and Cypher mutation is single-attempt and journaled before its result
is interpreted. Definitive nonzero rejection is never adopted. Thrown,
signaled, timed-out, output-capped, malformed-success, or unexpected-success
results are ambiguous and enter an independently bounded exact post-state
read. Reads may retry twice with at most 500 ms between attempts.

Cleanup runs in reverse dependency order under an independent context, joins
all settlements before destructive work, re-proves exact immutable ownership
immediately before deletion, continues after failures, and gives cleanup
failure precedence. The owned recovery root remains when a live provider
resource cannot be proved absent. Replacement or extra resources are not
deleted.

The main phase is bounded to 720 seconds, cleanup to 240 seconds, and mutation
settlement to 60 seconds. Child processes are async-spawned with a combined
bounded output buffer, abort fencing, SIGKILL escalation, and reap/join. The
Node supervisor has at least a 60-second margin beyond the worst-case inner
phase sum.

## Fixed output and verification

Success emits exactly:

```text
Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.
```

Failure emits one fixed category from `configuration`, `build`, `provider`,
`readiness`, `normalization`, `ownership`, `cleanup`, `deadline`, or `panic`.
Raw filesystem, Docker, kind, Kubernetes, Neo4j, Cypher, image, and provider
text is never printed.

Hermetic tests cover the exact graph manifest, license inventory, image and
platform identity, node-local storage, descriptor-safe apply/read paths,
provider-state normalization, cluster-only exposure, persistence sequence,
definitive-versus-ambiguous mutations, replacement resources, delayed
application, cancellation, panic, cleanup continuation/precedence, and global
absence. The M1-30a product proof remains green unchanged.

Live verification runs only after hermetic gates pass. It requires the fixed
success line, exact internal health, one retained marker after pod replacement,
and zero M1-30b containers, networks, image aliases, node-volume paths, and
temporary roots. The ambient Docker/Kubernetes state is fingerprinted
read-only before and after and must remain unchanged and untargeted.

M1-30b starts at `660/1/64/3` overall and `68/27/1/40/0` for M1. Completion
changes those values to `660/0/65/3` and `68/27/0/41/0`. M1-30c remains
Pending.
