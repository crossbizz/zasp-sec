# M1-30a Local Product Manifests Design

## Goal and boundary

M1-30a adds the first local Kubernetes deployment boundary for the four
existing Go product commands: `agentsec-api`, `agentsec-worker`,
`event-ingest`, and `runtime-gateway`. The repository gains one exact manifest
set, one dependency-free runtime image recipe, and one bounded disposable
verification harness that proves all four product pods become Ready.

This task does not add Neo4j, OpenTelemetry Collector, LocalStack, credentials,
provider calls, customer data, public ingress, NodePort or LoadBalancer
services, persistent volumes, or a long-running assembled developer target.
Those remain M1-30b through M1-30. M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Run the real Go commands in a disposable kind cluster (selected).** Build
   static binaries from the reviewed repository commands, package them in
   `scratch` images, load those images into an exact-pinned one-node cluster,
   and apply the tracked manifests. This proves the actual service listeners,
   probes, pod policy, and Kubernetes wiring without a registry or shared
   cluster.
2. **Deploy shell or BusyBox placeholder pods.** This would be faster but would
   not prove that the four product commands start or satisfy the shared health
   contract. It would turn the deliverable's "stubs" wording into a substitute
   runtime rather than deploy the existing stubs.
3. **Apply directly to the ambient OrbStack context.** This is familiar for a
   developer, but the current context is unavailable and is shared mutable
   state. It cannot provide exact ownership, isolation, or cleanup evidence.

The selected approach is local, reproducible, product-real, and independent of
ambient Kubernetes state.

## Repository layout

Add the following tracked boundary under `deploy/local`:

```text
deploy/local/
  Dockerfile
  product-stubs.yaml
  manifests.mjs
  manifests.test.mjs
  run.mjs
  run.test.mjs
```

`manifests.mjs` is the authoritative structured model and strict validator.
`product-stubs.yaml` is the canonical human-usable rendering of that model.
Tests parse the YAML with the existing direct `js-yaml` development dependency,
reject duplicate or unknown structure, validate every security and probe
invariant, and require a byte-exact re-render. The runner never accepts a
caller-supplied manifest or image definition.

`Dockerfile` is a single dependency-free runtime recipe:

```dockerfile
FROM scratch
ARG BINARY
COPY --chown=65532:65532 ${BINARY} /service
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/service"]
```

The runner compiles each command on the host with `CGO_ENABLED=0`, `GOENV=off`,
`GOWORK=off`, `-trimpath`, and an exact `m1-30a` build version. Only the binary
enters an owned temporary Docker build context. No compiler, source tree,
shell, package manager, CA bundle, or credential enters a runtime image.

## Exact Kubernetes resources

The tracked manifest contains one `Namespace`, four `Deployment` objects, and
four internal `ClusterIP` `Service` objects. Names and images are exact:

| Component | Deployment and Service | Image |
| --- | --- | --- |
| API | `agentsec-api` | `zasp-local/agentsec-api:m1-30a` |
| Worker | `agentsec-worker` | `zasp-local/agentsec-worker:m1-30a` |
| Ingest | `event-ingest` | `zasp-local/event-ingest:m1-30a` |
| Gateway | `runtime-gateway` | `zasp-local/runtime-gateway:m1-30a` |

All namespaced objects live in `zasp-local`. Every object carries
`app.kubernetes.io/part-of=zasp` and `zasp.dev/environment=local`. Component
selectors contain only the exact component label so one service cannot select
another pod.

Each Deployment has one replica and one container. It exposes only named
container port `health` on 8081, uses `imagePullPolicy: Never`, and declares no
environment variables, environment sources, command, arguments, volume,
volume mount, host namespace, host alias, affinity, toleration, or external
endpoint. Service port 8081 targets the named `health` port and remains
cluster-internal.

Every pod disables service-account token mounting and uses the default
cluster-only DNS policy. Pod and container security are exact:

- `runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, and
  `fsGroup: 65532`;
- `seccompProfile.type: RuntimeDefault`;
- `allowPrivilegeEscalation: false`;
- `readOnlyRootFilesystem: true`;
- `capabilities.drop: [ALL]`;
- no added capabilities or privileged mode.

Each container requests 10m CPU and 16Mi memory and is limited to 100m CPU and
64Mi memory. The startup probe calls `/healthz`; liveness calls `/healthz`; and
readiness calls `/readyz`, all by HTTP on the named `health` port with exact
short periods and one-second timeouts. The commands initialize readiness before
serving, so successful readiness proves the actual shared health handler.

## Disposable verification lifecycle

The root live command invokes `deploy/local/run.mjs`. It accepts no arguments
or environment configuration beyond an allowlisted `PATH`, `HOME`, locale, and
owned cache roots. It refuses proxy, Docker-host override, Kubernetes,
credential, cloud-profile, and provider environment variables. It never reads
the ambient kubeconfig or current context.

The runner creates a random `zasp-m1-30a-<16-hex>` marker and an exact-owned
temporary directory. It downloads the existing reviewed kind v0.32.0 binary
for the current supported host platform and verifies its pinned SHA-256. It
uses the existing exact kind node v1.35.5 digest and writes an owned kubeconfig
inside the temporary root. The kind API server binds only numeric loopback.

The main lifecycle is:

1. prove global absence for the exact cluster/container prefix and all four
   local image references;
2. compile the four static binaries into separate owned contexts;
3. build four `scratch` images with exact proof/run labels and retain their
   immutable image IDs;
4. create one exact-named kind cluster and re-prove its node container, image,
   loopback API binding, labels, network, and kubeconfig ownership;
5. load each retained image ID through kind and verify it is present on the
   node without a registry pull;
6. apply the canonical manifest through only the owned kubeconfig;
7. wait for exactly four product Deployments and exactly four product pods,
   then require each pod Running, Ready, restart count zero, exact image ID,
   exact service-account/security/probe projection, and its Deployment
   Available with one ready replica;
8. require exactly four internal Services and no Ingress, NodePort,
   LoadBalancer, external IP, or host-port exposure;
9. delete the exact cluster, re-prove the retained node and network absent,
   remove only the four retained image IDs after exact label/reference reproof,
   remove the owned temporary root after identity reproof, and perform a final
   prefix-wide absence audit.

The success line is fixed and contains no generated name or provider output:

```text
Local product manifests passed: pods=4 ready=4 services=4 internal=true cleanup=true.
```

Failures emit one fixed category from `configuration`, `build`, `provider`,
`readiness`, `ownership`, `cleanup`, `deadline`, or `panic`. Raw subprocess,
Docker, Kubernetes, filesystem, network, and provider text is never printed.

## Ownership, ambiguity, and cleanup

Every filesystem, image, container, network, and cluster mutation is
single-attempt and journaled before its result is interpreted. A definitive
nonzero provider rejection is not reconciled or adopted. A thrown, signaled,
timed-out, output-capped, malformed-success, or unexpected-success result is
ambiguous and may be reconciled only by exact retained name, immutable ID,
proof label, run label, image/config projection, and independently bounded
reads.

Reads are bounded and may retry twice with at most 500ms between attempts.
Cleanup runs in reverse dependency order under an independent context, joins
all mutation settlements before deletion, re-proves ownership immediately
before each destructive action, continues after each cleanup failure, and
gives cleanup failure precedence. An unproved candidate is retained and the
owned recovery root is not deleted. Cleanup never targets the ambient
OrbStack cluster, an unlabelled image, a name-only Docker resource, or a
resource whose immutable identity changed.

The Node supervisor bounds the main phase to 600 seconds and cleanup to 180
seconds, with a 60-second settlement margin. Every child is async-spawned with
a shared stdout/stderr cap, abort fencing, SIGKILL escalation, and reap/join.
Temporary path admission records canonical parent, path, device, and inode;
the same identity is required immediately before removal.

## Verification and completion

Hermetic tests use injected filesystem, process, Docker, kind, and Kubernetes
boundaries. They cover exact resource rendering, hostile manifest mutations,
image build arguments, environment allowlists, deadline and output limits,
definitive-versus-ambiguous mutation handling, replacement resources,
partial creation, delayed application, panic/cancellation, reverse cleanup,
cleanup precedence, and global prefix absence.

Live verification runs only after all hermetic gates pass. It must produce the
fixed success line, prove exactly four Ready product pods and four internal
services, and finish with zero exact-owned clusters, node containers, networks,
images, and temporary roots. The shared OrbStack context is fingerprinted
read-only before and after and must remain unchanged and untargeted.

Completion requires tests-only RED, six hermetic passes, all four Go race
suites, module tidy-diff/verify/vet, exact live readiness and cleanup, full
pinned repository verification, production audit, whitespace and secret
scans, zero-finding independent review, push, and exact-SHA Runnable UI
success.

M1-30a starts at `661/1/63/3` overall and `68/28/1/39/0` for M1. Completion
changes those values to `661/0/64/3` and `68/28/0/40/0`. M1-30b remains
Pending.
