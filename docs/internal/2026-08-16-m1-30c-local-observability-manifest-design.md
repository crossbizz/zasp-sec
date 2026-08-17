# M1-30c Local Observability Manifest Design

## Goal and boundary

M1-30c adds an opt-in OpenTelemetry Collector overlay to the disposable local
Kubernetes environment completed by M1-30a and M1-30b. The proof sends one
fixed synthetic OTLP/HTTP trace from an in-cluster Job, accepts it through an
exact-pinned Collector, and reads it back from a local file-backed test sink.
Success proves one span, the exact product observability resource boundary,
cluster-internal reachability, a Collector pipeline with no network exporter,
and exact cleanup.

M1-30a remains a complete, independently runnable four-product proof, and
M1-30b remains a complete graph overlay and persistence proof. Their tracked
manifests, default commands, fixed output, and provider traces remain
compatible. This task does not add application SDK wiring, remote telemetry,
Grafana Cloud, New Relic, credentials, LocalStack, customer data, public
ingress, a host workload port, or the final assembled M1-30 target. Those
remain later tasks. M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Add a separate Collector overlay with a file-backed test sink
   (selected).** The Collector receives OTLP/HTTP inside the cluster and writes
   one bounded artifact to an `emptyDir`. A read-only BusyBox sidecar exposes
   the artifact only through the proof-owned Kubernetes exec boundary. This
   reuses the real Collector and file-exporter behavior already established by
   M0-13 without introducing a remote endpoint.
2. **Use the Collector `debug` exporter and parse pod logs.** This removes the
   shared `emptyDir`, but the debug exporter's human-oriented log projection is
   less stable and mixes provider logging metadata with the span evidence.
3. **Publish OTLP to loopback and inspect a host-side sink.** A loopback port
   would be bounded, but it would weaken the source task's local-cluster
   boundary and repeat M0-13 rather than proving the assembled Kubernetes
   overlay.

The selected approach is additive, deterministic, and local. “No egress” is
an exact Collector-pipeline claim: the configuration contains only a local
file exporter and no remote exporter, destination, credential, proxy, or
backend. It is not presented as a general pod firewall. Adding a Kubernetes
`NetworkPolicy` without installing and proving a policy-capable CNI would
create a false enforcement claim, so this task does not do that.

## Repository layout and composition

Add this tracked boundary under `deploy/local`:

```text
deploy/local/
  observability-manifest.mjs
  observability-manifest.test.mjs
  observability.yaml
  observability-span.yaml
  observability-run.mjs
  observability-run.test.mjs
  observability-licenses.json
  observability-license-audit.mjs
  observability-license-audit.test.mjs
```

`observability-manifest.mjs` owns the exact structured resource model, strict
validator, canonical parser, and deterministic renderers. `observability.yaml`
contains the ConfigMap, Deployment, and Service; `observability-span.yaml`
contains only the Job. This split is an execution-authority boundary, not a
second resource model. `observability-run.mjs` composes the reviewed
product and graph lifecycles with observability-specific image loading,
provider normalization, span submission, sink validation, and cleanup. It
does not accept a caller-supplied manifest, image, fixture, namespace,
endpoint, command, or output path.

The shared local runner gains one exact `m1-30c` profile containing the graph,
observability-core, and test-span manifests in fixed order. The default
M1-30a profile and the M1-30b profile remain byte- and behavior-compatible.
Both graph-bearing profiles retain the exact `podPidsLimit: 512` kubelet
authority; M1-30a does not. Product readiness, graph readiness, and
observability readiness use profile-specific selectors so an additive
resource cannot change an earlier task's expected counts or provider
projection.

## Exact images and license boundary

The Collector uses the immutable multi-platform image already proven by M0-13
and M0-22:

```text
otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5
```

The span Job and sink reader reuse the exact BusyBox image already pinned and
loaded by M1-30b:

```text
registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9
```

The observability license inventory binds the Collector Contrib `v0.158.0`
source and Apache-2.0 license to the exact image revision and platform
artifacts. It cross-references, but does not duplicate or weaken, M1-30b's
BusyBox GPL-2.0-only evidence. Both images remain opt-in local development
dependencies. AgentSec does not embed credentials or approve an external
telemetry backend through this task.

## Exact Kubernetes resources

The observability overlay contains exactly four namespaced resources in
`zasp-local`:

1. one `ConfigMap` named `otel-collector-config`;
2. one single-replica `Deployment` named `otel-collector`;
3. one internal `ClusterIP` `Service` named `otel-collector`; and
4. one one-shot `Job` named `otel-test-span`.

Every resource has exact `app.kubernetes.io/part-of=zasp`,
`app.kubernetes.io/component=observability`, and
`zasp.dev/environment=local` labels. Workload labels additionally bind the
Collector or span-generator role. Names, selectors, configuration keys,
images, commands, ports, probes, resources, mounts, and security settings are
fixed.

The ConfigMap contains exactly three UTF-8 values:

- `config.yaml`, the canonical Collector configuration;
- `span.json`, the canonical synthetic OTLP/HTTP request; and
- `response.json`, the exact successful OTLP response
  `{"partialSuccess":{}}`.

The Collector Deployment has two containers. `otel-collector` runs the pinned
Collector with only the mounted configuration, a writable local sink
`emptyDir`, and a bounded writable `/tmp`. `sink-reader` runs pinned BusyBox,
mounts the sink read-only, and waits without opening a listener. Both are
non-root, capability-free, non-privileged, service-account-token free,
resource-bounded, and covered by `RuntimeDefault` seccomp. The pod has no host
network, host ports, host paths, secrets, projected credentials, cloud values,
proxy values, or customer values.

The Collector listens on container port 4318 for OTLP/HTTP and on 13133 for
an unpublished cluster-internal pod health endpoint. The Service exposes only
4318 inside the cluster. It is single-stack `ClusterIP` with no external IP,
NodePort, LoadBalancer, Ingress, or host publication. Startup, readiness, and
liveness checks use only that unpublished health endpoint; the design does
not claim that a `0.0.0.0` listener is loopback-only.

The Job mounts only the fixed span and expected response, plus a bounded
`emptyDir` at `/tmp`. It uses BusyBox `wget` to POST once to
`http://otel-collector.zasp-local.svc.cluster.local:4318/v1/traces`, writes the
response to `/tmp`, compares the exact bytes, and emits one fixed success
marker. It is non-root, read-only, capability-free, service-account-token
free, and resource-bounded. The Job has no credential, provider, proxy, or
caller-controlled input.

## Collector configuration and no-egress sink

The Collector configuration enables exactly:

- one OTLP receiver with only the HTTP protocol on `0.0.0.0:4318`;
- one `health_check` extension on `0.0.0.0:13133`;
- a memory limiter below the pod memory limit;
- a batch processor with one-span batch and fixed flush bounds; and
- one file exporter writing a single JSON artifact under the shared local
  sink volume.

The service has one traces pipeline in the exact order receiver, memory
limiter, batch, and file exporter. Internal Collector logs are error-only and
Collector metrics are disabled. The configuration contains no OTLP exporter,
HTTP exporter, Kafka, cloud backend, DNS destination, authorization header,
TLS secret, environment expansion, proxy, retry queue, extension other than
local health, or arbitrary include.

The local artifact is not a product database or retention policy. It exists
only in the disposable pod `emptyDir`, is capped at 64 KiB, and disappears
with the exact-owned cluster.

## Synthetic span and validation

The request contains exactly one trace and one span. Its seven ordered
resource attributes match the M1-21 product observability contract:

1. `service.namespace = agentsec`
2. `service.name = agentsec-api`
3. `service.version = m1-30c`
4. `deployment.environment.name = development`
5. `organization.id = pid_10000000-0000-4000-8000-000000000001`
6. `workspace.id = pid_20000000-0000-4000-8000-000000000002`
7. `environment.id = pid_30000000-0000-4000-8000-000000000003`

The trace ID, span ID, start and end nanoseconds, scope name and version, span
name, kind, flags, and status are fixed synthetic values. The request contains
no events, links, baggage, log records, metrics, raw prompts, responses, tool
arguments, evidence, secret material, provider data, stack traces, URLs, or
free-form customer labels.

Collector acceptance is not success. The runner waits for exact Job
completion, reads the sink artifact only through the exact retained
`sink-reader` container, caps combined provider output, and rejects an empty,
oversized, malformed, duplicate-key, multi-trace, multi-span, unknown-field,
reordered-identity, or semantically different artifact. The normalized result
must contain one exact trace, one exact span, all seven resource attributes,
and the original trace/span identity.

## Disposable lifecycle and provider evidence

`npm run local:observability:run` uses one random
`zasp-m1-30c-<16-lowercase-hex>` marker, an owned Docker configuration, an
owned kubeconfig, and one exact-pinned kind cluster. It never reads the ambient
kubeconfig or current context and never targets an existing cluster.

The main lifecycle is:

1. prove prefix-wide absence for M1-30c roots, labels, cluster/node/network
   names, local image aliases, and retained provider state;
2. create the exact-owned runtime root and the four M1-30a product images;
3. resolve and re-prove the graph, BusyBox, and Collector index/config/platform
   identities without mutating a pre-existing shared image;
4. create and re-prove the disposable kind cluster, exact active
   `podPidsLimit: 512`, graph node label, and graph data path;
5. load the four product images and exact graph/Collector platforms into the
   retained node, retaining the complete before/after containerd inventory and
   any required node-local aliases;
6. apply the canonical product, graph, and observability-core manifests
   through fresh descriptors and only the owned kubeconfig;
7. prove the four original products Ready, graph internal health and
   persistence, and the exact observability ConfigMap, Deployment, ReplicaSet,
   pod, Service, and EndpointSlice;
8. only after the Collector pod and EndpointSlice are exact and Ready, apply
   the canonical one-Job test-span manifest through a fresh descriptor, prove
   its exact completion, and prove one exact span reached and normalized from
   the file-backed local sink. The Job performs exactly one trace POST; it is
   never created concurrently with Collector startup;
9. re-prove the product and graph provider snapshots did not change while the
   observability proof ran; and
10. join mutation settlements, delete the exact cluster, remove only
    exact-owned image aliases/IDs and runtime roots, and prove final global
    absence.

Kubernetes reads use bounded raw JSON with recursive duplicate-key rejection.
Expected resources are cross-correlated by UID, owner UID, node, pod,
container, image ID, Service selector, EndpointSlice target, ConfigMap resource
version, Job controller UID, and exact completed timestamps. A syntactically
valid but incomplete provider projection is not evidence.

## Mutation, ownership, deadlines, and output

Every filesystem, Docker, kind, Kubernetes apply/delete, image load/tag, Job,
and exec boundary is single-attempt and journaled before interpretation.
Definitive nonzero rejection is never adopted. Thrown, signaled, timed-out,
output-capped, malformed-success, or unexpected-success results are ambiguous
and enter an independently bounded exact post-state read. Reads may retry
twice with at most 500 ms between attempts.

Cleanup runs in reverse dependency order under an independent context, joins
all settlements before destructive work, re-proves exact immutable ownership
immediately before deletion, continues after failures, and gives cleanup
failure precedence. The recovery root remains when a live provider resource
cannot be proved absent. Replacement or extra resources are not deleted.

The main phase is bounded to 900 seconds, cleanup to 300 seconds, and mutation
settlement to 60 seconds. Child processes use async spawn, one combined bounded
output buffer, abort fencing, SIGKILL escalation, and reap/join. Public output
never includes a trace, span, endpoint, port, path, provider response, or
artifact body.

Success emits exactly:

```text
Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.
```

Failure emits one fixed category from `build`, `cleanup`, `configuration`,
`deadline`, `normalization`, `ownership`, `panic`, `provider`, or `readiness`.

## Verification and status boundary

Hermetic tests cover the exact manifest/configuration/fixture bytes, license
inventory, image and platform identity, profile isolation, provider-state
normalization, cluster-only exposure, no-network-export configuration, exact
span submission and sink parsing, definitive-versus-ambiguous mutations,
replacement resources, delayed application, cancellation, panic, cleanup
continuation/precedence, and global absence. M1-30a and M1-30b remain green
unchanged.

Live verification runs only after hermetic gates pass. It requires the fixed
success line, one exact normalized span in the local sink, unchanged product
and graph provider state, zero M1-30c containers, networks, image aliases,
temporary roots, or cluster state, and unchanged ambient/shared fingerprints.

M1-30c starts by changing overall status from `660/0/65/3` to
`659/1/65/3`, and M1 from `68/27/0/41/0` to `68/26/1/41/0`. Completion changes
those values to `659/0/66/3` and `68/26/0/42/0`. M1-30d remains Pending.
