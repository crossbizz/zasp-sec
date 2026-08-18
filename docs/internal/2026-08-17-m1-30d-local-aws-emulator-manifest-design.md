# M1-30d Local AWS Emulator Manifest Design

## Goal and boundary

M1-30d adds an opt-in LocalStack S3 overlay to the disposable local
Kubernetes environment completed by M1-30a, M1-30b, and M1-30c. The proof
starts one exact-pinned LocalStack Community pod, exposes it only through an
internal ClusterIP Service, injects fixed local AWS endpoint environment
variables into one synthetic client Job, and proves that the Job completes an
S3 request through that endpoint. Success proves the local endpoint contract,
cluster-internal reachability, exact provider state, and cleanup.

The completed M1-30a product, M1-30b graph, and M1-30c observability profiles
remain independently runnable and byte-compatible. This task does not add an
AWS client to a product service, change the product AWS client factory, expose
LocalStack on the host, reuse a shared LocalStack container, persist emulated
AWS state, add IAM parity, or add the final assembled M1-30 start target.
Product client-factory wiring remains M1-31. The assembled target remains
M1-30. M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Add a separate LocalStack core overlay and staged S3 Job (selected).**
   The core contains an endpoint ConfigMap, one LocalStack Deployment, and one
   internal Service. After exact readiness, a one-shot Job reads the endpoint
   variables from the ConfigMap and makes one explicit S3 request. This proves
   the required boundary without changing product code before M1-31.
2. **Inject LocalStack endpoint variables into all four product Deployments.**
   No current product binary has the M1-31 client factory that consumes those
   values. Changing the M1-30a product bytes now would widen this task and
   create configuration with no product behavior to verify.
3. **Run a host-side LocalStack container and client.** This repeats the
   existing disposable Docker proofs and bypasses the Kubernetes manifest
   deliverable. It would also introduce host publication that the assembled
   local environment does not need.

The selected approach establishes one reusable endpoint contract. M1-31 can
consume the same names and values when it adds local-only product client
wiring, without retroactively changing what M1-30d proves.

## Repository layout and composition

Add this tracked boundary under `deploy/local`:

```text
deploy/local/
  aws-emulator-manifest.mjs
  aws-emulator-manifest.test.mjs
  aws-emulator.yaml
  aws-emulator-s3.yaml
  aws-emulator-image.mjs
  aws-emulator-run.mjs
  aws-emulator-run.test.mjs
  aws-emulator-licenses.json
  aws-emulator-license-audit.mjs
  aws-emulator-license-audit.test.mjs
```

`aws-emulator-manifest.mjs` owns the exact structured resource model, strict
validator, canonical parser, and deterministic renderers.
`aws-emulator.yaml` contains only the endpoint ConfigMap, LocalStack
Deployment, and Service. `aws-emulator-s3.yaml` contains only the staged S3
Job. The split is an execution-authority boundary, not a second resource
model.

`aws-emulator-run.mjs` composes the reviewed observability lifecycle with
LocalStack-specific image loading, provider normalization, staged S3
verification, and cleanup. It does not accept a caller-supplied manifest,
image, endpoint, credential, namespace, command, object, output path, or
cluster target.

The shared local runner gains one exact `m1-30d` profile containing the graph,
observability-core, observability-span, AWS-emulator-core, and S3 Job manifests
in fixed order. The M1-30a, M1-30b, and M1-30c profile bytes and provider traces
remain unchanged. The new profile retains the exact graph and observability
state while it proves the AWS overlay.

## Exact image and license boundary

Both the LocalStack Deployment and the client Job use the exact Community
image already proven by the repository:

```text
localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c
```

The image planner binds the immutable index, selected linux/amd64 or
linux/arm64 manifest, config, layers, runtime metadata, and node-local image
identity before Kubernetes apply. A pre-existing exact image is treated as a
read-only shared baseline. Only proof-created aliases or image identities may
be removed, after exact consumer and ownership reproof.

The AWS-emulator license inventory binds LocalStack Community `v4.7.0`, the
annotated tag object, source commit, Apache-2.0 license, Community supplemental
terms, source manifest, and exact image metadata. Bundled third-party
components retain their own terms and are not relicensed. The inventory
cross-references existing repository evidence but remains independently
strict and executable for this deploy boundary.

## Exact Kubernetes resources

The AWS-emulator core contains exactly three namespaced resources in
`zasp-local`:

1. one `ConfigMap` named `local-aws-endpoints`;
2. one single-replica `Deployment` named `localstack`; and
3. one internal `ClusterIP` `Service` named `localstack`.

The staged manifest contains exactly one `Job` named `localstack-s3-probe`.
Every resource has exact `app.kubernetes.io/part-of=zasp`,
`app.kubernetes.io/component=aws-emulator`, and
`zasp.dev/environment=local` labels. Workload labels additionally bind either
the server or S3 client role.

The endpoint ConfigMap contains exactly:

```text
AWS_ENDPOINT_URL=http://localstack.zasp-local.svc.cluster.local:4566
AWS_ENDPOINT_URL_S3=http://localstack.zasp-local.svc.cluster.local:4566
```

These are synthetic local endpoints, not credentials. The ConfigMap has no
region, account, profile, proxy, host address, public URL, or caller-controlled
value.

The LocalStack Deployment enables only S3 and disables persistence. It has no
Docker socket, host path, host network, host port, service-account token,
cloud credential, proxy, TLS key, customer value, or public ingress. Writable
state is confined to bounded `emptyDir` volumes required by the exact image.
The pod is single-replica, resource- and PID-bounded through the inherited
kind profile, capability-free, non-privileged, and covered by
`RuntimeDefault` seccomp. Any image-required user or writable-root exception
must be exact, documented, and proven by the live compatibility gate rather
than silently weakened.

The Service exposes only TCP 4566 inside the single-stack cluster. It has no
NodePort, LoadBalancer, external IP, host publication, or dashboard port. Its
selector and EndpointSlice are cross-bound to the exact LocalStack pod.

## Readiness and the S3 endpoint proof

LocalStack readiness is an exact S3 capability boundary, not a shallow TCP
accept. The Deployment readiness command performs a bounded S3 list operation
against `http://127.0.0.1:4566`. The runner waits for the exact Deployment,
pod, Service, and EndpointSlice state before it creates the test Job.

The Job imports `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` only from the
exact ConfigMap keys. It also receives fixed synthetic local values for
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`,
`AWS_DEFAULT_REGION`, and `AWS_EC2_METADATA_DISABLED`. It receives no token,
session credential, profile, role, web-identity file, proxy, dotenv value,
ambient host environment, or Kubernetes API credential.

The Job overrides the image entrypoint with one fixed shell command. It calls
the image-owned AWS wrapper with an explicit `--endpoint-url
"$AWS_ENDPOINT_URL_S3"`, performs `s3api list-buckets`, and requires an exact
zero-bucket result from the newly created in-memory service. The provider
response and endpoint are never printed. On success, it emits only:

```text
localstack-s3-endpoint-ready
```

The runner proves exact Job completion, pod ownership, ConfigMap references,
environment keys, command, image identity, timestamps, and the fixed log. A
Job created concurrently with LocalStack startup, a retrying mutation, an
alternate endpoint, a host endpoint, a credential source, an extra S3 result,
or a nonempty provider log is rejected.

## Disposable lifecycle and provider evidence

`npm run local:aws-emulator:run` uses one random
`zasp-m1-30d-<16-lowercase-hex>` marker, an owned Docker configuration, an
owned kubeconfig, and one exact-pinned kind cluster. It never reads the
ambient kubeconfig or current context and never targets a shared Kubernetes
or LocalStack instance.

The main lifecycle is:

1. prove prefix-wide absence for M1-30d roots, labels, cluster/node/network
   names, node-local aliases, and retained provider state;
2. create the exact-owned runtime root and the four unchanged M1-30a product
   images;
3. resolve and re-prove graph, BusyBox, Collector, and LocalStack image
   identities without mutating pre-existing shared images;
4. create and re-prove the disposable kind cluster, exact active
   `podPidsLimit: 512`, graph node label, and graph data path;
5. load the existing product, graph, observability, and LocalStack images,
   retaining every complete before/after containerd inventory and required
   node-local alias;
6. apply the canonical product, graph, observability-core, and AWS-emulator
   core manifests through fresh descriptors and only the owned kubeconfig;
7. prove the four products Ready, graph health and persistence, one exact
   observability span, and exact LocalStack S3 readiness;
8. only after the core is exact and Ready, apply the canonical S3 Job and
   prove its single endpoint-bound request and fixed completion marker;
9. re-prove the product, graph, observability, and LocalStack provider
   snapshots did not change unexpectedly; and
10. join mutation settlements, delete the exact cluster, remove only
    exact-owned aliases, image identities, and runtime roots, then prove final
    global absence.

Kubernetes reads use bounded raw JSON with recursive duplicate-key rejection.
Resources are cross-correlated by UID, owner UID, node, pod, container, image
ID, Service selector, EndpointSlice target, ConfigMap resource version, Job
controller UID, and exact timestamps. A syntactically valid but incomplete
provider projection is not evidence.

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

The main phase is bounded to 1,080 seconds, cleanup to 360 seconds, and
mutation settlement to 60 seconds. Child processes use async spawn, one
combined bounded output buffer, abort fencing, SIGKILL escalation, and
reap/join. Public output never includes an endpoint, port, credential,
provider response, bucket, resource identifier, path, or artifact body.

Success emits exactly:

```text
Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.
```

Failure emits one fixed category from `build`, `cleanup`, `configuration`,
`deadline`, `normalization`, `ownership`, `panic`, `provider`, or `readiness`.

## Verification and status boundary

Hermetic tests cover exact manifest and Job bytes, endpoint and credential
allowlists, license inventory, image and platform identity, profile isolation,
provider-state normalization, internal-only exposure, staged Job ordering,
the explicit endpoint argument, fixed output, definitive-versus-ambiguous
mutations, replacement resources, delayed application, cancellation, panic,
cleanup continuation and precedence, and global absence. The unchanged
M1-30a, M1-30b, and M1-30c suites remain green.

Live verification runs only after hermetic gates pass. It requires the fixed
success line, the exact S3 Job marker, unchanged product, graph, and
observability provider state, zero M1-30d containers, networks, image aliases,
temporary roots, or cluster state, and unchanged ambient and shared
fingerprints.

M1-30d starts by changing overall status from `659/0/66/3` to
`658/1/66/3`, and M1 from `68/26/0/42/0` to `68/25/1/42/0`. Completion changes
those values to `658/0/67/3` and `68/25/0/43/0`. M1-30 remains Pending until
its separate assembled-target verification succeeds.
