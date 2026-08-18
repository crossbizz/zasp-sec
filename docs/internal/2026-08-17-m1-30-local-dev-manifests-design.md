# M1-30 Local Development Manifests Design

## Goal and boundary

M1-30 adds one canonical repository-root start target for the local environment
assembled by M1-30a, M1-30b, M1-30c, and M1-30d. The target starts the exact
product, graph, observability, and LocalStack S3 profile in one disposable kind
cluster, proves every completed profile, proves that no vendor dashboard is
published outside the cluster, and performs the reviewed reverse cleanup.

The completed profile manifests, images, license inventories, provider
normalizers, mutation rules, deadlines, output, and cleanup behavior remain
unchanged. M1-30 introduces no product AWS client, queue, bucket, OpenSearch
template, credential, public ingress, host workload port, persistent developer
cluster, or new provider. Product AWS endpoint consumption remains M1-31.
M0-09, M0-18, and M0-19 remain Blocked.

## Considered approaches

1. **Add a thin canonical start target over the reviewed M1-30d lifecycle
   (selected).** `npm run local:start` invokes one small module that validates
   the complete assembly contract and delegates to the exact M1-30d runtime.
   This produces one cluster and one proof lifecycle without copying ownership
   or provider code.
2. **Copy the M1-30d runtime into a new M1-30 runtime.** This would create a
   second implementation of the same manifests, image preparation, provider
   normalization, deadlines, and cleanup. The copies could drift while both
   appeared green, so this approach is rejected.
3. **Chain the four existing live commands from a shell script.** That would
   create four separate disposable clusters rather than one assembled local
   environment. It would also repeat builds, pulls, provider calls, and
   cleanup without proving simultaneous composition, so this approach is
   rejected.

The selected target is intentionally a start-and-verify command. It does not
leave a mutable cluster running after success. A persistent operator-managed
environment would require a separate ownership, restart, upgrade, and teardown
design and is not implied by this microtask.

## Repository surface and target identity

Add two tracked files under `deploy/local`:

```text
deploy/local/
  start.mjs
  start.test.mjs
```

Add one root script:

```json
"local:start": "node deploy/local/start.mjs"
```

`start.mjs` exports `LOCAL_START_TARGET`, `projectLocalStartExposure(value)`,
`validateLocalStartAssembly()`, and `runLocalStartMain()`. `LOCAL_START_TARGET`
is an immutable, caller-independent descriptor that binds:

- the root command `npm run local:start`;
- the implementation entrypoint `node deploy/local/start.mjs`;
- the exact delegated profile `m1-30d`;
- the completed dependency sequence `m1-30a`, `m1-30b`, `m1-30c`, and
  `m1-30d`;
- the six canonical manifest files in their reviewed apply order; and
- the exact existing M1-30d success line and failure categories.

The descriptor accepts no caller input. It is deeply frozen and validated
through exact data-property, key, order, value, and prototype checks. Accessor,
prototype, duplicate, reordered, extra, or alternate target state fails before
provider mutation.

## Exact assembly and exposure proof

`projectLocalStartExposure(value)` accepts a testable resource projection only
through strict plain-array, plain-object, data-property, and primitive-value
checks. It rejects accessors, prototypes, symbols, aliases, cycles, and caller
coercion before counting external exposure. `validateLocalStartAssembly()`
builds fresh resources only through the reviewed M1-30a, M1-30b, M1-30c, and
M1-30d manifest builders, feeds those fixed values to the projector, and
requires the exact zero-exposure result. The runtime does not accept a caller-
provided manifest or projection.

The assembled set is exactly:

- four product Deployments and four product ClusterIP Services;
- one graph PersistentVolume, PersistentVolumeClaim, Deployment, ClusterIP
  Service, and staged health Job;
- one observability ConfigMap, Deployment, ClusterIP Service, and staged span
  Job;
- one AWS endpoint ConfigMap, LocalStack Deployment, ClusterIP Service, and
  staged S3 Job; and
- the existing namespace and no additional Kubernetes object.

“Without vendor dashboards exposed” is an external exposure invariant. The
assembly may retain cluster-internal HTTP health surfaces already required by
the reviewed graph, observability, and LocalStack proofs, but it contains:

- zero `Ingress` resources;
- zero `NodePort`, `LoadBalancer`, or `ExternalName` Services;
- zero `externalIPs`, `loadBalancerIP`, or external traffic policy settings;
- zero pod `hostNetwork`, `hostPID`, or `hostIPC` authority;
- zero container `hostPort` fields;
- zero host-path volumes or Docker socket mounts; and
- zero Docker-published ports on the exact kind node.

All Services remain exact `ClusterIP` resources inside the disposable cluster.
The proof does not claim that an internal vendor HTTP endpoint has no UI code;
it proves that no such endpoint is published to the host or an external
network.

## Runtime delegation and output

`runLocalStartMain(runtime, options)` performs the pure assembly validation and
then calls `runAwsEmulatorMain(runtime, options)` exactly once. It does not
spawn another npm process, invoke any earlier profile command, construct a
second runtime, read environment variables, translate provider output, or add
a second cleanup path.

The default call therefore uses the existing `DockerKindAwsEmulatorRuntime`,
its owned Docker configuration and kubeconfig, one random M1-30d marker, one
disposable kind cluster, and the exact main, settlement, and cleanup bounds.
Injected runtime and output objects exist only for hermetic tests and are
passed unchanged to the reviewed delegate.

Success remains exactly:

```text
Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.
```

Failure remains exactly:

```text
Local AWS emulator manifest failed: <category> rejected.
```

The ordered categories remain `build`, `cleanup`, `configuration`, `deadline`,
`normalization`, `ownership`, `panic`, `provider`, and `readiness`. Reusing the
reviewed fixed output avoids creating a second public interpretation of the
same lifecycle.

## Ownership, cleanup, and live verification

The target inherits the full M1-30d mutation journal, settlement join,
independent cleanup deadline, exact pre-deletion ownership reproof, cleanup
continuation, cleanup precedence, recovery-root retention, and global absence
audit. It never deletes a shared image, cache, container, network, volume,
kubeconfig, or Kubernetes target.

Live verification runs only after hermetic tests and uses exactly:

```sh
env -i PATH="$HOME/.nvm/versions/node/v22.23.1/bin:/usr/local/bin:/usr/bin:/bin" \
  HOME="$HOME" LANG=C.UTF-8 npm run local:start
```

It requires exit zero, the sole fixed success line, all four product pods
Ready, exact graph persistence, one retained observability span, one
endpoint-bound S3 request, internal-only Services, no published kind-node
ports, zero proof-owned residue, and unchanged selected shared and ambient
state.

## Testing and status boundary

Hermetic tests cover the exact target descriptor, fresh builder composition,
manifest order, dependency order, exact delegation count and arguments, fixed
output, failure categories, immutable input, and hostile dashboard-exposure
mutations. Existing product, graph, observability, AWS-emulator, license, and
quality suites remain unchanged and green.

M1-30 starts by changing overall status from `658/0/67/3` to
`657/1/67/3`, and M1 from `68/25/0/43/0` to `68/24/1/43/0`. Completion changes
those values to `657/0/68/3` and `68/24/0/44/0`. Exactly one M1-30 row moves
from In progress to Complete. M1-30a, M1-30b, M1-30c, and M1-30d remain
Complete; M1-31 remains Pending; the exact blocker set remains M0-09, M0-18,
and M0-19.
