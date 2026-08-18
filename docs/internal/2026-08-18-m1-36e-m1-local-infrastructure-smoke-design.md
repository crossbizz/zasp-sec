# M1-36e M1 Local Infrastructure Smoke Design

Date: August 18, 2026

## Goal

Run the repository's reviewed disposable local-infrastructure target and prove
that the required Kubernetes and LocalStack dependencies become healthy and
are then removed exactly. M1-36e records smoke evidence only; it does not add a
manifest, image, service, endpoint, provider capability, or long-lived local
environment.

## Selected boundary

M1-30a through M1-30d and the assembled local start target already own the
required implementation:

- `deploy/local/start.mjs` is the strict assembled entrypoint;
- `npm run local:start` is the single supported live command;
- the product, graph, observability, and AWS-emulator manifests are the six
  canonical tracked inputs;
- the M1-30d runtime creates one exact disposable kind cluster and one
  cluster-internal LocalStack Community S3 service; and
- the reviewed lifecycle joins mutations, cleans in reverse dependency order,
  and proves final global absence.

M1-36e therefore adds no smoke wrapper, second manifest, generated report,
dependency, image, port publication, or provider code. The execution sequence
is:

```bash
node --test deploy/local/start.test.mjs
npm run local:aws-emulator:test
npm run local:start
```

The live command must emit exactly:

```text
Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.
```

That result proves four product pods and services Ready, internal graph health
and persistence, one internal observability span, LocalStack S3 capability,
one explicitly endpoint-bound zero-bucket request, and exact cleanup.

## Live safety and evidence boundary

Execution uses repository-pinned Node.js 22.23.1 and npm 10.9.8 with an
allowlisted absolute `PATH` and `HOME`, and no ambient AWS, proxy, Docker-host,
Docker-context, kubeconfig, token, or cloud-provider variable. The runtime
creates an owned Docker configuration, kubeconfig, manifest descriptors,
image-build caches, kind cluster, Docker network, and proof labels beneath one
random M1-30d marker. It never reads the ambient kubeconfig or targets a shared
Kubernetes or LocalStack instance.

Before live execution, an independent read-only audit requires no proof-owned
M1-30d container, network, volume, image, or temporary-root residue. It records
the ambient Docker object sets, current Docker context, ambient kubeconfig
bytes when present, and complete fingerprints plus consumer sets for every
pre-existing exact shared image used by the target. Shared images are admitted
read-only and are never tagged or deleted on the host.

After the fixed success line, the same independent audit requires zero owned
residue, unchanged shared-image fingerprints and consumers, and unchanged
ambient Docker and kubeconfig state. Any mismatch, unproved absence, retained
recovery root, cleanup failure, extra output, or source-timebox overrun prevents
completion. Task cleanup may move only exact M1-36e-owned diagnostic artifacts
recoverably to Trash; it never deletes shared caches or unrelated state.

The live run inherits the reviewed 1,080-second main, 360-second independent
cleanup, 60-second settlement, child-output, SIGKILL, and ownership bounds.
The source task's 15-minute timebox is measured and reported for the successful
smoke itself; cleanup authority is never truncated merely to meet that target.

## Verification and scope

The focused assembly suite binds the exact 22-resource composition, six
manifests, dependency chain, no public or host exposure, fixed success/failure
output, cleanup precedence, and hostile object boundary. The full AWS-emulator
suite re-proves product, graph, observability, LocalStack, image, license,
provider-normalization, mutation, deadline, replacement, cleanup, and absence
behavior without live mutation. Six consecutive focused assembly executions
must pass before the one exact live smoke.

Full completion verification also reruns the M1 schema, OpenAPI, and UI/API
gates; all four Go-module race/tidy-diff/module-verify/vet matrices; pinned
repository verification; production dependency audit; whitespace and clean-
tree checks; pinned redacted secret scans; and a zero-finding whole-range
review.

M1-36e starts at 647 Pending / 1 In progress / 77 Complete / 3 Blocked overall
and M1 68 total / 14 Pending / 1 In progress / 53 Complete / 0 Blocked. It may
move to Complete only after the exact live success and post-cleanup audit,
review, scans, push, and exact-SHA Runnable UI success. Completion is 647
Pending / 0 In progress / 78 Complete / 3 Blocked overall and M1
14 / 0 / 54 / 0. M1-37 remains Pending throughout.

## Alternatives rejected

- A new smoke orchestrator would duplicate the reviewed assembled target and
  create a second cleanup authority.
- Reusing a shared Kubernetes or LocalStack target would make health and
  cleanup evidence non-isolated.
- Running only hermetic tests would not satisfy the required live dependency
  health check.
- Running each layer independently would repeat mutation and would not prove
  the assembled dependency chain.
- Publishing a host port or dashboard would widen the established internal-
  only boundary.
