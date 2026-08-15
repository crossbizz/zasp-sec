# M0-18 Fargate Verification Proof Design

## Decision

Implement a fail-closed proof harness for the source-plan M0-18 gate, but do
not substitute a local Kubernetes label for AWS Fargate authority. The live
proof runs one uniquely named canary Job through an explicitly supplied,
existing, disposable EKS Fargate test profile. It succeeds only when the Pod is
bound to the named profile, its assigned node reports
`eks.amazonaws.com/compute-type=fargate`, the canary exits zero after receiving
the exact body `agentsec-attack-lab-canary-v1` through the configured product
proxy, and every proof-owned Kubernetes resource is absent after cleanup.

The current host has none of the required real-AWS inputs, no AWS CLI or
`eksctl`, no reachable Kubernetes cluster, and no LocalStack auth key. The
official LocalStack EKS implementation creates embedded k3s/k3d or
self-managed nodes; that is useful for generic Kubernetes compatibility but it
does not establish the AWS-managed per-Pod Fargate compute boundary. Therefore
LocalStack, Docker Desktop, kind, or a synthetic node label cannot make M0-18
Complete or advance R-11. The reviewed harness will be implemented and M0-18
will become Blocked if the exact live fixture remains unavailable.

## Authority and sources

- The source task requires an existing disposable EKS Fargate test profile,
  a Fargate-scheduled Pod, observed canary behavior, and deleted run resources.
- [AWS EKS Fargate](https://docs.aws.amazon.com/eks/latest/userguide/fargate.html)
  states that EKS-managed controllers schedule matching Pods onto Fargate and
  that each Fargate Pod has its own compute boundary.
- [AWS Fargate profiles](https://docs.aws.amazon.com/eks/latest/userguide/fargate-profile.html)
  bind scheduling through namespace and optional label selectors, and expose
  the selected profile on the Pod.
- [LocalStack EKS](https://docs.localstack.cloud/aws/services/eks/) documents
  embedded k3s/k3d or self-managed nodes, not AWS Fargate execution.

These are distinct authorities. A local fixture may exercise parsing,
manifest generation, bounded polling, reconciliation, and cleanup, but it must
never emit the M0-18 success line or R-11 PASS.

## Live capability contract

The root live command accepts only the following explicit inputs:

- `AWS_M018_ISOLATED_TEST=I_UNDERSTAND_THIS_MUTATES_A_DISPOSABLE_EKS_PROFILE`
- `AWS_M018_KUBECONFIG`: absolute regular non-symlink kubeconfig path
- `AWS_M018_KUBE_CONTEXT`: exact context name
- `AWS_M018_CLUSTER_NAME`: exact EKS cluster name
- `AWS_M018_REGION`: one commercial AWS region
- `AWS_M018_FARGATE_PROFILE`: exact existing disposable profile name
- `AWS_M018_PROFILE_NAMESPACE_PREFIX=zasp-m018-`
- `AWS_M018_PROFILE_LABEL_KEY=zasp.agentsec.dev/fargate`
- `AWS_M018_PROFILE_LABEL_VALUE=true`
- `AWS_M018_PROXY_URL`: exact HTTPS canary endpoint, with no userinfo,
  fragment, query, or non-default port
- `AWS_M018_CANARY_TOKEN`: nonempty test credential, passed only through a
  proof-owned Kubernetes Secret reference

Ambient AWS credentials, profiles, proxy variables, generic `KUBECONFIG`,
dotenv files, default contexts, command arguments, and alternate endpoints are
not accepted. The harness does not create, update, or delete the EKS cluster or
Fargate profile.

## Workload and ownership model

Each run generates a 128-bit lowercase hexadecimal marker and derives one
namespace, ServiceAccount, Secret, Job, and Pod selector from it. Names use the
fixed `zasp-m018-` prefix and DNS-safe grammar. Every mutable resource carries:

- `zasp.agentsec.dev/proof=m0-18`
- `zasp.agentsec.dev/run=<marker>`

The Job uses the already reviewed immutable Kubernetes BusyBox test image:

`registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9`

The Kubernetes image packaging is Apache-2.0 at source commit
`22d90ebde235edec3541f728b37a01285bdd8b1b`; the mirrored BusyBox 1.36.1
runtime remains GPL-2.0-only and is not relicensed by that packaging. The audit
binds the index plus the Linux amd64 and arm64 platform/config digests.

Its fixed script reads the token through `secretKeyRef`, sends exactly one
bounded HTTPS request to the configured product proxy, compares the raw body
to `agentsec-attack-lab-canary-v1`, and exits zero only on equality. The Pod
uses `automountServiceAccountToken: false`, a read-only root filesystem,
non-root UID/GID, no privilege escalation, dropped capabilities, seccomp
RuntimeDefault, equal CPU/memory requests and limits, no host namespace,
hostPath, host port, persistent volume, or extra container.

Every create is single-attempt. Definite rejection is never reconciled or
adopted. Thrown, signaled, timed-out, or malformed success is ambiguous and may
be reconciled only by a fresh exact object read matching immutable UID, name,
namespace, labels, owner references, and full expected spec. Cleanup is
reverse-order under an independent context and re-proves exact UID plus all
retained ownership fields immediately before deletion. A replacement or
unprovable object is never deleted.

## Scheduling and canary evidence

The proof requires exactly one Job-owned Pod. It retains and cross-correlates:

- Pod UID, Job owner UID, ServiceAccount name, profile label, phase, container
  exit code, image ID, node name, and proof labels;
- Node UID, provider ID grammar, Ready condition, and exact
  `eks.amazonaws.com/compute-type=fargate` label;
- Job UID, complete condition, succeeded count one, failed count zero;
- fixed canary output bytes and empty unexpected stderr/termination data.

The profile label must equal `AWS_M018_FARGATE_PROFILE`; a user-supplied or
locally forged compute-type label is insufficient without the complete EKS
node/provider and Pod/profile projection. No provider identifiers, token,
manifest, logs, or raw errors cross the fixed process-output boundary.

## Deadlines, cleanup, and audit

- Main lifecycle: 10 minutes.
- Independent cleanup and absence audit: 5 minutes.
- Every read: at most 5 seconds, two attempts, backoff at most 500 ms.
- Every mutation: one attempt, followed by bounded exact reconciliation only
  for typed ambiguity.
- All child processes are asynchronously supervised, use SIGKILL at deadline,
  join/reap before cleanup, and share a 16 KiB stdout/stderr cap.

Final audit lists all namespaces and namespaced resources with either the
global proof prefix or proof label, not only the current marker. Success
requires zero namespace, ServiceAccount, Secret, Job, and Pod matches. Cleanup
failure overrides the main failure, and the kubeconfig is never changed.

## Process boundary

Success writes exactly:

```text
EKS Fargate proof passed: scheduled=true canary=true cleanup=true.
```

Failures write one fixed line from configuration, provider, scheduling,
canary, ownership, cleanup, deadline, or panic categories. If required inputs
are absent, the root command fails at configuration before any cluster request.

## Test and completion strategy

- Tests-first typed lifecycle with an injected cluster boundary.
- Loopback fake-kubectl coverage for strict JSON, retries, deadlines, mutation
  classification, candidate retention, replacement safety, global audit, and
  fixed output.
- A production live runner that is inert until every exact capability input is
  present.
- Six race/stability runs, repository gates, immutable image/license evidence,
  whitespace, secret scans, and whole-range review.
- M0-18 becomes Complete and R-11 remains `Not run — M0-18/M0-19` only after
  the exact live Fargate run. With the current missing fixture, M0-18 becomes
  Blocked with the exact dependency; M0-19 remains Pending.

## Self-review

This design does not create shared AWS infrastructure, weaken the Fargate
signal, treat LocalStack k3s as Fargate, expose the canary token, or advance the
egress half of R-11. It makes maximum safe local progress while preserving the
real-provider release authority.
