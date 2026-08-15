# M0-12 Tetragon Signal Proof Design

**Date:** August 14, 2026

**Decision owner:** Product owner, delegated to the implementation agent

**Status:** Approved for execution by the instruction to decide, fix, and proceed

## Decision

M0-12 will run Tetragon in one exact-owned, disposable, single-node Kubernetes
cluster. One synthetic workload will produce a process execution, a file
access, and an outbound TCP connection to an in-cluster sink. The proof will
strictly validate that all three observations carry the same Kubernetes
workload identity and that the sensor exposes explicit capability, policy,
health, and drop state.

This is an observation proof. It does not make Tetragon a semantic source of
truth, claim plaintext visibility, enable enforcement, prove internet egress,
or claim production-kernel coverage. The TCP event proves that the workload
initiated an outbound connection to the isolated fixture sink. M0-09 and
PROV-01 remain Blocked, and R-03 remains incomplete.

## Options considered

### Disposable kind cluster — selected

An exact-owned `kind` cluster supplies the Kubernetes pod, namespace,
container, and workload metadata required by R-07 while remaining disposable
and isolated from shared services. It supports the official Tetragon
installation path and permits exact lifecycle and zero-resource audits.

### Direct privileged Docker containers — rejected

Running Tetragon and a workload directly in Docker is simpler, but it cannot
prove Kubernetes workload identity. It therefore cannot satisfy M0-12 even if
the underlying eBPF probes work.

### Hermetic fixtures against an external cluster — fallback preparation only

A strict parser and injected orchestration boundary are useful and required
for tests, but recorded fixtures cannot close R-07. If the disposable Linux
kernel cannot provide the required eBPF capability, the implementation may
remain review-ready with a truthful capability blocker; it must not synthesize
a successful live result.

## Immutable runtime

- Tetragon release `v1.7.0`, source commit
  `1de2ed8ebea18e56257dc59597aa13bf8f0e471e`.
- Tetragon image index
  `quay.io/cilium/tetragon:v1.7.0@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527`.
- Tetragon arm64 descriptor
  `sha256:1bffeee60f1d47e367d237129e576729d14fe8db748440328aded8a6091c4a40`.
- Tetragon amd64 descriptor
  `sha256:eec0f2991bd11f02b3c2fe7a1740e01ca58ec6b2c5a1e57e395448e5c4822548`.
- Tetragon Operator image index
  `quay.io/cilium/tetragon-operator:v1.7.0@sha256:074ffbd19208eed79f68e191ed606e05009f910b4bb5148efcf2973e13504b82`.
- Tetragon Helm chart `1.7.0`, archive SHA-256
  `2d142ecff37a05bc2efab4c3f90cac2a545e8951d845fd15d023e1cbc31685f5`.
- kind `v0.32.0`; the host binary must match the official release asset
  checksum for the detected host platform. The Darwin arm64 checksum is
  `dca67911095a110c2b5c36e26df6cac860c602033e456c0db47be498cdef1ebb`.
- Kubernetes node image
  `kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95`.
- Kubernetes test-registry BusyBox fixture image index
  `registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9`,
  with arm64 descriptor
  `sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303`
  and amd64 descriptor
  `sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb`.
  This exact compatibility pin is served from the Kubernetes registry so the
  disposable kind node does not depend on Docker Hub pull-rate availability.

The implementation will retain platform-specific descriptors and complete
runtime metadata rather than accepting a tag or mutable name as ownership.
The kind configuration follows the official Tetragon requirement by mounting
the node's `/proc` at `/procHost`, and Helm sets
`tetragon.hostProcPath=/procHost`.

## Fixture topology

The generated cluster, namespace, workload, service, policies, files, and
temporary paths use one cryptographically random proof marker and a fixed
`zasp-m0-12-` prefix. They contain no customer data or credentials.

The cluster contains:

- one Tetragon DaemonSet installed by the exact chart;
- one fixed-label synthetic workload pod;
- one in-cluster TCP sink with no published host port;
- one narrow file tracing policy for the fixture path; and
- one narrow `tcp_connect` tracing policy. Both policies carry the exact
  proof/run pod-label selector and exact workload container-name selector, so
  omission cannot silently broaden them to unrelated workloads.

The workload performs, in order:

1. an explicit child-process execution;
2. an open/write/read of one fixed fixture path; and
3. one TCP connection to the sink's ClusterIP service.

No workload request targets the internet. The proof namespace and cluster are
not reused, and the repository's ambient Kubernetes context is never mutated.

## Strict observation boundary

The parser accepts only bounded UTF-8 JSON event streams with no duplicate
keys, no trailing JSON, bounded depth, exact event envelopes, and exact
allowlisted values. It retains only:

- event class and observation time;
- namespace, pod UID/name, container ID/name, workload labels, and node;
- process binary and execution identity;
- the exact fixture file path and access operation;
- the exact sink destination address and port for `tcp_connect`; and
- the Tetragon sensor identity and source version.

All three required event classes must resolve to one exact normalized workload
identity. Duplicate candidates, missing identity fields, aliases, wrong
namespace or labels, foreign events, and class-specific metadata mismatches
fail closed. Process lineage may help correlate events but is not used as an
authorization boundary.

## Capability, policy, health, and drop evidence

The proof requires explicit sensor evidence rather than treating emitted
events alone as proof of health:

- exact Tetragon build/version metadata, with the source commit interpreted
  only after the deployed immutable image reference has been re-proved;
- ready Tetragon and operator pods on the fixture node, each reporting the
  exact pinned image reference and proof/run labels;
- both tracing policies reported as loaded/enabled;
- an explicit bounded `tetra status` call to the sensor's gRPC health service;
- the required kernel/BTF/eBPF capability state; and
- all required loss/drop counters present with numeric values.

The required counters cover observer ring-buffer loss/errors, event queue
loss, notification overflow, and export rate-limit drops. The completion proof
requires each counter to remain exactly zero across the bounded fixture
interval. Missing metrics, malformed labels, negative/counter-reset values, or
any nonzero loss/drop value fail R-07.

## Runtime boundary and fixed output

The root runner receives only fixed tool paths and owned temporary paths. It
does not load `.env`, Kubernetes configuration, cloud credentials, profiles,
host proxies, or ambient Docker authentication. It creates an owned kubeconfig
and Docker configuration, and every subprocess receives an explicit
allowlisted environment.

Reads are bounded and may use two short attempts. Mutations are single-attempt.
Thrown, signaled, or malformed-success mutations enter exact reconciliation;
definitive nonzero results do not. All child stdout and stderr share a hard
aggregate cap. The public boundary prints one fixed success line or one fixed
category line without resource identifiers, provider payloads, paths, or
events.

## Lifecycle and cleanup

1. Prove no container, network, cluster, kubeconfig, or temporary-directory
   target exists under the complete proof prefix or labels.
2. Resolve and verify every binary, chart, and image pin before mutation.
3. Create the exact kind cluster and prove its node container, image,
   labels, mounts, network membership, and owned kubeconfig.
4. Install Tetragon, apply the two policies and fixture resources, and prove
   exact specifications and readiness.
5. Capture the capability/drop baseline, trigger the three workload actions,
   capture bounded events, and capture the final capability/drop state.
6. Validate the shared workload identity, exact observations, policy state,
   zero loss/drop delta, and fixed result.
7. Treat the exact disposable kind node as the containing ownership boundary:
   re-prove its retained full ID, immutable image/runtime/network fingerprint,
   and anonymous volume immediately before removing that full ID with volumes.
   This atomically disposes the namespace resources, policies, chart, and
   cluster without any name-based Kubernetes or Helm delete that could target
   a replacement. Then prove exact node-volume/network/name/prefix/label/temp
   absence in reverse dependency order.

Cleanup uses an independent deadline, continues across all retained targets,
and wins error precedence. Ambiguous creates retain candidates before result
interpretation. Cleanup authorization re-proves exact ownership immediately
before each mutation. A late main-phase continuation cannot inherit cleanup
authority.

## Verification and release boundary

Completion requires genuine RED/GREEN coverage for strict event and metrics
parsing, shared identity, foreign/duplicate events, capability/drop failures,
runtime ownership, ambiguous mutations, phase fencing, overflow, timeout,
panic, cleanup precedence, and fixed output. It also requires an exact live
disposable run, zero-resource audit, repository verification, dependency and
license audit, redacted secret scan, and independent review with zero Critical,
Important, or Minor findings.

Starting M0-12 changes the 728-task counts to Pending `716`, In progress `1`,
Complete `10`, Blocked `1`; M0 becomes `15/1/10/1`. Completion changes them to
`716/0/11/1` and M0 to `15/0/11/1`. Successful reviewed live evidence closes
R-07 only. M0-09/PROV-01 remain Blocked, and R-03 remains incomplete.
