# Identity checks now surround subscription setup

September 10, 2026. Unpublished work on `codex/runtime-sensor-lineage`.
Counts stay at 535 production-available, 132 component-only and 61 external
gates. This change wires generation startup; it doesn't complete a milestone.

`startLineageGeneration` composes the checked host boot reader, bounded Kubernetes
identity client, authenticated local subscription and private spool. It validates
node and enrollment inputs before network activity, performs the repeated identity
lookup, opens the checked subscription, then repeats the identity lookup. Both
copied observations must match in full.

Only then does it generate a fresh cryptographic UUIDv4 and publish a source-bound
manifest. No records are received or exposed by this constructor. Its caller gets
the subscription and storage only after manifest publication and the final
cancellation checks. Source access returns a copy. A retry needs another endpoint
and another generation; existing history isn't adopted into the new source.

## Startup isn't the stream lifetime

Startup has a 15-second cancellation deadline, covering two identity lookups with
their own five-second limits and subscription setup with its three-second limit.
The stream derives its lifetime from the caller, not the startup context. The
startup cancellation callback is stopped before success, and the temporary
context is retired. Trusted local filesystem operations and mutex acquisition
aren't promised to obey a wall-clock deadline.

Endpoint ownership transfers even on failure. The resulting object owns its
subscription and newly created storage generation. It borrows the API client,
boot reader and parent spool; their owner must keep them alive. A narrow publisher
dependency permits a test wrapper around the actual spool to cancel immediately
after publication, without timing hooks inside the filesystem writer.

Failure closes owned resources. If publication already happened, its directory
and manifest remain as abandoned history. They cannot be reused for writing.
Bare Close doesn't publish a termination seal or invent coverage counters.
The future event pump must record known termination and gaps explicitly.

## What this cannot prove

The second identity check follows client `GetEvents` request submission. gRPC
returning that stream doesn't acknowledge server listener registration or prove
an event-history cutoff. These checks don't exclude delayed cache notifications,
authenticate arbitrary provider replay, attest host mounts, or grant enrollment
authority. The caller must supply the controlled mounts, procfs boot reader,
trusted Kubernetes configuration and root-owned production endpoint.

This isn't an atomic Kubernetes snapshot or continuous identity monitoring.
Pump-time rechecks, bounded receive/batch handling, filter/drop accounting,
consumer admission, acknowledgment/reclamation, daemon/deployment wiring and
live pinned Tetragon compatibility remain required before activation.

## Checked against actual transports

The first tests failed on the missing startup implementation in
`/tmp/zasp-lineage-generation-start-red.log`. The integration fixture uses actual
verified HTTPS for Kubernetes-shaped identity reads and actual checked Unix gRPC
for the subscription. It verifies four HTTPS requests before the version RPC and
four after subscription setup, exact source/manifest binding, then sends a provider
event through the subscription converter into a readable bound spool chunk.

Negative cases change Node UID, cluster UID or boot identity after setup, cancel
the caller, or fail the second identity lookup. They return no generation and
leave no manifest. Invalid inputs fail before source network activity. Later
publication failure closes the endpoint without closing borrowed resources.
Cancellation immediately after actual manifest publication preserves the abandoned
directory, clears the active writer and refuses reuse. Retry tests use distinct
generation IDs and check Close against receive/storage access and borrowed lifetime.

A real elapsed-time test waits beyond the 15-second startup deadline and then
receives an event on the admitted stream. It also checks that the stream keeps
the caller's deadline and the startup context has been canceled. Focused races
pass in `/tmp/zasp-lineage-generation-start-expanded.log` (18.312 seconds).
Fresh full sensor-agent races, including the final retry test, pass in
`/tmp/zasp-lineage-generation-start-full-agent.log` (22.244 seconds).

All generation startup tests also passed on Linux arm64 in
`/tmp/zasp-lineage-generation-start-linux.log`, including the elapsed 16-second
lifetime test. The isolated container used a read-only root, no network,
UID/GID 65532, all capabilities dropped, 256 MiB memory without swap, 0.5 CPU,
GOMEMLIMIT 128 MiB and a 128 MiB tmpfs. Its exit was zero and OOMKilled was false.
The owned proof container was inspected and removed. Logs and binaries remain.
This isn't a full-daemon resource or persistent-disk durability proof.

Test binary: `/tmp/zasp-lineage-start-linux.2MYb2o/sensor-agent.test`, SHA-256
`534c9f6bab4f0f8f62ee64c2e7265a666689c9a53a1c00e05a61a2ed2ebd8efe`.
Production cross-build: `/tmp/zasp-lineage-start-linux.2MYb2o/sensor-agent`, SHA-256
`0d65eee7f2ff2d33512f304a88c543968b87e08ab9640172dc266cfe2b393e72`.
Pinned local image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.

Independent read-only review found no concrete blocker in this bootstrap
component. Installed Superpowers remains unavailable; the disclosed official
upstream test-first, fresh-verification and independent-review workflow supplied
the verification boundary. These are local fixture services, not a running
Kubernetes cluster or Tetragon daemon. No shipping or production-readiness claim.

Next: connect the bounded event pump and identity rechecks to this lifetime, then
consume published generations through durable admission and acknowledgment.
