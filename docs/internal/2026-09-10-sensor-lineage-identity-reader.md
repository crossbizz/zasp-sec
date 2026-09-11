# Reading host and Kubernetes identity

September 10, 2026. Work remains unpublished on `codex/runtime-sensor-lineage`,
based on verified main `a4fede82`. The 728-task scope and production counts are
unchanged: 535 production-available, 132 component-only, 61 externally blocked.
This implements a dependency of the local collector described in
`2026-09-10-sensor-lineage-generation.md`, not the collector itself.

## Implemented readers

The boot reader pins an open parent directory and requires the expected owner,
a regular single-link file and no group/world write permission. It opens the
leaf with `O_NOFOLLOW|O_NONBLOCK` and verifies opened-file identity. Actual reads
are bounded to 38 bytes, with only a canonical nonzero lowercase UUID and one
optional LF accepted. It doesn't rely on reported size being nonzero: procfs
may report zero. Read and Close are serialized; a replaced parent path cannot
redirect an existing reader.

`newProcBootReader` adds the production source requirements: Linux, a `boot_id`
leaf, root ownership and procfs for both the pinned parent and each opened leaf.
The lower-level explicit-owner constructor permits non-root fixtures; it isn't
production host authentication. No daemon configuration invokes either new
reader yet.

The identity resolver reads host boot ID, then two pairs of kube-system Namespace
and configured Node observations, then host boot ID again. It copies scalar IDs
before the next API call, so reused provider objects cannot retroactively change
the earlier observation. It requires exact requested names, canonical nonzero
UIDs, no deletion timestamps, an active Namespace and a Node boot ID matching
the host. Namespace/Node recreation, boot change, cancellation and malformed
responses return no partial identity.

The returned value is an identity observation. Repeated matching reads aren't
an atomic Kubernetes snapshot, tenant authority, exporter freshness or host
attestation. The cluster qualifier is the kube-system Namespace UID proxy already
chosen by the generation profile, not a native Kubernetes cluster UID. The future
collector must compare observations around an authenticated local subscription
and bind a new owned generation before writing records.

## Actual HTTP boundary

The dedicated Kubernetes client uses trusted in-cluster TLS configuration and
typed core-v1 GETs. It rejects insecure TLS and custom transports/auth plugins,
disables proxies and compression, owns cloned HTTP connections, caps headers at
16 KiB and response bodies at 1 MiB before decoding, and refuses redirects.
Only the configured Node and kube-system Namespace paths are permitted; mutation,
listing, foreign resources/origins/Host headers and extra queries are rejected
before network transport. The sole query is client-go's exact `timeout=5s`.
JSON is required, and compressed responses are rejected.

There is a five-second HTTP timeout and a five-second context for the complete
multi-read lookup. Cancellation is checked between reads and before returning
success. This doesn't make filesystem opening or `boot.Read()` interruptible by
context. Deployment must provide the intended local read-only host-proc mount,
not an arbitrary blocking filesystem. Procfs type checks alone don't authenticate
which mount was supplied. Client Close closes idle connections; eventual lifecycle
wiring must cancel the parent context before closing, not treat Close as an
in-flight cancellation barrier.

Client-side request restrictions aren't per-node RBAC. A shared DaemonSet service
account cannot express permission for only the Node named by each pod's NODE_NAME
using ordinary RBAC. The deployment must either document cluster-wide Node GET or
provision separate node-specific identities. Namespace GET can be restricted with
`resourceNames: ["kube-system"]`. No new permissions have been granted here.

## Verification

Missing reader and HTTP APIs first failed compilation in
`/tmp/zasp-lineage-identity-red.log` and
`/tmp/zasp-lineage-kubernetes-red.log`. Identity-unit tests then passed. Initial
actual-HTTPS tests exposed an integration defect: the guard rejected client-go's
timeout query before any network call. The failure is retained in
`/tmp/zasp-lineage-kubernetes-green.log`, despite that early filename. Source
inspection of pinned client-go v0.35.5 `rest/request.go` confirmed its timeout
serialization; accepting only that exact query repaired the actual request path.

The final fresh full sensor-agent race suite passes in
`/tmp/zasp-lineage-identity-reviewed-agent.log` (2.363 seconds). It includes actual
certificate-verified local HTTPS with four exact Kubernetes GETs and a real pinned
boot-file fixture. API contents are fixtures, not a live Kubernetes cluster.
The negative cases cover oversize/truncated replies, redirects, permission denial,
wrong media type, compression, cancellation and request-scope expansion. All
non-cancellation response tests require the context to remain live, so a timeout
can't masquerade as successful response validation.

Identity cases include host/API boot disagreement, host change during lookup,
Node/Namespace replacement through reused mutable objects, wrong names, missing
objects, zero UID, deletion, terminating Namespace, close during lookup and
cancellation between calls. File tests cover canonical bytes, size, modes,
symlink denial, parent replacement, read/close concurrency and non-procfs denial.

The compiled non-race Linux arm64 test binary ran all boot/proc reader tests three
times against real Linux procfs in `/tmp/zasp-lineage-identity-linux-final.log`.
The container used pinned local image
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`,
UID 65532, no network, read-only root, no capabilities, no-new-privileges,
256 MiB hard memory/no swap, 0.5 CPU, `GOMEMLIMIT=128MiB` and a 32 MiB tmpfs.
It exited zero with `OOMKilled=false`. The Linux-only procfs case is skipped in
native macOS tests and was explicitly executed in this Linux run. These are
reader tests under resource limits, not full-daemon memory or latency proof.

Independent read-only review found no concrete blocker in the readers or final
procfs/request-scope additions. The reviewer didn't rerun tests or approve shipping.
Installed Superpowers remains unavailable; the disclosed official upstream
test-first, verification-before-completion and independent-review fallback applies.

## Still required

Implement the authenticated local GetEvents subscriber, bounded private spool,
durable immutable manifest and lifecycle/gap handling. Connect these readers only
after validating the actual local endpoint and host mount, protect their paths from
checkpoint/spool writes, add deployment permissions/mounts, then verify reboot,
reconnect, historical adoption refusal and crash recovery. Production emission,
correlation-producer activation, full-daemon resource proof, remaining migration-48
authority cases and final browser/release gates are unchanged. No push or
production-readiness claim is made.
