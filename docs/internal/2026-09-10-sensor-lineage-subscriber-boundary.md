# Keep the control socket inside Tetragon

September 10, 2026. Design and downstream dependency audit on unpublished
`codex/runtime-sensor-lineage`. This checkpoint implements no subscriber, grants
no socket access and changes no task credit. The count remains 535
production-available, 132 component-only and 61 externally blocked.

## The access boundary

The pinned Tetragon v1.7.0 server registers the full FineGuidanceSensors gRPC
service without authorization interceptors. Its Unix listener has mode 0660.
The service includes policy addition/deletion, sensor removal, runtime hooks
and debug changes. A read-only volume mount or client exposing only GetEvents
doesn't prevent another client from invoking those methods.
[Server registration](https://github.com/cilium/tetragon/blob/v1.7.0/cmd/tetragon/main.go#L680),
[service methods](https://github.com/cilium/tetragon/blob/v1.7.0/api/v1/tetragon/sensors.proto#L271).

Decision: implement the fixed subscriber inside the trusted Tetragon pod. Only
that producer can access the raw socket. It writes sanitized records to a bounded
spool with an immutable source-generation manifest. The sensor agent gets read
access to the spool, not the raw socket. Don't introduce a transparent gRPC proxy
or describe raw socket-group access as read-only. This makes the producer part
of the Tetragon control-plane trust boundary; it doesn't eliminate that trust.

The subscriber must enforce its own fixed EXEC/EXIT/KPROBE allowlist, health-check
and namespace exclusions, and field redaction. Tetragon's exporter filters apply
to file export and don't automatically restrict a GetEvents subscription.
Reconstruct an allowlisted record from typed fields. Never marshal the entire
provider message, retain unknown protobuf bytes, or infer lineage from an
unsupported argument variant. Process arguments, working directories and new
environment-variable fields must not enter the spool.

## Dependency evidence, narrowly

The official v1.7.0 API module requires Go 1.26.0. The product sensor image and
module currently use Go 1.25. The official v1.6.0 generated API requires Go 1.25.0.
Its dependency manifest includes a placeholder root-module version with a local
replacement, so an actual downstream resolution check was required.
[v1.7 manifest](https://github.com/cilium/tetragon/blob/v1.7.0/api/go.mod),
[v1.6 manifest](https://github.com/cilium/tetragon/blob/v1.6.0/api/go.mod).

A separate temporary module at `/tmp/zasp-tetragon-client-compat.sdHJvo` pinned
`github.com/cilium/tetragon/api v1.6.0`. With `GOTOOLCHAIN=local`, a test imported
the official `api/v1/tetragon` package, serialized GetEventsRequest and checked
the full GetEvents method name. It passed in 0.712 seconds; output is retained in
`/tmp/zasp-tetragon-client-compatibility.log`. A subsequent `go mod tidy`,
`go mod verify` and uncached test also passed, with all modules verified and the
test completing in 0.517 seconds. The product dependency manifests are unchanged.

The downloaded module sum is
`h1:3/EXcNkEyjUwG+Vps6WGz1Wi/CiOck9gK5lx6ZBbiZw=`.
Independent source review found the selected existing request/response fields
unchanged, while v1.7 adds namespace-regex filtering, process environment
variables and argument variants. This supports trying the v1.6 generated client
for the bounded field subset. It isn't live server compatibility evidence.
Before adopting it, add executable descriptor/enum checks for the selected
surface against both releases and test the pinned v1.7 server. Don't import
code-generation helper packages that require the upstream root source tree.

## Before any record gets a generation

Validate the protected Unix socket parent, socket owner/type and Linux peer
credentials. Retain exactly the validated connection; implicit gRPC redial must
not silently connect to a replacement endpoint. UID alone doesn't attest the
server image, pod or host namespace. Deployment supplies that trust boundary.

Read and compare host boot, Node and cluster identities around stream creation.
Create the immutable enrollment-bound manifest before writing records. Every
new upstream connection requires fresh identity checks and a new generation.
Never apply current boot identity to an old exporter file or adopt a previous
generation's process cache. Delayed events from the current boot remain possible;
subscription time isn't a valid event-time lower bound.

Spool access needs pinned, non-consumer-writable parents and files, bounded
storage, owned crash recovery and input/checkpoint path-collision protection.
Disconnects and producer overflow must remain explicit collection gaps. A new
generation cannot claim lossless recovery across a gap.

Required negative proofs include inaccessible control methods from the sensor
container, replacement/reconnect rejection, server restart generating a new
manifest, unknown v1.7 field secrecy and no cache carryover across gaps. Actual
deployment, resource limits, source-to-API recovery and browser attribution
remain open.

The independent reviewer confirmed the control-socket concern and the bounded
dependency approach. It did not run a live subscription or approve shipping.
Installed Superpowers remains unavailable; the previously disclosed official
upstream test-first, verification-before-completion and independent-review
workflow remains the fallback. This audit isn't an implementation test pass.
