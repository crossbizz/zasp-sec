# Lineage follows a source generation

September 10, 2026. Unpublished work on `codex/runtime-sensor-lineage`, based on
verified main `a4fede82`. No original task credit changes: 535 production-available,
132 component-only, 61 externally blocked. M3-46, M3-47 and M7-07 remain open.
The full sandbox/container/cgroup/process scope is unchanged.

## The exporter cannot establish boot provenance

The deployed configuration pins Tetragon v1.7.0 at image digest
`deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527` in
`deploy/staging/tetragon/values.yaml`. Its exporter uses persistent hostPath files,
four uncompressed backups and the fixed `tetragon.log` name. The pinned writer
opens an existing file for append. Reading today's boot ID cannot qualify all
records already in that file.
[Pinned writer](https://github.com/cilium/tetragon/blob/v1.7.0/vendor/github.com/cilium/lumberjack/v2/lumberjack.go#L281-L308).

The chosen next producer is a trusted local GetEvents subscriber with a newly
created owned spool generation and immutable source manifest. A new subscription
registers an in-memory listener, with no stored-history replay at registration.
Its queue can overflow. Delayed notifications from Tetragon's event cache can
arrive later, so subscription time is not an event-time lower bound.
[Server](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/server/server.go#L76-L199),
[listener registration](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/grpc/process_manager.go#L67-L87),
[event cache](https://github.com/cilium/tetragon/blob/v1.7.0/pkg/eventcache/eventcache.go#L140-L185).

That producer must establish the actual local endpoint, match host boot ID and
Kubernetes Node boot identity around generation creation, bind the scoped
enrollment and Node/cluster identity before records are written, and refuse to
adopt historical exporter files. A generation UUID is an identifier, not evidence
that these steps happened. No boot identity is inferred from a timestamp, uptime,
node name, PID, namespace inode or abbreviated container ID. This is source-trusted
provenance, not host attestation.

## Components now implemented

`sensoradapter.RuntimeEvent` carries optional `observed_lineage` using the existing
closed `runtimelineage.Observation` contract. Both legacy and enrollment-bound
clients validate it at the unchanged millisecond event time before credentials.
The checkpoint validator uses the same validation. Absent lineage preserves the
old field order and exact wire bytes. Frozen envelopes retain precise process
start and all observation fields through credential rotation and file restart.

`LineageSource` contains the versioned local-stream profile, generation UUID,
enrollment binding, node name, cluster UID, Node UID and boot ID.
`NewLineageNormalizer` validates and copies the value once, starting with an empty
cache. No API attaches provenance to an existing unqualified normalizer/cache.
There is no runtime resolver callback that can change a retained generation.

Given that trusted source contract, normalization qualifies only matching node
names and valid full pod/container identifiers. Invalid or incomplete event
qualifiers preserve the event with lineage absent. A malformed source contract
is rejected at construction. Process ID and precise execution start are included
together only if the existing validator accepts them at the original event time.
Submillisecond precision is never rounded down to fit. Existing-running processes
are permitted by source-generation provenance; no subscription-time filter is
invented. Numeric cgroup ID isn't present in the supported provider surface and
isn't fabricated.

Qualified file processors require an actual enrollment-bound production client
with the same enrollment binding before creating checkpoint state. Their source
hash includes every provenance field and the existing pinned file-parent/path
binding under a new domain. With no context the old source hash is unchanged.
Changed generation, boot or Node identity rejects retained state before cache
restoration or transport. Legacy v1 cursors and unqualified v2 checkpoints cannot
be adopted into a qualified generation. Same-generation partial-process cache
replay remains supported.

The constructor relies on its caller to establish the trusted-generation
guarantee. It doesn't authenticate a spool or establish freshness merely by
receiving these strings. **No production daemon configuration creates this
contract or enables lineage emission yet.**

## Evidence and limits

The wire tests first failed compilation for the missing observation field in
`/tmp/zasp-sensor-lineage-wire-red.log`. With the field added but validation
missing, invalid observations reached credential reads and checkpoint validation
accepted them: `/tmp/zasp-sensor-lineage-validation-red.log`. The shared
`ValidAt` check repairs both paths without changing the underlying validator.

Tests cover malformed/absent boot identity, name/short-ID substitution, bare
process identity, process start after the millisecond event time, cgroup overflow,
null/empty observations, duplicate/case/escaped keys, unknown fields and
noncanonical timestamps. Hostile envelope tests recompute the idempotency digest
to reach decoding. Frozen checkpoint tests preserve exact bytes after an uncertain
send, restart and credential change; they explicitly inject an observation fixture
and don't claim actual source discovery.

The source tests first failed compilation in
`/tmp/zasp-sensor-lineage-source-red.log`. The first subsequent run exposed a test
fixture mistake: a shortened-container mutation changed the parent process only.
The corrected test changes the actual event process too; no production behavior
was relaxed. The failed run remains in `/tmp/zasp-sensor-lineage-source-green.log`
despite that early filename. The actual passing evidence is below.

Full fresh race suites pass in
`/tmp/zasp-sensor-lineage-source-reviewed-suites.log`: adapter 5.284 seconds,
lineage validation 1.484 seconds and runtime-event 3.886 seconds. Source tests
cover copied-context immutability, every source-hash dimension, malformed context,
bound-client enrollment mismatch, legacy/unqualified cache adoption denial,
reboot with reused names/process identity, Node recreation, changed generation,
same-generation partial cache restoration and deterministic precision omission.
Full sensor-agent compatibility passes in
`/tmp/zasp-sensor-lineage-agent-compatibility.log` (1.922 seconds).

The composed API fixture now runs both original unqualified recovery and qualified
generation recovery. A fixture-provided source contract feeds actual normalization,
file persistence, certificate-verified local HTTPS and registered PostgreSQL roles.
Public product enrollment and rotation supply real scoped credentials/binding.
After accepted-response loss and rotation, the exact request/receipt replays with
one artifact write and unchanged batch provenance, five stage rows and one outbox.
Actual archive decoding preserves the expected observation and scope while
agent/session and authoritative container/cgroup/process fields remain empty.
Both modes pass in `/tmp/zasp-sensor-lineage-source-https-postgres.log` (7.406
seconds). Source provenance and browser identity are fixtures; artifact storage
is a synchronized double. This isn't S3, live Tetragon, Kubernetes or deployed
end-to-end proof.

Independent read-only review found no concrete blocker in the source/wire
components, final cache-import regression or composed test extension. It didn't
rerun tests or approve shipping. Installed Superpowers remains unavailable;
the disclosed official upstream test-first, verification-before-completion and
independent-review fallback continues.

## Required next work

Implement and verify the trusted local subscriber, bounded private spool and
immutable generation manifest. Resolve host/Kubernetes identity with least-privilege
reads, protect all new input/state paths, and freeze generation provenance before
records enter the normalizer. Reconnect/reboot, mismatched boot IDs, historical
adoption, delayed current-boot events, gaps/overflow, rotation, crash recovery and
context loss all need source-level tests. Never claim lossless replay across a
collection gap.

Then wire the actual daemon and deployment, repeat full-daemon resource proof,
activate compatible correlation producers and verify real discovery/attribution
through the composed browser path. Remaining migration-48 authority/race cases,
full release verification and independent shipping review are still required.
No push or production-readiness claim is made here.

The next checkpoint implements pinned procfs boot reading and a bounded,
certificate-verified Kubernetes identity client with repeated scalar comparisons:
`docs/internal/2026-09-10-sensor-lineage-identity-reader.md`. It supersedes the
unimplemented reader portion above, not the open trusted subscriber/spool,
manifest, lifecycle, deployment or production-activation gates.
