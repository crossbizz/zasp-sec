# Sensor lineage: source audit before emission

This began as a read-only audit and now tracks the dependent implementation
and test-first evidence below. It adds no original-task
completion credit and does not enable a producer. M3-46, M3-47 and M7-07 remain
incomplete. Sandbox, container, cgroup and process scope is unchanged.

## What the current source actually supplies

`services/platform/sensoradapter/adapter.go` does not emit `observed_lineage`.
It retains Tetragon's full pod/container identity and process PID/start time for
its bounded local cache. Its workload hash includes provider names; that hash is
not a Kubernetes UID or a boot identifier. The normalizer's cache key is node
name, PID and precise start time. Production construction has no host-context
resolver attached.

`services/sensor-agent/kubernetes.go` currently exposes namespace-scoped Lease
operations and Pod listing for heartbeat coordination. It does not read Nodes
or the kube-system Namespace. The existing service account permissions must not
be described as sufficient for those additional reads without checking the
deployment templates and adding least-privilege contracts.

The OpenTelemetry definition of `k8s.cluster.uid` uses the kube-system Namespace
UID as a cluster proxy. Kubernetes has no native cluster UID. This is a compatible
candidate source for the existing profile, not a name hash or host attestation.
Source: [OpenTelemetry Kubernetes resource convention](https://opentelemetry.io/docs/specs/semconv/resource/k8s/).

The Tetragon API distinguishes the full pod container identifier from abbreviated
`process.docker`. Its process PID is from the host PID namespace; the container
PID is a different field. The process start field describes execution start.
The supported adapter surface does not supply a boot ID or numeric cgroup ID.
Do not infer those from namespace inode numbers or an opaque exec ID.
Source: [Tetragon API reference](https://tetragon.io/docs/reference/grpc-api/).

## Precision and replay constraints

`runtimelineage.Observation.ValidAt` requires a precise process start no later
than the event time. The adapter deliberately truncates event time to
milliseconds while retaining nanosecond process start. A process starting within
that same millisecond can fail this check. An emitter must not round the process
start down, move the event time forward or weaken the existing validator to make
the fields fit. Qualification and missing-precision behavior need explicit tests.

`sensoradapter/stream.go` persists a v1 cursor with device, inode, offset and drop
count. Pending normalized events are retained in memory only. Restart rebuilds
the process cache from the file and normalizes the next batch again. Deterministic
source-only normalization is necessary, but not sufficient, for exact restart
replay. Reconstruction reads only the cursor-selected file's prefix; the live
process cache can contain exec identities from earlier rotated files. Also,
appended complete lines can change the uncertain batch's end boundary after a
restart. Adding freshly fetched host context could change its event bytes too.

Independent read-only review identified these existing rotation and batching
constraints. Both are now reproduced in `sensoradapter/stream_restart_test.go`:
the uncertain one-event batch becomes two events after restart and append;
the acknowledged-rotation restart drops a distinct partial file event whose
exec identity was in the earlier file. The live-cache positive control succeeds.
The first RED log is `/tmp/zasp-sensor-stream-restart-red.log`; the final variant
with distinct post-restart event identity also fails in
`/tmp/zasp-sensor-stream-restart-distinct-red.log`. Neither test is skipped or
weakened. They are uncommitted on `codex/runtime-sensor-lineage`, based on PR 42's
verified main merge, and no repair has been implemented or shipped yet.

Before activating enrichment, the stream needs a reviewed way to preserve the
exact normalization context or pending envelope across retries and restarts.
Tests must cover response loss, cursor-write failure, crash before/after durable
state updates, rotation, old boot data, changed node identity, missing context
and partial lines. Old data must not acquire current boot identity by default.
The host/boot binding design is not settled by this audit.

## Next bounded work

Keep the original plan's active-work timeboxes. First reproduce the uncertain
batch and rotated-cache restart cases above and settle durable replay binding.
Then add a failing adapter qualification test and an explicit immutable-context
contract, preserving absent lineage's existing wire bytes. Review process
precision and partial cache replay before connecting any resolver. Split actual bounded
Kubernetes/host reads, deployment permissions and opt-in wiring into separately
verified steps. Do not activate emission before compatible consumers and replay
binding are in place.

After actual emission, verify the authenticated ingest and frozen-candidate path
without fixture-only job edits. Producer activation and real browser attribution
are separate required acceptance steps. The current container-first profile does
not by itself close every original sandbox/cgroup/process case or any live
cluster/provider gate.

## Enrollment boundary implemented first

Design review found that sensor IDs are unique only within their database scope.
Random token locators do not encode that scope or a stable enrollment identity.
The durable envelope must be tied to the full organization/workspace/environment
and sensor tuple, using the same credential actually sent on each attempt.
A separate credential check followed by another token read would race rotation.

An uncommitted first component now provides `sensor.EnrollmentBinding`: a
domain-separated SHA256 comparison value over all four identifiers. It contains
no token material and grants no authority. An explicit new private transport
schema, `runtime-event-enrollment-v1`, requires a canonical single
`X-Zasp-Expected-Enrollment` value. The production handler captures it before
authentication callbacks and compares it against authenticated scope and sensor
identity before reading the request body. Legacy transport rejects this header;
older servers reject the new schema. No downgrade is performed. Canonical archive
schema and bytes remain `runtime-event-v1`.

Test-first evidence: the binding helper initially did not compile in
`/tmp/zasp-sensor-enrollment-binding-red.log`; the enrollment transport tests
then failed in `/tmp/zasp-sensor-enrollment-constraint-red.log`, including legacy
handlers ignoring the new constraint. Full sensor and runtime-event race suites
pass in `/tmp/zasp-sensor-enrollment-constraint-final.log` after implementation.
Tests cover every scope dimension, same sensor ID in another scope, a different
sensor, matching authority with a changed token generation, malformed/duplicate
headers, unsupported transport, pre-body rejection and unchanged archive bytes.
Independent read-only review found no concrete blocker in this component.

This is not a real credential-rotation proof. Actual token rotation, replacement,
post-authentication revocation and the configured installation binding still need
composed verification. No client, journal, resolver or deployment is activated.
The two stream restart tests remain RED, and the branch is unpushed.

The proposed durable repair is one atomic versioned checkpoint holding an exact
pending envelope and compact process-cache state, saved before any sink call.
The envelope must freeze destination, transport schema, enrollment constraint,
body bytes and idempotency key, or strictly verify a pinned serialization version.
The writer needs an exclusive cursor lock, strict bounded canonical state,
private file permissions and fsync/rename/directory-fsync durability. Failed or
oversized writes must send nothing and advance nothing. Size and latency budgets
must fit the deployed resource limits; no checkpoint ceiling has been implemented
yet. Legacy reconstruction and events older than the ingest freshness window need
explicit retained-error behavior, without silent eviction or timestamp changes.

## Frozen request component and actual credential lifecycle

The uncommitted client now has an optional explicit `EnrollmentBinding` setting.
An empty setting keeps existing unbound transport unchanged, but cannot prepare
a durable envelope. No production configuration supplies this setting yet.
`PrepareEnvelope` validates and freezes version, destination, enrollment,
transport schema, exact JSON body and idempotency key without reading a token.
`IngestEnvelope` checks all fields and pinned serialization before reading one
current credential for that attempt. Unknown fields, duplicate keys, aliases,
alternate JSON spellings, mismatched digests and invalid timestamps fail closed.
Saved events outside the 24-hour freshness window return `ErrEnvelopeExpired`;
callers must retain them for recovery. No automatic re-timestamp or downgrade
exists. Body bytes have an 8 MiB sensor-side cap; this is not a checkpoint-memory
budget or proof of matching every configured server request limit.

The initial missing-API compile failure is recorded in
`/tmp/zasp-sensor-envelope-red.log`; focused race tests pass in
`/tmp/zasp-sensor-envelope-green.log`. Independent review found no concrete
implementation blocker but identified a coverage hole: a stale idempotency key
could mask invalid-body decoding. Tests now recompute the key after body changes
and independently reject duplicates, aliases, escaped keys, unknown fields,
null/empty event arrays, wrong source, future timestamps and oversized input
before token reads. `/tmp/zasp-sensor-envelope-hostile.log` passes (1.737 seconds).
These are client/handler components, not durable journal or deployment proof.

`apiserver/runtime_envelope_http_postgres_test.go` now composes the actual client,
HTTP handler, registered PostgreSQL ingest principal and real credential issue,
rotation and revocation SQL. HTTPS transport and artifact storage are explicit
test doubles; the test does not prove TLS or S3. The first bound request commits
its raw-artifact reference, batch, five stage rows and outbox, then its response
is deliberately lost. Replaying the exact envelope with the actual generation-2
credential reproduces reservation failure. Pass-through driver observations
record SQLSTATE `23505`, two reserve calls, one finalize and successful
generation-2 authentication. No credentials or query arguments are logged.

The final reproduction is `/tmp/zasp-sensor-envelope-lifecycle-red.log`:
same-enrollment finalized receipt replay fails; revoked prior credential,
cross-enrollment replacement before body reads, and revocation after initial
authentication but before reservation all pass. Negative cases preserve batch,
stage and outbox counts, the original batch authority contents and the one
existing artifact write. The three negative cases are separate subtests, so the
known replay failure does not prevent their execution. The future receipt test
requires zero additional artifact writes and unchanged original provenance.

Root cause is the existing v15 reservation's request digest and conflict tuple:
both include token ID and generation (`0015_runtime_data_plane.up.sql:619-622`).
V17 delegates to that function. Finalization independently requires the original
token (`0015_runtime_data_plane.up.sql:664-666`). A rotated token authenticates
but cannot replay that provenance-bound reservation. The repository sanitizes
the conflict to unavailable, so the client receives a retryable failure.

Independent review approved this next design direction, not an implementation:

- Add a separate finalized-acceptance lookup for enrollment-bound transport in
  a new forward migration. Do not edit already-shipped migration SQL or weaken
  legacy reserve/finalize's original-token checks.
- Authenticate the current credential, enforce exact full-scope enrollment and
  match batch ID, idempotency, canonical content digest, source, media/schema,
  byte size and event count. Verify immutable artifact and durable batch/job/
  outbox bindings; a state label alone is insufficient acceptance evidence.
- Return the already-finalized receipt without rewriting credential provenance,
  request digest, artifact version or batch data. Unknown/uploading batches
  remain with existing reconciliation. Replacement credentials must not acquire
  permission to finalize an abandoned upload.
- Recheck authority after blocking locks; cover concurrent revocation/expiry,
  reconciliation races, foreign scope/enrollment and altered payloads. Grant the
  new function only to the registered ingest role, use a fixed search path and
  include exact catalog fingerprint/readiness and rollback coverage, preserving
  schema-47 candidate-consumer readiness semantics through the forward upgrade.

That lookup and its migration are not implemented. Installation binding,
checkpoint/cache integration, writer locking and the two original restart
regressions remain unfinished. The full adapter race run reports only those two
known failures in `/tmp/zasp-sensor-envelope-adapter-current.log`; they are not
skipped or weakened. This branch is unpushed and grants no original-task credit.

Final component checks: full sensor and runtime-event race suites pass in
`/tmp/zasp-sensor-envelope-boundary-final.log` (1.485 and 4.000 seconds).
The full sensor-agent compatibility suite initially failed two successful-ingest
wiring tests because their fixed August 20 event was checked against production
`time.Now`. HEAD's unbound validation has the same 24-hour rule; the new envelope
configuration was not enabled in those tests. Only the fixture was corrected to
use the current clock, with a separate 25-hour-old rejection test added.
Production timestamps and validation are unchanged. The full sensor-agent race
suite passes in `/tmp/zasp-sensor-envelope-agent-compatibility-green.log`
(1.942 seconds); the initial failure is retained in
`/tmp/zasp-sensor-envelope-agent-compatibility.log`.

Independent final review found no new component or test-correction blocker and
confirmed the branch is not shipping-ready. Ledger validation passes in
`/tmp/zasp-sensor-envelope-ledger-check.log`: all 728 rows reconcile to
535 production-available, 132 component-only, 61 external and zero missing.
No full UI/release verification or push is claimed while the three replay
regressions remain RED. The next implementation is the reviewed finalized
acceptance boundary, followed by durable checkpoint/cache and installation
wiring. All original production and external gates remain intact.

The next implementation checkpoint supersedes the earlier unimplemented-lookup
status: migration-48 SQL/metadata and the Go acceptance boundary now pass actual
local token-rotation replay, reviewed authority-wait and quarantined-acceptance
regressions. Production rollout and durable file recovery are still incomplete.
See `docs/internal/2026-09-10-runtime-acceptance-replay.md` for exact proof limits,
test-first logs and the remaining release path. No original task credit changed.

The following checkpoint adds local Runner/CLI and release-source wiring for48,
with actual API/candidate-worker startup and rollback checks. Review-discovered
upgrade lock inversion and self-referential48 checksum defects were reproduced
before correction. Actual contention, pinned-release drift and authentication
wait tests now pass. The acceptance evidence document records the new 15-argument
lookup and measured fingerprint. This does not repair the two file-stream
restart failures or activate production lineage. The branch remains unpublished.

The subsequent durable-checkpoint implementation now repairs both original
file-stream restart failures. Cursor/cache persistence, frozen bound-envelope
replay and exclusive writer locking pass local tests, including actual
subprocess ownership. Resource stress under Linux 256 MiB/0.5 CPU passes with
the rendered `GOMEMLIMIT=128MiB`; initial failed measurements remain recorded.
This supersedes the earlier RED restart status, not the open production gates.
Installation binding, composed file/HTTP/SQL recovery, full-daemon resource proof
and lineage activation remain. See
`docs/internal/2026-09-10-sensor-durable-checkpoint.md` for exact evidence.

The installation checkpoint subsequently wires actual enrollment-bound sensor
construction and proves local file/HTTPS/PostgreSQL token-rotation recovery:
`docs/internal/2026-09-10-sensor-installation-binding.md`. The latest source
checkpoint implements optional sensor wire preservation and an immutable
generation-qualified normalizer with replay/cache binding:
`docs/internal/2026-09-10-sensor-lineage-generation.md`. Source audit rejects
assigning current boot identity to the existing append-only exporter file.
A trusted fresh local stream/spool producer is the next required implementation;
production emission and all original attribution/release gates remain open.
