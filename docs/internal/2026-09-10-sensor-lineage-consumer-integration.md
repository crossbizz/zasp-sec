# Admitted source to authenticated ingest

This is component progress toward M3-46/M3-47 and M7-07. No original task credit
is added. The authoritative ledger still has 535 production-available,
132 component-only, 61 blocked/external and zero missing across 728 microtasks.

## Production code added

`services/sensor-agent/lineage_consumer.go` connects the admitted immutable spool
reader to `sensoradapter.ChunkProcessor`. It copies the admitted source contract,
borrows the pinned source/spool roots and concrete production client, and passes
protected inputs through the cursor-collision checks. There is no fallback to
unqualified file processing or adoption of an earlier generation.

Every operation rechecks reader admission, including frozen pending replay,
which deliberately does not read another chunk. Closed readers, replaced
manifests and detached generation directories fail before checkpoint writes or
upload. Context is checked around source reads. The reader's lifetime mutex is
held through processing so its owner cannot close borrowed handles during an
upload. The source reader has an internal locked read method for this composition.
That mutex protects reader lifetime, not producer filesystem operations; producer
immutability and controlled permissions remain required. Filesystem operations
do not have a hard cancellation deadline.

Consumer Close owns only the cursor processor. It does not close the borrowed
reader/client, alter a seal, acknowledge a producer generation or reclaim data.
The caller closes borrowed resources after the consumer. Daemon activation is
still pending separately verified ACK/reclamation and deployment work.

## Composed test

The existing actual PostgreSQL ingest fixture now compiles a separate race-enabled
sensor-agent test binary. Its test-only entry initializes a fresh generation from
typed provider fixtures through the real sanitizer and producer spool, then uses
the real reader/consumer in separate process invocations. The production binary
has no fixture mode.

The parent creates and rotates an enrollment through the real public product
handlers and registered PostgreSQL roles. Public request identity is an authorized
scoped fixture, not browser/IdP authentication. The child uses the actual rotatable
token-file reader and sends through certificate-verified local HTTPS to the
production ingest handler and PostgreSQL repository. No token value is put in
child configuration, environment, argv or failure output; it remains in its own
0600 file. The configuration carries only paths, endpoint, CA and source identity.
Initialization refuses existing generations. Processing never recreates source.
The parent bounds and waits for each child; temporary state and private PostgreSQL
are owned by the fixture and cleaned up when it exits.

The proof covers:

- A first chunk is actually accepted before the child simulates losing its response.
  Its durable pending request survives process exit.
- Real credential rotation, then a new process replays identical body/idempotency
  with a changed credential. The original database authority is byte-for-byte
  unchanged, with one artifact write, one batch, five stage rows and one outbox row.
- A corrupt manifest rejects a restart before credential reads or ingest calls,
  leaving the pending cursor unchanged. Restoring the original fixture manifest
  permits the exact pending replay; the consumer itself does no repair.
- Another restart consumes a genuine partial file event using the first chunk's
  cached exact PID/start identity. A third chunk with the same PID but a changed
  start is rejected and accounted without credentials or transport.
- Two accepted chunks produce exactly two batches, ten stage rows and two scoped
  outbox rows. Source manifests, chunks and seal remain unchanged. Raw fixture
  secrets and file paths do not enter uploaded bodies. Observed lineage is retained
  without granting agent/session/container/cgroup/process correlation authority.

The artifact authority remains an in-memory double, not S3. Its prior single-key
implementation rejected the legitimate second object in the first composed run.
A focused RED test reproduced that limitation; the installed-sensor fixture now
keeps independent objects by exact scope/key while retaining the original per-key
drift checks. Product ingest checks were not relaxed.

This proves the compiled sensor test-process composition, not the deployed daemon,
live Tetragon, upstream boot attestation, full discovery coverage or cloud storage.

## Verification

Superpowers remains unavailable as an installed skill. Its official upstream
test-driven-development and verification/review workflow is the disclosed
fallback; no installed-plugin run is claimed.

The bridge tests failed at runtime against its fail-closed stub before the
implementation: `/tmp/zasp-lineage-consumer-bridge-red.log`.
The artifact fixture regression failed before its correction:
`/tmp/zasp-lineage-consumer-artifact-fixture-red.log`.

An initial overly narrow integration test selector skipped required inherited
credential-lifecycle subtests and failed before reaching the new scenario.
The full containing test is required. Its first complete run then exposed the
single-key fixture limitation above. Both failures are retained without being
counted as passing evidence.

Final focused bridge/reader races passed three repetitions in 4.704 seconds:
`/tmp/zasp-lineage-consumer-focused-agent.log`.
The full sensor-agent race suite passed in 25.178 seconds:
`/tmp/zasp-lineage-consumer-final-agent.log`.
The full containing HTTPS/PostgreSQL test plus artifact regression passed in
20.686 seconds, including the new child-process scenario in 12.15 seconds:
`/tmp/zasp-lineage-consumer-installed-https-postgres-final.log`.
The command was:

```sh
go test -race ./apiserver -run '^(TestProductionRuntimeIngestHTTPPersistsTransactionalOutboxBeforeAcceptance|TestInstalledSensorArtifactsKeepsIndependentObjectIdentities)$' -count=1 -v
```

Independent component review found no concrete blocker in the bridge, lifetime
test or scoped artifact fixture. It gives no shipping or reclamation approval.

Linux bridge/reader tests passed three repetitions as UID/GID 65532, with no
capabilities. A separate root producer with GID 65532 and only fixture SETUID/SETGID
capabilities launched an actual UID/GID 65532 child. That child admitted root-owned
source, ran the bridge, persisted its private cursor and verified the uploaded
observation; write attempts against the chunk, pending file and producer lock
still returned permission errors. That case passed three repetitions as well.

Both containers had 256 MiB/no-swap limits, 0.5 CPU, a read-only root, no network,
128 MiB noexec/nosuid temporary storage, `GOMEMLIMIT=128MiB` and no healthcheck side
process. Both exited zero without OOM and were inspected before removal. These
small-fixture runs are permission/component evidence, not maximal full-daemon
resource or fleet throughput proof.

Logs: `/tmp/zasp-lineage-consumer-bridge-linux.log` and
`/tmp/zasp-lineage-consumer-bridge-linux-permissions.log`.
Pinned Linux arm64 image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Test binary: `/tmp/zasp-lineage-consumer-bridge-linux.jcqU7J/sensor-agent.test`,
SHA-256 `85321d28cd129cc0f7b1fed8d5755a6aec4a14f3da42280e9154a954192984d7`.
The production Linux binary also builds at
`/tmp/zasp-lineage-consumer-bridge-linux.jcqU7J/sensor-agent`, SHA-256
`203298b13b8efa85ae4ecbdd0691b350d6c0b3b92e536baeb4c6affc9215e269`.
Logs and binaries remain; only the two owned exited proof containers were removed.

## Next required work

Consumer ACK publication has since been added in
`docs/internal/2026-09-10-sensor-lineage-consumption-ack.md`; producer-side independent
admission and crash-safe bounded reclamation/rotation remain open. Complete
daemon/deployment lifetime and permissions, protected
input checks, live source compatibility, correlation activation and the mixed
source-to-browser acceptance, including original sandbox/cgroup/process cases.
Full root release checks, composed Chrome and whole-branch review are still required
before a verified push to main. No push is claimed for this integration slice.
