# Private chunks, with a restart boundary

September 10, 2026. Unpublished component work on
`codex/runtime-sensor-lineage`. Counts remain 535 production-available,
132 component-only and 61 externally blocked. No task or milestone promotion.

The trusted source producer has a bounded private spool component. Each new
generation publishes one canonical source manifest and immutable numbered chunks.
The consumer isn't wired to these chunks yet. No deployment or production
lineage activation is implied.

## What gets persisted

The manifest binds the record-format version to the copied enrollment, generation,
node, cluster UID, Node UID and boot ID. It is synced before the generation
directory is made group-readable. A chunk has a canonical header with sequence,
record count, payload bytes, manifest SHA-256 and payload SHA-256, followed by
complete newline-delimited records. The reader checks all of these fields.
Checksums detect inconsistent content; they don't authenticate a malicious writer.

Publication creates an exclusive `.pending` file, writes it completely, changes
it to 0440, syncs the file, renames it to the final name and syncs its directory.
Readers accept only numbered final chunks. A final file can become visible before
directory sync returns. Any uncertain publication poisons the writer, prevents
further append or sealing, and preserves data for a future recovery reader.

A successful seal records known counters, an allowlisted termination reason and
`coverage_complete: false`. EOF isn't proof of complete coverage. A missing seal
means unknown termination, including abrupt process exit or uncertain publication.
An error after rename can leave a valid readable chunk despite append returning an
error. The future consumer must use the published chunks themselves, not producer
return values, to establish a contiguous committed prefix.

## Who can touch it

The spool requires a dedicated local directory owned by the producer, without
group/world writes or special mode bits. An exclusive file lock admits one writer.
The lock, manifest and chunk files require their exact modes, expected UID,
regular-file type and one link. Symlinks are rejected. The producer pins directory
and manifest handles, checks the named generation against its held directory, and
refuses a replaced manifest. Old generation directories are never reopened for
writing, including after restart.

The raw Tetragon socket isn't on this volume. Production still needs a root-owned
producer and a read-only consumer group, explicit mount/permission wiring, and
enrollment-bound consumer admission. The current constructor supports injected
owners for fixtures. It isn't a production authority constructor, and it doesn't
attest mount provenance or defend against arbitrary privileged filesystem changes.
Files use the producer process's group. A read-only consumer must never receive
deletion or producer-lock authority.

Record validation here checks canonical closed shape, matching node and one event
variant. It isn't semantic validation. The source caller must use
`sanitizeLineageEvent` before storage, and consumption must apply the qualified
normalizer's semantic checks before producing runtime events. Private paths and
addresses remain in these records; they aren't safe for logs or public APIs.

## The limits are explicit

At most eight generation directories can be reserved. Crash leftovers and failed
creation directories consume slots. Each generation accepts at most 128 chunks,
8 MiB of record payload, 1 MiB per chunk and 1,000 records per chunk. Each record
is capped at 256 KiB. Header/manifest/seal bytes and filesystem allocation overhead
are separate from the 8 MiB payload limit. A failed in-progress chunk uses the next
reserved chunk's payload allowance; the writer cannot continue after failure.

Capacity failure happens before creating a pending file and preserves existing
data. It can be sealed as `capacity`. There is no deletion, reclamation, durable
consumer acknowledgment or automatic rotation yet. Eight exhausted slots stop
creation. These bounds don't make this a continuously running production spool.

## Evidence and its limits

Initial missing-implementation RED: `/tmp/zasp-lineage-spool-red.log`.
Boundary RED: `/tmp/zasp-lineage-spool-boundary-red.log`. It caught an uncertain
append followed by an undercounted seal, writes into a detached generation, and
acceptance of special directory modes. All three now fail closed.

Fresh full sensor-agent race tests pass in
`/tmp/zasp-lineage-spool-full-agent.log` (6.171 seconds). Tests cover both payload
and chunk quotas, preservation at capacity, abandoned slot accounting, restart
refusal to adopt old generations, checksum/source mismatch, unsafe owners/modes,
symlinks, and concurrent reads while publication is paused before rename.

Cancellation tests observe actual filesystem boundaries without production test
hooks. The directory-sync failure test closes the held directory after validation
to cause an actual post-rename sync error. Subprocess tests exit abruptly after
file sync and after rename/directory sync; a new process recovers the producer
lock but cannot reopen old history for writes. This proves process-exit behavior
on the tested filesystem. It isn't a power-loss, disk-failure or remote-filesystem
durability test.

All spool tests passed three repetitions on Linux arm64 in
`/tmp/zasp-lineage-spool-linux.log`, using a read-only container root, no network,
UID/GID 65532, all capabilities dropped, 256 MiB memory without swap, 0.5 CPU,
GOMEMLIMIT 128 MiB and a 128 MiB temporary filesystem. The container exited zero,
with OOMKilled false. This is component execution on tmpfs, not a host persistent
disk or full-daemon resource proof. The owned proof container was inspected and
removed; test logs and binaries remain.

Test binary: `/tmp/zasp-lineage-spool-linux.6htIaZ/sensor-agent.test`, SHA-256
`bc33ea3d7b4a490f208fc20df7f809ce67bcd930117523c0b027075fb2bd5621`.
The production binary also cross-builds at
`/tmp/zasp-lineage-spool-linux.6htIaZ/sensor-agent`, SHA-256
`9d126966876c276b6ed94b4672241b418a0656ed8cc56f02ed5c85ce7e9f13c1`.
Pinned local image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.

Independent read-only review accepted the two publication/identity repairs and
found no further concrete blocker in this component. Installed Superpowers remains
unavailable. The disclosed upstream test-first, fresh-verification and independent
review workflow required the regression tests above. No shipping approval.

Next: bracket the actual subscription with boot/Node checks and wire immutable
generation creation. Then integrate consumer admission, contiguous durable
checkpoints, acknowledgment-bound reclamation and gap accounting. Live pinned
Tetragon compatibility, daemon resource proof, deployment and source-to-browser
attribution remain open.

Later component work connects consumption, authenticated reclamation and metadata
retirement. Established interrupted generations can now be closed without resuming
event append, preserving incomplete private bytes through ACK-gated reclamation:
`docs/internal/2026-09-11-sensor-interrupted-generation-recovery.md`. The earlier
observations above describe the original spool slice, not the current recovery
implementation. Pre-manifest reservations and daemon activation remain open.
