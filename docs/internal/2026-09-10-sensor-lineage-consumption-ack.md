# Sealed-consumption acknowledgments

Component progress only. This does not close M3-46, M3-47 or M7-07, activate a
daemon, authorize source deletion or change the original 728-task scope. Counts
stay at 535 production-available, 132 component-only and 61 external gates.

## What's implemented

`sensoradapter.ChunkProcessor.VerifyConsumed` requires durable committed state
without a pending upload. It rereads every consumed chunk, rechecks bounded
sequence/hash/line framing and recomputes source record count, byte count and
the entire digest chain. It re-establishes checkpoint durability before returning
the admitted source, exact ingest destination, device/inode and committed progress.
It does not normalize again, restore new identities, read credentials or upload.
Cancellation and uncertain persistence reject the proof.

Submitted and dropped counts are trusted local checkpoint accounting. Rereading
the source does not independently prove normalization decisions or authenticate
remote acceptance. This is not a cryptographic service receipt. The source seal
and the trusted local consumer still matter.

`lineageChunkConsumer.Acknowledge` holds the consumer and reader lifetime locks
through verification and publication. It requires the full verified source seal,
matches its chunk/record/byte totals to committed progress, calls the independent
prefix verifier, then checks the seal bytes and pinned manifest again. The receipt
contains the exact source contract, destination, physical generation identity,
manifest hash, checkpoint progress, complete seal and seal hash. The seal retains
its reason, producer dropped/filtered counts and `coverage_complete: false`.
Processing and Close cannot interleave within this operation.

The caller provides a separate consumer-owned ACK directory. Admission opens it
read-only, verifies the owner, protected parent, mode 0750 and held/named inode,
then scans a bounded closed filename set. Before any cursor write, construction
rejects directory inode overlap with the source, spool, cursor or any protected
input parent. The consumer borrows the ACK store; the caller closes it afterward.

Only a successful consumption proof can reach the private publisher. It lazily
takes a lifetime, owned, single-link 0600 `.consumer.lock`. It accepts at most
eight bounded receipts, each at most 8192 bytes. A new receipt writes a single
owned `.pending` file, makes it immutable-mode 0440, syncs the file, renames it,
then syncs the directory. No source file is written or deleted.

An identical receipt is accepted only after exact byte/ownership checks and fresh
file/directory durability barriers. Conflicting bytes are never overwritten.
Interrupted scratch is recoverable only while holding the lock and only for a
bounded, consumer-owned single-link regular file with the allowed mode. Unknown,
symlinked, hardlinked, foreign-owned or oversized entries fail closed and remain
untouched. A failure after rename is uncertain, not a successful acknowledgment.
Trusted producer immutability and controlled filesystem permissions remain required;
local fsync is not a guarantee about every host filesystem or power-loss behavior.

## Proof retained

Superpowers isn't installed. The previously read official upstream test-first,
verification-before-completion and requesting-code-review workflows remain the
disclosed fallback. No installed Superpowers run is claimed.

Initial prefix and publication tests failed against fail-closed stubs:
`/tmp/zasp-lineage-ack-prefix-red.log` and
`/tmp/zasp-lineage-ack-publish-red.log`.
The composed HTTPS/PostgreSQL ACK assertion failed before its child-process
implementation: `/tmp/zasp-lineage-ack-installed-red.log`. The failure specifically
reported a rejected acknowledgment after full consumption. A test-only lifetime
fixture initially supplied a nil transport and failed client construction; the
fixture now supplies a transport that rejects unexpected use.

Focused tests cover missing/changed chunks, valid-shaped corrupted committed
totals, an empty durable generation, complete multi-chunk prefix checking, pending
and unconsumed input, invalid seals, replaced source paths/manifests, closed handles,
cancellation, ownership, links, quota, conflicting receipts and concurrent Close.
Actual test subprocesses die at scratch/final publication boundaries; a new
process takes the released lock and safely retries. Linux uses an O_PATH directory
descriptor to provoke a real post-rename fsync failure, then checks that an
identical receipt cannot bypass the failed barrier.

The existing compiled sensor child now acknowledges the actual HTTPS/PostgreSQL
fixture's sealed source. Lost-response pending state cannot acknowledge or write
ACK state. Real credential rotation and exact replay preserve original database
authority. After three source records are consumed, the receipt accounts for two
submitted and one dropped, binds the actual generation device/inode and exact
manifest/seal hashes, and both initial and repeated ACK calls read zero tokens
and issue zero requests. Source files remain unchanged. The database retains two
batches, ten stage rows and two scoped outbox rows.

Provider/source identity and artifact storage remain fixtures. This is actual
local TLS, product handlers, registered PostgreSQL roles and compiled sensor code,
not live Tetragon, a deployed daemon, cloud storage or browser discovery proof.

Focused ACK races passed three repetitions in 5.936 seconds:
`/tmp/zasp-lineage-ack-focused-final.log`.
Full adapter races passed in 10.020 seconds:
`/tmp/zasp-lineage-ack-final-adapter.log`.
Final full sensor-agent races passed in 26.348 seconds:
`/tmp/zasp-lineage-ack-final-agent-reviewed.log`.
The containing HTTPS/PostgreSQL test plus artifact regression passed in 23.769
seconds, including the composed ACK scenario in 14.99 seconds:
`/tmp/zasp-lineage-ack-installed-final.log`. The final test checks both device
and inode against the actual generation directory. The authoritative ledger
validator and all 27 ledger regressions passed, as did `git diff --check`.

Independent review found no production-code blocker. It requested exact physical
generation comparison in the composed test; that assertion now checks both device
and inode. Review does not approve reclamation, activation or shipping.

Linux ACK/consumer cases passed three repetitions as UID/GID 65532 with all
capabilities dropped. A separate root fixture with GID 65532 used SETUID/SETGID
to launch the non-root consumer and CHOWN solely to create foreign-owned scratch
for its rejection test. The non-root child consumed root-owned source, wrote a
consumer-owned 0440 receipt and still received permission errors when trying to
write producer chunks, scratch or lock. Directory-sync and foreign-owner tests
passed three repetitions too.

Both containers had 256 MiB/no-swap limits, 0.5 CPU, read-only root, no network,
128 MiB noexec/nosuid temporary storage, `GOMEMLIMIT=128MiB` and no healthcheck.
Both exited zero without OOM and were inspected before removal. Logs, inspection
and binaries remain; only the two owned exited proof containers were removed.
These are small-fixture component/permission runs, not full-daemon scale evidence.

Logs: `/tmp/zasp-lineage-ack-linux.log`,
`/tmp/zasp-lineage-ack-linux-permissions.log`,
`/tmp/zasp-lineage-ack-linux-inspection.log`.
Pinned arm64 image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Test binary: `/tmp/zasp-lineage-ack-linux.f3Bx72/sensor-agent.test`, SHA-256
`f575e3d6f508c3b6e36b34f9312a5bd6b20f76605c9ec2273dc72874cdd05e6f`.
Production Linux binary also builds at
`/tmp/zasp-lineage-ack-linux.f3Bx72/sensor-agent`, SHA-256
`87763a70907571b1885ad07d6f75f726f1ac3aa814ec89c7802fab9bb7f189b1`.

## Next boundary

The producer's independent read-only issuer/source/receipt verification is now
recorded in `docs/internal/2026-09-10-sensor-lineage-producer-receipt.md`. It does
not grant reusable deletion authority. Add crash-safe bounded
reclamation and generation rotation, then verify daemon/deployment lifetime and
permissions, live source compatibility, correlation activation and original
sandbox/cgroup/process source-to-browser acceptance. The whole branch still needs
full root release checks, composed Chrome and final review before a verified push.
