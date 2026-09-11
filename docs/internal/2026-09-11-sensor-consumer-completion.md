# The consumer now authenticates completion before deleting its checkpoint

This connects the checkpoint-retirement primitive to producer and consumer
evidence. It doesn't retire ACKs, collect producer completion records or activate
the daemon. The eight-completion limit remains. No production task credit changes.

`lineageCompletionReader` uses pinned read-only directory admission, shared with
the producer's receipt reader. Each protocol still validates its own payloads.
The completion reader can't create producer files or acquire producer writer
ownership. Its production constructor requires a Linux non-root consumer and a
root-owned 0750 spool under a protected parent. The explicit-UID constructor is
used by same-user fixtures, not claimed as deployed permission evidence.

`lineageAcknowledgments.RetireCheckpoint` holds ACK-store and completion-reader
lifetime mutexes. It reads one exact bounded canonical completion record, requires
the complete versioned contract, matches the separately supplied trusted source,
destination and consumer UID, and verifies the physical spool device/inode.
Both the original source name and tombstone must be absent. Missing completion is
distinct from invalid completion; neither causes deletion.

It pins the producer record and the exact consumer-owned ACK bytes retained in
that record. Before taking ACK writer ownership, the ACK directory must differ
by inode from the cursor directory, producer spool and every protected-input
parent. The cursor and producer spool must also differ. Reader/descriptor bounds
and configured consumer UID are checked before this mutation boundary.

A visible completion rename can precede the producer's directory sync. The
consumer syncs the read-only completion file and producer directory itself, then
revalidates the pinned evidence before invoking the credentialless checkpoint
primitive. Its authorization callback repeats these checks while the cursor's
existing filesystem lock is held. Changed record/ACK bytes or inodes, replaced
directories, returned source names and invalid lifetimes reject deletion.
Completion and ACK bytes remain intact after success, including an absent-cursor
retry. This is locally owned evidence, not cryptographic remote-service attestation.

## What ran

Superpowers isn't installed. The previously loaded official upstream test-first,
verification-before-completion and independent-review workflows remain the
disclosed fallback.

The initial rejecting stub failed genuine empty and nonempty retirement:
`/tmp/zasp-lineage-completion-red.log`.
The first implementation run also failed because the test fixture still held the
finished consumer's ACK writer lock. The fixture now explicitly closes that writer
after publication. A separate live-writer regression confirms that another active
ACK writer still blocks retirement. Corrected focused tests passed in 7.653 seconds:
`/tmp/zasp-lineage-completion-corrected-green.log`.

Independent review found that output-isolation checks needed to precede ACK lock
creation. The new regression first failed:
`/tmp/zasp-lineage-completion-isolation-red.log`.
Explicit inode checks corrected it; focused tests passed in 5.395 seconds:
`/tmp/zasp-lineage-completion-isolation-green.log`.

Negative cases cover wrong source, destination, consumer or spool; incomplete,
missing, malformed or unknown-field completion; missing or different ACK; ownership,
modes and links; returned source/tombstone; closed readers/stores; cancellation and
output overlap. During actual cursor flock ownership, tests replace completion,
ACK, spool or ACK directory, return the source or cancel. The original checkpoint
stays intact. Concurrent Close waits until retirement releases both borrowed
lifetimes. Boundary tests before the final Close addition passed in 5.748 seconds:
`/tmp/zasp-lineage-completion-boundaries.log`.

The compiled sensor test child now performs authenticated checkpoint retirement
after source reclamation in the actual local TLS/PostgreSQL acceptance scenario.
It opens no source reader, token file, CA or HTTP client. It pins the credential's
parent only for output isolation. The token file is physically unavailable during
retirement and its separate-process retry. Both succeed, leave the cursor absent,
preserve exact ACK/completion bytes and keep the existing three-request/two-artifact
trace unchanged. The earlier scenario checks two database batches, ten stage rows
and two outbox rows after response loss and credential rotation. Identity and
artifact storage are fixtures; this is not live Tetragon, S3 or browser proof.

The new composition assertion first failed before the child path existed:
`/tmp/zasp-lineage-completion-installed-red.log`.
Its next run exposed the fixture's 0700 spool, incompatible with the read-only
consumer's required 0750 mode. The fixture now starts at 0750; production admission
was not loosened. That failed attempt is
`/tmp/zasp-lineage-completion-installed-green.log` (despite the filename).
The corrected containing test and artifact regression passed in 30.834 seconds:
`/tmp/zasp-lineage-completion-installed-final.log`.

Full sensor-agent races passed in 50.934 seconds before the final test-only
additions, then in 46.791 seconds with them:
`/tmp/zasp-lineage-completion-full-agent.log` and
`/tmp/zasp-lineage-completion-final-agent.log`.

Linux component tests passed three repetitions as UID/GID 65532 without
capabilities. A separate root fixture with only SETUID/SETGID/CHOWN launched a real
non-root consumer, retained its private cursor and ACK, reclaimed source as root,
then launched the non-root consumer again. That process used the production
completion-reader constructor, retired its private checkpoint, retried without
source and failed to open the root-owned completion record for writing. UID0
cannot instantiate the production consumer reader. This also exercises read-only
file/directory sync against actual root-owned completion evidence.

All runs used no network, read-only root, 256 MiB/no swap, 0.5 CPU, 192 file
descriptors, GOMEMLIMIT=128MiB and 128 MiB noexec/nosuid temporary storage. The first
two proof containers exited zero without OOM. Logs:
`/tmp/zasp-lineage-completion-linux.log` and
`/tmp/zasp-lineage-completion-linux-permissions.log`.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Initial test binary: `/tmp/zasp-lineage-completion-linux.cCmTvc/sensor-agent.test`,
SHA-256 `ef9883516c58ab0ae248f6e92c2635c0e75cdcd1a10d24f63d2f8d3203495c7a`.
Production Linux binary: `/tmp/zasp-lineage-completion-linux.cCmTvc/sensor-agent`,
SHA-256 `bfec26503483ffc739b076628894ba2262e18e995a755e5232417a14319c9aa3`.
The final test binary adds concurrent Close and actual producer-directory-sync
failure tests without changing product code:
`/tmp/zasp-lineage-completion-linux.cCmTvc/sensor-agent-final.test`, SHA-256
`fbfe509c842551ec627efbf44bd6670c6e78356b322e10cfa5bf52c785cb62c5`.

The final Linux binary passed three repetitions, including concurrent Close and
an actual O_PATH producer-directory descriptor injected after cursor lock
acquisition. Metadata admission still succeeds, sync fails before checkpoint
deletion, and reopening normal handles allows retry. This tests the actual
filesystem error path, not power loss. Log:
`/tmp/zasp-lineage-completion-linux-final.log`.

Following the careful skill, cleanup inspected the exact three owned proof
containers, all exited zero without OOM, and removed only
`zasp-lineage-completion-20260911-a`, `zasp-lineage-completion-20260911-b` and
`zasp-lineage-completion-20260911-c`. Their disposable state is gone; logs and
binaries remain. Inspection: `/tmp/zasp-lineage-completion-linux-inspection.json`.

Independent review confirmed the isolation correction and found no further
concrete component blocker, conditional on the composed HTTPS and restricted Linux
lifecycle tests, which passed. This does not grant whole-branch shipping approval.

The preceding full root UI/build verification remains recorded in
`/tmp/zasp-lineage-reclaim-root-verify.log`; this slice changes only Go and docs.
No composed Chrome, entire API-suite or deployed-source claim is added.
The final ledger validator, all 27 ledger tests and `git diff --check` passed.

The next retirement-evidence and ACK/completion collection handshake is now
verified in `docs/internal/2026-09-11-sensor-retirement-handshake.md`.
Bounded automatic rotation, orphan recovery and daemon wiring remain next.
Original multi-tenant source-to-browser security, sandbox/cgroup/process acceptance
and remaining M48 gates still precede a verified main push.
