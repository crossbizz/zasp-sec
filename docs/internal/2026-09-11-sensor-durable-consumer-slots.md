# Consumer processing now has durable fixed slots

`lineageConsumerSlots` assigns producer generations to eight fixed cursor names.
Assignment is durable before processing starts. This is the reservation and
processing handoff portion of the consumer controller, not automatic discovery,
slot release or daemon activation.

The consumer owns a separate 0700 state directory. Admission opens it read-only,
checks its owner and protected parent, and rejects overlap with producer, ACK or
protected-input directories before any write. The first reservation takes a
persistent `.slots.lock` flock for the store lifetime. Each fresh assignment also
takes its fixed cursor flock, so a running cursor writer prevents assignment.
Both lock files and the directory are synced before publication. Locks aren't
unlinked by this API.

The canonical 0440 assignment binds slot number, exact source identity,
destination, consumer UID, state-directory identity, producer-spool identity and
source-directory identity. Matching UUID alone isn't idempotency. A copied state
file or a replacement physical source rejects.

Scratch names include the fixed slot and source UUID. They count as occupied and
can't cause the same generation to get a second slot. Partial bytes are resumed
only when they match the expected canonical assignment constructed from a
separately admitted source. Read-only scratch is reopened through a pinned inode
check before completing a partial write. Foreign or mismatching scratch remains
untouched. Scratch-only entries are bounded occupancy, not source or processing
authority.

The inventory accepts only eight assignment records, eight bounded scratch files,
the fixed cursor/checkpoint temporary/lock names and the controller lock. Duplicate
source assignments, assignment/scratch overlap, cursor state without assignment,
links, unknown files and unsafe modes reject. Inventory and pinned identities are
checked again during publication. A late conflicting assignment stops publication
and preserves scratch.

Publication syncs the exact file, renames it to its fixed assignment name and
syncs the state directory. Restart repeats those barriers for an existing exact
record. `List` is read-only and returns committed-assignment hints. `CursorPath`
takes controller ownership and re-syncs the exact record before returning a path.
No method releases assignments or treats a missing checkpoint/source as free.

Lock order is slot store, source reader when present, ACK store, producer directory,
then cursor flock. Borrowed readers and stores must outlive the slot store. The
processing layer separately acquires its cursor flock.

## Review found a pathname handoff bug

Pinned state-directory checks alone didn't make a returned absolute pathname safe.
Replacing an ancestor could leave the old held assignment valid while a new
processor opened a different directory at that path. The actual assigned-consumer
constructor regression failed before correction:
`/tmp/zasp-lineage-slots-handoff-red.log`.

`sensoradapter.ChunkStateBinding` now passes source identity, destination, fixed
cursor basename and all three directory device/inode pairs into processor
construction. `NewChunkProcessor` compares the newly opened roots, basename and
actual client's destination before creating a lock or writing state. It retains
those opened roots for processing, so later pathname replacement can't redirect
I/O. `newAssignedLineageChunkConsumer` supplies this binding from the assignment.
The generic consumer constructor doesn't provide slot binding and must not be used
for future slot-controller wiring.

The ancestor-replacement test now proves rejection with zero state writes,
credential reads and network calls. Separate adapter tests cover the exact binding
and nine mismatches. Independent re-review found no remaining concrete blocker in
this correction. It didn't approve daemon activation, task credit or shipping.

## Evidence

Superpowers isn't installed. The previously loaded official upstream test-first,
verification-before-completion and independent-review workflow remains the
disclosed fallback.

Initial stub RED: `/tmp/zasp-lineage-slots-red.log`.
The first implementation correctly rejected the test's non-private directory,
then exposed a scratch-validation mismatch. After correcting fixture permissions
and using a slot-specific pinned scratch validator, positives passed in 2.684
seconds: `/tmp/zasp-lineage-slots-second-green.log`.

Boundary cases include five interrupted publication states, four actual child
process deaths, partial/read-only scratch, controller and live cursor contention,
foreign/copied/duplicate history, protected-input isolation, source replacement,
late publication conflicts and the pathname handoff regression. Filling eight
slots, reclaiming the original producer source and attempting a ninth assignment
still refuses reuse. Saved assignment history remains intact.

Final focused slot/consumer races passed in 8.030 seconds:
`/tmp/zasp-lineage-slots-handoff-final.log`.
Chunk-processing and binding races passed in 8.621 seconds:
`/tmp/zasp-lineage-slots-chunk-binding.log`.
Final full adapter races passed in 14.231 seconds:
`/tmp/zasp-lineage-slots-final-adapter.log`.
Final full sensor-agent races passed in 72.540 seconds:
`/tmp/zasp-lineage-slots-final-agent.log`.

The actual local HTTPS/PostgreSQL test now uses `consumer-state/cursor-0.json`
through durable slot reservation and the assigned consumer constructor. It reserves
before opening the token and reuses the same assignment in separate sensor child
processes across lost-response replay and credential rotation. Original authority,
three requests, two artifacts, two database batches, ten stage rows and two outbox
rows remain exact. Checkpoint/ACK retirement leaves assignment history and the two
persistent lock files. The containing API test and artifact regression passed in
46.271 seconds: `/tmp/zasp-lineage-slots-final-installed.log`.
TLS, handlers and PostgreSQL are real; source identity and artifact storage remain
fixtures. This isn't live Tetragon, S3 or browser evidence.

Restricted Linux slot tests passed three repetitions:
`/tmp/zasp-lineage-slots-linux-final.log`.
Six actual O_PATH directory-sync failures cover pre-reservation, empty scratch,
written scratch, published assignment, idempotent retry and cursor-path return.
Failure doesn't expose a usable assignment; normal-handle retry recovers.
Root producer/non-root consumer original and recovered lifecycles each passed
three repetitions through assigned processing:
`/tmp/zasp-lineage-slots-linux-permissions-final.log`.
Process death and injected sync failure don't prove host power-loss behavior.

Accepted runs exited zero without OOM or selected-test skips. They used no network,
read-only root, 256 MiB/no swap, 0.5 CPU, 192 descriptors, 128 processes,
GOMEMLIMIT=128MiB and 128 MiB noexec/nosuid temporary storage. Ordinary tests used
UID/GID 65532 and no capabilities. The ownership fixture used UID 0/GID 65532 with
only SETUID/SETGID/CHOWN. These limits aren't full-daemon resource proof.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Final test binary: `/tmp/zasp-lineage-slots-final.b399hE/sensor-agent.test`, SHA-256
`86bcea66030084edce152a8a41874d9b37c06e9712db8c63b3d0bb32037eabf9`.
Production Linux binary: `/tmp/zasp-lineage-slots-final.b399hE/sensor-agent`, SHA-256
`69ae964d168962ad3d1e9368bae38b90dd238524ffb3e0c8402d1993aba9de14`.

Following the careful skill, cleanup inspected and removed only the four exited
owned containers `zasp-lineage-slots-20260911-a` through `-d`. Their disposable
state is gone. Logs, binaries and `/tmp/zasp-lineage-slots-linux-inspection.json`
remain. The final pair includes the reviewed handoff correction; the earlier pair
doesn't substitute for those final gates.

## Next critical path

Follow-up: `2026-09-11-sensor-slot-retirement.md` records the subsequently verified
authenticated retirement and release implementation. This document's evidence
describes the earlier reservation-only slice.

Persist authenticated retirement evidence before forgetting consumer ACKs, release
only the exact assigned slot under its cursor lock and durability barriers, then
wire bounded consumer discovery/reconciliation and automatic rotation. Live
Tetragon compatibility/emission, complete candidate correlation, browser acceptance
and remaining M48 gates also stay open. M3-46, M3-47 and M7-07 receive no credit.
Counts remain 535 production-available, 132 component-only and 61 external gates.
No activation or push.

UI code didn't change in this slice. The preceding root verification is still
`/tmp/zasp-lineage-recovery-root-verify.log`, including 1,180 UI tests and production
build. Fresh whole-branch shipping checks and review remain required before main.
