# Finished generations release their bounded metadata slots

The producer and consumer now complete a three-phase retirement handshake. This
extends authenticated checkpoint retirement without activating the daemon or
granting production task credit. Fresh generation UUIDs are still required.

1. The consumer authenticates the exact producer completion and original ACK,
   retires the matching committed checkpoint, then replaces that ACK with a
   canonical `tetragon-retirement-ack-v1` record in the same bounded slot.
2. The producer validates this record against the exact completion digest,
   trusted request and physical spool/ACK directories. It syncs the retirement
   evidence before deleting and syncing the matching completion record.
3. The consumer establishes durable absence of the completion and source names,
   then removes and syncs its retirement ACK. Persistent ownership locks remain.

`RetireAcknowledgment`, `CollectCompletion` and `ForgetRetirement` pin directory
lifetimes and exact file bytes/inodes throughout their authority boundaries.
Original ACKs, wrong requests, different physical directories, changed completion
digests and active or returned sources don't authorize collection. The producer
never writes consumer state. The non-root consumer never writes producer state.

Already-retired retries re-establish durability without opening or deleting the
cursor. A later generation can therefore reuse the cursor slot safely. Matching
publication scratch is recoverable only when its owned, bounded bytes are an
exact prefix of the intended retirement record; unrelated scratch is preserved.
An absent-state retry means the directories are clean, not that former delivery
has been proved. It doesn't open or delete a checkpoint.

The handshake removes completed metadata rather than keeping permanent UUID
tombstones. It cannot prove that an old UUID has never been used after all its
metadata has been collected. Production generation creation uses fresh random
UUIDs. The eight-slot bounds still limit concurrent unfinished work, not lifetime
generation count. Automatic cursor-slot assignment, generation rotation and
orphan/unsealed-generation recovery remain unwired.

## An additional durability gap was found and fixed

Fresh source reclamation previously admitted a visible original ACK without
establishing that its rename was durable. A Linux O_PATH ACK-directory test
demonstrated source deletion despite an unusable directory-sync descriptor:
`/tmp/zasp-lineage-retirement-ack-barrier-red.log` (expected failing test).

The producer now calls `syncAcknowledgment` after repeated exact admission and
before opening reclamation inventory handles or publishing initial intent. It
pins the exact admitted ACK, syncs its file and directory, then rechecks bytes,
identity, reader lifetime and cancellation. Failure leaves source and intent
untouched. Recovery from an already durable producer intent remains independent
of mutable consumer ACK state. The new Linux regression passes after this fix.

## Verification and review

Superpowers isn't installed. The previously loaded official upstream test-first,
verification-before-completion and independent-review workflows are the disclosed
fallback, not an installed-plugin pass.

The initial rejecting implementation failed the handshake tests:
`/tmp/zasp-lineage-retirement-red.log`. Focused tests then passed in 8.219 seconds.
The expanded capacity and recovery set passed in 10.424 seconds:
`/tmp/zasp-lineage-retirement-first-green.log` and
`/tmp/zasp-lineage-retirement-recovery.log`.

Recovery covers cancellation and actual child-process death at five boundaries:
checkpoint removal, retirement scratch, retirement publication, completion removal
and retirement removal. Each reopens handles and finishes the handshake. Twenty-four
fresh generations alternate empty and nonempty input through one spool, ACK store
and cursor slot. Each cycle finishes with only one persistent lock in each
directory, preserving the cursor lock inode. This is bounded reuse evidence, not
fleet throughput or live provider proof.

The actual local HTTPS/PostgreSQL installation test invokes all three operations
twice in separate compiled sensor processes while the token file is physically
unavailable. They perform no token reads or extra requests. The existing trace
remains three requests and two artifacts, with the earlier two batches, ten stage
rows and two outbox rows retained. The first composition assertion failed before
the child paths existed in
`/tmp/zasp-lineage-retirement-installed-red.log`. Final containing-test and artifact
regression verification passed in 45.376 seconds:
`/tmp/zasp-lineage-retirement-installed-final.log`.
TLS and PostgreSQL handlers are real; source identity and artifact storage remain
fixtures. This doesn't prove live Tetragon, S3 or composed browser behavior.

Final full sensor-agent race tests passed in 57.575 seconds:
`/tmp/zasp-lineage-retirement-final-agent.log`.
Final Linux tests passed three repetitions, including the original ACK barrier,
five actual O_PATH directory-sync failure stages, crash recovery, 24-generation
reuse and the 128-chunk descriptor-bound regression:
`/tmp/zasp-lineage-retirement-linux-final.log`.
The root/non-root lifecycle passed three repetitions in 0.92, 0.82 and 0.88 seconds:
`/tmp/zasp-lineage-retirement-linux-permissions-final.log`. The non-root consumer
uses the production completion-reader constructor and cannot modify producer
files even after final collection.

Both final containers exited zero without OOM. They used no network, read-only
root, 256 MiB/no swap, 0.5 CPU, 192 descriptors, GOMEMLIMIT=128MiB and 128 MiB
noexec/nosuid temporary storage. The ordinary run used UID/GID 65532 and no
capabilities. The permission fixture used root with only SETUID/SETGID/CHOWN to
launch and check the separate consumer identity.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Final test binary: `/tmp/zasp-lineage-retirement-linux.GAYaC0/sensor-agent-final.test`,
SHA-256 `96d294164272cfc6c8b827fe2cf349f7db9138e89750ba61522215279bef03bb`.
Final production Linux binary: `/tmp/zasp-lineage-retirement-linux.GAYaC0/sensor-agent-final`,
SHA-256 `cfb58d925463ae9cc9b6903c0ef432ca51ec7627b973b459e1b0658e435de867`.

Independent review confirmed the original ACK barrier and found no remaining
concrete protocol blocker, conditional on the final Linux gates above, which
passed. This isn't daemon activation or whole-branch shipping approval.

Following the careful skill, cleanup inspected all five exact owned containers,
then removed only `zasp-lineage-retirement-20260911-a`,
`zasp-lineage-retirement-20260911-b`, `zasp-lineage-retirement-20260911-red`,
`zasp-lineage-retirement-20260911-final` and
`zasp-lineage-retirement-20260911-permissions-final`. Their disposable state is
gone; logs, binaries and inspection metadata remain. Inspection:
`/tmp/zasp-lineage-retirement-linux-inspection.json`. The RED container's exit 1
was expected; the other four exited zero, all without OOM.

The preceding root UI/build verification remains
`/tmp/zasp-lineage-reclaim-root-verify.log`. This slice changes Go and docs, not UI.
It adds no fresh full API-suite, Chrome, deployed-source or production task claim.
The final 728-row ledger validator, all 27 ledger regression tests and
`git diff --check` passed.
Counts remain 535 production-available, 132 component-only and 61 external gates.
Established interrupted-generation recovery now follows in
`docs/internal/2026-09-11-sensor-interrupted-generation-recovery.md`. Pre-manifest
reservation recovery and automatic control remain open.
No push. Remaining M48 acceptance, daemon/recovery/rotation, live source and
original sandbox/cgroup/process source-to-browser gates still precede shipping.
