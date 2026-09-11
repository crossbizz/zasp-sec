# Consumer slots can retire without losing delivery evidence

The bounded slot component now supports authenticated retirement and release.
It isn't wired into the production daemon yet. All 728 tasks remain in scope;
counts stay 535 production-available, 132 component-only and 61 external gates.
M3-46, M3-47 and M7-07 receive no new credit. No activation or push.

## What changed

`lineageConsumerSlots.Retire` saves the exact assignment, full root-owned completed
reclamation record, original consumption ACK and physical ACK-directory identity
in a fixed `retirement-N.json` record before replacing that ACK. A bounded
`.retirement-N-UUID.pending` scratch supports interrupted publication. Both records
occupy the slot. There are still eight slots, with no per-generation history growth.

Retirement passes `ChunkStateBinding` into checkpoint deletion. The freshly opened
cursor directory, fixed cursor name, source identity, destination and physical
spool/source/state identities must match the saved assignment before authorization,
locking or deletion. This closes the pathname handoff boundary for retirement as
well as processing. A replaced ancestor can't redirect deletion to foreign state.

After the exact retired ACK is synced, the local record advances to `AckRetired`.
Producer collection can race with that phase update: the saved full proof remains
available even after the root completion record is gone. Prepared evidence never
authorizes release, and retirement state blocks further processing through that slot.

`Release` requires that ready evidence, matches any remaining ACK exactly, and
holds the existing cursor flock through all cleanup and directory-sync barriers.
It doesn't recreate a missing cursor lock. Source, completion, checkpoint and
temporary checkpoint state must be absent before exact assignment and retirement
record deletion. Each unlink is followed by directory synchronization. A stale
release can't remove a newer assignment. Missing files alone aren't delivery proof.

`ListRetiring` returns bounded hints, including ready evidence left after assignment
deletion. Every mutation reauthorizes that hint. Saved work without the persistent
controller lock is rejected before lock creation. Lock order remains slot store,
borrowed ACK store and producer directory; borrowed mutexes are released before
calling primitives that acquire them, while controller and cursor ownership remain.

## Tests and review

Superpowers isn't installed. The previously read official upstream test-first,
verification-before-completion and independent-review workflow remains the
disclosed fallback. Initial RED: `/tmp/zasp-lineage-slot-retirement-red.log`.
Independent review found no remaining concrete blocker in this bounded component,
conditional on the final Linux gates below. It didn't approve shipping, daemon
activation or task credit.

Cancellation and actual child-process exit cover nine publication/deletion stages:
evidence scratch, evidence publication, checkpoint removal, ACK retirement, phase
scratch, ready-phase publication, ACK forgetting, assignment removal and evidence
removal. Restart retains exact authority and completes safely. Tests also cover
immediate producer collection after ACK rename, busy/missing cursor locks, a
reappeared checkpoint, corrupt or hard-linked evidence, foreign ACKs, changed
assignments, unknown files, ancestor replacement and missing controller ownership.

Twenty-four generations alternate empty and event-bearing sources and reuse slot
zero. After each full cycle the consumer state has only its two persistent locks;
the producer and ACK directories each retain one lock. No history files accumulate.

Final focused races: 18.391 seconds,
`/tmp/zasp-lineage-slot-retirement-final-focused.log`.
Final ownership/slot races: 22.628 seconds,
`/tmp/zasp-lineage-slot-retirement-ownership.log`.
Full adapter races: 13.986 seconds,
`/tmp/zasp-lineage-slot-retirement-full-adapter.log`.
Final full sensor-agent races: 87.413 seconds,
`/tmp/zasp-lineage-slot-retirement-final-agent.log`.

The installed-child HTTPS/PostgreSQL test now performs first checkpoint deletion
through `Retire`, followed by producer reconciliation and `Release`. Each phase
retries in a separate child. The credential file is absent during retirement and
release, with zero token reads or HTTP requests in those phases. The delivery path
still has exactly three requests, two artifacts, two accepted batches, ten stage
rows and two outbox rows. Final state contains only the two consumer locks.
The containing API test and independent-artifact regression pass in 44.609 seconds:
`/tmp/zasp-lineage-slot-retirement-final-installed.log`.
TLS, handlers, PostgreSQL and compiled child execution are real. Provider identity
and artifact storage remain fixtures. This isn't live Tetragon, S3 or browser proof.

Final restricted Linux runs pass three repetitions without failures or skips:
`/tmp/zasp-lineage-slot-retirement-linux.log` and
`/tmp/zasp-lineage-slot-retirement-linux-permissions.log`.
Seven actual O_PATH directory-sync failure stages cover preparation, publication,
phase completion, ACK forgetting, assignment removal, evidence removal and ACK
phase durability. Normal-handle retry recovers. Root producer/non-root consumer
original and recovered lifecycles exercise the complete slot handshake.
These tests don't prove host power-loss recovery.

Both containers exited zero without OOM. Limits: no network, read-only root,
256 MiB/no swap, 0.5 CPU, 192 descriptors, 128 processes, GOMEMLIMIT=128MiB and
128 MiB noexec/nosuid temporary storage. Ordinary tests ran as UID/GID 65532 with
all capabilities dropped. Ownership tests used UID 0/GID 65532 with only
SETUID/SETGID/CHOWN. These aren't full-daemon resource measurements.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Test binary: `/tmp/zasp-lineage-slot-retirement.NPMx7W/sensor-agent.test`, SHA-256
`1ff2610ae45099086aca320db5c6776aa4a0510facb688e950d0401cfc77dff2`.
Production binary: `/tmp/zasp-lineage-slot-retirement.NPMx7W/sensor-agent`, SHA-256
`6165b5d528280ec53a046f4bc34f0012825c91cce607f52ef165f1a75b1ebe30`.

Following the careful skill, cleanup inspected then removed only the exited owned
containers `zasp-lineage-slot-retirement-20260911-a` and
`zasp-lineage-slot-retirement-20260911-b`. Their disposable container state is gone.
Logs, binaries and `/tmp/zasp-lineage-slot-retirement-linux-inspection.json` remain.

## Next

Follow-up: `2026-09-11-sensor-consumer-reconciliation.md` records the subsequently
implemented bounded consumer discovery/reconciliation tick.

Wire bounded consumer discovery/reconciliation, using saved source identities and
fixed slots, with local retirement independent of credential availability. Then
complete automatic rotation and daemon wiring, live Tetragon compatibility/emission,
full candidate correlation, browser acceptance and remaining M48 gates.

UI code didn't change in this slice. The preceding root verification remains
`/tmp/zasp-lineage-recovery-root-verify.log`, including 1,180 UI tests and production
build. Fresh whole-branch shipping checks and review are required before main.

The authoritative status check validates all 728 rows with unchanged counts;
all 27 ledger-check tests pass in `/tmp/zasp-lineage-slot-retirement-ledger.log`.
`git diff --check` passes.
