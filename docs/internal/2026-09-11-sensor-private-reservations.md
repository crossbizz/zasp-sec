# Startup failures no longer need a public generation name

Follow-up: `2026-09-11-sensor-producer-reconciliation.md` adds automatic producer
enumeration and scoped reservation cleanup within a bounded reconciliation tick.
Consumer slot assignment and production daemon activation remain open.

`lineageSpool.Create` now reserves `.creating-UUID`, not `generation-UUID`.
The private name counts against the same eight-directory quota. Create publishes
and syncs the canonical manifest there, changes the directory to 0750, then
atomically renames it to the public generation name and syncs the parent before
returning the active writer. The returned root has the public path and retains
the admitted physical directory identity.

No event writer can operate in the private namespace. `generation.valid` requires
the public name and active producer ownership. Consumers also admit only public
generation names. After public rename, any error leaves established history for
`SealInterrupted`; cleanup never falls back to startup discard.

This closes the pre-manifest crash gap for new creations. Public 0700 directories
from the earlier, unshipped implementation remain preserved, not automatically
migrated or deleted.

## Discard isn't reclamation

`DiscardUnpublished(ctx, id)` holds the existing producer mutex and filesystem
ownership lock. It accepts only `.creating-ID` and its `.discard-ID` retry state.
Its authority is the producer-owned startup namespace contract, not an inference
that missing event files prove delivery.

An admitted directory has the exact producer owner, mode 0700 or 0750, and zero
or one file. A final `manifest.json` must be the complete canonical manifest with
the matching UUID. Scratch must be a bounded prefix of the actual manifest
grammar: fixed versions, profile and UUID, then bounded enrollment, node and UUID
fields. Generic JSON prefixes don't grant cleanup permission. Create now uses the
same Kubernetes node-name admission as its consumer reader.

Metadata and directory handles stay pinned. Discard syncs them and the parent,
renames the directory to `.discard-ID`, then syncs the parent before deleting its
admitted metadata. It syncs the empty directory, removes it and syncs the parent's
absence. Empty-state retry still establishes durability. It never claims delivery
or accesses a token, cursor, ACK or service API.

Unknown files, chunks, two metadata files, malformed values, wrong IDs, unsafe
modes, symlinks, hardlinks and conflicting names stop cleanup. Public sources,
reclamation tombstones and completion records aren't reservations. UUID collisions
across all private/public states also prevent Create.

## The late-conflict test mattered

The initial implementation checked conflicts at admission, but a public name
injected after discard rename could still be followed by metadata deletion.
The regression failed on that outcome:
`/tmp/zasp-lineage-reservation-conflict-red.log`.

Every reservation validation now rejects other names for the UUID, including
before each mutation and after sync boundaries. The corrected test preserves its
pinned manifest. Independent review found no remaining concrete component blocker,
conditional on the hostile, crash and Linux gates, which passed. This isn't
controller or production activation approval.

## Verification

Superpowers isn't installed. The official upstream test-first,
verification-before-completion and independent-review workflows loaded earlier
remain the disclosed fallback.

Initial RED tests demonstrated public exposure of incomplete manifests and missing
private cleanup: `/tmp/zasp-lineage-reservation-red.log`.
The initial reservation, spool and interrupted-history tests passed in 13.983
seconds: `/tmp/zasp-lineage-reservation-first-green.log`.
Expanded prefix, hostile-input and process-death tests passed in 3.002 seconds:
`/tmp/zasp-lineage-reservation-boundaries.log`.

Prefix tests check every byte cut of real canonical manifests, including a
253-character node. Wrong versions, IDs, enrollment/UUID characters and
noncanonical final JSON reject. Hostile filesystem cases preserve their original
bytes and modes after rejection.

Creation cancellation covers empty staging, synced scratch, private manifest,
readable private directory and public rename. Separate child processes exit at
those five boundaries, plus discard rename, metadata removal and directory
removal. Restart reacquires ownership and finishes the appropriate path. Private
stages disappear; public history stays and receives incomplete-coverage closure.
This is process-death evidence, not a power-loss claim.

The capacity regression retains an established event generation, fills seven
slots with private reservations, verifies ninth-slot refusal, discards those
reservations and creates a new generation. Existing event bytes don't change.
Final full sensor-agent races passed in 62.004 seconds:
`/tmp/zasp-lineage-reservation-full-agent.log`.

The actual local HTTPS/PostgreSQL scenario leaves a private manifest through real
Create, then invokes discard twice in separate compiled sensor processes while its
token is physically unavailable. Those phases make no token reads or requests.
Established-source recovery, replay and rotation, acknowledgment, reclamation and
the full retirement handshake then run. The existing three requests, two
artifacts, two database batches, ten stage rows and two outbox rows remain.
The containing API test and artifact regression passed in 43.258 seconds:
`/tmp/zasp-lineage-reservation-installed.log`.
TLS and PostgreSQL handlers are real. Provider identity and artifact storage are
fixtures; no live Tetragon, S3, Chrome or daemon proof is added.

Restricted Linux tests passed three repetitions:
`/tmp/zasp-lineage-reservation-linux.log`.
Six actual O_PATH parent-directory sync failures cover pre-publication, public
rename, pre-discard, discard rename, metadata removal and directory removal.
Failure never reports success; normal-handle restart finishes. Pre-discard and
rename-barrier failures retain metadata. Established-source recovery and retirement
regressions also pass in that run.

Root/non-root original and recovered lifecycles each passed three repetitions:
`/tmp/zasp-lineage-reservation-linux-permissions.log`. Public creation through the
new staging path remains readable to the separate consumer, which still can't
write producer files. Cleanup retains the separate ownership boundaries.

Both containers exited zero without OOM. They used no network, read-only root,
256 MiB/no swap, 0.5 CPU, 192 descriptors, 128 processes, GOMEMLIMIT=128MiB and
128 MiB noexec/nosuid temporary storage. The ordinary run used UID/GID 65532 with
all capabilities dropped. The permission fixture used root with only
SETUID/SETGID/CHOWN. This isn't full-daemon or persistent host-disk resource proof.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Test binary: `/tmp/zasp-lineage-reservation-linux.XzND4X/sensor-agent.test`, SHA-256
`47db8abf5b24811c7126426228ef27add3b404a88762426b52a5e5471bdef72c`.
Production Linux binary: `/tmp/zasp-lineage-reservation-linux.XzND4X/sensor-agent`,
SHA-256 `1dc143f91ce372d2947894d5adc3ccc741ebebc29806ad05476a1ea440604677`.

Following the careful skill, cleanup inspected the exact owned exited containers
and removed only `zasp-lineage-reservation-20260911-a` and
`zasp-lineage-reservation-20260911-b`. Their disposable state is gone. Logs,
binaries and `/tmp/zasp-lineage-reservation-linux-inspection.json` remain.

The preceding full root verification remains
`/tmp/zasp-lineage-recovery-root-verify.log`, including 1,180 UI tests, typecheck,
lint, production build and compiled-import checks. This slice changes Go and docs,
not UI. No fresh whole API-suite or Chrome claim is added.

The final authoritative ledger validates all 728 rows. All 27 ledger regression
tests and `git diff --check` pass.

Next: bounded enumeration, cursor-slot assignment and the automatic producer and
consumer controller. Live provider compatibility, original sandbox/cgroup/process
source-to-browser acceptance, remaining M48 gates and whole-branch verification
still precede a main push. Counts stay 535 production-available, 132 component-only
and 61 external gates. No activation or task credit.
