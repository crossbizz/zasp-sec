# Consumer discovery and reconciliation

The consumer now has a bounded discovery/reconciliation tick. It discovers public
producer generations, resumes durable assignments, processes one chunk per source,
ACKs a fully committed closed source, and retires/releases saved work. The daemon
doesn't invoke this controller yet. No activation, task credit or push.

All 728 original tasks remain in scope. Counts stay 535 production-available,
132 component-only and 61 external gates. M3-46, M3-47 and M7-07 stay open.

## Identity and ownership

`ListConsumerWork` reads the pinned producer directory and private slot inventory.
Enumeration accepts at most eight producer directories and eight reclaim records,
plus their fixed lock/scratch entries, and merges these with eight local slots.
Public manifests and physically bound producer reclaim records provide source
identity. It never constructs historical identity from the current host or an ACK.

Every public reader must reopen the same physical producer directory. Its source
and device/inode must match any saved assignment. Reclaim records must match trusted
enrollment, destination, consumer UID, generation name and producer physical root;
any surviving source must match the record's source identity. An incomplete record
is waiting producer work, including after source-directory removal. Completed
records cannot coexist with a source directory.

Root-owned private startup directories count against capacity but aren't opened,
adopted or deleted by the consumer. Unknown entries, duplicate UUID states, missing
producer ownership, foreign scope and conflicting history reject the snapshot
before consumer writes. Producer publication can race a snapshot and invalidate
that tick; callers must retry observation, not report such a race as proven data
corruption.

The first boundary tests found that an orphan assignment scratch was ignored.
Enumeration now requires a matching admitted public source for that scratch.
Missing-source scratch is preserved and rejected; `Reserve` still checks the exact
canonical prefix and physical binding before resuming it.

## One bounded tick

`ReconcileConsumer` serializes ticks on the slot store. Local retirement runs first,
then saved assignments, then new sources in generation-ID order. One failing item
doesn't prevent independent work in the validated snapshot. Each public source gets
at most one chunk-processing attempt per tick, with at most eight public sources.
Retirement and release use the already verified exact-evidence primitives.

Processing reopens the source and compares its snapshot identity before reserving
state. It then uses the fixed slot cursor and physically bound assigned-consumer
constructor. A sealed source receives an ACK only after durable committed progress
reaches its exact final sequence and `Acknowledge` verifies the full consumption
proof. Open or unfinished sources wait. No-source evidence alone never frees an
assignment.

A nil upload client still permits local retirement and release. Tests cover a
completed generation alongside a new public source with no client: cleanup
continues, the upload failure is reported, and the new source isn't assigned.
Progress counters describe successful operations in the current tick, including
idempotent retries; they aren't unique-generation or upstream-coverage counters.

## Evidence

Superpowers isn't installed. The previously read official upstream test-first,
verification-before-completion and independent-review workflow remains the
disclosed fallback. Initial RED: `/tmp/zasp-lineage-consumer-controller-red.log`.
Initial controller lifecycle races pass in 3.654 seconds:
`/tmp/zasp-lineage-consumer-controller-first-green.log`.
The orphan-scratch regression failed in
`/tmp/zasp-lineage-consumer-controller-boundary-red.log` before its correction.

Tests discover three generations without writing state, process two event-bearing
sources one chunk each per tick, and complete the empty-source ACK and cleanup
cycle. Boundary coverage includes foreign metadata, source replacement after
snapshot, a missing assigned source, incomplete reclaim transitions, private
startup, interrupted reservation recovery, evidence-only cleanup after assignment
unlink, concurrent ticks, cancellation and an independently progressing source
beside a busy cursor.

Controller plus slot/retirement focused races pass in 25.288 seconds:
`/tmp/zasp-lineage-consumer-controller-focused.log`.
Full sensor-agent races pass in 89.990 seconds:
`/tmp/zasp-lineage-consumer-controller-full-agent.log`.
The final controller-focused races, including the two subsequently added
mixed-client/cancellation tests, pass in 7.567 seconds:
`/tmp/zasp-lineage-consumer-controller-final-focused.log`.
No adapter production code changed in this slice.

The installed-child HTTPS/PostgreSQL fixture now uses the controller for the second
actual event upload and for both local retirement phases. Credential-free phases
run with the token file physically absent. Lost-response replay, original authority,
three HTTP requests, two artifacts, two accepted batches, ten stage rows and two
outbox rows remain exact. The containing API test and independent-artifact
regression pass in 40.091 seconds:
`/tmp/zasp-lineage-consumer-controller-installed.log`.
TLS, handlers, PostgreSQL and compiled children are real. Provider identity and
artifact storage remain fixtures. This isn't live Tetragon, S3 or browser proof.

Independent review found no remaining concrete blocker in this bounded component
or the orphan-scratch correction. Acceptance remained conditional on Linux and
HTTPS/PostgreSQL gates. It didn't approve daemon activation or shipping.

Restricted Linux controller tests pass three repetitions in
`/tmp/zasp-lineage-consumer-controller-linux-final.log`. Root producer/non-root
consumer original and recovered source lifecycles pass three repetitions in
`/tmp/zasp-lineage-consumer-controller-linux-permissions.log`, now using the
controller for automatic reservation, processing, ACK, retirement and release.
Selected tests have no skips or failures; containers exited zero without OOM.

Runs used no network, read-only root, 256 MiB/no swap, 0.5 CPU, 192 descriptors,
128 processes, GOMEMLIMIT=128MiB and 128 MiB noexec/nosuid temporary storage.
Ordinary tests used UID/GID 65532 with all capabilities dropped. Ownership tests
used UID 0/GID 65532 with only SETUID/SETGID/CHOWN. These limits aren't full-daemon
resource proof or host power-loss evidence.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Final controller test binary:
`/tmp/zasp-lineage-consumer-controller.eNN1D7/sensor-agent-final.test`, SHA-256
`a2542292552fb648dbaf5ebe808c309be83d4b42fa45f4557aedfca5fec0bf0d`.
Ownership test binary: `/tmp/zasp-lineage-consumer-controller.eNN1D7/sensor-agent.test`,
SHA-256 `c90da6df1042c8db2dda690bda9e94329dcf6f42f558daf2fab8176fcecc988a`.
That binary preceded only the final two extra controller tests; production code
and the ownership tests are identical. Production Linux binary:
`/tmp/zasp-lineage-consumer-controller.eNN1D7/sensor-agent`, SHA-256
`0bd441d291205be10d95d7e946dd5aa6cb062a108a9190490f392d1aed572eac`.

Following the careful skill, cleanup inspected and removed only the three exited
owned containers `zasp-lineage-consumer-controller-20260911-a`, `-b` and `-c`.
Their disposable state is gone. Logs, binaries and
`/tmp/zasp-lineage-consumer-controller-linux-inspection.json` remain. The final
ordinary run was `-c`; the earlier `-a` log is preliminary evidence.

## Still on the critical path

Follow-up: `2026-09-11-sensor-producer-daemon.md` records timed rotation and the
explicit producer executable role. Consumer-role and deployment wiring remain.

Wire producer rotation and both controllers into the installed daemon lifecycle,
preserving the root producer/non-root consumer boundary. Complete live pinned
Tetragon compatibility/emission, all original sandbox/container/cgroup/process
candidate correlation, browser acceptance and remaining M48 gates. Component
success doesn't close these requirements.

UI code didn't change here. The preceding root verification remains
`/tmp/zasp-lineage-recovery-root-verify.log`, including 1,180 UI tests and production
build. Fresh whole-branch shipping checks and review are required before main.

The authoritative ledger check validates all 728 rows with unchanged counts.
All 27 ledger-check tests pass in `/tmp/zasp-lineage-consumer-controller-ledger.log`;
`git diff --check` passes.
