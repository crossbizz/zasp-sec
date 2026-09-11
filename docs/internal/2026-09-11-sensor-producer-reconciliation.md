# The producer can find its own restart work

Follow-up: `2026-09-11-sensor-durable-consumer-slots.md` adds durable fixed consumer
assignment and an identity-bound processing handoff. Slot release, consumer
reconciliation and daemon activation remain open.

`ListProducerWork` and `ReconcileProducer` now compose the existing bounded
reservation, interrupted-source, reclamation and completion protocols. This is
one local reconciliation tick. It isn't wired into the production daemon yet.

The caller supplies enrollment binding, canonical HTTPS destination and consumer
UID from trusted installation configuration. Enumeration holds the producer
lifetime mutex and checks the complete eight-directory/eight-marker inventory
before any mutation. Source identity comes from producer-owned manifests or
physically bound reclaim records, never from consumer ACK files or current host
identity. A mixed enrollment, destination or issuer rejects the whole snapshot.

Private reservation metadata must match every enrollment byte present, even if
startup stopped partway through that value. The scoped discard path repeats that
check during mutation, so a valid foreign manifest substituted after discovery
isn't deleted. Existing unscoped `DiscardUnpublished` keeps its local producer
namespace contract. Public history never becomes private startup work.

Durable reclaim intents run first because operations share one bounded scratch
slot. Active generations are skipped. Inactive unsealed sources close with
explicit unknown counters and incomplete coverage. Each mutation still uses its
own pinned identity, filesystem ownership, sync and authorization checks; the
snapshot is only a work list. New generations created after discovery wait for
the next tick. No event append is resumed on historical sources.

One failed item produces a fixed operation-category error and doesn't prevent
independent work. Missing ACKs wait. After reclamation, an original ACK waits only
if its canonical contents exactly match the completed producer intent. A valid
retirement ACK permits the existing completion-collection primitive to recheck
and act. Malformed or foreign receipts remain errors. No token, API client or
consumer cursor is opened by the producer tick.

## What the tests establish

Superpowers isn't installed. The previously loaded official upstream test-first,
verification-before-completion and independent-review workflow is the disclosed
fallback, not an installed-plugin pass.

The initial positive tests failed against the stub:
`/tmp/zasp-lineage-producer-controller-red.log`.
The first implementation reclaimed sources but misclassified the still-original
ACK as a collection error. That run is retained at
`/tmp/zasp-lineage-producer-controller-first-green.log`; despite the filename,
it failed. Exact-original-ACK waiting corrected it, and both positive tests
passed in 2.540 seconds:
`/tmp/zasp-lineage-producer-controller-second-green.log`.

Boundary tests passed in 8.461 seconds:
`/tmp/zasp-lineage-producer-controller-boundaries.log`.
They cover mixed-scope rejection before private deletion, private enrollment
replacement after discovery, malformed receipt preservation with independent
source closure, invalid configuration/lifetimes, and all nine interrupted reclaim
states. Durable intents precede unrelated private cleanup. Initial scratch without
a durable owner can delay that cleanup one tick, but doesn't starve the matching
ACKed source.

The final focused race run passed in 10.928 seconds:
`/tmp/zasp-lineage-producer-controller-final-focused.log`.
It adds actual child-process death at all nine reclaim boundaries and a new active
generation created after snapshot admission. Restart reacquires producer ownership,
discovers the saved work and completes source reclamation. The live generation
stays writable and unsealed. Process death isn't power-loss evidence.

Full sensor-agent races passed in 65.377 seconds:
`/tmp/zasp-lineage-producer-controller-full-agent.log`.
That run preceded the final two test-only additions; the focused run covers them.
No production implementation changed afterward.

The compiled sensor subprocess in the actual local HTTPS/PostgreSQL scenario now
uses the discovery tick for source reclamation and completion collection. It runs
with the token physically unavailable, makes zero credential reads/extra requests,
and retains the existing exact evidence checks: three HTTP requests, two artifacts,
two database batches, ten stage rows and two outbox rows. The containing API test
and independent-artifact regression passed in 48.200 seconds:
`/tmp/zasp-lineage-producer-controller-installed.log`.
TLS, handlers and PostgreSQL are real. Source identity and artifact storage are
fixtures. This isn't live Tetragon, S3 or browser evidence.

## Linux and ownership

The controller, nine process-death boundaries, reservation sync failures, original
ACK durability and retirement sync-failure regressions passed three repetitions:
`/tmp/zasp-lineage-producer-controller-linux-final.log`.
The root producer/non-root consumer fixture now invokes the controller for both
producer phases. Original and recovered-source lifecycles each passed three times:
`/tmp/zasp-lineage-producer-controller-linux-permissions-final.log`.
The consumer still can't write producer files.

Independent final review accepted this bounded component with no remaining
concrete issue in the reviewed source and test additions. That acceptance doesn't
cover daemon activation, live-source collection, task credit or shipping.

Both accepted runs exited zero without OOM. They had no network, read-only root,
256 MiB/no swap, 0.5 CPU, 192 descriptors, 128 processes, GOMEMLIMIT=128MiB and
128 MiB noexec/nosuid temporary storage. Ordinary tests used UID/GID 65532 with
all capabilities dropped. Permission tests used UID 0/GID 65532 with only
SETUID/SETGID/CHOWN. These bounds don't prove a full daemon's host-disk behavior.

Two earlier harness attempts don't count: the first inherited the image's default
entrypoint and exited 1; the second used GID 0 and skipped the permission tests.
Their logs and metadata remain. The accepted runs explicitly selected the test
binary and correct group, with no skips in the selected cases.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Test binary: `/tmp/zasp-lineage-producer-controller-linux.iR9fN2/sensor-agent.test`,
SHA-256 `42f7b1d30093fd93689942414b3ae241975c97ca8fad9c1580102f8d9ce72a01`.
Production Linux binary: `/tmp/zasp-lineage-producer-controller-linux.iR9fN2/sensor-agent`,
SHA-256 `029a1b2ee410aaf30f921b20e881a26722b21c55053111d25e24ac6a1d473fcf`.

Following the careful skill, cleanup inspected and removed only the four exited
owned containers `zasp-lineage-producer-controller-20260911-a` through `-d`.
Their disposable state is gone. Logs, binaries and
`/tmp/zasp-lineage-producer-controller-linux-inspection.json` remain.

## Still open

Consumer discovery with durable eight-slot assignment, automatic rotation, daemon
wiring, live Tetragon compatibility/emission, full candidate correlation, browser
acceptance and remaining M48 gates still need implementation or proof. M3-46,
M3-47 and M7-07 stay open. Counts remain 535 production-available, 132
component-only and 61 external gates. No new task credit, activation or push.

The preceding root verification remains
`/tmp/zasp-lineage-recovery-root-verify.log`, with 1,180 UI tests and the production
build. This slice didn't change UI code. Whole-branch review and fresh shipping
gates remain required before main publication.
