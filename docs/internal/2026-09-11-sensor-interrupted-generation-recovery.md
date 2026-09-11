# Interrupted history can finish delivery and cleanup

`lineageSpool.SealInterrupted` closes an established generation after its producer
stops. It never resumes event append. The caller supplies the trusted source;
the method holds producer ownership, rejects an active target and pins its exact
canonical manifest, physical directory and bounded file inventory.

Every numbered chunk must pass complete decoding with a contiguous sequence and
the same source manifest. Recovery recomputes record and byte totals. A complete
pending next chunk is promoted only after validation and file/directory sync.
A complete pending seal must match the independently recomputed totals and exact
fragment state before promotion. Existing sealed history is verified and synced,
not rewritten.

Partial scratch survives as `interrupted.bin`, frozen at 0440. Its exact bytes,
including an empty file, remain private producer evidence. The recovery seal binds
its SHA-256 and byte length; it doesn't count those bytes as submitted records.
Consumers verify the fragment with the seal. Only subsequent authenticated
consumption and the existing producer reclamation protocol can delete it.
Complete conflicting chunk/seal objects, holes, unsafe files, changed identities,
unknown entries and quota violations reject recovery without rewriting history.

Restart seals say `reason: producer_restart`, `counters_unknown: true` and
`coverage_complete: false`. Dropped and filtered values aren't known zero after a
crash. They remain numerically zero with an explicit unknown flag, which future
controller/API reporting must honor. Original fully written seals retain their
original known counters. These are local source facts, not a remote delivery
attestation or proof that the provider emitted every event.

## Scratch needed a correction

The first independent review caught a real preservation error. A torn chunk
prefix such as `{"version":"tetragon-` also prefixes the intended restart seal.
Treating matching bytes as sufficient seal-scratch provenance deleted the original
fragment. The new regression reproduced that loss:
`/tmp/zasp-lineage-recovery-prefix-red.log`.

Recovery now preserves ambiguous initial scratch. Prefix cleanup requires an
already retained fragment phase, whose file and directory durability is
re-established before scratch removal. This phase means event append has stopped.
The remaining scratch can only retry the exact intended seal; conflicting bytes
remain untouched. Every publication rechecks the pinned inventory before rename,
and every successful retry includes file and directory durability barriers.

The operation has a fixed five-step limit. Each step holds at most the bounded
generation inventory, not an unbounded directory listing. A generation still has
at most 128 chunks and 8 MiB of published payload. A fragment is at most 1 MiB plus
1 KiB, with combined published payload and fragment bytes capped at 8 MiB plus
4 KiB. Chunk headers, manifest, seal and filesystem allocation are separate
bounded overhead. Fragment bytes aren't silently omitted from capacity checks.

## What actually ran

Superpowers isn't installed. The official upstream test-first,
verification-before-completion and independent-review workflows loaded earlier
remain the disclosed fallback.

The initial rejecting stub failed all seven initial recovery cases:
`/tmp/zasp-lineage-recovery-red.log`.
The first implementation run found that the test drove only one of two recovered
chunks before acknowledgment. The corrected fixture invokes the bounded processor
until it has consumed the sealed prefix. This wasn't a relaxation of ACK checks.
Recovery, reclamation and retirement races then passed in 23.092 seconds:
`/tmp/zasp-lineage-recovery-focused.log`.

After the shared-prefix fix, hostile input and publication recovery tests passed
in 4.984 seconds: `/tmp/zasp-lineage-recovery-boundaries.log`.
They include cancellation and actual child-process exit at five boundaries:
fragment rename, chunk rename, empty seal scratch, written seal scratch and seal
rename. Restart reopens ownership and preserves the published prefix. These tests
exercise process death, not power loss or remote-filesystem durability.

Final focused races passed in 6.539 seconds:
`/tmp/zasp-lineage-recovery-final-focused.log`. They add exact-byte file replacement,
detached generation and unexpected fragment injection while seal scratch exists.
Those attempts leave uncertain scratch and never publish a seal. The 128-chunk
plus fragment recovery also passes. Full sensor-agent races passed in 74.065
seconds before these final test-only additions:
`/tmp/zasp-lineage-recovery-full-agent.log`.

The separately compiled sensor process now recovers the actual local TLS and
PostgreSQL scenario's interrupted source twice with its token physically absent.
It makes no credential reads or requests during recovery. Existing lost-response
replay, credential rotation, exact PID/start cache behavior, all-drop handling,
ACK admission and the complete retirement handshake follow. The trace remains
three requests, two artifacts, two database batches, ten stage rows and two outbox
rows. The acknowledgment binds unknown counters and the exact fragment digest.

The first composed run failed its old `shutdown` expectation; the fixture now
requires the actual recovery contract. Failed attempt:
`/tmp/zasp-lineage-recovery-installed.log`. The corrected containing API test and
artifact regression passed in 49.402 seconds:
`/tmp/zasp-lineage-recovery-installed-final.log`.
TLS and PostgreSQL handlers are real. Provider identity and artifact storage are
fixtures, not live Tetragon or S3 proof. The composition doesn't prove the browser
or daemon deployment.

Linux component gates passed three repetitions:
`/tmp/zasp-lineage-recovery-linux.log`. They include recovery, retirement, real
O_PATH directory-sync failures and the existing maximum reclamation inventory.
The final recovery set also passed three repetitions with the 128-chunk plus
fragment and publication-replacement tests:
`/tmp/zasp-lineage-recovery-linux-final.log`.

Root/non-root original and recovered lifecycles each passed three repetitions:
`/tmp/zasp-lineage-recovery-linux-permissions.log`. The root producer closes the
partial source; an actual UID 65532 consumer verifies it, commits, acknowledges and
later retires its state. The consumer can't write producer chunks, fragments,
scratch or lock files. Producer reclamation and completion collection still
preserve the separate consumer ownership boundary.

All proof containers used no network, read-only root, 256 MiB/no swap, 0.5 CPU,
192 descriptors, 128 processes, GOMEMLIMIT=128MiB and 128 MiB noexec/nosuid temporary
storage. Ordinary runs used UID/GID 65532 with no capabilities. The permission
fixture used root with only SETUID/SETGID/CHOWN. All three containers exited zero
without OOM. This is restricted component execution, not persistent host-disk or
full-daemon resource proof.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Initial test binary: `/tmp/zasp-lineage-recovery-linux.pR0YXy/sensor-agent.test`,
SHA-256 `4dc72924896595824be52df8883d72f01ebf3a77a33c3a25480d623ee99869d0`.
Final test binary: `/tmp/zasp-lineage-recovery-linux.pR0YXy/sensor-agent-final.test`,
SHA-256 `9c2c0508891b6cef35730f5487ee0eb1bff2c02b2af0cc8be1137e6abd138dbe`.
Final production binary: `/tmp/zasp-lineage-recovery-linux.pR0YXy/sensor-agent-final`,
SHA-256 `86d2817ff0cb7bb07dd6efec2e4fe588c943f61043229827c9a2da0890c0ce44`.
The final test binary predates only the accurate spool comment about metadata
recovery, not product logic. Initial production binary SHA-256:
`697a0eef37caeeac5fc22dc2e4ad980005a9689397c3ba0e3f8331fbdaae01b6`.

Following the careful skill, cleanup inspected the exact owned exited containers
then removed only `zasp-lineage-recovery-20260911-a`,
`zasp-lineage-recovery-20260911-b` and `zasp-lineage-recovery-20260911-final`.
Their disposable state is gone. Logs, binaries and both inspection records remain:
`/tmp/zasp-lineage-recovery-linux-inspection.json` and
`/tmp/zasp-lineage-recovery-linux-final-inspection.json`.

Independent review accepted the shared-prefix correction and found no further
concrete recovery blocker, conditional on the full-agent, actual TLS/PostgreSQL
and Linux gates, which passed. This isn't whole-branch shipping approval.

Fresh root `npm run verify` passed on Node 22.23.1, including 196 UI test files,
1,180 tests, typecheck, lint, tenancy/API/release contracts, production build and
compiled import checks (seven client chunks, eight server chunks). Log:
`/tmp/zasp-lineage-recovery-root-verify.log`.

The final authoritative ledger validates all 728 rows. All 27 ledger regression
tests and `git diff --check` pass. Independent review confirmed bounded recovery
acceptance after the final gates; broader production activation remains unapproved.

## What still prevents activation

A crash before manifest publication can leave a 0700 reservation with insufficient
source metadata. This method intentionally doesn't adopt it. Those slots still
need a bounded recovery protocol. Trusted-source enumeration, cursor-slot
assignment, automatic generation rotation and the daemon controller remain open.
So do live pinned Tetragon compatibility, original sandbox/cgroup/process
source-to-browser acceptance, remaining M48 gates, full API-suite and composed
Chrome verification. No task credit or push. Counts stay 535 production-available,
132 component-only and 61 external gates.

New creation now closes the startup gap through private reservations and bounded
metadata-only discard, verified separately in
`docs/internal/2026-09-11-sensor-private-reservations.md`. Old public 0700 paths
remain preserved. Controller integration and live acceptance still aren't active.
