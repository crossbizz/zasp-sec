# Retiring one exact committed checkpoint

This is a deletion primitive, not the complete consumer retirement protocol.
No production task credit changes. The original 728-task scope remains intact.

`sensoradapter.RetireConsumedCheckpoint` accepts the configured source and HTTPS
ingest destination separately from consumption evidence. The caller must first
authenticate the producer's completed reclamation record and keep that evidence
stable. Its required authorization callback rechecks that authority immediately
before deletion, while the existing consumer cursor lock is held. The primitive
doesn't authenticate producer completion or remote delivery by itself.

There is no client, credential, normalizer or source reader in this path. It can
operate after producer source removal. Shared source-identity hashing keeps the
physical generation binding identical to the writer's checkpoint contract.
Endpoint validation shares the existing closed HTTPS runtime-ingest contract.

The cursor directory and its direct parent are pinned and ownership-checked.
Configured protected inputs and disjoint roots must not overlap the deletion
target. Retirement opens the existing slot lock without creating or removing it,
takes the same nonblocking exclusive filesystem lock as the consumer and rejects
any reserved checkpoint scratch. A live consumer prevents retirement.

Checkpoint admission uses one retained no-follow, nonblocking descriptor. It
checks regular-file type, owner, single link, 0600 mode and the 32 MiB size limit
before reading. Bounded canonical JSON must have the exact checkpoint version,
source hash, enrollment/destination target, committed progress and valid bounded
cache, with no pending upload. The held bytes and named identity are checked again
after authorization and before unlink. Altered or unrelated files remain intact.

After unlink, the same directory-sync helper used by absence retries must pass.
An absent checkpoint still requires authorization, a valid existing slot lock,
no scratch and a fresh directory sync. A checkpoint created during authorization
is neither deleted nor reported absent. The persistent lock stays in place to
avoid splitting writer ownership across two lock inodes. Future orchestration
must use a bounded set of cursor slots; per-generation lock accumulation is not
solved by this primitive.

## Evidence and limits

Superpowers isn't installed. This work follows the previously loaded official
upstream test-first, verification-before-completion and independent-review
workflows as the disclosed fallback.

The matching empty/nonempty retirement tests first failed against a rejecting
stub: `/tmp/zasp-chunk-retirement-red.log`. The initial focused green run passed
in 3.886 seconds: `/tmp/zasp-chunk-retirement-first-green.log`.

Tests cover source/destination/inode/progress mismatch, pending state, invalid
cache or JSON, wrong modes, links, missing or held locks, protected-input overlap,
cancellation and rejected/panicking authorization. Authorization-time replacement
of file, lock or directory, same-length changed bytes and scratch creation all
preserve the target. FIFO admission rejects without a blocking open.

Actual child processes exit immediately before and after unlink, then a fresh
call recovers. A canceled post-unlink call reports failure, and its absence retry
cannot bypass authorization. These boundary tests passed in 3.044 seconds:
`/tmp/zasp-chunk-retirement-boundaries.log`.

Independent review identified the initial helper's blocking-open race. The
implementation now opens one O_NOFOLLOW/O_NONBLOCK handle before reading;
review confirmed the correction and found no further concrete component blocker.
Its remaining full-suite and Linux conditions passed. Review does not cover a
consumer caller, ACK mutation, completion-record collection or production activation.

Full adapter races passed in 15.200 seconds:
`/tmp/zasp-chunk-retirement-full-adapter.log`.
Full sensor-agent races passed in 45.361 seconds:
`/tmp/zasp-chunk-retirement-full-agent.log`.

Linux tests passed three repetitions as UID/GID 65532 with no capabilities,
network disabled, read-only root, 256 MiB/no swap, 0.5 CPU, 192 file descriptors,
GOMEMLIMIT=128MiB and 128 MiB noexec/nosuid temporary storage. The Linux test
uses an actual O_PATH directory descriptor in the shared absence-sync helper:
metadata admission passes, directory sync fails, and a fresh authorized call with
normal handles succeeds. This tests the actual syscall error and shared helper;
it doesn't inject power loss or claim deployed storage durability.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Test binary: `/tmp/zasp-checkpoint-retirement-linux.TDt96y/sensoradapter.test`.
SHA-256: `c55a8322df2efd919b7a4cd7d10f51ada0d52b2c310534fb0c9d2df8dd7553cd`.
Log: `/tmp/zasp-chunk-retirement-linux.log`.
Inspection: `/tmp/zasp-chunk-retirement-linux-inspection.json`.
The careful skill limited cleanup to the exact owned container
`zasp-checkpoint-retirement-20260911-a`, after inspection showed exit zero and no
OOM. Its disposable state was removed; the log and binary remain.

The preceding reclamation slice passed complete root UI/build verification,
recorded in `/tmp/zasp-lineage-reclaim-root-verify.log`. This follow-on changes
only Go adapter code and tests plus documentation, with the full Go suites above.
It isn't a fresh composed Chrome or entire API-suite result, and nothing is pushed.

The consumer caller's completion authentication and actual checkpoint-retirement
composition are recorded in `docs/internal/2026-09-11-sensor-consumer-completion.md`.

Next: retire ACK state and collect producer
completion records. The current eight-completion limit remains. Keep the daemon
unactivated until that bounded lifecycle and the remaining original end-to-end
acceptance are verified.
