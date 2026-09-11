# Durable lineage chunk consumer

Scope: component work toward M3-46/M3-47 and M7-07. This does not close their
original acceptance criteria or activate qualified discovery in production.
The authoritative totals remain 535 production-available, 132 component-only,
61 blocked/external and zero missing across the original 728 microtasks.

## Implemented boundary

`services/platform/sensoradapter/chunk_processor.go` adds a separate
`tetragon-chunk-checkpoint-v1` processor. It borrows an admitted immutable
generation reader, its pinned source/spool roots and a concrete production
client with matching enrollment. It creates its own empty lineage normalizer.
It never adopts legacy file cursors or attaches provenance to an existing cache.

The cursor directory must belong to the consumer, reject group/world writes
and special mode bits, and differ by inode from both producer directories.
Reserved cursor/lock/temporary names cannot collide with supplied protected
inputs. Existing owned 0600 cursor files, lifetime flock, atomic temporary
publication, file sync, rename and directory sync provide the persistence path.
Borrowed roots and the client remain the caller's responsibility.

Each chunk must be contiguous, have 1-1000 records and a matching SHA-256 over
every record plus LF. Limits are 256 KiB per record, 1 MiB per chunk, 128 chunks
and 8 MiB of generation payload. Counts include records rejected by normalization.
Foreign-node records fail before cache mutation. Only explicit `ErrAdapter`
rejections become drops; internal errors or panics restore the pre-chunk cache
and do not advance source progress.

The checkpoint binds the copied lineage source, pinned generation device/inode,
destination and enrollment. Progress retains contiguous sequence, source bytes,
read/submitted/dropped counts and a rolling chunk-digest chain. Its pending state
contains the exact source digest, resulting progress, post-chunk process cache,
and frozen normalized events or an exact serialized upload envelope. It stores
no credential. Pending checkpoints retain one serialized cache, not duplicate
pre/post copies; the rollback snapshot is released before persistence/network.

Before every credential/network attempt, the processor persists its exact
pending envelope. A failed request or uncertain acknowledgment write retains
that pending state. Restart replays it before any new source read, with the current
credential for the same enrollment and unchanged body/idempotency/timestamps.
Expired events remain pending without retimestamping. All-dropped chunks commit
their source accounting/cache without accessing credentials or transport.

Loading rejects noncanonical/unknown/duplicate fields, malformed progression,
invalid arithmetic or chain transitions, foreign cache nodes, foreign event
lineage, mismatched targets and oversized state. Collection/string preflight
runs before struct allocation. Cache cardinality cannot exceed recorded
submissions, which rejects identity on zero consumed history. This is a necessary
count check, not proof each retained identity came from an execution: submissions
also contain other classes. The owned normalization path supplies identity.

`Committed` returns durable local progress only when no pending upload remains.
An empty generation can acquire a durable initial checkpoint without transport.
Neither state is a producer ACK, coverage claim or permission to reclaim files.
The retained prefix chain is a local assertion. Future ACK logic must independently
verify it against immutable source chunks and the generation seal.

## Verification and review

Superpowers is not installed. The official upstream test-driven-development,
writing-good-tests, verification-before-completion, requesting-code-review and
review-template instructions were read as the disclosed fallback. No installed
plugin execution is claimed.

Initial tests failed compilation because the new consumer API did not exist.
After implementation, focused races passed three repetitions (13.079 seconds).
The later zero-history cache test exposed an actual behavioral failure before
the count guard was added. Its failing output is retained in
`/tmp/zasp-chunk-processor-cache-history-red.log`.

Tests exercise real normalization, checkpoint files/locks and production-client
envelope handling. Only HTTP transport is replaced by deterministic responses;
these tests are not actual HTTPS/API/PostgreSQL delivery proof. Cases include
credential rotation and restart, qualified cache restoration, all-dropped input,
source/destination/enrollment drift, corrupt checkpoints, protected-input aliases,
internal cache insertion panic, expired pending events, both generation quotas,
and failures before/after pending and acknowledgment writes. Independent review
found no remaining concrete blocker, with final race/resource reruns required.

Final full adapter races passed in 8.730 seconds:
`/tmp/zasp-chunk-processor-final-adapter.log`. Final full sensor-agent races
passed in 25.130 seconds: `/tmp/zasp-chunk-processor-final-agent.log`.

All chunk tests passed three Linux repetitions, including the final cache-history
regression. Both maximal-cache/new-chunk and maximal-pending replay benchmarks
passed with three measured iterations per result, repeated three times. The
fixtures retain 41,007 cache entries near the 8 MiB encoded-cache bound. The new
chunk contains 612 records near 1 MiB; saved replay uses 600 events and an envelope
larger than 7 MiB. The encoded baseline retained for benchmark restaging also
counts against measured memory. These deliberately synthetic accepted-state
bounds are not a claim that every combination is producer-reachable.

The final container had a 268,435,456-byte memory/no-swap ceiling, 0.5 CPU,
`GOMEMLIMIT=128MiB`, UID/GID 65532, no capabilities, no network, read-only root,
128 MiB noexec/nosuid temporary storage and no healthcheck side process. It exited
zero with no OOM; peak cgroup memory was 195,801,088 bytes. Longest measured
operation was 1,483,370,936 ns, below the test's 10-second operation deadline.
This is component resource evidence, not full-daemon or fleet throughput proof.
The filesystem path has no hard cancellation deadline.

Final output: `/tmp/zasp-chunk-processor-linux-reviewed.log`.
Pinned Linux arm64 image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Final test binary:
`/tmp/zasp-chunk-processor-linux.lRMGg1/sensoradapter-reviewed.test`, SHA-256
`e521e595bf0709023c8ce678714f0c3245b35d2cb0aa190d13ec09e99a0b7172`.
The Linux production binary also builds:
`/tmp/zasp-chunk-processor-linux.lRMGg1/sensor-agent-reviewed`, SHA-256
`aec2f1c7b33f3efc10dc319511c523da77b32f631cbdaadea677c4c225dd0a31`.
The consumer is not wired into that daemon yet.

The first proof attempt accidentally retained the image's sensor entrypoint and
exited one before running tests. Subsequent runs explicitly selected the test
binary. Proof containers a/b/c/d were inspected and removed after termination;
logs and binaries remain. No product data or unrelated containers were touched.

## Remaining production work

Connect the admitted sensor-agent reader to this processor and prove the composed
source-to-actual-authenticated-ingest path. Add separately verified consumer ACKs,
bounded producer reclamation/rotation, complete daemon lifetime/deployment wiring
and protected-input collision checks. Verify pinned live Tetragon compatibility,
fleet identity-query cost, production correlation activation and mixed-evidence
browser flows, including sandbox/cgroup/process requirements. Full root release
verification, composed Chrome and whole-branch shipping review remain required
before a verified push to main. No task credit or push is claimed for this slice.
