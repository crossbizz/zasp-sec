# Sensor recovery checkpoint

September 10, 2026. Unpublished work on `codex/runtime-sensor-lineage`, based on
verified main `a4fede82`. This is component evidence, not a production closure.
All 728 original tasks retain their classification: 535 production-available,
132 component-only and 61 externally blocked.

Both original restart regressions now pass:
`TestFileProcessorRestartRetainsUncertainBatchBeforeAppendedLines` and
`TestFileProcessorRestartRetainsExecIdentityAcrossAcknowledgedRotation`.
Their first GREEN run is `/tmp/zasp-sensor-stream-restart-checkpoint-first.log`
(1.781 seconds). Earlier RED evidence remains in the lineage audit. This note
supersedes the earlier statements that those regressions are still failing.

## What changed

The processor persists a private versioned checkpoint before sending. It records
the original cursor range, pending request, next cursor, drop counts and sanitized
post-read process cache. A bound envelope pins destination, enrollment, schema,
exact body bytes and idempotency key without storing a credential. Replay reads a
fresh credential only after persistence. The acknowledged cursor becomes visible
only after a second durable write.

There is one cache per checkpoint. Pending work stores its post-read cache; after
acknowledgment that cache becomes committed. Pending work cannot be discarded or
combined with appended input. Changed source, destination, enrollment or
incompatible reduced limits fail closed. Expired envelopes remain intact and
require recovery. They aren't retimestamped.

Cache restore preserves eviction order and rejects invalid or duplicate identity
before publication. It retains no provider arguments, binary paths, credentials
or arbitrary maps. A reproduced timestamp defect lost correlation for `.100`,
`.123400` and `.123456700` fractional seconds. Retained identity now uses nine
fractional digits without rounding. The cache keeps its configured count limit
and an 8 MiB encoded identity limit. Log reads also cap aggregate retained input
at 8 MiB per batch, preserving the next complete line for the following read.

A stable private cursor lock uses exclusive nonblocking OS flock for the
processor's lifetime. Type, permissions, owner, link count and inode are checked.
The lock file isn't unlinked on close. Same-process and actual child-process
contention tests pass; child exit without `Close` releases the lock and preserves
its inode. Replacement is rejected before submission.

Persistence writes and fsyncs one reserved per-cursor temporary slot, renames it,
then fsyncs the parent directory. Retry after an uncertain write first persists
the pending checkpoint again. A crash-left reserved slot is recoverable only
when its ownership, mode, link count, type and size meet the private-file
contract. Other cursors' slots are untouched. This isn't cleanup of arbitrary
historical v1 temporary files. Legacy v1 migration reconstructs only from the
available selected-file prefix; history never persisted cannot be recovered.

## Tests and measured limits

Tests cover pending/acknowledgment write failures, accepted-response loss,
restart before appended input, cache retention through rotation, fresh credentials
with frozen requests, configuration drift, expired work, malformed cursor
progression, duplicate/aliased JSON, reserved-slot recovery and v1 migration.
New bound-client restart tests use an explicit HTTP `Do` double. They don't
compose the file processor with live PostgreSQL, TLS or artifact storage.

Retained RED logs include `/tmp/zasp-sensor-stream-lock-red.log`,
`/tmp/zasp-sensor-stream-line-budget-red.log` (70 lines retained 9,175,110 bytes),
`/tmp/zasp-sensor-cache-precision-red.log` and
`/tmp/zasp-sensor-checkpoint-duplicate-cache-red.log`.

The final full adapter, sensor and runtime-event race suites pass in
`/tmp/zasp-sensor-checkpoint-final-components.log` (5.396, 1.965 and 3.430 seconds).
The full sensor-agent race suite passes in
`/tmp/zasp-sensor-checkpoint-final-agent.log` (1.804 seconds). Three repetitions
of lock tests including subprocesses pass in
`/tmp/zasp-sensor-checkpoint-lock-subprocess.log` (7.927 seconds).
The 10-second bounded JSON fuzz run passes 642,473 executions in
`/tmp/zasp-sensor-checkpoint-preflight-one-cache-fuzz.log`. That property only
checks that accepted preflight input is valid JSON; it isn't a full semantic or
resource proof. Independent review confirmed rejection of both cache arrays
before decode, including empty arrays, and found no further concrete blocker in
the reviewed checkpoint/resource changes. Shipping remains unapproved.

Initial memory measurements failed the intended gate. The duplicate-cache
Darwin run peaked at 323,305,472 bytes RSS. Removing duplicate cache storage
reduced the stress checkpoint from 27,009,246 to 18,620,765 bytes with the same
41,432 identities and greater-than-7-MiB request. Darwin RSS still exceeded
256 MiB. Linux write-failure-only tests passed but reached the hard
268,435,456-byte limit with 88 memory-limit events.

The first transport benchmark used an invalid synthetic credential and failed
before HTTP; independent review caught this fixture defect. It provides no
transport memory evidence. With a valid generated synthetic credential, the
default-memory Linux transport run exited 137. Its auto-removed container didn't
retain OOM diagnostics, so this isn't classified as a confirmed OOM kill.
Logs are `/tmp/zasp-sensor-checkpoint-memory-linux-transport-baseline.log` and
`/tmp/zasp-sensor-checkpoint-memory-linux-transport-valid-token.log`.

The deployment template now sets `GOMEMLIMIT=128MiB`. This is a Go soft runtime
target, not a hard RSS limit. The missing-env contract test failed first in
`/tmp/zasp-sensor-checkpoint-memory-contract-red.log`; all 36 contract tests pass
after the template change in `/tmp/zasp-sensor-checkpoint-memory-contract-green.log`
(8.563 seconds).

Linux arm64 resource tests used the compiled non-race adapter test binary with
the existing pinned local image
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Limits: 256 MiB hard memory, no swap, 0.5 CPU, UID 65532, read-only root, no
network, dropped capabilities, 64 MiB tmpfs and `GOMEMLIMIT=128MiB`. Each
operation had a 10-second deadline.

Three iterations each of maximal persistence failure, successful persistence
with HTTP-503 retries, and third-attempt acknowledgment passed. Each used the same
near-8-MiB cache and request. Peak cgroup memory across these modes was
206,716,928 bytes with zero memory-limit, OOM or OOM-kill events. The longest
operation was 1,489,567,642 ns. Evidence:
`/tmp/zasp-sensor-checkpoint-memory-linux-cpu128.log`. The acknowledgment benchmark
explicitly restages its fixture after commit for the next iteration; production
doesn't rewind acknowledged work.

A hostile file reaches struct decoding with 100,000 entries in 32,000,253 bytes,
then rejects invalid identities before state publication. Three iterations under
the same limits pass at peak 166,772,736 bytes and zero memory-limit/OOM events:
`/tmp/zasp-sensor-checkpoint-memory-linux-hostile128.log`. These measurements
cover tested package paths, not every hostile input or the whole running daemon.
Owned proof containers were removed after recording exit status and diagnostics.
No application data was removed.

## Still open

The subsequent installation checkpoint now wires the public API receipt binding
through the UI, chart and actual production sensor construction. A composed
file/HTTPS/PostgreSQL create/rotate recovery test also passes, with artifact
storage still a double. See `2026-09-10-sensor-installation-binding.md` for exact
evidence and rollout requirements. Generic or unbound library sinks still have
the weaker normalized-event replay contract. Full-daemon resource measurement
must include cluster reporting and its actual transports.

Observed-lineage resolution/emission, production correlation-producer activation,
remaining migration-48 authority/reconciliation cases, full UI/build/release
verification and independent final shipping review remain unfinished. No push,
task credit or production-readiness claim is made. Installed Superpowers remains
unavailable; the previously read official upstream test-first,
verification-before-completion and independent-review workflow is the disclosed
fallback, not an installed-plugin pass.

Final ledger validation passes in `/tmp/zasp-sensor-durable-checkpoint-ledger.log`:
728 rows, 535 production-available, 132 component-only, 61 external, zero missing.
`git diff --check` passes. The branch remains unpublished.
