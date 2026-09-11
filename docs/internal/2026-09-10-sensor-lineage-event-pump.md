# The checked stream can now fill private chunks

September 10, 2026. Unpublished component work on
`codex/runtime-sensor-lineage`. Counts remain 535 production-available,
132 component-only and 61 external gates. No task promotion or push.

The new event pump owns one admitted generation for one run. It receives from the
checked subscription, batches the owned converted records, rechecks full host/
Kubernetes identity before publication and writes through the private spool. It
also rechecks identity on a separate timer while idle. It won't reopen populated
storage, run twice on one generation or reconnect to an old stream.

## Where the bounds sit

One receive worker feeds a capacity-one channel. At most one record is queued
and one is held by a blocked sender, with one receive in flight when the queue
isn't blocking the sender. The batch stays within 1 MiB and 1,000 records.
An overflowing next record is retained for the next batch after the earlier batch
publishes. Timer flushes handle partial batches. gRPC transport buffers are
separate from these application bounds.

Configuration permits batch sizes 1-1,000, flush intervals 50 ms-30 seconds and
idle identity intervals 50 ms-one minute. These aren't deployment defaults.
Every publication requires the existing repeated identity lookup, four Kubernetes
GETs plus boot reads. Idle checks incur the same lookup. This operational cost
needs a measured, reviewed fleet-scale configuration before deployment; the
component tests don't prove scalable control-plane load or sustained throughput.

The inherited spool limits remain eight generations, 128 chunks and 8 MiB payload
per generation. Capacity stops publication without removing old chunks. There is
still no acknowledgment-bound reclamation, rotation loop or continuously running
production collector.

## Counts don't imply complete coverage

The worker separately counts successfully converted records, intentional filter
exclusions and malformed/rejected provider records. On termination, the owner
cancels and closes reception, then joins the worker before reading those counts.
This includes queued records and a record held by a sender that couldn't enqueue.
Sends honor cancellation even when the queue is full. Checked counters refuse
overflow; overflow leaves the generation unsealed.

Confirmed appends count as committed records. Converted records that weren't
committed, plus locally rejected records, count as known drops. A generic append
failure is different: the failed batch might already be published. Its records
are reported as uncertain, excluded from definite drops, and prevent a seal.
Readers may later recover the published chunk. No deletion or overwrite tries to
resolve that uncertainty.

These counts cover local observations only. They can't measure Tetragon-side
loss, unobserved disconnect gaps or provider replay. Every termination seal still
has `coverage_complete: false`.

## How a run ends

Identity mismatch or lookup failure rejects pending records and ends the
generation. A foreign source node also stops it. A later good lookup can't
rehabilitate those records within this run.

After a disconnect, the pump joins reception, then checks identity before flushing
the final pending batch. Caller cancellation prevents that final event flush.
Known termination counters can still be sealed in already-owned storage using a
fresh cleanup context. One five-second cleanup budget covers receive join, final
identity/flush and seal. Filesystem operations and resource-close calls don't have
a hard wall-clock guarantee. If cleanup can't establish a safe result, termination
stays unsealed.

The pump closes its owned generation at exit. It doesn't close the borrowed API,
boot reader or parent spool. A rejected concurrent invocation doesn't close the
active pump. No provider error text or raw record is included in the result.

## Evidence

Missing-implementation RED: `/tmp/zasp-lineage-pump-red.log`.
The first run, `/tmp/zasp-lineage-pump-green.log`, exposed a test timing error:
waiting for a visible chunk didn't establish successful append completion before
canceling. The pump correctly classified that publication as uncertain. Clean
shutdown tests now wait for the spool's lock-protected committed chunk count.

Another test incorrectly tried to acquire the receive mutex after the last event;
it could catch the next blocked receive and wait for the fixture deadline. The
failure is retained in `/tmp/zasp-lineage-pump-boundaries.log`. Final-disconnect
tests now use successful transport receipt as their witness without waiting on
the next receive. Neither failure was passed off as a product-code defect.

Three focused race runs pass in
`/tmp/zasp-lineage-pump-reviewed-focused.log` (8.030 seconds). Fresh full
sensor-agent races, including the final idle/single-run cases, pass in
`/tmp/zasp-lineage-pump-full-agent.log` (25.193 seconds).

Actual Unix gRPC fixtures cover batch and timer publication, filtered/malformed
accounting, full-queue cancellation, identity failure with pending/queued/sender-
held records, capacity exhaustion across 128 committed chunks, the 1 MiB split
boundary and retained overflow record, final-check cancellation, idle identity
change, concurrent-run rejection and refusal to adopt populated history. A real
post-rename canceled append preserves its readable chunk, remains uncertain and
doesn't produce a seal. No live Tetragon or real Kubernetes cluster is involved.

Independent review accepted this bounded component after the focused and full
tests passed. Installed Superpowers remains unavailable. The disclosed official
upstream test-first, fresh-verification and independent-review workflow supplied
these checks. No production, scalability or shipping approval.

All pump tests also passed three repetitions on Linux arm64 in
`/tmp/zasp-lineage-pump-linux.log`. The isolated container used a read-only root,
no network, UID/GID 65532, all capabilities dropped, 256 MiB memory without swap,
0.5 CPU, GOMEMLIMIT 128 MiB and a 128 MiB tmpfs. It exited zero with OOMKilled
false. The owned proof container was inspected and removed; logs and binaries
remain. This is component execution on tmpfs, not a full-daemon, persistent-disk
or sustained-throughput proof.

Test binary: `/tmp/zasp-lineage-pump-linux.93hF3F/sensor-agent.test`, SHA-256
`77fe847718fc4f002bc5727514594cff3bdf2676a6c7a1afb7ccc168a5d1f2e7`.
Production cross-build: `/tmp/zasp-lineage-pump-linux.93hF3F/sensor-agent`, SHA-256
`a20c11a3178b5d0e79d3c25f6d04d97cd7ddd3aaccb7c1e4b31e7c0b2dfacebf`.
Pinned local image:
`sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.

Next: durable consumer admission/checkpoints and acknowledgment-bound reclamation,
then deployment wiring and live source-to-browser verification. The original
multi-tenant discovery/security/correlation scope is unchanged.
