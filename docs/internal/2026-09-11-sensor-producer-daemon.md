# Timed rotation and the producer daemon role

The sensor binary now has an explicit `lineage-producer` role. It runs the owned
producer loop, reconciles retained work, rotates generations and exposes health on
port 8082. Deployment manifests haven't enabled it. The production consumer role
and the installed source-to-browser path still need wiring and acceptance.

All 728 original tasks remain in scope. Counts stay 535 production-available,
132 component-only and 61 external gates. M3-46, M3-47 and M7-07 receive no new
credit. No deployment activation or push.

## Rotation without relabeling history

`lineagePumpConfig.MaximumDuration` closes quiet as well as busy generations.
The producer role requires a bounded age between one second and one hour.
Existing standalone component callers may leave it zero; the producer loop may not.
Rotation stops and joins receive work, then attempts the remaining batch under the
existing identity checks and cleanup deadline. Its seal records `rotation` and the
known dropped/filtered counters. It never claims complete upstream coverage.
Ambiguous publication keeps its existing unknown/unsealed recovery behavior.

`runLineageProducerLoop` reconciles producer-owned work before each startup attempt
and continues reconciliation while a pump runs. A full eight-directory spool does
not open another provider subscription. Retry requires a caller tick, including
after immediate disconnect or startup failure. New connections always pass fresh
identity checks and receive a new generation UUID. The loop doesn't append to or
relabel an old generation.

The loop owns generations and joins the pump before returning borrowed resources.
The owning goroutine closes its generation even if the pump rejects prerequisites
before installing its own cleanup. Review identified this early-rejection edge;
the regression verifies cancellation, released active ownership and retained
manifest history. A tick checks the completed channel before treating an existing
generation as running. Local filesystem calls aren't a hard wall-clock shutdown
guarantee.

Ten rotating empty generations complete with concurrent consumer processing and
reclamation, crossing the eight-slot limit. The test drains the fixture's request
queue on every connection; that observation isn't a production registration fence.
Backpressure, tick-bounded startup retries, early pump rejection, timed empty and
event-bearing rotation, generic health readiness and joined shutdown are covered.

## The executable boundary

`ZASP_SENSOR_ROLE=lineage-producer` selects the new role. An unset role preserves
the existing consumer behavior; unknown roles fail closed. Producer configuration
rejects a product-token file. The role reads only its Kubernetes service-account
credential, host boot source, local Tetragon endpoint and scoped spool/ACK metadata.
It doesn't upload to the control plane; the destination is receipt scope.

Production construction requires Linux, UID 0 and the configured non-root consumer
UID as the process's read-only group. Spool, ACK, socket parent, boot parent and
Kubernetes service-account directory must be separate paths and physical roots.
Spool admission requires UID 0, mode 0750 and the configured consumer group, with
no special permission bits. `newBoundLineageSpool` rechecks inode, mode, UID and GID
before creating the producer lock. This rejects an unreadable or replaced spool
before collection starts. Raw socket access remains confined to the producer role.

The role uses the actual procfs boot reader and bounded Kubernetes TLS identity
client. Client-side path restrictions aren't per-node server-side RBAC. The future
deployment still needs the intended mounts, service account permissions and network
policy; constructing this role isn't evidence those cluster settings are installed.

The shared health-server lifecycle now supports both role entry points. Producer
dependencies refuse closure while their loop is running. A timeout can report a
failed shutdown without closing borrowed handles underneath the active pump; process
termination and retained-spool recovery remain the final fallback.

Required producer-specific inputs are `ZASP_LINEAGE_SPOOL_DIRECTORY`,
`ZASP_LINEAGE_ACK_DIRECTORY`, `ZASP_TETRAGON_SOCKET`, `ZASP_HOST_BOOT_ID_FILE`,
`ZASP_LINEAGE_CONSUMER_UID`, `ZASP_LINEAGE_FLUSH_INTERVAL`,
`ZASP_LINEAGE_IDENTITY_INTERVAL` and `ZASP_LINEAGE_MAX_GENERATION_AGE`. The existing
node, enrollment, control-plane URL, batch-size, operation-timeout, poll-interval
and shutdown-timeout inputs remain required. Durations use the existing canonical
format, for example `5m0s`. Producer polling is bounded to 1-30 seconds; shutdown
configuration is bounded to 10-60 seconds.

## Evidence and limits

Superpowers isn't installed. The previously read official upstream test-first,
verification-before-completion and independent-review workflow remains the
disclosed fallback. Timed-rotation RED is
`/tmp/zasp-lineage-producer-rotation-red.log`; loop RED is
`/tmp/zasp-lineage-producer-loop-red.log`.
Initial combined races pass in 5.477 seconds:
`/tmp/zasp-lineage-producer-loop-green.log`.
Configuration and generic daemon health races pass in 2.132 seconds:
`/tmp/zasp-lineage-producer-daemon-config.log`.
Loop/configuration boundary races pass in 6.493 seconds:
`/tmp/zasp-lineage-producer-daemon-boundaries.log`.
The focused rerun with fixture request draining passes in 5.706 seconds:
`/tmp/zasp-lineage-producer-daemon-final-focused.log`.

The Linux composition launches the compiled production executable, not a Go test
entry point, with the real role/configuration path. A disposable tmpfs holds a
synthetic Kubernetes service account. The actual TLS server supplies Kubernetes
identity matching the container's real procfs boot ID; an actual Unix gRPC server
supplies a pinned-version Tetragon fixture event. The test observes readiness,
event publication, timed rotation into a distinct generation, SIGTERM and strict
post-exit source/seal validation. The ACK directory stays empty and credential text
doesn't appear in output. Negative child-process probes reject mode 0700 and a
wrong spool group without creating any spool files.

This is real daemon/transport/filesystem composition with fixture providers. It
isn't a live Tetragon kernel emitter, a deployed Kubernetes identity, loss-free
collection, cluster-load proof or host power-loss evidence. Separate root/non-root
original and recovered source tests still cover the consumer/reclamation boundary.

Independent reviews found no remaining concrete blocker after the loop cleanup,
completed-pump and spool-permission corrections, conditional on final gates. They
didn't approve deployment or shipping.

Final full sensor-agent races pass in 96.976 seconds:
`/tmp/zasp-lineage-producer-daemon-final-agent.log`.
The actual local HTTPS/PostgreSQL sensor integration and independent-artifact
regression pass in 45.348 seconds:
`/tmp/zasp-lineage-producer-daemon-final-installed.log`.
That separate integration retains exact lost-response replay, credential rotation,
three requests, two artifacts, two accepted batches, ten stage rows and two outbox
rows. It doesn't invoke the new producer daemon role.

Final restricted Linux loop/configuration/health tests pass three repetitions:
`/tmp/zasp-lineage-producer-daemon-linux-final-ordinary.log`.
Final actual producer executable and root/non-root original/recovered lifecycle
tests each pass three repetitions:
`/tmp/zasp-lineage-producer-daemon-linux-final-composition.log`.
Selected tests have no failures or skips. All containers exited zero without OOM.

Runs used no network, read-only root, 256 MiB/no swap, 0.5 CPU, 192 descriptors,
128 processes, GOMEMLIMIT=128MiB and 128 MiB noexec/nosuid temporary storage.
Ordinary tests used UID/GID 65532 and no capabilities. Root composition used
UID 0/GID 65532 with only SETUID/SETGID/CHOWN, plus a dedicated 1 MiB noexec/nosuid
service-account tmpfs. The production child had GOMEMLIMIT=96MiB. These are bounded
local composition limits, not full deployment resource guarantees.

Image: `sha256:5179869c86a8fa2f63ab144508f9f031fa24937636844859638ae44b5965dde4`.
Final test binary: `/tmp/zasp-lineage-producer-daemon-final.aPWv4I/sensor-agent.test`,
SHA-256 `dc592d71fed71a2e17f1310f266dcec7f27dbc02b575907578d89f953e1f9e80`.
Final production binary: `/tmp/zasp-lineage-producer-daemon-final.aPWv4I/sensor-agent`,
SHA-256 `1759a8737a590f08858348a1b462c295793476fa93ef425dee18b2423637d0a2`.

Following the careful skill, cleanup inspected then removed only the five exited
owned containers `zasp-lineage-producer-daemon-20260911-a` through `-e`. Their
disposable state is gone. Logs, binaries and
`/tmp/zasp-lineage-producer-daemon-linux-inspection.json` remain. Final gates are
the `-d` and `-e` runs; the earlier runs don't replace the final permission checks.

## Next

Wire the production consumer role into the existing heartbeat and cluster-reporting
path, then update the controlled installation with separate producer/consumer
mounts and ownership. Complete live pinned Tetragon compatibility/emission, all
original sandbox/container/cgroup/process candidate correlation, browser acceptance
and remaining M48 gates. The optional producer entry point doesn't close those
requirements.

UI code didn't change in this slice. The preceding root verification remains
`/tmp/zasp-lineage-recovery-root-verify.log`, including 1,180 UI tests and production
build. Fresh whole-branch checks and review remain required before main.

The authoritative ledger check validates all 728 rows with unchanged counts.
All 27 ledger-check tests pass in `/tmp/zasp-lineage-producer-daemon-ledger.log`;
`git diff --check` passes.
