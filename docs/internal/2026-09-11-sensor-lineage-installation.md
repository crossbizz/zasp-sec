# Lineage installation wiring

The later [projected-token refresh record](2026-09-11-sensor-projected-token-refresh.md)
supersedes this slice's init-time product-token copy. The historical evidence below
is unchanged; live Kubernetes acceptance is still open.

The customer-edge chart now selects the producer and consumer executable roles.
This is verified local installation wiring, not a deployed Kubernetes acceptance.
The 728-task counts remain 535 production-available, 132 component-only and
61 external gates. No credit for M3-46, M3-47 or M7-07. No push or activation.

## State and mount ownership

The chart uses the dedicated host path `/var/lib/zasp-sensor-lineage`. It doesn't
reassign or delete the legacy `/var/lib/zasp-sensor` checkpoint directory. Existing
legacy backlog must be reconciled as part of a controlled rollout; the new role
doesn't claim to import that history.

| Container | Producer spool | ACK directory | Private consumer state | Other inputs |
| --- | --- | --- | --- | --- |
| Layout initializer, UID 0 | Full layout mount | Full layout mount | Full layout mount | No token or Kubernetes credential mount |
| Producer, UID 0 / GID 65532 | Read/write | Read-only | Not mounted | Tetragon socket, host boot, Kubernetes authority |
| Consumer, UID/GID 65532 | Read-only | Read/write | Read/write | Product token read-only, kernel/BTF, Kubernetes authority |

Both long-running roles drop all capabilities. The initializer has only CHOWN and
DAC_READ_SEARCH. The latter is needed to reopen and fsync an existing consumer-owned
0700 directory after a prior initializer might have stopped between chown and
fsync. It is confined to the initializer's layout mount; it isn't granted to the
producer, consumer or token materializer. It is broader than ordinary directory
read permission and should not be described otherwise.

`lineage-layout` admits a root-owned 0750/0755 layout with only three fixed
directories and its persistent root-owned lock. It rejects symlinks, foreign
entries/owners/modes, nonempty partial directories and a busy initializer lock.
Preflight precedes writer-lock creation. It only changes ownership on empty,
root-owned incomplete directories. Existing completed directory contents aren't
read or reassigned. Restart pins, validates, fsyncs and revalidates their metadata;
correct-looking ownership alone isn't a durable completion claim. New directory
inodes and their parent are synced before success. No recursive chown or deletion.

Product-token materialization now runs non-root without capabilities. Its source
and output volumes aren't mounted by the producer. Kubernetes automatic token
mounting is disabled. Explicit projected authority is mounted only in the two
long-running containers. Tetragon's pinned chart explicitly enables its existing
Unix gRPC endpoint; the consumer no longer mounts or reads its log directory.

## Kubernetes authority is shared

Both containers are in one pod and use the same `sensor-agent` service account.
They share its namespace-scoped lease get/list/create/update and Pod-list access,
cluster-wide Node GET, and GET of the `kube-system` Namespace. This is workload-wide
authority, not per-container RBAC isolation. The producer's client issues only the
fixed identity GET requests, but its credential is not read-only. The consumer also
has the Node-read grant. Filesystem mount isolation does not change that fact.

The chart retains bounded resources, startup/liveness/readiness checks, a single
unavailable pod during rolling updates, and the existing control-plane/API/metrics
network rules. Producer readiness uses port 8082 and the consumer still checks its
colocated producer over loopback. The token copy remains init-time only. Applying
a changed Secret without restarting the pod doesn't refresh the materialized token;
credential-refresh/rollout behavior remains an acceptance gate.

## Evidence collected

The initializer and chart-isolation contract had observed failing tests before
implementation. Final release/staging contract tests pass all 44 cases. The
compiled initializer, exact directory ownership, restart, empty partial recovery,
retained file preservation, busy/foreign rejection and failed inode-sync barrier
pass three repetitions on restricted Linux. The O_PATH regression supplies a real
descriptor whose metadata checks succeed but fsync fails, and verifies rejection
without changing the directory.

A compiled initializer created a disposable Docker volume. Three different
generation rounds then ran prepare/process/reclaim/retire/collect/release in fresh
containers with the chart's per-role read-only subdirectory mounts. All 18 phases
passed. The test checks actual ST_RDONLY mount flags; it exercises cross-container
physical inode binding and fsync through source consumption, ACK verification and
full retirement. The final consumer state is two locks, not retained assignments.
The upload transport is a fixture. This proves local bind-mount feasibility, not
Kubernetes subPath deployment, real provider collection or durable API acceptance.

These role containers had no external network, a read-only root, 192 MiB memory
with no additional swap, 0.5 CPU, 64 PIDs, 192 file descriptors and no capabilities.
The root initializer had the two capabilities listed above. No final selected
Linux test skipped or failed and no container was OOM-killed.

Root `npm run verify` passes: 196 UI test files, 1,180 tests, typecheck/lint,
API/tenancy/release contracts, production build/import checks and the 728-row ledger.
The compiled graph has seven client and eight server chunks. This isn't a fresh
Chrome or end-to-end browser proof. The separate installed-sensor HTTPS/PostgreSQL
regression passes in 39.720 seconds. The final layout durability correction is
covered by the subsequent release, Linux initializer and mount reruns.
Final full sensor-agent race tests pass in 101.790 seconds, retained in
`/tmp/zasp-lineage-installation-final-agent.log`.

Independent review found no remaining concrete blocker in this bounded slice,
including the final fsync correction. Superpowers isn't installed; the previously
disclosed official upstream test-first, verification and independent-review workflow
was used.

Retained evidence includes `/tmp/zasp-lineage-installation-root-verify.log`,
`/tmp/zasp-lineage-installation-final-release-tests.log`,
`/tmp/zasp-lineage-installation-installed.log`,
`/tmp/zasp-lineage-layout-barrier-final.log` and each
`/tmp/zasp-lineage-mount-final-{1,2,3}-{phase}.log`.
Final binaries are in `/tmp/zasp-lineage-installation.eW9ibB/`:

- `sensor-agent`: `9d1d33bb2c97b6473211e6a2328d17d02d7305ee48b393bd312bc1866779d1eb`.
- `sensor-agent.test`: `63d8ad9504b5f31b8f730afd9df6e3444570c84808aeeefdd6752092c781a214`.

All 42 exact-owned containers from the preliminary and final proofs were inspected
and removed. Both instances of the disposable proof volume were removed after
their containers stopped. No proof container or volume remains. Metadata is
retained in `/tmp/zasp-lineage-installation-containers.json`, `-volume.json`,
`-final-containers.json` and `-final-volume.json`; logs and binaries remain on disk.
The 728-row ledger check and all 27 checker tests pass.

Kubernetes rollout and projected-volume ownership, token refresh, legacy backlog
transition, live pinned Tetragon-to-browser acceptance, full original sandbox/
container/cgroup/process scope, remaining M48 gates and whole-branch release review
are still open. No production-readiness claim follows from this record.
