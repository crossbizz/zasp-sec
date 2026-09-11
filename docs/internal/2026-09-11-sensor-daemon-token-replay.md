# Projected rotation through the executable

The compiled non-root sensor now has process-level proof for projected-token
rotation during a pending upload. This turn changes tests and evidence, not
production code. Counts remain 535 production-available, 132 component-only and
61 external gates. M3-46, M3-47 and M7-07 stay open. No push or activation.

The Linux fixture starts the actual `sensor-agent` executable as UID/GID 65532.
It verifies zero effective capabilities. A separate root container publishes the
Secret-shaped volume; the consumer's container mounts that volume read-only.
The first request uses the original token and receives 503. No acknowledgment
may exist at that point. The writer publishes a replacement credential, and the
same running daemon retries the exact body and idempotency key using the new
token. Only one request is accepted. The writer then removes the projected key;
root reclamation, consumer retirement and final slot release still complete.
The daemon stays live but unready while the fixture Kubernetes API returns 503,
joins after SIGTERM, and prints neither upload credential nor service-account token.

The writer and HTTP endpoints are test fixtures. This proves neither actual
Kubernetes publication nor server-side token revocation. A 503 response is not a
lost-success response; the separate API suite below covers that other boundary.
Both tests are useful, but they aren't one combined executable-to-real-API proof.

The test requires `ZASP_TEST_LINEAGE_DAEMON_PROJECTED=1` as well as the existing
isolated-daemon gate. Broad owned-file fixture runs don't accidentally start it.
No fixture environment switch or control-volume access was added to production.

## Results

The pre-refresh executable from `/tmp/zasp-lineage-installation.eW9ibB/sensor-agent`
failed the new test after 35.04 seconds, without reaching the initial upload.
The RED writer timed out waiting for that attempt. Both logs are retained as
`/tmp/zasp-projected-daemon-red-{consumer,writer}.log`.

The updated executable passed in 0.49 seconds. After the dedicated fixture gate
was added, the final run passed in 0.41 seconds. The original owned-file executable
lifecycle also passes three repetitions, including cleanup after token removal.
Logs: `/tmp/zasp-projected-daemon-green-consumer.log`,
`/tmp/zasp-projected-daemon-final-{consumer,writer}.log`, and
`/tmp/zasp-projected-daemon-owned-regression.log`.

The final consumer harness had no external network, a read-only root, 256 MiB
memory with no extra swap, 0.5 CPU, 128 PIDs and 192 file descriptors. Its private
tmpfs volumes hold only test state and test Kubernetes authority. The root harness
has CHOWN/SETUID/SETGID/KILL to prepare, launch and join its non-root child; the
consumer itself has zero effective capabilities. The separate fixture writer has
CHOWN/FOWNER and a RW projection mount. No SYS_ADMIN or privileged container.

The separate actual local HTTPS/PostgreSQL suite passes in 39.607 seconds:
`TestProductionRuntimeIngestHTTPPersistsTransactionalOutboxBeforeAcceptance`.
Its admitted-chunk recovery subtest ran for 31.03 seconds. It creates and rotates
credentials through the product handlers, loses a response after durable acceptance,
replays the same body/key with a changed credential, and checks unchanged scoped
batch provenance, five stage-work entries and one outbox item. The archive store
and browser identity remain fixtures. Log:
`/tmp/zasp-projected-daemon-full-api-replay.log`.

Two preceding API invocations used unsuitable subtest filters. The first didn't
select the intended recovery case. The second skipped prerequisite lifecycle
subtests and failed its request-count assertion before recovery. Neither is counted
as acceptance evidence; the full top-level rerun above executed all dependencies.

Selected host consumer/controller race tests pass in 12.887 seconds:
`/tmp/zasp-projected-daemon-host-race.log`. Production/UI sources are unchanged
since the prior full `npm run verify` (1,180 UI tests and compiled build). No new
Chrome or deployed-browser claim is made.

| Final Linux arm64 artifact | SHA-256 |
| --- | --- |
| `/tmp/zasp-projected-token-sensor-agent` | `9148d48613415235c1a4f3267aacb0a2a1d1758ebd99213103ae7c183794c9a1` |
| `/tmp/zasp-projected-daemon-final.test` | `7c79933ea3e8132345fbc2d2f7f40ccefcf9518cec8e3d4c1e73418eb0348838` |

Independent review found no concrete blocker in the bounded fixture changes.
Superpowers isn't installed; the previously disclosed upstream test-first and
independent-review workflow remains in use. The careful skill required exact
stopped-container inspection before cleanup. All seven owned containers and six
disposable volumes were removed. Logs, binaries and the inspection records
`/tmp/zasp-projected-daemon-containers.json` and
`/tmp/zasp-projected-daemon-volumes.json` remain. No OOM kill occurred.

Read-only Kubernetes checks found no current context. The existing `orbstack`
context's API at 127.0.0.1:26443 refused the connection. No context, cluster or
deployment was changed. Actual Kubernetes projection, the combined daemon/real-API
lifecycle, controlled legacy backlog transition, live Tetragon-to-browser and the
remaining original sandbox/container/cgroup/process scope still need acceptance.
Whole-platform race tests were started for broader pre-push review; their result
is not yet claimed here.
