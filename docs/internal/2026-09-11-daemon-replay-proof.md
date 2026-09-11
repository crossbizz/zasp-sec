# Running-daemon replay proof, in progress

Original scope and task credits are unchanged. This branch starts at `0bc905ac`.
PR 43 merged as main `c30d9fa6` after both branch checks passed. Main CI
34612285514 passes in 16 minutes. This next proof is separate and unpublished.
Local running-daemon/PostgreSQL composition passes; deployed acceptance remains open.

## Preparation verified

The sealed-source fixture has an explicit one-event mode while retaining the
existing three-event mode. It refuses rewriting an existing generation and never
labels a closed fixture as complete live coverage. The original helper failed
the one-event assertion; the corrected cases pass with races in 2.239 seconds.
Evidence: `/tmp/zasp-daemon-single-exact-red.log` and
`/tmp/zasp-daemon-single-green.log`. The first test draft incorrectly expected
complete coverage; that assertion was corrected before the exact RED run.

A TLS socket test verifies loss of the first accepted response before any headers,
closed-gate retry refusal, explicit replay release and exact body/key/authentication
digest evidence. Snapshots own their byte slices; at most eight forwarded attempts
are retained. Non-202 responses are forwarded without opening replay. Oversize
requests cannot reach the handler. Removing the attempt bound makes the ninth
attempt regression fail, recorded in `/tmp/zasp-daemon-trace-bounds-red.log`.

Independent review found that holding the state mutex across I/O could block
evidence polling. A real stalled-handler regression failed before the fix. State
locking is now short-held, an in-flight reservation permits only one handler,
and request context/read/write deadlines are five seconds. Socket test clients
have two-second timeouts. Replay cannot open while a handler is in flight.
All trace races pass in 2.089 seconds. Evidence:
`/tmp/zasp-daemon-trace-poll-red.log` and `/tmp/zasp-daemon-trace-poll-green.log`.
Final independent source re-review reports no findings; it did not rerun tests.

Superpowers isn't installed. The previously disclosed official upstream
test-first, verification and independent-review fallback applies. These checks
verify test helpers, not completion of an original product microtask.

## Composition implemented and repeated locally

Run only in an owned, inspected, networkless PostgreSQL 18 reference container,
with bounded private tmpfs, read-only root and exact read-only binary binds. Root
fixture setup must be distinguished from the unchanged production daemon running
as UID/GID 65532 with zero effective capabilities. PostgreSQL runs non-root.

Use the real migration runner through schema 48, separately registered API/ingest
principals and real public enrollment/rotation handlers. Browser identity and
artifact storage remain explicit fixture limitations. Discover one prepared,
sealed source using the actual daemon, not a consumer-loop test substitute.

After first actual ingestion commits, lose its response and keep retries gated.
Join the first daemon before inspecting its pending checkpoint and opening replay.
Rotate the real token, atomically replace its owned file and restart the unchanged
executable against unchanged source/state. Compare exact request bytes/key and
known issued-credential digests. Require one sensor-scoped batch, one artifact,
five stages and one outbox entry, including detection of duplicates under another
batch ID. Verify actual durable ACK source/destination, generation inode,
manifest/seal digests and progress. File existence alone isn't acceptance.

All waits and cleanup must be bounded. Cancel handlers independently, join every
child before removing owned state, preserve failure evidence and inspect container
exit/OOM state before exact removal. Repeat the focused composition and review
before full affected tests/UI verification and publication. Real producer-daemon
reclamation, Kubernetes projection, live Tetragon-to-browser discovery and deployed
infrastructure remain open gates.

The complete composition above now runs in
`TestRuntimeAcceptanceActualDaemonLostSuccessReplay`. PostgreSQL 18.6 uses real
schema-48 migrations and six registered database principals. The ordinary
consumer binary runs as UID/GID 65532 with zero effective capabilities. No product
test switch, SQL change or released migration edit was needed.

Review found two missing proof checks: returned receipt IDs weren't compared with
the persisted batch ID, and automatic temporary-directory cleanup could delete
state after a failed join. Both are corrected. Shared ownership cleanup runs after
all child cleanup, reports PostgreSQL wait errors and preserves roots after any
failure. It validates every original root inode/path before removing any root.
Linux regressions cover joined, failed-join and replaced-root outcomes. Both HTTP
receipt IDs must equal the same original SQL authority. Independent re-review
reports no findings in these corrections; the reviewer didn't rerun the container.

The corrected composition, all trace cases and ownership cases passed twice:
3.37s and 2.85s for the composition. Logs:
`/tmp/zasp-daemon-compose-reviewed.log` and
`/tmp/zasp-daemon-compose-reviewed-repeat.log`. Inspection is in
`/tmp/zasp-daemon-compose-reviewed-inspection.json`. Both exits were zero, PID zero
and no OOM. These supersede the earlier pre-review 3.85s and 3.30s passes.

`scripts/sensor-daemon-replay.mjs` builds all three binaries, inspects exact mounts
and container isolation before starting, runs the composition twice, checks an
actual PASS (not a skipped test), verifies no OOM/zero PID and removes only the
stopped owned container. Failed runs retain host evidence and stopped container
metadata; private tmpfs doesn't survive container exit. Its command groups use
the existing joined bounded command owner. Compilation has a five-minute limit
per binary; container execution is limited to 130 seconds per attempt, with a
120-second Go test deadline. The CI step has a 15-minute limit.

Runner tests first failed on the missing module, then passed five cases. The CI
step assertion failed before wiring and then all six cases passed. Logs:
`/tmp/zasp-daemon-runner-red.log`, `/tmp/zasp-daemon-runner-green.log`,
`/tmp/zasp-daemon-runner-ci-red.log`, `/tmp/zasp-daemon-runner-ci-green.log`.
The actual runner then passed both attempts (3.26s, 2.60s) and verified exact
container removal: `/tmp/zasp-daemon-runner-actual.log`. Image manifest:
`postgres:18.6@sha256:4d155aa3f2c2cc1838bb70e81396f76373ec7275ec9ce9cf32873cd677c9a992`.
The Linux arm64 runner-built binary SHA-256 values were:

| Binary | SHA-256 |
| --- | --- |
| apiserver.test | 5b39d1301f9c13d4ded11024730055b9ecfdca8f16981d92c61ed8d18dd17be0 |
| sensor-agent.test | fd4d08be9b1098269d51261ec16f3fe0b6456a87451835042d7aa609179233c6 |
| sensor-agent | 58b0aad54e0d58b092907d48da9edbf3b2c9d10a1605d5c88b02d4646dfc9207 |

Independent runner review found that a failed command join could skip Docker
shutdown and that sequential command budgets could exceed CI's deadline. Cleanup
now attempts every join and container reconciliation independently, aggregates
failures and forbids root deletion after any failure. A monotonic 12-minute
execution deadline reserves three minutes before CI's 15-minute stop. New tests
cover failed join, failed container cleanup, success ordering and remaining time.
All nine runner tests plus four existing command-owner tests pass (13 total):
`/tmp/zasp-daemon-runner-cleanup-green.log`; missing-helper RED is retained in
`/tmp/zasp-daemon-runner-cleanup-red.log`. The corrected runner passes the actual
composition twice again (3.72s and 2.76s), verifies no OOM and exact container
removal: `/tmp/zasp-daemon-runner-reviewed-actual.log`.

Full sensor races pass in 146.820s: `/tmp/zasp-daemon-final-sensor.log`.
The first pinned verification run failed an existing Attack Lab timing test:
its 20ms caller deadline included temporary credential filesystem setup, and the
collection method rejects a context that's already expired at entry as malformed.
The original focused case passed 20 repetitions, confirming intermittent timing.
Both caller-deadline tests now start their clock after fixture setup, with all
limits/assertions and production code unchanged. Thirty repetitions of both
corrected cases pass in 5.832s: `/tmp/zasp-daemon-existing-timeout-fixed.log`.
The failed broad run remains in `/tmp/zasp-daemon-final-ui.log`.

The two manually created disposable proof containers were inspected as exited,
PID zero, exit zero and no OOM, then removed by exact ID without force. Their
absence was checked; host logs and final inspection remain in
`/tmp/zasp-daemon-manual-final-inspection.json`. No unrelated container was touched.

Full API races and a fresh pinned UI/build verification are running. Hosted CI and
publication of this branch are not yet claimed. Counts remain 535/132/61.

Final source re-review reports no findings in the runner deadline/cleanup fixes,
the narrow Attack Lab fixture timer correction or the workflow contract. The
workflow contract now requires all 16 steps, including the actual daemon proof;
four hostile mutations reject omission, skip conditions, missing timeout and
allowed failure. Its 23 cases pass locally. The earlier full run correctly failed
the old 15-step contract (`/tmp/zasp-daemon-final-ui-retry.log`), and the final
fresh run includes the updated contract. The production source-release gate
passes: `/tmp/zasp-daemon-final-release-source.log`. This isn't a deployed canary,
image signature or live provider check.

Final UI verification passes all 1,188 tests in 196 files and typechecking.
Lint then rejected an explicit throw inside the runner's finally block. The
runner now retains execution and cleanup errors separately, combines them when
needed and throws after cleanup, without losing the original failure. Final
runner/command-owner tests pass 13/13, lint passes and the actual runner passes
twice again (3.66s and 3.39s), with exact removal. Evidence:
`/tmp/zasp-daemon-final-ui-stable.log`, `/tmp/zasp-daemon-runner-final-unit.log`,
`/tmp/zasp-daemon-runner-final-lint.log`,
`/tmp/zasp-daemon-runner-final-actual.log`.

The remaining verification commands were run after that correction: production
source/import tests, seven staging gates, all 41 release contract/gate tests,
production build, compiled import closure (seven client/eight server chunks) and
the 728-row ledger all pass. The build produced `dist/standalone/server.js`.
This is a combined verification record, not a claim that the earlier interrupted
`npm run verify` invocation exited successfully. No web runtime code changed.

Full API races pass in 596.655 seconds:
`/tmp/zasp-daemon-final-api.log`. All local verification for this proof is complete;
publication, hosted CI and merge of this branch remain pending. Original scope
and production task counts are unchanged.
