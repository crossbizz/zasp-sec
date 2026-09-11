# Lineage release verification checkpoint

September 11, 2026. Changes are published in PR 43 from
`codex/runtime-sensor-lineage`; hosted checks and the main merge are pending.
No original task credit changes. Earlier entries below retain their observations
at the time; the publication section records the latest state.

## Checks that passed

The full local authenticated runtime-ingest acceptance test passes in 42.448
seconds with the race detector. New cases exercise immediate SQLSTATE 55P03
under a held batch-row lock, release of authentication locks after that failed
lookup, and denial of damaged artifact checksums, batch counts, job digests,
outbox payloads and a missing durable stage. Fixture records are restored and
the original acceptance succeeds again. Evidence:
`/tmp/zasp-acceptance-binding-boundaries.log`.

The runnable-UI workflow now selects the full sensor-agent race suite and the
runtime-acceptance PostgreSQL tests. It checks that `initdb` exists and adds
the PostgreSQL binary directory to PATH to prevent an unavailable fixture
binary from silently skipping these tests. The new contract test failed before
the workflow change. All 42 selected release/staging contract tests pass after
the change. Logs: `/tmp/zasp-lineage-ci-red.log` and
`/tmp/zasp-lineage-ci-contract-green.log`. This is local evidence, not hosted CI.

## Release check failed

The full platform race suite exited 1. The 100,000-row connector reconciliation
index test failed with an unexpected EOF while inserting its history fixture.
Other package passes do not make the full run a pass. Evidence:
`/tmp/zasp-lineage-release-platform-full.log`.

An isolated repetition also exited 1, this time with explicit PostgreSQL
SQLSTATE 53100: `No space left on device` while writing a WAL temporary file.
That confirms disk exhaustion in the repetition, without proving the cause of
every earlier EOF. Evidence: `/tmp/zasp-lineage-release-skew-recheck.log`.
The host volume had approximately 995 MiB available during initial triage and
2.0 GiB after the repetition exited. Neither test is still running. No user
data was deleted to make space.

Docker's configured OrbStack socket was also unavailable when an additional
Linux run was attempted. That run did not create a container or provide Linux
verification. No restart or Kubernetes configuration change was performed.

## Remaining gates

The four missing local M48 boundary-test categories now pass and have independent
review, as recorded below. Successful full backend/UI/build verification and
whole-change release review remain required before a push.

Live Tetragon-to-producer, actual Kubernetes projection, combined running-daemon
rotation through real API/PostgreSQL lost-response replay, and the full original
M3-46/M3-47/M7-07 acceptance remain open. The 535 production-available,
132 component-only and 61 external-gate classifications are unchanged.

Superpowers is unavailable as an installed skill. The previously read official
upstream test-first, verification and independent-review workflow is the
disclosed fallback. No installed-skill or production-readiness pass is claimed.

## Follow-up: rotation and scope isolation

The containing runtime-ingest PostgreSQL race suite passes in 39.480 seconds,
then 39.130 seconds after review tightened the per-request observations. The
final run is `/tmp/zasp-acceptance-rotation-reviewed.log`.

Each foreign-scope case reuses the original sensor ID while changing exactly
one of organization, workspace or environment. The real SQL lookup rejects the
original enrollment binding with SQLSTATE 28000. With the foreign credential's
own valid binding, lookup returns no receipt for the original batch/key. The
actual client/HTTP handler rejects the original envelope before reading its
body. Original batch, stage, outbox and artifact-write observations stay unchanged.

The incomplete-upload case loses the artifact response after the artifact double
stores it. The real reservation remains unfinished. Following actual credential
rotation, both uploading and unknown states return no acceptance. Each HTTP
retry independently proves generation-2 authentication, one reservation attempt
and SQLSTATE 23505, with unchanged reservation/reconciliation data and no second
artifact write. Review required resetting diagnostic fields before each retry;
the final run includes that correction.

The unknown state and reconciliation scheduling time are explicit fixture-only
changes. Actual registered-role claim/finish SQL then finalizes the stored
artifact. Original generation-1 credential provenance, five stages and one outbox
remain. Two subsequent exact-body/key retries using generation 2 retrieve the
receipt without duplicate work. This closes the local boundary gap; it does not
prove deployed object storage, actual worker scheduling or live daemon operation.
Independent final review found no remaining concrete blocker in these changes.

## Recoverable disk cleanup and fresh gates

After checking ownership, contents and open-file use, 15 old goal-owned Linux
test executables were compressed in four exact fixture directories:

- `/tmp/zasp-lineage-retirement-linux.GAYaC0`
- `/tmp/zasp-lineage-recovery-linux.pR0YXy`
- `/tmp/zasp-lineage-completion-linux.cCmTvc`
- `/tmp/zasp-lineage-producer-daemon.wrdjnm`

Their allocated size decreased from 785,752 KiB to 340,428 KiB. Each compressed
stream was decompressed and matched to its prior SHA-256. The manifest is
`/tmp/zasp-release-compressed-binaries.sha256`. All 15 original binary contents
are recoverable from their `.gz` files. Logs, current proof binaries and user
source files were not removed.

The unchanged 100,000-row index test then passed in 73.092 seconds, recorded in
`/tmp/zasp-release-skew-after-compression.log`. That is evidence the local resource
problem was relieved for this test, not that the earlier full suite passed or
the separate default-planner retirement I/O defect was resolved.

CI now checks all four required PostgreSQL fixture executables and writes their
directory to GITHUB_PATH before any verification step. The first fresh UI run
failed its strict workflow contract because the expected step list was stale.
The updated contract requires the full 15-step workflow; all 15 focused tests
pass in `/tmp/zasp-release-workflow-contract-green.log`. Existing gates remain.

Full backend races passed with `-p 1` to reduce simultaneous package-level
fixture disk use, log `/tmp/zasp-lineage-release-platform-serial.log`: 79 packages,
including apiserver in 535.344 seconds. Opt-in external fixtures are not inferred
from an ordinary package pass. The fresh
root UI/build run passed, log `/tmp/zasp-lineage-release-ui-reviewed.log`: all
1,180 UI tests in 196 files, typecheck/lint, source/release contracts, production
build, seven client/eight server compiled chunks and the 728-row ledger. Fresh host sensor-agent
races pass in 135.317 seconds, log `/tmp/zasp-lineage-release-sensor-host.log`.

Twelve more inspected, unopened old executables were losslessly compressed in
`/tmp/zasp-lineage-receipt-linux.0jJhei`,
`/tmp/zasp-lineage-reader-linux.Kc4Abj`,
`/tmp/zasp-lineage-socket-linux.y8w9Lr` and
`/tmp/zasp-lineage-consumer-controller.eNN1D7`.
Their sizes decreased from 606,276 KiB to 256,976 KiB. Decompressed SHA-256 checks
pass against `/tmp/zasp-release-compressed-binaries-second.sha256`. Across both
groups, 27 recoverable binaries save 776 MiB. Logs remain untouched.

The read-only OrbStack status command confirmed `Stopped`, and its machine list
returned no entries. A local start request reported that Docker was ready, and
the Docker server query confirmed version 29.4.0. No reset, data deletion or
Kubernetes context change was requested. Existing unrelated containers were
observed after Docker returned; no container-level actions targeted them. The
explicit local `orbstack` Kubernetes context still refuses connections on
127.0.0.1:26443. Docker availability doesn't prove cluster availability.

The current full Linux arm64 test binary then exited 0 in an isolated container
as UID/GID65532, no capabilities/network, read-only root, 512 MiB memory/no extra
swap and two CPUs. This run isn't race-instrumented; the separate host run is.
Explicit mount/writer/daemon fixture-only tests skip without their required
fixtures; their earlier separate evidence isn't replaced by this ordinary suite.
Log: `/tmp/zasp-lineage-release-sensor-linux.log`. Its SHA-256 is
`7c79933ea3e8132345fbc2d2f7f40ccefcf9518cec8e3d4c1e73418eb0348838`, matching
the previously reviewed final Linux binary. Inspection confirms exit 0 and no
OOM kill. The image's inherited service healthcheck fails because the test
entrypoint doesn't run the service; no service-readiness claim follows. The
ordinary Linux run records 213 top-level passes and 20 explicit skips.

The one stopped test container was removed by its inspected exact ID. It had no
named volumes. Logs, binary and inspection remain at
`/tmp/zasp-lineage-release-nonroot-inspection.json`. No push or production
activation occurred.

## Composed run and the review blocker

The release-source gate passed in `/tmp/zasp-lineage-release-gate-current.log`.
It doesn't replace built-image signature/scan, hosted CI, live provider or DNS/TLS
gates. The full local composed Chrome run exited 0, including the real local
worker pipeline and runtime-enabled red-team fixture. Log:
`/tmp/zasp-lineage-release-composed-chrome.log`. Its browser console was clean,
all owned cleanup phases completed, and its 100 authenticated TLS API reads had
p95 9,941,083 ns. Live collection and managed services remain explicitly NOT RUN.

Running the harness contract alongside Chrome exposed a test isolation defect:
the SIGTERM test treated every newly created global temporary directory as its
child's property. The test now gives its child a private TMPDIR, retains an
unrelated sentinel, and always joins the child on assertion failure. It removes
only empty Go compiler scratch directories after verifying that no process
references that private parent. The first isolated run retained an empty Go
scratch directory and failed its final rmdir; the corrected Node suite passes
23 tests with two opt-in signal fixtures skipped. Log:
`/tmp/zasp-lineage-composed-contracts-signal-fixed.log`.

Independent security review then found that producer-side drops and interrupted
counter uncertainty were stored in seals but never reached sensor health. A
zero-chunk source could be acknowledged and fully erased while health reported
healthy with zero drops. Shipping was held. The new regression reproduced both
known and unknown loss; `/tmp/zasp-lineage-health-red.log` is the failing evidence.

The fix adds one bounded, identity-bound private coverage record with eight slot
watermarks. Producer totals and unknown history are durable before ACK or
retirement, survive restart and slot reuse, and aren't counted again on retries.
Old state without its ledger is unknown; damaged or foreign accounting state
blocks ACK. Filtered events aren't added to drops. Totals use the existing
1,000,000,000 reporting ceiling. The probe treats uncertainty as a current snapshot
so a transient read failure doesn't permanently latch degradation; historical
uncertainty remains sticky in the stored record. Legacy cursor encoding omits
the unused new stream fields.

Boundary races pass in `/tmp/zasp-lineage-health-probe-recovery.log` (18.409s),
including interrupted publication, exact totals through retirement/restart and
ten slot reuses, missing history and malformed/symlink/hardlink/foreign state.
The adapter race suite passes in `/tmp/zasp-lineage-health-adapter-race.log`
(14.202s). The first broader sensor run caught premature accounting writes before
foreign snapshot admission; that ordering was corrected, preserving the existing
no-write rejection tests. Final full sensor races pass in 120.511 seconds:
`/tmp/zasp-lineage-health-sensor-final-race.log`. The final ordinary non-root Linux
run exits 0 with 217 top-level passes and 20 explicit fixture-only skips:
`/tmp/zasp-lineage-health-linux.log`. Its binary SHA-256 is
`04fbac34e030541da9a0d65fde2c347822032751b5b7500c3bb1eee9cede0c44`.

The fresh actual executable also passes three owned-file upload/retirement/token
removal lifecycles (0.33, 0.24 and 0.24 seconds):
`/tmp/zasp-lineage-health-daemon.log`. The root fixture has only
CHOWN/SETUID/SETGID/KILL; its actual consumer child runs as UID65532 with zero
effective capabilities. The executable SHA-256 is
`3b4ddaad6428fd449ae809d313735fdcd1062f5d87c0e373d879eada4c5193b2`.
Both disposable containers had no network, read-only roots and bounded tmpfs,
memory/CPU/PIDs. Both exited 0 without OOM. Neither inherited image healthcheck
is credited as daemon readiness. Projected rotation and real API/PG composition
are separate, not inferred from the owned-file fixture.

Fresh `npm run verify` passes all 1,180 UI tests, typecheck/lint, compiled build
and 728-row ledger: `/tmp/zasp-lineage-health-ui-verify.log`. The release-source
gate passes: `/tmp/zasp-lineage-health-source-release.log`. Independent review
found no remaining concrete blocker in the fix or isolated SIGTERM test.
These production edits supersede the older sensor binary's proof. No new task
credit or production readiness claim follows; counts remain 535/132/61.

## Publication packaging

The initial consolidated local commit `8c136af2` was not pushed. The unchanged
credential hook failed closed because its default 1 MiB input limit was exceeded.
Smaller preflight scans then identified two synthetic user/password URL literals
in negative tests. Those tests now construct invalid userinfo URLs with the URL
library; credential rejection coverage remains. Their focused race tests pass
(adapter 2.468s, sensor 2.075s). No live credential was identified or rotated.

A read-only whole-diff scan using the scanner CLI's documented 2 MiB limit found
zero HIGH items. MEDIUM warnings were reviewed as fixture UUIDs/account IDs,
numeric bounds, dependency version text, loopback service URLs, synthetic bearer
strings and recorded test/CI identifiers. The hook itself wasn't changed,
disabled or bypassed. Publication is being split into dependency-ordered commits
whose individual pushes fit the unchanged hook. The original local consolidated
commit remains recoverable; no force-push is involved.

An isolated first-checkpoint worktree exposed stale schema-47 chart expectations
and historical test timestamps. Packaging now includes schema-48 expectations
with the API migration, and a current legacy sensor event fixture. That sensor
suite passes in 1.852 seconds. The intermediate full UI/build verification then
passed all 1,180 UI tests, typecheck/lint, contracts, production build, compiled
imports and the 728-row ledger. Evidence:
`/tmp/zasp-lineage-publish-first-ui-owned-deps.log`. An initial dependency-directory
symlink made the SBOM tool report missing development dependencies; a private
copy of the existing installed dependencies corrected that fixture setup. The
original dependency directory was unchanged.

Three dependency-ordered commits were pushed separately through the unchanged
credential guard: `1783d2ad` (API/migration and compatible UI), `043a900a`
(sensor collection and loss accounting), and `088226ad` (verification records).
Each push succeeded. Their final tree is identical to the consolidated verified
snapshot. PR 43 is open at https://github.com/crossbizz/zasp-sec/pull/43.
Push CI 34602697676 and PR CI 34602731586 are running at this checkpoint;
neither is recorded as a pass. Main remains at `a4fede82`.

The two final Linux proof containers were removed by their inspected exact IDs
after exit 0. They had no named volumes. Binaries, logs and inspection remain in
`/tmp/zasp-lineage-health-containers.json`; no user data was removed.
