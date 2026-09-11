# Lineage release verification checkpoint

September 11, 2026. Changes are published in PR 43 from
`codex/runtime-sensor-lineage`; hosted checks found a cleanup defect, and the main
merge is held while its correction is verified.
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

## Hosted cleanup failure

The first API/UI checkpoint passed push CI 34602348318. Subsequent pushes
34602656142 and 34602697676 passed UI verification but failed the harness SIGTERM
test: two Go compiler descendants still referenced its private TMPDIR after the
immediate `go build` process exited. The same test failed on the documentation
checkpoint's push CI 34602817317 and PR CI 34602820246. Only the superseded PR run
34602731586 was canceled; the other cancellation requests found already completed
runs. Main was not merged.

The hosted failure is retained in `/tmp/zasp-lineage-ci-failed.log`. Two new
deterministic regressions reproduced the parent-only cleanup defect, including
a TERM-resistant child and an already-exited parent:
`/tmp/zasp-owned-command-red.log`. Commands now get an owned POSIX process group,
bounded TERM/KILL shutdown and completion that waits for inherited output pipes
to close. Completed historical commands aren't signaled again. Go compiler
scratch is under the harness-owned root and is removed only after command
settlement. This isn't a claim about descendants that deliberately escape their
process group and close inherited pipes.

Another failing test and independent review caught cleanup rethrowing an already
settled spawn error. Cleanup now finishes, while the command's completion retains
its original error. All four helper tests pass independently. The full selected
Node CI invocation passes 71 tests with two explicit opt-in signal fixtures
skipped: `/tmp/zasp-lineage-ci-contracts-local.log`. The real early harness SIGTERM
test passes with both the normal cache and a private empty Go cache, with owned
process/root removal and unrelated-root preservation. Cold-cache evidence:
`/tmp/zasp-lineage-command-cold-cache.log`. Final independent review found no
remaining concrete blocker. Fresh full UI/build verification passed all 1,180
tests, typecheck/lint, source contracts, compiled imports and the 728-row ledger:
`/tmp/zasp-lineage-process-group-ui.log`. The release-source gate also passed:
`/tmp/zasp-lineage-process-group-release.log`. The composed run has passed its
local runtime pipeline and completed all browser flows and owned cleanup with
exit 0 in `/tmp/zasp-lineage-process-group-composed.log`. Its console was clean.
The correction is published as `bd5528b2`. Push CI 34604327038 and PR CI
34604332018 passed the cleanup regression but failed the database gate below.
Product API and sensor code are unchanged by this harness-only correction.

## PostgreSQL compatibility gate remains open

Both runs failed the migration runner at released migration 13, before migration
48. The hosted Ubuntu 24.04 image uses PostgreSQL 16.15. Local full-suite evidence
used PostgreSQL 18.3. Earlier green CI that didn't expose PostgreSQL tools must
not be interpreted as a full database compatibility pass. Failed hosted evidence:
`/tmp/zasp-lineage-corrected-ci-backend-failed.log` and
`/tmp/zasp-lineage-corrected-ci-full.log`. Subsequent sensor acceptance and Attack
Lab CI steps were skipped, not passed.

A disposable, non-networked PostgreSQL 16.12 container reproduced the runner's
v13 refusal. After that rollback, applying the exact released SQL only inside the
disposable diagnostic database allowed catalog inspection. Security readiness is
true on both versions, but the v13 live fingerprint is
`5550b4043c2d28e777b3988c6d484cd7408c49c295f9856ca5e08c10328c56f4`
on 16.12 and the pinned
`6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c`
on 18.3. Multiset comparison found exactly 135 additional NOT NULL constraint
catalog entries and 18 table-owner MAINTAIN ACL entries on 18. All remaining
canonical rows match. No schema check or released SQL was changed.

Evidence is in `/tmp/zasp-pg-catalog-diagnostic.FOX8OU/`: `postgres16.log`,
`postgres18.log`, the temporary Go overlay diagnostic and `container-inspection.json`.
The inspected diagnostic container exited 0 without OOM and had only the read-only
test-binary bind, no named volumes. It was removed by its exact ID. The shared
image and unrelated containers were unchanged.

The workflow correction pins Ubuntu 24.04 and reference PostgreSQL major 18,
installs through the official signed PGDG apt repository using a SHA-256-pinned
repository key, checks the actual server major and places its complete binary
directory first on PATH. Minor releases follow the signed major-18 package and
the selected server version is logged. This is a reference-environment correction,
not a fixed PostgreSQL 16 compatibility defect or an 18-only product contract.
The two workflow regression runs fail before the correction, first on the floating
OS and then on ambient database selection. Logs:
`/tmp/zasp-pg-reference-red.log`, `/tmp/zasp-pg-reference-setup-red.log`.

Original scope requires Neon, multi-tenant SaaS and the same binaries/schemas for
single-tenant installation, with no original PostgreSQL major restriction. Later
implementation plans mention 15+, 16 and 17. Independent scope review confirms
that those expectations can't silently become 18-only production support. A
verified compatibility design must address bootstrap as well as forward upgrade:
v13 rejects before commit and v14 requires v13 readiness, so a later migration
alone isn't a reachable repair. Preserve released SQL and pinned drift-denial
authority. Actual Neon majors, supported deployment configurations and the older
major compatibility matrix remain unverified release gates. Production acceptance
is withheld and original task counts don't change.

The reference-setup regression suite passes all 19 tests. Independent review
caught a dependent release contract looking for the former setup-step name; its
RED test is preserved in `/tmp/zasp-pg-reference-release-red.log`. The corrected
contract retains ordering/tool checks and adds explicit OS and database-major
assertions. Reviewer reruns pass both suites and final review reports no remaining
concrete finding. Shell syntax validation passes. These checks don't substitute
for executing the signed apt installation on the hosted runner.

Fresh full verification exits 0 with 1,184 UI tests, typecheck/lint, contracts,
production build, seven client/eight server compiled chunks and the unchanged
728-row availability ledger. Evidence: `/tmp/zasp-pg-reference-ui.log`.
The final release-source gate also exits 0:
`/tmp/zasp-pg-reference-release-source.log`. Built-image signatures/scans and live
provider/DNS/TLS acceptance remain separate deployment gates.

The reference correction is published as `54705e99` through the unchanged push
guard. Push CI 34606556303 and PR CI 34606560539 both installed the signed
PostgreSQL 18 packages and passed UI/build, cleanup, release-source and maintenance
alert steps. Both passed the migration and runtime-index packages but then failed
the enrollment-pairing HTTP test below. Subsequent sensor/Attack Lab steps were
skipped; neither run is a complete pass.

Two extra isolated Linux checks use PostgreSQL 18.6 from the official arm64 image
manifest `sha256:4d155aa3f2c2cc1838bb70e81396f76373ec7275ec9ce9cf32873cd677c9a992`.
The v13 diagnostic matches the pinned fingerprint and security readiness. The
existing `TestReleaseMigrationReachesExactPostgresTargetFromEmptyV1AndV2AndRejectsDrift`
passes in 6.02 seconds. Despite its historical name, its actual assertions cover
empty-to-48, idempotent 48, full rollback, v1-to-48 and checksum-drift refusal; it
doesn't separately set up a v2 starting state. This is a non-race Linux fixture
pass, not a claim about the actual CLI subprocess or hosted full-suite result.

Evidence: `postgres18-linux.log`, `postgres18-release.log`,
`container18-inspection.json` and `container18-release-inspection.json` under
`/tmp/zasp-pg-catalog-diagnostic.FOX8OU/`. Both containers ran as the image's
non-root postgres user with no capabilities/network, read-only root, bounded
memory/tmpfs and one read-only binary bind. Both exited 0 without OOM and were
removed by inspected exact IDs. Their logs and the pinned image remain available.

## Token expiry precision

Push 34606556303 and PR 34606560539 passed the actual migration runner suite in
86.973 and 79.425 seconds. Both then failed
`TestRuntimeEnrollmentPairingMigrationAndAuthority`: the real public sensor-create
handler returned 503. Evidence: `/tmp/zasp-pg-reference-ci-failed.log` and
`/tmp/zasp-pg-reference-pr-ci-failed.log`.

The handler passed a nanosecond expiry to PostgreSQL, which stores microseconds,
then required the committed expiry to equal the original nanosecond value before
revealing the one-time credential. That mismatch can produce a committed token
with a 503 response. A forced sub-microsecond clock reproduces the same failure
against local PostgreSQL, independent of the host clock's precision. The RED run
also reproduces creation and rotation failures in a precision-boundary double:
`/tmp/zasp-sensor-expiry-red.log`.

The fix truncates the intended expiry to microseconds before mutation. Exact
returned token ID, generation and expiry checks remain unchanged. TTL isn't
extended. No released migration, authentication check or SQL permission changes.
Fifty unit cases cover create/rotate, sub-microsecond clocks, a fractional TTL,
UTC conversion and refusal of both positive and negative 1ns/1us authority drift.
The real paired API test forces fractional time, verifies exact persisted and
returned expiry after create and rotation, ingests with the replacement token and
denies the old token before any artifact write. Its first negative assertion
expected 401; the existing ingest contract is 403. The failed diagnostic preserved
that 403 with zero artifact writes in `/tmp/zasp-sensor-expiry-revoked-status.log`.
Only the test expectation was corrected.

All focused handler races and the real PostgreSQL pairing test pass in 8.071
seconds: `/tmp/zasp-sensor-expiry-verified-focused.log`. Independent review reports
no findings and separately passes all 50 precision cases. Fresh full UI/build
verification exits 0 with 1,184 UI tests, contracts and the unchanged 728-row ledger:
`/tmp/zasp-sensor-expiry-ui.log`. The first full API run started before the new
401-to-403 test correction and cannot count as a final passing invocation; a
final-code full run remains required before merge.

The same final focused tests pass on non-root Linux PostgreSQL 18.6: five
top-level tests, including all 50 precision cases and the real pairing authority
test in 3.31 seconds. Binary SHA-256:
`982c693cb58ce45cbf579321575ad2d7568921b48f323bc1010fafa91b459bae`.
Evidence: `/tmp/zasp-sensor-expiry-linux.log` and
`/tmp/zasp-sensor-expiry-linux-inspection.json`. The bounded, networkless container
had read-only root, no capabilities and only a read-only binary bind. It exited 0
without OOM and was removed by its inspected exact ID. This run has no race
instrumentation; the separate host run supplies focused race evidence.
The final release-source gate passes in `/tmp/zasp-sensor-expiry-release-source.log`.

## Retained coverage and the commit-time secret scan

Expiry correction `c24bdf1d` is published. Push CI 34608709266 and PR CI
34608714471 failed the release contract's full-history Gitleaks scan on the fixed
HTTP idempotency identifier in `sensor_public_precision_test.go:69`. Independent
inspection of that immutable commit confirms this is a test correlation value,
not authentication material. The correction adds one exact introduction-commit
fingerprint to `.gitleaksignore`. No rule, directory or current file is excluded.
Gitleaks 8.30.1 then passes all 1,381 commits in 6.04 seconds:
`/tmp/zasp-sensor-expiry-gitleaks-reviewed.log`. The earlier precommit UI checks
had scanned HEAD before that new test entered history. A postcommit scan is now
required before this correction is pushed.

The broad API runs also exposed stale installed-process fixture expectations.
Cumulative coverage uncertainty was being classified as current activity, and
retirement expected only two lock files despite the new durable coverage file.
The test-only correction reports cumulative coverage through the existing child
result, classifies idle activity on a copy, and verifies exact bounded,
enrollment-bound coverage after retirement and another idle restart. The retained
slot-zero seal and assignment are a deduplication watermark, not active work.
Other slots must stay empty, and idle restart must leave the file bytes unchanged.
Production accounting, credential checks and retirement behavior are unchanged.

The initial correction had a local variable redeclaration, then an incorrect
all-empty-watermarks assertion. Both failed before publication and were fixed;
the retained watermark is intentional. Logs are preserved in
`/tmp/zasp-retirement-coverage-api.log` and
`/tmp/zasp-retirement-coverage-api-fixed.log`. Final focused real-PostgreSQL races
pass in 43.714 seconds: `/tmp/zasp-retirement-coverage-verified-api.log`.
The idle unit passes locally in 2.095 seconds and independently in 1.043 seconds.
Final independent review reports no findings in these test/gate corrections.

The earlier broad run in `/tmp/zasp-sensor-expiry-final-full-api.log` compiled
before the coverage fixture correction and fails the old two-file assertion in
454.544 seconds. It isn't final-code evidence. Fresh stable-code UI/build
verification passes all 1,184 tests, typecheck/lint, contracts, seven client/eight
server compiled chunks and the unchanged ledger in
`/tmp/zasp-retirement-stable-ui.log`. Full API races pass in 547.091 seconds in
`/tmp/zasp-retirement-stable-full-api.log`; full sensor races pass in 152.943
seconds in `/tmp/zasp-retirement-stable-sensor.log`. The source-release gate
also passes in `/tmp/zasp-retirement-stable-release-source.log`.

Correction `0bc905ac` is pushed through the unchanged credential guard. Its
postcommit Gitleaks scan passes all 1,382 commits in 4.82 seconds with no leaks:
`/tmp/zasp-retirement-postcommit-gitleaks.log`. Push CI 34610595193 passes in
15m30s and PR CI 34610598964 passes in 15m36s. Both execute every stage, including
sensor lineage/authenticated replay and Attack Lab network enforcement.

PR 43 merged the exact verified head `0bc905ac7f4214be79251037a4437cf8cf07464b`
at 2026-09-11 14:47:56 UTC as main
`c30d9fa68d230effcca63b6345a0c2a10d1b3270`. Main CI 34612285514 passes every
stage in 16 minutes, confirmed against that exact SHA. Deployment isn't claimed.
Original task classifications and
production gates are unchanged. Work on the next daemon replay proof is isolated
in a separate worktree and isn't part of this verified commit.
