# Executing frozen runtime correlation

In progress on `codex/runtime-candidate-executor`, based on consumer commit
`7aba535d` in PR 41. Push CI 34535065881 and PR CI 34535110848 passed.
PR 41 merged as main `4f454ade`; main CI 34536010806 passed.
PR 40 is on main `612f12d3` with all three checks passed.

Original scope and all 728 classifications are unchanged: 535 production-available,
132 component-only, 61 external gates. No M3-46/M3-47/M7-07 completion credit.
Production v2 job creation and deployment defaults remain disabled. This unshipped
branch now has opt-in v2 configuration, database injection, compatible v1/v2
dispatch and downstream receipt acceptance. The original sandbox/container/cgroup/
process scope is intact.

## Current boundary

V2 construction requires a candidate authority. Capability-free legacy `Execute`
rejects v2 before dependency I/O. Authorized execution checks the private worker,
token and live lease, retains the exact verified index bytes through the SQL
admission call, and independently checks the returned snapshot's index digest,
scope, batch, generation and archive digest before correlation effects.

Candidate overflow and malformed inputs quarantine without attribution; denial is
terminal denied; database unavailability retries; unknown failures return a fixed
unknown-outcome error. Nothing forwards provider messages or lease credentials.
Cancellation and local lease expiry are checked before graph, before receipt and
before returning success. Buffers borrowed by candidate admission are cleared.
These local checks don't replace SQL's live fence or authorize effects on their
own. A successful receipt write followed by cancellation still returns retryable.

The existing v1 path and receipt bytes remain unchanged. V2 uses the new pure
snapshot-bound correlator and canonical receipt. The unit-level fixed-snapshot
replay tests use declared adapters. Actual local Graph/S3 crash recovery with
late-conflict admission is verified separately below; neither grants producer
activation or deployment credit.

## Verification being collected

`/tmp/zasp-frozen-executor-red.log` failed on the missing authority config and
authorized execution method. The first implementation run failed because the
changed-receipt test supplied an invalid item ID, before reaching its intended
boundary. The fixture now uses a valid event ID and still changes exact receipt
bytes. `/tmp/zasp-frozen-executor-green.log` passes the focused v1/v2 checks.
Full worker races initially passed in 8.368 seconds in
`/tmp/zasp-frozen-executor-worker-full.log`; independent review found no blocker
in that draft but required explicit renewed-lease liveness checks.

The renewal regression failed in `/tmp/zasp-frozen-executor-renewal-red.log`.
Inspection also found the processor passed the original expiry to later
heartbeats and completion, where the real repository rejects expired leases.
A private per-execution synchronized window now records only successfully
confirmed heartbeat expiry; it never changes scope, batch, attempt or credentials.
Subsequent heartbeat, v2 executor and finish calls use the current expiry.

The first fix still failed because the graph snapshot builder validated the old
lease. Correcting that call passed the full worker races in 8.413 seconds in
`/tmp/zasp-frozen-executor-renewal-worker-final.log`. A database response may still
be rejected against its originally submitted local deadline. The executor permits
one exact snapshot replay only when a later confirmed lease window exists and the
context remains live. Continued uncertainty stays retryable without effects.
Bounded replay tests now use an expiry-checking stage authority, with zero, one
and two uncertain responses. These are declared adapters, not real DB/Graph/S3
renewal proof. The expanded full worker run passed in 8.903 seconds in
`/tmp/zasp-frozen-executor-renewal-bounds.log`.

Independent review then found a concrete blocker: a heartbeat returning success
after its own context timeout could publish a renewed expiry. The regression
failed first in `/tmp/zasp-runtime-heartbeat-late-success-red.log`, retaining the
late renewal. The keeper now captures the heartbeat context error before canceling
that context and also requires the parent execution context still live. A late
success cancels execution without updating expiry or permitting downstream I/O.
Independent review accepted this correction conditional on verification. Its first
full worker rerun failed in the unchanged parallel projection test
`TestProjectionProcessorKeepsLeaseAliveUntilDurableCompletion`: durable completion
didn't start within its one-second assertion. The failure is retained in
`/tmp/zasp-runtime-heartbeat-late-success-worker.log`; its cause isn't established
by a passing retry. Ten focused repetitions passed in 2.312 seconds. Source
inspection then found the fixture's unbuffered channel and nonblocking send can
drop the completion signal before the test receives. The channel now retains one
signal; no production projection behavior or assertion timeout was changed.

The next full run exposed a separate shutdown race in the new keeper: successful
finish cancels its loop, but an in-flight heartbeat treated that normal
cancellation as lease loss. The keeper now drops any renewal after parent
cancellation and exits without changing expiry. A heartbeat deadline while the
parent is live still cancels execution and returns an error. The processor checks
its caller context after completion, so this doesn't accept a canceled caller's
late success. New tests cover both shutdown and canceled completion. Twenty
focused race repetitions passed in 4.453 seconds in
`/tmp/zasp-runtime-renewal-shutdown-repeat.log`. The final full worker race suite
passed in 9.184 seconds in `/tmp/zasp-runtime-renewal-shutdown-full.log`.
Independent review found no blocker in the corrections. The 728-row ledger and
diff checks pass. The executor branch is still unpushed; broader integration,
UI/release checks and real DB/Graph/S3 execution proof remain.

## Production composition and exact readiness

The production factory injects the registered PostgreSQL candidate repository
through the existing worker database. The v2-configured dispatcher accepts only
v1/v2 claimed jobs and uses a per-call config copy for v1; it doesn't mutate the
shared executor or reinterpret old jobs. The v1 receipt bytes stay identical and
don't query candidate authority. Projection now accepts canonical v2 correlation
receipts while retaining the committed predecessor effect-digest check.

`/tmp/zasp-runtime-v2-composition-red.log` failed on the missing factory; focused
checks then passed. The first full run found an obsolete test treating v1 as an
unknown version; that negative now uses v3. The full worker race suite passed in
9.248 seconds in `/tmp/zasp-runtime-v2-composition-worker-final.log`.

Independent review found v2 could still report ready on schema 46. The corrected
test-first run `/tmp/zasp-runtime-candidate-readiness-red-corrected.log` reproduced
the false readiness and missing repository method. Its initial test draft also
had a wrong stub field and missing database interface method; those were fixed
before the meaningful RED run. V2 composition now requires the exact schema-47
checksum/live fingerprint and registered correlation principal, without fallback.
The response decoder rejects aliases, unknown/duplicate fields, null and false;
query cancellation and panics stay unavailable. V1 readiness remains unchanged.

The actual PostgreSQL test rejects predecessor 46, future 48, checksum and grant
drift, and accepts exact 47 again after restoration. Its first role-revocation
case failed because the fixture revoked as the wrong grantor, leaving the grant
intact. The corrected test uses the registration function's actual grantor and
asserts membership is gone before probing readiness. All PostgreSQL cases passed
in 6.204 seconds in `/tmp/zasp-runtime-candidate-readiness-postgres-final.log`.
The first full runtime-event/correlation/worker race run passed in 3.597/1.896/
8.866 seconds in `/tmp/zasp-runtime-candidate-readiness-full.log`. Independent
review found the composite gate closes the finding, conditional on test results
and the remaining integration gates. After adding cancellation/panic/nil-context
negatives, the final full race suites passed in 3.731/1.445/8.700 seconds in
`/tmp/zasp-runtime-candidate-readiness-final-full.log`. These checks don't activate
production v2.

All actual candidate PostgreSQL tests passed in 52.974 seconds in
`/tmp/zasp-runtime-candidate-executor-postgres-suite.log`, including the existing
freeze/replay and policy supersession characterization. Platform-wide compilation
passed in `/tmp/zasp-runtime-candidate-executor-platform-compile.log`.
Fresh `npm run verify` passed in `/tmp/zasp-runtime-candidate-executor-ui-verify.log`:
196 UI test files and 1,179 tests, typecheck, lint, production source/compiled
import checks, release contract checks, UI build and the 728-row ledger. This
isn't the full real-dependency release gate or a deployed-user acceptance pass.

Fresh graph-proof preflight found the historical `proofs/neo4j-graphstore` runner
didn't compile: it still called the removed `neo4jstore.New` constructor. The
failure is recorded in `/tmp/zasp-runtime-candidate-existing-graph-proof-compile.log`.
Its plaintext/no-auth setup also didn't meet the current production adapter's
verified-TLS/authentication boundary. Historical graph-proof success isn't a fresh
pass for this executor. Restore an owned authenticated TLS fixture using the
current adapter before claiming real graph crash/replay coverage; don't weaken
the production constructor to accommodate the old runner. The current production
adapter's component classification is unchanged; live composed proof stays open.

## Restoring actual graph evidence

The graph proof now uses the current `NewProduction` adapter, an opaque auth
reference, generated disposable credentials, and verified `bolt+s`. No production
constructor or trust requirement was weakened. The standalone proof process uses
an exact generated loopback certificate through Go's fallback-root mechanism;
this doesn't install a system CA or change production trust. Neo4j Community's
missing publisher-role attestation is explicitly excluded from this local proof.

The runner builds before allocating a container, then generates a one-day
certificate for IP 127.0.0.1 and a matching private key. The private key is in a
0600 host archive inside an owned 0700 directory, never a world-readable file.
Bounded stdin sends that archive to the already verified exact container;
tar ownership sets the key to Neo4j UID/GID 7474 and mode 0600 before startup.
The archive buffer is cleared after copy. Build, provisioning and proof subprocess
handles now participate in cleanup settlement. Exact image/name/label/environment/
volume checks and reverse cleanup remain required. No shared container changed.

The initial red tests are `/tmp/zasp-graph-tls-adapter-red.log` (removed constructor)
and `/tmp/zasp-graph-tls-runner-red.log` (missing auth/TLS setup). The first actual
container run passed three nodes, two edges, replay, scoped reads, Organization-B
zero state, schema audit and exact resource cleanup in
`/tmp/zasp-graph-tls-live-first.log`. A second run also rejected an untrusted
certificate and wrong credentials before passing the same persistence checks:
`/tmp/zasp-graph-tls-live-negatives.log`. These aren't candidate-executor crash/
replay tests, and they do not prove production role attestation or deployment.

The verification-wiring regression failed first in
`/tmp/zasp-graph-proof-verification-wiring-red.log`; `npm run verify` now includes
`graph:neo4j:test`, so removal of a required adapter constructor cannot silently
leave this proof uncompiled. The graph/adapter/proof race tests plus 25 runner/
license tests pass in `/tmp/zasp-graph-tls-complete-tests.log`. Material tests cover
certificate scope/expiry, exact archive ownership, host modes, overwrite denial,
foreign/linked directory denial and bounded stdin. Independent review found no
concrete blocker, conditional on the live negative tests and remaining gates.

The final live lifecycle passed in `/tmp/zasp-graph-tls-live-final.log`, with
positive connectivity/authentication before rejection probes and the current
production adapter positive check afterward. A new subprocess regression found
stdin setup could throw after spawn without terminating the child. It failed in
`/tmp/zasp-graph-tls-stdin-settlement-red.log`; the supervisor now kills and waits
for that child before cleanup. All 24 runner tests passed in
`/tmp/zasp-graph-tls-stdin-settlement-green.log`. Independent review accepted the
settlement correction and inspected the live evidence, conditional on full
verification/shipping gates. No executor activation was approved.

The first full verification after adding graph coverage stopped at two exact
OpenAPI verification-command assertions, not product behavior. Both expected
commands now include the new graph check while preserving every prior check.
The failed run is retained in
`/tmp/zasp-runtime-candidate-executor-graph-ui-verify.log`.
The next run reached UI tests and found four equivalent assertions in three
quality-contract files still pinned to the old command. Their exact expected
sequence now includes the graph check; all prior checks remain. That failure is
retained in `/tmp/zasp-runtime-candidate-executor-graph-ui-verify-final.log`.
The actual candidate-readiness test now has the `TestRuntimeCandidateAuthority`
prefix required by the existing CI selector. It passed again in 6.958 seconds in
`/tmp/zasp-runtime-candidate-readiness-ci-selected.log`; this rename changes CI
coverage, not test semantics.

Final fresh verification passed in
`/tmp/zasp-runtime-candidate-executor-graph-ui-verify-complete.log`: all 196 UI
test files/1,179 tests, graph adapter/proof tests, typecheck, lint, release
contracts, UI build, compiled import checks and the 728-row ledger. The live
graph lifecycle also passed again after the subprocess-settlement fix in
`/tmp/zasp-graph-tls-live-settlement-final.log`; its exact container and temporary
resources were removed. The existing CI test selector lists the new readiness
test in `/tmp/zasp-runtime-candidate-readiness-ci-selection.log`.
The batch remains unpushed pending runtime candidate graph/S3 integration and
shipping gates. All 728 classifications are unchanged.

The fixture follows Neo4j's official
[SSL framework](https://neo4j.com/docs/operations-manual/current/security/ssl-framework/)
and [Docker TLS configuration](https://neo4j.com/docs/operations-manual/current/docker/security/).

## Composing the actual graph dependency

The combined runtime harness now owns the same authenticated TLS Neo4j fixture
as the standalone proof. Its dependency retains the exact container and private
temporary directory until explicit close. Cancellation during startup settles the
in-flight operation before cleanup and checks cancellation before each subsequent
allocation step. The missing dependency API failed first in
`/tmp/zasp-runtime-graph-dependency-red.log`; all 26 runner tests passed in
`/tmp/zasp-runtime-graph-dependency-green.log`.

The combined worker process uses the real graph adapter for correlation and
projection. Its supplied test CA is confined to this isolated process; production
trust settings are unchanged. The source-wiring regression failed in
`/tmp/zasp-runtime-graph-composition-red.log` and then passed. The full actual v1
pipeline passed in `/tmp/zasp-runtime-real-graph-pipeline-first.log`, including
normal owned cleanup. Independent review found no blocker in lifecycle, cleanup
ownership or TLS composition. Community publisher-role attestation is still
excluded. The process-global fallback-root initializer must be called only once
in this isolated test process.

The new candidate recovery test is in progress. Missing helper compilation failed
in `/tmp/zasp-runtime-candidate-recovery-red.log`. The first actual run rejected
an incomplete OTLP fixture at ingress in
`/tmp/zasp-runtime-candidate-recovery-live-first.log`; all owned cleanup completed.
The fixture lacked five required context attributes. It now supplies the exact
ten-field shape required by the existing adapter, with no validation change.
The proof selects v2 only for its isolated tenant's pending, never-claimed jobs.
No production producer or deployment default is activated. Required marker
coverage failed first in `/tmp/zasp-runtime-candidate-recovery-wiring-red.log`.
Runner/combined harness tests pass 49 tests with two opt-in skips in
`/tmp/zasp-runtime-candidate-recovery-runner-tests.log`.

The second actual run reached the injected lost receipt response and failed an
incorrect test expectation. The existing executor reports a fixed unknown outcome
for an uncertain S3 write, not a confirmed retryable failure. The test now expects
that result and still requires the actual graph commit and persisted receipt.
The simulated vanished worker records no completion. Evidence is retained in
`/tmp/zasp-runtime-candidate-recovery-live-second.log`.

The third and fourth runs stopped when the late same-organization batch couldn't
claim archive work. The first hypothesis, an empty single SQS short poll, did not
explain the fourth failure after polling was added. Independent review identified
the actual scheduling conflict in the existing SQL: one live held/ack-pending
delivery per organization, plus same-stage live-lease exclusion. The original
coordinator was still renewing the target's delivery. Neither production guard
was changed. Those runs are retained in
`/tmp/zasp-runtime-candidate-recovery-live-third.log` and
`/tmp/zasp-runtime-candidate-recovery-live-fourth.log`.

The corrected schedule stops the target coordinator too, postpones redelivery
through actual SQS visibility, waits for both database leases to expire naturally,
then processes late evidence before making the target visible again. Read-only
observations require expiry with no acknowledgement. No owner changes a lease,
clock, completion, receipt or candidate row. Review accepted this schedule
conditional on an actual composed pass. The stale-worker rejection now requires
one real registered-role SQL invocation and its missing-lease result, not merely
the Go expired-lease precheck. Exact S3 locator comparisons include VersionID;
committed readback is compared to the initially persisted object too. The final
expanded pipeline will recheck both SQS queues after candidate completion.

Fresh full verification passed in
`/tmp/zasp-runtime-candidate-recovery-ui-verify.log`: 196 UI files/1,179 tests,
build, lint/typecheck, compiled imports and the unchanged 728-row ledger. Worker,
runtime-event and correlator races passed in
`/tmp/zasp-runtime-candidate-recovery-go-final.log` (9.494, 4.420 and 2.560 seconds).
Those precede the final scheduling corrections; fresh composed verification is
still required. Runner tests passed again (49 pass, two opt-in skips) in
`/tmp/zasp-runtime-candidate-recovery-runner-final.log`.

The fifth actual runtime-only run passed in
`/tmp/zasp-runtime-candidate-recovery-live-fifth.log`, including owned cleanup.
The final-tree runtime portion also passed inside
`/tmp/zasp-runtime-candidate-recovery-full-composed.log`. That second pass includes
the added durable session assertions (four rows, one recovered Strong event and
one unassigned Probable event), stale-worker SQL denial, and queue/DLQ emptiness
after all new batches. The original frozen PostgreSQL bytes/digest, actual Neo4j
snapshot result, S3 receipt bytes and S3 VersionID survive the crash and later
conflict. This is real local dependency recovery, not producer activation or
live deployment attestation. The same full run completed all existing browser
flows and owned cleanup: authenticated tenant boundaries, runtime enrollment,
worker-backed Sessions/timeline/evidence, and the declared confidence-display
fixture. Browser Strong/Probable attribution from activated production producers
is not established by those v1/browser-fixture paths.

Fresh final-tree UI verification passed in
`/tmp/zasp-runtime-candidate-recovery-ui-final.log`, including all 1,179 tests,
build, import checks and the unchanged ledger. Post-schedule worker/runtime-event/
correlator races passed in `/tmp/zasp-runtime-candidate-recovery-go-post-schedule.log`
(9.692, 3.578 and 1.539 seconds). Independent review found no new blocker,
conditional on final browser/cleanup, release and CI gates.

The production release source gate passed in
`/tmp/zasp-runtime-candidate-recovery-release-gate.log`. It explicitly excludes
built-image signing/scanning, remote CI, live providers and public DNS/TLS.
Graph restoration was committed as `9414767b`; opt-in executor/readiness/renewal
was committed as `cc2c8c52`. Their staged secret and privacy scans found no
credentials or privacy findings. The composed proof and final evidence are the
next dependent commit. No push has occurred yet.

The real SIGTERM proof passed in 32.388 seconds in
`/tmp/zasp-runtime-candidate-recovery-real-sigterm.log`, with no skip. It observes
all three exact-owned runtime/graph containers and both temporary roots, signals
the running combined harness after dependencies are ready, then requires exit
143, removal of those containers/directories and no surviving owned processes.

Still required: sensor lineage emission, composed browser attribution, producer activation,
final scans and PR/main checks. No task credit changed.
Superpowers remains unavailable as an installed skill; the disclosed official
upstream test-first/fresh-verification/independent-review workflow is used.

## Publication checkpoint

The composed proof/evidence commit is `74627be3`, following `9414767b` and
`cc2c8c52`. The verified batch was pushed and PR 42 is open:
https://github.com/crossbizz/zasp-sec/pull/42 . Initial push and PR checks started;
neither is counted as passed yet. The pre-push guard remained enabled. Final
staged secret scans found no leaks. Every privacy warning was inspected and was
a public CI run identifier or synthetic test UUID, with no real personal data.
Main merge and main CI are still pending. This publication checkpoint supersedes
the earlier unpushed status above without erasing the test-failure history.

## CI caught an early cleanup regression

Push CI 34542732669 and PR CI 34542734159 failed the early PostgreSQL SIGTERM
test. The eager graph dependency constructor rejected an inherited forbidden
environment before cleanup was installed. This left its newly created empty
temporary root behind. Local runs without that environment had passed.

The regression now supplies a synthetic, non-secret AWS_REGION value and fails
against the previous implementation in
`/tmp/zasp-runtime-candidate-ci-cleanup-red.log`. Graph construction now happens
only at the dependency startup point, inside the existing try/finally boundary.
Cleanup accepts a dependency that was never constructed. The environment guard
is unchanged; no credentials, proxies or external graph targets were allowed.

The exact early-shutdown regression passed in 1.870 seconds in
`/tmp/zasp-runtime-candidate-ci-cleanup-green.log`. An actual later startup with
the same rejected environment reached migrations, rejected graph construction,
and cleaned PostgreSQL, owned processes and files before exiting nonzero:
`/tmp/zasp-runtime-candidate-ci-constructor-rejection.log`.
The empty root from the RED reproduction was confirmed empty and removed;
unrelated pre-existing temporary roots were left untouched.

The first broad local rerun had two failures unrelated to the constructor fix:
a new comment matched the existing forbidden-word source contract, and running
two harnesses concurrently confused the shutdown test's global root inventory.
The comment was corrected without changing the assertion, and harness runs are
serialized. The exact CI regression command now passes 67 tests with two explicit
opt-in skips in `/tmp/zasp-runtime-candidate-ci-regressions-serial.log`.
Independent read-only review found no concrete blocker, conditional on fresh full
verification and CI. Full verification passed all 1,179 UI tests, typecheck, lint,
build, import boundaries and the unchanged ledger in
`/tmp/zasp-runtime-candidate-ci-fix-verify.log`. The source release gate passed in
`/tmp/zasp-runtime-candidate-ci-fix-release.log`, with its external exclusions
unchanged. The new complete composition has passed actual runtime recovery;
browser flows are still running in `/tmp/zasp-runtime-candidate-ci-fix-composed.log`.
This runnable, reviewed correction can be pushed for CI while that longer check
continues. PR 42 remains unmerged; no task credit changed.

The correction shipped to the PR branch as `3fffdea2`. Its staged secret scan
found no leaks; all four privacy warnings were the two public CI run IDs above,
each repeated in both evidence documents. The pre-push guard stayed enabled.
The full repeated composition then exited zero, including actual recovery,
every existing browser flow and owned cleanup. The separate final three-container
SIGTERM test passed without a skip in 32.246 seconds:
`/tmp/zasp-runtime-candidate-ci-fix-real-sigterm.log`.
The updated PR body was scanned with public-repository visibility and had no
privacy findings. Push CI 34543727745 and PR CI 34543729424 are running against
the correction; neither is accepted until its final result is read.

Both correction checks passed: push 34543727745 in 8m35s and PR 34543729424
in 7m52s. PR 42 merged as main `a4fede82f00e093a9b8e749a065868ba214f666c`.
Main CI 34544444052 is running and is not counted as passed yet. The next branch
is `codex/runtime-sensor-lineage`, based on that exact main merge. Its new failing
sensor restart regressions are uncommitted and were not part of PR 42.

Main CI 34544444052 completed successfully. PR 42 is fully through local,
push, PR and main verification. This closes shipment of the executor/recovery
slice, not producer activation or any additional original task.
