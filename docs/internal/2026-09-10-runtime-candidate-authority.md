# Frozen runtime candidate authority

Status: merged through PR 40 as main `612f12d3`; main CI 34533327507 passed.
No original task credit. M3-46, M3-47 and M7-07 remain unaccepted.
All 728 classifications remain 535 production-available / 132 component-only /
61 externally blocked. The original sandbox/container/cgroup/process scope is
unchanged. Enrollment pairing and lineage preservation alone do not satisfy it.

The preceding concurrent-load diagnostic, PR 39 / commit `81c037ad`, passed
push CI 34523789643 and PR CI 34523836361 and merged as main `8ec83a9b`.
Main CI 34524724253 passed. Its full local
verification and final composed Chrome diagnostic passed. Review permits this
isolated candidate work while the immediate-retirement raw-work concern and
reference-load acceptance remain open. Neither assertion is relaxed.

## Reviewed authority boundary

The existing correlator consumes only candidates from the same archive. Its
executor receives a stage lease but not the worker identity and lease token needed
for a database-fenced admission. Production has no candidate authority yet.

Add one private transaction that admits validated observations and freezes the
candidate snapshot before correlation effects. The transaction must:

- Authenticate the registered correlation worker, exact scope, batch, generation,
  stage, attempt, implementation and live worker/token lease after lock waits.
- Bind the submitted archive bytes and index receipt to the exact committed
  predecessor, raw artifact checksum/version and immutable M45 source/domain.
  An arbitrary digest next to unrelated observations is not sufficient.
- Derive observations from that bound archive, using the registered worker as
  the validated archive decoder, not a public caller or tenant-supplied domain.
- Require fresh active source and anchor authority for new admission. Pairing is
  an enrollment association, not host attestation or permanent authorization.
- Persist immutable observations and the selected bounded snapshot atomically.
  Replays return the original snapshot, not today's candidate set.
- Bind snapshot bytes/digest to correlation results and downstream receipts.
  Worker identity and lease tokens must never enter those artifacts.

Lock ordering must be checked against existing claim, finish, revocation and
recovery paths. Avoid global locks and cross-batch stage locks. Sensor identity
locks use deterministic order; freshness is rechecked after waits. Concurrent
admissions outside the freezing statement's snapshot may be excluded. Describe
that cutoff, never claim complete historical knowledge.

Qualified cluster/node/boot/pod/full-container identity, event-time windows and
contradiction rejection are required. Process IDs need start times; bare reused
PIDs, abbreviated containers and host names are insufficient. Deduplicate by
agent/session identity only after matching observations. Multiple distinct
identities remain Probable with unknown authoritative IDs. Overflow must fail
closed, never truncate an ambiguous candidate set into Strong. Runtime lineage
can produce Strong, never Exact.

## Compatibility and acceptance

Existing `runtime-correlation-v1` jobs and receipts retain their algorithm and
bytes, including retries after prior effects. New snapshot-backed work needs an
explicit implementation and receipt version. Consumers must accept that version
before producers enable it. No existing in-flight v1 work is reinterpreted.

New database authority needs owner-only access, FORCE RLS, exact schema
readiness/fingerprint checks and downgrade refusal when provenance is retained.
No production activation until actual database, pipeline and browser checks pass.

Required acceptance checks (not all passed):

1. Explicit execution capability reaches only the authorized executor; legacy
   execution remains unchanged. Missing or invalid capability fails closed.
2. Crash after graph/receipt effects but before stage finish, admit a conflicting
   candidate, then retry. Snapshot bytes, result digest and attribution stay fixed.
3. Real PostgreSQL rejects foreign scope/domain, expired or replaced leases,
   stale predecessor/archive digests and authority revoked during lock waits.
4. Real PostgreSQL proves deterministic freeze, duplicate admission, overflow,
   late observations, concurrent revocation and retention-safe rollback.
5. Qualified unique and competing lineage, contradiction and time-window cases
   pass, with no false Exact or false unique result.
6. Real five-stage pipeline and Chrome show authentic mixed evidence, tenant
   denial, revocation/recovery/replay and no credential persistence.
7. Full verification, independent Superpowers workflow review, secret/privacy
   scans, runnable-UI push checks, PR checks and main checks pass.

The installed Superpowers plugin is unavailable. Its official upstream TDD,
verification-before-completion and independent review workflow is used. No
installed-plugin or production-deployment proof is claimed.

## Progress evidence

`/tmp/zasp-runtime-execution-authority-red.log` failed on the missing explicit
execution capability and dispatcher. The processor now passes its private worker
and token fields to an optional authorized executor; legacy executors receive
only the original lease. The dispatcher validates local shape and current lease
expiry, catches panics and rejects missing capability before effects. Database
admission must still recheck fresh authority after waits; this is not that fence.

`/tmp/zasp-runtime-execution-authority-green.log` passed focused stage race tests,
including authorized dispatch through the processor, invalid authority rejection,
non-serialization of private capability fields, and existing stage lifecycle
tests. No production correlation version or candidate behavior is enabled yet.

Full worker races passed in 8.193 seconds before the formatting guard. Independent
review accepted the transport boundary, requiring v2's legacy `Execute` to reject
bypass and prohibiting capability logging. A new regression then demonstrated
credential exposure through formatted values in
`/tmp/zasp-runtime-execution-format-red.log`. Formatting now emits only a fixed
redacted label; reflective/structured logging of the capability remains forbidden.
The full final worker race suite passed again in 8.652 seconds in
`/tmp/zasp-runtime-execution-authority-full.log`. At that transport checkpoint,
database admission was still absent.

The first database test now specifies unique admission, an immutable target
snapshot, a late conflicting admission, exact replay of the original target and
two candidates for a new target batch. It uses declared seeded committed rows
and a registered PostgreSQL worker, not a claimed Graph/S3 crash proof.
`/tmp/zasp-runtime-candidate-authority-red.log` fails to compile because
`migrations.ProductionRuntimeCandidateAuthority` does not exist yet. That is the
expected missing implementation, not a passed database test. The proposed private
SQL boundary takes exact scope/batch/generation, worker/token/attempt/version,
input digest, index receipt bytes and archived event bytes.

The draft M47 authority now binds the exact committed index receipt and raw
archive bytes, admits qualified OTLP observations in the immutable paired domain,
and freezes an immutable snapshot under a live correlation-v2 lease. It is not
initially in the deployable CLI release catalog; release wiring is recorded below.
The initial unconditional Down refusal
has now been replaced by the verified guards recorded below. The private API
repository and v2 executor remain unimplemented. The explicit matching profile uses a five-minute event-time
window; it is not a claim about maximum telemetry delivery latency.

`/tmp/zasp-runtime-candidate-authority-first.log` passed the actual PostgreSQL
unique/late-conflict/frozen-replay/new-batch test in 7.384 seconds. Invalid/null
authority and direct-table-access rejections were added. A physical-boundary
fixture exposed pre-filter truncation hiding a viable candidate behind revoked
observations in `/tmp/zasp-runtime-candidate-overflow-red.log`. The corrected
bound rejects overflow before authority filtering; the green run passed in
6.224 seconds. This scale fixture uses owner-seeded rows, not actual ingest.

Independent review found stale worker/delivery checks on replay and a lease check
before a potentially blocking snapshot INSERT. All three actual PostgreSQL
regressions failed in `/tmp/zasp-runtime-candidate-freshness-red.log`, then passed
in `/tmp/zasp-runtime-candidate-freshness-green.log` in 9.145 seconds after adding
a common fresh execution check immediately before both return paths, including
after the INSERT. The expired-insert case also requires complete rollback.
Candidate selection now deduplicates narrow occurrence keys before loading full
payloads. Final review and additional scope/revocation/rollback tests remain open.

## Migration guard evidence

The empty-rollback test failed against the original unconditional refusal in
`/tmp/zasp-runtime-candidate-rollback-red.log`. M47 now fingerprints its authority
functions, predecessor compatibility, owner/column grants, forced RLS, policies,
constraints, indexes and triggers. The owned PostgreSQL fixture reported security
ready and fingerprint
`4217a4b8fcc9fc6b796012dbfcad58bb25ef0e773bc7f9f62347c1be818d7cc5`.
The inspected declaration is pinned in the draft migration, not computed and
accepted automatically at deployment.

`/tmp/zasp-runtime-candidate-schema-drift-retention.log` passed in 12.797 seconds:
empty Down restores the exact M46 fingerprint; function-body/function-grant,
table/column-grant, forced-RLS, extra-policy, disabled-trigger, removed-index,
future-version and missing-metadata cases refuse unsafe downgrade. Readiness also
rejects the tested drift; missing stored metadata is independently a Down guard
because the readiness caller supplies its own pinned fingerprint.

The raw SQL downgrade waits on the first uncommitted candidate admission and
then refuses once its observation and snapshot commit. It locks snapshots before
observations, matching freeze's initial prior-snapshot read. Retained evidence is
never deleted to permit downgrade. Independent read-only review found no blocker
in these SQL guards, subject to actual concurrency/drift verification.

Additional actual PostgreSQL tests reject source and anchor revocation during
admission lock waits and require zero retained rows for the rejected batch.
The maximum-target case uses 1,000 distinct event times against more than 1,000
physical observations, exercising the 1,001-per-target bound. It must return
overflow within a local 10-second database statement budget and save no snapshot.
The first run took 616.320375 ms; this is an owner-seeded local bounded-work
fixture, not actual ingest throughput or reference-load acceptance.

The transactional runner's missing methods failed first in
`/tmp/zasp-runtime-candidate-runner-red.log`. Its first implementation exposed
missing exact-version recognition; that was corrected, and repeat Up/Down passed
in `/tmp/zasp-runtime-candidate-runner-catalog-green.log` (6.457 seconds).
At that checkpoint, `Runner.Version` recognized exact M47 metadata while the CLI
deployment target and API startup contract were still at 46. Production v2
consumers remain disabled.

Review found a full-runner lock inversion: inherited sensor-exclusive locks could
wait on snapshot/readiness locks held by a worker that later needs the sensor.
The actual worker-transaction regression reproduced blocking until the two-second
deadline in `/tmp/zasp-runtime-candidate-runner-lock-red.log`. Down now acquires
all integration/sensor, version/metadata and candidate-table preflight locks with
NOWAIT. Contention refuses the attempt and rolls back every acquired lock; it
does not make a worker the deadlock victim or erase evidence. A later operator
attempt can retry once use has drained. No automatic retry loop was added.

`/tmp/zasp-runtime-candidate-runner-lock-green.log` passed all focused candidate
PostgreSQL race tests in 18.864 seconds, including prompt full-runner refusal both
before snapshot access and after an uncommitted snapshot insert, continued worker
operation, unchanged schema, two empty Up/Down cycles, all drift/revocation cases,
and maximum-target overflow (766.668 ms on that run). New API/repository binding,
v2 receipts/algorithm, actual graph/S3 crash recovery and composed browser proof
remain open. No original microtask or production-availability count changed.

The full migrations/worker race run first found an outdated future-version test
that still treated 47 as unsupported. The fixture now tests exact 47 and rejects
48, preserving the unknown-version assertion. The final full run passed in
`/tmp/zasp-runtime-candidate-migrations-worker-final.log`: migrations 1.954 seconds,
worker 8.374 seconds. Independent review accepted the NOWAIT correction at draft
level after inspecting the final focused PostgreSQL evidence. It did not approve
shipping, release activation or original-task acceptance.

## Next integration boundary

The concrete repository is
`services/platform/runtimeevent/production_pipeline_repository.go`,
`PostgresProductionPipelineRepository`. Its existing private JSON database can
carry the exact SQL freeze call, but a new closed response decoder must bind
snapshot bytes/hash, scope/batch/generation, archive and index-receipt digests.
No arbitrary caller-supplied candidate list can bypass that boundary.

The shared `strictProductionJSON` helper caps responses at 16 KiB. The candidate
response hex-encodes a snapshot of up to 1 MiB, so its dedicated closed decoder
needs an explicit envelope bound slightly above 2 MiB, with the decoded body still
capped at 1 MiB. Do not raise the shared ingest/control response limit. Actual
`PostgresJSONDatabase` sanitizes database errors, so repository tests must also
cover the production adapter's error mapping, not only a raw pgx test double.

`runtime_correlation.go` currently clears the index receipt immediately after
decoding. V2 must retain the verified exact bytes through the database binding,
then clear them; re-encoding a receipt is not proof of its original object bytes.
Production cloud dependency construction precedes database composition in
`production_runtime.go`, so candidate authority must be explicitly injected into
the v2 executor. Its legacy Execute entry must reject capability-free invocation.

The existing `runtimecorrelation` batch digest and receipt remain v1. V2 needs its
own digest domain and snapshot-digest binding, with old receipt decoding and
original v1 result bytes preserved. New consumers must handle the new receipt
before any producer emits it. The stage dispatcher/claim path must also preserve
the ability to finish and retry already-created v1 jobs, not merely accept v2 in
configuration while stranding or quarantining legacy claims.

## Release wiring in progress

`/tmp/zasp-runtime-candidate-domain-final.log` passed the expanded PostgreSQL
candidate suite in 24.459 seconds: identical lineage in another paired enrollment
domain is excluded, an unpaired OTLP source gains no runtime candidates or
observation admission, and a previously frozen target replays unchanged after
source and anchor revocation. This is still fixture-backed database evidence.

The full `npm run verify` in `/tmp/zasp-runtime-candidate-ui-verify.log` passed
1,179 tests in 196 UI test files, typecheck, lint and earlier API/tenancy checks,
then correctly failed the deployment assertion: embedded schema 47 versus chart
46. Build was not reached and that run is not a verification pass. The assertion
was preserved. CLI up/down target, exact chart/job identities and API startup
contract are now being wired to 47; composed E2E keeps its historical release
checks and adds M47. No correlation-v2 producer or receipt is enabled.

The CLI release test failed against the original v46 target in
`/tmp/zasp-runtime-candidate-cli-red.log`. Actual registered API construction on
schema 47 also failed before its supported-schema ceiling was updated in
`/tmp/zasp-runtime-candidate-api-startup-red.log`. The corrected API startup and
repeat empty Up/Down test passed in 9.139 seconds in
`/tmp/zasp-runtime-candidate-api-startup-green.log`. Full CLI races, release
contracts, complete UI/build verification and actual composed Chrome verification
must pass before this authority-only slice can ship. V2 integration and original
task acceptance remain separate unfinished work.

Release-contract integration initially rejected the renamed schema job because
the rendered-job allowlist still required v46. The allowlist now requires the
exact v47 migration identity. `/tmp/zasp-runtime-candidate-release-contracts-green.log`
passed 67 checks with two explicitly gated interruption tests skipped. This is a
contract pass, not the composed browser run. Independent review found the new
candidate PostgreSQL tests absent from mandatory CI; its selector, exact workflow
expectation and valid fixture now include `TestRuntimeCandidateAuthority`.
The focused workflow test passed all 15 cases in
`/tmp/zasp-runtime-candidate-workflow-test.log`.

The first full CLI suite in `/tmp/zasp-runtime-candidate-cli-full.log` exposed
legacy test helpers that downgraded directly from the current release to M46's
Down operation, skipping M47. Those helpers now unwind 47 first; the unknown
future-version case now rejects 48. No retained-data guard or historical
rollback assertion was relaxed. The corrected full CLI run passed in 82.814
seconds in `/tmp/zasp-runtime-candidate-cli-final.log`.

The draft secret scan flagged four appearances of the deterministic transport
test token, not an external credential. That test now constructs an explicitly
synthetic repeated-character token. No scanner rule was disabled. The scan of all
tracked changes plus new draft files is clean in
`/tmp/zasp-runtime-candidate-draft-secrets-green.log`; focused stage races passed
again in 2.159 seconds in `/tmp/zasp-runtime-candidate-authority-fixture-final.log`.
Final staged scans are still required before publishing.

The fresh full `npm run verify` completed successfully in
`/tmp/zasp-runtime-candidate-ui-verify-final.log`: 196 UI test files / 1,179 tests,
typecheck, lint, release assertions, standalone build, compiled import closure
and authoritative ledger validation all passed. The ledger still has 728 rows:
535 production-available, 132 component-only, 61 externally blocked, zero missing.
The full API race suite passed in 432.653 seconds in
`/tmp/zasp-runtime-candidate-apiserver-full.log`. The composed schema-47 browser
run failed in `/tmp/zasp-runtime-candidate-composed-final.log` during the temporary
policy action flow, after migration, runtime pipeline and earlier Chrome flows
passed. Its owned cleanup completed. This is not a composed verification pass.
Independent final read-only review had found no remaining concrete
blocker in this authority-only slice, conditional on composed Chrome completion
with cleanup, final staged scans and required shipping CI. No original task
credit or production v2 activation was approved.

The draft privacy scan reported 29 medium numeric-pattern matches and zero high
matches. Every reported span was inspected: fixture AWS account IDs and UUIDs,
public CI run IDs, a zero-UUID rejection literal and the uint32 maximum. No real
personal data was found and no scanner rule was disabled. Final staged scans and
push/PR/main CI remain pending. Nothing from this branch is committed or pushed.

## Composed policy failure under investigation

The action worker reported pending policy deployment; the deployment worker's
last recorded PostgreSQL error was a missing bundle during fallback readback.
The trace overwrote preceding errors, so it cannot establish the original store
failure. No production policy behavior has been changed to hide that failure.

Independent review identified a possible existing supersession race: a source
change advances desired generation after a deployment claim, the stale store
refuses, and fallback read finds no bundle. The lease remains held until expiry;
the composed helper exits on its first worker error while normal production
polling continues. This hypothesis still needs actual evidence from the failing
flow and baseline comparison. Delaying the helper or ignoring worker failures
would not establish recovery.

Two test-only trace regressions failed first in
`/tmp/zasp-policy-deployment-diagnostic-red.log`: preceding failures were lost and
policy operations were all labeled `other`. The trace now retains its latest 32
failure classifications and labels the five fixed policy operations, with no SQL
arguments or credential values. Focused race tests passed in 2.328 seconds in
`/tmp/zasp-policy-deployment-diagnostic-green.log`. The deterministic actual
PostgreSQL supersession comparison passed for both schemas 46 and 47 in 10.925
seconds in `/tmp/zasp-policy-deployment-supersession-baseline.log`. It uses an
owner-seeded source update through the real workflow enqueue trigger after a
registered deployment repository claim, then verifies conflict, missing readback,
an empty subsequent claim and a retained fresh lease without a stale bundle.
This proves the behavior predates M47, not that it caused the original browser
failure or that action recovery succeeds.

Independent review accepted the test-only characterization and bounded trace.
If needed, recovery requires an explicit fresh worker/token/generation-fenced
supersession transition that releases only an obsolete lease, preserves identical
stored-bundle lost-response reconciliation and denies late old-owner Store/Finish.
It must not convert arbitrary store failures into successful work. That change is
separate from M47 until a relevant dependency is established. The full composed
diagnostic rerun in `/tmp/zasp-runtime-candidate-composed-diagnostic.log` passed
all functional flows, including actual temporary-policy apply/cleanup, session
isolation, autonomous response and recovery rehearsal. It then failed a Docker
inspection during cleanup. Neither composed attempt is a complete pass.

Fresh inspection verified the one remaining disposable OpenSearch container's
exact full ID, name and run-marker/proof labels. Manual removal targeted only
that ID; the run-marker query was then empty. Unrelated containers were untouched.
The failed inspection followed by successful inspection establishes a transient
read failure, not a reason to delete an unverified resource.

Two cleanup regressions failed in `/tmp/zasp-runtime-cleanup-inspection-red.log`.
Cleanup now retries one nonzero inspection result, with each read still capped at
three seconds. Successful responses must still match exact ID, name and labels;
malformed responses or ownership mismatches are never retried into acceptance.
Persistent inspection failure still refuses deletion and fails the run.

Full worker races after diagnostic changes passed in 8.915 seconds in
`/tmp/zasp-runtime-candidate-worker-diagnostic-full.log`; the original policy
deployment database lifecycle passed in 6.327 seconds in
`/tmp/zasp-policy-deployment-original-regression.log`. The complete source release
gate passed in `/tmp/zasp-runtime-candidate-release-final.log`, covering source
SBOM/license/container/secret, resilience and dependency checks. Built-image
signing/scans, remote CI and live deployment remain separate gates.

The cleanup/browser-helper suite passed 30 tests with two explicitly gated
interruption skips in `/tmp/zasp-runtime-cleanup-inspection-green.log`. The
additional ownership-on-retry tests passed all nine cases in
`/tmp/zasp-runtime-cleanup-ownership-final.log`. The actual runtime SIGTERM test
was then enabled and passed without skips in 17.249 seconds in
`/tmp/zasp-runtime-cleanup-real-signal.log`, verifying both owned containers,
processes and temporary directory were removed.

The post-fix full composed run passed with exit zero in
`/tmp/zasp-runtime-candidate-composed-cleanup-final.log`. It verified schema 47,
the real local runtime pipeline and product API, discovery and enrollment flows,
temporary-policy apply/cleanup, session isolation, recovery rehearsal, SSO/SCIM,
administration, tenant denial, API restart/reload, a clean console and credential
privacy, then completed all owned cleanup. Its 100 local authenticated TLS reads
had p95 10,320,250 ns; this is not reference-load acceptance or a live provider
deployment. The two prior failed attempts remain recorded above.

The staged secret scan is clean in
`/tmp/zasp-runtime-candidate-staged-secrets.log`. Staged privacy scanning reported
29 medium numeric-pattern matches and zero high matches. Every exact span was
inspected: fixture AWS accounts/UUIDs, public CI IDs, zero-UUID rejection and the
uint32 bound. No private data or real credential was found; no rule was disabled.
Independent final review approved authority-only shipping conditional on required
CI, after inspecting the post-fix browser/cleanup evidence and staged diff.
The verified commit is `cd22a99ea8ff50ac81a66c6acf8be5469c4e24e0`, published in
PR 40. Push CI 34532351627 and PR CI 34532402341 passed. It merged as main
`612f12d37bce30c7f1c80836de0bb25bfaee7b20`; main CI 34533327507 passed.
No original task credit or v2 activation.
