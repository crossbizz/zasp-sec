# Recovering a finalized sensor acceptance

Unpublished work on `codex/runtime-sensor-lineage`, based on verified main
`a4fede82`. This closes a local replay defect in the dependent sensor work; it
does not close an original task or establish deployed production readiness.
Counts remain 535 production-available, 132 component-only and 61 external.

## What failed

The actual client/HTTP/registered PostgreSQL ingest test first accepts a bound
envelope, loses its response, rotates the real enrollment credential and retries
the unchanged request. Generation 2 authenticates, but reserve fails with
SQLSTATE 23505 because the existing batch's request digest and conflict tuple
include its original token ID and generation. Finalization also enforces the
original credential. Evidence is retained in
`/tmp/zasp-sensor-envelope-lifecycle-red.log`.

The original credential provenance checks are unchanged. Replacing or relaxing
them would give a replacement token authority over abandoned uploads. The
reviewed repair is a separate finalized-acceptance lookup.

## Implemented component

New, unshipped migration 48 defines `zasp_runtime_lookup_acceptance`. It requires
the registered ingest principal and exact release readiness, authenticates the
current credential and checks the full scoped enrollment hash. It matches the
batch ID, idempotency key, canonical content digest, source, media/schema, size
and event count. Accepted replay requires exact persisted artifact, runtime
batch, job, outbox payload/digest and all five stage bindings. No artifact write,
batch reservation, finalization or provenance rewrite occurs on that path.

Missing and unresolved uploading/unknown batches return no acceptance and retain
the existing reservation/reconciliation behavior. A replacement credential still
cannot finalize an abandoned upload. Quarantined work gets a receipt only if it
has the same complete evidence of prior acceptance; acceptance is not a claim of
successful downstream processing.

The lookup uses the existing authentication locks. It takes the batch share lock
with NOWAIT to avoid waiting on a worker while holding sensor authority. After
database work, it rechecks the registered principal and release readiness, then
checks token expiry against wall time. Authentication audit updates remain;
original batch, artifact, job, stage and outbox records are not rewritten.

The Go repository uses one exact SQL boundary and decodes a closed response.
The enrollment-bound handler invokes it before reserve and returns the original
batch receipt only for proven acceptance. Missing lookup capability, database
failure, cancellation or malformed output fail closed. Legacy unbound transport
does not use the new lookup. The production sensor configuration still does not
supply an enrollment binding, and no producer activation is claimed.

## Test and review trail

The new migration API initially failed to compile in
`/tmp/zasp-runtime-acceptance-migration-red.log`. Actual PostgreSQL installation
then passed security assertions and measured the catalog fingerprint. The raw
migration test checks exact v48 readiness, compatible v47 candidate readiness and
rollback restoring the exact prior live fingerprint. It passed initially in
`/tmp/zasp-runtime-acceptance-migration-green.log`.

The first composed client/HTTP/PostgreSQL rotation run passed in
`/tmp/zasp-runtime-acceptance-lifecycle-first.log`. It proves response-loss
recovery with a rotated credential, one artifact write total and unchanged
original batch authority. Its transport and artifact store are explicit test
doubles; PostgreSQL credential and ingest operations use real registered roles.
This is not TLS, S3 or deployed sensor evidence.

Independent review found two defects in the first lookup. Both were reproduced
before correction in `/tmp/zasp-runtime-acceptance-review-red.log`:

- An ingest role revoked while authentication waited on a real token-row lock
  could still receive acceptance after the wait.
- A previously accepted batch in quarantined state was rejected despite intact
  finalized artifact, batch, job, outbox and stage bindings.

The final principal/readiness recheck and exact-proof quarantine handling fix
both. Combined migration and actual lifecycle race tests pass in
`/tmp/zasp-runtime-acceptance-reviewed-green.log` (10.384 seconds). This includes
the two review cases, revoked prior credentials, cross-enrollment replacement
rejected before body reads, and revocation after initial authentication before
the next database effect. The quarantine transition is fixture-only; it is not
proof of a real worker quarantine flow. The measured fingerprint at that checkpoint was
`8778fa3781412a7ca273d92c75ad0a49ad508180619e47616f965ec293f90c0b`.

Additional repository tests reproduced acceptance of duplicate keys, aliases and
extra empty metadata in `/tmp/zasp-runtime-acceptance-response-red.log`. Closed
key-set and uniqueness checks now reject them. Exact SQL arguments, batch and
state matching, absent/null fields and cancellation after database return are
covered. Full runtime-event and sensor race suites pass in
`/tmp/zasp-runtime-acceptance-response-green.log` (3.592 and 1.648 seconds).
Independent follow-up review found no remaining concrete component blocker,
while explicitly withholding shipping approval pending the remaining work.

The final repeated migration/lifecycle run after the response-decoder correction
passes in `/tmp/zasp-runtime-acceptance-final-local.log` (10.914 seconds).
`/tmp/zasp-runtime-acceptance-ledger.log` validates all 728 ledger rows with
unchanged classifications. All test processes completed; no push was attempted.

## Rollout wiring and review corrections

The Runner now supports exact 47-to-48 upgrade and 48-to-47 rollback. The CLI
up/down sequences, version ceiling, API startup ceiling, rendered migration job
identity, schema expectation and combined-proof marker now include 48. The
lifecycle fixture uses the actual Runner. None of this has been pushed or
deployed yet.

Runner, CLI and API tests failed before their wiring repairs. Two actual
Runner/API upgrade/startup/rollback cycles pass in
`/tmp/zasp-runtime-acceptance-runner-green.log` (6.992 seconds). Full CLI races
passed in `/tmp/zasp-runtime-acceptance-cli-full.log` (71.624 seconds); migration
package races passed in `/tmp/zasp-runtime-acceptance-migrations-full.log`.
Release-source/render tests first failed, then passed 63 tests with two opt-in
skips in `/tmp/zasp-runtime-acceptance-release-contract-green.log`. These are
contract tests, not a new composed Chrome run.

Review found an upgrade lock inversion: a catalog reader could later need the
sensor locks held by the waiting migration. The actual Runner regression failed
at its deadline in `/tmp/zasp-runtime-acceptance-runner-lock-red.log`. Both
directions now acquire sensor/integration, catalog and metadata preflight locks
with NOWAIT inside the same rollback-on-error transaction. Six actual reader
contention cases pass, each in about 0.01 seconds, while preserving the starting
schema and allowing reader progress. Uncontended retry succeeds. The lock tests
and repeated API startup cycles pass in
`/tmp/zasp-runtime-acceptance-runner-lock-green.log` (10.528 seconds).

A separate actual registered-worker test found that its compatibility wrapper
derived expected48 checksum values from the database being checked. The wrong
checksum was accepted by candidate readiness, API readiness and bound HTTP
replay. All three failures are retained in
`/tmp/zasp-runtime-acceptance-all-startup-drift-red.log`.

Candidate readiness now pins both 47 and 48 from application metadata. Only
SQLSTATE 42883 can try the explicitly pinned47 predecessor; false readiness,
permission errors and other provider failures never fall back. API startup pins
the optional48 catalog checksum and fingerprint while retaining the existing
live-readiness chain. Lookup now takes 15 arguments: its last two are the
application-pinned48 checksum and fingerprint, checked both before and after
authentication. The newly measured and pinned fingerprint is
`6ab72c59e40e2b758acca94556ca378ecb61c52d8775bb8f35dae93c685bf819`.

Actual47/48 worker startup, unsupported49, checksum/fingerprint drift, grant
drift, principal revocation, API startup, migration/rollback and bound replay
pass together in `/tmp/zasp-runtime-acceptance-all-startup-drift-green.log`
(26.416 seconds). Full runtime-event and migration races pass in
`/tmp/zasp-runtime-acceptance-pinned-repositories.log` (3.487 and 1.789 seconds).
Independent follow-up review found no further concrete blocker in these
corrections, without giving shipping approval.

The controlled authentication-wait proof now also changes the48 checksum and
lets the current credential expire while the real token-row lock is held.
Both are denied after release, as is principal revocation; persisted work and
artifact-write count stay unchanged. The first expanded run passes in
`/tmp/zasp-runtime-acceptance-authentication-waits.log` (7.803 seconds).
The repeat explicitly asserts that database transaction start and the observed
wait precede expiry. It passes with the broader API/Runner/worker and older
session/enrollment schema compatibility suite in
`/tmp/zasp-runtime-acceptance-rollout-compatibility.log` (64.330 seconds).
The full CLI race repeat with the final pinned migration passes in
`/tmp/zasp-runtime-acceptance-cli-pinned-full.log` (76.716 seconds).
The full worker race suite also passes with the new readiness path in
`/tmp/zasp-runtime-acceptance-worker-pinned-full.log` (9.007 seconds).
`/tmp/zasp-runtime-acceptance-rollout-ledger.log` validates all 728 rows with the
unchanged 535/132/61 classification. `git diff --check` passes.

The installed Superpowers skill remains unavailable. The previously read
official upstream test-first, verification-before-completion and independent
code-review workflow is the disclosed fallback, not an installed-plugin pass.

## Still required before shipping

All four previously missing local boundary-test categories now pass with
independent review: incomplete uploads across rotation, foreign scope with a
reused sensor ID, corrupt or missing durable bindings, and batch-lock contention.
The upload case also verifies actual SQL reconciliation followed by exact replay.
The full release run failed, with disk exhaustion confirmed in an isolated
repetition. After recoverable compression of old fixture binaries, the isolated
index test passes; fresh full backend and UI/build verification remain pending. See
`docs/internal/2026-09-11-lineage-release-verification.md` for evidence and gates.
The real reader-contention tests cover upgrade/rollback preflight, not a deployed
rolling release with active HTTP requests.

The following component checkpoint makes both original file-stream restart tests
GREEN and implements durable cache/request persistence and exclusive writer
locking. Linux package resource tests pass with a rendered 128 MiB Go memory
target under the 256 MiB hard limit. Evidence and limits are in
`docs/internal/2026-09-10-sensor-durable-checkpoint.md`. Installation binding,
composed file/HTTP/PostgreSQL lifecycle proof, full-daemon resource verification,
lineage resolver/emission and producer activation remain unfinished. No full
UI/release gate, push or original-task credit is claimed. The preceding source
audit remains in `docs/internal/2026-09-10-runtime-sensor-lineage-audit.md`.
