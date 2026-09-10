# Runtime enrollment pairing, September 10, 2026

Status: merged through PR 34 as main `2ec567e578f9254ed6c44531aa829318b3723092`,
with the explicitly disclosed full-suite exception below. Push CI 34509076346
passed on retry after a PostgreSQL-tool lookup timeout; PR CI 34509136931 passed
unchanged. Main CI 34510681669 passed. Not accepted as cross-batch correlation
evidence. Original task counts remain
535 production-available, 132 component-only and 61 external gates out of 728.
M3-46, M3-47 and M7-07 remain component-only under their original owners.

## What is implemented

Schema 45 records immutable operator-configured OTLP-to-Tetragon enrollment
pairings. Creation requires an active Tetragon anchor in the exact organization,
workspace and environment and the existing `manage_workflows` permission.
The event payload cannot supply enrollment pairing authority. Existing unpaired
OTLP enrollments do not gain cross-source trust.

Pairing and batch-domain sidecars have forced row security, owner-only access,
type-bound composite foreign keys and update/delete rejection triggers. Retained
references prevent identifier deletion and reuse. Each new batch's domain comes
from its authenticated source enrollment; historical Tetragon batches bind to
themselves and historical OTLP batches remain unpaired. An anchor stored in a
batch is provenance, not permission to admit a future correlation candidate.

Creation binds pairing to the durable idempotency receipt and request digest.
Legacy unpaired requests retain their original digest and response shape.
Historical replay cannot add, remove or replace pairing, or issue another token.
It checks current caller permission after lock waits. Anchor revocation denies
new pairing but does not rewrite an existing historical receipt.

The generated product API and UI accept an optional `runtime_sensor_id` only for
OTLP creation. The UI lists current active Tetragon anchors and shows configured
pairing as read-only. It explicitly says that configuration does not confirm
current activity or attribution. Changing the anchor requires a new enrollment.

Release migration/catalog, API startup, staging identity and production chart
checks now target schema 45. Unknown schema 46 is rejected. Empty rollback works;
rollback refuses retained pairing or batch-domain provenance. This is a forward
rollout once such provenance exists, not a promise of rollback after use.

## Verification so far

- PostgreSQL exposed a real receipt-lock race: permission could be revoked while
  replay waited. The fix rechecks permission after the receipt lock. The regression
  observes the blocked database session before committing revocation.
- `/tmp/zasp-pairing45-authority-green.log`: real PostgreSQL race run passed,
  including startup at 45, future-46 rejection, all three foreign-scope dimensions,
  immutable source/anchor kinds, replay, token count and retained-data rollback.
- `/tmp/zasp-pairing45-cli-red.log` proved the release command stopped at 44.
  `/tmp/zasp-pairing45-cli-green.log` passed after wiring the migration.
  `/tmp/zasp-pairing45-cli-full.log`: full migration CLI and catalog race suites
  passed, including actual database upgrade/downgrade checks.
- `/tmp/zasp-pairing45-http-domain-green.log`: all pairing PostgreSQL tests
  passed. The real product HTTP API issues a paired enrollment token; the real
  runtime ingest handler uses that token with the registered ingest database role,
  persists the exact source/anchor domain, replays the same batch and rejects
  event-body pairing injection. Caller identity and routing context are injected
  at the product handler; this does not independently prove browser authentication.
  Its raw artifact store is a declared test double.
  Historical OTLP backfill remains null. Concurrent pairing and batch transactions
  block Down; committing either makes Down reject without discarding provenance.
- `/tmp/zasp-pairing-http-green.log`: HTTP tests passed for legacy/pairing intent,
  field order, duplicate/null/unknown/case-variant fields, tenant-field injection,
  missing fields and oversized bodies. Invalid inputs must return 400 before
  credential generation or repository mutation.
- `/tmp/zasp-pairing-ui-green.log`: 3 focused files, 13 tests passed for generated
  decoder/API/UI behavior. This is component evidence, not browser composition.
- `/tmp/zasp-pairing45-browser-contract-red.log` and `-green.log`: the source
  contract first required a missing lifecycle proof, then passed after adding it.
  The actual full Chrome lifecycle also passed in
  `/tmp/zasp-pairing45-chrome.log`: schema 45, the five-stage owned SQS/S3/OpenSearch
  pipeline, real browser pairing creation, reload, rotation, token privacy,
  anchor/source deletion and retained pairing, all later security/discovery flows
  and complete cleanup. Exit status was 0. This does not prove cross-batch
  correlation or live deployment.
- `/tmp/zasp-pairing45-verify.log`: full Node 22 repository verification passed,
  including 196 files / 1179 tests, types, lint, API generation, production build,
  compiled production import boundaries and authoritative ledger validation.
  Final-tree verification also passed in `/tmp/zasp-pairing45-verify-final.log`
  after the CI and startup-contract corrections, with the same 196 files /
  1179 tests and a successful production build.
- `/tmp/zasp-pairing45-release.log`: source release gate passed. Built-image,
  remote CI, live provider and public DNS/TLS gates remain separate.
- Independent read-only review found no remaining Critical or Important issue,
  conditional on historical/backfill, concurrent Down, full API and Chrome proof.
  Historical/backfill, concurrent Down and Chrome now passed; the full API
  exception is disclosed below.
  Follow-up review of the new HTTP/backfill/rollback tests found no blocker and
  confirmed these evidence limits. The reviewer did not rerun the tests.
- CI now includes pairing and sensor regressions alongside all existing runtime
  session tests. Review caught the old command in the workflow contract;
  `/tmp/zasp-pairing45-ci-contract-red.log` reproduced that mismatch and
  `/tmp/zasp-pairing45-ci-contract-green.log` passed all 15 tests after correcting
  both the assertion and valid fixture.
- The first full API race run failed only the static startup-query test, which
  still required a schema-44 maximum. It is corrected to require 45 and reject
  the old 44 maximum. Real database startup at 45 and rejection of 46 had already
  passed. Its first failure is retained in `/tmp/zasp-pairing45-api-full.log`;
  the next full run and reviewed scope exception are recorded below.
- The corrected full API retry exited 1 after 312.226 seconds. It failed only
  the unchanged schema-11 connector reconciliation query-plan performance test;
  all pairing tests passed. `/tmp/zasp-pairing45-api-full-green.log` is a failure
  log despite its name. This unresolved scaling issue and baseline verification
  are tracked in `2026-09-10-connector-reconciliation-plan-regression.md`. A green
  repeat will not be described as a fix. Review permits independent M45 shipping
  only if the unchanged base reproduces the failure and required CI passes.
- The unchanged main revision `1aab7f58448f13e015ca398c8f483b58b53df5a5`
  reproduced that same failure in an isolated worktree. Its eight-repeat race
  command exited 1 after 262.777 seconds, including the same 2,481 shared blocks.
  Five current-branch repetitions passed in 198.286 seconds. This establishes
  a pre-existing intermittent defect, not a passing full API suite or a fix.
- Independent read-only review verified the clean detached base and matching
  failure log, then confirmed conditional M45 merge approval after unchanged
  required push/PR checks pass. Reconciliation remediation must precede frozen
  candidate work; no additional original task is accepted by this exception.
- Staged secret scan passed. Privacy scan found 15 medium matches and zero high
  findings; every context was checked and contains fixed fixture UUIDs, example
  AWS account IDs or public CI run IDs, not customer personal data.

## Still required before shipping this slice

Final secret/privacy scans, push/PR checks, merge and main CI passed.
Commit `c87000fb53d6f08d7fdc1d630a27ff4ff62517ae` passed a 1,362-commit
history secret scan. The pairing-specific
API/database gates and full Chrome lifecycle passed. The connector scaling
defect remains next on the critical path and blocks any claim of production
readiness. No verification listed as pending is a pass.

## Still required for the original product criteria

Enrollment pairing alone does not finish automatic discovery or Strong/Probable
attribution. The production path still needs retained candidate observations,
qualified host/boot/container/process lineage, bounded frozen cross-batch
snapshots, fresh source/anchor admission checks, immutable replay and actual
unique/competing candidate composition. These remain in scope.

No live deployment, customer/provider identity attestation, production HA or
external release gate has been proven by this local work.
