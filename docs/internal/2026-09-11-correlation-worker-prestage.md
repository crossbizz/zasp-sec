# Pre-stage the compatible correlation worker

The chart now selects the existing v2 dual-reader on schema 48. SQL still creates
v1 work. This is the first rollout step toward actual cross-batch correlation,
not routing activation, a deployment or completion of M3-46, M3-47 or M7-07.
All 728 tasks and the 535/132/61 classifications remain unchanged.

The ordering matters: the migration is a Helm pre-upgrade hook. Activating v2
jobs in that hook before replacing v1 workers lets old workers claim jobs they
can't execute and consume retry attempts. Pre-stage compatible workers first;
require verified replacement of every old correlation replica before routing49.
No old lease, receipt or stored implementation version is rewritten.

The current v2 executor copies its configuration for v1 leases and removes
candidate authority from that copy. Existing tests require identical v1 receipt
bytes, successful completion and zero candidate calls. V2 readiness still checks
the pinned candidate schema and registered PostgreSQL principal before polling.
Missing permissions or schema drift blocks v1 backlog too. That stricter readiness
is an explicit rollout gate, not an unconditional availability claim.

The rendered-release validator rejects a v1, unknown, empty, omitted, duplicated
or indirectly sourced correlation version. The chart mismatch failed first in
`/tmp/zasp-correlation-prestage-red.log`. An initial negative used an absent fixture
account field and failed at the wrong boundary; it wasn't accepted as evidence.
After adding a valid-account positive control, the downgrade regression failed
on the missing validation in `/tmp/zasp-correlation-prestage-gate-exact-red.log`.

All 39 rendered-release tests pass in
`/tmp/zasp-correlation-prestage-contracts.log`. Full worker races pass in 9.530s:
`/tmp/zasp-correlation-prestage-worker.log`. Actual PostgreSQL candidate readiness
at 47/48, missing/future/drifted release and revoked-principal cases pass in
11.262s: `/tmp/zasp-correlation-prestage-readiness.log`. These are local tests.

Independent rollout-source review found no concrete blocker to pre-staging on
healthy schema48, with the readiness qualification above. Independent final
three-file review found no critical or important issue. Fresh full `npm run verify`
passes all 1,188 UI tests, typecheck, lint, production build and all 728 ledger rows:
`/tmp/zasp-correlation-prestage-full-verify.log`. The complete source release gate
also passes in `/tmp/zasp-correlation-prestage-source-gate.log`. Publication was
held while PR44's CI architecture failure was repaired. Superpowers isn't
installed; its official upstream test-first, verification and independent-review
workflow is used, not claimed as an installed-skill pass.

The composed schema-48 proof now runs the pre-staged v2 reader against actual
production-created v1 jobs from separately enrolled raw and semantic sources.
The first actual run failed at correlation because the old Execute-only test
wrapper erased version negotiation. That RED is recorded in
`/tmp/zasp-correlation-prestage-backlog-red.log`. Passing actual executors through
composition preserves the same optional interfaces as production; no production
Go code changed. The corrected run reads both completed v1 receipts from their
exact S3 versions, verifies the committed digest, scope, batch and generation,
retains 26 Unattributed raw results and three Exact semantic results, and checks
zero candidate observations or snapshots for either batch. Existing replay
checks and the separate fixture-selected v2 recovery proof remain intact.

The full actual pipeline and installed-Chrome suite passed with exit 0 and
successful cleanup in `/tmp/zasp-correlation-prestage-backlog-full.log`.
Supporting contracts passed 72 tests; two opt-in real-signal cleanup probes were
skipped in `/tmp/zasp-correlation-prestage-combined-contracts.log`. Full worker
races passed again in 9.109s in `/tmp/zasp-correlation-prestage-final-worker.log`.
The complete source release gate passed in
`/tmp/zasp-correlation-prestage-final-source-gate.log`. Independent follow-on
review found no critical or important issue in the two-file proof extension.
Final runnable-UI verification after combining the repaired daemon branch passes
with exit 0: all 1,188 UI tests, typecheck/lint/build, compiled imports and all
728 ledger rows in `/tmp/zasp-correlation-prestage-final-verify.log`.
PR44's corrected push and PR CI passed, including both actual AMD64 daemon
attempts. It merged as `fd4ba167`; the pre-stage branch incorporates that main
commit without additional source changes. New main CI 34621326929 is pending.

Published as PR45 at `b8f8da248c377fad606db5aa0584555ffd1691b3`. Push CI
34621547317 and PR CI 34621568895 are running. Postcommit history scanning
found no leaks across 1,390 commits; the exact PR-body scan has zero findings.
Public CI IDs and the synthetic account explain the unchanged push guard's
nonblocking warnings. No publication safeguard was changed or bypassed.

Rollback to the v1 worker remains compatible only while v2 jobs haven't been
created. Routing49 needs its own forward migration, pinned readiness/CLI wiring,
guarded rollback and real ingest-to-candidate-to-browser evidence without fixture
stage-version updates. Sandbox, cgroup and process requirements remain in scope.
