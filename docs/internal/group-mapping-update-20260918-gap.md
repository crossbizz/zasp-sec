# Group mapping update: next diagnosis

## Mounted result and current decision

The real API dispatch is confirmed: composition registers the identity handler,
production.go decodes expected_version, and administration_repository.go189-190
selects the suspected query without a schema alternate. The joined isolated
registered-role run in `group-mapping-update-20260918/red-observed.log` exits1
for the intended failure: create200/version1/audit1/session revocation works;
stale0 returns409 and a foreign group returns404 with no change. A valid
version1 update instead returns409, retains security_engineer/version1, leaves
audit count1 and leaves the session active. Root inspected that log directly.

M2-33 is now component-only. Historical Complete is preserved, while current
totals are526production-available/141component-only/61external. The ledger's
new premature-promotion guard failed first with Missing expected rejection;
after correcting the row, audited class sets and published counts, all37
ledger tests passed under Node22.23.1. These are ledger-consistency tests,
not product acceptance.

The bounded correction will separate zero-version creation from positive-version
updates, preserve atomic version/audit/credential effects and verify the real
mapping writer's contention with connector rejection locks. No new migration,
grant or live-provider authority is needed. User-requested autonomy applies.

## Earlier source finding

The split create/update correction passes the original mounted regression in
`group-mapping-update-20260918/green/mapping-first-green.log`. The expanded
`green/contention-red.log` then proves the predicted lock inversion using the
actual registered mapper route and an observed PostgreSQL blocking relation:
mapper409 instead of200, audit400 as expected, captured SQLSTATE40P01. This is
an actual deadlock, not an inferred timeout. The same run passes successive
version updates, real group-only next-session permission changes, session/PAT
revocation and audit-failure rollback. Root inspected the joined log directly.

The connected correction changes rejection ordering to membership, mappings,
then credential, while preserving fresh authority and post-wait expiry checks.
That correction and its fresh acceptance are in progress. No production class
promotion follows from the partial passing checks.

During the independent M8-41 review, source inspection found a separate
inherited concern at `services/platform/apiserver/administration_repository.go:40`.
`postgresUpsertGroupMappingSQL` feeds its INSERT only when expected version is
zero, while the conflict update requires the stored version to equal that same
parameter. Stored mappings start at version one. A positive expected version
therefore appears to suppress the input row before the conflict update can run.

This needs a mounted registered-role reproduction through the actual
`updateGroupMappings` API, with create, valid-version update, stale conflict,
tenant denial, durable audit and credential-revocation assertions. Check current
dispatch first; do not assume this constant is the only selected implementation.
Original requirement M2-33 must support real updates, not just initial creation.
The earlier production-available claim is superseded by the mounted result above.

Any repair must also verify mapping/session lock order with the new connector
rejection transaction. The current writer mutates mappings before revoking
credentials; rejection locks credentials before mappings. A repaired update
path could make that previously unreachable contention real. Test actual
registered writers, preserve tenant boundaries and fixed public errors, and
use one connected RED/GREEN/review batch. No live identity-provider access is
required or authorized by this local task.
