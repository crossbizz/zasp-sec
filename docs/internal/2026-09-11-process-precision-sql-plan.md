# Exact SQL time contract

Continue integration step3 of `2026-09-11-process-precision-design.md` with
Superpowers TDD and independent review. This is a new SQL fragment for the next
migration, not a change to released migrations or permission to accept V2 jobs.

The old candidate validator casts nanosecond text directly to `timestamptz`.
That rounds to microseconds. The new contract must split canonical whole seconds
from the fractional digits and add the fraction as exact `numeric`. Validate
calendar/time fields by round-tripping whole seconds only. Reject non-UTC,
noncanonical/trailing-zero fractions, invalid calendar times and Unix seconds<=0,
matching `runtimelineage.PreciseObservation`. Bind the source time to the exact
millisecond display bin, and compare optional process start without rounding.

Files: `migrations/sql/fragments/runtime_precision.sql` defines private immutable
`zasp_runtime_precise_epoch(text)` and `zasp_runtime_precise_lineage_valid(jsonb,text)`.
Both belong to `zasp_discovery_authority`, with PUBLIC execution revoked and
fixed search paths. `apiserver/runtime_precision_contract_postgres_test.go`
executes the actual fragment on disposable PostgreSQL18. The future migration
must include this fragment in its checksum/fingerprint and guarded lifecycle;
do not register or activate an incomplete migration now.

- [x] Write PostgreSQL tests for same-millisecond valid process starts, a1ns
  future start, exact1ns epoch differences, calendar/UTC/canonical rejection,
  lineage identity bounds and no PUBLIC execution. Compare acceptance with the
  Go V2 contract on hand-selected boundary cases.
- [x] Run against rejecting SQL stubs and observe expected assertion failures.
- [x] Implement exact numeric conversion and separate V2 lineage validation.
- [x] Run real PostgreSQL race tests, related Go races, UI build and review.
- [x] Record evidence and unchanged task counts. Continue with schema/job routing,
  frozen candidates and matching; this helper alone does not enable persistence.

Expected PostgreSQL stub failures are in `/tmp/zasp-precision-sql-red.log`.
Fresh PostgreSQL18 race tests passed3.197s in
`/tmp/zasp-precision-sql-final.log`, including non-UTC TimeZone/SQL DateStyle,
absolute1ns epoch, exact five-minute boundary arithmetic and optional identity.
Related runtimeevent/runtimelineage/runtimecorrelation races passed in
`/tmp/zasp-precision-sql-packages.log`; UI build exited0 in
`/tmp/zasp-precision-sql-ui.log`. Independent Superpowers review approved the
scoped SQL contract and final test additions without findings. The SQL fragment
is not yet included by an activated migration or used by production matching.
