# Planner receipt portability remains open

The new worker completion receipt uses explicit UTC formatting. That does not
prove cross-session portability of the retained planner terminal evidence.

Read-only source audit:

- `0068_production_temporal_executor.planning.sql` creates terminal audit bodies
  with `to_jsonb(j)` and `to_jsonb(p)`, including timestamp columns. Its
  `planning_terminal_valid` reserializes those rows and compares the entire
  JSON body. Neither function fixes a timezone locally.
- `0074_production_temporal_test_executor.planning.sql` copies those installed68
  functions into74. The78 planning file then copies the74 functions into78.
- `0078_production_temporal_finding_response.control.sql` invokes the terminal
  validator from stop evidence, inspection and cleanup. A rendering mismatch
  can prevent recovery even when the audit digest remains valid.

Existing native diagnostic `worker-planning-terminal-diagnostic.log` directly
compares the same captured state. Under America/Los_Angeles, job/reservation
and native terminal validation are true. Under UTC, the audit digest remains
valid but terminal validation is false. Differing fields are
`budget_deadline_at`, `budget_started_at`, `released_at` and `reserved_at`.
The diagnostic failed100.98s; this is retained evidence, not a new test run.

Ruling13 removed only an unnecessary UTC override in the new finding facts
reader, restoring predecessor caller-context behavior. That fix did not make
the original proof portable between different sessions.

Required follow-on verification must create terminal evidence under one session
timezone and consume/replay it under another, covering68/74/78, prepared and
sent recovery, and late usage where relevant. Original audit bytes/digest,
accounting, one-send behavior, tamper rejection and exact replay must remain
intact. Any implementation must respect effective-catalog compatibility and
historical pins; no broad serializer rewrite, timestamp removal or weaker proof
comparison is approved by this audit. No source was changed for this report.

## Follow-on source trace

The same issue also reaches two other boundaries:

- `0068_production_temporal_executor.late_usage.sql` compares the terminal job,
  unchanged reservation fields and later reservation receipt using full-row
  JSON. The original terminal receipt and the later usage receipt can have
  different timestamp offsets. Fixing only `planning_terminal_valid` would
  leave late accounting replay exposed to the same mismatch. Copies in 74 and
  78 retain these comparisons.
- `0080_authorization_worker_planning.sql` derives signed `job_digest` facts
  from `to_jsonb(j)::text` in `planning78_source`. Different connection settings
  between authority capture and execution can change that digest without a
  product row change. This second path is a source finding, not yet a consuming
  native reproduction. Canonicalizing this transient digest alone cannot repair
  previously stored terminal evidence.

`services/platform/apiserver/temporal_planner_timezone_postgres_test.go` adds a
separate native 68 regression: prepare a real unsent intent, revoke its actor,
recover and replay through the registered compensation principal in
America/Los_Angeles, then reconnect as that principal in UTC and replay again.
It checks original body/digest preservation, one receipt, released uncharged
reservation, no new send and unchanged catalog readiness. It does not fabricate
terminal evidence. The initial run on isolated source snapshot
`/tmp/zasp-timezone.RKMIYx` failed as intended: test 24.58s, package 25.827s,
SQLSTATE 40001 `executor terminal replay conflict` at the replacement-session
replay. Same-zone controls and the evidence/accounting/catalog checks passed;
owned PostgreSQL joined normally. This is a consuming regression RED, not a fix.

The command used Go 1.25.13 with ambient GOROOT removed:

```sh
go test ./apiserver -run '^TestTemporalPlannerTerminalCrossSessionPostgres$' -count=1 -v -timeout=8m
```

The sorted per-file SHA256 manifest aggregate for both copied service trees
was `6706fd3fd63ddbb373cd05ef3299d0558855dd59f512fe618dddcc51fe20accb`
before and after the run. No production migration or catalog pin was changed.

## Current repair candidate

The bounded repair is now in
`services/platform/migrations/sql/0080_authorization_worker_planner_portability.sql`.
It adds current-profile replacements for the six terminal/late-usage validators
in 68, 74 and 78. Each replacement is derived from its verified predecessor
using exact-count substitutions. Original audit bodies/digests, accounting and
all remaining predicates stay unchanged. The helper re-renders only known
timestamp columns after validating explicit offsets and equal instants, then
the original full-row JSON comparison still runs. Transient job facts use a
separate full-row digest with the two budget timestamps serialized in UTC.

The worker owner is integrating the effective catalog projections and both
planning-source consumers. The dedicated regression now upgrades the stored68
terminal receipt through the current profile before replay. Its first upgrade
attempt stopped at discovery72 because the retained planner fixture lacks the
discovery scheduler registration. The test now provisions that prerequisite
through the existing registered-principal API, following the established
authorization profile fixture. That failed setup run is not a validator result.
Original68 RED evidence above remains valid.

The corrected upgrade/replay case passed on the integrated isolated snapshot
`/tmp/zasp-portability.BHINQr`: test 43.41s, package 44.627s, Go 1.25.13,
owned PostgreSQL stop=0/wait=0. The command is the same focused regression
command above. Before/after source manifest aggregates both equal
`fe262fb5c8c2503c31b9a6f8951eed4f6a5bcdca6073b949de763729b9e6ef69`.
This proves an actual68 prepared terminal receipt survives the69-78/current80
upgrade and replays through a new UTC compensation connection, without changing
its body/digest, charging its released reservation, adding a second terminal
receipt or reopening a send. Native68 catalog readiness remains true after the
new effective projections are installed.

Seven controls reject extra/non-time field changes, missing/null/malformed or
offset-free timestamps, and a one-microsecond instant change. The digest control
accepts equivalent timezone renderings but detects an added non-time field.
These controls test the new helper against actual captured job rows. They do not
replace native sent/late-usage and74/78 consuming cases. Those cases and
independent review remain open; no full portability or production pass is claimed.

## Corrected grouped 68 verification

Independent review found a malformed-receipt hole in the initial candidate:
the helper's SQL NULL rejection became JSON null inside `jsonb_build_object`.
A stored `job:null` or `reservation:null` could then match. Two consuming
corruption controls, with recomputed valid audit digests, reproduced acceptance
on the initial candidate in `/tmp/zasp-portability-null-red.HiKZZi`
(package 43.688s). The test changes are transaction-scoped and rolled back.
The repair now requires a non-null normalized job and, when a reservation exists,
a non-null normalized reservation before the original body comparison.

The corrected prepared and sent/late-usage group passed on immutable snapshot
`/tmp/zasp-portability-green.sEjjG9`, Go 1.25.13: package 97.482s,
prepared 42.80s and late usage 52.68s. Both owned databases stopped normally
(pg_ctl exit=0, server Wait exit=0). The exact command was:

```sh
go test ./apiserver -run '^TestTemporalPlanner(Terminal|LateUsage)CrossSessionPostgres$' -count=1 -v -timeout=8m
```

Before/after service source manifest aggregates were identical:
`bacb4cc0565af1d85c2e4183e866fb4e2cbe0e05f941920d1b03557c25676efc`.
The sent case obtains a real first-send permit and refuses a duplicate before
recovery. It creates terminal evidence in Los Angeles, upgrades the profile,
records late usage in UTC, and replays through an Asia/Kolkata connection.
Checks cover unchanged original audit bytes/digest, one late row/audit,
exactly 100 tokens and 500 cost units, no new admission, foreign-association
and changed-response rejection, and no reopening of start/admit.
The prepared case includes both malformed-null controls. Provider response
bytes are controlled local test input, not evidence of a deployed provider.

Independent specification and quality review passed for this bounded68 scope,
including the joined result, in the execution scratch directory's
`launch-installer-review/planner-portability-review.md`. Actual74/78 signed worker consumers remain
under verification. The full portability gate and production gate remain open.
