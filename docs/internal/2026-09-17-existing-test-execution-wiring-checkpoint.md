# Registered existing-test execution connection

The worker repository now selects the guarded schema55 execution entrypoint
on each operation and supplies compiled checksum/fingerprint. Missing55 keeps
the existing execution statement; probe failure never falls back. The SQL
wrapper derives test intent from persisted scoped definition/plan/steps under
organization/run locks. Existing-test intent uses private dispatch; ordinary
actions use v24. Only the wrapper grants EXECUTE to the registered worker role.
Private dispatch remains ungranted and its denial is asserted before each case.

## Evidence

- Routing RED56465d reproduced the old v24 selection at55; GREEN95cfcf passes.
- Owned registered dispatch RED198d83 reached missing wrapper42883 after real
  preparation/approval/claim. No fixture grant substitutes for wrapper authority.
- Initial installc5a003 failed on a missing quote in the new credential JSON
  accessor. The source was corrected before calibration or passing claims.
- Owned calibration51b576 measured fingerprint
  `673c22d356eae39367b2a57a1180ab40e4c294d33a717c02261fc3628271d068`.
  Fingerprint recheck and existing release/drift/rollback acceptance pass in
 6181d9 (3.82s and9.83s). Prior55 binaries no longer match this candidate.
- Registered SQL acceptance6181d9 passes14 modes21.37s: supervised/autonomous
  run/rerun, approval/plan binding refusal, and observed audit/outbox/link waits
  across approval expiry. Exact scoped link/run/outbox/receipt/reservation state
  is asserted. Expanded a33ec5 passes14 modes24.95s, including owner/API denial,
  wrong checksum/fingerprint, foreign organization and wrong worker/lease before
  each dispatch, with unchanged snapshots after refusals.
- Actual repository acceptance58636b passes all four positive modes8.95s:
  registered worker connection, NewPostgresJSONDatabase,
  NewSecurityAgentWorkerRepository, real claim and ExecuteSecurityAgentRun,
  followed by the same persisted-state assertions. No temporary private grant.
- Grouped worker/migration raceeb749b passes42.777s/5.750s. Focused repository
  routing/worker/budget race875d7a passes2.760s. These are not a full platform
  or linked-worker process regression against the changed pin.
- Independent review identified legacy approval/plan/runtime deadline capture
  as an Important requirement. Both branches now capture those deadlines;
  existing-test dispatch also captures target/credential deadlines. The final
  check occurs after writes and readiness, even though dispatch clears lease
  columns. Source re-review and Go/test review found no new findings. The
  remaining timing acceptance below is still required.

All test/compile processes for this checkpoint are terminal; owned databases
joined normally. No host PostgreSQL started. Ledgerc9a6db validates728 rows,
534 production-available,133 component-only,61 external,zero missing.

## Open batch gates

1. Complete whole-feature integration review and affected legacy regressions
   on the exact release candidate. Grouped invocation, cancellation, recompiled
   recovery, bootstrap and composed HTTPS acceptance pass below. Shared final
   deadline ordering has bounded legacy timing proof; do not describe it as
   separate timing coverage of every action branch.
2. Complete public before/after evidence and composed browser acceptance, then
   exact push-candidate UI/regression/release/advisory gates before shipping.

M7A-21 remains component-only and public capabilities remain disabled. No live
provider/storage/queue proof, throughput result, production promotion, commit
or push is claimed. UI inputs are unchanged; no new UI build is claimed here.

## Grouped execution acceptance update

Owned grouped run acce23 exits0: registered legacy preparation and dispatch at55
pass fresh/expired-budget cases (20.39s), and final-run-write lease/approval
expiry rollback passes (12.10s). The latter observes an actual RowExclusive
waiter behind a SHARE lock, waits past a database-clock deadline, releases the
blocker, requires SQLSTATE40001 with `existing test execution authority expired`,
and verifies unchanged scoped snapshots. Legacy v24 control c65f86 fails because
it returns successfully after lease expiry, establishing a discriminating RED.
Deadlines are installed before locking the run table to avoid fixture self-lock.
Owned PostgreSQL processes joined normally. Independent review found no Critical
or Important findings in this bounded test delta. It does not cover every legacy
action or a forced wait inside the final readiness check.

The worker executable was recompiled against the current55 pin (4b2120), and
the current API test executable compiled successfully (ed291d). Grouped linked
recovery acceptance0601b6/584051/57d0fb exits0: overlapping replicas7.40s,
stopped queued work20.95s, tenant-separated restart7.33s and settlement restart
44.98s. All four supervised/autonomous run/rerun settlement modes preserve
exact durable snapshots and one settlement audit after fail-stop24. These use
owned PostgreSQL and controlled provider responses, not live cloud proof.
Ledger7cf702 validates728 rows:534 production-available,133 component-only,
61 blocked/external,zero missing. No availability category changed.

Current migration CLI8332ec and its test executable69f3db compile successfully.
Owned binary acceptance334984 exits0 in6.07s: direct empty-database up-to-55,
registered principals/readiness, idempotent replay, historical command refusal,
metadata-drift upgrade/rollback refusal with unchanged snapshots, clean/no-op
rollback to54 and reupgrade55. No cloud database or deployed executable is used.

Grouped invocation regression74daff/99a114/7f8be4 exits0: registered worker claim
51.55s, invocation start54.04s, terminal9.30s and journal client22.19s. Each runs
four supervised/autonomous run/rerun modes. These retain the existing controlled
admission/dispatch fixtures and prove their scoped authority and replay checks;
they are not composed public-API or real target invocation proof. No HTTPS
adapter child was supplied or claimed in this group.

Cancellation9467a9 exits0 in29.31s across all four supervised/autonomous run/rerun
modes against the same current API executable. All grouped acceptance processes
in this update are terminal; owned database cleanup succeeded. No production
source changed during these grouped runs.

Recompiled TLS journal child ab8f37 and production adapter routing child40790c
pass grouped owned HTTPS40150c against the current55 pin: known response19.95s
and unknown response17.39s, four supervised/autonomous run/rerun modes each.
Each mode runs the actual registered adapter composition and database-to-HTTPS
child. Rerun modes cover lost acknowledgement; unknown responses preserve
uncertainty. This is controlled local TLS/DB evidence, not a deployed provider.
Both database processes joined normally and the parent exited0.

Final-readiness timing is now verified for the shared wrapper's supervised
legacy path. Clean mutation RED66bf8a/3bdeef removes only the installed final
expiry guard and fails both lease/approval cases by returning success after
expiry. Unchanged wrapper GREEN54d873/f26c2b exits0 in15.65s. The hook requires
real effects, executing step, exact dispatch audit and cleared lease before
blocking; the observer proves a waiter before DB-clock expiry. Exact40001 and
unchanged combined snapshots establish rollback. Original functions are restored
and registered readiness passes afterward. Timing replaces readiness only inside
the owned fixture, so it is not fingerprint/ACL/release-integrity proof.
Independent review found no Critical/Important issues. Neighbor regression
0200d9/bcd2ad passes legacy14.86s, final-write11.92s and routing0.08s. See
[full commands and evidence](2026-09-17-execution-readiness-test-report.md).

## Verification cadence

User-authorized feature batching retains task-level acceptance and evidence
mapping. Run targeted regression tests while changing behavior; group related
integration cases and independent review into coherent feature batches. Update
the authoritative ledger once per batch. Reuse compiled executables only while
their source/build inputs remain unchanged. Before a push, run affected full
regressions, UI runnability and release gates against the exact candidate. This
changes verification cadence, not the728-task scope or production proof bar.
