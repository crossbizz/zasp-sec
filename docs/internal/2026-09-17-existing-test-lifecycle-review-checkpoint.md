# Lifecycle review checkpoint

Status: changes requested. Three Important findings reproduced; fixes and
re-review pending. No production promotion, commit or push.

Independent reviewer: /root/existing_test_lifecycle_review. Reviewed the21-file
inherited-baseline delta at
/private/tmp/zasp-existing-test-lifecycle-review-20260917.patch, not the full
dirty HEAD diff. No Critical or Minor findings in that review. Baseline HEAD is
ecc047ee2e90c36ec702ade129a2b08eae0a7a1a.

## Reproduced findings

1. Manual admission validates the exact trigger before inserting the request
   receipt. That insert can wait. The final trigger lookup discarded identity,
   accepting newly current evidence without matching the admitted receipt.
2. Shared admission checks binding/trigger authority before a blocking singleton
   execution-state update. Automatic admission can commit stale authority after
   that wait; the wrapper only checked release readiness afterward. Later
   scheduler/delegation waits also require consideration.
3. Scheduling limits raw candidates before checking eligibility. An earlier
   concurrency-blocked candidate can repeatedly consume limit1 and starve a
   later eligible existing-test definition.

All three were reproduced using immutable Linux test binary
/private/tmp/zasp-lifecycle-review-red-20260917-14 in owned cached Docker
PostgreSQL, with no network, read-only mounts and tmpfs. Selection:
`^TestExistingTestLifecycleBatch(LateAuthority|MixedSchedule)Postgres$`.

- request_receipt: stale admission returned no error,10.67s, output97620a.
- execution_state: stale automatic admission returned created1,10.99s.
- MixedSchedule: simultaneous eligible later definition received created0 with
  limit1,6.72s.
- Terminal output00d120 exits1. PostgreSQL processes27/64/95 each joined with
  pg_ctl0/serverWait0. The request/state tests use a previously recorded
  future-timestamp event within the production30-second clock-skew allowance,
  becoming current during the observed final-write lock wait. They do not
  bypass the same-device replay-floor lock with an impossible live insertion.

## Evidence that remains valid but narrower

Final12 at fingerprint
b8a5cfc03428d8b2e1dd6adf45670dbf9da9e9554c83d20799a100bb821d6bfd
passed14 selected SQL suites including ordinary admission, history, legacy
fences, ACL/fingerprint and rollback. It did not cover these three cases.
Mixed13 passed total-limit sharing between real public test/legacy definitions
plus automatic foreign-only evidence and disabled-test refusals. That earlier
mixed test did not cover an invalid candidate ahead of a simultaneous valid one.

The implementer owns one combined fix/test batch. Recalibrate only after SQL
changes apply, run current immutable acceptance, and return the scoped delta to
the same reviewer. Mounted browser/worker proof and the separate operator global
kill-switch issue remain open. None of this is live production evidence.

## Host verification incident

The broad affected apiserver race command used `-skip Postgres`, but some
database-owning tests omit Postgres from their function names. It started a
host PostgreSQL fixture, violating this task's Docker-only database constraint.
It timed out after601.456s (implementer outputecafd1); no per-fixture terminal
join is proved from that timeout. This run is failed verification, not a pass.
It also found the old template-ID expectation missing the two new templates.

The implementer's process inventory557970 and main's independent8c958b both
showed no surviving newly owned PostgreSQL/apiserver/initdb/pg_ctl process.
Only pre-existing PostgreSQL69792 (older than3days) and its children remained;
they were untouched. No broad kill or deletion was used.

The batch brief now requires a positive non-database host test allowlist checked
against function bodies/call paths. A negative name filter is only secondary.
All database verification continues in owned Docker. Record the replacement
focused host command and terminal evidence separately; do not relabel this
failed run as successful.

## First fix verification

Calibration15 applies the first SQL fixes and observes intermediate55 pin
ecc0b107aad588147d289d51d1b499818702ebf73cf7b715801d24d663ebc127
(456808,4.53s, ownedPG29 joined cleanly).

Immutable16 grouped output9c7127/944fa6:

- Request-receipt late-authority case passes16.84s.
- Execution-state case passes the stale-refusal and atomic-state assertions,
  then fails its subsequent positive-control expectation: manual read returned
  Replayed:false after scheduler created1. This is not a full case pass; the
  implementer is diagnosing which eligible definition consumed that run.
- Mixed scheduler concurrency-head case passes6.15s.
- New disabled-head regression fails as intended: five disabled earlier test
  definitions consume the capped four-candidate scan, leaving a healthy sixth
  unadmitted (created0,5.96s). Increasing the scan cap alone does not fix fairness.
- PostgreSQL processes29/63/95/125 joined cleanly; Docker exits1.

The implementer is adding stable eligibility checks before bounded selection,
while preserving exact authority revalidation under locks, and correcting the
positive-control setup without weakening admission. Re-review remains pending.

## Candidate with eligibility preselection

Owned calibration17 output3c460c applies the candidate-binding preselection
helper and observes55 pin
5982d49adccd658e27f84af2098cef3bb90ce743bef6f3eaab411118d78e30da.
The expected old-pin mismatch exits1 after3.73s; PostgreSQL28 joined cleanly.
This is calibration, not acceptance of the final fixes.

The implementer reports replacement host verification using an explicit18-test
non-database allowlist, `-skip Postgres` as a second filter, and PATH restricted
to /usr/bin:/bin: apiserver race2.040s (dca670), securityagent1.693s and
migrations5.228s (d93b9e). The earlier failed broad run remains recorded above.
Final owned grouped acceptance and independent re-review are still required.

## Final18 grouped run and code re-review

Main independently reran the restricted host commands: apiserver2.379s,
securityagent1.298s, migrations4.923s, terminal1b9666 PASS. This is the explicit
18-function API allowlist plus the two named non-API packages, not all API tests.

Owned final18 completes with16 of17 selected top-level suites passing; the
LateAuthority suite has request_receipt PASS17.87s but execution_state and
delegated_wait fail in fixture setup on an unsupported activation transition,
before their intended lock waits. Terminalc05a53 exits1; all19 PostgreSQL
processes joined cleanly. DisabledHead passes7.01s, MixedSchedule6.87s;
fingerprint/release/rollback/legacy/version suites pass at5982.

Independent re-review of v2 reports all three Important defects addressed in
code, no new Critical/Important code/Minor findings. Acceptance is conditional
on corrected setup and successful affected-case verification. Snapshot-only
candidate-binding ACL/owner/search-path/fingerprint/rollback coverage is included.
Permanent organization-lock contention has no fairness guarantee.

Reviewed v2 patch SHA256:
15496eba4bbdf750d1ceaf67b683873c046851ce763f83a7ab1b8372863b30e5.
Admission SQL SHA256:
d50944ff4dba3f301142adc292333447a2d15262ace8e5539617f2bbd1648265.
Release Go SHA256:
f2750fd1492c19f3b1554bcb4f6f333f1639667e8e57c6ebe832aa24555448e5.

After the test-only fixture correction at unchanged product hashes/pin, rerun
LateAuthority, its shared TriggerMatrix helper consumer and fingerprint. Combine
those results with the passing final18 suites; do not erase final18's failure or
claim every suite ran again. Final test delta still needs reviewer confirmation.

## Targeted19 evidence

Production hashes above remain unchanged. Final v3 patch SHA256 is
97f2594904fea0cde062b5594dc475bc8e6c24e3e3eb4f415a1f326d055f2680,
independently checked by main and reviewer. The reviewer accepts the isolated
late-case fixture: it skips only the unrelated earlier runtime definition in
the automatic lock cases; the base matrix still covers all12 combinations.

Targeted19 output413551/bfc89b:

- TriggerMatrix PASS14.78s.
- LateAuthority/request_receipt PASS16.68s.
- LateAuthority/execution_state PASS15.92s.
- LateAuthority/delegated_wait fails during public legacy-control setup with
  kill-switch version conflict40001, before the intended wait. It assumes
  creation version0 for a control that already exists. This is a fixture
  prerequisite failure, not evidence that the production fix failed.
- CompiledFingerprint PASS3.64s.
- All five PostgreSQL processes28/62/94/125/158 joined cleanly; Docker exits1.

The three original defect regressions now have passing evidence across18/19.
The additional delegated-wait proof still gates bounded acceptance. Correct its
prerequisite through public control read/current-version mutation, preserving
the observed lock, post-wait atomic refusal and positive control. Re-run the
affected proof and fingerprint; retain earlier same-product passing coverage.

## Targeted20 evidence

The fixture now reads the existing public legacy control version before
mutation. Independent narrow review accepts that correction. Exact v4 patch
SHA256 fc0070f8ee976ab6fc67f0bc2ad8454b96773a2ae90ba9690b39fe76d36da2a1;
product hashes and5982 pin remain unchanged.

Targeted20 terminal0a6a2a exits1: receipt-wait PASS16.25s, execution-state-wait
PASS14.57s, fingerprint PASS3.42s. Delegated-wait fails because the operation
never reaches the intended held write before the deadline. All four owned
PostgreSQL processes26/63/95/126 joined cleanly. This timeout is not evidence of
a production defect and is not valid delegated-wait acceptance.

Root cause traced by implementer: the legacy21 scheduler does not lock the
definition row, and its receipt/run writes have no foreign key to that row.
The proposed blocker was not on its write path. The reachable wait is its
scoped automatic-trigger advisory transaction lock (release21, lines78ff).
The fixture will hold that exact legacy key, which the new test admission does
not take, and retain observed-blocker, atomic-refusal and positive-control
checks. No timeout widening or product change is planned. Review stays pending.

## Targeted21 and final review closure

Terminal7fe3f4 exits0. The corrected fixture witnesses the actual legacy
advisory lock after prior test-run writes. The operation refuses changed
authority with SQLSTATE40001, rolls back atomically, and admits the subsequent
positive control. Delegated-wait passes18.22s; compiled fingerprint passes4.03s.
Owned PostgreSQL processes27/64 both join with pg_ctl0/serverWait0.

Final independent v5 review approves bounded lifecycle spec and quality:
all three Important findings closed, no remaining Critical/Important findings
in the reviewed delta. Passing coverage is combined from same-product
runs18/19/20/21, not a claim that earlier failed commands passed.

Main output7a97b0 verifies v5 patch SHA256
f4ef90f60d6cef0ff0fb6ad87bf7de93756671a42f92a2b8286b48c7f1a12d13
and the unchanged SQL/release hashes recorded above. Compiled55 remains
5982d49adccd658e27f84af2098cef3bb90ce743bef6f3eaab411118d78e30da.
Reviewer confirms reverse patch check and unchanged HEAD.

This closes only the public lifecycle prerequisite. The historical prohibited
host-PostgreSQL run retains its missing per-fixture cleanup proof. Mounted
browser/worker composition, platform-global stop/re-enable, full release and
live provider/deployment/load/advisory gates remain open. No commit, push,
activation or production-ledger promotion follows from this closure.
