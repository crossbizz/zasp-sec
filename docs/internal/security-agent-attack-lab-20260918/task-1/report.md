# Task1 frozen for independent review

Status: DONE_WITH_CONCERNS. Admission foundation only. The process incident below is part of this handoff, not permitted database proof.

HEAD remains `8733b16f8d939d38a8157dd2519e57fc6f630542`. Nothing was staged, committed or pushed. The scoped patch compares captured inherited dirty bytes with this task's final bytes, not HEAD or the branch base. `blobs.json` has29 identities,28 changed files; the captured budget-release database file is unchanged. Reverse application passed `git apply --reverse --check`.

Frozen patch SHA256: `61cc67271f26fe641c256158796d8cc6db3aa914b09a196d2bb3c7385a65c1aa`.

Release57 checksum: `6a1b499d50b74ccb4a589f5de5d508ff43d2170f55cfadc7529924f3db7edd04`.

Release57 fingerprint: `95b582775ad0e6908861d890f62a1f56832e16103bb8845cd31685903d9b75ad`.

No accepted1..56 SQL or pins were edited. Release56 remains checksum `f5871c564709034eaf89f325fcb732a3f3314ecc0ff95f7a0ec99f6d674ddfc1`, fingerprint `8534cdcdce945aab8f85dce88d9bf8a01b100387490a7cefe5d51f2ae11d8ced`. The release-cycle test restored this exact live fingerprint after unused57 downgrade.

## What changed

Additive57 saves and replaces exact predecessor entrypoints, including ACL order. API and lease-bound agent wrappers call private shared admission/cancellation cores. No application role can execute those cores directly. Dedicated reconciler registration grants only the fixed57 role with INHERIT and without SET/ADMIN; it does not yet grant settlement functions.

The closed definition pair is `start_attack_lab` + `attack_lab_run` + one exact `existing_test` reference. Draft creation and validation do not require a failed source. Planning selects the latest eligible same-scope failed terminal source, with timestamp/runID ordering and exact attempt/evidence identity. Plans freeze that source. Both autonomies require an approved distinct operator, current selected-scope view/manage_workflows/run_tests permission and fresh authentication.

Dispatch checks organization admission, run/step, definition, source/attempt, environment, target and credential authority under locks. It reserves the effect, creates the deterministic Attack Lab execution and outbox, and inserts a forced-RLS scope-complete link in one transaction. Final checks use wall-clock time. Retained link replay survives public receipt expiry and rejects changed input/approval identity.

Production repository operations probe57 readiness per operation and route matching definitions to internally pinned57 planner/prepare/accept/reserve/dispatch wrappers. Corrupt57 does not fall through55. The worker request includes only a SHA256 digest of the trusted snapshot, not its private evidence reference. The model candidate remains index/action/target ID. Existing run_test/rerun_test references remain on55.

Public approval projection includes the source/safety snapshot, exact UTC-Z expiry and the moderate-risk human-interpretation wording. Catalog availability is unchanged. The optional definition capability must be exactly one true value; omitted, false and ambiguous values deny the new action.

## Shared verification

All permitted database runs used the cached digest in the plan, `--pull=never --network none`, owned disposable PostgreSQL, a read-only worktree mount and no provider call. Every retained database run reports normal PostgreSQL process join. Logs contain exact commands.

- `red.log`: original reference rejection and missing dispatch authority.
- `planner-red.log`: real planner preparation rejected the valid action; a digest on a legacy action was accepted before the fix.
- `first-registered-green.log`: initial registered preparation/approval/claim/dispatch/replay checkpoint. This predates the final pin and is not final acceptance.
- `authority-green-rollback-red.log`: expanded authority passed; unused rollback failed. Diagnosis found reordered ACL entries for workflow/risk mutation. Preserving ACL ordinality fixed exact restoration.
- `postgres-green.log`, session64625 exit0: authority19.03s and release-cycle7.46s. Covers deterministic source tie-break, newer source after approval, observed concurrent same-step dispatch, one linked job/outbox, retained replay, actual automatic test_write admission, supervised read_only, production truth and production-write declaration refusal, revoked/wrong-scope approver, stale auth, expired lease, source/definition drift. Release cycle covers runner upgrade57, registered reconciler positive/replay and mixed-authority denial, direct-core/table denial,58 refusal, exact unused rollback/re-upgrade, registered source-free draft/validation, and retained definition-history rollback refusal.
- `authority-waits-green.log`, session22850 exit0,33.14s: adds actual production_write credential registration refusal; corrupt57 planner_context/reserve refusal; missing failed source; observed permission revocation, fresh-auth expiry, approval expiry, worker lease expiry and credential/preflight expiry waits; changed input/approval replay refusal; active and terminal linked-history downgrade refusal. Denials compare effect/link/job/outbox/receipt/audit state.
- `repository-bridge-green.log`, session52929 exit0,8.66s: actual automatic scheduler → production Go repository context/acceptance → approval → dispatch. Changed source between planner load and acceptance fails without parent mutations. This is controlled registered-role proof, not a model/provider run.
- `race-green.log`, session27285 exit0: exact listed native tests only, no PostgreSQL selection. Worker2.231s, API2.134s, CLI2.578s. Covers real request preparation/digest binding and digest-only processor bridge, existing run/rerun controls, reference/override/capability negatives, explicit CLI commands and the compiled binary's invalid-principal-before-DB errors.

The last source change was adding independent prompt/target reference-override negatives; the exact native race group tested those final bytes. The final automatic repository case changed only its test branch after the shared database batch; session52929 tested that branch. Unchanged database evidence was reused.

## Process incident and boundaries

`native-race-incident.log` records session26940. Its broad native regex accidentally included the PostgreSQL tests. Homebrew PostgreSQL binaries were present, so those disposable host fixtures ran despite the no-host-PG constraint. The agent notified the controller after detecting this. Post-run process inspection found no matching owned PostgreSQL/apiserver test process. That native database result is excluded from permitted acceptance; cached-container results above are separate. Subsequent native selection was inspected with `go test -list` and anchored to exact non-Postgres test names.

Final read-only cleanup check found no `zasp-attack-lab-task1` container and no matching owned AttackLab PostgreSQL/test process. No downloads, live provider calls, advisory requests, Terraform, publication gates or UI suites were run.

Task2 must implement the real controller/recovery proof and dedicated renewable-lease reconciler, cancellation, exact immutable evidence and settlement. The link schema reserves exact proof bytes plus a digest, but no placeholder can report successful settlement. Task3 still owns catalog enablement, controls/UI/product workflow, full connected proof and publication. Explicit enabled activation through the mounted UI, real provider execution and deployment remain unproved here. The automatic fixture seeds its enabled definition and tenant control, then uses the real scheduler and registered execution authority.

Independent spec/quality review is still required. This does not complete M7A-22 or reduce the original728-task scope.
