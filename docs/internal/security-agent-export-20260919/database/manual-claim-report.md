# Manual claim isolation correction

Status: implemented and verified at component scope, awaiting independent re-review. No definition activation or workflow-capability edits are included. Original manual report/patch and its 888a5f54 evidence remain unchanged.

The reviewer identified an uncaught manual recheck after provisional budget and lease writes inside the shared organization claim loop. A revoked requester, disabled control or changed prerequisite raised an exception that rolled back earlier claims and prevented later tenants from progressing. The original invalid run remained eligible.

## Change

Only the additive manual fragment, release pin and new registered claim test change. The installed claim function preserves organization -> locked run -> budget ordering. Each eligible candidate now has a subtransaction, with a manual authority/provenance check before budget writes and another before claim emission. A marked check's closed SQLSTATE/message domain refusal rolls back that candidate's provisional writes, then records needs_human/manual_authority_unavailable and clears its lease. The attempt is not advanced. Existing budget/provider reservations remain intact, including an outstanding reservation after reclaim.

Only named domain denials are caught. Unexpected 55000, 42501 and 40001 errors propagate, including errors raised from the marked check. The known P0002 branches cover absent Attack Lab preflight proof and absent retained manual request receipts. No role check, catalog guard, accounting policy or existing action prerequisite was bypassed.

manual_authority_unavailable is an internal last_error_code. It is not inserted into the constrained budget.stop_reason enum or public budget_stop_reason. Registered public detail calls confirm the authority stop omits that budget field. Corrupted original provenance still refuses historical projection.

Pin: 888a5f54afdd322a23ff22381d2abc33701c5274165270e0e4563e5a2e9694c6 -> 0d5ce2f2b6a6252ee8bc5e675b2776a5c23c03fb50754f7c46345f8fbae906f3.

## Evidence

- manual-claim-red.log: four real registered failures before production changes, 20.83s, container1. Revoked requester and retained-accounting reclaim raised42501; disabled control55000; changed original provenance40001. Four clean owned PostgreSQL joins.
- manual-claim-pin.log and manual-claim-pin2.log: isolated rollback-only catalog calibration, not behavioral regression. Both returned the observed catalog pin, container1, one clean PostgreSQL join each. The second reflects the final closed preflight/provenance refusal list.
- manual-claim-green.log: affected batch, overall container1 because the new test had a fixture scoping error. Release registration/exact predecessor ACL restore/up-down-up passed7.13s. Connected manual admission passed7.95s. All seven manual action prerequisite cases passed37.44s. Those unchanged groups are valid at the final pin.
- The fixture accidentally selected the same definition_id in both tenants when creating its first/later healthy runs. This added foreign candidates and invalidated the expected-order assertion. That failed assertion is not evidence of a production defect. The original RED still reached the real uncaught manual refusal, but it does not prove the intended final candidate ordering. The fixture now scopes those INSERTs by organization. No production edit or pin change followed this fixture correction.
- manual-claim-isolation-green.log: all eight corrected cases passed40.89s, container0, eight clean PostgreSQL joins. Cases cover revoked requester, disabled control, original-definition corruption, retained accounting on reclaim, permission loss after provisional writes, expired run_test credential binding, missing Attack Lab proof and missing original manual request receipt. Every case checks committed earlier/later same-tenant and later foreign work, invalid run needs_human without attempt churn/new authority, and no re-entry on a second poll. The reclaimed budget/provider records are compared byte-for-byte. A fixture-only trigger forces permission loss after the provisional lease update. Unknown error injection tests confirm errors still propagate and leave the candidate unchanged.

No host PostgreSQL, external provider/advisory request, image pull, new dependency, commit, stage or push. No live fixture remains. The full public activation/autonomy/multi-step workflow and production proof remain open.

## Exact commands

Build from services/platform, exit0 before each container invocation:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-manual-claim.test
```

The following exact argument sets were used with the common command below; logs capture stdout/stderr through tee with shell pipefail enabled.

| Container name | Selector | Timeout | Log |
| --- | --- | --- | --- |
| zasp-manual-claim-red | ^TestSecurityAgentManualClaimIsolationPostgres$ | 180s | manual-claim-red.log |
| zasp-manual-claim-pin | ^TestSecurityAgentExportReleasePostgres$ | 90s | manual-claim-pin.log |
| zasp-manual-claim-pin2 | ^TestSecurityAgentExportReleasePostgres$ | 90s | manual-claim-pin2.log |
| zasp-manual-claim-green | ^TestSecurityAgent(Manual(ClaimIsolation\|Admission\|ActionPrerequisites)\|ExportRelease)Postgres$ | 240s | manual-claim-green.log |
| zasp-manual-claim-isolation | ^TestSecurityAgentManualClaimIsolationPostgres$ | 180s | manual-claim-isolation-green.log |

For example, the final successful invocation from the shipping worktree was:

```sh
set -o pipefail
/usr/local/bin/docker run --rm --name zasp-manual-claim-isolation --pull=never --network none --read-only --user postgres --cpus 2 --memory 2g --pids-limit 512 --tmpfs /tmp:rw,exec,size=1400m --tmpfs /var/run/postgresql:rw --mount type=bind,src=/private/tmp/zasp-manual-claim.test,dst=/export.test,readonly --mount type=bind,src=/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917,dst=/workspace,readonly -w /workspace/services/platform/apiserver --entrypoint /export.test postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba -test.run '^TestSecurityAgentManualClaimIsolationPostgres$' -test.v -test.timeout 180s 2>&1 | tee docs/internal/security-agent-export-20260919/database/manual-claim-isolation-green.log
```

## Frozen bytes

Before blobs are in manual-claim-before. Unchanged admission_test.go was also copied for preservation; it is not part of this correction.

```text
1de36377d869c4cc4e8330788b5ffd017bdf7996703677cb1036d1e9c06c44dc  before/manual.sql
117efa7002c03f12ba57f8e03cc1ca7ae6e31cb6ad1df56cd3d0de4a1c6fa9c8  before/release.go

cb4106ae08975d8b4ba38bfefc975a05d28aca8839ce5433745b8a75a4982bc4  services/platform/migrations/sql/fragments/security_agent_manual.sql
813a6bf7f11ddd1e0d9246a2581690a60d0fe4a5c518dc8390ab4a3184c994fc  services/platform/migrations/security_agent_exports_release.go
65087bceabcb2aeb4081836dc43c698d41d3f217f24ae19efeabf49ba41686e0  services/platform/apiserver/security_agent_manual_claim_postgres_test.go
f389a6c4d19c87ad31da02a400c265700fb2847ebfd8d3e6f70c6746553a6953  manual-claim.patch

3fddf94887e7a0f0e5a25351f4f5ae9b7f3de6d2bf6522da4e3fe6660fcb216f  manual-claim-red.log
e70a9df03993785e9482f1ceb5e7b1fc42f6158eb776989db0952e05e3b891b9  manual-claim-pin.log
39c82810c7ec234780faf34b14886d74e723209d5990118a3a1a49af40225336  manual-claim-pin2.log
77d3f38afd96a9a0baff25c36d62239eb79da14878315a25060deb86a3a86ee1  manual-claim-green.log
84619d90599125ce84e7cd62c6f71f0c0973bd47c0469a9a360a0428ed965e58  manual-claim-isolation-green.log
```

The remaining four frozen manual batch files retain their original reported hashes. git apply --reverse --check docs/internal/security-agent-export-20260919/database/manual-claim.patch exited0; no patch was applied or reversed.
