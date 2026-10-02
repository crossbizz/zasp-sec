# Manual admission and original provenance

DONE_WITH_CONCERNS. Implemented and frozen for independent review. This is connected registered component evidence, not completion of M7A-23, deployment, browser authentication or external-provider proof.

Accepted baseline: `16d71c1f47360dc46b7fba40e0ab438d0f902a0a0683978c99cf8a88e4a42336`.
Final release58 pin: `888a5f54afdd322a23ff22381d2abc33701c5274165270e0e4563e5a2e9694c6`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.
Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.

The six-file task delta is `manual.patch`, relative to inherited before bytes in `manual-before/`. Root transferred ownership of the original manual admission test, SHA ae5d7dd6be70687d7a10ef69870fd0a0adc097d4824d4e3e769baa604684bc0c. Its public handler test remains root-owned and outside this patch. The accepted accounting fragment is unchanged:52e75bf8a0a892cc7577f36cd43dafa0e6f53604389bf99ebd4fb75e2571c6bf.

## What changed

The new exact13 `zasp_sa_manual_run` is granted only to the registered Security Agent API role. It requires exclusive role authority, READ COMMITTED and exact58 readiness. Organization advisory/admission locks precede scoped idempotency, definition and source locks. It validates the exact current definition and its original version/digest/activation, original version actor and current requester scopes, enabled controls, environment scope and each action's prerequisites. Rechecks follow waits and the final audit/request-receipt writes.

The manual intent digest covers schema version, scope, requester, definition/version and idempotency key. Freshly generated run/audit/correlation/receipt IDs are excluded. One transaction writes the run, trigger receipt, audit and request receipt. Replay uses the original IDs and digest, rechecks current authority and expiry, and does not write another receipt or audit. The scheduled definition trigger is unchanged.

Source-free manual admission works for run_test/rerun_test through the exact persisted test definition and for start_attack_lab through retained failed proof and existing preflight/safety bindings. Export targets the actual parent run. update_finding_response and revoke_integration_connection still need original finding evidence; isolate_session needs runtime evidence; create_temporary_policy still needs original finding/path evidence even though its target is the environment. Missing prerequisites refuse before creating execution authority. Explicit-source and scheduled routes are unchanged. This does not implement multi-step planning.

The original-receipt resolver checks full scope/run/definition/version/requester, canonical intent, digest, response binding and original definition digest. It does not require historical receipts to remain within their idempotency replay TTL. No existing receipt-deletion path was found. Manual public values have explicit empty legacy evidence arrays plus the closed manual_trigger object. A ProductID row without any receipt retains its predecessor behavior; a mismatched retained receipt cannot borrow that exception.

Additive amendments cover the shared budget claim, run page/detail, current family approval values, export and existing-test/Attack Lab planner context/rechecks/preparation, dispatch authorization and cancellation values. Manual context includes typed run.manual_trigger and original untrusted manual evidence. Canonical plan evidence_ids is empty; plan.trigger_digest remains bound to the original receipt. Export selected evidence stays a separate ordered typed list, never a fabricated ProductID. Existing accounting wrappers, reservation semantics, receipt-first replay and deterministic provider-free prepare authority are unchanged.

The release catalog explicitly includes zasp_sa_manual_ functions, owners, ACLs and full definitions. New private helpers are owner-only. Replaced predecessor bodies/owners/ACLs are retained for exact restore. Downgrade locks trigger receipts and refuses retained manual history, independently of export history.

The existing collector's owner-seeded manual component fixture now includes the canonical request receipt and empty parent-plan evidence array. It remains component-only evidence. The new ManualAdmission test uses actual API admission and seeds no parent run, trigger receipt, plan, step or provider permit.

## Tests and corrections

TDD evidence is retained, including failed setup or fixture checks without relabeling them as product bugs.

- `manual-admission-red.log`: actual API missing-function42883,5.32s, clean owned PostgreSQL join, container1. Root had independently recorded the same missing-function RED before ownership transfer.
- Interim producer pin da3bab67 passed atomic admission, unchanged scheduled kind, exact replay, version/scope/current-requester refusal and distinct-key assertions. `manual-connected-red.log` then reached a behavioral list failure: raw64hex was placed in evidence_ids without manual_trigger,5.84s.
- At checkpoint6aa977, the connected path reached correct nested detail/context/action_details. An assertion decoded it as bare detail and failed. `manual-connected-fixture-error.log` is fixture evidence, not a product defect.
- Offline compilation hit ENOSPC. An inadvertently started subsequent run used the prior binary; `manual-stale-binary.log` is not new-source verification. Four exact obsolete database-owned binaries were removed after root confirmed none was mounted: -binding, -cancel, -grants and -origin, about264MiB of regenerable output. Source, patches, logs and shared cache were untouched. Root separately cleaned its own obsolete outputs.
- `manual-connected-green.log`: actual manual producer -> budget claim -> typed context -> real reserve/explicit-zero settlement/accept -> independent approval decode/decision -> reclaim -> export dispatch -> shared registered capture PASS8.47s. Seven action prerequisite subcases PASS36.00s. Eight owned PostgreSQL joins, container0.
- `manual-safety-red.log`: exact release restore, concurrent same-key admission and current permission loss during final audit write passed. Cancellation returned raw digest legacy evidence and failed behaviorally4.60s. Integrity probes initially used an ungranted private reader, so their refusal assertions are invalid evidence; they were replaced with the actual guarded context reader and an initial positive control.
- Cancellation now records and replays original manual metadata with empty evidence_ids, without changing cancellation authority.
- A retention fixture initially also had an inherited export action control. Before claiming independent manual retention coverage, the test removed that control and asserted absence of other export history. The corrected Integrity case also checks manual function owner/ACL and deliberate volatility drift refusal. `manual-integrity-green.log`: PASS5.80s, clean join, container0.
- Final self-review added borrowed_product_id. `manual-borrowed-id-red.log` proves a parent carrying a substituted ProductID could borrow the legacy no-receipt fallback despite its retained original manual receipt. The first subcase is valid behavioral RED. Its fatal assertion prevented restoration and contaminated later subcases in that run; those later failures are not separate bug evidence. The test now restores each probe after a nonfatal assertion. The minimal production correction requires that no scoped parent receipt exists before allowing the legacy fallback.
- Calibration logs record observed catalog pins and expected stale compiled-pin refusal. They are not behavioral RED or acceptance runs.

## Affected feature batch

`manual-feature-batch.log` ran coherent pin2dfa9559c6a6a6e610d0e61ba22e970131f73baff76cb72cd8306752d39b999e. All11 top-level groups passed;23 PostgreSQL lifetimes joined with pg_ctl and server Wait exit0, no skips, container0.

| Group | Result |
| --- | --- |
| ExportPlannerAdmission | PASS18.61s, autonomous/supervised/failure |
| ExportPlannerPredecessorReplay | PASS11.98s, accept/fail |
| ExportSources | PASS21.14s, all four selected families including manual |
| ExportRelease | PASS6.41s, exact predecessor fingerprint/ACL restore and up/down/up |
| ManualAdmission | PASS7.34s, connected planner/approval/dispatch/capture |
| ManualActionPrerequisites | PASS34.54s, seven action subcases |
| ManualIntegrity | PASS5.51s, original scope/version/digest/intent/response checks |
| ManualConcurrency | PASS4.53s, two simultaneous same-key API calls, exactly one run/receipt/audit |
| ManualCancel | PASS4.67s, fresh and receipt replay |
| ManualPostWait | PASS4.65s, effective scope removed during final audit wait, no surviving writes |
| ManualHTTP | PASS5.90s, root-owned real handler/repository/API-role test |

The main batch's exact draft test is retained as `manual-feature-draft-test.go.txt`, SHA70c437f57d50b725709e83eada8e5929338bdbb0a62bd4ceb4400d66e5c88d40. `manual-main-batch.patch` retains its complete six-file product/test checkpoint. `manual-checkpoint/` retains the earlier6aa977 producer/read source snapshot used by root's first HTTP proof.

After the minimal borrowed-ID guard and pin update, only affected groups ran again at final888a5f54:
ExportRelease PASS6.46s; ManualAdmission PASS7.38s; ManualIntegrity PASS5.67s (six independent mutations, manual-only downgrade, function drift and ACL); root ManualHTTP PASS5.58s. Four clean owned PostgreSQL joins, container0. Complete output: `manual-binding-final-green.log`.

Every database log starts with the exact command. All used cached Linux/arm64 PostgreSQL digest80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba, --pull=never --network none --read-only --user postgres, owned tmpfs and mounted offline binary. No host PostgreSQL, image pull, external provider or advisory call occurred.

Offline compilation, from services/platform, exited0 before the successful runs:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

Root's HTTP test SHA at the main batch was d35de389c637931f7719acd71e387d9bd73be48db6544ca628be2982ef4d2c0e. It supplies identity at the middleware boundary. It proves the real handler/repository/database path, not browser login, production identity or external storage.

## Frozen hashes

Before:
```text
ae5d7dd6be70687d7a10ef69870fd0a0adc097d4824d4e3e769baa604684bc0c  admission_test.go
909c909efe462474cfd3f8b015fd012323dcf0189886b08af2a75f58e3202715  down.sql
feec0ae7806f79d26718ca5bd207e7425cb802a7979e440e4cd243d9e79d69ed  export_test.go
471b487eeecbd667adf01c787865645ed31e58d2fb4f07782fb5feed3a4c82ab  release.go
389a23b75746bf1f3cc147de7ae2f3b2d7a8f79fc670f939d7303068776d651c  up.sql
```

After:
```text
1de36377d869c4cc4e8330788b5ffd017bdf7996703677cb1036d1e9c06c44dc  services/platform/migrations/sql/fragments/security_agent_manual.sql
117efa7002c03f12ba57f8e03cc1ca7ae6e31cb6ad1df56cd3d0de4a1c6fa9c8  services/platform/migrations/security_agent_exports_release.go
30df8924c0dc32cc861363bb39fe8dd722cf8c83ce0e33cbae0def1c9c43cee1  services/platform/migrations/sql/0058_production_security_agent_exports.up.sql
2e68048c8b0ac75cf987871692a8b1789d1a2a2c89d5550859b9fa1791bc57d0  services/platform/migrations/sql/0058_production_security_agent_exports.down.sql
828c381f39a5d953c77302abe9e26105296f7de8c809c9b5f6578038f3c5c028  services/platform/apiserver/security_agent_manual_admission_postgres_test.go
80d1bd1a8fe0fae4fd9f13c738c00b2f46d46dd3ebea647758d4b9d1df64fe04  services/platform/apiserver/security_agent_export_postgres_test.go
352450b1e7f6e8167a88865641410c55e3f76fcb8bdbab704baefa64eee79d72  docs/internal/security-agent-export-20260919/database/manual.patch
```

Key logs:
```text
914682a1c16db4420515d56bc39ceb132532275d26b50bec9e487ea5d08f9a50  manual-admission-red.log
fd175611f8de64b0b51275f2de63f2384a33743734a55f12e524d2eb033afca9  manual-connected-red.log
d0ac90761a13a87d3253b3a2a371246587348fce8738e7348c60040059fe02d0  manual-feature-batch.log
57a5402239d88346d8aefb60838f33386249ae24e7fbf2bb33b3888b8149d769  manual-borrowed-id-red.log
9ea192a916019375a108c3351c3bc5144706ef75a6df1dce4e6db3eef7ab3d27  manual-binding-final-green.log
```

`git apply --reverse --check docs/internal/security-agent-export-20260919/database/manual.patch` and `git diff --check` exited0. No stage, commit, push or subagent. No live Docker/compile/PostgreSQL session remains.

Definition activation/public enablement, true multi-step planning, existing-test dispatch lost-reply reliability, full authenticated UI/runtime workflow, deployment and external production proof remain required connected work. This batch does not waive them. Root owns the independent review of these frozen bytes.
