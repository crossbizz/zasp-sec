# Planner admission checkpoint

DONE_WITH_CONCERNS. This release58 SQL batch is frozen for independent review. It does not complete M7A-23 or establish production readiness.

Pin: `4f5dbcc24bcc51b39c3aff1fc019ffed8e15b3e4bd8278367e364c5fc9a1073c`.
Base: independently accepted approval/route component at `e60b91c5d4ecd09bd20617e12eca85bc139865c9532f71e6613e578a6a5bd676`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.
Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.

The five-file delta is `planner.patch`, relative to retained inherited before bytes under `planner-before/`. It adds the planner fragment and registered PostgreSQL test, embeds that fragment into58, updates its exact fingerprint, and adds private input retention/downgrade handling. Earlier accepted links/sources/jobs/renderer files are untouched. Root owns Go/TS/API and their separate tests.

## What changed

The public interfaces are context6, reserve14, accept15 and fail13 under the agreed `zasp_sa_export_*` names. Context/reserve require the current worker lease. Accept/fail classify the immutable run-bound definition privately, then delegate to the existing family implementation or the export implementation. Their callers need no lease-gated family probe after a committed response. Existing-test replay after acceptance/failure clears the lease still returns its original receipt; changed input is refused.

A private forced-RLS, owner-only `zasp_sa_export_planner_inputs` row captures full scope/run/attempt, original definition ID/version/digest, ordered typed selection, canonical context/input digest and capture time. Context creates only that input snapshot. It creates no plan, step or provider permit. Scoped foreign keys and a nonempty-table downgrade refusal retain these inputs.

Initial selection includes only readable original associations. Audit references require effective view_audit for both required principals; a security_engineer can obtain finding-only input without an audit role floor or leaked withheld IDs/counts. Once captured, selection never grows or silently shrinks. Later audit inserts do not change the original context or reservation input. Current authority and source versions are checked again at use and after source waits.

Selection order is original trigger, readable same-run audit rows, then retained same-run proof step references. The resolver clone preserves all seven accepted source checks and bounded redaction, changing only its entry requirement from an existing export step to its scoped non-simulated parent. The resolved body is not model input. Closed typed references are all the model receives; it can choose an exact ordered subset and only its own parent as target. No model-created source relation, private locator or storage path is accepted. More than100 references refuses without truncation.

The context binds the original definition version/digest and current active matching definition. Reserve and accept reuse that captured context, preserve the predecessor org/run/budget lock order, and recheck current lease, budget, controls and principals after waits. Acceptance writes a real canonical flattened plan, step, optional supervised approval and audit in the predecessor savepoint/receipt protocol. Late lease or budget expiry rolls those writes back. Sticky budget stops and accounting behavior stay unchanged.

## Evidence and a correction

Superpowers TDD produced registered behavioral RED before SQL: all three admission modes reached missing context function42883, with no prior plan/step/reservation. `planner-red.log` contains the exact command/output; three owned PostgreSQL lifetimes joined normally, container exit1.

The first draft exposed an invalid positive fixture: security_engineer did not have effective view_audit even though direct scope JSON listed it. The fixture now uses security_admin for all-readable input and separately tests the engineer finding-only case.

The early permission-wait RED in `planner-wait-red.log`, and the two permission failures in `planner-feature-batch.log`, are INVALID fixture evidence for a stale-permission bug. Changing direct scope JSON did not revoke security_admin's effective role grant. They must not be cited as production bug proof. The fresh recheck implementation was informed by source inspection and the agreed authority-after-wait requirement.

The corrected wait fixture uses security_engineer plus a real security_admin group mapping. It asserts effective audit access true, captures input, blocks source-row collection, deletes that group grant, asserts effective access false, then releases the barrier. The normal registered call refuses.

An isolated schema clone omits only the post-source-wait authority call. Production SQL and pin are unchanged by this mutation. The corrected case then fails because the clone returns success after permission revocation: `planner-mutation-red.log`,5.30s, exit1, one clean PostgreSQL join. A preceding mutation setup attempt used an invalid group-reference spelling; `planner-mutation-setup.log` retains that23514 setup failure and is not behavioral proof.

The one affected feature batch used the final production SQL/pin. It had18 PostgreSQL lifetimes, all joined normally, no skips, container exit1 solely from the two invalid permission fixtures:

| Registered group | Result |
| --- | --- |
| PlannerAdmission | PASS18.74s; autonomous, supervised, failure |
| PlannerRefusals | Invalid permission fixture stopped the group at4.89s |
| PlannerPredecessorReplay | PASS11.73s; existing-test accept/fail receipt replay and changed-input refusal |
| PlannerAuthorityWait | Invalid permission fixture failed at5.08s |
| PlannerEngineer | PASS5.10s |
| PlannerAccounting | PASS16.45s, characterization of retained gap, not safety acceptance |
| PlannerBounds | PASS10.32s; overflow and input-only retention |
| PlannerLateAcceptance | PASS13.61s; audit-lock lease expiry and receipt-lock budget expiry |
| PlannerRetainedSources | PASS9.71s; attack_path and retained runtime_decision |
| Release | PASS6.59s; actual Runner registration, drift and up/down/up |

Admission uses a real registered claim, context, provider reservation, usage settlement, acceptance, supervised decision where needed, and registered export dispatch. It seeds prerequisite definition/run/trigger/source state, not a plan or step. No external model is called.

Only the two corrected fixture groups ran again. `planner-followup-green.log` records Refusals PASS7.58s and AuthorityWait PASS4.76s; container exit0, both owned PostgreSQL lifetimes joined with pg_ctl and server Wait exit0. Refusals now covers original definition drift, captured source drift/permission loss, parent mismatch, tuple ordering, empty selection, extra path field and private worker/API access boundaries. No production SQL or pin changed between the affected batch and this follow-up.

Every database test used the cached Linux/arm64 postgres image by digest, `--pull=never --network none --read-only --user postgres`, owned tmpfs data and an offline-built binary. The first line of each retained log is its exact Docker command. Calibration logs retain both observed draft pins and expected mismatch exits.

Offline compilation before the runs exited0, from `services/platform`:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

## Accounting gap, still required

A registered worker with a valid current claim/context can call accept directly without reserve or settle. A queued plan is accepted. It can also reserve50 tokens/100 cost and call accept without settlement; a queued plan is accepted and the permit stays unsettled. The tests deliberately retain this predecessor behavior, they do not prove safe accounting.

The existing-test delegated accept test also calls context then accept without a reservation and succeeds, followed by stable lost-reply replay and changed-input refusal. Attack Lab's acceptance clone shares the predecessor structure by inspection; this batch did not directly run its missing-accounting case. A subsequent all-family policy change must close missing/outstanding usage consistently before production acceptance. No export-only accounting rule was introduced.

Unknown usage is different: actual budget_settle_planner with unknown usage stops the parent at needs_human/budget_usage_unknown, retains the unsettled reservation, and acceptance refuses without a plan. That safe-stop behavior is tested.

## Frozen bytes

```text
d211420809fa752b8edb9bc3491516066561a90573cb2ecb6745071a512c1135  before release.go
87a38c5cf59e10f4cbd0d05d7a5e90f8237029f2865e24db8b98a21bf0038f0c  before up.sql
20d2706de4f746ae978fa1f663eb9e9e53c585a437fce3324d23dfd910ad2c15  before down.sql
e33648e41af5a93fd6ff226eef7da38251bc1febcf4b2c39c26b4241279d3bcb  after services/platform/migrations/security_agent_exports_release.go
63de6baa21b8e99bfd42a4ce05257d822df8ede9e6ac3e157a4171bb26caa45c  after services/platform/migrations/sql/0058_production_security_agent_exports.up.sql
909c909efe462474cfd3f8b015fd012323dcf0189886b08af2a75f58e3202715  after services/platform/migrations/sql/0058_production_security_agent_exports.down.sql
667bc4f5a556d1eac55d4b133a205451794338e8768e96f589dd32908ae5f3db  new services/platform/migrations/sql/fragments/security_agent_export_planner.sql
4deae895ff86c7314fa7cffe06c3cd8bed345fa752473c18f85264fae8b66e1e  new services/platform/apiserver/security_agent_export_planner_postgres_test.go
8898f875c0a28aa5922f1657fb4b824d5c85fdc16537cd573aa6d586391aaa06  planner.patch
d1263cd790616f61c38a2d9c74e2c9eeb82b4321fed88693f5983f3f59296449  planner-red.log
145deb9c61ad858755d4072deae944c8e8fc80d64fc6b79142dcd9f15d6367cc  planner-feature-batch.log
2dd5a9fd288ac45fbe5dcbd34f42a41eba475513fd2c7ba1563b56e009adf552  planner-mutation-red.log
9f44ba8045a86384731ec2d87d8f57c853407630453afc20ba071b5a10b1f535  planner-followup-green.log
```

`git apply --reverse --check docs/internal/security-agent-export-20260919/database/planner.patch` exited0 against the frozen files. No staging, commit, push, image pull, host PostgreSQL, provider/advisory call, new dependency or subagent occurred.

Manual context currently refuses explicitly. Its next connected change must add validated optional run.manual_trigger, keep original digest/version, and fix legacy plan evidence IDs; the snapshot table and digest need no new columns. True multi-step planning and publicly admitted prior-proof selection, definition activation, all-family accounting closure, existing-test dispatch lost-reply reliability, fully mounted public workflow, deployment and external production proof remain open. Approval/run projection are earlier independently accepted components, not omitted from this sequence.

Root owns the independent review of this frozen planner delta.
