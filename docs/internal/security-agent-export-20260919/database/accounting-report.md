# All-family planner accounting closure

DONE_WITH_CONCERNS. The accounting closure is implemented and frozen for independent review. This is registered component evidence, not full M7A-23 or production acceptance.

Accepted baseline pin: `49c9b2e421d80372470136ede8e9cced66ba34fa19dae1b72e88f6ee0b0cfecb`.
Final pin: `16d71c1f47360dc46b7fba40e0ab438d0f902a0a0683978c99cf8a88e4a42336`.
HEAD: `8733b16f8d939d38a8157dd2519e57fc6f630542`.
Worktree: `/Users/manishmaheshwari/Projects/zasp-sec/.worktrees/cached-runtime-ship-20260917`.

The five-file task delta is `accounting.patch`, relative to retained inherited before bytes in `accounting-before/`. It adds one SQL accounting fragment and its registered test, embeds the fragment after planner clone construction, updates the exact release58 pin, and adapts existing export planner fixtures to real accounting. The accepted planner SQL, renderer, source collectors and job lifecycle are unchanged. Root explicitly approved the affected existing-test-fixture ownership extension.

## The boundary now enforced

A single private gate covers direct legacy, v33, existing-test and Attack Lab accept/fail entry points, plus the private export accept/fail cores reached by the public58 wrappers. The eight predecessor bodies and their ACLs are saved through the existing58 restoration mechanism. All ten retained implementations live as owner-only functions in the private prior schema. Public signatures and their existing ACLs stay unchanged.

The gate validates exclusive worker authority and exact58 readiness, then locks organization admission, run, budget and current-attempt reservation in that order. It uses the existing organization advisory lock as well. A scoped receipt for the current attempt bypasses fresh accounting only so the original body can run its exact outcome/input/output/model/policy/candidate conflict checks. Receipt presence itself never grants a new plan or invents replay authority.

Fresh model output requires the reservation keyed by the same full scope/run/current attempt, settled with complete usage, matching input digest, output digest, model and original worker/lease digest. Any outstanding reservation for the run refuses. Missing accounting and unsettled accounting refuse without deleting a permit or consuming the attempt; real settlement followed by retry succeeds. Explicit zero usage is valid. Reservation cost policy is deliberately not equated with planner policy.

The only zero-provider exception is planner_unavailable with NULL output, no current-attempt reservation and no outstanding run reservation. It can record a terminal failure, never acceptance. Even a settled current-attempt reservation cannot use that exception.

The gate does not mutate a budget stop. An already stopped or expired budget delegates to the original savepoint/receipt protocol, which returns budget_stopped and creates no plan, step or approval. Unknown usage remains sticky and keeps the unsettled permit. The existing post-write lease/deadline checks remain active. Deterministic prepare APIs have no new provider requirement.

Previously committed receipts retain their predecessor replay rules, including historical receipts created before this fix. This batch does not repair historical plans or pretend those earlier outputs were accounted.

## RED first

`accounting-red.log` records the actual registered58 bypass before product changes. Every family, export, existing-test, Attack Lab, legacy and v33, accepted both missing and outstanding accounting. Their rejected-output failure paths also accepted unaccounted output. The test rolls back each probe to exercise both cases, then uses real reserve/zero-usage settlement/accept/replay as a positive control.

All five subcases failed for those behavioral assertions:32.02s, container exit1. Five owned PostgreSQL lifetimes joined with pg_ctl and server Wait exit0.

An initial compilation attempt overlapped root's manual-start file creation and failed on its temporarily missing securityAgentRunInput type. Root completed that change; the retry compiled. No unrelated file was changed here.

Calibration exposed one implementation setup error: pg_get_function_identity_arguments includes argument names and cannot be passed as a regprocedure type signature. The saved signature now comes from the function OID's regprocedure text. `accounting-calibration-setup.log` retains that42601 failure; it is not behavioral RED. The next calibration observed the final pin and failed only the expected stale compiled-pin check. Both owned PostgreSQL processes joined normally. `accounting-calibration.log` retains the exact observed fingerprint.

## One affected batch, one fixture follow-up

The main feature batch ran the final production SQL/pin. It had35 owned PostgreSQL lifetimes, all joined normally, no skips. Twelve of thirteen top-level groups passed:

| Group | Result |
| --- | --- |
| AccountingAdmission | PASS36.01s, all five families |
| AccountingFailure | PASS28.17s, all five |
| AccountingNoProvider | PASS25.49s, all five |
| AccountingStops | Fixture inspection failure24.63s |
| AccountingPrivateACL | PASS4.48s |
| PlannerAdmission | PASS18.86s, autonomous/supervised/failure |
| PlannerCandidateOrder | PASS6.10s |
| PlannerRefusals | PASS6.43s |
| PlannerPredecessorReplay | PASS12.11s |
| PlannerEngineer | PASS5.47s |
| PlannerAccounting | PASS15.42s |
| PlannerLateAcceptance | PASS14.53s |
| Release | PASS6.85s |

Container exit1 came from the stop fixture. It tried to inspect private planner_receipts using the worker connection and correctly received42501. The returned response was budget_stopped; this was not a product defect. The exact draft test source is retained in `accounting-draft-test.go.txt`, and complete output in `accounting-feature-batch.log`.

The corrected stop test commits the registered response, inspects persisted receipt and absence of execution authority through the owner connection, verifies cleared-lease replay and changed-input refusal, then restores only that isolated fixture between cases. It finally performs real unknown-usage settlement and checks the retained stop/reservation. It adds no worker table permission or test-only bypass function.

Only AccountingStops ran again: PASS35.78s across all five families, container exit0, five clean owned PostgreSQL joins. `accounting-stops-green.log` is complete. No production SQL or pin changed after the feature batch.

The registered coverage includes wrong attempt, input, output, model, worker and token digest; outstanding run accounting without a current-attempt permit; known-zero acceptance; committed accepted/rejected/unavailable receipt replay; changed replay refusal; unknown usage; stopped/expired budgets with attacker-supplied unaccounted output; private clone/gate non-bypass; actual planner/reserve/settle/accept/approval/dispatch; and late audit/receipt waits. Reservation identity-drift cases use owner-controlled fixture mutations. They do not claim external provider proof or a new concurrent-settlement interleaving test.

The private ACL case checks all ten saved implementations are unavailable to worker/API and exercises direct worker refusal. It also checks all eight predecessor entry points were saved. The existing release test compares the full57 live fingerprint and public function ACL catalog before58 and after downgrade, then applies58 again and registers actual compliance workers. It passed without changes.

All database runs used cached Linux/arm64 PostgreSQL by digest, `--pull=never --network none --read-only --user postgres`, owned tmpfs data and the mounted offline binary. Each log starts with its exact Docker command. Compilation before runs used this command from `services/platform` and exited0 after the transient root edit:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 /opt/homebrew/bin/go test ./apiserver -c -o /private/tmp/zasp-export-db-test-initial.test
```

## Frozen hashes

```text
03092135441a5daa8cdf3cc173821a67115783b215ba1cbb44bb2f327791e561  before release.go
63de6baa21b8e99bfd42a4ce05257d822df8ede9e6ac3e157a4171bb26caa45c  before up.sql
f2cabf76357055501369b0b7f2529550b3466cbdd2f450ffa4fddfcbda5e2643  before planner_test.go
52e75bf8a0a892cc7577f36cd43dafa0e6f53604389bf99ebd4fb75e2571c6bf  new services/platform/migrations/sql/fragments/security_agent_export_accounting.sql
471b487eeecbd667adf01c787865645ed31e58d2fb4f07782fb5feed3a4c82ab  after services/platform/migrations/security_agent_exports_release.go
389a23b75746bf1f3cc147de7ae2f3b2d7a8f79fc670f939d7303068776d651c  after services/platform/migrations/sql/0058_production_security_agent_exports.up.sql
3d65b3149780d266b04f849d83f58fca779667e33477532ae7e1eb71efd5aa75  new services/platform/apiserver/security_agent_export_accounting_postgres_test.go
08181f084c37b8d477d001c91c834d88f38c6557b106344fe64b1c76fdc0bb9e  after services/platform/apiserver/security_agent_export_planner_postgres_test.go
d4776309df9ad4924bba679d5ea1bf259f6e4ec4161732437ccee3f46616012e  accounting.patch
9e2c16d141a660ea5d5ed54836e2e7ec93f1ffe2ef542f85a71c01e2fbd7f26a  accounting-red.log
acff98a6a94db6fa505e41aabd75a00c9912a2916176fdc6c6d4d778fa23d2bc  accounting-feature-batch.log
8ab9444f5085e53d87c9dbb8c59632271ecaa61ec1dad939757bb90e7e1e42d2  accounting-stops-green.log
cf39a63db6c564632ece2f29db45e1d10a254a212a5e2cff4941601aaf734c73  accounting-draft-test.go.txt
```

`git apply --reverse --check docs/internal/security-agent-export-20260919/database/accounting.patch` and `git diff --check` exited0. Earlier accepted evidence remains untouched; the old missing/outstanding characterization describes its old pin and is superseded by this implemented closure, pending review.

No stage, commit, push, image pull, host PostgreSQL, dependency install, external provider/advisory call or subagent occurred. Root owns the independent review. Manual producer/claim/read/context authority, multi-step planning, definition activation, existing-test dispatch replay, mounted public workflow, deployment and external production proof remain open. The agreed future manual function needs explicit catalog/ACL/drop coverage because its prefix is not zasp_sa_export_; that change is not hidden inside this batch.
