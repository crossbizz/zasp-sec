# Inventory navigation regression checkpoint

The composed Red Team SIGTERM test71877 failed before its shutdown checkpoint:
the real Support-agent click on /discovery/assets set an inventory selector,
but the global activity parser replaced the drawer with an invalid-link page.
Cleanup completed. This exposed a product integration bug despite the earlier
2001-test UI pass and selective integration review.

## Bounded repair and independent review

Recovery implementer /root/candidate_navigation_fix reproduced12 intended RED
failures:4 parser delegations and8 actual shell click/initial-location cases.
Thirty new refusal cases passed. An initially invalid HTTP test fixture was
corrected before the intended RED, without product changes.

Only canonical single inventory selectors on /discovery/assets,
/inventory/tools, /identities and /inventory/runtimes delegate to the existing
authenticated product reader. All other activity parsing stays strict.
No router source, backend authority, harness labels or browser assertions changed.
Focused GREEN42; grouped9-file243 tests; scoped lint and full typecheck passed.

Frozen incremental patch99c08abc8d5efa8c63a1740f9a4ef2826aa287d9631652b2e59def9c7af87dc5
was root hash/reverse-checked. Reviewer /root/candidate_navigation_review returned
spec APPROVED and quality APPROVED, no Critical/Important findings. It checked
actual reader/client scope wiring and real shell/decoder use, not fixture-only
mock routing. Review limitations: synthetic history/remount is not actual browser
history/reload or backend authorization proof.

Minor deferred: new positive shell cases do not explicitly assert
X-Zasp-Expected-Scope on detail GET/remount. The reviewer verified unchanged
provider/client wiring supplies it. This is a nonblocking test-strengthening
suggestion, retained for final review; it was not silently discarded.

## Candidate transfer and fresh gates

Exact resulting blobs:
- app/domain/activity-links.ts:9fd031e3d6af32ae1d9dc375bb46e8f23b1b9d0b
- app/domain/activity-links.test.ts:eeaf835792d2bf2f0e92a228966be210ff467e9f
- app/components/ZaspProductionApp.test.tsx:58a61ee1a39aa6f96ff75b29818d4f40f3893245

Root transferred only those reviewed files using apply_patch and verified blobs.
git diff --check passed. Fresh candidate checks:
-95250 full Vitest:2043 passed,0 failed,0 pending, exit0.
 JSON /private/tmp/zasp-schema55-candidate-tests.47H9Oq/ui-navigation-full.json.
-25759 full typecheck followed by full lint: exit0.
-37426 UI build: exit0, Vite8.0.16.
-e5e117 source imports62 files and compiled7 client/8 server chunks: pass.

Fresh sorted dist SHA-list aggregate:
a107e454c1c5afaeeb0567d66f79b0fce738c8dfdcf0fe397984cbbb683d5466.

## Browser result and next integration failure

Original composed Red Team real-SIGTERM case is rerunning in61002 against this
fresh build, with explicit test-name selection, enabled real-runtime opt-in,
offline Go/npm and the temporary no-pull/build Docker guard. Log:
 /private/tmp/zasp-schema55-candidate-tests.47H9Oq/navigation-redteam-signal.log.
Run61002 is now terminal, exit1 after229.93s. The real Support-agent click and
reload passed, followed by all four inventory routes. The log explicitly records
typed inventory deep-link reload acceptance. This closes the reproduced inventory
navigation symptom on the fresh build. Dist aggregate remained unchanged.

The same broad run subsequently failed before its Red Team shutdown checkpoint:
exerciseSecurityAgentAutomaticLifecycle clicked Enable supervised execution while
the UI refused activation pending explicit cost-budget configuration. The broad
mode retains older schema setup; selected modes install newer budget releases.
This new configuration/protocol gap is under read-only diagnosis; budget guards
must not be weakened or the automatic lifecycle skipped to make the test pass.
Normal cleanup completed, no owned zasp containers remained. No successful Red
Team SIGTERM proof is claimed. Log SHA256:
1db2ef6f77a3b77032aac66bc4ac4681828fd858f18544d9d16858d61eec9444.

The other two SIGTERM cases already passed on unchanged runtime sources.
Do not run another broad harness concurrently: this signal test observes roots
created since its start and would count another harness's owned root.
Four-outcome mounted-existing-test browser batch68481 completed successfully on
the same fresh build. The retained log records both actions/autonomies, fail,
comparable fail-to-pass, no baseline, engine error, reload/history, foreign
read/control refusal and positive cancellation controls. All cleanup stages ran.
Log navigation-mounted-existing-test.log in the same directory has SHA256
7df4daf232d2df82f3e898d650fae39b52039559b0296c384c510429a8df1879.
This proves local composition only, not live provider/cloud/IAM/load acceptance.

Read-only diagnosis of61002 identified stale broad fixture configuration:
post-runtime schema upgrade, explicit definition budgets/concurrency, controlled
planner policy and accounted usage, scoped control setup, and budget-aware503
unknown-usage assertions. One coordinated TDD fixture batch is now assigned to
/root/candidate_harness_batch. No production guard change is authorized.

Launch boundary rechecked in security_agent_budget_runtime.go: the production
planner's PlannerBudget returns model/unit with unknown maxima and no cost-policy
version. It intentionally stops paid dispatch until a verified same-model policy
is installed. The test-only controlled-transport wrapper does not supply this
missing production configuration path. Even a passing broad fixture cannot close
the production pricing-policy or live accounting gate. Track that remaining
implementation/authority requirement separately from fixture acceptance.

No original-task promotion, branch commit, push or deployment. Fresh approved
advisory and real release/provider/IAM/load evidence remain open.
