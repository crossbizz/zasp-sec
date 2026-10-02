# The selector now has its own admission owner

Implemented and frozen for independent review. The installed authority, connected worker and shipped deployment-consumer groups passed on final75 pin `1c3bc338060e89fe5d9e44b1449979aab01df775366eaf24b0005efb48fd6ba3`, including the direct SQL catalog-check correction found in self-review. This is not acceptance of all P4C, P4D, or production readiness.

I worked only in the linked `cached-runtime-ship-20260917` checkout at HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. No commit, push, production provisioning, or authoritative ledger edit was made. The controller owns independent review and ledger changes.

## What moved

The actual `securityAgentProcessor.RunOnce` still calls `ScheduleSecurityAgentTriggers` for retained families. Its PostgreSQL compatibility route now detects installed75, checks the compiled pin and registered worker, and calls `zasp_temporal75.retained_schedule`. That copy excludes the specialized test candidates while preserving the original delegated v33 family path. Direct old73 admission is fenced at the parent INSERT boundary too; skipping a Go branch is not the ownership boundary.

The production worker composes a separate selector configuration reconciler and registers `TestSelectorWorkflow` plus `AdmitTestSelector`. It scans definition references, not source occurrences. Each canonical organization/workspace/environment/definition reference has its own Temporal Schedule; the Activity calls75's current admission SQL. It never calls retained `RunOnce`, `ScheduleSecurityAgentTriggers`, or a lease/claim loop.

75 copies the accepted73 source selection and atomic admission bodies. Source eligibility, canonical source-version occurrence, receipts, all-owner capacity, and73 start-command capture remain in that transaction. Automatic authorization changes from the human creator to the current74 scoped service grant. Current74 authorization checks definition/version/history, grant and revocation, audit proof, test/target binding and execution controls. It does not impersonate the inactive creator.

The first connected attempts found a real hole. A75 parent was committed with73 start evidence but still visible to the retained worker until74 takeover. A deterministic registered retained claim changed it to `planning`, version2, attempt1, with a lease.75 now inserts an immutable admission/config-revision marker, with a foreign key to73 admission, in the same admission transaction. Its restrictive parent-row policy hides that committed row immediately. Unmarked historical/manual/other-family parents keep their prior ownership.

The policy has explicit accounting and74 parent-lock read branches. PostgreSQL still requires execution permission while initializing its helper expression. After controller approval, only75's read-only boolean visibility predicate has PUBLIC EXECUTE. Schema usage is not public, and the helper rejects unregistered session principals before looking up any marker. Marked-row access still requires the exact registered API/executor/compensation principal. This is an effective permission change and a review boundary, not a claim of unchanged permissions. No74 tracked grants or policies were changed.

The scoped file inventory is `p4c-selector-evidence/scoped-files.txt`:20 implementation/test/deployment files plus this report. Existing files changed are the migration CLI dispatcher, worker composition/product/runtime, the reused single-test planner fixture's75 dispatch branch, and the API compatibility route. New files contain75 migration/SQL, the registered selector repository, configuration source/processor, orchestration workflow/reconciler, installed/live/CLI tests and the three production deployment files. No staging deployment file changed.

## Configuration means future selection

`deploy/production/temporal-test-selector.config.json` ships revision1, whole-second cadence1, enabled true. `temporal-test-selector.mjs` consumes that file and runs the actual migration CLI's `up-temporal-test-selector`, then `configure-temporal-test-selector`, waiting for each child. It requires an explicit executable and config path; it does not provision any service. Neither the deployment file nor admission derives cadence from worker `PollInterval`.

From the checkout root, the consumer is `node deploy/production/temporal-test-selector.mjs /absolute/path/to/agentsec-migrate deploy/production/temporal-test-selector.config.json`. It uses the CLI's existing registered migration-principal environment and database configuration. An update needs the next revision in the desired JSON. The configuration command reads `ZASP_TEST_SELECTOR_CONFIGURATION`; it is not a worker poll setting.

The installed append-only configuration has schema version1, monotonic revisions1..1,000,000, and integer cadence1..86,400 seconds. Missing, fractional, malformed, stale and disabled configuration fail closed at admission. Exact configuration replay is idempotent. The setting is shared desired selector configuration; Schedule identity and admission remain definition scoped.

Reconciliation takes a definition-scoped session lock before reading current desired configuration. No database transaction crosses a Temporal RPC. It creates missing Schedules, repairs current revisions, pauses disabled definitions/configuration and refuses foreign action/queue/scope or future revisions. Ambiguous writes return an unknown outcome; the durable desired row remains eligible for a later full scan. Schedule overlap skips only wakeups. Product occurrence identity is the source/version, not the Schedule tick.

`enabled=false` stops future selector admissions. It does not cancel admitted runs. Definition disable/delete/version change, grant revocation, target/credential revocation, execution kill switches and explicit run cancellation remain execution authority checks before fresh I/O. Operators must use those controls when they mean to stop admitted work.

## The packet and the old bytes

The pre-edit archive includes the dirty platform source, production/staging deployment files and the two accepted74 handoff documents. It is now durable at `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-selector-evidence/baseline-source.tgz`, SHA256 `c1a8bfc9654249543fd2dd29b606bb89b072f3707e92820ee3864d89eb7e03ae`. `baseline-hashes.txt` and `baseline-status.txt` preserve the initial hashes and dirty checkout status. The working copy was first captured under `/tmp/temporal-selector-baseline.nx0KUP`.

Accepted74 report SHA256: `6bd302061f1a8ae5b0920f18c4c11e1b38f370a67f8bc6fc8338030af0c56ec0`. Accepted fix1 review: `10ee388e5a043798dd13e53f8b3448c593a495aad176acb6bb200c00ae929012`. Installed74 pin stays `24aacf71b65ff37a7a92d4f623542940dd84a7ed4b2867c3ac526e4a20660d8a`.

Only additive75 SQL was edited. A recursive comparison of baseline migration SQL against current SQL reports only the added75 file; every historical migration/fragment is byte-identical. Both accepted74 document hashes still match. `overlay.diff` is relative to the captured dirty overlay, not HEAD. `SOURCE.sha256` covers all21 scoped implementation/test/deployment/report paths. `EVIDENCE.sha256` covers the recoverable baseline, logs, diff and manifests. Controller-owned retirement/ledger files and later read-only briefs are outside this source comparison.

## Commands, including the failed attempts

Commands below ran from `services/platform`, unless a deployment command says otherwise. Logs retain complete output. Shell wrappers printed a log tail after Go returned, so the wrapper's exit0 is not the Go test result; the PASS/FAIL lines below are the evidence.

| Log | Command or boundary | Observed result |
| --- | --- | --- |
| `group-red.log` | `go test ./apiserver -run '^TestTemporalTestSelectorAdmissionPostgres$' -count=1 -v` | FAIL18.922s, case17.91. Missing75 interface. This did not reach later assertions. PG75272 joined. |
| `reconciliation-red-compile.log` | New orchestration test against absent types | Compile failure only. |
| `reconciliation-red.log` | Reconciliation group against unavailable implementation | Behavioral RED0.833s. |
| `compile1.log` | Installed75 compile/admission | FAIL22.261s, case21.25. DDL compiled; initial pin mismatch. PG76106 joined. |
| `admission-green-attempt1.log` | Same installed admission target | FAIL22.104s, case21.27. Checksum normalization defect. PG76302 joined. |
| `compile2.log` | Same target after normalization repair | FAIL23.013s, case22.02. DDL compiled, next pin observed. PG76452 joined. |
| `group-green-attempt2.log` | Orchestration plus installed admission group | Orchestration PASS0.801s. API FAIL32.960s, case32.10: ambiguous `definition_id` in the test's proof JOIN, not a failed canonical invariant. PG76837 joined. |
| `admission-cli-attempt3.log` | Installed admission and CLI dispatch group | Admission PASS35.886s, case34.89. CLI FAIL24.846s, case23.53: missing actual command route. Owned PGs joined. |
| `deploy-red.log` | `node --test deploy/production/temporal-test-selector.test.mjs` from checkout root | Shipped1s descriptor test failed against unavailable helper; invalid/fractional case passed. |
| `deploy-green.log` | Same deployment test | 2 tests passed, 69.17ms. Helper-level proof only at this point. |
| `connected-red.log` | `go test ./apiserver -run '^TestTemporalTestSelectorLivePostgres$' -count=1 -v -timeout=5m` | API FAIL45.764s, case44.37; nested worker15.746s, case14.59. Actual composition had no Schedule. PG78112 joined. |
| `connected-cli-green-attempt1.log` | Connected API plus installed CLI target | CLI PASS34.609s, case33.26. Connected FAIL55.382s, case54.38; nested25.669s, case24.59. Schedule admitted, but a single processor pass did not establish delivery. PG78641 joined. |
| `connected-start-diagnostic.log` | Connected target with boundary diagnostics | FAIL53.752s, case52.70; nested25.347s, case24.28. Queued/version1/attempt0, no lease or74 owner/delivery; organization try-lock unavailable. PG78981 joined. |
| `connected-green-attempt2.log` | Bounded repeated actual processor passes | FAIL96.694s, case95.73; nested68.056s, case67.04. Provider request arrived without74 request/reservation evidence, then delivery stayed pending. PG79219 joined. |
| `retained-claim-red.log` | Installed admission plus actual retained claim before takeover | FAIL32.909s, case31.91. Claimed75 parent `pid_d900347e-3743-4e67-870a-b9b25490aa84`, planning/version2/attempt1. Creator active. PG80109 joined. |
| `marker-compile.log` | Same installed target | FAIL22.945s, case21.95. Marker DDL compiled; pin update required. PG80361 joined. |
| `marker-green.log` | Marker policy with OR read branch | FAIL27.731s, case26.77. Predicate EXECUTE permission42501 during accounting. PG80558 joined. |
| `marker-case-compile.log` | CASE read branch | FAIL23.198s, case22.16. New compiled pin measured. PG80830 joined. |
| `marker-case-green.log` | CASE without helper EXECUTE grant | FAIL28.168s, case27.18. Same expression-initialization permission failure. PG81152 joined. |
| `marker-public-compile.log` | Approved narrow public predicate candidate | FAIL23.144s, case22.15. DDL compiled; stale compiled pin. PG81671 joined. |
| `marker-final-compile.log` | Expanded capacity fixture | FAIL20.747s, case19.70 before75 compile. Raw owner parent INSERT was rejected by73's registered-principal accounting. Removed that setup, not the guard. PG81924 joined. |
| `marker-final-compile2.log` | Real registered manual occupancy fixture | FAIL24.581s, case23.57. DDL compiled; final pin measured. PG82427 joined. |
| `marker-authority-green.log` | `go test ./apiserver -run '^TestTemporalTestSelectorAdmissionPostgres$' -count=1 -v -timeout=4m` | PASS48.010s, case47.00. PG82647 joined. |
| `selector-test-compile.log`, `selector-live-compile.log` | `go test ./agentsec-worker -run '^$' -count=1` | Compile-only passes1.179s and1.210s. Not behavior evidence. |

The last installed group uses real registered callers. It covers missing/invalid/stale/disabled configuration, inactive-creator admission, duplicate wakes, atomic canonical73 command plus75 marker, direct old73 and retained selector exclusion, marked pre-takeover retained claim exclusion, direct mutation denial, unregistered schema/predicate/table denial, real manual occupancy/cancellation, marked occupancy against another source version, actual74 takeover and executor/compensation reads, same-name/same-definition-ID tenants with real74 create/activation, cross-scope admission/API-read refusal, grant revocation and unchanged73/74/75 readiness.

The connected frozen command was `go test ./apiserver ./agentsec-migrate -run '^TestTemporalTestSelector(LivePostgres|InstalledReleasePostgres)$' -count=1 -v -timeout=6m`, log `connected-cli-marker-green.log`. API PASS117.409s, case116.63; nested worker PASS91.607s, case90.62; native adapter PASS8.745s, case8.20. The actual source read revision2 after serialization. The first start was accepted after one actual processor pass, completed through the native child and parent receipt, and had exactly one provider and native call. Disabling selection after admission did not cancel it. Revoking the second admitted run's grant at committed preparation blocked fresh provider/native I/O; a later actual selector Activity also refused admission. The revoked execution workflow returned nil after its safe handling, so this is not a claim that it returned a workflow error. First worker Close succeeded in2.811583ms. PG82880 joined normally.

The same command's CLI case PASS48.314s, case47.32, with its owned PostgreSQL joined. It built the real CLI, invoked the shipped Node consumer twice, verified a single installed1s revision, and rejected missing/fractional configuration through the executable. Both consumer child commands joined.

Initial hash capture used the wrong relative path and produced an empty `connected-final-before.sha256`. I corrected it from the checkout root immediately after launch; `connected-final-start.sha256` has2047 platform files. No platform source edits occurred between launch and that capture. Start and after manifests compare equal, both SHA256 `4f569f83e77899e56833f7f0a4f6bfed1e10dc199f614070b4df44251b21474a`.

Self-review then found that the separately granted75 retained SQL entry inherited70/73 readiness while only its Go caller checked75. Specialized INSERT ownership still denied old-worker admission, but direct retained SQL could delegate other families despite75 drift. The controller required a75 fail-closed wrapper around the private copied body. The passing connected/CLI result above remains pre-correction evidence.

`retained-catalog-red.log` records the grouped reproduction: API FAIL50.705s, case49.68, PG83787 joined. The application route returned unavailable after controlled75 ACL drift, but direct `zasp_temporal75.retained_schedule` returned `{"created":0}` without an error. This was an authority failure even though no specialized parent was created. The wrapper now calls the registered worker guard and current75 catalog check before entering the private body. Other-family delegation is unchanged.

The wrapper's independent compile in `retained-catalog-compile.log` measured final75 pin `1c3bc338060e89fe5d9e44b1449979aab01df775366eaf24b0005efb48fd6ba3`; the expected stale-pin attempt failed26.057s, case25.07, PG84289 joined. After binding that pin, the same installed command passed54.135s, case53.12, PG84477 joined (`retained-catalog-green.log`). It includes the new direct-drift rejection and the earlier ownership/capacity/tenant assertions. `deploy-final-green.log` records2 focused Node tests passed in54.553ms.

Final affected connected/CLI verification used the same complete command, with platform source frozen before launch. `final-connected-cli-green.log`: API PASS138.418s, case137.66; nested worker PASS107.059s, case105.92; native adapter PASS8.994s, case8.23. PG84739 joined normally. It again proved actual scheduled75 admission through73/74 native child and parent settlement, creator inactive before admission, current desired revision after the held SQL lock, selector-disable semantics, grant revocation before fresh I/O and refused later admission. First worker Close succeeded in169.622875ms. Actual deployment-consumer/CLI PASS49.593s, case48.57, with owned PostgreSQL normal join. Process inspection after completion found no remaining Go/test children.

`final-connected-before.sha256` and `final-connected-after.sha256` compare equal for2047 platform files. Each manifest's SHA256 is `f8b06d6f503309088c060d88610a898eb5a834f022cd2945df5d6e2bf7b3e41a`. No source edits followed this run.

## What the local transport cannot prove

PostgreSQL runs in owned disposable processes with actual registered principals and the installed migration chain. Local Temporal is the existing service at `127.0.0.1:7233`; each connected run has an isolated namespace. The fixture deletes its own Schedule. It does not provision a shared production runtime.

The worker uses the actual composition, Schedule, admission Activity, durable73 relay and74 execution chain. Provider HTTP and native adapters are controlled fixtures with exact request/credential/reservation checks. The OpenFGA endpoint is a controlled readiness response only; product authority is not stubbed. Artifact storage is local. A prepared-input barrier borrows the real store solely to hold the second admitted run before provider I/O while its actual grant is revoked.

The new capacity cases use real manual legacy occupancy/cancellation and marked75 pending occupancy against a fresh source version. They do not repeat every older execution owner's accepted73 matrix. Other-family delegation is preserved in the copied source and unmarked manual claims are exercised, but this is not a new execution proof for all retained families.

Per-operation latency and shutdown bounds remain gates. End-to-end case time is not per-operation latency. A later successful Close retry would not prove first-attempt shutdown. No claim about production FGA, vendor provider behavior, real credentials, real remote artifact storage, or performance acceptance is made.

The measured successful Close is after completed/refused workflow work. It does not close the earlier74 in-flight shutdown gate.75 uses the existing full catalog-readiness checks, whose cost still needs per-operation measurement. Grant revocation blocks admission and fresh execution authority, but does not itself pause the desired Schedule: that Schedule can keep producing refused, bounded-retry Activities until the definition or selector setting is disabled. Those operational costs need review; they were not hidden by accepting a permissive grant or resetting a deadline.

## The work still outside this selector

Retained v33/non-test families still own their periodic selection and execution until their explicit P9 replacement.75's specialized INSERT and visibility guards prevent the old worker from owning newly selected test runs; they do not retire every retained family. The controller owns the authoritative retirement rows.

These are report-only retirement entries for that ledger:

| Concrete retained surface | Current owner and limit | Replacement gate |
| --- | --- | --- |
| `securityAgentProcessor.RunOnce` -> `ScheduleSecurityAgentTriggers` ->75 retained wrapper/body -> original v33 delegated selector | Registered retained worker; specialized test candidates are excluded and their INSERTs denied | Migrate each remaining periodic family with its actual admission/execution proof before removing this caller. |
| Retained claim/lease processors reached by the same worker composition | Unmarked historical/manual/other-family rows only;75 markers and existing74 owners fence new selected test runs | Drain or explicitly retain historical owners, then prove equivalent family behavior and cleanup/accounting before retiring those claims. |
|75 private copies of73 admission/selection,70 compatibility readiness, accepted55 source contracts | Installed compatibility dependencies, not a second selector owner | Replace pinned predecessors only with equivalent product occurrence, eligibility, capacity, audit and catalog proof. Preserve historical SQL and receipts. |
|74 pending/accept-start application relay over73 committed start commands | Registered Temporal executor; no source scan, no run lease | Any later delivery replacement must preserve durable acceptance, replay, scope and unknown-outcome handling. This task does not remove the relay. |

75 configuration and immutable admission markers are product facts. They are not lease engines scheduled for deletion.

Source-specific manual/resource/event/webhook/approval trigger migration is still P4C work. Manual admission remains its accepted65/66 route, with74 takeover where supported. Required SQS, event and DLQ paths were not removed or replaced. Temporary policy, attack-lab, export, webhook and the remaining action families need their P4D work and retirement evidence. This slice is not their completion.

I used Superpowers grouped TDD, then its debugging process for the claim race and predicate-permission failure. The verification skill kept failed attempts and fresh results separate. The controller owns the single independent task review of this frozen packet; no nested reviewer was spawned.
