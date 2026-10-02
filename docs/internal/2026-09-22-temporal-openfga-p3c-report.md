# P3C: the worker now consumes product runs

FIX1 READY FOR SCOPED RE-REVIEW. The original Important1 finding was valid: initial local checks constructed the SDK worker below the shipped entry point, whose legacy readiness rejected installed69. The frozen fix1 affected group now passes the shared shipped constructor, real readiness, manual/Temporal consumption and shutdown on installed69/70/71. The fix1 section records the exact scope and remaining gates; earlier lower-level results alone did not prove this composition.

Worktree: `.worktrees/cached-runtime-ship-20260917`, unchanged HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. I preserved the existing dirty overlay. No commit, push, production activation, shared-database reset, principal provisioning outside disposable fixtures, or ledger edit occurred.

The approved P3C brief, parent P3 brief and integration notes define this packet. I used Superpowers executing-plans, grouped test-driven-development, systematic-debugging and verification-before-completion, with the implementer self-review/report contract. Those checks caught two actual integration gaps: the runtime login couldn't execute private 68 principal readiness, and reserved-test stop rejected a parent already stopped by the workflow. Both fixes are confined to additive 69. Historical 68 stays exact.

## What runs

`buildWorkerRuntime` still creates the legacy worker/outbox connection. With runtime services enabled in `security-agent` mode it now creates separate executor and compensation pools, builds the real planner, signed-policy adapter, artifact authority and linked runner, checks installed 69 and exact 68 registered session principals, and starts a registered SDK worker on the configured queue. The worker registers `SecurityAgentWorkflow` and six explicit Activities. Exported lifecycle methods aren't registered as Activities.

The outbox remains the committed-command relay. It doesn't execute the plan or authorize a signal. `retainedTemporalEngine` first validates the immutable65 start or committed decision through69; a terminal run with verified cleanup acknowledges a repeated start without consulting expired Temporal history. Valid late decisions for a terminal run have a retained outcome, including when the engine is unavailable. A mismatched decision is refused before RPC.

Inside the workflow, a fresh product observation chooses planning, approval wait, policy application, verified advancement, linked test, or terminal cleanup. Signals only wake another observation, their bodies aren't authority. Waiting steps whose current dependency authority is lost request compensation immediately. The SDK test environment covers this code's decisions, including malformed hints, missing approval, stale state, unverified predecessors and disconnected cancellation. It doesn't retest the vendor's scheduler.

`RunTemporalPlanning` and `RunTemporalTest` are the accepted reusable executors. Application and cleanup use the accepted repository methods, actual Ed25519 signing, source/delivery readback and signed acknowledgement. Only verified receipts advance the successor. No lease token or Activity attempt number is an effect identity.

There is one narrow change to the accepted Go planner: already-sent known responses reconcile through a detached 10-second context after cancellation. If stop already preserved an unknown result, the existing late-usage operation records the known response against the original request, credential and reservation. It never reloads, resends, admits or rewrites terminal evidence. The owned cancellation case deactivates the requester and proves one charge of 30,000 nano-credits with no plan admission.

## Authority stays in SQL

Additive69 exposes `inspect`, `inspect_message`, boolean-only `principal_ready`, and compensation-only `stop`. All calls bind scope, original65 start event/digest/version and immutable66 Temporal ownership.68 still validates current requester, approvals, versions, budgets, journals and product receipts. No permissive OpenFGA replacement was added. P7 remains open.

The controller approved two private, exact-source copies:68 `progress_transition`, changing only the forced worker-stop predicate, and68 `test_stop`, extending only its reserved-stop gate to an authenticated69 stop bound to the same terminal parent and immutable start. Extraction requires exactly one matching substitution.69 fingerprints both copies and their saved predecessor definitions. Runtime roles cannot invoke the private functions or insert stop evidence.

`stop` serializes on the accepted budget/run lock order. Its stable identity is the product scope/run, never the SDK attempt. It stores the service cause (`workflow_cancelled`, `workflow_deadline`, `workflow_failed`) and executes unresolved test stop in the same transaction. A rejected child stop rolls everything back. Existing API cancellation and its replay remain intact. A stopped parent isn't a cleanup receipt; started work keeps unknown usage, unsent work can release its reservation, and late known usage remains admissible without another send.

69 has its own real CLI route: `agentsec-migrate up-temporal-workflow`. It requires the exact installed68 predecessor on the registered61 release lineage, uses migration locks, registers the compiled checksum/pin, and checks the exact migration session on return. The actual owned API/worker fixtures execute that binary route, not just the Go runner.

Independent fresh-source69 catalog pin:

`5c5952d665d582373bf63d010b5d9f6d85cdf197e8a8b5f37554058e146b960d`

Accepted 68 pin remains `437c678da9969a5935fe7efaa27f593fc58eaeac4e74ff434a5ed44eab2b75eb`. All 150 historical SQL files through 67 and every 68 source byte are unchanged against this packet's pre-edit baseline.

## Cleanup and shutdown

The cleanup consumer renews expired markers with the current configured key and the original source digest, then consumes expiry or changed-composition replacement deliveries through the same effect. Tests remove the original signing key from the current trust set. The original source/signature/digest/identity, prior signed bundles and effect identity stay exact; only documented target projection fields `state` and `verified_at` change, and the tests separately require verified state and a non-null verification time.

Workflow Activities have a 20-minute start-to-close timeout, one-hour schedule-to-close bound, 30-second heartbeat timeout and five attempts. Long work heartbeats every 10 seconds without details. Disconnected cleanup has a two-hour schedule bound and 12 attempts. The workflow's product-wait deadline is 24 hours; existing SQL budget deadlines still gate effects. Validation errors are non-retryable, infrastructure/CAS failures have finite retries, and errors sent to Temporal contain fixed redacted messages. Cancellation is preserved as cancellation.

Close marks readiness unavailable and stops new Activity admission, asks the SDK worker to stop, and joins active work (including compensation) before closing owned pools/planner/cloud clients. Only then does outer shutdown close legacy/outbox and runtime-service clients. A bounded drain failure retains those resources for a later Close, it doesn't pretend the borrowers joined. Focused race checks cover the new mutex/atomic/once lifecycle code.

## What the local integration proves

The local server reports Temporal 1.32.0 on `127.0.0.1:7233`. Each invocation creates a unique `p3c-owned-<UnixNano>` namespace and queue with 24-hour workflow retention. Namespace handles are in the logs. Disposable PostgreSQL instances are joined after each fixture; existing local namespaces weren't deleted. Diagnostic failed runs can remain in those isolated namespaces with no polling worker, they aren't production tasks.

The full route uses actual HTTP activation/admission and typed approvals, real SQL outbox delivery, the registered local SDK worker, the real planner transport/usage parser, real signed policy repository, actual linked invocation journal and red-team HTTPS adapter, verified cleanup, then typed HTTP product readback. It checks exactly one planner request and one runner call on success. Raw SDK cancellation after policy application and after test reservation each produces a durable worker stop and verified signed cleanup, with zero runner calls.

Boundary labels matter. Browser identity/freshness, TLS planner response, artifact storage driver and runner subprocess output are controlled local fixtures. The linked adapter still exercises an actual TLS request and persisted one-call journal. This isn't real Stytch, S3/KMS, OpenRouter or Promptfoo deployment evidence. Production constructors retain their credential, endpoint, artifact and signing checks.

Actual workflow history is read back and checked: workflow/Activity inputs are only the exact scoped immutable StartRequest (plus cleanup reason), observation results are a redacted phase, and committed decision signals contain scoped IDs. Bodies, tokens, source envelopes, provider responses and artifacts aren't returned into history. These checks don't claim protection against a separate unauthorized caller writing arbitrary signal payloads directly to the Temporal service; deployment must restrict that service.

## Evidence, including failed diagnostics

All logs and hashes are under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`, with prefix `p3c-`. Commands below run from `services/platform`; each uses `-count=1` and records complete output. A filename containing `green` or `red` isn't a result.

| Group and exact selector | RED or diagnostic result | Development result before final freeze |
| --- | --- | --- |
| `go test ./orchestration -run 'TestSecurityAgentWorkflow' -count=1 -v` | `p3c-workflow-red.log`: missing workflow/Activity symbols; `p3c-workflow-green.log` is actually FAIL on noncanonical fixture IDs | `p3c-workflow-development.log`: PASS0.814s |
| `go test ./orchestration -run 'TestActivities\|TestActivity' -count=1 -v` | `p3c-lifecycle-red.log`: missing Close | `p3c-lifecycle-development.log`: PASS0.833s |
| `go test ./apiserver -run '^TestTemporalWorkflow(Catalog\|RetainedStartAndStop)Postgres$' -count=1 -v` | `p3c-authority-red.log`: missing69; catalog compiler logs preserve intermediate pin failures | `p3c-authority-development.log`: PASS29.539s on its then-current source; superseded by final checks |
| `go test ./agentsec-worker -run '^TestTemporalProductRefusesUnboundStart$' -count=1 -v` | `p3c-product-red.log`: missing adapter | `p3c-product-development2.log`: PASS1.203s; only this one test |
| `go test ./agentsec-worker -run '^TestTemporalRuntimeRefusesIncompleteConfiguration$' -count=1 -v` | `p3c-runtime-red.log`: missing runtime; initial implementation then failed compilation on interface Close | `p3c-runtime-development2.log`: PASS1.149s; only this selector |
| `go test ./apiserver -run '^TestTemporalWorkflowLatePlannerCancellationPostgres$' -count=1 -v` | `p3c-late-usage-red.log`: FAIL24.019s cancelled context; development FAIL22.788s exposed terminal result conflict | `p3c-late-usage-development2.log`: PASS24.977s |
| `go test ./apiserver -run '^TestTemporalWorkflowReservedTestStopPostgres$' -count=1 -v` | `p3c-reserved-stop-diagnostic.log`: FAIL29.991s, reserved gate after parent stop | Included in `p3c-integration-development6.log`: PASS29.94s |
| `go test ./agentsec-worker -run '^TestTemporalProductRevokedWaitDoesNotRetainPolicy$' -count=1 -v` | `p3c-revoked-wait-red.log`: FAIL1.058s retained waiting approval | `p3c-final-preflight-unit.log`: PASS |
| `go test ./agentsec-worker -run '^TestTemporalProductClassifiesPermanentValidation$' -count=1` | `p3c-classification-red.log`: missing classifier | `p3c-final-preflight-unit.log`: PASS |
| `go test ./apiserver -run '^TestTemporalWorkflow(StopSendFencing\|ActualReservedCancellation)Postgres$' -count=1 -v` | Earlier fencing diagnostic rejected NULL in fixture lock observation; changed to COALESCE, joined callers on failure | `p3c-fencing-cancel-development.log`: PASS96.909s, real reserved SDK cancellation and both fencing orders |

Actual HTTP integration development logs1-5 retain the failed authentication freshness, wrong activation/body decoder fixtures, private principal-readiness ACL and artifact-interface/reserved-stop failures. None is called a pass. Development5 ended at122.250s with the owned subprocess killed by its fixture deadline, not a harmless observation timeout. The fixed real worker/cancellation/reserved-stop group is `p3c-integration-development6.log`, PASS123.821s.

The first cleanup consumer diagnostic passed its nested worker but failed the parent immutable comparison because it included mutable target projection fields. The corrected parent comparison excludes only those two fields. `p3c-cleanup-consumer-development.log` then passed rotated-source and changed-replacement cases, while its expired fixture correctly rejected a delivery expiring before a still-valid five-minute source. The fixed aged-source/real-expiry case is `p3c-cleanup-expired-development.log`, PASS103.755s. Final checks rerun all three together.

The retention/rollback preflight initially failed to compile because the public ordered repository doesn't expose legacy cancellation. The fixture now uses the actual cancellation repository, preserving its authority checks. `p3c-retention-rollback-development2.log` passed in 101.562s, covering the actual worker with history/retention assertions, API cancel coexistence and private/rollback stop checks.

### Frozen final checks

The first freeze covered 1,936 files, SHA256 `2dce9e3a24c29c34e11f768d8c9955d3bbb57a057c2be71f665bf22e2f0ea32f`. I then found a production startup bug during self-review: the cloud constructor's new session string wasn't in the existing approved session list. `p3c-runtime-cloud-red.log` records the exact constructor-config check failing (1.032s). The fix reuses `zasp-red-team-worker` for the already configured red-team role; it doesn't widen the validator or grant another authority.

The controller approved retaining the running PostgreSQL verification for unchanged SQL/product consumers and rerunning only affected runtime/config/race checks. The capture script enforces that exactly `security_agent_temporal_runtime.go` and its test changed between freezes, with every other file byte-identical. Both snapshots remain in evidence: `p3c-frozen-source-before-runtime-fix.json` and final `p3c-frozen-source.json` (SHA256 `0eed69395fedf3f5b3561aa7a1ba1c8e77c79a20dbd30be58d1f04b002497d7a`). The final local worker flows also compile the revised constructor source.

These are the exact grouped commands. All processes reached exit 0 and were joined. Logs contain all subtest results.

Effective toolchain: `/opt/homebrew/bin/go`, Go 1.25.6 on darwin/arm64, `GOTOOLCHAIN=auto`, empty `GOFLAGS`, recorded in `p3c-final-toolchain.log`. The final commands here did not use `-vet=off`. The preceding P3B report's explicit vet workaround is separate evidence; this packet doesn't claim that its known unrelated vet issue is fixed, nor that standalone vet or the required release Go 1.25.13/advisory gates passed.

```sh
go test ./apiserver -run '^TestTemporalWorkflow.*Postgres$|^TestTemporalExecutorPlanningTransportFaultsPostgres$/(lost_result|unknown)$' -count=1 -v

go test ./orchestration ./agentsec-worker ./agentsec-migrate -run '^(TestSecurityAgentWorkflow|TestActivities|TestActivity|TestTemporalProduct|TestTemporalRuntime|TestSecurityAgentWorkerModeRequiresV32PlannerAuthority|TestLoadWorkerRuntimeConfigRequiresExactModeAuthority|TestComposeWorkerRuntimeMountsOnlyProductionReadyModes|TestAuditExportRuntimeDatabaseCloseRetainsUnjoinedBorrowers|TestServeWorkerRuntimeBoundsShutdownWhenProcessorIgnoresCancellation|TestServeWorkerRuntimeSurfacesDependencyDrainFailure|TestRunReleaseMigrationRejectsAmbiguousInputsAndStopsOnFailure)' -count=1 -v

go test ./agentsec-worker -run '^(TestTemporalRuntime|TestSecurityAgentWorkerModeRequiresV32PlannerAuthority|TestLoadWorkerRuntimeConfigRequiresExactModeAuthority|TestComposeWorkerRuntimeMountsOnlyProductionReadyModes|TestAuditExportRuntimeDatabaseCloseRetainsUnjoinedBorrowers|TestServeWorkerRuntimeBoundsShutdownWhenProcessorIgnoresCancellation|TestServeWorkerRuntimeSurfacesDependencyDrainFailure)' -count=1 -v

go test -race ./orchestration ./agentsec-worker -run '^(TestActivitiesDrainRetainsActiveCompensation|TestTemporalRuntimeConcurrentCloseJoinsWorker)$' -count=1 -v
```

| Frozen evidence | Terminal result |
| --- | --- |
| `p3c-final-postgres.log` | PASS547.935s, 12 top-level tests, no failures/skips, all 16 owned PostgreSQL instances joined |
| `p3c-final-unit-runtime-cli.log` | PASS: orchestration0.631s, worker2.503s, migration CLI0.623s |
| `p3c-final-runtime-fix.log`, after revised freeze | PASS2.076s, including approved cloud config and rejection of an ambient token path |
| `p3c-final-race.log`, initial freeze | PASS: orchestration1.785s, worker2.306s |
| `p3c-final-runtime-fix-race.log`, revised freeze | PASS: orchestration1.503s, worker2.319s |

The unchanged 1233-second P3B executor suite wasn't repeated. Only `lost_result` and `unknown` transport cases supplement the new planner cancellation case. The initial runtime group isn't used as evidence that the rejected cloud session could start production.

Final SQL timings: cleanup consumers 188.97s (all three), affected planner transport 44.39s, stop/send fencing 37.96s, actual worker 51.03s, applied SDK cancellation 40.76s, reserved SDK cancellation 55.78s, late known planning cancellation 23.84s, API cancellation coexistence 17.71s, applied stop 27.42s, reserved stop/private ACL/rollback 29.40s, independent catalog 12.00s, retained start/principals/stop 17.83s. Raw SDK cancellation checks and the successful flow each inspect real history and verify retained commands without engine RPCs after terminal cleanup.

The generated `p3c-hashes.json` has before/after hashes for 23 changed source files, all log hashes, report hash, both freeze hashes and scoped diff hash. The capture checks 150 unchanged historical SQL files and all 9 accepted 68 SQL files. `git apply --check --reverse --whitespace=error p3c-scoped.diff` checks the packet's diff against the actual overlay. No HEAD-wide diff is substituted.

Changed source paths, all relative to `services/platform/`:

```text
agentsec-migrate/bootstrap_release.go
agentsec-migrate/main.go
agentsec-worker/production_runtime.go
agentsec-worker/runtime_config.go
agentsec-worker/security_agent_temporal_cleanup_integration_test.go
agentsec-worker/security_agent_temporal_planning.go
agentsec-worker/security_agent_temporal_planning_test.go
agentsec-worker/security_agent_temporal_product.go
agentsec-worker/security_agent_temporal_product_test.go
agentsec-worker/security_agent_temporal_runtime.go
agentsec-worker/security_agent_temporal_runtime_test.go
agentsec-worker/security_agent_temporal_workflow_integration_test.go
apiserver/security_agent_temporal_cleanup_consumer_postgres_test.go
apiserver/security_agent_temporal_stop_fencing_postgres_test.go
apiserver/security_agent_temporal_worker_postgres_test.go
apiserver/security_agent_temporal_workflow_postgres_test.go
migrations/production_temporal_workflow.go
migrations/sql/0069_production_temporal_workflow.up.sql
orchestration/activities.go
orchestration/activities_test.go
orchestration/cleanup.go
orchestration/security_agent_workflow.go
orchestration/security_agent_workflow_test.go
```

The report and `p3c-*` evidence artifacts are the only other packet outputs. The code-review skill's independent review step goes to the controller, following this packet's explicit no-subagents instruction. It isn't replaced by my self-review.

## Deployment inputs, still not activated

Use separate secret references for `ZASP_POSTGRES_DSN` (existing legacy/outbox login), `ZASP_TEMPORAL_EXECUTOR_POSTGRES_DSN` (registered exact executor login), and `ZASP_TEMPORAL_COMPENSATION_POSTGRES_DSN` (registered exact compensation login). For example, deployment secret keys named `legacy-outbox-dsn`, `temporal-executor-dsn`, and `temporal-compensation-dsn`. These are proposed references, not created secrets. Never place credential values in manifests, command arguments, Temporal inputs or this report. No fallback or SET ROLE path exists.

An operator must install the reviewed predecessor chain, provision the distinct logins through the approved administrative process, register them through68 `register_principals`, then run the shipped `up-temporal-workflow` route as the exact migration login. Both runtime sessions must pass69 boolean readiness for their own role and refuse the other role.69 doesn't provision shared logins. Do not switch admission routes or turn on this worker until the remaining acceptance gates pass.

`ZASP_TEMPORAL_PRICING_BINDINGS_FILE` is an absolute mounted JSON path, at most64KiB and1-100 unique scoped records. Each record carries `organization_id`, `workspace_id`, `environment_id`, `account_profile`, `credential_reference`, `policy_id`, `policy_version`, `policy_digest`, `account_id`, `account_version`. All pins must match administrator-approved pricing and the configured planner; these fields aren't credentials. A suggested ConfigMap key is `temporal-pricing-bindings.json`, mounted read-only at `/var/run/config/zasp-temporal/pricing-bindings.json`.

Existing planner configuration remains required: endpoint, model, policy version, bounded timeout/max tokens and `ZASP_SECURITY_AGENT_PLANNER_TOKEN_FILE` mounted from the existing planner secret. `ZASP_GATEWAY_SIGNING_PRIVATE_KEY_FILE` must be the approved production Ed25519 secret file with matching `ZASP_GATEWAY_SIGNING_KEY_ID`; the Activity rereads it for compensation recovery. Production-key refusal stays intact. Key-ID rotation requires corresponding configuration rollout; replacing a file doesn't change the configured ID.

The runner/artifact path needs the configured red-team role/web-identity token, runner image, target endpoint/token/CA and timeout, AWS region, evidence bucket/owner/KMS key, and the approved Node/runner/Promptfoo paths in the worker image. Suggested secret references are the existing planner token, gateway signer and red-team target token mounts, never inline material. Runtime readiness checks actual role/artifact authority, it doesn't infer it from a nonempty environment variable.

The existing runtime-services gate still requires enabled status, environment, Temporal address/namespace/distinct task queues and TLS files, plus OpenFGA endpoint/store/model/token/CA configuration. Connection readiness isn't active FGA enforcement. `ZASP_SHUTDOWN_TIMEOUT` is1s-1m for this worker and batch concurrency is1-64; incomplete configuration refuses startup. Legacy/manual execution and its ownership fences remain available under the accepted preceding packets.

## Self-review and remaining gates

I checked scope/start binding at every Activity boundary, bounded cancellation recovery, unknown usage, stable effect identity, closed-run retention, history payloads, source/delivery signatures, exact principal entry, private-copy ACLs, transaction rollback and resource-close ordering. The final hash capture enumerates all changed paths against the pre-edit overlay, not HEAD-wide changes. Self-review found and fixed the rejected cloud-session configuration before handoff; no source changed after the revised freeze.

P7 active OpenFGA enforcement, P8 completed-candidate acceptance and P10 live/deployed Stytch/provider/signing/runner evidence remain required. No production readiness claim. Full production constructor execution against deployed AWS and credentials is part of those gates; this packet proves the real local worker composition with controlled external dependencies. The final release Go 1.25.13 and full advisory gates also remain open.

Finite cleanup retry exhaustion leaves product cleanup pending/unknown and the workflow failed; it never marks success. Deployment must monitor that state and use a reviewed recovery procedure. This packet doesn't install a second scheduler or silently resurrect a closed workflow. Independent controller review and the final candidate build/typecheck/import/`npm run verify` and live integration batch still precede publication.

## Fix round1: the shipped entry point

Important1 was correct: "the shipped constructor cannot reach the new worker on its required installation". `buildWorkerRuntime` reached `NewSecurityAgentWorkerRepository` and its historical public readiness before the SDK consumer. Initial P3C's lower-level SDK tests missed this. The original completed-runtime claim is superseded by this section; independent fix review is still required.

The controller approved two bounded additive authorities after concrete dependency inventories.70 has22 existing operation roots,58 exact source-verified private copies and five private guard adapters.71 has15 role-separated linked-test/reconciliation roots,22 private signatures and two guard adapters, plus the separately approved16th read-only adapter classifier. Historical public readiness, the150 SQL files through67 and all nine accepted68 SQL files stay unchanged.69 is unchanged by fix1. Neither63 nor64 is reactivated.

The inventories are `p3c-fix1-surface.md` and `p3c-fix1-linked-test-surface.md` in the packet directory. They list every copied signature, indirect table/trigger boundary, role and retirement obligation. Source extraction checks the exact full signature, owner, ACL and SHA256 of `pg_get_functiondef`. The two invocation-complete overloads have separate full identities and source hashes; only the14-argument wrapper is exposed, and the real manual journal exercised its12-argument private core. All copies keep their source definer/invoker mode and trusted search path.

Independent catalog pins:

```text
70 d15a4b32b9b528fc3913db76097f18d93c74461b31758a19c87142b972f03c99
71 1bfbd14f6f2a23fd3dd2be171473f646cc3c5b0b4b0b36de4dd2f12cec5f07b3
```

The real CLI routes are `up-temporal-compatibility` then `up-temporal-legacy-tests`, after `up-temporal-workflow`. Both use the exact registered migration session, predecessor checks, schema locks, transaction, registration and independent catalog verification. An early CLI test failed because the registered runner didn't forward the new command; that forwarding is now wired and tested through the binary. No historical guard was relaxed to fix it.

`PostgresJSONDatabase` probes the installed authority before the old repository constructor. Absent extensions preserve the old path; present but invalid extensions refuse. Closed statement maps select only the existing22 worker operations and the15 role-separated linked operations. Manual scope and ownership checks remain in SQL. The existing66 restrictive RLS and lease trigger exclude Temporal-owned work from legacy collection, claim and mutation paths.

The linked adapter's persisted classifier chooses `legacy_single_test` or `retained_ordered`, once per resolve/start/complete operation. Each selected operation checks its own current authority. No fallback follows denial, unknown JSON or changed identity. `/v1/effects/evaluate` keeps68 authority; the retained61 linked route remains available. The red-team worker rejects a legacy classification when the installed mode has only linked authority, avoiding an absent standalone repository.

Manual execution also exposed an older pricing gap: the base prepared planner deliberately returned an unknown ceiling. The approved Go-only `installedLegacyPricedPlanner` reuses the existing strict pricing bindings file and registered-worker request-bound pricing lookup. It binds exact body, model/config, scope, credential and the full approved bound, then rechecks current approval before one-shot dispatch. Missing, ambiguous, stale, revoked or malformed approval cannot send. Base deployments keep their original behavior. No new SQL grant, default ceiling or caller-selected maximum was added.

### What actually ran together

`TestTemporalWorkflowShippedCoexistencePostgres` installs69/70/71 through the real CLI on an owned database. It admits a new manual run through the existing typed API repository after installation, before the fixture's one-way Temporal scope activation; idempotent replay returns that same manual owner. It then activates the scope once and admits the ordered run through the actual authenticated HTTP handler. Both execute on the same final installation. There is no authority toggle during consumption.

The fixture calls the shared `buildWorkerRuntimeWithIO` implementation used by shipped `buildWorkerRuntime`. Only external planner/cloud/storage transports vary. Database pools, repository constructors, readiness, runtime-service connections, outbox relay, legacy processor, SDK registration and shutdown are real. The linked child and parent reconciliation use the real composed worker entries, actual runner, actual routed HTTPS invocation journal, artifact write/readback and typed SQL receipts. The controlled queue reads the exact committed outbox payload; it doesn't synthesize child completion or parent settlement and doesn't prove deployed SQS publishing.

Exactly two planner sends and two runner calls are required. The ordered run is remediated with signed cleanup and typed HTTP receipt. The manual `run_test` action succeeds, its child is complete at attempt1, one completed invocation is retained, and input/output artifact references plus immutable after-proof and digest-backed reconciliation are checked. Its terminal result is `needs_human/test_baseline_unavailable`, not remediation. This is the supported no-baseline outcome already asserted by `security_agent_existing_test_reconcile_lease_postgres_test.go:270`. The final typed API read preserves that result and manual identity.

Development3's third planner call wasn't a resend: the cloned manual definition retained an automatic finding trigger, so the existing scheduler admitted a separate automatic run. The fixture now gives that definition a valid attack-path trigger without matching evidence. Production scheduler behavior and the2/2 assertion are unchanged. Persisted per-run trigger, attempt, definition and settlement decisions are logged by the fixture.

### REDs and intermediate checks, kept intact

All paths below are under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`. Diagnostic failures aren't passing evidence.

| Evidence | Exact scope and result |
|---|---|
| `p3c-fix1-installed-red.log` | FAIL14.080s, missing optional diagnostic inventory path. Setup failure only. |
| `p3c-fix1-installed-red2.log` | FAIL14.220s, actual installed69 repository constructor refusal. |
| `p3c-fix1-constructor-development2.log` | PASS20.021s, `TestTemporalInstalledWorkerRepositoryPostgres`: real CLI70 and repository readiness, not process execution. |
| `p3c-fix1-linked-red.log` | FAIL16.579s, actual registered linked constructor refusal. |
| `p3c-fix1-linked-development.log` | PASS37.366s, linked constructor/catalog before the later classifier pin. Superseded by final affected catalog checks. |
| `p3c-fix1-linked-runtime-development.log` | PASS1.706s, selector `^TestRedTeamRouting\|^TestExistingTestClient`. Unit composition only. |
| `p3c-fix1-journal-router-green.log`, `p3c-fix1-adapter-routing-green.log` | Closed router unit checks PASS2.504s; production adapter selection group PASS5.832s. Actual manual journal coverage is in the coexistence fixture. |
| `p3c-fix1-shipped-integration-development2.log` | FAIL69.072s, counts1/1, manual path had not sent. |
| `p3c-fix1-manual-diagnostic2.log` | FAIL72.846s, manual `budget_usage_unknown`; led to the approved pricing reuse adapter. |
| `p3c-fix1-shipped-integration-development3.log` | FAIL83.376s, counts3/2 with a separate automatic admission; not a passing group. |
| `p3c-fix1-shipped-integration-development4.log` | PASS73.798s, shipped composition, exact2/2, real manual journal/artifact/terminal proof and ordered HTTP receipt; owned DB joined. |
| `p3c-fix1-legacy-pricing-development2.log` | PASS2.270s,15 binding/rotation/revocation/unknown/cancellation/duplicate cases. Stub-backed authority, actual no-send assertions; not provider deployment proof. |
| `p3c-fix1-router-defensive-red.log`, `p3c-fix1-router-defensive-green.log` | FAIL1.300s then PASS1.762s, installed linked mode rejects absent standalone authority and makes no mutation. |
| `p3c-fix1-negative-development.log` | PASS53.241s, independent70/71 pins, source/ACL mismatch refusal and rollback, private grants, wrong role and unlinked classifier refusal. |
| `p3c-fix1-collection-development.log` | FAIL22.263s, added probe used limit100 although historical expiry allows1..25. Corrected only fixture limits to10. |

The exact final commands, frozen hashes and joined terminal results follow below. No unchanged547-second P3C or1233-second P3B suite was repeated.

### Operator and retirement notes

Install reviewed70 then71 with the existing exact migration login before this composition. Keep the separate existing legacy worker, red-team worker, adapter, executor and compensation session identities. No SET ROLE fallback or permissive credential reuse. Existing mounts and `ZASP_TEMPORAL_PRICING_BINDINGS_FILE` described above supply the approved scoped pricing selection to both runtime consumers; no new secret type is introduced. Secret provisioning and production activation were not performed.

Terminal parity demonstrated here is the single-action manual `run_test` family.70 retains all22 upstream operations, but that isn't proof of every downstream family. Export remains blocked by `zasp_audit_export_job_policy_guard` -> `zasp_audit_exports_require_ready` -> historical55 readiness, and its old constructor. Standalone red-team and other action/attack-lab/export downstream modes need their P4/P8 work; this fix does not advertise standalone parity or fabricate their receipts.

P9 must retire70's copied existing-tests schedule and three claim functions,71's copied reconciliation scopes/claim/heartbeat/release and linked lease bookkeeping, and the temporary installed pricing wrapper. Retain domain checks, immutable evidence, request binding and no-resend behavior at the final Temporal boundary. This is transitional parity, not approval of a second permanent orchestration engine.

The original review's Minor diagnostic-log-noise finding is deferred. Tests still retain noisy SQL/diagnostic output; this fix's new protocol labels distinguish manual71 from Temporal68. P7 active FGA and P10 live identity/provider/cloud/signing/runner evidence, final Go1.25.13/advisory gates and independent scoped re-review remain open.

### Frozen affected verification

Fix1 baseline is `p3c-fix1-baseline.json` and its copied pre-edit files, captured before this round against the dirty overlay at HEAD `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`. It is separate from the earlier P3C freeze, which missed the shipped constructor. `p3c-fix1-frozen-source.json` has SHA256 `852c344ff2f80d4a441280fd4ddfb634832465141d308e8195765e1e1ecea99c`. No source changed after that freeze. The fix-only diff has29 source files plus this report; packet inventories/logs are outside source.

I used local `/opt/homebrew/bin/go`, Go1.25.6 darwin/arm64, `GOTOOLCHAIN=auto`, empty `GOFLAGS`. `p3c-fix1-final-go-env.log` records it. These fix1 commands use default vet, with no `-vet=off`. The original P3C final commands also omit that flag, as recorded above; the workaround belonged to preceding P3B runs. Neither packet proves standalone vet or the required final Go1.25.13/advisory gate. This sentence was corrected after scoped review; the retained fix1 manifest and diff describe the pre-correction report, while source and test evidence are unchanged.

Run from `services/platform`:

```sh
go test ./apiserver -run '^TestTemporal(InstalledWorkerRepository|CompatibilityCatalog|LegacyLinkedInstalled|LegacyTestsCatalog|WorkflowShippedCoexistence)Postgres$' -count=1 -v
go test ./agentsec-worker ./red-team-adapter ./redteamadapter ./legacytests ./agentsec-migrate -run '^(TestInstalledLegacyPricing|TestRedTeamInstalledAuthority|TestRedTeamRoutedAuthority|TestComposeRedTeam|TestExistingTestClient|TestExistingTestRuntime(Dispatch|ReadOnlyArtifacts|Composition|CloseRetainsReadinessBorrower|Configuration)|TestTemporalRuntime|TestComposeWorkerRuntimeMountsOnlyProductionReadyModes|TestSecurityAgentWorkerModeRequiresV32PlannerAuthority|TestLoadWorkerRuntimeConfigRequiresExactModeAuthority|TestProductionAdapter|TestLegacyJournal|TestClosedRoleSeparatedRouting|TestRunReleaseMigrationRejectsAmbiguousInputsAndStopsOnFailure)' -count=1 -v
go test -race ./agentsec-worker ./orchestration ./redteamadapter -run '^(TestInstalledLegacyPricing|TestRedTeamInstalledAuthority|TestTemporalRuntimeConcurrentCloseJoinsWorker|TestActivitiesDrainRetainsActiveCompensation|TestLegacyJournalRouterClosedSelection|TestExistingTestRuntimeCloseRetainsReadinessBorrower)$' -count=1 -v
go test -race ./agentsec-worker -run '^(TestInstalledLegacyPricingBindsCurrentPreparedRequest|TestRedTeamInstalledAuthorityRejectsLegacyClassification)$' -count=1 -v
```

The first race selector's two short pricing/router names match no full test names. The second race command supplies their exact names; the first still runs concurrent shutdown, active compensation drain, reconciler borrower close and both linked protocol selections. No package-wide unrelated race suite is claimed.

| Frozen evidence | Result |
|---|---|
| `p3c-fix1-final-postgres.log` | PASS162.790s, five top-level tests, zero failures/skips and all five owned PostgreSQL processes joined. Installed worker18.78s, independent70 catalog14.52s, linked principal/ACL constructor20.44s, independent71 catalog16.19s, shipped coexistence91.84s. |
| `p3c-fix1-final-unit.log` | PASS: worker5.640s, production adapter5.980s, journal/router3.029s, closed legacy map0.939s, migration CLI1.190s. `TestExistingTestClientOwnedPostgres` and `TestProductionAdapterOwnedRouting` skip because the unit process has no owned fixture environment; the separate real owned coexistence test is required evidence. |
| `p3c-fix1-final-race.log` | PASS: worker3.993s, orchestration1.476s, journal/router6.193s. |
| `p3c-fix1-final-pricing-race.log` | PASS5.050s: exact installed pricing15 cases and installed classification refusal. |
| `p3c-fix1-collection-development2.log`, before freeze | PASS81.537s: corrected limit10, nonempty manual-only claim, expiry/schedule/settlement scans preserving the Temporal row, actual wrong-scope/owner classifier refusal, followed by the complete shipped coexistence flow. |

Final PostgreSQL and nested worker/provider processes are joined. Local Temporal is1.32.0 with fresh unique namespaces/queues; controlled FGA readiness is a real client call to a fixture endpoint, not active FGA policy proof. Controlled identity, provider TLS, runner command and artifact storage remain external-IO limits. There was no shared database reset, production provisioning, activation, commit, push or ledger edit.

`p3c-fix1-hashes.json` records before/after hashes for all30 changed files,159 byte-identical SQL files through68, every fix1 log hash, the freeze hash and scoped diff hash. `p3c-fix1-scoped.diff` is relative to this fix round's pre-edit overlay, not a HEAD-wide substitution. The capture refuses any source change after the freeze. Reverse diff/whitespace validation passes against the current overlay.

Self-review covered the early constructor path, exact authority selection, SQL source extraction and overload mapping, private ACLs, current pricing before dispatch, absence of fallback, ownership filters, manual settlement proof, actual shutdown and evidence limits. The verification skill kept the failed diagnostics separate from terminal passing groups; grouped TDD exposed the original constructor and defensive router faults. Independent review is delegated back to the controller under the packet's explicit no-subagents instruction. Review Important1 against this fix-only diff before accepting it.
