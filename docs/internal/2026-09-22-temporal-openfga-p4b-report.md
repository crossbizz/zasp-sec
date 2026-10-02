# P4B ready for independent review

This opening section is the current handoff. Everything under "Preserved development record" is dated progression, including earlier incomplete statements and superseded candidate pins. Those records are retained so failures and fixture corrections stay attributable. No release, production activation, full P4 completion or independent acceptance is claimed.

The implementation connects additive72 admission, real collectors and typed inventory writes to the shipped worker/outbox/scheduler and scoped public HTTP discovery entrypoint. Real local Temporal1.32.0 and owned PostgreSQL exercised manual, periodic and overlapping sync, two tenants with identical connector names/IDs, and267 pages across Continue-As-New with a cold worker restart. Final affected verification passed. This is a local implementation handoff for review, not acceptance of P4C/D or the external release gates.

## The boundary that ships

`agentsec-migrate up-temporal-discovery` installs72 atomically after the attested61/67/68/69/70/71 lineage and exact configured-principal checks. An existing72 authority must validate; it cannot fall back to71 or old discovery. No72 run inserts a legacy public job. Manual and scheduled admission atomically persist the public sync,72-owned run and existing canonical SQS outbox. The only stable collection-workflow starter is the upgraded SQS consumer. Schedule ticks and desired-state/startup repair only admit through SQL and persist that same outbox.

The Schedule service identity is its canonical scoped schedule ID, not a logged-in creator. The scheduled fixture has no matching human schedule-principal membership. Manual requests still pass the existing identity, browser CSRF, scope, idempotency, audit and receipt paths. Human membership revocation refuses replay. Product checks before fresh credential/provider/artifact/apply work use the current connector, connection, subject and persisted original deadline.

SQL owns page/effect receipts and current authority. It does not run another scheduler. A repeated page command returns its immutable recorded result forever; a lost preparation response returns unknown without dispatch. Known-safe retries advance receipt identity and durable not-before while retaining provider cursor/generation. Unknown effects cannot acquire resend permission. Generation contention produces an immutable no-IO wait receipt with no generation or effect allocation; Temporal waits, and each fresh resume checks current authority/deadline. Verified terminal evidence releases the resource for the next run.

`EffectID` is scoped to the persisted run, generation and page/receipt attempt. Product effects use Attempt0, while legacy Attempt1..100 with absent EffectID retain their original encoding. AWS credential/security/STS identities and versioned artifact manifests carry the product effect. Resume binds the manifest's prior producing effect to the actual SQL checkpoint, scope, provider, generation and digest. The public sync attempt is a separate projection:0 before the first durably authorized fresh dispatch,1 thereafter, unchanged across pages, safe retries and continuation. Only positively72-owned readback accepts terminal-before-dispatch0 or queued retryable0 with its persisted not-before. Legacy validators are unchanged.

Application requires a complete candidate and a matching current generation. The existing typed inventory writer, snapshot inputs and three projection queues execute in the same transaction as the verified apply receipt. Deadline/current-authority checks run before and after local application; crossing the budget rolls it back. Evidence-only settlement can report committed success, unresolved outcome_unknown or incomplete without application. It never recollects, applies or resends. Cancellation cannot erase committed or uncertain apply evidence.

The product path uses the existing bounded ceiling10000 cumulative pages,1000 items and64MiB, with one fresh page per effect. The original24-hour SQL budget survives retries and history segments. Exhaustion is incomplete, not a synthetic complete snapshot or zero-progress continuation loop. A bounded worker-owned cache stores verified versioned bytes/metadata only:1024 entries,64MiB, full tenant/storage/version/encryption identity, cloned bodies, eviction and joined close. Each exact-scope/effect batch has a fresh authority check; storage misses retain verified S3 and per-send guards, then recheck before returning the in-memory batch. No authorization verdict is cached. Check/use timing cannot atomically fence an external effect against concurrent revocation.

## Schema and permissions for review

Final72 SQL source checksum: `9a0bf6dd0ad59d8fc53696661ed13c7104cf5475d344d9efe9bc14059c6552ef`.

Independent compiled catalog pin: `cc999bbfb204d348f51c65de31aefe2bf9103c03011d7292f9607d370ffb7f94`.

Nine tables are owned by `zasp_discovery_authority`, with ENABLE/FORCE RLS and the exact-owner policy: registration, predecessor_functions, principals, schedules, runs, page_waits, page_effects, checkpoints and apply_effects. Registration, saved predecessors, principals and no-IO wait receipts reject mutation through immutable triggers. Runtime logins have no direct table access or private-helper execution. The page/apply entrypoints enforce first-result immutability.

| Registered role |72 executable surface |
| --- | --- |
| zasp_discovery_api | Manual sync, schedule put/delete, scoped sync detail/history, schedule detail and freshness. Current human checks remain. |
| zasp_discovery_worker | Scheduled tick admission, page prepare/guard/record, apply prepare/commit, finish/settle, start readback and explicit ownership route. |
| zasp_discovery_scheduler | Scheduled admission, desired-state read/ACK, pending desired scan and oldest-due reconciliation. |
| zasp_outbox_worker | Exact claim/heartbeat/ACK/retry wrappers for the retained transport protocol. No product lease authority. |
| Risk/graph/search projection roles | Only schema USAGE and the named retained_principal_ready compatibility check, preserving original role-specific principal checks. No product effect/table grants. |

The first four roles receive named readiness entrypoints. Registration requires the existing exact login, sole non-admin membership, safe role attributes and original registered binding, not membership alone. All72 function owners/ACLs, schemas, relations, constraints, indexes, RLS, trigger definitions/enabled state and both sides of FK triggers are independently pinned. The domain catalog includes the exact public connector, sync/outbox, generation, inventory and projection dependencies; normal inventory writes do not invalidate readiness, static identity-rule drift does.

The24 retained helpers are enumerated in SQL's predecessor_functions INSERT. Their definitions, owners and ACLs are saved and checked. The inventory fingerprint's definition/owner/ACL and live static/catalog result are pinned. It does not call the precision readiness chain, so it does not recurse through the compatibility wrapper.

One live historical function is replaced by additive72, without changing its historical migration file: `public.zasp_production_runtime_precision_live_fingerprint()`. Original51 counted every outbox user trigger and its own definition. The bounded handoff attests the original before mutation, saves it immutably, then projects exactly the new named72 outbox guard and the original self-definition entry. Every other historical catalog item remains live. Independent72 pins the actual guard, projected helper, saved baseline and wrapper. Disabled/replaced guard, extra unrelated trigger, helper/wrapper drift and saved-baseline mutation are tested. Existing installation checks72 before71; absent/invalid72 fails closed. No historical expected fingerprint is refreshed.

## P4A amendments included here

Known-safe retry must consume a strictly advancing product receipt before another page command. Activity failure now invokes evidence-only settlement instead of leaving the admitted run unsettled; unknown preparation remains unknown.

Temporal wakeups use the exact non-early whole-second ceiling of the original SQL anchor, with unchanged cadence. Original anchor, oldest DueAt and canonical occurrence IDs never round. Scheduler repair uses the exact original grid; verified Temporal ticks use only the exact ceil grid. Scheduled-by provenance remains required. Whole-second anchors, rollover and supported epoch edges are covered; unsupported negative anchors refuse.

The compact action prefix is `discovery-occurrence/v1/` plus the full SHA256 of canonical scoped ScheduleID, length88. The ScheduleID and collection WorkflowID are unchanged. Only the exact prior own long-action form with matching queue/type/full input can be repaired. Prefix-only or foreign-input adoption refuses.

Duplicate start inspection now includes Continue-As-New. The returned current execution and its immutable first-execution reference must agree with authoritative descriptions/history, exact scoped Ref/integration/input digest/original deadline/type/queue. At most two descriptions and two first-event reads are allowed. Missing, foreign or uncertain history cannot acknowledge SQS. The first execution must contain the original checkpoint0 input; a continued checkpoint alone is not proof of admission.

## Local evidence and its limits

`buildWorkerRuntimeWithIO` is the shipped constructor, shared with `buildWorkerRuntime`. The full tests use its actual database authority, runtime clients, registration, production credential resolver, provider factory, S3/SQS adapters and outbox processor. `NewDiscoveryPublicHTTPHandler` uses the real discovery surface/repository with retained identity/CSRF middleware. Only cloud/provider/versioned-storage byte IO, token/identity sources and security-tool IO are controlled. OpenFGA is an HTTP readiness double, **not authorization proof**. No live Stytch, AWS, Kubernetes, GitHub or Okta deployment claim follows.

All local Temporal tests register unique owned numeric namespaces, verify the exact test description before retiring them, stop/join workers and close clients. Each PostgreSQL fixture owns and joins its process. No shared namespace/database is removed. The former page74 diagnostic cancellation targeted one exact owned workflow; it did not cancel unrelated work.

Final commands run from `services/platform`. Log paths below are under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`; shell redirection captured stdout/stderr. Default vet is enabled except the explicitly named mutation check, whose intentional unreachable bypass needed `-vet=off`.

| Command and log | Observed result |
| --- | --- |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryContinuationPostgres$' -count=1 -timeout 24m -v`, p4b-continuation-cache-cold-green.log | PASS663.984s; child634.90s. Real receipt256 Continue-As-New, joined worker stop and new cold cache,267 persisted effects/provider pages/checkpoints,258 typed entities, generation1,3 projections,0 jobs, original deadline unchanged. |
| `go test ./agentsec-migrate -run '^TestTemporalDiscovery(OverlapWait\|WaitSettlement\|ShippedRuntime)Postgres$' -count=1 -timeout 8m -v`, p4b-wait-readback-overlap-green.log | PASS158.512s. Wait26.81s, expired/revoked settlement53.55s, shipped runtime77.38s (child48.41s). Initial scheduled and concurrent manual run both finish, followed by an actual nominal Temporal Schedule tick,3 nonempty snapshots/9 projections/3 published rows/0 jobs. |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryTenantIsolationPostgres$' -count=1 -timeout 5m -v`, p4b-tenant-isolation-green.log | PASS92.501s; child64.85s. Same connector names and integration/schedule IDs in two organizations retain distinct Temporal IDs,4 successful runs,4 snapshots/12 projections, foreign generation1, cross-tenant HTTP refusal and24/8 scoped artifact objects. |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryCurrentEffectGuardPostgres$' -count=1 -v`, p4b-final-current-effect.log | PASS24.758s. An already prepared effect refuses disabled connector/schedule, changed config/reference/subject, revoked connection and an expired exact original budget. Each disposable mutation rolls back and the original positive guard still works. Added regression coverage for existing checks, not an initial behavioral RED. |
| `go test -race ./agentsec-worker ./orchestration ./apiserver ./connectors/... -run 'Test(Discovery\|ProductDiscovery\|ProductEffect\|ProductKubernetes\|TemporalDiscovery\|ProductionDiscovery\|InventoryCollection\|AWSInventory\|AWSSecurity\|FirstPartyCollection\|PublicIntegrationSync)' -count=1 -timeout 12m`, p4b-final-affected-race.log | PASS: worker2.618s, orchestration2.839s, API71.249s, AWS2.984s, collection3.707s, providercollection3.462s, Kubernetes53.777s. Other printed packages had no matching tests and are not counted as coverage. GitHub/IdP have the focused provider command below. |
| `go test -race ./connectors/githubdiscovery ./connectors/idpdiscovery ./connectors/kubernetesdiscovery ./connectors/collection -run '^Test(InstallationCollectionAPI\|OktaCollectionAPI\|KubernetesCollection\|Pinned\|ProductEffect\|ProviderAdapter\|CollectionCancellation)' -count=1 -v`, p4b-final-provider-race.log | PASS: GitHub1.610s, IdP1.349s, Kubernetes1.824s, collection2.069s. |
| `ZASP_P4B_LOCAL_TEMPORAL=1 go test ./agentsec-worker -run '^TestProductDiscoveryContinuedStartLive$' -count=1 -v`, p4b-start-continuation-live.log | PASS2.455s; child1.35s. Real Temporal, controlled two-segment workflow under the production starter: current and first RunID differ, matching duplicate succeeds and foreign digest refuses. Worker stopped and owned namespace retired. Starter-only evidence, not collection/SQL proof. |

The final installed command is `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InstalledAuthority|InstallAtomicity|Admission|CoalescingAtomicity|ManualAndDesiredChange|PageReceipts|PartialCheckpoint|TemporalWakeupPrecision|ApplyEvidence|InventoryRulePin|OutboxOwnership|ScheduleDelivery|StartDelivery|PublicReadback|PreDispatchReadback|Coexistence|TenantIsolation)Postgres$' -count=1 -timeout 20m -v`, captured in p4b-final-installed.log. **PASS731.887s**, all17 selected cases. Final-source isolation passed111.76s (child63.77s), with4 succeeded receipts,4 nonempty snapshots,12 projections,4 published outbox rows and0 jobs. The namespace retired and PostgreSQL joined. Case durations are retained in the log; a printed child PASS is never substituted for the parent command result.

The long267-page proof precedes the narrow lifecycle and duplicate-inspection fixes; those do not change SQL, collection, receipt advancement, Continue-As-New execution or cold-resume behavior. Current-source runtime/isolation and focused real continued-chain inspection cover the amended composition/start boundary. No claim that the663.984s command ran on later bytes.

## Failures kept, causes separated

The first isolation command, p4b-tenant-isolation-first.log, failed76.056s because BatchSize1 plus a runtime restart meant both fixture-driven reconciliation turns visited the first tenant. A next turn on the same runtime registered the foreign paused Schedule. No production pagination or identity rule changed.

The historical checkpoint40 unknown remains unattributed. p4b-continuation-green2.log failed513.767s with41 prepared pages, last-good cursor41 and future original deadline. Later success does not explain that failure, and it is not labeled a performance timeout. The cold component reproduction passed267 pages/258 entities in4.089s. A separate uncached live diagnostic reached74 pages without reproducing the same failure, then was intentionally canceled at the exact owned workflow; its command failed833.732s and settled incomplete. The verified cache addresses measured repeated reads, not a proven cause of the earlier unknown. O(n²) cold-read scale debt remains explicit.

Lifecycle self-review found unborrowed Ready calls and an outbox timeout path that could close clients beneath a canceled caller. Initial p4b-lifecycle-red.log was compile-only missing helpers. The focused race group passed2.534s. A deliberate two-helper passthrough mutation reproduced early destruction, acceptance of new calls and repeated close (p4b-lifecycle-mutation-red.log, FAIL1.096s); both bypasses were removed before final affected tests. The wrapper now rejects new calls, joins processor/readiness borrowers, retains all owned dependencies after timeout and closes once on a later successful join. Discovery readiness uses the same Activity borrower set. No wider runtime modes were refactored.

Exact lifecycle commands: compile RED `go test ./agentsec-worker -run '^TestDiscovery(OutboxLifecycle|ReadinessJoins)' -count=1 -v`; initial GREEN `go test -race ./agentsec-worker -run '^TestDiscovery(OutboxLifecycle|ReadinessJoins|RuntimeBorrowers)' -count=1 -v`; deliberate mutation RED `go test -vet=off ./agentsec-worker -run '^TestDiscovery(OutboxLifecycle|ReadinessJoins)' -count=1 -v`. Restored GREEN is included in p4b-final-affected-race.log with vet and race enabled. The continued-chain behavioral RED command was `go test ./orchestration -run '^TestDiscoveryStartDelivery' -count=1 -v`.

Continued-chain duplicate RED, p4b-start-continuation-red.log, failed0.682s on a matching checkpoint256 chain. `go test -race ./orchestration -run '^TestDiscovery' -count=1 -v` passed1.864s in p4b-start-continuation-green.log, covering matching, foreign current/first input, missing first history, different chain, wrong described run and unknown inspection. This is application delivery logic, not a vendor conformance suite.

Earlier collector setup/adapter failures have distinct causes: typed readiness received a non-JSON SQL boolean; PostgreSQL timestamp decoding used Local instead of UTC; jsonb formatting did not meet the strict canonical credential decoder; reference-only configuration and product AWS effect binding then needed the proper exact adapters. The first shipped runtime outcome_unknown was controlled S3 Head/Get returning a hardcoded us-east-1 KMS key after Put used us-west-2, fixed only in the IO double. The next-generation AWS adapter rejected its own exact completed subject cursor; its bounded fresh-generation acceptance fix retained foreign/midstream refusal. These are not the unexplained checkpoint40 failure.

Cache behavior has compile RED for the new API, then behavioral RED1.070s for missing reauthorization after a storage miss and RED1.140s for unnecessary prior-artifact reads on resume. The earlier1.079s cache test incorrectly expected zero reads, forgetting four real S3 write-verification reads; that fixture mistake is preserved. Corrected cache/resume GREEN was worker1.571s/Kubernetes4.002s/providercollection0.552s; race coverage passed worker2.791s/collection1.310s/providercollection1.518s. Full-scope/effect, current revoke on hit, version/tenant mismatch, mutation isolation, miss/hit, eviction, tampered cold storage and joined close are covered.

No-IO wait readback initially failed because queued attempt0 had no projected retry_at. Decoder RED0.865s and installed SQL RED22.425s preceded the scoped correction. The final candidate-pin command failed18.998s while printing the independently compiled new pin; it was not accepted installation evidence. The158.512s wait/settlement/runtime group above then passed. The old validator remains unchanged.

Additional grouped RED/GREEN commands retained in the packet:

| Command | Logs and result |
| --- | --- |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryPageReceiptsPostgres$' -count=1 -v` | p4b-page-receipts-red.log FAIL18.986s missing prepare function; p4b-page-receipts-green.log PASS24.727s. |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryPartialCheckpointPostgres$' -count=1 -v` | p4b-partial-checkpoint-red.log FAIL22.044s persisted partial rejected. Grouped `go test ./agentsec-migrate -run '^TestTemporalDiscovery(PageReceipts\|PartialCheckpoint)Postgres$' -count=1 -v` passed47.296s in p4b-partial-checkpoint-green.log. |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryApplyEvidencePostgres$' -count=1 -v` | RED21.556s; initial green-named command FAIL76.653s on existing syncs_check4 for unknown/no_apply, then p4b-apply-evidence-green2.log PASS77.643s after preserving public failed/completed invariants. These candidates were empty; nonempty typed evidence is supplied by collector/runtime tests. |
| `go test ./agentsec-worker -run '^TestProductDiscoveryArtifactsEffectAndResume$' -count=1 -v` | p4b-artifact-real-s3.log FAIL1.160s, corrected actual-S3 test p4b-artifact-real-s3-green.log PASS1.056s; later fresh-page-budget group PASS1.180s. Final affected race includes the current cache/resume version. |
| `go test ./agentsec-migrate -run '^TestTemporalDiscoveryOverlapWaitPostgres$' -count=1 -v` | p4b-overlap-wait-red.log FAIL24.758s, busy55P03. `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InstalledAuthority\|OverlapWait)Postgres$' -count=1 -v` passed54.327s in p4b-wait-authority-green.log before the readback amendment. |
| `go test ./apiserver -run '^TestTemporalDiscoveryNoIOWaitReadback$' -count=1 -v` | p4b-wait-readback-decoder-red.log FAIL0.865s; green PASS0.839s. SQL readback RED uses the overlap command above, FAIL22.425s. Current-source affected race and installed readback/wait groups are the final proof. |
| `go test -race ./agentsec-worker ./connectors/collection ./connectors/internal/providercollection -run 'Test(DiscoveryArtifactCache\|ProductDiscoveryArtifactsEffectAndResume\|ProductEffect\|ProductionDiscoveryDependencies\|ProductionDiscoveryReadiness)' -count=1 -v` | p4b-artifact-cache-race.log: worker2.791s, collection1.310s, providercollection1.518s, all PASS. |
| `go test -race ./orchestration -run '^TestDiscoveryWorkflow' -count=1 -v` | p4b-page-failure-settlement-green.log PASS1.788s after behavioral RED0.694s (preceded by an unrelated compile mistake). |

Catalog candidate commands used the installed-authority command from the preserved record and intentionally rolled back when the compiled independent pin differed. Their intermediate failures are all retained in the final log manifest. None is presented as permission to refresh an applied predecessor pin.

## What remains outside this acceptance

Full broad `agentsec-api` startup is a mandatory P8 gate, by controller ruling. `NewPostgresRepository` reaches `PostgresJSONDatabase.SchemaVersion` with pre61 recovery/sandbox readiness; sensor, recovery, inventory and security-agent constructors have further historical readiness gates. P4B's scoped HTTP proof does not bypass or satisfy that chain. P8 must implement and test compatibility on this same upgraded installation before any release/push readiness claim.

P4C still owns scheduled existing-test/common-trigger admission and shared capacity. P4D must complete downstream families and concrete recovery after finite workflow/cleanup exhaustion or unavailable/expired history, including non-reclaimable pre-IO uncertainty. Unknown preparation here cannot be automatically retried. P9 must retire the temporary positively matched legacy discovery route and retained_principal_ready after backlog/equivalence proof, preserving adjacent projections and required transports. The controller's explicit retirement row remains untouched.

All original728 obligations, full scale acceptance, Stytch/OpenFGA authorization, deployed-provider/cloud tests, final toolchain, P8/P9/P10 and independent full-P4B review remain gates. Required SQS/event/DLQ mappings are unchanged, including M0-06, M1-13, M1-33, M1-41, M1A-04, M3-43, M3-52d, M5-13, M7A-50, M8-03, M8-17c, M8-34 and M8-59a3. No ledger promotion is made by this report.

Self-review traced current authority through admission, credential/provider sends, artifact resume, apply and settlement; inspected exact role/RLS/catalog handoff and retained ownership routing; and corrected the shutdown and continued-duplicate gaps with focused tests. All66 changed Go files passed `gofmt -l` with no output. No commit, push, shared provisioning or authoritative ledger edit was made by this implementer.

The final packet contains68 changed paths:67 application/test/SQL paths and this report. `p4b-frozen-source.json` lists every exact before/after source hash; `p4b-scoped.diff` is against the captured1,945-path pre-edit overlay, not HEAD; `p4b-hashes.json` binds the baseline, freeze and scoped diff plus all174 development/verification log hashes. The202 preexisting SQL files are byte-equal to the baseline. The capture helper enforces historical SQL equality and refuses finalization if any source changed after freeze. Its final scoped whitespace check must also pass. Review must use these manifests, preserving the controller-owned retirement/ledger/progress files outside this scoped diff.

## Preserved development record

The entries below retain their original checkpoint status. They are not the current completion claim or final catalog pin.

Latest development checkpoint (not frozen): the page/ceil/real-collector installed group passed127.559s (`p4b-page-ceil-authority-green.log`). Real manual/periodic execution subsequently passed80.79s inside the combined `p4b-runtime-continuation-green.log`; that command still FAILED116.736s because its separate continuation case had malformed test credential JSON. Earlier manual/periodic green2 and count-diagnostic commands failed84.592s and82.887s respectively: all three runs succeeded, but the parent incorrectly required three positive new-observation counts. Immutable migration10 counts only new source observations. The corrected assertion preserves three succeeded receipts, three nonempty generation snapshots, nine projections, three published outbox rows and zero legacy jobs, and requires later counts zero.

The corrected real continuation then FAILED513.767s (`p4b-continuation-green2.log`): run checkpoint40,41 prepared effects, last-good Kubernetes cursor41/generation1, terminal `outcome_unknown`, original future admission deadline unchanged. Its namespace retired and PostgreSQL joined. The precise failed boundary is still under investigation; it is not accepted continuation or timeout evidence. A separate cold real-collector reproduction passed267 pages/258 entities in4.089s (`go test ./connectors/kubernetesdiscovery -run '^TestProductKubernetesColdResumeAcrossHistoryBoundary$' -count=1 -v`, `p4b-cold-resume-diagnostic.log`), excluding a deterministic page41 cursor grammar limit in that component. It does not replace installed proof.

Controller-approved no-IO contention receipts now live in independently pinned72 `page_waits`, with FORCE RLS, immutable trigger and no generation/effect allocation. Known-busy admission advances receipt identity and durable not-before; Temporal owns the wait. The RED was55P03 at busy admission (`p4b-overlap-wait-red.log`, FAIL24.758s). The new catalog candidate was inspected before updating the literal to `81459b6af51c83082f6ca63c4b302357e69348cf4ac406138cecadd5621d76ad`; the candidate command failed85.726s. `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InstalledAuthority|OverlapWait)Postgres$' -count=1 -v` passed54.327s (`p4b-wait-authority-green.log`), including immutable replay, no dispatch on wait, not-before enforcement, current revocation, unknown first effect retained, and generation2 only after positive terminal evidence releases generation1. Both owned PostgreSQL instances joined. Concurrent eventual success and deadline settlement remain open.

Approved cache work remains pending: bounded worker-owned verified immutable artifact bytes, no authorization caching, exact scope/effect guard for each bounded synchronous hit batch, unchanged guarded storage on misses, cold restart correctness. Cold resume's cumulative re-reading is O(n²); the cache cannot establish arbitrary-scale acceptance or remove the original scale gates.

Checkpoint 1 records additive installation and admission, not a working Temporal discovery runtime. The controller authorized two internal checkpoints inside P4B; this report does not reduce the deliverable. Checkpoint 2 continues in the same worktree.

HEAD is `6e7d759007e0ad7cb2e5ef385d99f48bc3aa774a`, branch `codex/cached-runtime-ship-20260917`. Before edits, `p4b-capture.mjs baseline` copied 1,945 paths and captured the dirty overlay. No commit, push, shared provisioning, historical SQL edit, or authoritative ledger edit occurred. All PostgreSQL processes were disposable local instances and joined normally in the recorded tests. Go reports `go1.25.6 darwin/arm64`; this is not the final toolchain gate.

## What is present at checkpoint 1

The shipped `agentsec-migrate up-temporal-discovery` command installs additive schema `zasp_temporal72` on the supported61/67/68/69/70/71 lineage. It validates configured migration/API/discovery/scheduler/outbox logins against the existing exact registrations before DDL. The installer uses one transaction, the existing schema/evidence locks, predecessor readiness, independent catalog compilation, immutable registration and final readiness. A registration fault rolls back the entire schema. Existing but invalid72 is refused, not replaced.

Candidate72 SQL checksum: `87ef3341eb725c46b99d48506365b532b5eab7dd8a297787f77aefbb412bf5d0`.
Independent candidate catalog pin: `d6d89c050aac9de518d97b77d4f701439312e8ce782b462dc98c0a394079acb0`.
These pins cover this checkpoint only. The full72 authority has not frozen.

Tables: `registration`, `predecessor_functions`, `principals`, `schedules`, `runs`. All are permanent, owned by `zasp_discovery_authority`, FORCE/ENABLE RLS with an exact-owner policy. The first three reject mutation through the existing67 immutable trigger. Schedules and runs hold product state, without leases or heartbeat fields. The fingerprint includes functions, owners, ACLs, columns/defaults, constraints, indexes, RLS policies, user triggers and both sides of foreign-key triggers.

The registered API, discovery worker, discovery scheduler and outbox login each retain their existing distinct authority role. Runtime logins cannot read/write72 tables or call private helpers. Only API gets `public_request_sync` and `public_put_schedule`; worker/scheduler get `scheduled_admit`; all four get readiness. Runtime entry points validate exact `session_user`, not group membership alone. A shadow login granted the worker group is refused. Catalog PUBLIC-grant, persistence and RLS drift tests fail readiness. No new broad runtime grants were added.

Manual and scheduled admission converge on one private boundary. It locks current integration, verified connection and scoped provider subject, then atomically writes public sync,72 run and the existing discovery-jobs outbox envelope. It persists a24-hour deadline from database admission time. No legacy job is inserted; a direct legacy claimant cannot find the72 job, and a separately admitted retained job is still claimable.

The scheduled boundary locks the scoped desired schedule, checks enabled state and exact non-NULL revision, validates the nominal wakeup against its anchor/cadence, and derives canonical sync/job/outbox identity from persisted oldest due. It advances to the first future cadence in the same transaction. The test uses a fixed microsecond timestamp and independent literal canonical IDs/digest. A conflicting outbox row proves sync/run/due rollback. Repeated wakeups return explicit `not_due`.

The API extraction retains current membership/scope checks, idempotency, audit and receipt behavior. The desired schedule writer persists a newer revision with delivery still pending. It does not yet deliver that change to Temporal. Creator membership is irrelevant to the scheduled service boundary; manual replay still refuses revoked human membership.

P4A amendment, approved by the controller: a known-safe retryable page must supply a strictly advancing product receipt version/digest before the workflow waits and issues its next command. This token does not advance the provider cursor or generation. Unknown effects cannot acquire resend permission through elapsed time. The changed workflow rejects a nonadvancing token. SQL receipt production and retry-not-before enforcement are checkpoint 2 work.

## Extraction roots and dependencies

| Root | Retained or extracted boundary |
| --- | --- |
| SQL10 `zasp_discovery_request_sync`; SQL13 `zasp_execution_request_sync` | Extract connector/version/subject validation and public sync/outbox writes. Omit the old queued-job insertion entirely. No call to old request_sync from72. |
| `agentsec-worker/scheduler_runtime.go: scheduledRequest` | Preserve scoped canonical scheduled_sync/job/outbox seeds, request digest and idempotency key. Wakeup time is not product identity. |
| SQL13 public request/put schedule functions | Keep mutation shape, effective human scope, audit, idempotency and public receipt helpers. New72 schedule rows hold revisions and pending delivery. |
| Public sync/outbox/freshness and workflow audit/idempotency/receipts | Existing exact discovery-authority RLS/grants remain. Sync updates invoke `zasp_execution_sync_version_trigger`; initial admission is INSERT. Public outbox has no legacy-job FK. |
| Eight pinned retained functions | canonical_id, subject_valid, bump_freshness, workflow_replay, record_public_mutation, sync_body, sync_version_trigger and effective_scope_permissions. Save definition/owner/ACL at install;72 readiness compares live catalog. No blanket SQL copy. |
| `zasp_sa_multistep_prior.lock_scope` | Uses the existing scope-table owner's controlled locking helper. Its installed predecessor ownership/readiness remains in the71 chain. |
| Generation reservations/checkpoints | Existing generation reservation FK is sync-only. Legacy job authorities/checkpoints/schedule_runs depend on old jobs and are not reused for72. Their72 product counterparts are still needed. |
| Inventory apply | SQL14 typed writer and core inventory fence are the next extraction boundary. Complete collection, current generation, typed write triggers/RLS and committed inventory receipt still need implementation and real proof. |

Public historical migrations are immutable. The rejected predecessor-handoff/job-trigger proposal was not implemented; the controller chose72-owned runs without legacy jobs.

## Exact test record

Commands ran from `services/platform`, with default vet, using `set -o pipefail` and `2>&1 | tee ../../.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/<log>`. Logs below are immutable checkpoint evidence. Table durations are package totals unless explicitly called a case duration.

Command keys:

    I: go test ./agentsec-migrate -run '^TestTemporalDiscoveryInstalledAuthorityPostgres$' -count=1 -v
    A: go test ./agentsec-migrate -run '^TestTemporalDiscoveryAdmissionPostgres$' -count=1 -v
    M: go test ./agentsec-migrate -run '^TestTemporalDiscoveryManualAndDesiredChangePostgres$' -count=1 -v
    F: go test ./agentsec-migrate -run '^TestTemporalDiscoveryInstallAtomicityPostgres$' -count=1 -v
    R: go test ./orchestration -run '^TestDiscoveryRetryConsumesAdvancingProductReceipt$' -count=1
    D: go test ./orchestration -run '^TestDiscovery' -count=1

| Log prefix `p4b-` | Command | Observed result |
| --- | --- | --- |
| install-red.log | I | FAIL18.418s, shipped CLI lacked the route. |
| install-development.log | I | FAIL18.268s, forward fingerprint reference during SQL compilation. Corrected readiness to PL/pgSQL. |
| install-pin.log | I | FAIL20.105s, first independently compiled pin differed. |
| install-green.log | I | PASS24.367s, initial scaffold only. |
| admission-red.log | A | FAIL19.665s, scheduled_admit missing. |
| admission-pin.log | I | FAIL19.879s, expanded catalog needed a new pin. |
| admission-green.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InstalledAuthority\|Admission)Postgres$' -count=1 -v` | PASS46.748s. |
| retry-receipt-red.log | R | Build failure, missing fmt import in test. Not behavioral RED. |
| retry-receipt-red2.log | R | FAIL0.835s; receipt mismatch observed, but assertion inside Activity goroutine caused Goexit. Not clean behavioral evidence. |
| retry-receipt-red3.log | R | FAIL0.637s; corrected test observed reused checkpoint0 and acceptance of invalid retry receipt. |
| retry-receipt-green.log | D | PASS0.839s. |
| manual-config-red.log | M | FAIL20.004s, public_request_sync missing. |
| manual-config-pin.log | I | FAIL18.093s, expanded catalog needed a new pin. |
| atomicity-red-manual-green.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InstallAtomicity\|ManualAndDesiredChange)Postgres$' -count=1 -v` | Combined FAIL39.234s. Atomicity case FAIL18.00s: wrong configured API reached DDL. Manual/config case PASS20.29s. An earlier status message incorrectly paired20.004s with GREEN; that is the separate RED total above. |
| atomicity-green.log | F | PASS18.840s after all exact configured-role checks. |
| null-revision-red.log | A | FAIL21.028s: NULL revision bypassed current schedule authority. |
| null-revision-pin.log | I | FAIL17.016s, reviewed pin after NULL guard correction. |
| checkpoint1-authority.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery' -count=1 -v` | Combined FAIL106.287s. Installed authority PASS22.19s, install atomicity PASS17.51s, admission PASS19.84s, manual/config PASS24.09s (case durations). New coalescing fixture failed21.79s at its setup INSERT because the conflict key was too short, before exercising product rollback. |
| checkpoint1-coalescing.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryCoalescingAtomicityPostgres$' -count=1 -v` | PASS19.532s, case18.67s, after a valid25-character conflict key. Tests actual failed-outbox rollback, canonical oldest-due identity, future due, persisted24-hour budget and duplicate not_due. |
| checkpoint1-workflow.log | `go test -race ./orchestration -run '^TestDiscovery' -count=1` | PASS2.140s. |

The database fixture seeds connector configuration, verified subject and human membership as controlled identity/provider IO. The real shipped CLI, PostgreSQL authority, registered logins, catalog checks and transactions execute unchanged. No real Temporal service, provider collector, inventory write or application worker constructor has been exercised by this checkpoint. The fake registration fault is test-only and forces a SQL error inside the real migration transaction.

## Snapshot and self-review

Changed application paths: migrations/production_temporal_discovery.go; migrations/sql/0072_production_temporal_discovery.up.sql; agentsec-migrate/bootstrap_release.go, main.go and temporal_discovery_test.go; orchestration/discovery_workflow.go and discovery_workflow_test.go; this report. Paths are relative to `services/platform` except this report. The evidence helper and logs live under the plan packet.

`p4b-checkpoint1-frozen-source.json` records before/after source hashes; `p4b-checkpoint1-scoped.diff` is against the captured dirty overlay; `p4b-checkpoint1-hashes.json` records every log hash, baseline/freeze/diff hashes and the historical-SQL unchanged check. These are checkpoint snapshots, not the final full-P4B freeze. Later work must retain them and produce a final new manifest.

Self-review traced the actual public sync/outbox FKs and trigger owners, checked grants against direct private/table access and shadow logins, and found the NULL revision hole through behavioral RED. The fix now refuses NULL explicitly. Test setup mistakes remain disclosed above. Extra admission coverage exercises existing grouped behavior; it is not presented as an independent initial RED for each added assertion.

## Checkpoint 2 is required

Implement persisted page/effect receipts, generation and cursor/manifest state without legacy attempts or leases. Prove exact-command replay, lost responses, advancing known-safe retry receipts without cursor movement, SQL retry-not-before, unknown/no-resend, current connector/provider/credential revocation, partial/denied/malformed/cancelled/terminal distinctions, verified complete inventory application and evidence-only settlement. SQL must compare every fresh-work deadline to the persisted original budget; late delivery and Continue-As-New cannot extend it. Preserve durable run/generation/effect identity, including AWS identity.

Real schedule source and desired-change delivery remain absent: dedicated-session exact-scope advisory serialization, reread after lock, bounded RPC with no transaction across RPC, safe unlock/join, pending/unknown repair, disable/delete and current revision refusal. Startup/recreation repair must call the same admission after acknowledged Temporal Schedule write.

Keep the existing SQS/outbox tenant envelope. The upgraded consumer must be the sole stable DiscoveryWorkflowID starter; ACK only confirmed matching started/already-started execution, never a foreign collision. Ambiguous starts retain redelivery. Inject the persisted original deadline at first start and allow bounded evidence-only settlement after fresh-work expiry. No product job claims or heartbeats.

Wire actual collectors, scoped inventory writers, typed API readback and the shared shipped `buildWorkerRuntimeWithIO` constructor with installed72 selection. Present-invalid authority must fail closed; unsupported lineage can retain its old route. Preserve adjacent streaming/risk/search/graph readiness and shared lifecycle. Actual local Temporal plus disposable PostgreSQL must prove coherent manual and periodic sync, two same-named tenant connectors, overlap serialization, duplicate/retry and checkpoint continuation beyond256 pages, deadline edges, current disable/revoke, durable start/configuration repair and joined shutdown. No product-repository or processor fixture success is acceptable.

P4C scheduled existing-test/common trigger/shared capacity and P4D remaining family settlement/recovery stay required. Preserve every original728 obligation, Stytch and canonical tenant/RLS identity, the P0 retirement inventory and required SQS/event/DLQ mappings (M0-06, M1-13, M1-33, M1A-04, M3-43, M3-52d, M5-13, M7A-50, M8-03, M8-17c, M8-34, M8-59a3). Live Stytch/provider/cloud, toolchain, P8/P9/P10 and independent full-P4B review gates remain open.

## Checkpoint 2 working notes, not a handoff

P4B is still incomplete. The current source is beyond the immutable checkpoint1 snapshot, but there is no final frozen diff and no full shipped Temporal/API sync proof yet.

The installed product now has non-reclaimable page and apply receipts, provider checkpoints carrying the producing EffectID, stable generation reservation, original persisted deadline/current connector checks, known-safe retry receipts without cursor movement, typed inventory application and evidence-only settlement. The real four-provider factory accepts lease-free input. AWS security/STS authority and provider credential bindings retain a validated product EffectID with Attempt0; legacy Attempt1..100 serialization remains unchanged when EffectID is absent. Guarded HTTP sends retain original context deadlines. A denied send closes its request body.

Installed AWS collection runs through the actual factory, credential resolver, provider collection client and S3 artifact driver. Only secrets/STS, external inventory/security calls and versioned S3 bytes are controlled. The parent verified nonempty typed entities, one snapshot input and three projection work rows, exact page replay without extra writes, committed evidence settlement and readiness after ordinary inventory writes. The original inventory rule fingerprint's definition/owner/ACL and live result are independently pinned; rule drift fails closed.

The public outbox keeps its SQS transport lease protocol. A72-owned row is protected from unregistered legacy-role claim/heartbeat/ACK/retry by an exact-session row guard. Four72 wrappers call pinned retained transport helpers; old non72 rows retain their route. This guard changes the public51 precision fingerprint because that historical query includes every user trigger on the shared outbox. The controller approved one explicit two-delta projection: save immutable original51 definition/owner/ACL; a private72 copy projects only the exact72 trigger row and the51 function's own definition entry. The live51 wrapper first verifies registered72 and the independent72 catalog. Every unrelated catalog entry remains live. Historical SQL files and62..71 pins are unchanged. The72 fingerprint includes the actual guard, wrapper, helper and saved baseline. Its inventory dependency reads catalog metadata and static identity rules, not the precision readiness chain, so this path does not recurse. The installer attests71 before an absent72 mutation; an existing72 installation validates72 without using predecessor readiness as a fallback.

The Schedule source now owns a bounded dedicated PostgreSQL session and canonical scoped advisory lock across the RPC callback, without an SQL transaction across the RPC. It rereads current desired state after acquiring the lock. Each attempted write resets durable delivery acknowledgment, including retries of an already delivered revision. Current-revision ACK and oldest-due reconciliation are separate product transactions; errors keep repair pending. Desired-change scanning, including a startup pass, does not poll for due work. Queued-start loading verifies the existing scoped outbox payload and returns the persisted original deadline. The starter uses stable IDs and rejects foreign immutable history, workflow type or task queue; unknown start responses cannot acknowledge delivery.

Recent focused commands run from `services/platform`, with output under the plan packet. This list is development evidence, not the complete final command inventory:

| Log | Command | Result |
| --- | --- | --- |
| p4b-inventory-rule-collector-green.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InventoryRulePin\|RealCollector\|PartialCheckpoint)Postgres$' -count=1 -v` | PASS82.559s, all owned PostgreSQL processes joined. |
| p4b-outbox-ownership-red.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryOutboxOwnershipPostgres$' -count=1 -v` | FAIL22.931s: unregistered old transport claimed a72 row. |
| p4b-outbox-ownership-green.log | Same ownership command | FAIL22.685s at shipped install, before behavior. Diagnostic logs preserve the51-dependent readiness failure. |
| p4b-outbox-handoff-pin.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryInstalledAuthorityPostgres$' -count=1 -v` | FAIL20.255s: SQL definition order referenced missing72 fingerprint. |
| p4b-outbox-handoff-pin2.log | Same installed-authority command | FAIL20.518s: candidate pin printed for review. |
| p4b-outbox-handoff-green.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery(InstalledAuthority\|InstallAtomicity\|OutboxOwnership)Postgres$' -count=1 -v` | PASS72.431s. Cases27.94s,20.48s,23.15s; all PostgreSQL joins. Tests guard/helper/wrapper/unrelated-trigger drift and retained71/non72 behavior. |
| p4b-effect-body-red.log | `go test ./connectors/collection -run '^TestProductEffectTransportClosesRejectedBody$' -count=1 -v` | FAIL0.450s: rejected request body not closed. |
| p4b-effect-body-green.log | `go test ./connectors/collection -run '^TestProductEffectTransport' -count=1 -v` | PASS0.417s. |
| p4b-artifact-real-s3.log | `go test ./agentsec-worker -run '^TestProductDiscoveryArtifactsEffectAndResume$' -count=1 -v` | FAIL1.160s: fixture omitted required observation time. |
| p4b-artifact-real-s3-green.log | Same artifact command | PASS1.056s: real S3 driver, distinct new-effect keys, prior-effect resume and mismatched producing-effect refusal before provider/write. |
| p4b-schedule-start-red.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery(ScheduleDelivery\|StartDelivery)Postgres$' -count=1 -v` | FAIL44.234s: missing schedule_current and start_delivery boundaries. |
| p4b-start-client-red.log | `go test ./orchestration -run '^TestDiscoveryStartDelivery' -count=1 -v` | Build RED, missing NewDiscoveryStarter. |
| p4b-start-client-green.log | Same starter command | PASS0.742s. |
| p4b-schedule-source-red.log | `go test ./agentsec-worker -run '^TestProductDiscoveryInstalledScheduleSource$' -count=1 -v` | Build RED, missing source constructor. |
| p4b-schedule-start-pin.log | Installed-authority command above | FAIL20.498s, new candidate pin. |
| p4b-schedule-start-green.log | Schedule/start command above | PASS65.641s. Schedule40.22s including actual source child1.78s/package2.973s; start24.26s. Both owned PostgreSQL joins. |

Current candidate pin is `cbde723e0922f6864e015808e7d4c6015ab3c7ab611c2b9eb0acec21049c62b1`, not a final freeze. The complete collector/receipt RED/GREEN inventory and scoped source hashes will be added before full review. Earlier failures remain in their original logs, including misleading development filenames; a filename containing green is not a passing result.

### API readback and retained-route work, still incomplete

The public `attempt` field now describes one admitted product run:0 before the first durably prepared page dispatch and1 afterwards. Pagination, safe receipt retries and Continue-As-New do not change it. Provider EffectID/receipt attempts remain separate and never fabricate a legacy lease attempt. A known-safe retry projects queued status, a retryable error code and the72 persisted not-before. Detail/history/freshness use scoped72 wrappers; retained syncs keep the old body. Only a positively owned72 terminal-before-dispatch row permits attempt0. The legacy Go validator is unchanged. API mutation and schedule-delete wrappers check current human membership/scope before receipt replay, and retain public audit/receipt identities. Stytch and session middleware are unchanged.

The concrete database adapter selects72 only after checking installation and its registered-principal readiness. Present-invalid72 errors cannot fall back. Actual API repository tests cover manual/replayed admission, desired revision update/delete, typed detail/history/freshness, scope refusal and the run states below. These are installed PostgreSQL component tests, not the required full HTTP/Temporal entrypoint proof.

| Log | Command from services/platform | Result |
| --- | --- | --- |
| p4b-start-processor-red.log | `go test ./agentsec-worker -run '^TestProductDiscoveryInstalledStartProcessor$' -count=1 -v` | Build RED, missing start processor. |
| p4b-start-processor-green.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryStartDeliveryPostgres$' -count=1 -v` | PASS32.759s; actual SQL with controlled external start outcomes, unknown redelivery and confirmed ACK. |
| p4b-public-readback-red.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryPublicReadbackPostgres$' -count=1 -v` | Build failure: test used a nonexistent result type. |
| p4b-public-readback-red2.log | Same readback command | FAIL29.973s, installed API constructor rejected72. |
| p4b-public-readback-pin.log | Installed-authority command above | FAIL20.666s, candidate pin after readback/attempt changes. |
| p4b-public-readback-green.log | `go test ./agentsec-migrate -run '^TestTemporalDiscovery(PublicReadback\|PreDispatchReadback\|RealCollector)Postgres$' -count=1 -v` | PASS118.572s. Nonempty real collector+succeeded readback40.49s; queued/running/retryable/running/failed49.54s; pre-dispatch failed attempt027.72s. All PostgreSQL joins. |
| p4b-public-mutations-red.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryManualAndDesiredChangePostgres$' -count=1 -v` | FAIL28.937s: test identity omitted browser CredentialKind, so the retained receipt decoder refused it. |
| p4b-public-mutations-red2.log | Same mutation command | FAIL35.220s: missing72 public_delete_schedule after manual/replay/update succeeded. |
| p4b-public-delete-pin.log | Installed-authority command above | FAIL21.333s, candidate pin after delete authority. |
| p4b-public-mutations-green.log | Same mutation command | PASS34.902s, including exact installed API mutations, two72 runs/no public job and pending deleted revision4. |
| p4b-public-api-legacy-green.log | `go test ./apiserver -run 'Test.*(Discovery\|PublicIntegrationSync)' -count=1` | PASS184.221s, affected retained API tests. |
| p4b-coexistence-red.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryCoexistencePostgres$' -count=1 -v` | FAIL23.136s: missing scoped delivery_route. |

The candidate pin changed to `57d44b09e18e700cb25848fb8dc3dd1e48f723bf21a6422e53f25cc561e4e54f` for the passing API mutation group. Retained routing/readiness work after this group is not yet green or frozen. That compatibility surface is temporary migration debt: only a positively matched retained public job and its canonical scoped outbox envelope may enter the old processor;72 ownership is exclusive. The worker still checks current72 before choosing either branch. Risk/graph/search compatibility uses the original role-specific execution-principal check and the72 readiness chain through71/67 to the unchanged registered60 predecessor security predicates. The only proposed new grants to those three roles are72 schema usage and its named readiness function, with no product effect/table authority.

### Manual/periodic and bounded-page development

Still incomplete. The first real manual generation returned `outcome_unknown`: AWS's adapter rejected a subject-bound completed cursor on fresh page1. SQL correctly retained the last-good cursor. The adapter now accepts only its exact completed subject-bound form as the next generation's starting checkpoint; foreign, midstream and later-page completed cursors stay rejected. Focused `go test ./connectors/awsdiscovery -run '^TestInventoryCollection' -count=1 -v` is GREEN0.464s after RED0.493s. No unknown old dispatch was resent.

The next manual/periodic integration passed both initial and manual collection but failed waiting120s for an occurrence (`p4b-shipped-manual-periodic-green.log`, FAIL148.376s). Read-only local Temporal logs established a separate concrete defect: canonical ScheduleID length226 plus `/occurrence` length11 produced a237-character action prefix; Temporal's appended timestamp exceeded its255-character persisted workflow ID limit. The exact redacted error is `createOrUpdateCurrentExecution failed. Failed to insert into current_executions table. Error: pq: value too long for type character varying(255) (22001)`. `p4b-temporal-schedule-diagnostic.log` keeps the97 relevant log records from2026-09-23T18:35:45Z through18:36:06Z, without workflow/tenant identifiers.

Controller-approved action prefix is now `discovery-occurrence/v1/` plus full SHA256 of canonical scoped ScheduleID (length88). ScheduleID and collection WorkflowID remain unchanged. Reconciliation accepts the exact previous own long form only with matching queue, workflow type, full scoped input and acceptable revision; hash-prefix or foreign-input adoption refuses. Compact-action RED0.716s is `p4b-compact-action-red.log`.

A second, independent service observation: stored interval offset55.123456s produced `NextActionTimes` at whole second55, early relative to SQL's anchor. The wakeup projection now ceilings to the next whole second without changing SQL anchor, persisted oldest due or canonical occurrence IDs. Worker admission accepts only this exact ceil grid; scheduler reconciliation accepts the original exact grid. Whole-second anchors are unchanged, rollover and epoch edges are tested, unsupported negative anchors refuse. Ceil-options RED0.760s is `p4b-ceil-wakeup-red.log`. Grouped `go test ./orchestration -run '^TestDiscoverySchedule' -count=1 -v` passed0.712s in `p4b-schedule-amendments-green.log`. Both P4A amendments require independent review with this P4B diff.

Product collection now separates existing cumulative ceiling10000 pages from one fresh page per effect, retaining cumulative1000 items/64MiB and original deadline. Legacy absent-field request serialization is unchanged. Exhausted cumulative pages return truthful `incomplete`, no cursor advance, provider IO, manifest write or zero-progress continuation. Actual S3 driver replay/new-effect/prior-effect resume test passed1.180s after build RED for the new bound. Installed SQL/real collector group first failed85.170s at all three expected boundaries (`p4b-page-ceil-authority-red.log`): SQL missing incomplete, worker accepting old fractional wakeup, real collector consuming all four AWS phases in one effect. The two changed SQL function definitions were inspected before pin update to `388e91ada6ef4beb0290c37e895b42fdb21993437b782339b3bc555171b6eb75`; rollback-only candidate check failed21.246s as expected. Historical SQL/pins were not changed. Subsequent integration verification is still in progress.

### Shipped worker progression, not a freeze

Current candidate72 pin is `06303fd0a4e8fc87939f431b941f3e0cf9a1bb9ed6bf7aa17ae5b73d10b3e864`. `p4b-coexistence-green.log` passed75.389s with actual registered worker, outbox and three projection constructors, wrong/unregistered projection principal and present-invalid72 refusal. Missing/ambiguous ownership assertions added after that run still require verification. The controller's explicit temporary-retirement row in `2026-09-22-temporal-openfga-retirement.tsv` remains in scope for the final packet.

The installed72 branch of `buildWorkerRuntimeWithIO` now owns real PostgreSQL, Temporal clients, registered workflows/Activities, product authority, credential resolver, collector factory and S3/SQS drivers. Only external cloud credentials/SDK clients, security-tool IO and an OpenFGA readiness HTTP server are controlled. The FGA server is a readiness double, **not authorization proof**. Unique `p4b-owned-<numeric>` namespaces are verified by exact description before deletion; no shared namespace is deleted. Failed early test namespaces were explicitly retired and logged.

| Log | Command from services/platform | Result |
| --- | --- | --- |
| p4b-discovery-io-regression.log | `go test ./agentsec-worker -run '^TestProductionDiscovery(Dependencies\|Readiness)' -count=1 -v` | PASS1.219s. |
| p4b-shipped-runtime-red.log | `go test ./agentsec-migrate -run '^TestTemporalDiscoveryShippedRuntimePostgres$' -count=1 -v` | Build failure, missing external discovery IO composition seam. |
| p4b-shipped-runtime-red2.log | Same installed runtime command | FAIL27.677s. Test hand-built map-sorted SQS body violated the actual queue's canonical envelope. This is fixture failure, not proof of an old-route refusal. |
| p4b-shipped-runtime-green.log | Same installed runtime command | FAIL32.040s, same fixture envelope defect. Replaced it with the actual production queue publisher. |
| p4b-runtime-cleanup-lifecycle.log | `ZASP_P4B_RETIRE_NAMESPACE=p4b-owned-1790186280350399000 go test ./agentsec-worker -run 'Test(ProductDiscoveryRetireOwnedNamespace\|DiscoveryRuntimeBorrowersJoinBeforeClose)' -count=1 -v` | PASS1.308s; first failed-run namespace retired, canceled close retains borrowed resources until join. |
| p4b-runtime-cleanup2.log | `ZASP_P4B_RETIRE_NAMESPACE=p4b-owned-1790186423033291000 go test ./agentsec-worker -run '^TestProductDiscoveryRetireOwnedNamespace$' -count=1 -v` | PASS1.373s, second failed-run namespace retired. |
| p4b-shipped-runtime-green2.log | Installed runtime command above | FAIL31.053s. Real workflow started and correctly settled outcome_unknown: S3 double Head/Get returned a hardcoded us-east-1 key after Put used configured us-west-2. Namespace retired and PostgreSQL joined. |
| p4b-shipped-runtime-green3.log | Same installed runtime command | PASS40.239s; child5.41s, Temporal1.32.0, nonempty typed inventory, namespace retirement and PostgreSQL join. Only the double changed to return the encryption key from Put; production verification stayed intact. |
| p4b-shipped-outbox-red.log | `go test ./agentsec-worker -run '^TestProductDiscoveryShippedTemporalRuntime$' -count=1` | Build failure, missing low-level outbox IO seam. |
| p4b-shipped-outbox-green.log | Installed runtime command above | FAIL23.560s, child compile failure from incorrect SDK adapter interface name. |
| p4b-outbox-io-regression.log | `go test ./agentsec-worker -run '^Test.*Outbox' -count=1` | PASS1.461s. |
| p4b-shipped-outbox-green2.log | Installed runtime command above | PASS33.649s; shipped outbox SQL claim/publish/ACK to production SQS envelope, sole consumer start, real Temporal collection/apply, namespace retirement and PostgreSQL join. |

**Explicit P8 dependency, controller ruling:** P4B proves `NewDiscoveryPublicHTTPHandler` plus production discovery surface/repository and real identity/CSRF middleware, with the shipped worker/outbox/scheduler. It does not establish full `agentsec-api` deployability. Broad root `NewPostgresRepository` still calls `PostgresJSONDatabase.SchemaVersion` with pre61 recovery/sandbox readiness; downstream sensor, recovery, inventory and security-agent constructors have their own historical readiness gates. Full API-root startup on the same upgraded installation is mandatory P8 acceptance before release or push readiness. Adjacent guards are not weakened here, and their compatibility work is not waived. The controlled identity IO in the scoped test is not Stytch deployment proof. Manual/periodic and remaining full P4B behavior tests are still in progress.
