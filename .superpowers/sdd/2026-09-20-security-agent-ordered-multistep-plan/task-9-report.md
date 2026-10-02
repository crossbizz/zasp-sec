# Task 9: dormant successor invocation and settlement

Base: `a7bd9e57ddeb267d511240b446508776cd63221b`. DONE_WITH_CONCERNS: the dormant Task9 authority and requested grouped verification are complete. No push. Public execution, generic workers/outbox dispatch, cleanup aggregation and every other action pair stay closed.

I executed the supplied brief in the existing isolated worktree with Superpowers TDD. Development used focused tests. The parent completion audits required expiry reconciliation for both started and completed-but-unsettled journals. All affected groups passed after the final source freeze; earlier gate results and environment corrections are recorded below.

## Inspected authority

The complete release55 invocation journal, worker claim/heartbeat/finish/cancellation, link enqueue, reconciliation/settlement and evidence snapshot functions were inspected. `invocation_start_core` commits a unique per-category started row before provider I/O. A completed replay must match its attempt/input/request/lease and returns the stored observation. An unresolved started row refuses another call. This boundary can retain uncertainty without a new provider idempotency protocol.

Release55 `authorize_invocation` is deliberately a single-step, step-zero gate. `reconcile_settle` can write `remediated`. Neither is ordered authority. The private release61 path must replace the parent admission/lease checks and consume pinned evidence itself; public55 readiness stays exact55. Historical functions and existing public repositories are not edited.

The historical enqueue core publishes a generic `test-jobs` outbox record. Task 9 creates the canonical child/link privately without an outbox record. This leaves invocation dormant. The actual per-category journal and existing-test finish verification remain the intended pinned execution boundary; configuration/target source locks must not introduce blocking inversion beneath ordered locks.

Budget53 step reservations consume a slot permanently, including restart and unknown outcomes. They have no refund/delete operation. Task 9 keeps that contract: one reservation for step one, never a replacement or refund.

## Focused evidence so far

From `services/platform`:

```sh
go test ./apiserver -run '^TestSecurityAgentMultistepTestClaimPostgres$' -count=1 -timeout=5m
```

RED in 13.307s on the base. The real private application/deployment repositories created `temporary_policy_applied.v1`; progression created the successor approval and the API principal approved it. The expected claim failed at missing `zasp_sa_multistep_prior.test_action` (SQLSTATE 42883). No owner-created application acknowledgement, control or receipt was used. An earlier 9.647s setup failure used fixture index1100, exceeding the existing three-digit ID helper; index900 fixes that test setup and is not counted as a behavior RED.

The first implementation attempt reached a PL/pgSQL ambiguous `audit_id` reference. The column now has a table qualifier. Readiness measurements still fail closed when the registered fingerprint changes; no readiness check is bypassed.

Claim and lease heartbeat/recovery are GREEN:

```sh
go test ./apiserver -run '^TestSecurityAgentMultistepTest(Claim|Lease)Postgres$' -count=1 -timeout=5m -v
```

26.993s, claim12.87s and lease13.01s. Stable child and reservation survive exact claim replay and expired pre-invocation lease recovery. A stale worker cannot renew the recovered lease. Recovery refuses any retained invocation journal, rather than resending provider work. The preceding intended heartbeat RED was22023 `ordered test operation rejected` in the26.669s claim/lease run.

The private Go successor response boundary was RED at the absent method1.158s, then GREEN1.555s with literal canonical child/reservation IDs and malformed state/version/identity/bounds refusals. The private journal client was RED at the absent ordered conversion0.918s, then GREEN1.119s. It reuses the existing strict journal decoder behind a fixed private-query allowlist and exact61 pins; it does not alter the public55 client.

Dispatch plus exact replay was GREEN13.951s. The next resolver test was RED14.283s with missing private function42883. A clone-anchor failure9.178s exposed the published67-byte start-core name's PostgreSQL63-byte truncation; the exact anchor now uses its stored identity. A14.432s SQL42702 failure exposed a duplicate join column; the lease join is now explicitly scoped. The controlled-TLS child then reached the intended private readiness RED16.329s. These intermediate syntax/readiness failures are not counted as feature proof.

Every SQL change is measured against the live registered fingerprint. Mismatches refuse migration until the exact pin is updated. No readiness check is bypassed. Historical child writers can acquire child before definition/source locks, so ordered invocation uses `FOR UPDATE NOWAIT` for the child after its ordered authority. This does not wait in the inverse order or block a safety writer.

## Dormant authority implemented

Three new release61 fragments install private test claim/dispatch, immutable input preparation, and settlement authority. No published function is replaced. The release55 start and finish cores are cloned into the existing private release61 schema, with exact source anchors and replacements limited to the ordered parent/lease and readiness checks. The registered fingerprint binds those private definitions, tables, policies and ACLs. Demotion drops the private schema only after the existing unused-authority gate and exact predecessor restoration.

`test_action` accepts only canonical step one of the admitted pair. It checks the current approved version-two approval, requester/approver separation and permissions, predecessor application receipt and active control/deployment, plan and input digests, budget, stop state and release pins. Claim creates one canonical child and link, one stable consumed step reservation and one effect lease. It publishes no outbox message. Heartbeat renews the child and effect together. Recovery is scoped to that exact child and refuses any retained invocation journal. Organization admission serializes ordered writers; child and external test/source locks use NOWAIT where a historical writer has the opposite relation order. A safety writer can finish while ordered work refuses and retries.

The private repository reads an immutable input artifact through `artifactstore.Store`, validates its exact canonical key, version, hash, size and closed payload, then stores those bytes in an immutable release61 preparation table. Private dispatch uses the real release55 target resolver. The private adapter reuses the existing strict Go journal request/response decoder behind a fixed SQL allowlist and exact61 pins. The actual per-category journal commits `started` before HTTPS I/O. A completed observation survives a lost acknowledgement and process/connection restart without another provider call. An uncertain `started` observation is never resent.

Settlement reads actual immutable input/output versions. SQL reconstructs the exact allowed evidence document from the completed journal: test/target/version, ordered categories, request and response digests, safety/credential resolution and secret-version digest, comparison identity, Promptfoo0.121.19, curated pack/check/prompt/assertion identities, runner image, redaction policy and artifact manifests. It invokes the pinned finish core and writes the actual immutable child attempt. The same transaction records the bound snapshot, result digest, audit, link settlement and `existing_test_settled.v1`, then moves step one to succeeded and the aggregate to contained only for all-protected observations. Reproduced or mixed observations yield needs_human. The temporary control stays active and its cleanup ownership is untouched. No path produces remediated.

An explicit private uncertainty operation requires an actual unresolved started journal and current worker lease. It records needs_human/inconclusive/unknown_outcome without a typed terminal receipt or fabricated attempt. Budget reservations stay consumed, provider uncertainty stays visible, cleanup remains required. Error artifacts, missing evidence, cancel, stop or expired/stale leases cannot settle or create proof.

Input bytes are bounded at65536, output bytes at1048576, manifests and dispatch/settlement responses at16384, and action/uncertainty wire messages at4096. Matching SQL and Go checks include recursive duplicate-key rejection and a24-level artifact JSON depth bound. Exactly64KiB input and1MiB output pass with raw-byte hashes; one-byte-over-limit evidence refuses without authority mutation.

## Later focused RED/GREEN evidence

All commands below ran from `services/platform` with `-count=1`.

- Actual TLS invocation first passed in17.366s after the private readiness RED. An immutable artifact dispatch test was RED13.799s at the missing private Go method, then13.910s at the missing artifact-aware SQL signature. It was GREEN17.651s after that boundary was installed. An ALTER syntax failure8.705s was implementation feedback, not behavior proof.
- Initial settlement was RED17.591s at the absent private Go settlement method, after real private dispatch and HTTPS journal completion. A subsequent17.286s run exposed the old flat decoder's rejection of the valid `error_code:null` field. The new artifact decoder rejects duplicate keys recursively while allowing the exact null error field.
- `go test ./apiserver -run '^TestSecurityAgentMultistepTest(Settlement|DispatchedLease|Wire|Unknown)Postgres$' -count=1 -timeout=5m -v` passed wire12.82s, first settlement17.10s and dispatched heartbeat16.00s; unknown was the intended missing-authority RED15.57s, command62.600s. Its preceding43.799s run reproduced accepted nonhex lease tokens and a missing child heartbeat, then found PostgreSQL's regex repetition limit for the512-character artifact version bound. SQL now checks length separately.
- A current-authority evidence matrix was RED23.036s because deleting step one's reservation still allowed containment. Exact reservation count is now checked before settlement. Unknown, evidence, reproduced and mixed paths use actual controlled HTTPS journal observations, never owner-written positive evidence.
- `go test ./apiserver -run '^TestSecurityAgentMultistepTestWaitPostgres$|^TestSecurityAgentMultistepTestArtifactJSON$' -count=1 -timeout=5m -v` was GREEN78.872s. The real PostgreSQL wait schedules took77.71s: two claims yield one lease; cancellation or stop before the wait refuses the claim; schema fencing precedes run locks; heartbeat expiry during an audit wait rolls back; a child safety writer succeeds while ordered work refuses NOWAIT. An earlier55.878s test batch passed unknown16.45s and evidence21.75s, but reused a fixture role across schedules; those setup-only errors were fixed by separate owned clusters.
- A settlement audit wait past the old lease deadline was GREEN18.28s. The accompanying cancellation race exposed the existing private transition decoder rejecting the valid cancelled parent with an executing canonical step one (16.39s RED). The literal response test was RED1.396s too.
- Parent-authorized compatibility adjustment: the existing cancel-only `blocked/cancelled/executing` response allowance now accepts either canonical step of the exact pair. It still requires cancel, canonical approved approval/version2, cancelled parent and the exact run-version increment; every other impossible state remains refused. This small change to the prior private progression repository needs explicit independent review.
- `go test ./apiserver -run '^TestSecurityAgentMultistep(TestCancellationResponse|ApplicationCancellationResponse|TestCancellationPostgres|TestMixedPostgres|TestBoundsPostgres|TestEvidencePostgres)$' -count=1 -timeout=5m -v` was GREEN75.521s: prior step-zero decoder0.18s, new step-one literal and14 near-misses0.30s, evidence/repository matrix23.22s, actual mixed observations17.52s, exact artifact bounds16.84s and actual cancellation race16.35s.
- `go test ./apiserver -run '^TestSecurityAgentMultistepTestDispatchedRecoveryPostgres$' -count=1 -timeout=5m -v` was GREEN17.988s. Before any journal start, both expired leases recover onto the same child, reservation and immutable input, with a new token/attempt; the actual provider path then succeeds. Recovery after any journal start remains refused.
- Invalid worker syntax was a focused repository RED0.967s. All four new private Go methods now use the same worker pattern as SQL. `go test ./apiserver ./redteamadapter -run '^TestSecurityAgentMultistepTest(RepositoryBoundary|ArtifactJSON|CancellationResponse)$|^TestOrderedJournalPrivateBoundary$' -count=1` was GREEN, apiserver2.086s and redteamadapter0.891s.
- Metadata checksum source-list test was RED0.474s after adding the fragments. Its exact expected list now includes all three files; no fingerprint check is weakened.
- Terminal replay drift was RED in 42.425s: changed effect input/attempt and child version/verdict/artifact were accepted. The immutable snapshot now binds the full terminal child plus the effect identity and attempt. `go test ./apiserver -run '^TestSecurityAgentMultistepTest(Unknown|Evidence)Postgres$' -count=1 -timeout=5m -v` was GREEN in 40.093s (unknown 16.85s, evidence 22.13s). Effect deletion is already blocked by the existing link FK23503.
- The remaining terminal near-misses were RED in 40.923s: effect outcome/result/cleared-lease and reconciliation version/response drift could replay. Immutable link identity and exact terminal postconditions now refuse those cases. Three matching pre-settlement drift cases (already-set effect outcome/result and changed link version) were RED in 41.912s; the live invocation gate now requires an unresolved effect and the untouched pending link. The same focused command was GREEN in 40.795s after both fixes, unknown 16.95s and evidence 22.78s. No source changed after that GREEN except this report.
- `go test ./migrations -run '^TestSecurityAgentMultistepCandidateMetadata$' -count=1` was GREEN in 0.285s. One preceding selector used the wrong test prefix and ran no tests; it is not counted as verification.

## Proof boundary

The HTTPS provider is a controlled local TLS server, with real signed request validation, PostgreSQL journal start/completion and lost-ack replay. This is not a live provider, cloud object store or Promptfoo container execution claim. Native artifact fixtures are built from the actual completed journal and exact pinned evaluation contract, then read through a real `artifactstore.Store` with an immutable in-memory driver. Owner SQL is used only for configuration before admission or explicit negative drift faults, not acknowledgement/invocation/terminal settlement evidence.

Public55 readiness still refuses61. Generic worker/outbox routes, public existing-test repositories, cleanup aggregation, API/CLI/UI activation and all other action pairs remain closed. Engine-error/incomplete evidence stays unresolved or needs_human through the real uncertainty lane; it never becomes a terminal success receipt. Task10 must own cleanup aggregation.

The invocation worker's explicit uncertainty transition requires its current valid lease. A separate private security-agent worker operation now closes an orphaned expired started or completed-but-unsettled journal. Stop, cancellation and changed current authority still refuse; neither worker may resend uncertain provider I/O. No generic expiry scheduling is activated.

## Completion audit: crashed invocation workers

The parent asked for a completion audit of the previously recorded expired-worker limitation. Inspection confirmed there was no deterministic release61 close: the live uncertainty call requires an active lease, while recovery refuses every existing invocation journal. I reproduced that gap using the actual controlled HTTPS unknown-outcome journal after its child process exited. The positive expiry close was RED in 17.232s at missing `test_reconcile_uncertain` (42883); the strict private repository response boundary was RED in 1.109s.

`test_reconcile_uncertain` belongs to the security-agent worker principal, separate from the invocation/settlement red-team worker. Its private Go request has exactly nine fields and no lease token or provider payload. Shared schema fencing precedes Organization/budget/run/plan/step/effect/child locks. It requires the exact current plan/link/definition/approval/control/deployment/reservation, expected run/effect versions, matching current child/effect attempt and token hash, both lease expiries, and an actual unresolved started journal with current target/comparison identity. A missing journal, live lease, stale version, stopped/cancelled parent or authority drift refuses without mutation.

It atomically marks needs_human/inconclusive/unknown_outcome/failed, retaining the started journal and both reservations. There is no provider call, fabricated child attempt or terminal receipt. A canonical audit binds the request, expired lease evidence, full post-close snapshot and exact response; replay is read-only and rechecks current authority. The temporary control and cleanup_pending effect remain untouched.

The first implementation check exposed the published target resolver's correct refusal of a security-agent principal (17.825s, then direct SQL diagnosis in 18.464s). A private, ungranted read-only clone changes only that principal predicate. Its pinned target validation and NOWAIT source locks are unchanged; historical resolver source and ACLs are untouched. The clone is in the registered fingerprint and is dropped with the private schema on unused demotion.

First expiry GREEN was 18.232s, including actual Go/SQL close, exact replay and ten current-authority negatives. The final focused packet was:

```sh
go test ./apiserver -run '^TestSecurityAgentMultistepTest(ExpiredUnknown|ExpiryRace|ExpiryStop|ExpiryCancel|ExpirySettlement)Postgres$|^TestSecurityAgentMultistepTestExpiryResponse$' -count=1 -timeout=5m -v
go test ./apiserver -run '^TestSecurityAgentMultistepTestExpiryNoJournalPostgres$' -count=1 -timeout=5m -v
```

GREEN in 79.340s: expired close/current and terminal drift matrix 17.22s; stale invocation worker versus expiry reconciler 14.96s; stop committed during the wait 14.89s; real private cancellation committed during the wait 15.19s; valid current immutable settlement wins before expiry 15.60s; closed response positive/near-miss matrix 0.37s. The no-journal refusal was GREEN in 13.722s. No provider evidence was owner-inserted. Owner clock faults only made the two existing lease deadlines expire.

## Source freeze and grouped gate

Registered fingerprint: `058dbad9dc9a7cd94eccd6fd10e71613ab95080effcd9459b2044399184124ca`.
Candidate fingerprint unchanged: `2941a7ee76eb6af211f0329a9f16bace0b63dbdd22023280a98a4baa55529d98`.

The staged code/test scope is 28 files: five prior Task7/Task8/release61 files and 23 uniquely named Task9 files, 3432 insertions and 9 deletions. `gofmt -l` is empty and `git diff --cached --check` passes. A diff against the base for historical release22, release55 and all existing-test fragments is empty. No public repository, worker or historical SQL is staged. The report will be the 29th scoped file. The 1044 unrelated status entries match the pre-freeze snapshot.

From `services/platform`, after the corrected freeze:

```sh
go test ./apiserver -run '^TestSecurityAgentMultistep' -count=1 -timeout=30m
go test ./migrations -count=1 -timeout=30m
go test -race ./apiserver ./agentsec-worker ./redteamadapter -run 'TestSecurityAgentMultistep(Application|Deployment|Progression|Test)|TestSecurityAgentOrdered|TestSecurityAgentWorkerRepository|TestSecurityAgentActionProcessor|TestOrderedJournal' -count=1 -timeout=30m
go test ./apiserver ./agentsec-worker -run '^(TestSecurityAgentExistingTest(Worker.*|Journal.*|Invocation.*|Settlement(Postgres|VersionBoundaryPostgres|RecoveryPostgres|StoppedPostgres)|Cancellation.*|StoppedLeased.*|Failure.*|Binding.*|Preparation.*|Reconcile.*|Final.*|Legacy.*|CompiledFingerprint.*|Release.*)|TestLinkedRedTeam.*|TestRedTeam.*|TestExistingTest.*|TestProductionRedTeam.*|TestProductionSecurityAgentTemporaryPolicy.*|TestProductionPolicyDeployment.*|TestSecurityAgentAction.*|TestTemporaryPolicy.*|TestPolicyDeployment.*|TestComposePolicyDeployment.*|TestLoadSecurityAgentActionPrivateKey.*)$' -count=1 -timeout=30m
ZASP_RECONCILE_CLIENT_BINARY=/tmp/zasp-task9-legacy.XmTKyZ/worker.test ZASP_LINKED_TLS_TEST_BINARY=/tmp/zasp-task9-legacy.XmTKyZ/adapter.test go test ./apiserver -run '^TestSecurityAgentExistingTest(StoppedQueued|SettlementProcessRestart)Postgres$' -count=1 -timeout=10m
go test ./artifactstore ./redteamadapter -count=1 -timeout=10m
```

The first, superseded gate passed migrations in 18.784s, artifactstore in 0.458s and redteamadapter in 1.188s. Its race parent had the old fingerprint while the runtime-built child picked up the expiry correction; exact readiness correctly refused that mismatch. That group ended in 941.272s (worker 8.310s and adapter 2.875s passed). The first full multistep group ended in 1092.881s with the same old-parent/new-child readiness mismatch. Neither is counted as a final pass.

The first legacy group ended in 719.366s with two explicit setup failures: stopped queued and settlement process-restart require `ZASP_RECONCILE_CLIENT_BINARY`. Worker tests passed in 12.338s. I built the registered test binaries with `go test -c -o /tmp/zasp-task9-legacy.XmTKyZ/worker.test ./agentsec-worker` and `go test -c -o /tmp/zasp-task9-legacy.XmTKyZ/adapter.test ./redteamadapter`, then supplied both environment variables for the fresh gate. No test was omitted to hide a failure.

The second gate passed migrations in 18.619s, artifactstore in 0.297s, redteamadapter in 1.158s, full multistep in 1215.557s, and the race group in 1073.080s (worker 7.627s, adapter 2.174s). This gate predates the completed-journal extension below and was rerun after its source freeze.

The second legacy command ended in 814.578s with settlement claim mismatches in the ordinary settlement, version-boundary and stopped-settlement fixtures. Worker tests passed in 12.886s. Root cause is the global test environment: `assertExistingTestEvidenceSnapshot` calls the optional registered client before its immediate SQL settlement assertion. With `ZASP_RECONCILE_CLIENT_BINARY` set, that client claims and releases the link with a 300-second delay, so the next immediate claim correctly returns an empty array. The final legacy gate will separate ordinary fixtures (binary unset) from the two fixtures that require it (stopped queued and process restart). No historical fixture or production source was changed to accommodate this test environment.

The test child process built for controlled TLS invocation does not use `-race`; the race group covers the parent repository schedules and the adapter unit boundary. No stronger child-process race claim is made.

Independent review belongs to the parent review process under the explicit no-subagent instruction. The cancel-only step-one decoder allowance and separate expiry-reconciliation principal are called out for that review. No public activation or cleanup aggregation is included in this packet.

## Completion audit: completed journals without settlement

The parent required the crash boundary after every category has completed but before immutable artifact settlement too. The focused test invokes two real categories, lets the child process exit, stores the exact output artifact, then expires both existing leases. It was RED in 19.631s: the private expiry SQL still required a started row and returned 40001 `ordered expiry journal changed`. Ten current-authority refusal cases already passed. A deterministic expired-reconciler versus stale-settlement schedule was RED in 18.175s for the same refusal.

The response test was RED in 1.474s: the old closed decoder rejected both new positive responses and accepted a response with the new journal status missing. Its two exact allowed pairs are `started`/`test_outcome_unknown` and `completed_unsettled`/`test_evidence_unsettled`; absent, null, unknown and mismatched pairs must refuse. The decoder's first GREEN was 1.496s.

The production change is restricted to the existing private expiry function and Go decoder, plus the measured readiness pin. It requires at least one current journal row, classifies any retained started row as unknown, and classifies an all-completed journal without settlement as unsettled evidence. Both paths require the exact expired child/effect leases and current authority, produce needs_human/inconclusive/unknown_outcome without any receipt, and bind the distinct reason into the immutable audit/replay response. No provider resend or artifact write is possible through this boundary.

```sh
go test ./apiserver -run '^TestSecurityAgentMultistepTest(Expired(Unknown|Completed)|Expiry(Race|Stop|Cancel|Settlement|NoJournal|CompletedRace|CompletedStop|CompletedCancel))Postgres$|^TestSecurityAgentMultistepTestExpiryResponse$' -count=1 -timeout=6m -v
```

GREEN in 159.537s. Started and completed expiry close/replay/negative matrices passed in 18.12s and 17.98s. Started stale-worker, stop and cancel schedules passed in 15.00s, 14.81s and 15.26s; valid settlement wins in 15.80s. Completed-journal stale-settlement, stop and cancel schedules passed in 16.22s, 16.04s and 16.23s. Empty-journal refusal passed in 12.45s, and the strict response matrix in 0.52s. Stored output artifact bytes remain exact after reconciliation. The live registered fingerprint was measured first; the stale compiled pin refused in 9.209s before the exact replacement. Metadata tests passed in 0.502s.

The isolated legacy diagnosis command, `go test ./apiserver -run '^TestSecurityAgentExistingTestSettlement(Postgres|VersionBoundaryPostgres|StoppedPostgres)$' -count=1 -timeout=5m -v`, passed unchanged in 123.801s with the optional client binary unset.

`go test -list` enumerated 158 tests in the original affected-legacy selector. The final split covers exactly those tests: 156 ordinary cases and two binary-required cases, with no omission or overlap.

Final grouped results, all GREEN on the frozen source:

| Gate | Time |
| --- | --- |
| Full multistep PostgreSQL | 1318.356s |
| Full migrations | 18.871s |
| Race | apiserver 1173.157s; worker 8.295s; adapter 2.886s |
| Ordinary affected legacy | apiserver 718.778s; worker 12.977s |
| Binary-required stopped-queued/process-restart | 73.258s |
| Artifactstore and adapter | 0.471s; 1.380s |

The staged code/test diff stayed at SHA256 `b93205642afe8a4608217c793b3dfd3cbe65d22fd664e72c26c269b2870c4ef6` throughout the final gate. Only this report changed while tests ran. All owned test handles completed; no test failure is deferred. The remaining concerns are the stated controlled-provider/artifact proof boundary and the explicitly deferred cleanup/public-worker activation, not an unrecoverable journal crash state.
