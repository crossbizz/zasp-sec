# P4B fix1 final handoff

All 33 top-level installed discovery cases have passing case evidence on the reviewed source, across the timed-out full command and the passing unfinished-only command. The timeout remains a failed package run. Independent source re-review found both original findings addressed and no new actionable defect; the controller owns final local acceptance. See `docs/internal/2026-09-22-temporal-openfga-p4b-fix1-review.md`. The original P4B packet is unchanged.

Source-only review checkpoint: 11 application/test/retirement files are frozen separately as `p4b-fix1-source-review.{json,diff}` with `p4b-fix1-source-review-hashes.json` and a static report snapshot. The controller independently verified the 11 source hashes and five packet hashes, then resumed the independent reviewer while the same installed process continued. The source-review manifest SHA256 is `c4d668541848b19466859f13320f748131db69c99eff1d33ff69867a29491c9b`. This ongoing report and the final evidence manifest are separate. Final capture must compare every source-review hash and refuse drift.

The first full installed command was session **91184**, started from `services/platform`:

```text
go test ./agentsec-migrate -run '^TestTemporalDiscovery.*Postgres$' -count=1 -timeout 45m -v
```

Its output is `p4b-fix1-final-installed.log`. It failed at the 45-minute package timer, with 30 of 33 top-level cases passed and continuation still active. The package result is FAIL 2758.936s. It is not an aggregate package pass.

After exact owned-resource cleanup and a fresh comparison of all 11 reviewed files plus all 204 historical SQL files, the controller authorized only the three unfinished cases on the same source. Session **18716** completed this command from `services/platform`, logged to `p4b-fix1-final-remaining.log`:

```text
go test ./agentsec-migrate -run '^TestTemporalDiscovery(Continuation|ShippedRuntime|TenantIsolation)Postgres$' -count=1 -timeout 35m -v
```

This remaining command passed 1121.725s, including real local Temporal continuation/manual/periodic/isolation cases, not just SQL contract fixtures. Completed cases were not restarted. Both command handles are closed.

This fix addresses symmetric retained/72 discovery generation ownership (P1) and organization-wide `max_active_jobs`, configured or default 4, across both owner families (P2). It does not retire all retained execution, implement P4D recovery, or establish deployed provider/FGA authorization proof.

## What changed so far

The additive 72 authority now counts durable active owners, including unresolved preparation after a retained lease expires or a job reports an unknown outcome. Generation ownership and organization capacity use the existing transaction-level quota lock. A failed try-lock permits no claim, generation or effect. Temporal owns waiting through advancing no-IO receipts; these receipts are not permission to call a provider.

The lock order matters. Retained claim keeps its existing quota-before-job order. Input and 72 preparation can already hold scoped provider/run locks, so their shared quota acquisition uses `pg_try_advisory_xact_lock`, never a blocking reverse-order wait. Acquisition requires READ COMMITTED so the next authority query can see committed owners. Direct input contention raises 55P03; the shipped claim wrapper returns typed busy for a nonterminal blocked job. Both preserve retry delivery. The separate preexisting recovery-scope lock can still block persistence of a no-IO wait receipt; the replica test observes and releases that transaction explicitly before asserting progress.

Retained generation preparation records exact scope, job, attempt, generation, snapshot, worker, lease-token digest, and pre-dispatch checkpoint version/digest in a private FORCE-RLS table. Repeating the same attempt cannot authorize another dispatch. A later attempt requires a recorded safe partial completion and its exact, strictly advancing checkpoint. Reusing an existing generation also checks that prior preparation directly at the input boundary. Unknown preparation remains explicit pending evidence. Elapsed time alone cannot release it.

Self-review found and reproduced a cutover case: a job already leased and prepared before 72 had no dispatch receipt, so a repeated input call on that same live lease could look like a first dispatch. The corrected guard distinguishes a new generation from an existing one. An existing pre-72 generation without exact safe completion evidence is quarantined, even if its lease is still live. It remains visible in durable generation/job state and active capacity accounting. A genuinely in-flight old operation may still supply verified completion evidence through retained authority; the new guard does not synthesize a safe retry. Automatic recovery of unproved pre-72 work is not implemented here and remains a P4D/P9 cutover gate.

The shipped retained delivery repository uses the typed 72 wrapper when current 72 is installed. Present-invalid 72 fails closed. Old direct delivery calls that hit the row guard can fail with SQLSTATE 23502 because their historical response code assumes an UPDATE returned a row. That obsolete direct-entrypoint limitation is temporary P9 debt: the entire statement rolls back, it grants no claim or effect, and supported shipped callers receive typed busy responses instead. There is no broad 23502-to-busy mapping.

The supported SQL13 bulk claimant filters blocked ownership/capacity before its LIMIT and checks again at mutation. SQL10 discovery access was already revoked by SQL13; its runtime route and ACLs are unchanged. The bounded compatibility handoff saves and attests the original SQL13 claimant, SQL13 fingerprint and SQL60 identity helper before replacement. Only the approved exact function entries are projected. Actual replacement bodies, live security attributes, saved originals and private helpers remain independently pinned by 72. No historical expected pin is refreshed.

Retained JSONB credential configuration is canonicalized on hydration without dropping fields. Existing credential decoders still reject unknown, invalid and mixed-provider content before IO. The installed mixed-owner test exposed this spacing mismatch, which previously produced a failed `malformed` sync even though the processor returned nil after its failure ACK. The child now asserts actual typed nonempty application and succeeded completion; the parent independently checks persisted results.

## The apply defect exposed by the mixed-owner proof

The same-account, different-integration collector case reaches complete snapshot application and fails SQLSTATE 23503 on `zasp_inventory_relationships_organization_id_workspace_id_fkey3`. This is the relationship-to-snapshot composite FK, not an entity-endpoint FK.

AWS relationship IDs omit integration. SQL14's relationship upsert conflicts by scoped relationship ID, updates `snapshot_id`, and preserves the first row's `integration_id`. A second connector for the same provider account generates the same relationship ID, then the upsert pairs the first integration with the second snapshot. The FK correctly refuses it. The fixture uses legitimate overlapping account/resources and must remain unchanged.

The controller-approved correction preserves raw provider/artifact IDs and shared entity IDs. The private 72 normalizer checks raw field types, complete relationship schema, IDs, duplicate IDs/native identities and collisions before preserving an existing edge ID for its exact tenant/integration/source/native identity, or deriving a new integration-scoped ID through the existing public canonical helper. This applies to all four providers. It does not change entity identity rules, the inventory FK, or historical writer bodies.

For 72, `record_page` retains the raw request digest for immutable input replay, then computes the complete receipt over the normalized candidate and persists that candidate. A repeated call checks the raw digest and returns the recorded result without consulting later inventory. Application and all projection inputs consume the persisted normalized candidate.

The retained apply wrapper verifies its current registered principal, actual job lease and exact prepared attempt/generation/snapshot/token digest. Its first successful application atomically stores a raw request digest and normalized relationship body in that preparation row, then calls the unchanged typed writer. Later identical requests use the stored body. A changed request conflicts. Failed application rolls back both mapping evidence and inventory writes.

The compatibility test first writes an edge through the unchanged historical apply function, then replays it through the new wrapper. Its original noncanonical edge ID remains intact. A controlled, restored fixture mutation of the live relationship ID proves retained replay does not recompute its candidate from mutable inventory. A complete 72 receipt also replays after the other connector's later observation. The parent checks two shared entities and two connector-owned edges, persisted projection payloads, collision refusal and an explicit empty domain snapshot that removes only one connector's edge. That removal is installed domain-application evidence, not a claim that the cloud double deleted resources.

## Evidence chronology, not filename interpretation

Logs live under `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/`, with the `p4b-fix1-` prefix. Exact final commands and hashes will be frozen after the remaining work.

- `acquisition-red.log`: compile-only fixture failure, not behavioral RED. `acquisition-red2.log`: FAIL 48.544s, reproduced both a retained claim overlapping unresolved 72 work and a second integration obtaining an effect at quota 1. Owned PostgreSQL joined normally.
- The first candidate catalog run failed against the old compiled pin. `acquisition-green.log` then passed 80.382s for the initial ownership/capacity/authority surface, before the later bulk compatibility correction.
- `dispatch-red.log`: behavioral FAIL 0.917s, valid 72 used the old route and invalid 72 fell back. `dispatch-green.log`: race PASS 2.060s.
- `bulk-preparation-red.log` was compile-only. `bulk-preparation-red2.log`: FAIL 47.968s; retained preparation passed 23.19s, actual limit-1 independent-tenant progress failed 23.87s with no claimed items.
- The first bulk catalog candidate failed 42601 because a generated function body contained its own dollar-quote delimiter. The next candidate run supplied the independently compiled pin. `bulk-handoff-green.log`: PASS 78.506s, including retained preparation, limit-1 fairness and authority drift checks. Original predecessor fingerprints remained unchanged.
- `collector-io-first.log`: FAIL 138.684s. A child's nil processor return was insufficient evidence; the parent correctly rejected persisted success. `collector-io-diagnostic.log`: FAIL 40.738s, with the retained sync failed/malformed and its owner still retained. This established the credential JSONB hydration defect.
- `retained-json-red.log`: behavioral FAIL 0.948s. `retained-json-green.log`: race PASS 2.115s. Expanded configuration regressions are recorded separately.
- `collector-io-green.log` is a failed group, FAIL 171.699s. Both same-resource acquisition orders passed their child and strict parent assertions (42.64s and 44.30s parent cases). Both different-integration quota cases failed at application. `quota-io-diagnostic.log`: FAIL 44.641s, recording the exact relationship-to-snapshot FK error above.
- `safe-resume-first.log`: PASS 24.826s, exact safe checkpoint/completion allowed the next retained attempt with unchanged generation; stale completion did not.
- `replicas-default-first.log`: test timeout, FAIL 180.752s. The fixture awaited a second transaction while holding a first transaction that blocked its no-IO wait receipt through the preexisting SQL27 recovery-scope advisory lock. Read-only `pg_stat_activity`/`pg_locks` checks found the first connection idle in transaction and the second waiting on that exact lock, not the quota lock. This was a fixture wait cycle, not evidence of a production deadlock. The timed-out parent could not join its owned PostgreSQL. The exact owned data directory was stopped using `pg_ctl stop -m fast -w`; `replicas-owned-cleanup.log` records success. No shared instance or data was removed.
- `replicas-default-green.log`: FAIL 47.667s. The replica diagnostic query lacked explicit text types (42P18); default capacity passed 24.24s. The corrected asynchronous fixture observes the exact recovery lock before releasing the first transaction, joins the second query, checks no first-owner mutation, then commits a fresh second-owner preparation and proves another replica cannot acquire capacity. `replicas-green2.log`: PASS 28.118s (case 27.27s), owned PostgreSQL joined normally.

Later evidence:

- `ownership-expanded-green.log`: PASS 115.238s, including unresolved 72 retention, direct-old rollback, shared capacity, retained preparation, independent-tenant bulk progress with actual retained SQL10 runtime behavior, and exact safe resume.
- `retained-config-group-green.log`: race PASS, apiserver 2.141s and worker 3.269s. Valid noncanonical configuration is accepted after hydration; unknown, invalid and mixed-provider configuration is refused before IO.
- `apply-route-red.log`: behavioral FAIL 0.929s, current 72 used the old apply route and invalid 72 fell back. `apply-route-green.log`: race PASS 2.144s.
- `collector-identity-green.log`: PASS 184.642s, all four actual collector cases with strict parent success/release/nonempty inventory assertions. This preceded the stronger identity compatibility assertions and cutover guard.
- `identity-validation-red.log`: behavioral FAIL 25.614s, numeric raw `source_native_id` was accepted by normalization. Explicit JSON string-type validation fixed it. `identity-compatibility-green.log` selected only the mapping test and passed 23.642s; it was not the requested combined case. `identity-compatibility-green2.log`: FAIL 118.771s because the new removal fixture called `settle` with six arguments instead of nine. Both children passed their retained replay checks; the parent group remained failed.
- `preexisting-red.log`: behavioral FAIL 23.228s, a pre-72 unresolved generation obtained another input after 72 installation. The added existing-generation safe-receipt check closes that path.
- `cutover-identity-green.log`: PASS 215.611s. Preexisting quarantine 26.72s, both quota collector/compatibility/removal cases 98.00s, retained safe resume 24.86s, four-provider mapping/validation 24.82s, and installed authority/tamper/exact-role checks 40.19s. Every owned PostgreSQL instance joined normally.
- `final-race.log` is an overbroad failed verification command. `TestProduct.*` also selected unrelated `TestProduction*` tests. Apiserver failed 241.022s: the sensor-agent child build required a `go.mod` update, then the package timed out during `TestProductionSecurityAgentActionNaturalRecovery/create_temporary_policy/work`. These remain separate unresolved full-suite/P8 debt. No dependency files were changed to hide the failure. Its orphan test-owned PostgreSQL, PID 34641, was stopped successfully using its exact `TestProductionSecurityAgentActionNaturalRecoverycreate_temporar3029284471/001/data` directory; `broad-race-owned-cleanup.log` records that stop. The timeout did not complete the original parent's join. No shared instance or data was removed.
- `final-race-focused.log`: corrected selector race PASS, apiserver 2.180s, worker 2.856s, orchestration 1.651s. The installed-only child tests explicitly skipped without their parent environment. They are not counted as integration proof here.

The exact focused race command, from `services/platform`, was:

```text
go test -race ./apiserver ./agentsec-worker ./orchestration -run '^(TestRetainedDiscovery.*|TestDiscoveryExecutionRepository.*|TestProductionDiscoveryCredentials.*|TestDiscoveryProduct.*|TestTemporalDiscoveryNoIOWaitReadback|TestDiscoveryWorkflow.*|TestDiscoveryStartDelivery.*|TestDiscoveryArtifactCache.*|TestProductDiscovery.*)$' -count=1 -timeout 3m -v
```

The controller's read-only sensor diagnosis is recorded separately in `docs/internal/2026-09-23-sensor-module-verification-gap.md`: `go list -mod=readonly ./...` reproduces the build failure, and `go mod tidy -diff` identifies stale sensor-module metadata against its `../platform` replacement. No module files were changed. That document is outside this fix1 source packet; the build follow-up remains distinct from the NaturalRecovery timeout.

The final installed run's package timer fired during `TestTemporalDiscoveryContinuationPostgres`, then active for 9m42s. The first read-only post-timeout observation was collecting/checkpoint 177/pages 178 with the original deadline still current; by deliberate cleanup, it had advanced to checkpoint 187/pages 188. These are post-timeout observations, not an atomic capture of the exact panic checkpoint. No workflow terminal outcome was reported. The host had elevated load during this run, but the measured cause of this interruption is the package's 45-minute timer; no product deadlock or product deadline expiry is established.

The interrupted parent could not join its child or PostgreSQL. I positively matched the fixture's exact canonical workflow ID through Temporal description to `p4b-owned-1790207887419314000`, then stopped only child PID 56064, its Go wrapper PID 56056, and PostgreSQL PID 55643 using the exact owned `TestTemporalDiscoveryContinuationPostgres1043518987/001/data` directory. The existing namespace cleanup helper verified the namespace's ownership description and retired it (PASS 2.112s). A process check confirmed those PIDs were gone. Logs: `continuation-owned-identification`, `final-timeout-owned-cleanup`, and `final-timeout-namespace-cleanup`, each with the fix1 prefix and `.log` suffix. This was explicit failed-test cleanup, not normal parent cleanup or passing continuation evidence. No shared resource or data was removed.

The reviewed, unchanged catalog pin is `b8b6cca0dd01e2b6a5ed03917def976434f37746a93413ad5a42bc3917b6a253`. Installed authority, drift checks and the final remaining group used this pin.

The unfinished-only group's continuation case passed 938.14s, with its real-Temporal child passing 910.44s (worker package 911.485s). The child checked the actual Continue-As-New receipt at 256, cold worker restart from verified versioned storage, 267 provider pages and 534 artifact objects. The parent separately checked a succeeded run, unchanged original deadline, 267 persisted page effects/checkpoint version 267, generation 1, 258 inventory entities in the snapshot input, three projection records and no legacy job rows. Namespace `p4b-owned-1790208520278981000` was retired and owned PostgreSQL joined normally. Intermediate 64/128/192/256 log markers were provider request counters, not proof of committed receipts. The terminal assertions supply that proof.

Shipped runtime passed 83.73s (child 56.47s, worker package 57.723s): three succeeded initial/manual/scheduled syncs, three nonempty snapshots, nine projections, three published outbox rows and no legacy jobs. Later discoveries had zero newly discovered objects, preserving deduplication semantics. Tenant isolation passed 99.14s (child 72.50s, worker package 73.640s): identical-name scoped connectors retained distinct schedules, runs, HTTP receipts and artifact keys; the parent checked four succeeded syncs, four nonempty snapshots, 12 projections and no legacy jobs. Both namespaces were retired and both owned PostgreSQL processes joined normally.

## Packet and remaining gates

The separate fix1 baseline captured 1,983 paths before edits. The controller later requested exact retirement rows; its current retirement TSV was captured separately before my first edit to that file and added as the 1,984th baseline record, with the later capture time/reason recorded in the manifest. The three new rows preserve all existing controller rows and separate temporary retained control flow from shared relationship domain logic that stays.

The final artifacts are `p4b-fix1-scoped.diff`, `p4b-fix1-frozen-source.json` and `p4b-fix1-hashes.json`, produced by `p4b-fix1-capture.mjs`. They include this final report separately from the 11 previously reviewed files. The capture refuses any change to those reviewed files and checks all 204 original pre-72 SQL files against the original P4B baseline. The original packet's historical count 202 meant migration-directory SQL only; the extra two files are under `services/platform/tenantrls/sql`. All 204 remain byte-equal.

`p4b-fix1-final-case-coverage.log` enumerates all 33 source-defined top-level cases and maps each to exactly one terminal PASS: 30 in the timed-out command and three in the unfinished-only command. No case is missing or double-counted. It also verifies the 11 reviewed hashes, all 204 historical SQL hashes and the original baseline/freeze/diff/hash artifact hashes. The two logs contain 36 and three normal owned-PostgreSQL joins respectively; the interrupted continuation's separate explicit cleanup is not counted as a normal join. The earlier P4B packet remains historical local evidence; it does not attest to the changed 72 SQL or retained repository bytes.

P4D must provide an explicit recovery path for retained unresolved preparation. P9 must remove the temporary retained wrapper/bulk compatibility route after backlog/equivalence proof. No pending preparation may be silently discarded or called successful. The controller owns additions to the authoritative retirement ledger.

All original 728 obligations remain. Broad `agentsec-api` root startup is still a mandatory P8 gate. Local provider/storage/credential doubles and OpenFGA readiness doubles are not deployed integration or authorization evidence. The original cold artifact O(n²) scale debt and unexplained checkpoint-40 unknown remain disclosed in the original report.
