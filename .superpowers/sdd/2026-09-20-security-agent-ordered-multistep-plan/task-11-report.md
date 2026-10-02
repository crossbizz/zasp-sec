# Task 11 release61 worker orchestration

Task11 prerequisite packet, based on reviewed
`994263f62c772300e261cb1a9703c3a46bd7b07c`.
No public/default route activation, push, historical SQL change, or live proof.

## Preflight and prerequisite ruling

The initial worktree had 1,044 unrelated entries. The index was empty. The
scoped writing-style.md was absent (also absent in the main checkout); unrelated
Cowork project style files were not adopted. Superpowers TDD and systematic
debugging govern this packet. The private apiserver methods are not exported;
worker composition must remain a separate dormant boundary. Exact readiness
is registered checksum plus fingerprint
`c2a7dab23a9d3c4aa0729869ebaefb372ef65ad4bb6aafe14cda5b6ffa182daa`.

Private mutators take schema admission before Organization/budget/run/step
authority. Application then takes shared deployment/source resources NOWAIT.
Planning bounds caller, lease, budget and pricing; started unknown work is not a
resend permit. Separate planner/action/deployment/test/expiry principals are
required. Cleanup has independent retained safety authority but originally
required a complete application receipt and active control.

That last prerequisite is incompatible with cancellation at a commit boundary.
The preflight reproduced cancellation after source_store and deployment_finish:
actual Task11A worker child creates pricing-bound provider usage, immutable
artifacts and admission; private approval, claim and source/deployment producers
create downstream evidence. Cancellation succeeds, application completion
correctly refuses, but cleanup also refuses. Owner writes seed only configuration
and queued inputs, never success. These are controlled component fixtures;
the inherited planner transport is controlled in-process, not a live provider
or a new TLS combined-process proof.

Controller ruling: correct this load-bearing security prerequisite within
Task11. Authorize cleanup of exactly proven partial application on terminal
cancelled/stopped/deadline parents without manufacturing an application receipt,
control, successful step, or successor permission. Preserve exact source and
deployment identities and unrelated policies. Unknown work cannot resend.
Verified removal must retain a distinct immutable partial-cleanup receipt and
conservative outcome. This requires a release61-only snapshot/cleanup extension,
an updated registered checksum/fingerprint, and restoration/readiness gates;
historical SQL and public routes remain unchanged. Rollback cost and final
manifest will be recorded after implementation.

The controller subsequently directed a separate commit/review checkpoint for
this prerequisite. The worker façade/runtime and complete Task11 orchestration
are deliberately deferred until that independent review. This report therefore
does not claim that full Task11 is complete.

## RED chronology

Working directory for Go commands: `services/platform` in the named worktree.

1. `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$' -count=1 -timeout=5m -v`
   Expected semantic RED: no permitted cleanup handoff at either retained
   source/deployment cancellation boundary. Observed FAIL, package 41.686s,
   source_store 18.13s and deployment_finish 19.39s, both `repository operation
   conflict`. Planning children PASS 5.75s/5.88s with one provider call each.
   Both owned PostgreSQL processes joined normally (pg_ctl and server exit 0).
   The first gofmt command used a repository-relative path from the module
   directory and failed to find the file; corrected to `apiserver/...` before
   the next run. This is not a semantic test failure or production change.

2. Same command with a diagnostic retry below the Go error-redaction boundary.
   The source_store diagnostic confirms SQLSTATE40001,
   `ordered retained application evidence changed`, both cases. FAIL41.495s;
   cases18.31s/19.06s, planning children5.75s/5.83s. All processes joined.

3. Minimal partial-claim correction replaces the receipt-only cleanup FK with
   the scoped step FK and adds an exact retained partial-source snapshot. No
   application receipt/control is created. The first new-pin probe failed as
   expected at exact readiness, package21.749s, fingerprint
   `cdf6baf48eda9e8ea9b7624de23ffc944c92109ba720edd3a13b67a9a379f373`.
   This is metadata refresh evidence, not semantic RED. Updated the compiled
   pin to the independently measured value. Focused GREEN: same two-case
   command with `-timeout=3m`, PASS52.017s; source18.81s/deployment19.33s,
   planning children5.89s/5.92s, PostgreSQL normal exits.

4. Added the next semantic assertion before production receipt changes: exact
   partial cleanup store/read/finish/completion must create only a distinct
   `temporary_policy_partial_cleaned.v1`, remain cancelled, replay exactly,
   and never create an application receipt/control/test child. Focused RED
   command is the same selector with `/source_store$`, FAIL25.153s; actual
   source/deployment removal completed, but the normal-receipt decoder refused
   the incomplete normal shape. No production receipt changes preceded RED.
   Added separate partial receipt kind and closed fields, with no successful
   application/control/effect fields. New-pin probe22.089s measured
   `0db4b0f2e5f9c0b9242d9c9c47ae227ef68951f1351f06d0fcedee9f02d5df36`.
   Two-case lifecycle/replay GREEN58.546s, source22.13s/deployment22.59s.

5. Source provenance RED:
   `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/source_drift$' -count=1 -timeout=3m -v`
   FAIL27.571s. Key ID, payload digest, generation and policy version mutations
   each incorrectly acquired a cleanup claim (all test transactions rolled back).
   Root cause: partial snapshot compared signature/envelope digest but omitted
   these original request/response bindings. Added exact signed-source and
   source-store-response target comparisons. Each owner fault is restored to
   the originally authority-produced row; no positive evidence is invented.
   New-pin probe9.354s measured
   `d77016d0d1d8b083a3b0ee59884abf62c5c6e5785b39cef3c884125cffe6c8e0`.

6. Expanded command:
   `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/^(source_drift|stopped|deadline|lease_loss)$' -count=1 -timeout=5m -v`
   FAIL98.565s only because the initial stopped fixture disabled a kill switch
   without a durable budget-stop record. The reviewed transition correctly
   refused live progression with SQLSTATE55000 `ordered execution disabled`;
   it did not write a terminal audit. Root cause was the test's chosen input,
   not partial cleanup: corrected it to a negative budget-stop fault plus
   disabled switches, then consume the real blocked transition. Deadline21.64s,
   lease-loss22.66s and all source-drift cases21.69s already passed. This does
   not prove an autonomous kill-switch-to-terminal producer; that remains a
   runtime integration consideration.

7. Mixed stored/planned target RED:
   `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/mixed_targets$' -count=1 -timeout=3m -v`
   FAIL26.430s. The reviewed acknowledgement count included a never-stored
   target. Minimal change counts only stored/verified apply sources; normal
   post-receipt cleanup still requires all verified targets. New-pin probe
   9.470s measured
   `3658e32af2583c8b4c73381fda764c8fcb54352b08e0f6eb0f20e46023e05b5b`.

8. Corrected/new regression command:
   `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/^(stopped|mixed_targets|composition)$' -count=1 -timeout=4m -v`
   PASS88.733s; stopped22.75s, mixed22.36s, composition29.63s. The composition
   case runs two actual planning child processes and two real approved source
   producers, then removes only the first cancelled run's source. The unrelated
   source row is byte-identical and its two policies plus the persistent policy
   remain in the acknowledged replacement bundle. No owner-created success.

9. `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/cleanup_unknown$' -count=1 -timeout=3m -v`
   PASS25.856s. An unacknowledged stored removal bundle cannot complete. After
   exact negative lease-expiry faults, private reconciliation retains cancelled,
   retryable/unknown_call and no receipt; replay changes no durable evidence.
   This is existing recovery behavior exercised through the new partial gate,
   not mislabeled as a new semantic RED.

10. Final partial decoder regression command:
    `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/source_store$' -count=1 -timeout=3m -v`
    PASS27.175s, including existing closed-response/receipt mutation helper and
    explicit normal-kind downgrade, remediated partial outcome, and missing
    partial digest refusals. Original exact lifecycle and replay still pass.

11. Action-key drift probe:
    `go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/source_drift$/action_key' -count=1 -timeout=3m -v`
    Initial FAIL26.839s was SQLSTATE23503 from the existing scoped effect FK,
    before cleanup invocation. This is not an exploitable authority gap or
    semantic RED. Corrected the test to recognize that precise protective FK
    refusal; no production change followed it.
    Corrected focused check PASS26.465s.

## Current changed-path manifest

- `services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go`
- `services/platform/apiserver/security_agent_multistep_cleanup_repository.go`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup.sql`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup_deployment.sql`
- `services/platform/migrations/production_security_agent_multistep.go`
- `.superpowers/sdd/2026-09-20-security-agent-ordered-multistep-plan/task-11-report.md`

## Source freeze and grouped verification

Source/test freeze:2026-09-21T07:34:51Z. Formatting/diff checks passed; the
registered pin is3658e32af2583c8b4c73381fda764c8fcb54352b08e0f6eb0f20e46023e05b5b.
Only this report may change while the consolidated prerequisite gate runs.

```text
ec89d61a5e5152eaa239f8899efb26fb32fe0ec46d6de8dc73b2d35da0fd19c8  services/platform/apiserver/security_agent_multistep_cleanup_repository.go
063b23b28cdefde1820a7b406b329d5300660b671d52f4dfb01fd348a9e606c7  services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go
0d4f1b7f8dd11d80394432734d45ea6572222ab120c30b2cb8a70d106ef59139  services/platform/migrations/production_security_agent_multistep.go
6f315575a133fa6b4161c0d75d47949ca134f5f8f3438a113c0808c06ad1e364  services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup.sql
b438cc49e4931287279b434b3cac3ba959d0c5a734b900bb7251fdff455a08bf  services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup_deployment.sql
```

Commands, all from `services/platform`:

1. `go test -race ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$' -count=1 -timeout=10m`
2. `go test ./apiserver -run '^TestSecurityAgentMultistepCleanup.*Postgres$' -count=1 -timeout=25m`
3. `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Registered.*|Schema|RollbackSnapshot|ForeignKeyTriggerDrift|LegacyActionRestoration|PlanningLegacyRestoration|PlanningClaim|ProgressionAuthority|ApplicationClaim|TestSettlement|Pricing.*)Postgres$' -count=1 -timeout=25m`
4. `go test -race ./migrations ./agentsec-worker ./redteamadapter ./artifactstore/... ./internal/multisteppricing -count=1 -timeout=20m`

Group1 PASS under race, 239.818s: all nine new real-PostgreSQL scenarios and
their decoder/provenance subcases.

Group2 PASS, 991.350s: the complete existing cleanup PostgreSQL group, including
normal post-receipt cleanup, cancellation, conservative outcomes, composition,
published recovery, late stop/expiry, deadline waits and gateway safety.

Group3 PASS under race, 446.573s: exact readiness/schema/rollback/restoration,
pricing and representative planning/progression/application/test consumers.

Group4 PASS: migrations 36.194s, agentsec-worker 56.438s, redteamadapter 3.257s,
artifactstore 1.350s, s3driver 2.948s, internal/multisteppricing 12.891s.
All four commands exited 0. This is the separately authorized prerequisite's affected gate,
not the full Task11 orchestration gate. No orchestration façade/runtime is added.

Rollback cost: one new private snapshot helper; cleanup parent FK now binds the
scoped step instead of requiring successful application; one distinct immutable
partial receipt kind/closed shape; one source-count predicate; updated compiled
release61 checksum/fingerprint. Existing post-receipt cleanup remains on its
original snapshot and receipt kind. No additional saved legacy function or
release60 SQL change. Retained real admission/cleanup evidence still forbids
down; unused release61 must restore the exact prior release through grouped
migration/restoration checks before commit.

## Preservation and proof boundaries

After focused tests, the residual status and out-of-manifest tracked patch still
match the baseline captured before production edits:

- Residual entries:1,044 (five scoped source/test paths make current total1,049).
- Residual status SHA256:`ea9d965d6938301c00a021e193e7a893467d1180448736c3d02328afdbb1646c`.
- Out-of-manifest tracked binary diff SHA256:`c5fcd9a78e5f71dc094f71e5522df0c7ee71fbb9ebde13fc2c5243a4e3dd45f4`.

The index was empty before scoped staging. Controller-owned docs were baseline, not modified here.
All completed test PostgreSQL processes reported normal joins. Tests run against
real local PostgreSQL with actual private Go boundaries, an inherited controlled
planner transport and immutable local artifact service, and controlled deployment
store/read/finish acknowledgements. These are component tests, not new TLS,
live-provider, cloud-gateway, production deployment or public-route proof.

Partial cleanup retains the canonical control identity only as the existing
cleanup-row/response binding; it does not insert a control row. Its distinct
receipt omits control, application-receipt and successful-effect fields. The
application step stays executing with a cleaned effect under the conservative
terminal parent, and the second step stays cancelled. Future runtime aggregation
must consume the distinct partial receipt, never reinterpret it as application
success or permission to run the test.

Final precommit checks: all five source/test SHA256 values still exactly match
the freeze above; `gofmt -l` returned no paths; scoped `git diff --check` exited 0.
Both preservation hashes above still match. After the final group exited 0,
`ps -axo pid,ppid,etime,command` showed no test apiserver or owned PostgreSQL
server process. All four grouped commands are joined; no fixture remains running.

## Commit checkpoint

Source/test commit: `81631cc747cf74809716186177eab516853907ff`
(`fix: retain release61 partial-application cleanup authority`), exactly the five
source/test manifest paths, 454 insertions and 14 deletions. This report is
committed separately so it can identify the actual source commit.

Status: DONE_WITH_CONCERNS for this prerequisite packet only. Independent review
is required before implementing the Task11 worker façade/runtime. No full
orchestration, autonomous kill-switch terminalizer, live provider, new TLS
combined-process, cloud gateway or public-route evidence is claimed.

## Independent review correction 1: expired application deployment handoff

Review found that cancellation after application deployment store/read leaves
expired leased sequence/generation/input fields. Source enqueue preserves them;
cleanup recovery then treats the application bundle as candidate cleanup proof
and refuses forever. Source-store and deployment-finish coverage missed these
two commit boundaries. This correction remains prerequisite-only.

Semantic RED command (before production changes):
`go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/deployment_(store|read)$' -count=1 -timeout=4m -v`
Expected: live lease claim refuses; after natural 30-second lease expiry and a
cleanup restart/reclaim, cleanup deployment claim fails on the retained
application bundle. Actual Task11A planning/admission and private source and
deployment producers supply all positive evidence.

Observed RED: FAIL 105.184s; deployment_store 51.03s, deployment_read 50.07s,
both `cleanup deployment claim repository operation conflict`. Live application
lease refusal, natural expiry and cleanup restart/reclaim passed before that
failure. Both owned PostgreSQL processes joined normally. Added provenance
mutation refusals and immutable unknown-evidence/fresh replacement assertions,
and a second real planning/source producer to retain unrelated temporary policy.

Provenance RED, same command narrowed to `/deployment_read$`, FAIL 55.868s:
all six altered generation/credential/lease/input/bundle/audit cases incorrectly
acquired cleanup. The audit restoration fixture also raised SQLSTATE42702 from
an unqualified `event_kind` in its joined UPDATE; qualified the test-only column
(the running binary preceded that edit). This fixture error is not a production
RED. Production remains unchanged through both semantic RED runs.

Initial implementation adds an initial-partial-claim-only handoff under the
existing lock order. It validates exact source/credential/lease, signed bundle,
claim/store/optional read provenance and request hashes including lease tokens.
It retains an `unknown_application_outcome` audit containing the prior work
(token hashed), unchanged bundle and original audit digests, then clears only
the exact expired work lease. Applied generation/digest are not advanced.
Snapshot/partial receipt digests bind the retained unknown audit; later calls
also verify its bundle and referenced audit bytes. No application resend,
receipt, control, successor or successful parent is created.

Metadata probe `/deployment_store$` FAIL 22.101s measured
`893181188fbe193c7640b45b4eb1b85b9d694a1473c54496d7dbb9a60ecb4367`.
After that pin update, the two-case GREEN attempt FAIL 110.913s at SQLSTATE42702:
the handoff's local `id` conflicted with the gateway credential column. Root
cause was local naming, corrected to `handoff_id`; mutation refusals in this
run are not counted as safety GREEN because the naming error masked them.
`go test ./apiserver -run '^TestSecurityAgentMultistepRegistered.*Postgres$' -count=1 -timeout=2m -v`
FAIL 26.714s on stale pin, without printing the new measured identity.
`go test ./apiserver -run '^TestSecurityAgentMultistepApplicationClaimPostgres$' -count=1 -timeout=2m -v`
FAIL 9.162s measured corrected identity
`1751017bd40e0ea564ce9b6aec3fb87e3738ca4df0d0c8eea53fad13265e0661`, now pinned.
These pin probes are metadata checks, not semantic RED.

Second two-case attempt FAIL 113.683s with SQLSTATE22P02. Investigation used a
read-only expression in the owned test PostgreSQL: `jsonb->'work'-ARRAY[...]`
parses subtraction before extraction and tries to parse `work` as JSON. Exact
expression reproduced `Token "work" is invalid`; parenthesized the extracted
object. No authority rule was relaxed. Two initial psql probes used nonexistent
owner role names and failed before SQL; inspected the fixture to resolve
`zasp_e2e` and used that exact test owner for the read-only expression.

Controller ruling also includes claim-only expiry: absence of store/read/finish
audits and the claimed bundle must produce distinct `no_external_call`, retaining
exact claim/work/token evidence; unexpected evidence refuses. The first added
claim-only run FAIL 54.109s at the same JSON parsing error, so it is not yet a
semantic RED for claim-only behavior. No claim-only production behavior added yet.

Diagnostic `/deployment_store$` FAIL 53.701s confirmed `Token "work" is invalid`
at handoff line 18. Corrected-pin application-claim probe FAIL 9.330s measured
`7f3838f8fbc5845e733b4a1c232bd18a8285ce72dcf0db60d5dcd36878b3e5e5`.
With that pin, the three-boundary command
`go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/deployment_(claim|store|read)$' -count=1 -timeout=5m -v`
now produces semantic claim-only RED: exact expired claim refused with
SQLSTATE40001 `ordered partial handoff stored evidence changed`, no parser error.
Claim-only production extension starts only after this observed failure. Its
absent stored-row mutation subcases are explicitly skipped; store/read scenarios
exercise those mutations against real produced bundle/store evidence.

That three-boundary run FAIL 161.703s: claim-only semantic RED 50.10s; store/read
still refused authentic stored evidence at 47.91s/49.17s. Per debugging's
three-attempt checkpoint, reported the repeated failures and paused production
fixes while isolating the predicate. The claim-only extension retains a
`no_external_call` audit with no bundle and exact claim/work/token provenance,
and cleanup allocation skips its originally reserved sequence so that absence
remains durable. Metadata application-claim probe FAIL 9.658s measured
`e777be91ae937c3e1dbf8a813a2fb456cd62ea9f3a786d2d13aacc89b496c4ca`.

Read-only predicate query in the owned PostgreSQL isolated exactly two authentic
store-request versus bundle-snapshot differences: `issued_at` and `expires_at`
are second-resolution `...Z` strings in Go's time.Time JSON, but the retained DB
read snapshot emits equivalent `...000000Z`. Every other signed field matches.
The proposed correction compares these two values as timestamptz and preserves
exact equality of every other field, original signed request hashes and original
bundle bytes. Controller agreement requested before that further production fix.

Claim/store diagnostic command (`/deployment_(claim|store)$`, `-timeout=4m`)
FAIL 118.512s: claim-only lifecycle GREEN 55.64s, store predicate RED 48.20s.
The diagnostic reports `work:null` (no work-field differences) and only those
two timestamp textual differences. Controller agreed to typed timestamp equality
while retaining exact non-time fields/raw hashes. Added signed-bundle fault
assertions for both timestamps at plus/minus one microsecond and a non-time
key-ID mismatch before changing that comparison. The authentic lifecycle is
the semantic RED; near-miss refusals must stay protected through normalization.

Near-miss command `/deployment_read$`, `-timeout=3m -v`, FAIL 55.165s before
normalization: authentic lifecycle still rejected (50.83s), all fourteen real
negative provenance assertions refuse and restore the original produced rows.
Implemented only the agreed typed timestamp equality; all non-time JSON fields,
original request hashes, bundle bytes and retained evidence stay exact.

Final timestamp-corrected application-claim metadata probe FAIL 9.243s measured
`ab2ae53d303dfac7481444aed12a8915817bf21b0e46ed1143601e7fefdcaab3`, now pinned.

Focused GREEN: three-boundary command above PASS 178.376s; claim-only 55.36s,
store 53.45s, read 54.69s. All fourteen stored-evidence mutations refuse, including
both timestamps plus/minus one microsecond, key/signature, missing claim and
unexpected bundle. Claim-only's six applicable lease/claim mutations refuse;
eight stored-evidence subcases are inapplicable there and explicitly skipped.
Each boundary proves live-lease refusal, natural expiry, private Go and SQL
wrong-scope/stale-version refusal, unchanged applied fields/newer desired
generation at handoff, connection restart, cleanup lease loss/reconciliation/
reclaim, fresh removal sequence/generation, immutable application evidence and
distinct handoff outcome, conservative partial receipt, terminal replay and
persistent/unrelated-source preservation. Each runs two real planner children;
no owner-created success. All owned child/PG processes joined.

### Correction source freeze and consolidated gate

Source freeze: 2026-09-21T08:29:42Z. `gofmt -l` returned no paths and scoped
`git diff --check` exited 0. Residual status and out-of-manifest tracked patch
hashes still exactly match the 1,044-entry baseline above. Only this report may
change during the new consolidated gate.

Correction manifest:

- `services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go`
- `services/platform/migrations/production_security_agent_multistep.go`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup.sql`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup_deployment.sql`
- `.superpowers/sdd/2026-09-20-security-agent-ordered-multistep-plan/task-11-report.md`

```text
ac1f8dd64a03ad17b3aa3dfcab64c959efe10d8a46ad7668ee4d8b8335110322  services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go
a0905de77e49d52cf4379dc9d613bfd4979c455ecd24888c6b7e5a6a6613f675  services/platform/migrations/production_security_agent_multistep.go
96b788e48261de332d2ad736b5d00f4fe29c79ec34fdcad92e5bc6121950ac18  services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup.sql
c3b98926bfd330c9347ccb60904597c857702ce363e7903dd7e4baa689472e84  services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup_deployment.sql
```

Commands, from `services/platform`, launched once after that freeze:

1. `go test -race ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$' -count=1 -timeout=15m`
2. `go test ./apiserver -run '^TestSecurityAgentMultistepCleanup.*Postgres$' -count=1 -timeout=25m`
3. `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Application.*|Deployment.*)Postgres$' -count=1 -timeout=25m`
4. `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Registered.*|Schema|RollbackSnapshot|ForeignKeyTriggerDrift|LegacyActionRestoration|PlanningLegacyRestoration|PlanningClaim|ProgressionAuthority|TestSettlement|Pricing.*)Postgres$' -count=1 -timeout=25m`
5. `go test -race ./migrations ./agentsec-worker ./redteamadapter ./artifactstore/... ./internal/multisteppricing -count=1 -timeout=20m`

Group 1 PASS under race, 421.062s, exit 0: all twelve real PostgreSQL partial
cleanup scenarios, including the three newly covered deployment boundaries.

Group 2 PASS, 1006.586s, exit 0: complete existing cleanup PostgreSQL regression
group, including normal receipts, terminal replay, composition, cancellation,
published recovery, deadlines, late stops and gateway/credential safety.

Group 3 PASS under race, 496.505s, exit 0: full application/deployment PostgreSQL
group, including normal delivery/finish, source authority, composition and wire.

Group 4 PASS under race, 445.882s, exit 0: exact registered readiness, schema,
rollback/FK/saved-function/legacy restoration, pricing and affected authorities.

Group 5 PASS: migrations 40.686s, agentsec-worker 57.494s, redteamadapter 4.643s,
artifactstore 3.535s, s3driver 2.476s, internal/multisteppricing 13.543s; exit 0.
All five groups exited 0 on the frozen source. Rollback cost of this correction: one additional private
handoff helper, one append-only audit event shape with two distinct outcomes,
partial snapshot/receipt digest binding to that evidence, a cleanup sequence
allocation guard, and the new release61 checksum/fingerprint. No new table,
historical function definition, public grant/route, or normal receipt kind.
Retained cleanup/admission evidence continues to prohibit destructive down.
The no-live-proof and prerequisite-only limitations above are unchanged.

Final precommit verification: branch is `codex/cached-runtime-ship-20260917`,
base remains `4005f1da48a7d1a9f06258c82be6678f3b5bd3a0`, index empty; all four
frozen SHA256 values match exactly. `gofmt -l` is empty and scoped
`git diff --check` exits 0. Residual status SHA256 remains
`ea9d965d6938301c00a021e193e7a893467d1180448736c3d02328afdbb1646c`, and the
out-of-manifest tracked patch SHA256 remains
`c5fcd9a78e5f71dc094f71e5522df0c7ee71fbb9ebde13fc2c5243a4e3dd45f4`.
All five commands joined. Final process inventory found no test PostgreSQL,
apiserver or worker process. No push, public-route activation or external
provider/gateway call was performed. This is prerequisite fix round 1, ready
for independent re-review; the Task11 orchestration runtime remains deferred.

Correction source/test commit: `52ff8924fbaf160e2ec004eadd1f3551d3808cfe`
(`fix: fence expired application deployment handoffs`), exactly the four source
manifest paths, 243 insertions and 5 deletions. This report is committed
separately to name that actual commit. Checkpoint result: DONE_WITH_CONCERNS
solely because this is the dormant prerequisite, not completed orchestration
or live/TLS/provider/cloud deployment proof. No remaining failure was observed
in the correction's five consolidated gates.

## Prerequisite fix round 2: historical claim-only absence

Base: `9ab0a69c1b681d3b97d0a9dc0769f078abced381`. Independent re-review
accepted the store/read correction but found that claim-only snapshot validation
incorrectly required the abandoned sequence to remain absent forever. The
unchanged device allocator allows another producer to use that sequence after
the exact expired lease is released. Controller ruling: retain absence as an
immutable fact at handoff, not a global reservation or live absence predicate;
stored/read unknown-outcome proof must still bind its original exact bundle.

Read-only preflight verified the suspect predicate in `cleanup_partial_snapshot`,
the existing device locks and handoff evidence, and the unchanged allocator.
The two ordered runs use identical policy IDs, so the real regression signs A's
source with the exact planned TTL but 45 seconds of remaining lifetime. It lets
that source expire naturally (no owner edit to source/audit), then independently
plans, admits, approves, stores and deploys B through actual private Go/SQL.
B must reuse A's formerly absent bundle sequence before A stores cleanup.

Semantic RED command (from `services/platform`):
`go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/^deployment_claim_cross_run$' -count=1 -timeout=5m -v`.
Expected failure: after B's legitimate store/ack, A's restarted cleanup rejects
the valid immutable no-external-call handoff because the old sequence now exists.
The regression also requires later A cleanup allocation, B/persistent source
preservation, conservative receipt and byte-identical handoff after replay.

Fixture debugging before semantic RED (same command): first run exit 1,
21.776s, panicked because existing envelope policies are `json.RawMessage`,
not a compiled-policy slice. Read the producer and decode that actual wire
type. Second run exit 1, 21.681s, rejected source store. Diagnostic-only third
run exit 1, 21.645s, proved policies unchanged but payload digest different:
the canonical signing payload includes timestamps. Retain the signer's actual
new payload digest alongside its new signature/envelope digest. These are
test construction failures, not semantic RED or production fixes. All owned
PostgreSQL/planner processes joined on each failed attempt.

Observed semantic RED: exit 1, 76.785s. Both independent planner children
joined with one provider call each; B's real private deployment reused the
historically absent sequence (explicit assertion passed). A's cleanup restart
then failed at reconcile with `repository operation conflict`, before source
store. This is the expected shared snapshot/current absence check failing on
legitimate cross-run progress. No production behavior changed before this RED.

Minimal GREEN design: initial locked handoff still proves live bundle absence
and exact claim/audit/work/token provenance. Its `no_external_call` plus JSON
null bundle is the immutable historical statement; subsequent validation
checks its body digest and referenced audit digests, and current cleanup
compares that handoff digest to its committed snapshot. Only the erroneous
live absence predicate is removed. Unknown application outcome still compares
the exact stored original bundle. Neither generic allocator nor work handoff
mutation is changed.

Pin measurement: `go test ./apiserver -run
'^TestSecurityAgentMultistepApplicationClaimPostgres$' -count=1 -timeout=2m -v`
reported the new registered fingerprint
`91804eaae2d3594783ab2396d6a48f5711a509c2fc322f9550eb6cd8f6d4ccba` and
expected stale-pin readiness refusal, exit 1, 9.361s. Refreshed the compile-time
pin; this metadata probe is not counted as a semantic RED. Also corrected the
cleanup allocator comment: its existing same-run sequence skip is not a global
reservation. No allocator behavior changed.

Focused GREEN, original semantic command: PASS, exit 0, 94.133s (cross-run
subtest 79.90s). Both actual planner children joined with one call each.
Private cleanup restart/reclaim/store/deployment/complete/replay succeeded;
audit digest tamper, audit body tamper, substitution of B's bundle plus
recomputed handoff hash, and substitution of B's claim audit plus recomputed
hash all refused through Go and SQL without mutating state. Existing tenant,
stale token and stale version refusals also execute in this cross-run case.
The test checks A remains cancelled with no application receipt/control/test
success, while persistent policy and B's exact source remain intact. Added
one final byte-identical B bundle preservation assertion for the frozen gate.

Focused unchanged-boundary regression command:
`go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/^(deployment_claim|deployment_store|deployment_read)$' -count=1 -timeout=7m -v`.

Focused unchanged-boundary GREEN: PASS, exit 0, 168.512s; claim 55.24s, store
53.39s, read 55.16s. All six applicable claim provenance checks and all fourteen
read provenance checks passed; eight stored-bundle-only checks are explicitly
inapplicable/skipped for claim-only (there is no stored bundle). Repeated the
cross-run command after the final B-bundle assertion: PASS, exit 0, 82.874s,
including all four historical proof substitution refusals. All owned children
joined; no test or PostgreSQL process was left running by focused tests.

### Round 2 source freeze and complete manifest

Source freeze: `2026-09-21T09:07:41Z`. Only this report may change during gates.
Manifest is exactly the four source paths below plus this report:
`.superpowers/sdd/2026-09-20-security-agent-ordered-multistep-plan/task-11-report.md`.

```text
e12521fe36eb00f6fcc428c54c939758016d0fa7263f274a23c6661cb5828290  services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go
c2f25468828e6b0d5cf440ae5dc87a1f522d55a07d29de4306a0b448682f911e  services/platform/migrations/production_security_agent_multistep.go
934e757655bb13d0db392365a6d50cedd41fea535437fc79c208dbc7b1bdb49d  services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup.sql
5aa1688b8010fb1ab92813f41d0b0d540a2a9d49978453628a064c99cc07b89f  services/platform/migrations/sql/0061_production_security_agent_multistep.cleanup_deployment.sql
```

`gofmt -l` is empty; scoped `git diff --check` exits 0. Index is empty.
Residual status and out-of-manifest binary diff still match the two recorded
baseline SHA256 values; all 1,044 unrelated entries are preserved.

Consolidated commands (from `services/platform`, each launched once after freeze):

1. `go test -race ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$' -count=1 -timeout=15m`
2. `go test ./apiserver -run '^TestSecurityAgentMultistepCleanup.*Postgres$' -count=1 -timeout=25m`
3. `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Application.*|Deployment.*)Postgres$' -count=1 -timeout=25m`
4. `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Registered.*|Schema|RollbackSnapshot|ForeignKeyTriggerDrift|LegacyActionRestoration|PlanningLegacyRestoration|PlanningClaim|ProgressionAuthority|TestSettlement|Pricing.*)Postgres$' -count=1 -timeout=25m`
5. `go test -race ./migrations ./agentsec-worker ./redteamadapter ./artifactstore/... ./internal/multisteppricing -count=1 -timeout=20m`

Round2 group 5 PASS, exit 0: migrations 41.091s; agentsec-worker 58.274s;
redteamadapter 4.674s; artifactstore 3.358s; s3driver 2.747s;
internal/multisteppricing 13.819s.

Round2 ruling/rollback cost: one existing private snapshot predicate now
recognizes the sealed `no_external_call`/null-bundle handoff as historical
absence. Initial handoff still proves absence while holding the reviewed locks;
its claim/work/token/audit provenance and exact expired-lease mutation are
unchanged. The cleanup row and partial receipt bind the original handoff digest.
Store/read retains the exact original bundle comparison. No new table, column,
audit event shape, receipt kind, role/grant, generic allocator behavior, public
route or orchestration entry point is added. Rollback is the existing release61
down/restoration contract plus restoration of the old private predicate/pin;
retained evidence still prohibits destructive down. No evidence is erased or
rewritten by production code.

Proof boundary remains component-only PostgreSQL with actual private planning,
admission, approval, application, deployment and cleanup Go/SQL boundaries,
controlled planner/artifact fixtures and locally signed deployment envelopes.
This is not a new TLS transport, live provider, live gateway, cloud deployment,
or public/default route proof. Task11 orchestration remains deliberately
deferred pending independent prerequisite re-review. No push is authorized.

Round2 group 4 PASS under race, exit 0, 450.614s: registered readiness, schema,
rollback snapshot, FK/trigger drift, legacy action and planning restoration,
pricing and affected authority checks.

Round2 group 1 PASS under race, exit 0, 506.479s: all thirteen partial cleanup
boundaries including the actual two-run claim-only sequence reuse regression,
its proof-tamper/substitution refusals, restart/reclaim, conservative immutable
receipt/replay, and preservation of B's exact source and stored bundle.

Round2 group 3 PASS under race, exit 0, 502.382s: complete affected application
and deployment PostgreSQL regression group, including normal finish and exact
stored/read bundle provenance.

Round2 group 2 PASS, exit 0, 1008.604s: full normal cleanup PostgreSQL group,
including post-receipt behavior, conservative terminal outcomes, every-target
acknowledgement, replay, expiry, recovery, lease loss, composition and late stops.
All five consolidated groups passed on the frozen source; no gate was retried.

Final precommit verification at `2026-09-21T09:25:33Z`: all four source hashes
still match the freeze exactly; `gofmt -l` empty, scoped `git diff --check` exit
0. Branch is `codex/cached-runtime-ship-20260917`, base is the recorded round1
report head, and index was empty. Final residual count is 1,044 with status
SHA256 `ea9d965d6938301c00a021e193e7a893467d1180448736c3d02328afdbb1646c`
and out-of-manifest binary patch SHA256
`c5fcd9a78e5f71dc094f71e5522df0c7ee71fbb9ebde13fc2c5243a4e3dd45f4`.
Every test command joined; final owned PostgreSQL/apiserver/worker process
inventory is empty. No external provider/gateway call, push, public route or
default activation occurred. Round2 is ready for independent prerequisite
re-review, not orchestration continuation.

Round2 source/test commit: `b2035fe5779bbc2a54d7d16a8a501890b54f6dea`
(`fix: retain historical claim-only handoff proof`), exactly four source
manifest paths, 113 insertions and 14 deletions. This evidence report is
committed separately so it can name the actual source commit. Checkpoint:
DONE_WITH_CONCERNS only for prerequisite/component-only scope and the unchanged
no-live-proof disclosure, with orchestration runtime still deferred. No
remaining failure was observed in this correction's five frozen grouped gates.

## Task11 orchestration continuation: approved design and execution plan

Approved prerequisite head: `8429515dbc4f337198a4749104b0bc6d60c62d50`.
Independent review approved both corrections without new Critical/Important
findings. The controller explicitly approved the architectural composition:
separate worker/action/deployment/red-team DB handles; a closed private façade;
one release61 scoped authoritative reader exposing ownership booleans but never
foreign lease secrets; bounded one-transition ticks, fresh state after commits,
reviewed expiry/reclaim only, and durable SQL kill-switch stop. No duplicate
workflow state table. Existing isolated worktree/branch and residual preserved.

Gateway ruling: drive the existing signed-bundle store/read/finish protocol as
the controlled reader/acknowledgement boundary. Do not invent HTTP publication
or claim physical delivery. Physical gateway delivery is a Task12/deployment
gate. Provider/existing-test sends retain the reviewed durable journals.

Execution plan (inline under the controller's no-delegation instruction):

- [x] Durable kill-switch-only stop: extend the real preflight with switch-off
  and no budget-stop seed; observe the semantic failure; add the missing
  server-derived stop condition to the locked private transition; verify
  conservative audit, no application receipt, and partial cleanup.
- [x] Scoped reader and closed façade: add release61-only orchestration SQL,
  register/hash it with the existing migration, and add a Go composition that
  retains principal separation. Test absent boundary, exact readiness, scoped
  state, ownership/token non-disclosure, live/expired authority and tamper
  refusal before runtime behavior. No relation reads before the schema fence.
- [x] Planning/admission and approval pause ticks: reuse Task11A preparation,
  provider journal, artifact and admission contracts; read authoritative state
  before the next operation; prove restart at each planning commit, no resend
  of a started request, and no application before approval zero.
- [x] Application/deployment and successor ticks: sign only DB-derived targets,
  call the reviewed action and delivery authorities, reread between source,
  claim/store/read/finish and receipt commits, and pause for approval one.
  Heartbeat only the submitted exact owned lease; lost ownership stops work.
- [x] Existing-test/cleanup/terminal ticks: reuse pinned artifact dispatch and
  invocation journals, settle known completed evidence, reconcile eligible
  uncertainty, run normal/partial cleanup and aggregate from durable receipts.
- [x] Combined PostgreSQL/process/TLS proof: actual private boundaries,
  controlled fixtures and no owner-created success; every commit restart,
  approval pauses, cancellation, stops/expiry, lease loss, unknown outcomes,
  cross-tenant/mixed-binary denial and process joining. Then freeze once and run
  the full affected grouped gate; scoped source/report commits and re-review.

First behavior semantic RED (from `services/platform`):
`go test ./apiserver -run '^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/^kill_switch$' -count=1 -timeout=3m -v`.
Expected: switch-only progression refuses instead of terminalizing. Observed:
exit 1, 22.699s, `ERROR: ordered execution disabled (SQLSTATE 55000)` at actual
private progression after real planning/approval/source store. No budget stop
was written by the fixture. The owned planner and PostgreSQL process joined.

Kill-switch minimal GREEN: lock the same four execution switches and include
disabled/missing switches in the existing private progression's conservative
blocked branch, without invoking live context or fabricating budget usage.
Pin metadata probe (ApplicationClaim command used above) measured
`780d57331abb2c0368b7befb37d7ac759505846032b94554dc91aa3c82fbedc5`, expected
stale-pin refusal exit 1, 9.497s. After pin refresh, the original kill-switch
command PASS, exit 0, 37.329s, including actual partial cleanup/receipt/replay.
Later-stage kill-switch and reader coverage remains in the orchestration work.

Reader semantic RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61StatePostgres$' -count=1 -timeout=3m -v`.
Expected failure: actual private repository lacks the authoritative state
boundary after real Task11A planning/admission. Subsequent assertions require
read-only approval state, exact tenant/run denial, fresh post-claim state and
exact token ownership without disclosure of any lease secret.

Observed reader semantic RED: exit 1, 21.032s, explicit `authoritative private
release61 state boundary absent`, after actual planning/admission. Minimal
reader GREEN adds a scoped, registered, principal-fenced SQL read with existing
Organization/budget/run/step locks and immutable admission validation, plus a
strict Go decoder with a 30-second cancellation-bound SQL deadline. Initial
coverage is admitted run/step/approval/action-lease state only; further state
needed by the runtime will be added with its own semantic tests.

Reader pin probe measured
`b91e11bc85e385f37cecc44713b380fc45490d3524edc1c2c956a8f91bcbb574`, expected
stale-pin refusal exit 1, 9.486s. After refresh, original reader command PASS,
exit 0, 34.051s: real admission remains unchanged, every substituted tenant/run
ID refuses, and a fresh reread after actual action claim distinguishes wrong
versus exact supplied token without returning either token. All processes joined.

Composition RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61CompositionPostgres$' -count=1 -timeout=2m -v`.
A fail-closed type/constructor scaffold permits the semantic test to compile;
it performs no operations and always returns unavailable. Expected RED is that
the real four registered principals cannot construct the dormant façade yet.
The same test requires each wrong-principal substitution, cancelled context
and fingerprint drift to refuse construction before any execution.

Observed composition semantic RED: exit 1, 9.707s, `private
principal-separated composition absent`. Minimal GREEN adds an explicit
constructor, per-operation readiness across the four dedicated handles and
only named delegation to reviewed private repositories, with a shared
30-second cancellable operation cap. No default/public registration. Its
registered readiness helper checks the exact release before the selected
principal. Pin probe measured
`03827392fc88548225fb24a68f091deb5a0f7ac72b1780d4229ca1865c606d94`, expected
stale-pin refusal exit 1, 9.504s; pin refreshed before focused GREEN.

Composition focused GREEN: original command PASS, exit 0, 11.332s, all four
real principals accepted only in their dedicated lane; PostgreSQL joined.

Controller tick ruling: retain Task11A prepared → durable start permit →
provider send → result as one bounded journaled tick. Splitting after start
would discard the only legal send permit and force uncertainty. Every other
tick commits one transition. Fault/restart tests must still cut both durable
provider boundaries and prove no resend; no cached/reconstructed permit.

Later-stop semantic RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61LaterStopPostgres$' -count=1 -timeout=3m -v`.
Expected: after real planning/application/deployment/receipt and successor
readiness, switch-only stop either loses its blocked audit by reusing the
existing ready audit or rejects an executing-successor response. Tests require
an immutable blocked audit and stable fresh-state replay for approval and
executing stages, without owner-created positive success.

Observed later-stop RED: exit 1, 56.515s. Approval stage reports `stop reused
ready audit and lost terminal evidence`; executing stage reports the private
Go decoder's `repository provider unavailable`. Root cause inspection confirms
the SQL committed conservative state but reused the earlier ready audit ID,
while the decoder allowed executing evidence only for API cancellation. Minimal
correction must distinguish blocked progression audit identity and permit only
the exact conservative progress response, retaining the executing evidence.

Queued/planning reader RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61QueuedStatePostgres$' -count=1 -timeout=2m -v`.
Expected: the admitted-only reader rejects a canonical queued input. Follow-on
assertions require zero steps/no invented job before real private planning
claim, then exact ownership/non-disclosure on fresh reads after that claim.

Observed queued-reader RED: exit 1, 9.589s, `queued/planning authoritative
state unavailable repository operation conflict`. Minimal extension reads the
same Organization/budget/run locking order, validates canonical trigger scope,
distinguishes admission from pending planning, and returns only planning state,
lease deadline and exact supplied-token ownership. No token/digest returned.

Unexpected metadata probe failure: ApplicationClaim probe exit 1, 9.066s,
SQLSTATE 42601 localized by the fixture's statement excerpt to the new
`IS DISTINCT FROM CASE ... END` conditional. Root cause: the PL/pgSQL IF parser
needs the CASE expression parenthesized; changed that expression only. Before
the next build, also renamed the new PL/pgSQL run variable to `parent_row` to
avoid shadowing the existing SQL table alias. No semantic behavior bypassed.

Corrected pin probe: exit 1, 9.620s, expected stale-pin refusal, measured
`185ba998327ca7d81d50501a4eb28c68554fd76af291a3bbb502a5dc2c9d80a3`.
After refresh, focused group command
`go test ./apiserver -run '^TestSecurityAgentRelease61(QueuedState|State|LaterStop)Postgres$' -count=1 -timeout=4m -v`
ran 89.218s: admitted reader PASS (33.19s), both later-stop stages PASS
(45.93s), queued reader unexpected FAIL (8.95s) with decoder-unavailable.
Investigating that boundary independently before changing its behavior.

Runtime planning/approval-pause semantic RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61PlanningTicksPostgres$' -count=1 -timeout=4m -v`.
A fail-closed Tick scaffold allows compilation. Expected RED: the first real
queued run cannot advance. Follow-on assertions require an independently
restarted worker process at each planning commit, real controlled TLS provider
call only for prepared/start/result, immutable artifacts, then two read-only
approval pauses with no effects. The façade uses all four actual principals.

Runtime fixture compile corrections (not semantic REDs): 2.126s missing Exec,
then 14.901s grouped attempt missing SchemaVersion; inspected JSONDatabase and
completed its test adapter (SchemaVersion fails closed and is unused by the
private façade). The latter also confirmed queued decoding still failed.
Read-only SQL diagnostic then proved the row itself was valid (`planning:null`)
while `budgetJSONObject`, below the closed-key helper, also rejects null.
Corrected the new optional-job wire representation to `{}` and restored the
unaltered strict closed-object decoder; test continues requiring no job/steps.

Actual runtime semantic RED: grouped QueuedState/PlanningTicks command exit 1,
36.008s; independently spawned tick reports `dormant release61 tick absent or
unsafe ... planning_claim worker execution unavailable` (23.52s). The queued
reader diagnostic subtest took 11.35s and confirmed the null representation.
Minimal planning tick reuses Task11A's existing loop with a transition bound
(zero = claim only; one = one retained state operation), then rereads via the
four-principal façade and discards state. Fresh process per tick uses the same
immutable file artifact store and controlled TLS transport. No default wiring.

Wire correction pin probe: exit 1, 10.489s, expected stale-pin refusal, measured
`8f29c4f6b2b0f59c9419d9c8daf6ffa0874ee951a3448f1496154037e5b1ed16`; refreshed.

Planning focused GREEN:
`go test ./agentsec-worker -run '^TestSecurityAgentMultistepPlanning(SQLDeadline|SQLDeadlineClamp|EarliestAuthority|RawTransport)$' -count=1 -timeout=2m`
PASS 1.146s. QueuedState/PlanningTicks original grouped command PASS 73.068s:
eight separately joined worker processes (six planning transitions and two
approval pauses), exactly one controlled TLS provider request at result tick,
then immutable admitted two-step plan with no action effects. Queued-state
ownership/non-disclosure PASS 9.61s; planning process group 62.36s.

Application/deployment runtime semantic RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61ApplicationTicksPostgres$' -count=1 -timeout=4m -v`.
Expected: after real tick-based planning and explicit API approval zero, the
runtime has no application claim transition. Follow-on process-restart checks
require source store, deployment claim/store/read/finish, application receipt,
successor readiness, and repeated approval-one pauses, with no test effect.

Observed application runtime RED: exit 1, 54.831s. All eight real planning/pause
processes passed; after explicit API approval, `application_claim` reports
`dormant release61 tick absent or unsafe`. Minimal GREEN adds only next action
selection from the fresh scoped reader and named façade delegation. The reader
returns server-derived targets and at most one current delivery claim (bounded
to the existing composition envelope), never a foreign lease token or a foreign
owned claim. Source signing reuses compiled containment policies; deployment
signing uses only the reviewed DB-derived full composition. Each source,
claim/store/read/finish, receipt and successor-ready commit is a separate tick.

Application metadata probes: expected stale-pin refusal 9.958s measured
`1aa7773fbcf970be463057b0bfad479647a4348de3c4a1966c4dd5632b842370`;
source-qualified the target-loop columns to avoid PL/pgSQL `phase` shadowing
before execution, then reprobed (9.758s), final pin
`a611223c475d5c22b8ed7e36e077302bb3870c498f235d134fb952b887e55377`.
Planning focused regression command PASS 0.919s.
Application process GREEN: original command PASS 106.544s (test 105.41s),
eighteen independent joined ticks through full signed acknowledgement,
application receipt and two approval-one pauses, no test effect yet.

Ordered-runner design ruling: controller approved a uniquely named dormant
entry, explicit journal composition and reuse of existing evaluation/command
validators with canonical pre-dispatched immutable input. No random new input,
no route/default registration. Controlled Promptfoo/TLS command fixture remains
component-only; exact journals, artifact/evaluation association and no-resend
must be proven before private settlement.

Reader stop signal RED: later-stop test now also reads authoritative state
after disabling switches and requires `stop_required=true` before transition.
Command: `go test ./apiserver -run '^TestSecurityAgentRelease61LaterStopPostgres$/^approval$' -count=1 -timeout=2m -v`.
Expected failure: reader currently omits that server-derived signal, so a
paused runtime cannot distinguish approval wait from required durable stop.

Existing-test runtime semantic RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61ExistingTestTicksPostgres$' -count=1 -timeout=5m -v`.
Expected: after actual planning/application process ticks and explicit approval
one, the runtime lacks test claim. Follow-on assertions will require canonical
immutable input dispatch, real category journal/TLS execution and exact private
settlement, without owner-created application/test success evidence.

Reader stop RED observed: exit 1, 26.304s, `authoritative reader omitted
switch-only stop`; real admitted/application-complete state was otherwise
intact. Minimal reader addition computes the same locked switch/budget/plan/
effect stop predicates used by progression, only for nonterminal parents.
Metadata probe expected stale-pin refusal 9.783s, measured/refreshed
`cf9ca6bb8cebb15ff2df957c9ad9059a21d1b4f399e8194415505e1f29195efd`.
Worker stop tick RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61(StopTick|LaterStop)Postgres$' -count=1 -timeout=4m -v`.
Expected: reader test green, paused runtime still returns approval_pause instead
of consuming stop_required through durable private progression.

Existing-test runtime RED observed: exit 1, 96.777s; the first eighteen
planning/application/pause processes passed, then test_claim reported the
absent transition after actual approval one (test 95.84s).

Controller approved the second bounded-journaled-tick exception: after input
dispatch, one `test_settle` tick runs the configured existing command against
that canonical immutable input, category journal start/complete, immutable
output Put/Get, and reviewed SQL settlement. There is no separate output-
prepared workflow table/audit. Restart/fault at category start/completion and
output Put/Get must preserve identities, replay completed journals without
provider resend, and never resend unknown work. Subsequent ticks reread SQL.

Stop dispatch RED observed: grouped command exit 1, 110.316s. StopTick
failed at `approval_pause` instead of `stopped` after the eight real planning
ticks (62.43s); LaterStop passed both approval/executing cases (46.76s).
Minimal dispatch now consumes the SQL stop flag through private progression,
then rereads; it does not synthesize a terminal state in memory.

Explicit journal composition RED command: `go test ./redteamadapter -run
'^TestRelease61JournalComposition$' -count=1`. Expected semantic absence of
the dormant pinned Release61 method, tested via interface assertion. Requires
exact registered pins/adapter readiness and caller cancellation before exposure.
Reader test-state metadata probe: expected stale-pin refusal, exit 1 9.864s;
measured/refreshed `77f1f5bfdad4df51b8276dd9c14ad0d23823ecc01b766a4b7f6b226f9dd034af`.

Journal composition RED observed exit 1, 0.659s: all four cases reported
`explicit dormant release61 journal composition absent`. Minimal method
delegates the reviewed private selector and bounded exact Ready; no handler.

Journal composition GREEN plus existing private boundary regression: exit 0,
1.046s. StopTick/LaterStop GREEN: exit 0, 127.920s (69.16s / 57.65s),
all nine restart processes joined; no provider calls on stop.

Existing-test continuation compile/check: `go test ./agentsec-worker
./redteamadapter -run '^(TestRelease61JournalComposition|TestSecurityAgentRelease61OwnedTick)$'
-count=1` passed 1.158s / 1.455s; owned process test skips without parent DB,
so this is compilation/isolated journal coverage, not lifecycle proof.
Actual ExistingTestTicks rerun uses its original RED command, in progress.

Full cleanup/terminal semantic RED: `go test ./apiserver -run
'^TestSecurityAgentRelease61LifecycleTicksPostgres$' -count=1 -timeout=6m -v`.
Expected: after reviewed test settlement the runtime lacks cleanup_claim.
Assertions cover one process per removal/deployment commit and terminal replay.

ExistingTestTicks unexpected failure: exit 1, 120.041s (test119.08s).
Planning/application and test_claim passed; test_dispatch returned the closed
worker error. Systematic debugging: inspect immutable artifact and dispatch
boundaries first; add fixture-only PostgreSQL SQLSTATE/message diagnostics
(no arguments, bodies, or lease secrets), then rerun before any behavior fix.

Diagnostic rerun exit 1,119.502s: SQLSTATE40001 `red team target unavailable`.
Read-only witness before dispatch showed queued child and only test_claim audit.
Root cause: combined fixture omitted the existing-test target's discovery
source/snapshot/evidence configuration, which the reviewed target resolver
requires. Minimal fixture correction installs reviewed `seedOrderedTestSource`
before planning; this is initial target configuration, not run success evidence.
The first LifecycleTicks attempt also exited1,112.760s at that earlier dispatch
failure; it does not count as cleanup RED. Rerun LifecycleTicks now doubles as
the focused test-settlement GREEN check and intended cleanup RED.

Lifecycle focused result exit1,124.546s (test123.37s): all 21 transitions
through test_settle passed. Actual adapter process reported one controlled TLS
invocation and same-journal replay without resend; private settlement committed.
Next process failed exactly at absent cleanup_claim: semantic cleanup RED.
Additional runner input-binding regression `go test ./agentsec-worker -run
'^TestRelease61RunnerRequiresCanonicalDispatchedArtifact$' -count=1` passed
1.118s: canonical identity, tenant, manifest hash/version, bytes, runner-image
drift, and temporary workspace removal. These are isolated negative checks,
not substitutes for the actual process settlement.

Minimal cleanup continuation reads the reviewed cleanup snapshot/immutable
receipt under existing locks, exposes only owned-lease booleans and one exact
delivery claim, and delegates source/removal delivery/completion to reviewed
repositories. No extra workflow table or terminal-success synthesis.

Cleanup reader metadata probe: expected stale-pin refusal exit1,10.011s;
measured/refreshed `8408198db33b9978129b0f0927325a70562f0293976cc28b65294c709c6d2418`.
Lifecycle GREEN attempt running with this exact pin.
Post-commit acknowledgement-loss fixture calibration command:
`go test ./apiserver -run '^TestSecurityAgentRelease61CommitAckTicksPostgres$'
-count=1 -timeout=6m -v`. Expected initial fixture RED: no injected error yet,
so first planning claim incorrectly returns success for the fault expectation.
This calibrates fault injection; it is not counted as a production semantic RED.

Ack-loss calibration RED observed exit1,28.245s at first planning_claim:
`post-commit fault did not interrupt worker`. Fixture now returns its injected
error only after actual QueryJSON/autocommit succeeds, requires a fired marker,
and matches named SQL operation without logging request arguments or tokens.

Lifecycle unexpected harness timeout: exit1,141.082s. cleanup_claim actually
passed in child (3.84s) but the inherited two-minute migration-fixture context
expired while joining it. Root cause is the legacy setup deadline, not cleanup
authority. Dedicated lifecycle exercise now uses a four-minute context derived
from `t.Context()` (preserving test cancellation), independent of setup's
two-minute migration limit; each process still has its own 80/90s cap.

Lease recovery semantic RED command: `go test ./apiserver -run
'^TestSecurityAgentRelease61LeaseTicksPostgres$' -count=1 -timeout=6m -v`.
Expected failure: runtime currently waits forever after exact expired
application claim instead of reclaiming through the reviewed claim authority
with a fresh caller token. Same scenario asserts foreign live application,
deployment, test, cleanup lease waiting and expired no-journal test reclaim.
Owner mutations here only inject expiry; they do not create success evidence.

The already-built ack-loss attempt also exhausted the old setup deadline
(134.638s), after successful fault/restart through cleanup_deployment_read.
Same proven harness cause; rerun uses the new test-bound four-minute context.

Bounded loop semantic RED: `go test ./agentsec-worker -run
'^TestRelease61LoopRejectsUnboundedOrCancelledWork$' -count=1` expects absence
of the dormant loop method; requires finite backoff, caller cancellation and
unconfigured-runtime refusal. The loop may not register a default worker.

Loop RED observed exit1,0.976s `bounded dormant release61 loop absent`.
Minimal opt-in Run uses serial bounded Tick, 100ms–30s finite timer backoff,
caller cancellation and terminal receipt exit. Any Tick error stops that owner;
there is no automatic external retry or goroutine. Added timer-cancel,
three-tick backoff and single-error-stop checks.

Lifecycle GREEN exit0,168.973s (test167.84s): thirty independent worker
processes traversed both approval pauses, real planning/provider/artifacts,
application store/read/finish, actual test journal/TLS/output/settlement,
cleanup store/read/finish and immutable terminal replay. All processes/PG joined.
Lease semantic RED exit1,86.720s: foreign live application lease correctly
waited; expired application with a fresh token still returned lease_wait.
Minimal fix delegates that exact expired leased effect to reviewed claim;
SQL still refuses the old token, live owner, drift, and wrong scope.

Ack-loss chain GREEN exit0,148.444s; all successful durable transitions
injected response loss, then next processes resumed from state without repeats.
Loop focused GREEN1.113s. Heartbeat semantic RED command:
`go test ./apiserver -run '^TestSecurityAgentRelease61HeartbeatTicksPostgres$'
-count=1 -timeout=6m -v`. Expected: short but live owned application lease
currently proceeds to source store instead of reviewed heartbeat. Same scenario
covers linked child/effect and retained cleanup owned heartbeats.

Planning uncertainty process coverage command: `go test ./apiserver -run
'^TestSecurityAgentRelease61PlanningUncertaintyTicksPostgres$' -count=1
-timeout=6m -v`. Covers started-commit acknowledgement loss (zero send),
provider result unknown (one send), and completed-but-unsettled expiry, then
reviewed planning reconcile and terminal restart without admission or resend.

Heartbeat RED observed: real short owned application lease returned
application_store instead of application_heartbeat. Minimal shared source
executor now bounds owned work to the current lease and delegates heartbeat
when less than one 90s tick remains; removal uses its reviewed heartbeat.
Owned deployment read/store/finish is additionally bounded to its own lease.

Heartbeat RED exact result exit1,81.119s. Lease second RED exit1,140.624s:
application expiry reclaim now passed; test fresh-token no-journal expiry still
waited. Minimal test reclaim requires expired effect, zero journal rows, and
queued child or expired leased child, then delegates reviewed test claim.

Lease scenario additionally queues a cleanup-expiry RED: after foreign live
cleanup wait, expire matching cleanup/effect leases; expect reviewed reconcile,
fresh-token retryable claim and conservative needs_human after verified removal.
Current code is expected to remain at lease_wait. No removal receipt is seeded.

Lease recovery GREEN exit0,202.851s (before added cleanup expiry assertions):
fresh-token application/test reclaim, foreign live lease waits and complete
cleanup/terminal replay passed. The new cleanup-expiry semantic RED is running.
Heartbeat next semantic RED exit1,143.457s: application heartbeat passed;
short owned child/effect leases ran test_settle instead of test_heartbeat.
Minimal fix will delegate reviewed joint child/effect heartbeat and bound
test operations to both owned deadlines.

Planning uncertainty grouped exit1,144.356s: started-ack-loss and completed
expiry passed; provider-unknown fixture expected an error but HTTP200 valid
UTF8 error JSON is durably retained by the reviewed result operation. This
is a known malformed result, not transport uncertainty. Root-cause evidence:
sendSecurityAgentOrdered accepts bounded HTTP200 bytes; candidate semantics
are checked later. Change only fixture to HTTP502 after one received request,
which creates the intended uncertain send without changing production.

Parent ruling: after completed journals but before command-output Put, bounded
deterministic command reconstruction is allowed. It must validate the same
canonical input/evaluation and stable output identity/digest with zero category
or provider resend. Unknown journals cannot use this exception. This is not a
general command retry guarantee.

Journal expiry semantic RED command: `go test ./apiserver -run
'^TestSecurityAgentRelease61JournalTicksPostgres$/journal_start_expiry$'
-count=1 -timeout=6m -v`. Actual adapter SQL commits start, fixture loses only
the acknowledgement, proves zero provider calls, then process exits. Exact
effect/child expiry should invoke private test reconciliation; current runtime
is expected to wait forever. Companion cases cover owned unknown, completion
ack-loss/reconstruction, and completed-but-unsettled expiry.

Cleanup expiry RED observed exit1,163.632s: exact expired matching leases
returned lease_wait instead of cleanup_reconcile. Minimal routing delegates
expired cleanup to reviewed reconcile (which independently excludes a live
delivery lease), then retryable cleanup to reviewed claim with caller token.

Runtime partial-cleanup process coverage command: `go test ./apiserver -run
'^TestSecurityAgentRelease61PartialTicksPostgres$' -count=1 -timeout=6m -v`.
Actual planning/admission/application, API cancellation at source store and
deployment finish, fresh-process cleanup through strict partial receipt and
terminal replay; asserts no application/test success receipts, controls or
successor effect. This exercises the approved prerequisite, not new authority.

Revocation semantic RED command: `go test ./apiserver -run
'^TestSecurityAgentRelease61RevocationTicksPostgres$/requester$' -count=1
-timeout=3m -v`. After actual Task11A admission, revoke requester membership;
the next tick must durably stop/audit and replay terminal, with zero effects.
Current reader only sees the approval pause and is expected to fail. Companion
cases revoke definition and existing-test credential authority.

Journal expiry RED exit1,137.932s: actual private start committed, controlled
ack-loss proved zero TLS calls, then expired child/effect returned lease_wait
instead of test_reconcile. Minimal fix delegates only expired leased linked
child/effect with retained journals to reviewed reconcile_uncertain; no lease
token is reconstructed and no artifact or success receipt is synthesized.

Heartbeat+planning uncertainty grouped GREEN exit0,347.401s: heartbeat
196.46s; planning start-ack loss45.69s, provider502 unknown55.83s,
completed-unsettled expiry48.75s. All PG/child processes joined.

Environment interruption: partial application_store compilation failed linker
ENOSPC; the next deployment_finish case compiled and ran. Revocation/requester
command also failed before semantic execution (exit1,4.160s), not a RED.
Data volume237MiB free, shared Go build cache40GiB. Parent authorized only
`go clean -cache` after current test processes join. No repository/user/temp
data deletion; no further builds until cache cleanup and free-space check.

Cleanup-expiry lifecycle GREEN exit0,226.500s: expiry reconcile, fresh retryable
claim, verified cleanup receipt and conservative needs_human terminal replay.
Partial runtime grouped exit1,142.688s solely from source-store ENOSPC compile;
deployment-finish cancellation/strict partial receipt/replay passed135.05s.

Queued pending disk recovery: nested reader validation RED
`go test ./apiserver -run '^TestRelease61StateRejectsMalformedTestAuthority$'
-count=1` (invalid state/owned lease/category/duplicate observations/manifests).
Artifact reconstruction coverage `go test ./apiserver -run
'^TestSecurityAgentRelease61ArtifactTicksPostgres$' -count=1 -timeout=6m -v`
loses acknowledgements after real output Put/Get, restarts completed journals
with zero provider resend and compares the complete immutable file identity/
content snapshot before versus after settlement.

Parent approved dormant DeploymentLeaseDuration configuration: zero defaults
300s, exact integer seconds30–300 only; same selection on application and
cleanup deployment calls. No public/default configuration registration.
Fixtures may select30s and wait for genuine SQL expiry, never rewrite stored
lease/audit evidence. Pending semantic RED after cache recovery:
`go test ./agentsec-worker -run '^TestRelease61DeploymentLeaseBounds$' -count=1`.
Expected absence of bounded configuration; tests include default/endpoints,
fractional seconds, negative, undershoot, overshoot and duration overflow.

Journal group exit1,344.058s: owned started uncertainty/cleanup GREEN175.27s;
completed acknowledgement loss/reconstruction GREEN166.19s, replay TLS0 after
initial TLS1. Both expiry cases failed compilation because the new fixture
driver gained its fault marker while a positional literal remained in the
binding test. Root cause identified at exact compiler line36; changed that
fixture to keyed embedded-field initialization. No production change for it.
All current processes joined before parent-authorized cache-only clean.

Cache cleanup exit0; Data free space41GiB (previous237MiB). Only reproducible
Go build cache removed; no repository, retained evidence or user data deleted.
Cold-cache combined focused RED started: `go test ./agentsec-worker
./apiserver -run '^(TestRelease61DeploymentLeaseBounds|TestRelease61StateRejectsMalformedTestAuthority)$'
-count=1 -timeout=3m`.

Both semantic REDs observed: worker1.086s (bounded deployment configuration
absent); apiserver1.605s (all eight malformed nested child cases accepted).
Minimal GREEN will validate exact duration seconds and reuse closed reviewed
input/artifact/observation contracts before returning reader state.

Focused GREEN worker1.171s/apiserver0.934s. Requester revocation runtime
semantic RED exit1,95.774s: next tick remained approval_pause after actual
membership revocation. SQL correction deliberately not started while the
current process group recompiles worker binaries between fixtures; avoid
introducing a pin/source mismatch into that evidence run.
Running focused grouped process command: `go test ./apiserver -run
'^TestSecurityAgentRelease61(JournalTicks|PartialTicks|ArtifactTicks)Postgres$'
-count=1 -timeout=30m -v`. Uses true30s deployment expiry for claim/store/read
cancellation; asserts live wait first, no lease/audit clock rewriting.

Deployment uncertainty semantic RED command: `go test ./apiserver -run
'^TestSecurityAgentRelease61DeploymentUncertaintyTicksPostgres$' -count=1
-timeout=4m -v`. Actual signed application store commits; foreign live
deployment owner waits, genuine configured30s lease expires, then expected
durable stopped transition and approved provenance-bound partial handoff.
Current runtime is expected to remain lease_wait at stopped (no automatic
application deployment resend and no fabricated application receipt).

Deployment uncertainty RED observed exit1,101.672s: exact 30s lease expired
without rewriting evidence; foreign live lease waited and next tick remained
lease_wait instead of stopped. This separately proves the need for durable
expired-deployment stop authority; it cannot reuse the application bundle as
cleanup evidence. SQL change remains queued until the focused process group
finishes so compiled parent/worker release pins stay aligned.

Budget/plan fault group exit1,125.893s: budget deadline stop/replay passed
66.28s. Plan-row clock fault failed58.69s with SQLSTATE40001 `ordered persisted
authority changed`: the hashed plan also binds its expiry, so mutating only
row/approval clocks is an integrity fault, not natural expiry. Keep that
fault as an unchanged-state refusal test; do not rewrite admission hashes.
Added genuine expiry case: configure60s duration before planning, perform real
admission, then wait for stored plan expiry. No positive evidence is seeded.

ScopeTicks command `go test ./apiserver -run
'^TestSecurityAgentRelease61ScopeTicksPostgres$' -count=1 -timeout=7m -v`
exit1,258.899s: every foreign-scope tick was refused with zero provider calls;
all valid transitions including cleanup_complete passed, but nearly sixty
joined processes exhausted the fixture's four-minute exercise budget while
joining the first successful terminal tick. Root cause is doubled negative
process coverage, not authority. Scope scenario alone gets six minutes;
per-process80/90s and production deadlines remain unchanged.

Gateway authority semantic RED: `go test ./apiserver -run
'^TestSecurityAgentRelease61ApplicationDriftTicksPostgres$/generation$'
-count=1 -timeout=4m -v`. After actual signed source store, generation drift
must durably stop without application receipt/successor execution, retaining
the source and uncertainty. Current runtime is expected to attempt deployment
claim and fail locally without terminalizing. Companion device/credential
revocation cases remain conservative, not permission to bypass cleanup fences.

Scope rerun GREEN exit0,261.296s (test260.36s): all thirty foreign ticks
refused with zero provider calls and unchanged scoped state; all thirty valid
ticks completed through cleanup and repeated terminal replay. Integrity plus
natural expiry command `go test ./apiserver -run
'^TestSecurityAgentRelease61RevocationTicksPostgres$/(plan_integrity|natural_expiry)$'
-count=1 -timeout=5m -v` GREEN exit0,153.243s:63.68s integrity refusal and
88.43s natural configured expiry, durable stopped transition and terminal replay.

Generation drift RED exit1,70.359s (69.35s test): actual application source
store followed by work generation change reached deployment claim and rejected
SQLSTATE40001 `ordered application target changed`; no durable stop occurred.
This is the same missing current-authority stop classification as requester
revocation, not permission to bypass the existing deployment check.

Long grouped run's journal section GREEN666.48s: started acknowledgement loss
170.53s, completed acknowledgement loss165.30s, expired started164.60s,
expired completed166.05s. Actual private journals preserve zero resend;
completed reconstruction uses the approved stable artifact exception. Partial
and artifact sections are still running; keep SQL/pin unchanged until joined.

Additional existing-behavior restart coverage while SQL is held: input Put/Get
faults occur only after the real immutable operation, then a fresh process
repeats dispatch with the identical input identity/content snapshot. Command:
`go test ./apiserver -run '^TestSecurityAgentRelease61ArtifactTicksPostgres$/input_'
-count=1 -timeout=7m -v`. No production change was needed to start this check.

Mixed binary coverage command: `go test ./apiserver -run
'^TestSecurityAgentRelease61MixedTicksPostgres$' -count=1 -timeout=6m -v`.
At queued, source store, test settlement, cleanup completion and terminal
boundaries, a separately joined worker substitutes a stale release61 pin at
the actual readiness query after constructing the dormant composition. It
must refuse before provider work and leave the full SQL snapshot unchanged;
the exact-pin worker then resumes. This tests uncached per-tick readiness,
in addition to the reviewed legacy-worker fence gates in the final packet.

Input artifact restart group GREEN exit0,259.216s: input Put130.73s,
input Get127.40s. Both faults followed actual durable writes/reads, resumed
dispatch from SQL, retained identical artifact snapshot and invoked the actual
category provider exactly once. Additional journal restart fixtures now cover
a second category after a first completed journal; they remain queued for the
next focused group (no production changes for that coverage).

Mixed pin lifecycle GREEN exit0,188.408s (187.25s test), including terminal
replay. Stale readiness refuses before state/external action; exact worker
continues. Long group's partial section GREEN661.27s: source108.64s,
deployment claim138.94s, store140.50s, read141.70s, finish131.49s. All actual
cancelled runs retained conservative strict partial receipts, never created
application receipt/control or successor execution, and replayed terminal.
Only output-artifact section remains before releasing the SQL edit hold.

Frozen development group GREEN exit0,1581.871s. Output artifact section253.13s
(Put130.00s/Get123.13s): actual operation acknowledgement loss, stable complete
immutable snapshot, and provider0 on journal-backed reconstruction after the
initial provider1. All owned processes joined; SQL edit hold released.

Minimal stop-authority correction now reuses reviewed transition_current(true)
and application_current, classifying only named current revocation/expiry
errors. Persisted hash corruption, readiness and lock errors still raise.
Reader and progression share one private predicate; progression retains its
existing conservative audit/state transition. Forward gateway changes stop;
an exact expired application delivery claim must match original audit/work,
source, credential, generation and token-bound digest before stopping. This
predicate performs no lease handoff, resend, receipt or cleanup mutation.
The approved partial cleanup authority remains responsible for immutable
unknown/no-call evidence and any exact expired-lease transition. Terminal
replay never rechecks live context. Metadata probe/pin refresh follows.

Metadata probe exit1,9.356s as expected for changed registered functions:
measured `2c1632624a1daed2f971225b49e4203f5b46e77846b6a3bcb222cf952fff3792`.
Refreshed exact release61 pin before focused current-authority GREEN attempts.

Focused correction commands (not the final source-freeze packet):

- `go test ./apiserver -run '^TestSecurityAgentRelease61(RevocationTicks|ApplicationDriftTicks|DeploymentUncertaintyTicks)Postgres$' -count=1 -timeout=20m -v`
- `go test ./apiserver -run '^TestSecurityAgentMultistep(ApplicationClaim|ProgressionAuthority|ProgressionBinding|ProgressionGatewaySafetyWriter)Postgres$' -count=1 -timeout=10m -v`
- `go test ./apiserver -run '^TestSecurityAgentRelease61JournalTicksPostgres$/journal_(start|complete)_second$' -count=1 -timeout=8m -v`

Hold SQL/pin while the compiled-parent/fresh-worker process checks run.

Correction attempt1 regression group FAILED exit1,60.859s: application claim
passed14.91s, but ordinary progression's previously reviewed gateway-refusal
contract became a successful blocked transition. Verified targets also
legitimately permit applied_generation >= their original generation; treating
all higher desired generations as stale application broke seeded authority
fixtures. Root cause confirmed against application_ready's existing >= rule.
Do not alter those reviewed tests. Controller approved a closed worker-only
`stop` operation, used only after fresh stop_required, that revalidates under
the same locks and reuses blocked audit/state authority. Ordinary progress
must retain its existing refusals. Forward generation stopping applies only
to unacknowledged stored sources. Stale/disappeared stop signals must refuse.

New semantic RED `go test ./apiserver -run
'^TestSecurityAgentRelease61StopAuthorityPostgres$' -count=1 -timeout=3m -v`
exit1,21.751s: actual Task11A admission and reader signal succeed, but the
closed worker stop operation is absent (`repository operation rejected`).
Includes restored-authority stale signal, foreign principal/scope/version,
exact durable stop and stable replay assertions.

Cleanup uncertainty RED queued: `go test ./apiserver -run
'^TestSecurityAgentRelease61CleanupUncertaintyTicksPostgres$' -count=1
-timeout=5m -v`. Actual cleanup deployment store, genuine30s delivery expiry,
then a short owned cleanup/effect lease should wait without heartbeat so the
reviewed expiry reconciler can retain unknown_call/retryable/needs_human.
Expected missing behavior: current runtime renews cleanup ownership despite
the irrecoverable local delivery lease, postponing reconciliation indefinitely.
Only owned cleanup/effect clocks are negative fixtures; deployment leases,
audits and bundles are never rewritten. No unknown removal is acknowledged.

Second-category journal focused group exit1,303.483s: start-second GREEN
176.57s; complete-second reached actual SQL settlement with both completed
categories replaying provider0, but failed the fixture's receipt-count check
125.31s. Root cause: its old exact scenario-name condition treated every name
except `journal_complete` as uncertain, including the new completed-second
case. Corrected that test-only classification; no production change. Rerun
will be grouped with the next focused runtime correction verification.

First correction's current-authority process group revocation section GREEN
419.46s: requester77.88s, definition65.63s, credential65.14s, budget66.15s,
persisted integrity refusal57.58s, natural expiry87.09s. This does not override
the ordinary-progression regression failure; dedicated stop correction still
required. Preservation read-only check: 26 scoped paths, normal short-status
residual1,044 with SHA256 `ea9d965d6938301c00a021e193e7a893467d1180448736c3d02328afdbb1646c`;
out-of-manifest binary diff still `c5fcd9a78e5f71dc094f71e5522df0c7ee71fbb9ebde13fc2c5243a4e3dd45f4`.
An initial --untracked-files=all inventory expanded directories to2,259 entries;
normal short-status reproduces the original1,044 baseline exactly.

Cleanup uncertainty semantic RED observed exit1,167.544s (166.57s test):
after actual removal bundle store and genuine delivery expiry the tick returned
cleanup_heartbeat instead of lease_wait. Minimal GREEN: do not renew owned
cleanup while its retained delivery lease is lost; allow exact cleanup/effect
expiry reconciliation, then retain retryable conservative state and stop the
local loop for explicit recovery without external resend. Normal retryable
cleanup with no retained delivery is unchanged. No SQL/pin change for this fix.

First stop predicate's actual unknown application-deployment store path GREEN
145.31s: genuine expiry, durable conservative stop, approved provenance handoff,
fresh removal bundle, partial receipt and terminal replay. Application device
revocation fixture then failed SQLSTATE23514 before exercising runtime because
it changed state without the required revoked_at. Compared the established
gateway safety-writer fixture; corrected only negative fixture state/time/
version coherency. Credential and generation cases continue on held SQL pin.

Cleanup uncertainty GREEN exit0,186.622s (185.50s test): lost delivery waited
without renewal, exact reviewed expiry reconciler committed unknown_call /
retryable / needs_human, and two restart attempts refused without changed
evidence, cleanup receipt or provider resend. No deployment claim/store/read/
finish repeated after uncertainty. The cleanup/effect clock negative fixture
does not modify the original delivery lease or audit/bundle provenance.

Joined current-authority group exit1,789.298s: Revocation GREEN419.46s,
DeploymentUncertainty GREEN145.31s; ApplicationDrift223.14s had credential
GREEN78.94s/generation GREEN80.23s and the documented device fixture CHECK
failure63.97s. All processes joined before changing SQL/pin.

Closed stop correction implements the controller ruling: only worker `stop`
revalidates the extra stop predicate; ordinary progress keeps its refusal
contract. Stop requires a current condition, exact scoped version, and an
existing immutable stop audit for terminal replay. Generation drift only stops
unacknowledged stored targets. Runtime calls stop only after fresh stop_required.
Metadata probe `go test ./apiserver -run
'^TestSecurityAgentMultistepApplicationClaimPostgres$' -count=1 -timeout=2m -v`
expected pin refusal exit1,9.418s; measured fingerprint
`94c40ec744be6be4a9fe1cd766274d39bdfa5fdf104eafd4e6c628d616ea2ed1`, now pinned.

Focused stop GREEN: `go test ./apiserver -run
'^TestSecurityAgent(Release61(StopAuthority|LaterStop)|Multistep(ApplicationClaim|ProgressionAuthority|ProgressionBinding|ProgressionGatewaySafetyWriter))Postgres$'
-count=1 -timeout=12m -v`, exit0,128.115s. ApplicationClaim13.82s,
ProgressionAuthority20.92s, Binding13.25s, GatewaySafetyWriter9.97s,
StopAuthority21.90s, LaterStop47.11s. Ordinary post-receipt generation and
gateway revocation/rotation refusals are preserved. Stop stale-signal,
foreign-principal/scope/version refusal and immutable terminal replay pass.
`go test ./agentsec-worker ./redteamadapter -run 'Release61' -count=1
-timeout=3m` exit0,1.710s/0.747s.

Remaining focused process command on this pin: `go test ./apiserver -run
'^TestSecurityAgentRelease61(ApplicationDriftTicks|RevocationTicks|DeploymentUncertaintyTicks|JournalTicks)Postgres$/(device|credential|generation|requester|definition|budget|plan_integrity|natural_plan_expiry|journal_complete_second)$|^TestSecurityAgentRelease61DeploymentUncertaintyTicksPostgres$'
-count=1 -timeout=20m -v`. The natural-expiry case is named natural_expiry
(not the unmatched natural_plan_expiry selector); its previous focused GREEN
remains recorded and the full final gate includes it without this filter.

### Orchestration packet changed-path manifest

The orchestration packet above prerequisite head
`8429515dbc4f337198a4749104b0bc6d60c62d50` is limited to these 27 paths
(including the separately recorded metadata-test oracle amendment):

- `.superpowers/sdd/2026-09-20-security-agent-ordered-multistep-plan/task-11-report.md`
- `services/platform/agentsec-worker/security_agent_multistep_planning.go`
- `services/platform/apiserver/security_agent_multistep_progression_repository.go`
- `services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go`
- `services/platform/migrations/production_security_agent_multistep.go`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.progression.sql`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql`
- `services/platform/agentsec-worker/security_agent_release61_command_test.go`
- `services/platform/agentsec-worker/security_agent_release61_lease_test.go`
- `services/platform/agentsec-worker/security_agent_release61_loop.go`
- `services/platform/agentsec-worker/security_agent_release61_loop_test.go`
- `services/platform/agentsec-worker/security_agent_release61_runner_binding_test.go`
- `services/platform/agentsec-worker/security_agent_release61_runtime.go`
- `services/platform/agentsec-worker/security_agent_release61_runtime_test.go`
- `services/platform/agentsec-worker/security_agent_release61_test_runner.go`
- `services/platform/apiserver/security_agent_release61_composition.go`
- `services/platform/apiserver/security_agent_release61_composition_postgres_test.go`
- `services/platform/apiserver/security_agent_release61_runtime_postgres_test.go`
- `services/platform/apiserver/security_agent_release61_state.go`
- `services/platform/apiserver/security_agent_release61_state_postgres_test.go`
- `services/platform/apiserver/security_agent_release61_state_test.go`
- `services/platform/apiserver/security_agent_release61_stop_postgres_test.go`
- `services/platform/migrations/sql/0061_production_security_agent_multistep.orchestration.sql`
- `services/platform/redteamadapter/release61_composition.go`
- `services/platform/redteamadapter/release61_composition_test.go`
- `services/platform/redteamadapter/release61_owned_https_test.go`
- `services/platform/migrations/production_security_agent_multistep_test.go`

Preservation checkpoint before the final packet: normal short-status residual
1,044, SHA256 `ea9d965d6938301c00a021e193e7a893467d1180448736c3d02328afdbb1646c`;
out-of-manifest tracked binary patch SHA256
`c5fcd9a78e5f71dc094f71e5522df0c7ee71fbb9ebde13fc2c5243a4e3dd45f4`.
Index empty. Controller-owned documentation ledger remains baseline.

Proof boundary: the controlled TLS planner/provider and controlled command
fixture exercise real private Go repositories, SQL journals, immutable
artifacts, and signed-bundle store/read/finish acknowledgements. They are
component-only proof, not live provider/cloud/gateway delivery. No physical
gateway publication lane was invented. No default runtime, public API, CLI,
UI or deployment registration uses the new composition. Production policy,
catalog, credentials, live delivery and Task12 activation remain external
gates. The dirty generic red_team_runner.go is not part of this packet.

Rollback cost: orchestration is dormant code plus release61 registered private
functions/checksum/fingerprint, with no new workflow-state table. An unused
release61 demotion restores the reviewed predecessor; after ordered durable
evidence exists, rollback must retain its immutable audits/receipts and obey
the existing guarded migration authority. Do not erase executed evidence or
downgrade an active worker; stop owners and preserve conservative cleanup.

Remaining focused group GREEN exit0,855.580s: Journal complete-second182.81s;
Revocation319.72s (requester65.63,definition66.03,credential66.35,budget65.12,
integrity56.58); DeploymentUncertainty143.68s; ApplicationDrift207.98s
(device69.79,credential69.15,generation69.04). All owned processes joined.

### Orchestration source freeze and consolidated packet

Source freeze: `2026-09-21T12:18:06Z`, prerequisite HEAD
`8429515dbc4f337198a4749104b0bc6d60c62d50`, branch
`codex/cached-runtime-ship-20260917`. All focused commands joined. gofmt -l
returned no files; scoped git diff --check exited0. Only this report may
change during the grouped gate. Source/test SHA256 manifest:

```text
a2a9a0112083a70d3f34680aef0ecabdb36d58e58d34e177c40b8031ac281e3a  services/platform/agentsec-worker/security_agent_multistep_planning.go
a2b467a66ec93e68359874f103670658207496f3c2455d70c9552f02644dffb0  services/platform/apiserver/security_agent_multistep_progression_repository.go
ffa356263652f38cae05d16beb2c2da18943b78154601e0e0df800c72899538c  services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go
5ee7d0310bcbed480326f4eb1f988ddc014cc4a3090dfdca11e416f2ebf8e8e6  services/platform/migrations/production_security_agent_multistep.go
f2467b91fd4ba182a133bb62e2428894d00247c7ad3b36489630bbdb49e63901  services/platform/migrations/sql/0061_production_security_agent_multistep.progression.sql
85a550d3719c842f243cb6d15575b4d8e23234412bd9ff269d3d53caf945740d  services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql
72c1ef950a9551a27873f4c3dc3e9d1132560d8da688c5c09cc354b281c032ed  services/platform/agentsec-worker/security_agent_release61_command_test.go
1eac75ee61234dcab22c274cd8d34342e8831b9ec1eee1410b79689be2ae8aab  services/platform/agentsec-worker/security_agent_release61_lease_test.go
28addb8da0e1b880a8919d580d7d5278742e27c575f550e3c02705a90775fcc8  services/platform/agentsec-worker/security_agent_release61_loop.go
2e452d83a0b995ba27e2807f227dc3c92189b20d6a8af4ea2f61f3448bbe4450  services/platform/agentsec-worker/security_agent_release61_loop_test.go
4886ca5fdf453d6a47fa526e5d0ee5b979505056b3717153cbe129521f769cdd  services/platform/agentsec-worker/security_agent_release61_runner_binding_test.go
dc61288a68ed73d3077d417724461011b88d2b1f6e999bbbedce11f3b2b20d2e  services/platform/agentsec-worker/security_agent_release61_runtime.go
a6cba94299b4a9e7fe751efa8b64bb17b37988b57e576de55ed2ea789e66e660  services/platform/agentsec-worker/security_agent_release61_runtime_test.go
0866144c77569569f205502d1bd23f12644c24089b795efc9309d1de36df8feb  services/platform/agentsec-worker/security_agent_release61_test_runner.go
56d78e3d5486032ea14c26474c5dc9b358544191e782b0c761ae1e3ab3adc2fe  services/platform/apiserver/security_agent_release61_composition.go
061914b9fb2979eb2760f89fd821841590225f92243cf5489eec061e2fd8b5ca  services/platform/apiserver/security_agent_release61_composition_postgres_test.go
6a7d04f10f74c65abb0626e12da657e2a1477b40c1a32e5a8d5fb4bf61a29044  services/platform/apiserver/security_agent_release61_runtime_postgres_test.go
61fc04b1ae32bb05e9e10e19974bb104adf1f693aec06eb606ff1abf22df4cd3  services/platform/apiserver/security_agent_release61_state.go
8a7850d27da161e9c0d1fbd3d83bfeb668049d35a286c0e6f45c9231f574cf44  services/platform/apiserver/security_agent_release61_state_postgres_test.go
ebe2720d8d0f236d0d62e0afe3fd66deeae385a37d5f21d060a9137565220599  services/platform/apiserver/security_agent_release61_state_test.go
63cc162183b4a58c44678251aaff5f23ee6585e21f53e6f3e40b5aa753921a82  services/platform/apiserver/security_agent_release61_stop_postgres_test.go
fae6ddb152335c5c217790961cbe1019efbb0b38d3ec387ce3e3a51e437b8e9c  services/platform/migrations/sql/0061_production_security_agent_multistep.orchestration.sql
35860db761090d6422110b6d9ca31bcad564b41cef14cfbe85d93dc8e0bd6062  services/platform/redteamadapter/release61_composition.go
f9cd11d70302fe5efb44eca1bd8284b1e1d40908854f1f6817e4005f6964978f  services/platform/redteamadapter/release61_composition_test.go
d4dec6ba5b3da603222b7e86b7283e99dee453fbf8ebfce3eaf8e9e6a9297f65  services/platform/redteamadapter/release61_owned_https_test.go
```

Consolidated commands, each launched once from services/platform; disjoint
Postgres groups collectively include every Multistep and Release61 test.
All non-PostgreSQL apiserver tests, full affected worker/adapter/artifact/migration
packages, and selected unaffected public/legacy PostgreSQL routes run under
race as well. No parallel test code/source editing; bounded process groups:

- A: `go test -race ./migrations ./agentsec-worker ./redteamadapter ./artifactstore/... ./internal/multisteppricing -count=1 -timeout=25m`
- B: `go test -race ./apiserver -skip 'Postgres' -count=1 -timeout=20m`
- C: `go test -race ./apiserver -run '^TestSecurityAgentMultistepCleanup.*Postgres$' -count=1 -timeout=35m`
- D: `go test -race ./apiserver -run '^TestSecurityAgentMultistep(Application|Deployment|Test).*Postgres$' -count=1 -timeout=40m`
- E: `go test -race ./apiserver -run '^TestSecurityAgentMultistep.*Postgres$' -skip '^TestSecurityAgentMultistep(Cleanup|Application|Deployment|Test)' -count=1 -timeout=40m`
- F: `go test -race ./apiserver -run '^TestSecurityAgentRelease61(JournalTicks|ArtifactTicks)Postgres$' -count=1 -timeout=45m`
- G: `go test -race ./apiserver -run '^TestSecurityAgentRelease61(PartialTicks|RevocationTicks|ApplicationDriftTicks|DeploymentUncertaintyTicks|CleanupUncertaintyTicks|PlanningUncertaintyTicks)Postgres$' -count=1 -timeout=45m`
- H: `go test -race ./apiserver -run '^TestSecurityAgentRelease61.*Postgres$' -skip '^TestSecurityAgentRelease61(JournalTicks|ArtifactTicks|PartialTicks|RevocationTicks|ApplicationDriftTicks|DeploymentUncertaintyTicks|CleanupUncertaintyTicks|PlanningUncertaintyTicks)' -count=1 -timeout=45m`
- I: `go test -race ./apiserver -run '^TestSecurityAgent(ManualHTTP|ManualClaimIsolation|ExportDefinitionHTTP|ExportNonExportRoute|AttackLabRegisteredPublicProjection|ExistingTestHTTP|ExistingTestHTTPLifecycle|ExistingTestPreservesAPIEnqueueBoundary|ExistingTestLegacyWorkerFence)Postgres$' -count=1 -timeout=20m`

Gate A exit1: migrations36.678s failed CandidateMetadata `source identity
unbound`; worker56.796s, adapter5.538s, artifactstore1.595s, s3driver2.787s,
pricing11.154s all passed under race. Root cause: production correctly hashes
the new registered orchestration fragment, but the independent test oracle
and mutation inventory still ended at planning. Focused reproduction
`go test ./migrations -run '^TestSecurityAgentMultistepCandidateMetadata$'
-count=1` exit1,0.634s with the same assertion.

Controller-approved test-only freeze amendment: add exactly the orchestration
fragment to that oracle and mutation inventory; no production source or SQL/pin
changes. Manifest expands to27 paths with
`services/platform/migrations/production_security_agent_multistep_test.go`.
Old test SHA256 `f457f22ae8280dae395efd94e8b76fad25d5129e409ded12b60b20cadf6a8052`;
new test SHA256 `3e69ff87477cad5ac67e2b925f2afb4de1abeee7eed4e8a805a53c608f98215e`.
This file is compiled only into migrations tests, never into the apiserver,
worker or adapter binaries. All disjoint frozen groups remain valid and are
not restarted. Full migrations alone will rerun with
`go test -race ./migrations -count=1 -timeout=25m`; other Gate A package results
remain valid on unchanged sources.

Test-only amendment frozen at `2026-09-21T12:21:41Z`. Focused oracle/mutation
GREEN `go test ./migrations -run
'^TestSecurityAgentMultistep(CandidateMetadata|EveryFragmentBound)$' -count=1`,
exit0,1.346s. The original25 source/test hashes remain unchanged.

Gate A2 full migrations race rerun PASS, exit0,31.743s. No production change
or unaffected group restart was needed for the test-only oracle amendment.

Gate C full normal cleanup PostgreSQL family PASS under race, exit0,1120.191s.
Includes retained normal receipt behavior, exact source composition, lease/
heartbeat/recovery, cancellation, late stop, every-target acknowledgement,
expiry/deadline windows and conservative replay. Gate D started after C joined.

Gate B FAILED, exit1,1200.844s. It reported the unrelated dirty baseline
TestCoreCompositionMatchesPublicOpenAPI mismatch: base/public150/160 versus
expected150/157, then reached its20m overall timeout while advancing in
TestRuntimeSandboxSearchLeaseRejectsReadinessAfterRowWait/heartbeat migration
setup. The name-only skip also selected210 PostgreSQL tests whose names omit
Postgres; this was an overbroad selector, not evidence of a stalled Task11 test.
Read-only process inspection/sampling showed child waits and advancing fixture
names. The exited gate's go/test PIDs85583/85612 and owned PostgreSQL were
absent after join; no manual stop or deletion was necessary.

Focused unchanged-baseline reproduction `go test -race ./apiserver -run
'^TestCoreCompositionMatchesPublicOpenAPI$' -count=1 -timeout=2m` failed with
the same150/160 count, exit1,1.026s. composition.go, composition_test.go and
openapi/openapi.yaml are pre-existing out-of-manifest dirty paths; the test
counts CoreOperations and that YAML, neither of which Task11 changes. Residual
1,044 and both recorded residual SHA256 values remain byte-identical. No
unrelated composition/OpenAPI edit is made and broad apiserver baseline is
NOT claimed green.

Controller-approved B2 replacement: frozen Task11 state unit file and directly
affected existing Multistep unit families, with exact test names enumerated:

- `TestSecurityAgentMultistepAdmissionRepositoryBoundary` — `apiserver/security_agent_multistep_admission_repository_test.go`
- `TestSecurityAgentMultistepApplicationRepositoryBoundary` — `apiserver/security_agent_multistep_application_repository_test.go`
- `TestSecurityAgentMultistepApplicationSignatureBoundary` — `apiserver/security_agent_multistep_application_repository_test.go`
- `TestSecurityAgentMultistepApplicationCancellationResponse` — `apiserver/security_agent_multistep_application_repository_test.go`
- `TestSecurityAgentOrderedCandidateClosedContract` — `apiserver/security_agent_multistep_contract_test.go`
- `TestSecurityAgentOrderedContextCannotWidenAuthority` — `apiserver/security_agent_multistep_contract_test.go`
- `TestSecurityAgentOrderedSubmissionBindsTrustedRun` — `apiserver/security_agent_multistep_contract_test.go`
- `TestSecurityAgentOrderedRelease60RepositoryRemainsClosed` — `apiserver/security_agent_multistep_contract_test.go`
- `TestSecurityAgentMultistepDeploymentRepositoryBoundary` — `apiserver/security_agent_multistep_deployment_repository_test.go`
- `TestSecurityAgentMultistepDeploymentWireDecoder` — `apiserver/security_agent_multistep_deployment_wire_test.go`
- `TestSecurityAgentMultistepDeploymentSigningBudget` — `apiserver/security_agent_multistep_deployment_wire_test.go`
- `TestSecurityAgentMultistepProgressionRepositoryBoundary` — `apiserver/security_agent_multistep_progression_repository_test.go`
- `TestSecurityAgentMultistepProgressionResponsePostconditions` — `apiserver/security_agent_multistep_progression_response_test.go`
- `TestSecurityAgentMultistepTestCancellationResponse` — `apiserver/security_agent_multistep_test_cancellation_repository_test.go`
- `TestSecurityAgentMultistepTestExpiryResponse` — `apiserver/security_agent_multistep_test_expiry_repository_test.go`
- `TestSecurityAgentMultistepTestRepositoryBoundary` — `apiserver/security_agent_multistep_test_repository_test.go`
- `TestSecurityAgentMultistepTestArtifactJSON` — `apiserver/security_agent_multistep_test_settlement_repository_test.go`
- `TestRelease61StateRejectsMalformedTestAuthority` — `apiserver/security_agent_release61_state_test.go`

B2 command: `go test -race ./apiserver -run '^(TestSecurityAgentMultistepAdmissionRepositoryBoundary|TestSecurityAgentMultistepApplicationRepositoryBoundary|TestSecurityAgentMultistepApplicationSignatureBoundary|TestSecurityAgentMultistepApplicationCancellationResponse|TestSecurityAgentOrderedCandidateClosedContract|TestSecurityAgentOrderedContextCannotWidenAuthority|TestSecurityAgentOrderedSubmissionBindsTrustedRun|TestSecurityAgentOrderedRelease60RepositoryRemainsClosed|TestSecurityAgentMultistepDeploymentRepositoryBoundary|TestSecurityAgentMultistepDeploymentWireDecoder|TestSecurityAgentMultistepDeploymentSigningBudget|TestSecurityAgentMultistepProgressionRepositoryBoundary|TestSecurityAgentMultistepProgressionResponsePostconditions|TestSecurityAgentMultistepTestCancellationResponse|TestSecurityAgentMultistepTestExpiryResponse|TestSecurityAgentMultistepTestRepositoryBoundary|TestSecurityAgentMultistepTestArtifactJSON|TestRelease61StateRejectsMalformedTestAuthority)$' -count=1 -timeout=10m`. This narrow replacement does not erase or supersede
the unrelated Gate B failure/timeout; both remain handoff concerns.

Gate F full category-journal and input/output artifact process families PASS
under race, exit0,1582.841s. Includes category start/complete for both categories,
expired unknown/completed journals, command reconstruction with zero provider
resend, immutable Put/Get fault boundaries, cleanup and terminal replay.

B2 FAILED, exit1,16.213s: existing
TestSecurityAgentMultistepTestCancellationResponse/progress reports `impossible
successor cancellation accepted progress`. Root cause under investigation:
the Task11 response decoder extended the executing-step blocked branch to
ordinary progress as well as stop, admitting a cancelled-parent response that
the reviewed ordinary-progress contract rejects. Source remains frozen while
the other groups join; do not weaken the existing test.

Controller ruling: after all current frozen groups join, restore ordinary
progress refusal exactly. Only private stop with exact needs_human response
may decode an executing blocked step. Change only the new LaterStop
terminalization call to stop, keeping successor-ready progress unchanged.
Then amend the source freeze and rerun exact affected decoder/units, closed
stop compatibility, LaterStop and Release61 process selectors that include
the decoder. Current frozen evidence remains labeled with its original hash;
no relabeling or unrelated baseline fix is permitted.

Gate I selected legacy/public PostgreSQL routes PASS under race, exit0,190.898s:
manual HTTP and claim isolation, export HTTP/non-export routing, Attack Lab
public projection, existing-test HTTP/lifecycle/enqueue boundary and legacy
worker fence. This does not change the separate unrelated OpenAPI count concern.

Gate G current frozen binary PASS under race, exit0,1850.504s: planning
uncertainty, partial cancellation at all five application/deployment boundaries,
revocation/budget/integrity/natural expiry, application delivery uncertainty,
cleanup delivery uncertainty and device/credential/generation drift. This is
pre-decoder-amendment evidence and will not be relabeled as its later rerun.

Gate D full application/deployment/existing-test PostgreSQL families PASS
under race, exit0,1094.672s. Gate H original frozen release61 remainder PASS
under race, exit0,2197.838s: prerequisite preflight/provenance refusals, scoped
reader/composition, full lifecycle and acknowledgement restart, lease/heartbeat,
cross-tenant/mixed-binary, stop and replay. H remains explicitly before the
decoder amendment and will be rerun on the amended source. E still pending;
all other old-binary groups have joined before any decoder change.

Gate E PASS under race, exit0,1785.427s. All original frozen groups have now
joined. Controller further requires SQL ordinary progress to preserve its
reviewed switch-only refusal: only closed worker stop may consume
execution_stopped after a fresh stop_required read. New preflight kill_switch
test now reads that signal, demands ordinary progress refuse without writes,
then calls stop. Only the new LaterStop terminalization changes to stop;
its successor-ready progression remains progress. No original refusal test
is weakened.

Amendment semantic RED command: `go test ./apiserver -run
'^TestSecurityAgentRelease61OrchestrationPreflightPostgres$/kill_switch$'
-count=1 -timeout=3m -v`. Expected failure: ordinary progress consumes
worker-only stop. Existing B2 TestCancellationResponse/progress supplies the
independent Go decoder semantic RED. Production SQL/decoder remain unchanged
until the new SQL RED joins.

Observed SQL semantic RED: exit1,22.699s; kill_switch reports `ordinary progress
consumed worker-only stop <nil>`. Real planning provider_calls=1; owned
PostgreSQL joined normally. Root cause confirmed: shared blocked predicate
unconditionally consumes execution_stopped. Minimal correction gates this
new condition to op=stop; executing blocked Go responses accept stop only
with needs_human (original cancel response retained).

Exact 18-unit B2 race selector now GREEN, exit0,16.245s. Metadata probe
`go test ./apiserver -run '^TestSecurityAgentMultistepApplicationClaimPostgres$'
-count=1 -timeout=2m -v` expected refusal, exit1,9.621s, measured new exact
registered fingerprint `6b6a74cba9ee791d8b23c08df2f3d08949a339e23460694bc0e2d2d3f25c8e92`.
Updated only the release61 constant to that measured value; PostgreSQL joined.

Focused amended race command: `go test -race ./apiserver -run
'^TestSecurityAgentRelease61(OrchestrationPreflight|StopAuthority|LaterStop)Postgres$'
-skip 'OrchestrationPreflightPostgres/(source_store|deployment_.*|stopped|deadline|lease_loss|source_drift|mixed_targets|composition|cleanup_unknown)$'
-count=1 -timeout=5m -v`. Kill-switch preflight GREEN,25.21s (top-level36.59s,
including worker build); closed stop and LaterStop still running at freeze.

### Amended source freeze — 2026-09-21T13:21:11Z

Only five files changed from the original source freeze (plus the already
approved metadata-test-only oracle amendment): progression decoder, preflight
kill-switch test, LaterStop test, progression SQL stop-only predicate and
measured fingerprint constant. Original hashes are retained above. No public
route, generic allocator, historical SQL or unrelated baseline was changed.
`git diff --check` exit0. The following complete 26-source manifest is frozen
for amended process gates F2/G2/H2 and compatibility/migration group J;
report-only evidence additions are permitted while these run.

```text
a2a9a0112083a70d3f34680aef0ecabdb36d58e58d34e177c40b8031ac281e3a  services/platform/agentsec-worker/security_agent_multistep_planning.go
7205f464cded976826f6eabea4e08bf574639e8a63df263e319da3f582bfe70a  services/platform/apiserver/security_agent_multistep_progression_repository.go
d615c9bcc3786c8b52fb6e1dfc24c50b949183208f3d5833ec3ecbc9a21abbe3  services/platform/apiserver/security_agent_release61_orchestration_preflight_postgres_test.go
efa3762231a61e5d5d9f196e90feabc019cd0b19d9b17bddaeb9a9e11b7564b3  services/platform/migrations/production_security_agent_multistep.go
fcc21f4dbf71aef0787d7f7a04ea1441bb7827f1d1eb754fe5a1cd4ac88435c9  services/platform/migrations/sql/0061_production_security_agent_multistep.progression.sql
85a550d3719c842f243cb6d15575b4d8e23234412bd9ff269d3d53caf945740d  services/platform/migrations/sql/0061_production_security_agent_multistep.promote.sql
72c1ef950a9551a27873f4c3dc3e9d1132560d8da688c5c09cc354b281c032ed  services/platform/agentsec-worker/security_agent_release61_command_test.go
1eac75ee61234dcab22c274cd8d34342e8831b9ec1eee1410b79689be2ae8aab  services/platform/agentsec-worker/security_agent_release61_lease_test.go
28addb8da0e1b880a8919d580d7d5278742e27c575f550e3c02705a90775fcc8  services/platform/agentsec-worker/security_agent_release61_loop.go
2e452d83a0b995ba27e2807f227dc3c92189b20d6a8af4ea2f61f3448bbe4450  services/platform/agentsec-worker/security_agent_release61_loop_test.go
4886ca5fdf453d6a47fa526e5d0ee5b979505056b3717153cbe129521f769cdd  services/platform/agentsec-worker/security_agent_release61_runner_binding_test.go
dc61288a68ed73d3077d417724461011b88d2b1f6e999bbbedce11f3b2b20d2e  services/platform/agentsec-worker/security_agent_release61_runtime.go
a6cba94299b4a9e7fe751efa8b64bb17b37988b57e576de55ed2ea789e66e660  services/platform/agentsec-worker/security_agent_release61_runtime_test.go
0866144c77569569f205502d1bd23f12644c24089b795efc9309d1de36df8feb  services/platform/agentsec-worker/security_agent_release61_test_runner.go
56d78e3d5486032ea14c26474c5dc9b358544191e782b0c761ae1e3ab3adc2fe  services/platform/apiserver/security_agent_release61_composition.go
061914b9fb2979eb2760f89fd821841590225f92243cf5489eec061e2fd8b5ca  services/platform/apiserver/security_agent_release61_composition_postgres_test.go
6a7d04f10f74c65abb0626e12da657e2a1477b40c1a32e5a8d5fb4bf61a29044  services/platform/apiserver/security_agent_release61_runtime_postgres_test.go
61fc04b1ae32bb05e9e10e19974bb104adf1f693aec06eb606ff1abf22df4cd3  services/platform/apiserver/security_agent_release61_state.go
8a7850d27da161e9c0d1fbd3d83bfeb668049d35a286c0e6f45c9231f574cf44  services/platform/apiserver/security_agent_release61_state_postgres_test.go
ebe2720d8d0f236d0d62e0afe3fd66deeae385a37d5f21d060a9137565220599  services/platform/apiserver/security_agent_release61_state_test.go
c2470f75e75021ccb8c9cbc28dcdb0996e3b083da7fdbd4ee5c057cb1cf125ef  services/platform/apiserver/security_agent_release61_stop_postgres_test.go
fae6ddb152335c5c217790961cbe1019efbb0b38d3ec387ce3e3a51e437b8e9c  services/platform/migrations/sql/0061_production_security_agent_multistep.orchestration.sql
35860db761090d6422110b6d9ca31bcad564b41cef14cfbe85d93dc8e0bd6062  services/platform/redteamadapter/release61_composition.go
f9cd11d70302fe5efb44eca1bd8284b1e1d40908854f1f6817e4005f6964978f  services/platform/redteamadapter/release61_composition_test.go
d4dec6ba5b3da603222b7e86b7283e99dee453fbf8ebfce3eaf8e9e6a9297f65  services/platform/redteamadapter/release61_owned_https_test.go
3e69ff87477cad5ac67e2b925f2afb4de1abeee7eed4e8a805a53c608f98215e  services/platform/migrations/production_security_agent_multistep_test.go
```

F2/G2/H2 repeat the exact original F/G/H race commands on this amended source.
J runs the exact 18-name B2 selector; full race migrations; and under race
all Multistep Progression, Registered, Schema, RollbackSnapshot,
ForeignKeyTriggerDrift, LegacyActionRestoration, PlanningLegacyRestoration,
ApplicationClaim PostgreSQL tests. The selected tests exercise changed SQL
compatibility, restoration/readiness and fingerprint drift. Original broader
application/deployment/cleanup gates C/D and public gate I are preserved as
original-freeze evidence, not relabeled amended-source evidence.

Focused amended race group fully GREEN, exit0,114.677s. StopAuthority22.74s;
LaterStop53.22s (approval26.32s, executing23.97s). All owned PostgreSQL
processes reported joined normally. J PostgreSQL command:
`go test -race ./apiserver -run '^TestSecurityAgentMultistep(Progression.*|Registered.*|Schema|RollbackSnapshot|ForeignKeyTriggerDrift|LegacyActionRestoration|PlanningLegacyRestoration|ApplicationClaim)Postgres$' -count=1 -timeout=35m`.

Amended freeze J units: exact B2 18-name race selector PASS,exit0,17.640s.
J migrations: `go test -race ./migrations -count=1 -timeout=25m`
PASS,exit0,32.959s. PostgreSQL compatibility/process groups remain running.

J PostgreSQL compatibility/restoration group PASS under race,exit0,301.278s.
No changes were needed. Amended source hashes remain frozen; F2/G2/H2 are
the remaining process groups. Preservation read-only recheck: exactly1,044
out-of-manifest entries and both original status/binary-diff SHA256 hashes
match. No index contents or unrelated modifications were introduced.

Amended gate F2 PASS under race,exit0,1524.197s: all category start/complete
boundaries (including both categories and expired journals), immutable
input/output Put/Get fault recovery, no provider resend, cleanup and terminal
replay. This is evidence for the amended hashes above, distinct from F.
Read-only caller inventory confirms the release61 composition constructor is
called only by component tests; no default/public registration was added.

Amended gate G2 PASS under race,exit0,1779.453s: planning uncertainty,
all five partial application/deployment cancellation boundaries, requester/
definition/credential/budget/integrity/natural expiry, deployment and cleanup
uncertainty, and device/credential/generation drift. H2 is the only remaining
group. This result is for the amended source, not relabeled original G.

Amended gate H2 PASS under race,exit0,2111.499s: full prerequisite preflight,
scope reader/composition, planning/application/existing-test/lifecycle/commit
restart, lease/heartbeat, scope and mixed-binary refusal, runtime stop,
queued/state authority, closed stop and LaterStop approval/executing replay.
All amended grouped commands have joined. Read-only process inventory found
none of the owned Go/test process IDs (18609/18639,18630/18657,18647/18683,
19294/19303), no running PostgreSQL fixture or worker compiler. No manual
termination, lease-row rewrite or destructive cleanup was used for this gate.

### Final orchestration verification and handoff concerns

All 26 source/test SHA256 hashes exactly match the amended freeze. Scoped
gofmt -l returned no files; git diff --check exit0; index was empty before
scoped staging. Exactly1,044 unrelated short-status entries remain, status
SHA256 `ea9d965d6938301c00a021e193e7a893467d1180448736c3d02328afdbb1646c`,
outside-manifest tracked binary patch SHA256
`c5fcd9a78e5f71dc094f71e5522df0c7ee71fbb9ebde13fc2c5243a4e3dd45f4`.
Branch remains codex/cached-runtime-ship-20260917 above approved prerequisite
8429515dbc4f337198a4749104b0bc6d60c62d50. No public/API/CLI/UI/default
registration, push or unrelated edit occurred.

Final packet result is DONE_WITH_CONCERNS, pending independent Task11 review:
affected grouped unit/migration/authority/process/race gates pass, including
the separately recorded amended compatibility and full release61 reruns.
The broad non-Postgres-named API gate B is NOT green: it includes the preserved
unrelated OpenAPI composition mismatch and timed out in pre-existing
PostgreSQL-named-without-suffix families. The exact scoped replacement is
green; it does not erase that baseline failure/timeout. No production or live
provider/cloud/physical-gateway proof is claimed. All controlled TLS, command,
artifact and gateway acknowledgement evidence is component-only; external
configuration and activation remain Task12/deployment gates.

### Orchestration commits

Source commit: `e4c59006522694f1226eacf1bd68dda7ef6851f6`
(`feat(security-agent): add dormant release61 ordered worker orchestration`).
Staged scope verified as exactly the 26 frozen source/test manifest paths,
3117 insertions and28 deletions; staged diff --check exit0. This evidence
report is a separate documentation-only commit after the source commit, so
its report records the final source identity without changing tested bytes.
No push. Independent full Task11 review is the next gate; no Task12 runtime
registration or public activation is included.

## Independent review correction — dependency closure and local readiness

Independent review of `e4c59006..e282d306` returned CHANGES REQUIRED. The
published Task11 tree was not self-contained: a clean `git archive e282d306`
failed to compile because registered release61 journal/composition code named
the untracked `PostgresInvocationJournal`, journal receipt/comparison types and
SQL constants. Overlaying that reviewed adapter precursor exposed two more
dirty-only dependencies: Task11 planner contracts named unpublished apiserver
specialization fields and `budgetJSONObject`, while the worker named generic
prepared-plan/cost types and release61 runner-v2 evidence/image fields. This
was a Critical reproducibility defect. It invalidates the old report's claim
that the final committed Task11 range was fresh-checkout reproducible.

The same review found an Important fail-closed defect. `Tick` could call
journal readiness and authoritative state before proving the planner, artifact
store, test runner, both worker identities and lease tokens, signing key ID,
private key and registered public-key match were locally usable. Composition
also accepted an empty gateway key set. TDD RED for thirteen invalid runtime
dependencies observed four or five composition database calls plus two journal
database calls before rejection. Empty composition keys were accepted.

The correction in source commit `98c61e95` makes the exact range independent:

- The reviewed linked-HTTPS adapter prerequisite is committed as an exact
  closure: adapter/invoker/secret-resolver changes, journaled invocation,
  PostgreSQL journal, target comparison and their focused tests.
- Task11 owns private ordered planner context, evidence/reference, prepared
  request and cost-bound shapes, plus an exact duplicate/trailing/null-rejecting
  JSON object parser. It no longer imports the dirty generic planner/budget
  feature chain.
- The release61 runner consumes the pinned runner image and strict v2 evidence
  contract with only the two request/result data fields needed by the shared
  runner; unrelated linked-runtime routing remains uncommitted.
- `GatewayPolicyKeys.Valid` and exact `Contains` permit composition and worker
  preflight to validate the configured signing key locally. Empty keys,
  malformed keys and public/private mismatch fail before database readiness.
- `securityAgentRelease61Runtime.preflight` runs before journal readiness,
  state reads, claims, mutations, artifact/provider calls or process work. It
  checks every runtime dependency, identity/token, planner/runner local state,
  signing key and composition key match. The thirteen-case test records zero
  composition, journal, store and provider calls for every refusal.
- A Task11-namespaced test-fixture closure replaces references from committed
  Task11 tests to untracked budget/existing-test test helpers. It adds no
  production planner/budget route. The attack-path fixture refactor is staged
  without its unrelated working-tree test addition.

### Review-fix RED/GREEN evidence

Focused TDD GREEN after each RED:

- `go test ./agentsec-worker -run
  '^TestSecurityAgentRelease61TickPreflightsEveryDependencyBeforeRead$'
  -count=1` — PASS; all thirteen invalid configurations make zero reads,
  writes, artifact calls and provider calls.
- `go test ./policy ./apiserver -run
  '^(TestGatewayPolicyKeysExposeOnlyValidatedExactMembership|TestSecurityAgentRelease61CompositionRejectsMissingKeysBeforeReadiness)$'
  -count=1` — PASS.
- `go test ./agentsec-worker -run
  '^(TestSecurityAgentOrdered|TestSecurityAgentMultistepPlanningRawTransport|TestSecurityAgentMultistepPricingPreparedBinding|TestSecurityAgentRelease61TickPreflightsEveryDependencyBeforeRead)$'
  -count=1` — PASS.

A fresh archive of the exact staged tree, and then a second fresh archive of
commit `98c61e95`, passed:

```text
go build ./agentsec-worker ./redteamadapter ./apiserver ./policy
go test ./agentsec-worker ./redteamadapter ./apiserver ./policy -run '^$' -count=1
```

Both commands exit0. The compile-only test command proves every committed test
file resolves without any untracked overlay. On the exact commit archive, the
focused normal suite also passed: worker ordered/preflight/linked-artifact,
policy key membership, apiserver ordered/composition and the complete normal
`redteamadapter` package.

Exact-commit focused race tests passed:

```text
go test -race ./agentsec-worker -run '^(TestSecurityAgentOrdered|TestSecurityAgentMultistepPlanningRawTransport|TestSecurityAgentMultistepPricingPreparedBinding|TestSecurityAgentRelease61TickPreflightsEveryDependencyBeforeRead|TestRedTeamLinkedArtifactPreservesBoundObservation)$' -count=1
go test -race ./policy ./apiserver -run '^(TestGatewayPolicyKeysExposeOnlyValidatedExactMembership|TestSecurityAgentRelease61CompositionRejectsMissingKeysBeforeReadiness|TestSecurityAgentOrdered)' -count=1
go test -race ./redteamadapter -run '^(TestSecretsCredential|TestHTTPSInvoker|TestAuthorizeTarget|TestLinkedHandler|TestLegacyHandler|TestJournaledInvocation|TestMountedExistingTestAdapter|TestJournalReceipt)' -count=1
go test -race ./redteamadapter -run '^(TestPostgresJournal.*|TestPostgresResolver.*|TestRelease61JournalComposition|TestOrderedJournalPrivateBoundary)$' -count=1
```

Results were PASS: worker 3.700s, policy 1.651s, apiserver 2.641s,
adapter boundary group 2.046s and adapter PostgreSQL-stub/readiness group
2.745s.

Affected real PostgreSQL/process verification on the exact commit archive:

- `TestSecurityAgentRelease61OrchestrationPreflightPostgres` passed under race
  in 501.83s, including source-store, deployment claim/store/read/finish,
  stop, kill switch, deadline, lease loss, source drift, mixed targets,
  composition and cleanup uncertainty.
- An initially overbroad combined preflight+journal selector used one 15-minute
  timeout. Preflight passed, then race/cold-process load caused `journal_start`
  to reach a changed deployment lease and `journal_complete` to observe
  planning reconciliation before the expected next tick; the command reached
  its exact 900.680s timeout during `journal_complete_expiry`. The timeout
  stack was waiting for an owned child process, not a SQL deadlock. The command
  exited itself and process inventory found no owned worker, adapter or
  PostgreSQL residue. This failed/timeout run is retained as a concern and is
  not relabeled green.
- The six directly affected journal scenarios were then run in bounded groups
  so each fixture received its designed process budget. Under race,
  `journal_start` passed in 165.536s, `journal_complete` in 164.084s, the
  start/complete expiry pair in 338.442s and the start/complete second-category
  pair in 343.771s. These use real owned PostgreSQL, controlled TLS and joined
  worker/adapter processes; they remain component proof, not live provider or
  production deployment proof.

No broader historical Task11 gate is represented as rerun on `98c61e95`.
Earlier results in this report remain historical evidence for the original
source freeze; the commands above are the review-fix evidence. The unrelated
dirty working tree was preserved, no public/default route was activated and no
push occurred.

### Review-fix commits

Source commit: `98c61e95` (`fix(security-agent): make release61 runtime
self-contained`). It is a 59-file exact source/test closure above `e282d306`;
the partial prerequisite staging deliberately excludes unrelated dirty hunks.
This report is committed separately after the tested source identity.

## Independent re-review correction — exact preflight identity and legacy runner

Independent re-review confirmed the clean dependency closure in `98c61e95`,
but found one Critical and two Important readiness defects. The active legacy
red-team production constructor passed no runner image in the committed tree,
while the shared runner constructor had begun requiring a release61 image pin;
legacy worker construction therefore always returned `errRuntimeUnavailable`.
The release61 preflight also accepted any nonnil journal and validated only the
pricing scope/run. It did not prove the ordered journal mode, exact release61
checksum/fingerprint and usable database, or the exact account profile,
tenant-scoped credential reference, canonical policy/account identities,
versions and digests bound to the locked planner model and credential.

Source commit `75957f630ae15ae8fdfa044165a292e6b5333627` corrects all three
findings without staging or depending on the dirty
`red_team_production.go`, `runtime_config.go`, or `RedTeamRunnerImage` feature:

- `PostgresInvocationJournal` now records private immutable ordered-mode state
  only when the exact release61 `ordered()`/`Release61` composition succeeds.
  `ValidOrderedConfiguration` performs no I/O and requires that mode, exact
  caller-supplied checksum/fingerprint and a nonnil (including typed-nil-safe)
  database. A base journal with the exact release61 pins is explicitly refused.
- `multisteppricing.ValidLookupIdentity` is the single zero-I/O validator for
  the lookup identity. `Repository.Lookup` reuses it, and release61 preflight
  builds the same request while holding the current planner read lock. This
  binds scope, provider/model/profile/unit, scoped credential reference and
  token digest, request policy/version/limit, canonical policy/account IDs,
  versions and policy digest before readiness or state I/O.
- Preflight tests mutate every selection identity field, both canonical IDs,
  the planner model, journal mode/pins/database, and runner image. Each refusal
  records zero composition, journal, artifact-store and provider calls.
- The shared runner constructor again accepts an empty image only for dormant
  legacy v1 composition and rejects any malformed nonempty image. Direct v2
  use and release61 preflight still require a digest-pinned image. Construction
  no longer reads mounted token/CA files; the existing production `Ready`,
  `Run`, and release61 preflight boundaries still validate them before work.
  A regression uses the real `newProductionRedTeamDependencies` constructor,
  not an injected runner, and proves the committed legacy configuration remains
  constructible.

TDD RED was observed before implementation: the new journal/pricing methods
were absent; stale/base journals and malformed pricing fields performed two
journal plus five composition calls; the empty-image legacy runner and real
production dependency constructor both returned `runtime unavailable`.

Focused GREEN on the affected packages:

```text
go test ./internal/multisteppricing ./redteamadapter ./agentsec-worker -count=1
```

PASS before the final source commit: pricing 4.272s, adapter 1.427s, worker
29.155s. No SQL behavior changed, so the re-review instruction to avoid the
long PostgreSQL gates was followed.

A clean staged archive ran `go build ./...`, the complete affected-package
normal suite, and the preserved prior focused race selectors. Results were
PASS: pricing 4.109s, adapter 1.392s, worker 8.180s; worker focused race 5.603s;
adapter boundary race 1.342s; adapter PostgreSQL-stub/readiness race 2.650s;
and full pricing race 9.088s.

Finally, a fresh `git archive` of exact source commit `75957f63` at
`/tmp/task11-final-8FUBY3` passed `go build ./...` and the exact five-test
normal/race correction selector:

```text
go test ./internal/multisteppricing ./redteamadapter ./agentsec-worker \
  -run 'Test(LookupIdentityValidationMatchesRepositoryRulesWithoutIO|PostgresJournalConfigurationIsExactAndZeroIO|SecurityAgentRelease61TickPreflightsEveryDependencyBeforeRead|ProductionRedTeamRunnerAllowsUnpinnedLegacyV1Composition|ProductionRedTeamDependenciesRemainConstructibleForLegacyV1)$' -count=1
go test -race ./internal/multisteppricing ./redteamadapter ./agentsec-worker \
  -run 'Test(LookupIdentityValidationMatchesRepositoryRulesWithoutIO|PostgresJournalConfigurationIsExactAndZeroIO|SecurityAgentRelease61TickPreflightsEveryDependencyBeforeRead|ProductionRedTeamRunnerAllowsUnpinnedLegacyV1Composition|ProductionRedTeamDependenciesRemainConstructibleForLegacyV1)$' -count=1
```

Normal PASS: pricing 0.506s, adapter 0.713s, worker 1.841s. Race PASS:
pricing 1.437s, adapter 1.675s, worker 4.198s. The source commit contains
exactly eleven owned source/test files (222 insertions, 35 deletions). The
massive unrelated dirty tree remains preserved, no public/default route or SQL
was changed, no PostgreSQL gate was rerun, and no push occurred.
