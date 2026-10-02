# P4C admission-accounting checkpoint

P4C is in progress. This is a bounded admission-accounting checkpoint for independent review, not P4C acceptance, P4 completion, or deployed readiness. New73 starts are persisted but **not consumed by a Temporal workflow**. Do not activate this packet as completed orchestration.

I captured 1,987 baseline paths covering `services/platform` and this report, preserving existing file bytes and SHA-256 values. The baseline is `.superpowers/sdd/2026-09-22-temporal-openfga-execution-plan/p4c-baseline.json`, SHA-256 `a40ba8d70ad7a2a0d575782c60dc5a909b62eec902949bd0c496858c668a4116`. `p4c-capture.mjs` produces the overlay-relative diff and checks every accepted SQL file, including72. Base HEAD is recorded in that manifest. No commit, push, production activation, shared reset, or retirement-ledger change is authorized in this packet.

## The callers don't share one trigger schema

Source paths in this report are relative to the retained worktree. These are checked source observations, not test results.

| Entry and caller | Installed route and identity | What P4C must preserve |
| --- | --- | --- |
| Selected ordered HTTP: `security_agent_ordered_http.go`, `runSecurityAgent` | `SecurityAgentOrderedResourceAuthority.Trigger` in `security_agent_ordered_resource.go`, then public62 `trigger_resource`; classification occurs before semantic validation. | Finding/attack-path kinds, source/version, canonical ordered run ID, actor/idempotency receipt, audit and historical replay. |
| Retained HTTP: `PostgresRepository.RunSecurityAgent` | `security_agent_repository.go`: manual branch; otherwise public55 existing-test route or older finding/session route selected by readiness. | Existing test source checks and specialized request shapes. A shared repository helper alone does not migrate the selected ordered handler. |
| Manual HTTP | `security_agent_manual_start.go`: temporal66 `manual_run` on the upgraded installation; SQL65 captures the public request receipt atomically. | Original manual intent digest, caller-provided persisted run/audit/receipt identity, replay and current requester/creator permission checks. |
| Automatic source selection | `security_agent_runtime.go:RunOnce` calls `ScheduleSecurityAgentTriggers`; `security_agent_worker_repository.go` selects versioned scheduling; its installed70 database adapter maps to `zasp_temporal70.op02 -> body14`. | Finding, fresh blocked runtime event, attack-path selection, per-source eligibility, skipped stale candidates, bounded fairness. Automatic admission has no public request receipt, so SQL65's receipt trigger does not capture its start. |
| Webhook action | `send_response_webhook` definition/action family and `security_agent_webhooks_repository.go` acceptance/settlement; original M7A-24. | Destination/version/secret/signature authority, no-resend unknown delivery, status/acceptance/settlement. There is no existing inbound `webhook` trigger kind to invent. |
| Approved action | Ordered HTTP decision adapter and retained `DecideSecurityAgentApproval`, then SQL65 decision capture. | Same scoped run, current approval/fresh-auth authority, no new run or capacity allocation. |
| Production composition | `agentsec-api/production_runtime.go` forwards ordered-HTTP selection to `apiserver/production.go`; `security_agent_ordered_production.go` verifies exact release. Worker `production_runtime.go` builds the retained repository/processor and the Temporal worker/relay. | Preserve both selected and retained routes. Never place `RunOnce` or an old lease loop inside an Activity. |

The old existing-test function named `schedule` is a periodic scan of sources, not a user-defined cadence. Definitions can also contain `schedule/daily`; that is separate. The controller ruled that P4C should preserve exact schemas, use a Temporal Schedule to wake source selection, and install explicit versioned selector configuration with a shipped 1-second value. The value matches the inspected deployment's existing worker interval, but it must not become an implicit runtime fallback. Reject missing, invalid, or fractional-second selector configuration.

## Who holds capacity

The same Security Agent definition can have work under several execution owners during cutover:

* Ordered Temporal. SQL66 owns the run, SQL68 owns planning/effect journals, and workflow69 drives the two-step ordered protocol.
* Retained ordered61 planning and progression keep their original rows and authority. They cannot be discarded because another owner has been enabled.
* Single-action parents still use installed70, with linked existing-test invocation and reconciliation through71. The actual `existingTestScheduler` in `security_agent_test_scheduler.go` is a downstream reconciliation loop, not the automatic source-selector boundary.

SQL68 `active_count` handles organization-wide planning and budget limits. It does not implement per-definition scheduled admission. Existing-test admission has two separate per-definition counts: the locked admission core and candidate selection before LIMIT. Both currently query run rows through the caller's visibility. P4C must make both see all owners and enforce the same bound at insertion, including paths that do not use the scheduler helper.

Lease expiry is not proof of release. `zasp_security_agent_test_invocations.state='started'`, an unsettled test link, Temporal unknown/sent effects, unresolved provider reservations and cleanup ownership need an explicit occupancy decision. A terminal parent label alone is insufficient. Discovery's72 generation/quota implementation is not a test-capacity recipe.

## What this checkpoint changes

Additive73 copies the exact installed70 `body02` admission and `body14` candidate selector into private functions. Its predecessor registration pins those full copied definitions and ACLs. Both per-definition counts now use the existing no-member `zasp_temporal_accounting` role, which68 already permits to see all parent owners. No existing role membership or historical SQL bytes change.

`zasp_temporal73.capacity_guard` covers actual parent INSERTs, including callers outside the selector. It takes the existing organization advisory lock with try-lock semantics, reads the current exact-version definition bound, and rejects oversubscription with40001. This avoids waiting in reverse order behind an older caller's definition lock. It requires read committed. Simulated runs retain their non-execution semantics. Existing request replay checks occur before INSERT and are not new admissions.

`unresolved` uses the installed domain authority for private evidence; only the accounting role can call it directly. It counts these retained obligations even when the parent is terminal:

| Evidence owner | Occupancy predicate |
| --- | --- |
| Temporal68 effects | Started, unknown, cleanup pending, or verified temporary policy awaiting cleanup. |
| Temporal68 cleanup | Anything other than cleaned. |
| Temporal68 provider reservations | Neither settled nor explicitly released before dispatch. |
| Retained provider reservations | No response-bound settlement. |
| Retained effects and controls | Leased, unknown outcome, cleanup pending/failed; control not disabled. |
| Test links and invocation journal | Link not settled, or linked invocation still started. |
| Attack Lab/export links | No parent settlement receipt. |
| Webhook deliveries | No parent settlement, dispatching, or uncertain delivery. |

Active parent states preserve the original list, including `contained`. This is accounting, not permission to retry, settle, clean up, or resend any effect. In particular, it does not alter the accepted pre72 discovery-preparation recovery debt. The focused test proves private68 provider visibility across owners; it does not yet prove every row in this inventory through actual family execution.

Only the actual installed worker selector is rerouted: the existing compatibility database adapter probes73 and dispatches its original typed schedule statement to `zasp_temporal73.schedule`. If73 is absent it preserves70. If73 exists but fails exact readiness, it fails closed. The admitted source/run identities, trigger receipt, audit and final source rechecks remain copied from70. One immutable `retained_single_action` admission and revision1 start command are inserted in that transaction. Other delegated scheduler families keep their original bodies and do not get a73 start merely because this wrapper exists.

The new `up-temporal-admission` CLI dispatch and registered Runner install73 only after exact72. Registration is repeat-safe; wrong configured principals are rejected before DDL. The independent compiled catalog pin is `15f43bafaeb4ae3fe4df96f01680abacad107e55c572e4063dbb16fb4c171b5c`. Readiness fingerprints the new run-capacity trigger, copied functions, private tables, ACLs, policies and constraints. The CLI test uses the shipped dispatcher and registered Runner against disposable PostgreSQL, not an external executable invocation.

## Controller-approved temporary handoff

Workflow69 is specialized: it requires the ordered two-step definition, ordered canonical identity and human requester membership. It cannot execute a single-action scheduled test or webhook merely because a start command exists.

The controller approved this bounded P4C direction before implementation:

1. Preserve the ordered69 route. A family-bound workflow for new specialized admissions owns admission-to-release ordering and committed command consumption.
2. Product admission atomically records the source receipt, capacity and one durable start. Keep explicit `retained_single_action` execution ownership.
3. A registered Activity rereads current authority and writes a one-time scoped release receipt. Actual retained claim/dispatch must refuse fresh work until that receipt exists. The receipt never replaces current checks before provider IO.
4. Installed row-boundary revisions capture later decisions and results. Signals are wakeups; Activities reread persisted state. Duplicates, reordered signals and worker restart cannot create another release or effect.
5. Complete only after verified family settlement with unknown and cleanup constraints. Pending or unknown stays truthful. Cancellation, revocation and deadline handling need evidence both before and after release.

P4D replaces the retained adapter with lease-free Activities using the same canonical run, child, effect and invocation identities after quiescence/equivalence checks. Retained leases remain explicit P4D/P9 debt. This approval is not permission for a no-op receipt workflow or a second custom durable scheduler.

The controller superseded that temporary bridge choice after the concrete dependency comparison. A bridge would need revision capture across parent/approval, test invocation and link settlement, webhook acceptance, export and Attack Lab links, and cleanup, including pinned predecessor tables. Parent release alone cannot enforce later approved dispatch or reconstruct unknown child effects. The next approved slice is the minimum lease-free `run_test`/`rerun_test` family executor, preserving71's canonical child/invocation identities and actual child-to-parent settlement. It has not been implemented here. No generic release/await workflow, relay, polling workflow, or replacement durable state machine was added.

## Evidence so far

Grouped TDD is in use. The first command was run from `services/platform`:

```text
go test ./apiserver -run '^TestTemporalAdmissionScheduledInstalledPostgres$' -count=1 -timeout 5m -v
```

Each admission log below uses that exact command. All owned PostgreSQL processes report normal joined shutdown, including failed runs.

| Log | Result and interpretation |
| --- | --- |
| `p4c-admission-red.log` | FAIL17.187s, predecessor setup, not behavioral RED. |
| `p4c-admission-fixture.log` | FAIL17.357s, exact failed predecessor identified as72. |
| `p4c-admission-prerequisite.log` | FAIL17.966s,72 DDL and accepted fingerprint match, roles_ready=false. The older fixture lacked its distinct registered scheduler. Fixed fixture registration only. |
| `p4c-admission-red2.log` | FAIL17.053s, intended missing installed admission Runner RED. |
| `p4c-admission-catalog.log` | FAIL19.539s, initial independent catalog compile. Setup evidence, not behavior. |
| `p4c-admission-catalog2.log` | FAIL19.119s, expanded authority catalog compile. Setup evidence. |
| `p4c-admission-catalog3.log` | FAIL20.386s, fingerprint normalization corrected to bind installed70 predecessor tokens. Setup evidence. |
| `p4c-admission-green-attempt1.log` | PASS26.440s, actual installed selector refuses hidden Temporal active owner, admits after terminal release, atomic start and duplicate wakeup. Earlier source, not final verification. |
| `p4c-admission-boundary.log` | FAIL21.889s, expanded fixture attempted legacy worker_id column deliberately absent from68 reservations. Setup error fixed without production authority changes. |
| `p4c-admission-release-red.log` | FAIL26.412s, behavioral safe-release RED: explicit never-dispatched released_at was still counted, so scheduled admission returned0. Corrected predicate to require released_at IS NULL. |
| `p4c-admission-catalog4.log` | FAIL20.653s, final independent catalog compile before installing its pin. Setup evidence. |

The additional installed migration group used:

```text
go test ./agentsec-migrate -run '^TestTemporalAdmissionInstalledReleasePostgres$' -count=1 -timeout 5m -v
```

`p4c-admission-cli.log`: PASS27.138s on the earlier pin. Proves wrong registration rollback, shipped dispatch, repeated install, final registered readiness and drift rejection. It is not final-source proof.

Final affected group command:

```text
go test ./apiserver ./agentsec-migrate -run '^TestTemporalAdmission(ScheduledInstalled|InstalledRelease)Postgres$' -count=1 -timeout 5m -v
```

`p4c-admission-final.log`: PASS, apiserver31.573s and agentsec-migrate27.682s. Both owned PostgreSQL processes joined normally. This final source proves hidden active-owner capacity, private unresolved-provider occupancy, explicit safe release, actual worker admission plus atomic start, duplicate wakeup, per-definition manual coexistence and exact full-capacity replay, accepted69/71/72 readiness, registered CLI dispatch/repeat and catalog drift refusal. No P4B whole group or unrelated whole package suite was rerun.

The controller requested a broader accounting checkpoint before freezing. The same focused apiserver command was extended and rerun, without changing production source or the compiled pin. `p4c-admission-isolation-race.log`: PASS50.247s, owned PostgreSQL joined. The additional assertions use the same definition, test and finding IDs in a second tenant; five blocked first-tenant sources before the four-candidate scan window at limit1; and two real worker connections in both transaction orders. The first connection holds an uncommitted admission, the competing connection returns0, rollback leaves no admission, retry admits1, and a late competitor returns0. Each iteration verifies exactly one parent, source receipt, admission and start.

Self-review then tightened the candidate-fairness fixture so the first tenant's active blocker is its already-Temporal historical owner, hidden from the retained worker. The controlled retained parent is terminal; no immutable owner row is changed. This catches regression of candidate selection back to the old RLS-visible count, rather than merely proving ordinary retained capacity. `p4c-admission-hidden-fairness.log`: PASS50.555s, owned PostgreSQL joined normally. This reruns the full expanded API checkpoint against the final test source; the earlier CLI group still tests identical production and CLI-test bytes.

## Self-review and review packet

The source review found and corrected the never-dispatched release accounting bug, the distinction between simulated and executing parents, and missing retained link obligations. The expanded real-worker test uses controlled database state for historical owners and provider receipts; it performs no provider IO and does not claim an executor or terminal-parent integration proof. Its manual-path check invokes the shipped retained manual repository and repeats the exact request at concurrency1. That is replay/coexistence evidence, not manual Temporal migration.

The review must still challenge untested occupancy branches, source revocation/deadline races, and all-owner guard coverage across non-test triggers. The grouped installed test now covers two-tenant same-identity isolation, both connection orders for competing admission/rollback/retry, and candidate fairness under the LIMIT scan. The current checkpoint does not close the full P4C matrix. Approval before actual action dispatch remains mandatory and unchanged.

The overlay-relative diff is `p4c-scoped.diff`; `p4c-frozen-source.json` records every changed file's pre/post SHA-256, all log hashes, baseline hash, diff hash and capture-script hash. The capture script refuses to freeze if any pre-existing SQL byte changed, including72. Its final manifest hash is provided with the handoff rather than embedded here to avoid a self-referential report hash. Review against this overlay baseline, not HEAD alone.

Temporary integration retirement inventory for the controller's ledger merge:

| Surface | Owner and retirement gate |
| --- | --- |
| `securityAgentCompatibilityDatabase.QueryJSON`73 schedule redirect | P4C/P9: retire the retained RunOnce automatic-selector call only after configured Temporal Schedule wakeups prove source, duplicate, fairness and capacity equivalence. Do not remove common admission authority. |
|73 `schedule_body`/`admit` copied70 adapters and retained delegated selector bodies | P4C/P4D/P9: replace through an additive reviewed authority after all specialized trigger semantics are migrated; preserve scoped canonical source/run identities and existing receipts. |
|73 immutable start/admission records | P4C minimum lease-free slice must consume each existing identity without another run/effect; no relabeling as ordered69. Unconsumed rows are not workflow success. |
| Existing70/71 downstream claims, leases and settlement adapters | P4D/P9 remain open. Quiesce/equivalence-check the same run/step/test/invocation identities before executor cutover. |
| New73 capacity trigger/accounting | Shared product invariant, not a temporary execution lease. Any successor must retain atomic all-owner bounds and conservative unresolved ownership. |

No new release relay, retained executor wrapper Activity, or public-table revision bridge exists to retire.

## Still open

Remaining P4C: full shared-capacity acceptance matrix; manual, finding/event, attack-path, webhook-action and approved-action common routing; separate service/human authority; configured whole-second selector Schedule with shipped1s and configuration-change/duplicate-wakeup evidence; durable delivery/consumption of73 starts; cancellation/revocation/deadline handling; and actual specialized child/parent receipt evidence. Approved action must continue the existing run and never allocate a new slot. Existing ordered69 is unchanged. No required SQS/event/DLQ transport was removed, and its original acceptance mappings remain open where not already proved by accepted predecessors.

P4D must close all downstream families listed in `p4d-preparation.md`, including policy deployment, tests, Attack Lab, exports, TTL cleanup and recovery. Accepted P4B debt includes pre72 uncertain preparations that hold capacity; they require an explicit recovery/cutover disposition. Do not silently release them.

P8 still needs the broad API-root startup and product acceptance gates, with the sensor module verification gap and NaturalRecovery timeout kept separate. P9 owns retained-selector retirement and backlog equivalence. P10 and the deployed Stytch/OpenFGA/provider gates remain open. Controlled local fixtures do not prove deployed authorization.

## Checkpoint fix1: direct INSERT-guard evidence

Review finding: **Important: [P2] Exercise rejection at the new shared INSERT guard** in `2026-09-22-temporal-openfga-p4c-checkpoint-review.md`.

The finding is valid. The original capacity and concurrency refusals could occur in73's selector/admission prechecks. The original manual replay used another definition. Those tests did not isolate a rejecting invocation of the new common row guard. This fix adds one installed-boundary test group, with no production changes and no executor work.

`security_agent_temporal_admission_guard_postgres_test.go` now exercises two retained callers:

1. The worker-authorized, still-installed `zasp_temporal70.op02`. Its old RLS-visible selector and admission core cannot see the controlled Temporal parent occupying the same definition's only slot. The73 INSERT trigger must refuse admission. A before/after product snapshot verifies unchanged parent, trigger receipt, audit, public request receipt,73 admission and65/73 start records. After the controlled historical parent is terminal with no unresolved journal obligations, the same retained caller admits once and a duplicate admits zero. This route remains retained: successful70 admission does not acquire a73 start through the new selector.
2. The retained finding API, `postgresSecurityAgentRunV24SQL -> public.zasp_security_agent_run_v24 -> public.zasp_security_agent_run`. This real authorized route takes definition/source locks and reaches parent INSERT without the selector's early organization try-lock. A separate connection holds the organization advisory lock. The assertion requires SQLSTATE40001, the exact `admission organization busy` reason, and PostgreSQL error context naming `zasp_temporal73.capacity_guard`, before a three-second statement timeout. The caller rolls back, the holder releases its lock, retry admits, and the identical request replays at capacity one without changing any product snapshot.

### Mutation proof and restoration

The TDD and review-verification skills required proof that removing the rejection logic breaks the tests. The opt-in test-only environment variable `ZASP_TEST_P4C_GUARD_MUTANT=1` changes `capacity_guard` to return NEW inside the disposable database. It does not edit SQL files, alter a predecessor, bypass readiness, or hardcode readiness true. The harness saves every73 function definition, computes the mutated normalized catalog fingerprint, substitutes that fingerprint through73's functions and registration, and verifies real73/70/72 readiness remains true. Thus the rejection assertions cannot pass merely because a stale fingerprint disables the release.

The behavioral mutant's catalog pin was `3b4051cd9b335a51c2714f0ed8f3df04c02ea8c1ee2ffaba1ba5665c891c303d`. The first subtest then admitted1 despite hidden Temporal capacity. The second admitted while the organization lock was held, returning no error in396.08025ms. Both are expected behavioral RED failures.

Deferred cleanup restored every saved73 function definition and the original registration, checked exact function-definition equality, and verified73 and72 readiness at the original pin. The owned PostgreSQL process then joined normally. No migration/source restoration was necessary because no production source bytes were changed.

### Exact fix1 commands and evidence

Commands ran from `services/platform`:

```text
ZASP_TEST_P4C_GUARD_MUTANT=1 go test ./apiserver -run '^TestTemporalAdmissionRetainedInsertGuardPostgres$' -count=1 -timeout 5m -v
```

`p4c-fix1-guard-red.log`: FAIL19.117s. The mutation had valid readiness and restored cleanly, but an ungranted `current_ready` probe and a nonexistent `commands.definition_id` snapshot column stopped the assertions. This is a fixture/setup failure, not behavioral RED. The fixture now uses the granted client-ready operation and scopes commands through their parent rows.

`p4c-fix1-guard-red2.log`: expected FAIL20.318s. Both intended behavioral failures occurred with valid mutant readiness, then exact restoration and normal owned PostgreSQL shutdown. No catalog refusal was counted as behavioral proof.

Final affected group:

```text
go test ./apiserver -run '^TestTemporalAdmission(RetainedInsertGuard|ScheduledInstalled)Postgres$' -count=1 -timeout 5m -v
```

`p4c-fix1-guard-green.log`: PASS72.409s. The direct guard group passed in20.37s, including hidden capacity2.41s and row contention0.78s; the existing scheduled group passed in51.06s. Both owned PostgreSQL processes joined normally. This includes the original expanded admission, isolation, hidden-owner fairness, concurrent rollback/retry and manual-replay group. CLI source, migration source, catalog pin and CLI tests are unchanged from the reviewed packet; no unrelated suites or predecessor groups were repeated.

### Fix1 review packet and remaining scope

The separate fix baseline contains1,992 reviewed-source paths. Its SHA-256 is `d91c620aa7e48d3ad4f0fcdca491711cd805a7d0fea024de2ae57d9f64187815`. `p4c-fix1-scoped.diff` is relative to that baseline, not HEAD and not the original pre-P4C overlay. `p4c-fix1-frozen-source.json` records changed source hashes, all fix1 log hashes, the baseline/diff/capture hashes and unchanged SQL verification.

The original packet remains intact: manifest `a5fd6aa756ede51b948b347ac0584406d69c54dd230a1ab12eee34183ba06384`, diff `5b89f000886bdd00b444546ccae67d9263f5b59ff4523719db8d2c8188432d72`. The new capture script refuses to freeze if those original packet files or any reviewed SQL file changed.

Self-review: these tests now fail when the row guard returns NEW despite a valid catalog, and the contention assertion identifies the trigger itself rather than a selector skip. Controlled database state is still not provider execution evidence. All wider occupancy-family tests, Temporal start consumption, current service/human authority, selector Schedule, approved pre-IO execution, cancellation/deadline, downstream P4D settlement, P8/P9 acceptance and deployed gates remain open exactly as described above. Fix1 does not approve production activation or full P4C completion.
