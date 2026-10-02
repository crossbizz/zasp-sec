# Durable Security Agent Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for inline feature-batched execution. Steps use checkboxes for tracking.

**Goal:** Enforce every original M7A-49/M7A-95 budget dimension in durable production paths before another start.

**Architecture:** PostgreSQL stores immutable limits, organization admission,
reservations and sticky stops. Worker planning and action dispatch use that
authority; cleanup and receipt settlement remain possible after a stop.

**Tech Stack:** Go 1.25.6, PostgreSQL 18, existing pgx adapters, TypeScript UI,
OpenAPI and the existing registered worker principals.

**Spec:** [budget design](2026-09-15-security-agent-budget-design.md).

## Global constraints

- Preserve all 728 original requirements and supervised safety floors.
- Add a forward schema version after v52; never edit historical migrations.
- Reserve before starting; unknown usage is not zero and cannot release credit.
- A database clock and scoped durable state survive restart and approval waits.
- No live AI request, resource provisioning, spending or push during RED.
- Keep cleanup available for effects started before a stop.
- Cost unit is explicit openrouter_credit; integer nano-credit ceiling 1..10^12.
- Missing cost authority blocks new paid planning while definitions remain readable.

## Batch 1: Durable admission and deadline/action guards

Files: create `services/platform/migrations/production_security_agent_budgets.go`,
`services/platform/migrations/sql/0053_production_security_agent_budgets.up.sql`
and `.down.sql`; register in `migrations.go` and migration CLI; extend
`apiserver/security_agent_worker_repository.go` and
`apiserver/security_agent_budget_postgres_test.go`. Add migration tests beside
existing production migration tests.

Interfaces: `Runner.UpProductionSecurityAgentBudgets(ctx)` and
`Runner.DownProductionSecurityAgentBudgets(ctx)`; release metadata
`ProductionSecurityAgentBudgets()` and its semantic fingerprint. SQL tables
`zasp_security_agent_run_budgets`, `zasp_security_agent_budget_reservations`,
`zasp_security_agent_org_admissions` use complete scoped primary keys and forced
RLS. They are worker-function-only, not directly granted to API/worker logins.

- [x] Add and run the registered-worker expired-started-run regression.
  RED 958ffc: one expired run returned to planning; fresh control passed.
- [x] Add two-worker organization admission regression with independent-tenant
  positive control. RED ce619c/a45657: two same-organization definitions with
  limit=1 both entered planning; separate-organization control passed. The
  combined race run also reconfirmed the deadline defect; all owned servers
  and both worker operations joined. This does not prove every lock interleaving.
- [ ] Add migration ACL/readiness/rollback tests and simultaneous admission
  cases before creating authority. Table limits include steps, tokens,
  nano-credit cost, start/deadline, definition version and sticky stop reason.
  - [x] Reproduce unrelated-consumer readiness failure on the actual v52 graph.
    REDf0b128 (5.518s): baseline API/ingest ready, staged budget installation
    changes live fingerprint without changing pinned52 identity; structural
    security stays true. Version/context controls pass; independently reviewed
    RED fixture. This is not a migration repair. Next implement v53 identity,
    exact inherited readiness composition and rollback protection without
    editing historical migrations or accepting live drift as a new baseline.
    Draft release envelope now restores warmed unrelated consumers and rejects
    helper/metadata/checksum drift (d9acc6, 7.101s). Initial mutable-pin defect
    found by review reproduced REDd71395, then compiled guard literals repaired
    the tested rebaseline path. Candidate template identity is not full release
    metadata. Next bind all up/down fragments in Metadata/Runner, save exact
    predecessors and implement transactional rollback/refusal before activation.
    Follow-up review found excluded compiled-pin drift; RED85a498 reproduces
    acceptance of changed SQL checksum pin plus matching metadata. Keep that
    acceptance and resolve independent pin authority before approving the
    draft. The earlier d9acc6 pass does not close this release gate.
    Updated API/ingest Ready callers now pass compiled candidate pins through
    the actual adapter, closing the targeted SQL-pin regression and coherent
    two-root replacement test (93781e, 16.133s). Runtimeevent race suite passes
    85439e. Candidate checksum covers all three templates, not a down artifact.
    Keep genuinely old binaries fail-closed as a separate unverified rollout
    requirement; complete operation/worker coverage and registered up/down next.
    Registered up/down and Version53 metadata now cover the assembled up/down
    identity, exact predecessor restoration and retained-authority refusal.
    Group4a07be passes runner/consumer tests (12.415s), including eight busy
    table fences and the RLS-restricted rollback barrier regression61374d.
    Migration suite8b968e passes. CLI integration is next; full ACL/lifecycle
    and release acceptance remain open, so this parent item stays unchecked.
    Explicit CLI up-to-53/down-to-52 now passes real binary group342486
    (30.615s) after REDc5bafa, including registration/readiness, retry and exact
    empty rollback. Default49 and historical refusal remain; affected command
    group72cd4f passes (5.527s). Independent bounded source review approved.
    Retained-history CLI, complete runtime/ACL/lifecycle and release gates
    still keep this item open.
    Updated registered planner/action Ready and fresh construction now bind
    external application pins after RED4ad6ce. Read-only worker grants and new
    frozen candidate identity pass expanded consumer/migration group23ce11
    (14.965s); independent source review approved this bounded change. Direct
    operations, alternate adapters, old binaries and full lifecycle stay open.
    Six composed provider/action worker modes now construct fresh registered53
    repositories after actual migration, with no staged SQL injection. Version
    RED26fa39 preceded conversion; groupeddbc63d passes53.002s. Independent
    source review found no weakened assertions. These are processor.process
    cases, not daemon/RunOnce, live billing or gateway delivery acceptance.
    All33 action lifecycle cases now use actual migration34..53 and fresh
    restricted Ready checks. REDb1c7f9 showed the prior33-only fixture; full
    matrixeb32fa passes179.899s. Independent review found no weakened oracles.
    Populated production backfill, credential lifecycle, daemon/gateway delivery
    and full combined/release verification still keep this item open.
- [ ] Implement durable first-admission snapshot and organization row locking.
  Wire deadline checks into claim, prepare and dispatch without an older-entry
  bypass; persist needs_human before returning a no-work result.
  - [x] Stage the shared admission SQL fragment and exercise real worker claims:
    immutable snapshots, durable claim deadline stops, organization limits,
    base/v22/v23 routes and nonblocking cross-tenant progress. Grouped race run
    dfecd2 passed ten leaf cases; independent slice review approved. This is
    not v53 activation, action/prepare enforcement or completion of Batch 1.
  - [x] Implement staged conservative legacy backfill after RED500654. Runs
    with unrecorded prior usage retain a sticky stop and old start; recover
    only exact-version limits, preserve unknowns as NULL on stopped rows,
    revoke active worker leases, and leave control/effect data intact. Initial
    grouped run c9e891 passed twelve leaf cases; expanded run 072ef2 passed
    fourteen, including literal recovered limits, historical lookup, malformed
    values and rejection of unknown-limit activation. Independent review approved.
    This is not full migration registration or verified cleanup execution.
- [ ] Reserve action count by stable step identity in the same transaction as
  authorization to start. Repeat delivery returns the original reservation.
  - [x] Stage private scoped step reservations before each effect-bearing leaf
    INSERT. RED00dbb2 authorized an effect with no reservation; initial four
    cases passedfa60be. Expanded affected group passedc464ac (23 cases), including
    exact limit, reused reservation, over-limit stop and action/input conflicts.
    Final valid-argument helper ACL denial passed75bc7e. Independent source
    review approved the bounded slice. Prior usage/approval are owner fixtures.
  - [ ] Verify actual two-worker reservation contention, exhaustion on the other
    action routes and full retry/restart lifecycle before closing this item.
    - [x] Observe both worker connections blocked before duplicate-claim release;
      exactly one dispatch/reservation succeeds and the other loses its lease.
      Finding exact-limit/over-limit cases also verify target state/version.
      Expanded eight-case race group passed9e8d87 after correcting fixture setup.
      This is one step delivered twice; distinct-step contention, revocation/
      isolation exhaustion and full retry/restart remain open.
- [ ] Complete the start-guard draft after RED68e356: expire only the budget
  after claim and before prepare/approved dispatch. Entry-only guards are not
  enough; add lock-delayed expiry tests and recheck at the first mutation.
  Repair planner run-to-organization lock inversion and stopped-candidate
  propagation. Current combined fixture is RED at v33 readiness (d60709), so
  implement v53 registration/fingerprints without bypassing that gate.
  - [x] Reproduce claimed-action policy-source storage after budget expiry.
    Corrected REDbf71d8 stores one target and enqueues generation2→3 with no
    stop; fresh control passes. Independent RED-stage review approved the
    counterexample, not a repair or gateway-delivery claim.
  - [ ] Guard action-source storage and enqueue using the registered action
    principal and exact effect lease. Avoid cleanup's effect→run lock cycle;
    normalize ordering or acquire effect nonblocking before any target lock.
    Recheck database time after deployment/prerequisite waits. Add strict bound
    action-stop decoding and worker handling, preserving effects/reservations.
    Staged v28 guard and strict repository decoder now pass grouped race run
    956d13 (123.577s), including expired/fresh and busy-effect/deployment cases.
    Worker handling and remaining action routes keep this item open.
    Initial apply-only worker stop consumer passed action-processor race group
    f6853f after RED37e059. Composed database/worker and heartbeat-race coverage,
    other action routes and partial-target cleanup still keep this item open.
    Stop-origin negative tests reproduced REDbf1ad3; private apply-store signal
    now excludes Finish errors. Coordinated heartbeat-error controls and action
    processor group passed five race repetitions (021cef), independently reviewed.
    These boundary doubles do not close composed SQL/heartbeat acceptance.
    Composed PostgreSQL/action processor expired/fresh cases now pass9b3263
    (17.612s), with mutation RED34312c proving missing stop consumption fails.
    Reviewed as local process() proof only; no deployment delivery, deterministic
    heartbeat overlap, partial-target cleanup or release completion.
    Expanded composed run d263ab passed expired/fresh/post-commit-heartbeat
    (26.100s), including actual forwarded Finish calls and generation deltas;
    independently reviewed. This closes that specific retained-effect-lease
    heartbeat interleaving only. Partial cleanup, other routes and rollout remain.
  - [ ] Verify expired/fresh/lock-delayed action starts, cleanup exemption and
    partially stored/applied targets. Include legacy and current entry points;
    do not substitute a claim-only check for actual source/apply authorization.
    Six-case source guard run001dc2 now covers target-lock expiry and fresh
    release with an observed pre-expiry block; stale action transaction-clock
    mutation failed3d0484 and exact restoration passed. Independent review
    accepted this boundary; replay, cleanup, partial targets and legacy routes
    still keep the full item open.
    New stopped_reclaim RED2064a3 returns apply after a committed stop and
    expired effect lease. Repair reclaim plus stored/partial-source cleanup;
    filtering claims alone does not complete the lifecycle requirement.
    Expired leased stop routing and stored-source cleanup discovery now repaired
    in both claim functions after RED754620. Group83796a passed8apply/reclaim
    plus3composed cases (47.586s), including signed cleanup source/enqueue under
    sticky stop. Independently reviewed. Already-pending stopped effects,
    repeated expiry, partial/multi-device cases and deployment remain open.
    Pending stopped routing now repaired after RED1c3030. Same-target cleanup
    replay after a second lease loss preserves the envelope and generation.
    Reviewed13case race group eb0fce passed52.489s. Partial/multi-device,
    credential changes, direct legacy execution and deployment remain open.
    Two-device partial source case now proves actual stop on second Store and
    cleanup of only the first stored source; mutationf2137f detected missing
    stored-source eligibility, restored grouped cases passed592a63 (9.446s).
    Independently reviewed; gateway delivery and broader credential schedules
    remain outside this proof.
    Retained legacy `_v27` store leaves reproduced expired bundle writes
    (REDfddfeb), now guarded before mutation. Target-wait controls pass; review's
    credential-FK wait reproduced RED2f3f30 and now returns nonblocking conflict.
    Ten legacy cases passeda42dbd (37.808s), follow-up reviewed. Unique-index
    INSERT waits, legacy cleanup and isolate_session payload proof remain open.
    Unique-index wait reproduced on both leaves (RED87653a). Subtransaction
    rollback plus post-write current-clock check now removes tentative writes
    and persists the stop. Four wait cases pass90c09c; consolidated14legacy
    cases pass6f4aad (58.471s), independently reviewed. Legacy replay/cleanup,
    isolate_session payloads and full rollout remain open.
    Follow-up scoped race run ecc049 passed both legacy cleanup/exact-replay
    cases and the current stored-reclaim control (9.671s). Mutation087e2c
    previously failed both exact apply replay assertions. This closes the
    bounded temporary-policy replay schedule only; actual isolate_session
    payloads, credential lifecycle and full rollout remain open.
    Consolidated action-budget suite passed all 27 cases (bebba1, 95.907s);
    no source changed after the scoped replay review checkpoint. This is the
    affected action-suite baseline, not full Batch 1 or release verification.
    Four real isolate_session payload cases now cover current/legacy fresh and
    expired starts. Bypass mutation failed6b311f; restored20-case race group
    passed383bed/841481 (78.980s), source independently reviewed. Fixture events
    and approvals are not ingestion/API proof; isolation cleanup/replay, its
    lock-wait schedules, credential lifecycle and full rollout remain open.
    Current/legacy isolation stored-source cleanup and exact replay after two
    lease losses now pass grouped6-case race run3dcd56 (17.662s), following
    enumeration-eligibility mutation REDf21281. Independent source review found
    no Critical/Important issues. Fixture sticky stop and local source cleanup
    do not prove gateway removal or credential/device lifecycle. Proceed to
    forward release integration; retain those broader lifecycle gates.
  - [x] Reproduce prerequisite-lock deadline crossing (416fe9), retain entry
    lock ordering, and recheck before leaf plan/effect creation. Both initial
    regression cases pass (8501a2); independent review approved this repair.
    Follow-up finding-target regression failed (84b98c); scoped target locking
    now precedes the budget recheck/effect insert. Grouped c085ff passes seven
    expired/fresh/legacy-denial cases; independent finding-slice review approved.
    Full boundary remains incomplete: guard actual application and repair
    planner ordering/stop results, then complete release integration.
  - [x] Reproduce expired planner acceptance returning a provider error after
    durable stop (a83ab7). Add budget_stopped receipt/response classification,
    replay support and strict Go decoding. Focused expired/fresh/replay race
    tests pass (8060f2); decoder null negatives failed first (3926f1) and the
    repaired repository group passes (cad7c1). Independent review approved
    propagation and the null fix. Planner lock ordering/context permits remain
    open; this is not a complete planner budget or release gate.
  - [x] Reproduce run-before-organization planner locking with an observed
    blocker and independent NOWAIT row probe (0b2051). Acquire org locks before
    context's run lock in both versions. Focused v33 ordering/expired/fresh
    replay group passes (56473f); predecessor behavior and context budget
    permits still need coverage. Independent review approved this bounded repair.
- [ ] Run the actual failing acceptance and action lifecycle group:
  - [x] Reproduce pre-provider context leakage after a prerequisite-lock wait:
    e774cd returns usable context after deadline and leaves run planning;
    fresh control passes and both owned servers join.
  - [ ] Add durable tagged context stop, nested accept/fail propagation and
    strict Go decoding/worker no-call handling. Verify both authority stop
    persistence and provider suppression; retain token/cost reservation gates.
    - [x] Stage bound tagged-result decoding and dedicated worker stop handling;
      consumer race group passes (df0370). These boundary-double tests do not
      prove SQL propagation or composed provider suppression.
    - [x] Produce scoped tagged stops after context prerequisites and propagate
      through nested accept/fail. Strengthened context and failure regressions
      failed first (f6e4da/13e152); grouped 383196 passes eight cases, including
      same-method replay and cross-method conflicts with NULL/nonnull output.
      Independent review approved the bounded SQL/replay fix. Worker nested
      failure-stop handling passes consumer race group1078bf after REDc3fb24.
    - [x] Verify composed controlled-provider zero-call behavior and concurrent
      heartbeat/stop terminal handling. Direct predecessor coverage and full
      v53 integration remain required; context is not a spending reservation.
      Three actual repository/processor/planner cases pass fb2edd, including a
      fresh control and delayed committed-result delivery followed by actual
      heartbeat conflict. Reconciliation mutation failed68472b and was restored.
      Independent source review approved. This is pre-context expiry and one
      scheduled overlap, not arbitrary mid-request expiry or full RunOnce proof.
      - [x] Reproduce typed-stop/heartbeat conflict failure (d4640d); preserve
        validated terminal state through heartbeat join. Affected race group
        e97cf7 passes; independent review approved processor decision logic.
        Boundary doubles only; the composed checkpoint above adds one DB schedule.
      - [x] Reproduce flat Execute/Accept stop failures (8952ed), bind stopped
        results to run/next version/empty artifacts and reuse typed reconciliation.
        Independent review approved the bounded mapping; requested per-artifact
        negatives expand the flat matrix to 17 cases. Affected race group
        09f26b passes. These flat-result cases are boundary doubles, not release
        evidence; the composed checkpoint covers context stops only.

```sh
GOTOOLCHAIN=local GOPROXY=off go test -race ./apiserver ./agentsec-worker ./migrations -run 'SecurityAgent' -count=1 -v
```

Expected: each deadline/action/concurrency negative stops durably, no subsequent
step/effect starts, fresh controls and cleanup succeed; no unexplained skips.
- [ ] Independent review of locking, all reachable old/new entry points,
  fingerprint transitions and rollback refusal before considering this batch green.
  - [x] Action heartbeat completion race: actual-repository RED1f3d40 showed
    normal worker cancellation turning a committed stop into heartbeat failure.
    Separate scheduling shutdown now joins each heartbeat with a five-second
    bound, retaining parent cancellation and genuine error failure. Four
    composed cases ff7089 and action-processor group2ce611 pass; independent
    review approved. Full worker package50287 passes46d095 (31.381s); original broad-run
    interleaving, long-lived daemon and full release remain separate gates.

## Batch 2: Durable AI token and cost reservations

Files: create `agentsec-worker/security_agent_budget.go` and its tests;
extend `security_agent_planner.go`, `security_agent_runtime.go`, repository
budget methods and v53 SQL. Add controlled-provider composed cases using
`apiserver/security_agent_planner_worker_postgres_test.go` and its owned child.

Go interfaces, implemented by the registered repository, bind the existing
claim, worker ID and lease token on every call:

```go
type SecurityAgentBudgetReservation struct {
    ReservationID, InputDigest, Model, CostPolicyVersion string
    MaximumTokens, MaximumCostNanoCredits int64
}
type SecurityAgentBudgetUsage struct {
    ReservationID, OutputDigest string
    PromptTokens, CompletionTokens, TotalTokens, CostNanoCredits int64
}
```

`ReserveSecurityAgentPlannerBudget(ctx, claim, workerID, leaseToken, reservation)`
returns a scoped permit or durable stopped result, never an uncommitted stop.
`SettleSecurityAgentPlannerBudget(ctx, claim, workerID, leaseToken, usage)`
reconciles exactly once; unknown outcome retains its full reservation.

Historical RED: actual registered53 processor called the controlled provider
with a NULL immutable cost allowance (1ff0e1: one call and three artifact IDs,
14.151s). Preserve this missing_cost_authority regression. Its parent durable
stop oracle is not reached until child zero-call acceptance passes. Existing
fresh fixture behavior predates spending enforcement; its positive control
must gain explicit supported cost configuration and an actual durable permit,
not an exemption from the new guard. Worker integration now closes that negative
regression and exercises a controlled permitted path (f6f0dc,27.335s). The test-only
bounds do not establish production pricing; production paid planning remains
blocked until verified request-cost policy/configuration is implemented.

Implementation order within this batch:

1. Add scoped provider reservation authority to the unpublished53 artifact:
   exact input/model/cost-policy/unit/maximum binding, forced RLS and worker-only
   functions. Extend catalog fingerprints, cutover fences, and retained-history
   rollback refusal with the new table. Do not accept a live fingerprint as a
   production pin or edit historical releases.
   Storage is now implemented after RED2de97d (missing table): scoped attempt
   and reservation uniqueness, request/issuer binding, forced RLS, all-or-none
   exact usage, retained overage, catalog coverage, down fence and rollback
   retention. Group387b89 passes19.363s including26 constraint negatives and
   nine cutover fences; full migration package d8febe passes1.435s. Independent
   review found no blocking storage issue. This is not a reserve/settle API or
   enforcement completion. The worker missing-cost RED remains open.
2. Atomically reserve under organization→run→budget locking before outbound
   work. Missing immutable cost or verifiable request bound commits a sticky
   unknown-budget stop. A repeated reservation response must never authorize
   another call; unknown prior attempts retain allowance and block restart.
   The registered-worker SQL reservation primitive now exists after RED060d91.
   It recomputes canonical context, binds attempt/input and issuing lease,
   checks declared caps against immutable limits plus prior usage, and stops
   reused/unknown reservations without reissuing a permit. Declared caps are
   not a verified provider policy; the production caller remains unwired.
   Final20-case reservation group48ce1b passes90.949s; full migrations72d861
   passes1.745s. Independent review found no blocking issue. The gap checkpoint
   distinguishes this SQL primitive from actual provider enforcement.
3. Settle exact response-bound usage once, independently of candidate validity.
   Preserve accounting after stop/lease expiry without renewing execution
   authority. Conflicting replay refuses mutation; missing usage retains the
   full reservation and stops further planning. Never refund on process death.
   The SQL settlement draft now authenticates the persisted issuing worker/
   attempt and lease-token digest after live lease loss; it uses org→run→
   budget→reservation locks and compares exact output/usage on replay. Missing
   operation RED6ac05e preceded implementation. Independent review exposed old
   replay cancelling a newer pending reservation (RED14a159); the repair makes
   exact replay mutation-free. Final combined accounting group396234 passes
   224.061s (20 reserve/27 settle cases plus storage/migration/consumer checks),
   independently reviewed. Go methods/strict response validation and processor
   settlement before Accept/Fail now exist; no permit, stop reset or lease renewal
   is allowed. Latest worker evidence is recorded in the gap checkpoint.
4. Wire the actual processor before Plan and before Accept/Fail. Test expired,
   missing-authority, exhausted, unknown and replay cases alongside a genuinely
   permitted fresh control. A configured number alone is not proof of a
   verifiable same-model request-cost bound; unsupported billing stays blocked.
   Repository work comes first: add strict scoped permit/settlement decoders
   and registered methods. Require explicit known/unknown usage (known all-zero
   differs from absent usage), reject null/extra/mismatched authority fields,
   and bind permit expiry to SQL's current lease/deadline, not the stale original
   claim timestamp after heartbeats. Go normalizes timestamp offsets and checks
   a future expiry within300 seconds of its clock, with no positive skew
   allowance. This sanity check does not independently prove the SQL deadline.
   The strict Go adapters now exist (group4f8bcc passes15.165s, race detection
   and three migrated PostgreSQL scenarios; independent review accepted).
   A settlement acknowledgement is
   accounting only, never a start permit. Keep a bounded settlement context
   after heartbeat cancellation so a captured response can be recorded without
   invoking Accept/Fail or restoring execution after lease loss.
   Worker integration now passes five actual migrated modes a48cc1 (34.100s),
   including accounted approval after two prior registered heartbeats with the
   original claim. Normal/flat-stop result decoders accept monotonic bounded
   versions;42-case focused result matrix and affected tests pass d3afcb.
   Committed approval concurrent with an in-flight heartbeat conflict now passes
   the actual repository/worker barrier case. Group3b2453/b733e5 passes worker
   3.120s/API39.205s, including15 Accept/Execute/Fail race cases and six composed
   worker modes. Worker normal-result validation prevents malformed alternate
   authority responses from being counted as confirmed completion. Other
   lifecycle and crash/restart interleavings remain distinct.
   Pricing activation is still open: max_price is a rate filter, not itself
   evidence of a total charge ceiling. Bind actual prompt/output token limits
   and all supported billing dimensions before enabling production paid calls.

- [ ] Test malformed/missing/negative/overflow cost, inconsistent token totals,
  exact-limit and one-unit excess, conflicting output digest and duplicate
  settlement. Use literal cost values, not expectations computed by the parser.
- [ ] Add exact decimal-to-nano-credit decoding and preserve usage independently
  of candidate validity. A rejected model candidate still incurred usage.
  - [x] Capture optional exact usage in the actual planner result, including
    candidate rejection. RED1bbc8e preceded the bounded rational parser;
    expanded planner group3108f4 passes2.285s, independently reviewed. Nil
    remains unknown. Durable settlement/retention and worker stopping are
    now exist, but live pricing/restart/release verification keeps this parent open.
- [ ] Reserve before the actual outbound call using the configured same-model,
  same-unit request-cost upper bound. Refuse dispatch when that bound cannot be
  established. Cap request tokens by remaining durable allowance.
- [ ] Settle before candidate acceptance; a breached/unknown allowance stops
  further authorization. Exercise child process loss before/after response and
  restart without unknown/same-attempt provider redispatch or restored credit.
  A new attempt after confirmed settlement may replan only with a fresh permit
  against remaining original allowance; both calls remain charged. This follows
  original cumulative-budget/retry requirements, not a one-call-per-run limit.
  - [x] Abrupt child exit after reservation before provider dispatch, and after
    response capture before settlement, followed by a different worker/process
    reclaim. Final grouped run2cbe01 passes57.480s with exact unknown-row
    retention, zero redispatch/artifacts/effects and a durable stopped run.
    This is worker-process loss with a surviving database and controlled lease
    expiry, not database power-loss or post-settlement candidate-recovery proof.
  - [x] Abrupt exit after committed usage settlement before candidate acceptance:
    a new attempt obtains a distinct reservation and counts both calls when
    allowance remains; insufficient remaining request capacity stops before
    transport. Original accounting and full budget snapshot (except stop reason)
    remain unchanged. Final four-crash/six-composed grouped run5b4f27 passes70.761s.
    This verifies accounted retry, not recovery of the lost candidate without
    another paid call, live billing or host/database power-loss durability.
- [ ] Run the composed worker tests and independent security review. Record
  controlled transport evidence separately from actual provider billing gates.
  - [x] Registered53 missing-cost RunOnce scheduling/claim/repeated polling:
    real repository and unwrapped production planner, no fixture lease/budget
    seeding. Two polls leave exactly one needs_human/budget_usage_unknown run,
    a cleared lease and no provider calls, artifact IDs, plans, effects or
    reservations. Seven-mode group580083 passes71.603s; independent review
    approved. RED560f5d was missing fixture wiring, not a product defect.
    This does not close full daemon/positive-pricing/concurrent polling gates.

## Batch 3: Configuration, visibility and release integration

Files: `openapi/openapi.yaml`, generated clients, Security Agent definition
validation/API repository, `app/features/securityagents/SecurityAgentsView.tsx`
and tests, current migration/runtime configuration, CI workflow, docs/internal
ledger/evidence. Cost-policy runtime configuration must have model, version,
unit and verifiable request bound; no baked-in guessed prices.

- [ ] Write API/UI tests for explicit max_ai_cost_nano_credits, legacy missing
  authority, unit display, activation refusal, needs_human reason and immutable
  existing-run limits. Update generated contracts using repository scripts.
- [ ] Implement those fields and states with real APIs; no demo fallback or
  automatic tenant budget assignment. Keep definition reads backward-compatible.
  Production workflow input preservation and activation-state read compatibility
  now pass grouped API race run832b28 (2.997s), after RED373ed4/053d8a. Explicit
  integer bounds and invalid/null rejection are covered; missing draft cost is
  never assigned. SQL write integration, missing-cost activation refusal,
  OpenAPI/client/domain HTTP and UI wiring remain open in this batch.
  Follow-up: OpenAPI/generated optional cost contracts, browser definition/
  receipt decoding and blank-by-default create input now exist. Group772995
  passes96 UI/decoder tests; OpenAPI39/check, typecheck/lint and UI build9fd806
  pass. Existing-definition editing/display, activation refusal, SQL integration
  and alternate HTTP/domain remain open; no production availability promotion.
  Real migrated53 workflow create/update and activation readback now prove cost
  transport. Missing-cost supervised activation reproduced7de03a; unpublished53
  now guards both execution activation targets under existing row lock. Group
  84570e passes11 cost cases and migration rollback/consumer checks65.330s,
  independently reviewed. Explicit API error/UI gating and existing-definition
  cost editing remain open, with autonomous/replay side-effect additions under
  final verification. No live billing/release claim.
  Final expanded activation/write-read run90fc35 passes55.265s with both execution
  targets, exact operation errors, no side effects on refusal and mutation-free
  receipt replay. Migration group84570e remains current for unchanged SQL source.
  Editor/removal and missing/unsaved-cost activation UI gates now exist after
  RED8ea507/0aa2f9; the API gives a fixed cost_budget_required400 after513ea1.
  Real SQL/error groupd92a59 passes53.753s. Review found leading-zero editor state
  retained after integer save; regression241899 preceded receipt normalization.
  Final UI/build rerun is pending. Real enabled-definition reconfiguration and
  stale-client error display remain open alongside pricing/release acceptance.
  Follow-up: both now have bounded evidence. Registered SQL reconfiguration
  increase/removal preserves admitted budgets, rejects stale direct CAS, replays
  through HTTP and direct SQL after revalidation, and writes public update/delete
  audit versions (910d1c,10.147s). The post-repair409 was fixture correlation-ID
  reuse causing audit23505 (daeab9), corrected without another production fix.
  Current cost/activation/migration-fences/consumer batch0230cb passes73.868s.
  Known stale-client refusal now shows fixed save/revalidate guidance, with
  fresh UI/receipt89 tests, typecheck and full build passingccd8e8. Independent
  review found no Critical/Important source issue. Concurrent activation/update,
  alternate domain HTTP, verified pricing and broader release gates remain open.
  Observed activation/edit concurrency is now covered in both first-winner
  orders: real blocked backend PIDs, one committed public version, no losing
  receipt/audit/revision, and mutation-free rejected retry. Grouped race run
  959862 passes20.417s with admitted-run reconfiguration; independent review
  found no Critical/Important issue. Alternate HTTP is confirmed memory-backed
  component-only, not mounted production. Its optional cost transport gap stays
  open; verified pricing authority and full release acceptance remain unfinished.
  Production request compatibility repair: remove temperature unsupported by
  pinned GPT-5-mini and require provider parameter support (official docs plus
  public endpoint metadata b99383). RED510f36 preceded the change; affected race
  group84a453 passes2.220s and independent review found no blocking source issue.
  Full worker race24f0b6 passes29.487s; six-mode migrated worker groupdda2bf passes
  40.198s using controlled transport. No request cost maxima were inferred from
  catalog rates; paid dispatch stays blocked without verified pricing authority.
  Public stop visibility now has bounded evidence: optional allowlisted reason
  from the tenant-scoped durable budget, strict API/client decoding and fixed
  UI guidance for five reasons. RED6b88b6/a8843c/d4eec2 preceded the repair;
  Go reads9fde83 pass, UI117/typecheck/build1cd3f2 pass, OpenAPI39/check and
  migrations01a831 pass. Candidate pin10ac4fb7b3212c5b89164911070c184e5aa3525cb29aacbb526bf5e183e20eb5
  was measured9a4ca4. Worker/migration groupf2a2bd passes63.040s, extended
  public-handler foreign org/workspace/environment/read checks5ddb39 pass16.442s.
  Independent review found no blocking source issue. A follow-up compatibility
  batch adds explicit X-Zasp-Budget-Details:v1 opt-in; legacy requests retain
  seven fields and new clients accept old-server omission. RED4b2767/780a6a,
  Go race ca7bc0, UI/API93/typecheck/build3d2188 and OpenAPI39/check bc69b6
  document the boundary. Composed PostgreSQL/worker legacy/opt-in/tenant checks
  b2b401 pass25.223s. Review found no Critical/Important issue; its minor schema
  mismatch for unsupported header values was corrected. Mounted auth/proxy/live
  rollout remain open.
- [ ] Complete the matrix: approved-but-expired runs, independent action/time/
  token/cost exhaustion, two workers/definitions/environments, cross-tenant
  references, unknown effects, no new effects after stop and actual cleanup.
- [ ] Verify migrated and mixed-version runtime readiness, rollback refusal,
  browser/API flow, affected race tests and full UI/build release checks.
  Broad September16 checks now pass UI1665, dependency9, lint, source/compiled
  import graphs and current UI build. Staging gate68fb0e remains red because the
  explicit chart/release contract stops at52 while the embedded budget schema
  is53. Next: explicit53 rendered deployment and audit-export migration/policy
  sequence, retaining default49 and precision-phase/old-runtime safeguards.
  See 2026-09-16-release-verification-checkpoint.md; do not merely update the
  latest-version assertion or interpret older-phase release tests as53 proof.
  Deployment trace found a prerequisite: ConfigureAuditExports and
  RegisterAuditExportWorkers required an exact52 chain even after up-to-53.
  Real binary RED3b6bee reproduces registration failure at53. Operational setup
  now selects only exact compiled52 or53 metadata and pins that release's
  readiness before and after mutation; historical migration readers are
  unchanged. Full migration unit race1d7dc0 passes2.007s including malformed/
  future metadata and initial/final drift controls. Two-schema real CLI group
  791779 passes64.934s: fresh registration/configuration, rotation, replay and
  rollback run at52 and53. Independent review found no Critical/Important issue;
  its lower-version control was added. RegisterAuditExportAPI remains exact52
  and needs separate caller/rollout analysis. Chart53 support remains unfinished.
  Follow-up rendered deployment batch now closes chart53 support: explicit
  precision phases, optional export workers/policy sequence, target53 hook and
  matching schema annotations. Default49 is unchanged. REDbb9bb4 then focused
  render5 tests6acb84, grouped staging7 tests89cd98 and production197 tests193bf3
  pass. Lint/typecheck/ledgerae94e3 pass. Independent review found no blocking
  source issue; actual
  mixed-binary/live rollout and API capability registration remain separate gates.
  API capability setup is now locally integrated: explicit CLI command consumes
  the existing discovery API principal env, Runner uses exact52/53 compiled
  authority, and enabled-export hooks register API before workers/policy.
  RED71f858/76b50b/dc3ee5 preceded changes. Migration racefa6862, real52/53
  binary groupb5d02a77.942s, release197/staging7 tests58efc4 and lint/typecheck/
  ledgerb7a61d pass. Review found no Critical/Important issue. Fresh/replay/refused
  bindings preserve role grants. Live enrollment/authenticated export acceptance
  remains open; no deployment or availability promotion was performed.
- [ ] Independent batch review; record exact evidence per M7A-49/M7A-95.
  Integrate only the verified batch, preserve unrelated WIP, and push main only
  after all applicable external release/disclosure gates are authorized and met.

## Current checkpoint

The registered v53 migration and explicit CLI now have local upgrade/empty
rollback evidence. API, ingest and updated planner/action readiness bind
application pins; worker constructor fallbacks reject coherent SQL-root drift
(group23ce11). Prior prerequisite/finding waits, planner stop propagation and
organization-first locking have bounded component evidence above. The broader
SecurityAgent baseline run failed14 budget cases at fresh repository readiness
(35ca12), because their shared fixture still staged fragments on33. That
fixture now upgrades through the real migration chain to53 without relaxing
readiness; the scoped14-case behavior run passesb5beb0 (63.379s), independently
reviewed. The consolidated selected SecurityAgent group now passesb5fc59
(API432.502s/worker2.568s/migrations2.895s). It began before the usage-parser
delta; current-source worker tests741a4c pass2.380s separately. These local
passes do not close all Batch1 or release requirements.
Next work includes populated migrated worker/action lifecycle, operation-level
and old-binary compatibility, context spending permits and durable accounting.
Do not bypass readiness or treat local component passes as production proof.
Batch 1 remains incomplete; cost configuration, provider accounting and
production completion are not claimed.
