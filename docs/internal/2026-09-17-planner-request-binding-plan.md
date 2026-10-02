# Planner Request Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Implement this coherent feature batch with focused TDD, one independent review and grouped acceptance.

**Goal:** Bind the planner budget decision and dispatch to one immutable prepared request while retaining durable stop/settlement and crash recovery.

**Architecture:** Prepare once before reservation; the prepared object owns the bytes and validation snapshot. The worker reserves and checks a copied budget request, then dispatches that object without reserialization. Production pricing authority remains unavailable and must still commit the unknown-budget stop before any outbound call.

**Tech Stack:** Existing Go worker, PostgreSQL repositories, controlled HTTP transport tests. No new dependencies.

**Spec:** docs/internal/2026-09-17-planner-request-binding-design.md

## Global Constraints

- Full728 scope is unchanged; this is a missing prerequisite, not full pricing acceptance.
- No SQL fingerprint, UI, deployment configuration, account/provider choice or production ACL change.
- No provider/network/download calls, Docker/host PostgreSQL, commits/index changes or shipping-tree edits by the implementer.
- Never replace or relabel the database canonical input digest as the body digest.
- Credentials stay out of prepared values, hashes, logs and persisted evidence.
- Missing production pricing authority continues through the existing durable unknown-budget stop.
- Preserve unknown usage, no blind paid retry and settlement before candidate acceptance.
- Parent owns runtime acceptance and source transfer. One implementation agent; no subagents.

## Preflight and decisions

One task owns the interfaces and every affected planner adapter. Splitting these
into independently accepted microtasks would permit an intermediate worker that
silently bypasses crash hooks. Existing direct planner tests may retain a Plan
convenience method, but worker dispatch cannot fall back to that method.

Ruling: use a prepared-object interface so fixture wrappers can replace their
old Plan override with an explicit prepared-dispatch override. Cost if wrong:
adapter rework. Retain direct Plan as a Prepare/Dispatch convenience for existing
unit tests only, with one shared implementation of transport/response logic.

| Producer / consumer | Contract check |
| --- | --- |
| planner / budget runtime | Prepare returns a single immutable object; reservation and Dispatch use that same object |
| budget runtime / SQL | Stable reservation ID and canonical InputDigest remain unchanged; exact permit checks remain |
| production planner / fixture wrapper | Controlled caps wrap the prepared production object only in test files |
| runtime tests / worker | Context recording and cancellation hooks move explicitly into prepared dispatch |
| crash fixture / parent database proof | Exit86, zero/one send counts and settled/unknown states remain asserted |
| task / spec | No positive production price authority invented; no component-to-live promotion |

### Task 1: Immutable request preparation and budget-bound dispatch

Acceptance execution addendum: the apiserver provider/crash parent tests
currently compile their child with Go. Add shared explicit prebuilt-worker
support using ZASP_BUDGET_PROVIDER_WORKER_BINARY (absolute regular executable,
mode logged), retaining local compile when unset and all skip/crash markers.
Cover invalid paths with focused tests. This permits root to execute in cached
PostgreSQL without host PG or a compiler/download inside the container.

**Files:**

- Modify services/platform/agentsec-worker/security_agent_planner.go: planner interface, Plan extraction and response validation.
- Create services/platform/agentsec-worker/security_agent_prepared_plan.go: prepared request ownership, identity and one-shot dispatch.
- Modify services/platform/agentsec-worker/security_agent_budget_runtime.go: prepare/reserve/dispatch ordering.
- Create services/platform/agentsec-worker/security_agent_prepared_plan_test.go: executable request-binding/refusal tests.
- Modify services/platform/agentsec-worker/security_agent_planner_test.go only to preserve direct-plan coverage or reuse setup.
- Adapt services/platform/agentsec-worker/security_agent_runtime_test.go, security_agent_budget_runtime_test.go, security_agent_budget_provider_postgres_test.go, production_combined_budget_fixture_test.go.
- Create services/platform/agentsec-worker/security_agent_cost_policy.go and focused tests for the internal request-bound authority result. No production constructor/configuration may accept a test authority.
- Update the request-binding design and production-pricing critical-path documentation with actual limitations after verification.

**Interfaces:** replace the worker-facing Plan requirement with:

```go
type securityAgentPlanner interface {
    Prepare(context.Context, securityAgentPlannerContext) (securityAgentPreparedPlan, error)
    Close() error
}

type securityAgentPreparedPlan interface {
    PlannerBudget() apiserver.SecurityAgentBudgetReservation
    Dispatch(context.Context) securityAgentPlannerResult
}
```

Production Prepare returns a pointer-owned object. Store the body as an
unexported string, not caller-owned bytes. Deep-copy AllowedActions,
AllowedTargets, Evidence and ExistingTest including any nested reference data.
Keep the cloned context for candidate validation, not only serialization.
Identity covers exact body digest, model, endpoint/routing and data-policy
identity; no credentials. Snapshot configuration atomically under planner.mu.
Dispatch checks cancellation/closed state and configuration identity before
send, reads credentials only then, and consumes the object at most once through
an atomic/mutex guard. Concurrent Dispatch calls cannot produce two sends.
Do not hold the planner mutex across network I/O. Keep existing transport
limits, redirect policy and response parsing in one implementation.

The internal verified-cost-bound type must bind request identity, model,
openrouter_credit unit, supported account profile, cost-policy version,
expiry and token/cost maxima. It is not a descriptor with a verified boolean.
Production has no producer of a positive verified bound in this batch; its
prepared PlannerBudget returns model/unit with unknown caps. Test-only wrappers
may create controlled bounds, with mismatch/expiry/profile validation, and must
not become reachable from production constructors. A structural descriptor
validator is not evidence of approved pricing provenance. If the type requires
new authority decisions beyond this boundary, report that before expanding.

- [ ] Write failing tests before implementation. Use existing testSecurityAgentPlannerContext and securityAgentPlannerTransport. One concrete baseline is:

```go
func TestSecurityAgentPreparedPlanFreezesContext(t *testing.T) {
    transport := &securityAgentPlannerTransport{responseStatus: http.StatusOK,
        responseBody: openRouterPlannerResponse(`{"version":1,"summary":"Review","steps":[{"index":0,"action":"update_finding_response","target_id":"pid_71000001-0000-4000-8000-000000000001"}]}`)}
    planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{
        Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini",
        Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second,
        MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport,
    })
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { _ = planner.Close() })
    value := testSecurityAgentPlannerContext()
    prepared, err := planner.Prepare(context.Background(), value)
    if err != nil { t.Fatal(err) }
    if transport.calls != 0 { t.Fatal("prepare sent request") }
    value.AllowedActions[0] = "create_temporary_policy"
    result := prepared.Dispatch(context.Background())
    if result.Failure != "" || transport.calls != 1 { t.Fatalf("result=%+v calls=%d", result, transport.calls) }
}
```

Expand that test to compare captured exact body against the prepared body, then
mutate targets, evidence and nested test reference too. Add table cases for
closed/cancelled planner, model/endpoint/policy drift, duplicate/concurrent
dispatch, wrong-model/unit/profile/expired or absent authority. Assert zero
sends for refusals, not just an error string. For production absence, assert
unknown caps and actual worker reservation/stop ordering; direct prepared
Dispatch in transport tests is not proof of budget-authorized production use.

- [ ] Run the focused RED group offline. Missing new interface compilation is scaffolding evidence only; establish behavioral RED for the ordering/binding assertions before claiming TDD acceptance. Record exact failures.

- [ ] Extract current request serialization and validation to Prepare. Keep Plan convenience delegating to Prepare then Dispatch, with no alternate serializer. Use cloned validation context for the existing final validSecurityAgentPlannerCandidate check.

- [ ] Change planWithBudget at the existing reservation boundary:

```go
prepared, err := processor.config.Planner.Prepare(ctx, plannerContext)
if err != nil || prepared == nil { return zero, errWorkerExecution }
request := prepared.PlannerBudget()
request.ReservationID = claim.RunID + "/planner/" + strconv.Itoa(claim.Attempt)
request.InputDigest = inputDigest
// Reserve and retain every existing permit/range/context/expiry check here.
// After those checks and context.WithDeadline:
result := prepared.Dispatch(providerCtx)
```

Do not remove or weaken existing settlement code. Preparation errors must not
send. Absent pricing on a valid request must still reach Reserve with unknown
caps so SQL can durably stop; don't convert that path into a local silent return.

- [ ] Adapt all four named fixture files as part of this task. Move budgetRuntimePlanner's order/cancel hooks and budgetCrashPlanner's before-send/after-response hooks to explicit prepared wrappers. Preserve actual transport call assertions and exit86. Avoid embedded method promotion silently selecting production methods instead of the hooks.

- [ ] Run one grouped GREEN/race command after the coherent patch:

```sh
env GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOCACHE=/private/tmp/zasp-budget-go-cache go test ./agentsec-worker -run '^(TestSecurityAgentPrepared|TestSecurityAgentPlanner|TestProductionSecurityAgentPlanner|TestSecurityAgentProcessorBudget|TestCombinedBudgetFixture)' -race -count=1 -timeout=90s -v
```

Inspect selected test names; include the actual existing combined-budget fixture
name if the regex doesn't select it. No skipped DB helpers count as acceptance.
Run package compile once to catch fixture interface breakage. Don't launch
database tests or broad runtimes from the agent.

- [ ] Freeze the task-only patch against pre-edit copies, exact source/input
hashes, commands/output and limitations. Root dispatches independent review,
then owns grouped cached-PostgreSQL provider suppression and process-loss cases
using TestProductionSecurityAgentBudgetProviderSuppressionThroughWorker,
TestProductionSecurityAgentBudgetProcessLossRetainsUnknown and
TestProductionSecurityAgentBudgetProcessLossRetainsSettled. Inspect their
current binary/tool requirements before execution; no host PG/downloads.

- [ ] Transfer only reviewed exact sources into shipping. Reuse unchanged UI
evidence, rerun affected runtime acceptance for changed planner behavior, and
keep publication blocked until its existing external gates pass. No task or
milestone promotion from synthetic provider costs. Commit/push is root-owned
only after mandatory release checks, not an implementer step in this dirty tree.

## Self-review

Every design acceptance item maps to preparation/dispatch tests or preserved
budget/crash tests above. SQL and external price authority remain explicit
unclosed gates. The body digest and canonical input digest are separate. The
only new worker-facing methods are Prepare, PlannerBudget and Dispatch on the
named interfaces. Controlled overrides must move together with the worker.
