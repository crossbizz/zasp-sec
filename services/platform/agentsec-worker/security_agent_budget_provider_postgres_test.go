package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Controlled transport pricing only. This wrapper is never available to the
// production constructor and does not establish a live provider cost policy.
type budgetFixturePlanner struct {
	*productionSecurityAgentPlanner
}

func (p *budgetFixturePlanner) Prepare(ctx context.Context, value securityAgentPlannerContext) (securityAgentPreparedPlan, error) {
	prepared, err := p.productionSecurityAgentPlanner.Prepare(ctx, value)
	if err != nil {
		return nil, err
	}
	return controlledPreparedPlan(prepared.(*productionSecurityAgentPreparedPlan)), nil
}

// Only parent-owned crash fixtures select this planner. Exit bypasses all
// deferred accounting/cleanup, preserving the real process-loss boundary.
type budgetCrashPlanner struct {
	*budgetFixturePlanner
	afterResponse bool
	transport     *securityAgentPlannerTransport
}

type budgetCrashSettlementAuthority struct {
	*apiserver.SecurityAgentWorkerRepository
	transport *securityAgentPlannerTransport
}

func (a *budgetCrashSettlementAuthority) SettleSecurityAgentPlannerBudget(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string, usage apiserver.SecurityAgentBudgetUsage) (apiserver.SecurityAgentBudgetSettlement, error) {
	result, err := a.SecurityAgentWorkerRepository.SettleSecurityAgentPlannerBudget(ctx, claim, worker, lease, usage)
	if err != nil || !result.Known || result.StopReason != "" {
		return result, err
	}
	a.transport.mu.Lock()
	calls := a.transport.calls
	a.transport.mu.Unlock()
	if calls != 1 {
		panic("settled crash without one provider call")
	}
	fmt.Fprintf(os.Stdout, "owned budget crash boundary: provider_calls=%d\n", calls)
	os.Exit(86)
	return result, err
}

func (p *budgetCrashPlanner) Prepare(ctx context.Context, value securityAgentPlannerContext) (securityAgentPreparedPlan, error) {
	prepared, err := p.budgetFixturePlanner.Prepare(ctx, value)
	if err != nil {
		return nil, err
	}
	return &securityAgentPreparedStub{budget: prepared.PlannerBudget(), dispatch: func(ctx context.Context) securityAgentPlannerResult {
		return p.dispatchAtCrashBoundary(ctx, prepared)
	}}, nil
}

func (p *budgetCrashPlanner) dispatchAtCrashBoundary(ctx context.Context, prepared securityAgentPreparedPlan) securityAgentPlannerResult {
	wantCalls := 0
	if p.afterResponse {
		result := prepared.Dispatch(ctx)
		if result.Usage == nil || result.Usage.TotalTokens != 160 || result.Usage.CostNanoCredits != 100 {
			panic("crash fixture did not capture exact provider response")
		}
		wantCalls = 1
	}
	p.transport.mu.Lock()
	calls := p.transport.calls
	p.transport.mu.Unlock()
	if calls != wantCalls {
		panic("unexpected transport count at crash boundary")
	}
	fmt.Fprintf(os.Stdout, "owned budget crash boundary: provider_calls=%d\n", calls)
	os.Exit(86)
	return securityAgentPlannerResult{}
}

// This instrument only delays delivery of an actual committed repository result.
// It never replaces SQL, results or errors. Removing worker stop reconciliation
// must fail the heartbeat case; allowing planning after expiry must issue a
// forbidden transport request or leave the parent's durable assertions wrong.
type budgetCommittedStopAuthority struct {
	*apiserver.SecurityAgentWorkerRepository
	committed  chan struct{}
	conflicts  atomic.Int32
	completion bool
}

func (a *budgetCommittedStopAuthority) LoadSecurityAgentPlannerContext(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string) (apiserver.SecurityAgentPlannerContext, error) {
	result, err := a.SecurityAgentWorkerRepository.LoadSecurityAgentPlannerContext(ctx, claim, worker, lease)
	if a.completion {
		return result, err
	}
	close(a.committed)
	if errors.Is(err, apiserver.ErrSecurityAgentBudgetStopped) {
		<-ctx.Done()
	}
	return result, err
}

func (a *budgetCommittedStopAuthority) AcceptSecurityAgentPlannerCandidate(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string, submission apiserver.SecurityAgentPlannerSubmission, approval string, expires time.Time, audit, correlation string) (apiserver.SecurityAgentPrepareResult, error) {
	result, err := a.SecurityAgentWorkerRepository.AcceptSecurityAgentPlannerCandidate(ctx, claim, worker, lease, submission, approval, expires, audit, correlation)
	if a.completion {
		close(a.committed)
		if err == nil {
			<-ctx.Done()
		}
	}
	return result, err
}

func (a *budgetCommittedStopAuthority) HeartbeatSecurityAgentRun(ctx context.Context, claim apiserver.SecurityAgentRunClaim, worker, lease string, seconds int) error {
	select {
	case <-a.committed:
	case <-ctx.Done():
		return ctx.Err()
	}
	err := a.SecurityAgentWorkerRepository.HeartbeatSecurityAgentRun(ctx, claim, worker, lease, seconds)
	if errors.Is(err, apiserver.ErrRepositoryConflict) {
		a.conflicts.Add(1)
	}
	return err
}

func TestSecurityAgentBudgetProviderOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_BUDGET_PROVIDER_TEST_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned budget database")
	}
	mode := os.Getenv("ZASP_BUDGET_PROVIDER_TEST_MODE")
	crash := mode == "crash_before_provider" || mode == "crash_after_response"
	settledCrash := mode == "crash_settled_remaining" || mode == "crash_settled_exhausted"
	restart := mode == "restart_unknown" || mode == "restart_settled_remaining" || mode == "restart_settled_exhausted"
	remaining := mode == "crash_settled_remaining" || mode == "restart_settled_remaining"
	if mode != "expired" && mode != "fresh" && mode != "fresh_heartbeat" && mode != "completion_heartbeat" && mode != "heartbeat" && mode != "missing_cost_authority" && mode != "run_once_missing_cost_authority" && !crash && !settledCrash && !restart {
		t.Fatal("unknown budget scenario")
	}
	permitted := mode == "fresh" || mode == "fresh_heartbeat" || mode == "completion_heartbeat" || crash || settledCrash || restart
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid owned database configuration")
	}
	local := func(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
	if !local(config.Host) || config.User != "zasp_e2e" || config.Database != "postgres" {
		t.Fatal("requires parent-owned loopback fixture")
	}
	for _, fallback := range config.Fallbacks {
		if !local(fallback.Host) {
			t.Fatal("nonlocal fallback refused")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	var version int64
	if err := owner.QueryRow(ctx, `SELECT max(version) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 53 {
		t.Fatalf("composed budget worker requires registered release53: version=%d err=%v", version, err)
	}
	workerURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid fixture URL")
	}
	workerURL.User = url.User("security_agent_v33_worker_login")
	database := combinedE2ERecoveryDatabase(t, ctx, workerURL.String())
	repository, err := apiserver.NewSecurityAgentWorkerRepository(database)
	if err != nil {
		t.Fatal("migrated worker unavailable", err)
	}
	if err := repository.Ready(ctx); err != nil {
		t.Fatal("migrated worker readiness", err)
	}
	if mode == "run_once_missing_cost_authority" {
		verifyBudgetRunOnceMissingCost(t, ctx, repository)
		return
	}
	const organization = "pid_6a000001-0000-4000-8000-000000000001"
	worker, lease := "budget-provider-worker", "budget-provider-worker-lease"
	wantScheduled := 1
	if restart {
		worker, lease = "budget-restarted-worker", "budget-restarted-worker-lease"
		wantScheduled = 0
	}
	if count, err := repository.ScheduleSecurityAgentTriggers(ctx, worker, 1); err != nil || count != wantScheduled {
		t.Fatalf("schedule=%d error=%v", count, err)
	}
	claims, err := repository.ClaimSecurityAgentRuns(ctx, worker, lease, 60, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%d error=%v", len(claims), err)
	}
	if restart && claims[0].Attempt != 2 {
		t.Fatalf("restart attempt=%d", claims[0].Attempt)
	}
	if permitted && !restart {
		tokens, cost := 1000, 200
		if remaining {
			tokens, cost = 2000, 400
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET max_tokens=$3,max_cost_nano_credits=$4 WHERE organization_id=$1 AND run_id=$2`, organization, claims[0].RunID, tokens, cost); err != nil {
			t.Fatal(err)
		}
	}
	if restart {
		var valid bool
		tokens, cost := 1000, 200
		if remaining {
			tokens, cost = 2000, 400
		}
		if err := owner.QueryRow(ctx, `SELECT max_tokens=$3 AND max_cost_nano_credits=$4 AND stop_reason IS NULL AND deadline_at>clock_timestamp() FROM zasp_security_agent_run_budgets WHERE organization_id=$1 AND run_id=$2`, organization, claims[0].RunID, tokens, cost).Scan(&valid); err != nil || !valid {
			t.Fatalf("restart lost original cost authority: %v %v", valid, err)
		}
	}
	if mode == "fresh_heartbeat" {
		for i := 0; i < 2; i++ {
			if err := repository.HeartbeatSecurityAgentRun(ctx, claims[0], worker, lease, 120); err != nil {
				t.Fatal(err)
			}
		}
		var version int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE organization_id=$1 AND run_id=$2`, organization, claims[0].RunID).Scan(&version); err != nil || version != claims[0].Version+2 {
			t.Fatalf("heartbeat version=%d err=%v", version, err)
		}
	}
	if mode == "missing_cost_authority" {
		var missing bool
		if err := owner.QueryRow(ctx, `SELECT max_cost_nano_credits IS NULL AND stop_reason IS NULL AND deadline_at>clock_timestamp() FROM zasp_security_agent_run_budgets WHERE organization_id=$1 AND run_id=$2`, organization, claims[0].RunID).Scan(&missing); err != nil || !missing {
			t.Fatalf("missing-cost regression needs a live run without cost authority: missing=%v err=%v", missing, err)
		}
	}
	if mode == "expired" || mode == "heartbeat" {
		if tag, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '301 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1 AND run_id=$2`, organization, claims[0].RunID); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("expire claimed budget: %v", err)
		}
	}
	transport := &securityAgentPlannerTransport{responseBody: openRouterPlannerResponse(`{"version":1,"summary":"Apply bounded containment","steps":[{"index":0,"action":"create_temporary_policy","target_id":"pid_6a000003-0000-4000-8000-000000000003"}]}`)}
	if permitted {
		var response map[string]json.RawMessage
		if err := json.Unmarshal(transport.responseBody, &response); err != nil {
			t.Fatal(err)
		}
		response["usage"] = json.RawMessage(`{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"cost":0.0000001}`)
		transport.responseBody, err = json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
	}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{
		Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = planner.Close() })
	var selectedPlanner securityAgentPlanner = planner
	heartbeatInterval := 10 * time.Millisecond
	if permitted {
		selectedPlanner = &budgetFixturePlanner{planner}
		// This positive case checks accounting, not concurrent heartbeat results.
		heartbeatInterval = 20 * time.Second
	}
	if crash {
		selectedPlanner = &budgetCrashPlanner{budgetFixturePlanner: &budgetFixturePlanner{planner}, afterResponse: mode == "crash_after_response", transport: transport}
	}
	var authority apiserver.SecurityAgentWorkerAuthority = repository
	if settledCrash {
		authority = &budgetCrashSettlementAuthority{SecurityAgentWorkerRepository: repository, transport: transport}
	}
	instrument := &budgetCommittedStopAuthority{SecurityAgentWorkerRepository: repository, committed: make(chan struct{})}
	if mode == "heartbeat" {
		authority = instrument
	}
	if mode == "completion_heartbeat" {
		instrument.completion = true
		authority = instrument
		heartbeatInterval = 10 * time.Millisecond
	}
	ids := 0
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{
		Authority: authority, Planner: selectedPlanner, WorkerID: worker, LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: heartbeatInterval,
		Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: func() (string, error) { return lease, nil },
		NewProductID: func() (string, error) { ids++; id, err := domain.NewProductID(); return id.String(), err },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.process(ctx, claims[0], lease); err != nil || ctx.Err() != nil {
		t.Fatalf("actual processor: error=%v context=%v", err, ctx.Err())
	}
	wantCalls, wantIDs := 0, 0
	if permitted && (!restart || remaining) {
		wantCalls, wantIDs = 1, 3
	}
	if transport.calls != wantCalls || ids != wantIDs {
		t.Fatalf("provider calls=%d want=%d artifact IDs=%d want=%d", transport.calls, wantCalls, ids, wantIDs)
	}
	if (mode == "heartbeat" || mode == "completion_heartbeat") && instrument.conflicts.Load() != 1 {
		t.Fatalf("actual post-commit heartbeat conflicts=%d", instrument.conflicts.Load())
	}
	t.Logf("owned budget processor joined: provider_calls=%d artifact_ids=%d heartbeat_conflicts=%d", transport.calls, ids, instrument.conflicts.Load())
}

// Unlike process-level fixtures, this exercises real scheduling, claim,
// processing and a second worker poll without seeding a lease or budget row.
func verifyBudgetRunOnceMissingCost(t *testing.T, ctx context.Context, repository *apiserver.SecurityAgentWorkerRepository) {
	t.Helper()
	transport := &securityAgentPlannerTransport{responseBody: openRouterPlannerResponse(`{"version":1,"summary":"Forbidden provider response","steps":[]}`)}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{
		Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = planner.Close() })
	ids := 0
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{
		Authority: repository, Planner: planner, WorkerID: "budget-run-once-worker", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: 20 * time.Second,
		Now:           func() time.Time { return time.Now().UTC() },
		NewLeaseToken: func() (string, error) { return "budget-run-once-lease-token", nil },
		NewProductID:  func() (string, error) { ids++; id, err := domain.NewProductID(); return id.String(), err },
	})
	if err != nil {
		t.Fatal(err)
	}
	for poll := 0; poll < 2; poll++ {
		if err := processor.RunOnce(ctx); err != nil || ctx.Err() != nil {
			t.Fatalf("actual RunOnce poll%d: error=%v context=%v", poll, err, ctx.Err())
		}
	}
	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()
	if calls != 0 || ids != 0 {
		t.Fatalf("RunOnce escaped missing cost authority: provider_calls=%d artifact_ids=%d", calls, ids)
	}
	t.Logf("owned budget processor joined: RunOnce polls=2 provider_calls=%d artifact_ids=%d", calls, ids)
}
