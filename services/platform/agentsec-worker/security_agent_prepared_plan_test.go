package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

type plannerMutationTransport struct {
	transport *securityAgentPlannerTransport
	mutate    func()
}

func (t *plannerMutationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mutate()
	return t.transport.RoundTrip(r)
}

func requestBindingPlanner(t *testing.T, transport http.RoundTripper) *productionSecurityAgentPlanner {
	t.Helper()
	p, err := newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func bindingResponseTransport() *securityAgentPlannerTransport {
	return &securityAgentPlannerTransport{responseStatus: http.StatusOK, responseBody: openRouterPlannerResponse(`{"version":1,"summary":"Review","steps":[{"index":0,"action":"update_finding_response","target_id":"pid_71000001-0000-4000-8000-000000000001"}]}`)}
}

// Removing the owned validation snapshot lets post-serialization caller
// mutation reject a candidate authorized by the bytes already sent.
func TestSecurityAgentPreparedPlanValidationUsesOwnedContext(t *testing.T) {
	value := testSecurityAgentPlannerContext()
	transport := bindingResponseTransport()
	p := requestBindingPlanner(t, &plannerMutationTransport{transport: transport, mutate: func() {
		value.AllowedActions[0] = "create_temporary_policy"
		value.AllowedTargets[0] = value.EnvironmentID
	}})
	result := p.Plan(context.Background(), value)
	if result.Failure != "" || transport.calls != 1 {
		t.Fatalf("serialized context lost validation authority: result=%+v calls=%d", result, transport.calls)
	}
}

func TestSecurityAgentPreparedPlanFreezesContext(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "finding", true: "existing_test"}[existing], func(t *testing.T) {
			transport := bindingResponseTransport()
			p := requestBindingPlanner(t, transport)
			value := testSecurityAgentPlannerContext()
			if existing {
				value.AllowedActions = []string{"run_test"}
				value.ExistingTest = &apiserver.SecurityAgentExistingTestReference{DefinitionID: value.AllowedTargets[0], DefinitionVersion: 7}
				transport.responseBody = openRouterPlannerResponse(`{"version":1,"summary":"Review","steps":[{"index":0,"action":"run_test","target_id":"pid_71000001-0000-4000-8000-000000000001"}]}`)
			}
			preparedValue, err := p.Prepare(context.Background(), value)
			if err != nil {
				t.Fatal(err)
			}
			prepared := preparedValue.(*productionSecurityAgentPreparedPlan)
			body := prepared.body
			if transport.calls != 0 {
				t.Fatal("prepare sent request")
			}
			value.AllowedActions[0] = "create_temporary_policy"
			value.AllowedTargets[0] = value.EnvironmentID
			value.Evidence[0].Summary = "changed evidence"
			if existing {
				value.ExistingTest.DefinitionVersion = 99
				value.ExistingTest.DefinitionID = value.EnvironmentID
			}
			result := prepared.Dispatch(context.Background())
			if result.Failure != "" || transport.calls != 1 || string(transport.requestBody) != body {
				t.Fatalf("prepared request changed: %+v calls=%d", result, transport.calls)
			}
			digest := sha256.Sum256(transport.requestBody)
			if prepared.identity.BodyDigest != "sha256:"+hex.EncodeToString(digest[:]) {
				t.Fatal("identity does not cover exact sent body")
			}
			var request securityAgentOpenRouterRequest
			if json.Unmarshal(transport.requestBody, &request) != nil || request.MaximumTokens != 512 || request.Model != "openai/gpt-5-mini" || request.Provider.DataCollection != "deny" || !request.Provider.RequireParameters || !request.ResponseFormat.JSONSchema.Strict || len(request.ResponseFormat.JSONSchema.Schema) == 0 {
				t.Fatalf("lost outbound limits/schema: %+v", request)
			}
			if strings.Contains(request.Messages[1].Content, "changed evidence") || strings.Contains(request.Messages[1].Content, `"definition_version":99`) || prepared.contextValue.Evidence[0].Summary == "changed evidence" {
				t.Fatal("caller-owned evidence/reference reached prepared state")
			}
			if existing && prepared.contextValue.ExistingTest.DefinitionVersion != 7 {
				t.Fatal("reference not owned")
			}
		})
	}
}

func TestSecurityAgentPreparedPlanRefusesDriftAndCancellation(t *testing.T) {
	for _, mode := range []string{"closed", "cancelled_dispatch", "cancelled_preparation", "model", "endpoint", "policy", "token_limit", "client", "credential"} {
		t.Run(mode, func(t *testing.T) {
			transport := bindingResponseTransport()
			p := requestBindingPlanner(t, transport)
			prepareCtx, cancelPrepare := context.WithCancel(context.Background())
			defer cancelPrepare()
			prepared, err := p.Prepare(prepareCtx, testSecurityAgentPlannerContext())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "closed":
				_ = p.Close()
			case "cancelled_dispatch":
				cancel()
			case "cancelled_preparation":
				cancelPrepare()
			default:
				p.mu.Lock()
				switch mode {
				case "model":
					p.model = "other/model"
				case "endpoint":
					p.endpoint = "https://other.invalid/route"
				case "policy":
					p.policyVersion = "changed-policy"
				case "token_limit":
					p.maximumTokens++
				case "client":
					p.client = &http.Client{Transport: transport}
				case "credential":
					p.token = nil
				}
				p.mu.Unlock()
			}
			if result := prepared.Dispatch(ctx); result.Failure == "" || transport.calls != 0 {
				t.Fatalf("refusal sent: %+v calls=%d", result, transport.calls)
			}
		})
	}
}

func TestSecurityAgentPreparedPlanDispatchIsOneShot(t *testing.T) {
	transport := bindingResponseTransport()
	p := requestBindingPlanner(t, transport)
	prepared, err := p.Prepare(context.Background(), testSecurityAgentPlannerContext())
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan securityAgentPlannerResult, 32)
	var joined sync.WaitGroup
	for range 32 {
		joined.Add(1)
		go func() { defer joined.Done(); results <- prepared.Dispatch(context.Background()) }()
	}
	joined.Wait()
	close(results)
	success := 0
	for result := range results {
		if result.Failure == "" {
			success++
		}
	}
	if success != 1 || transport.calls != 1 {
		t.Fatalf("success=%d calls=%d", success, transport.calls)
	}
	if result := prepared.Dispatch(context.Background()); result.Failure == "" || transport.calls != 1 {
		t.Fatal("duplicate dispatch sent")
	}
}

func TestSecurityAgentPreparedPlanPreparationErrorsNeverReserve(t *testing.T) {
	for _, mode := range []string{"invalid", "closed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			events := []string{}
			transport := bindingResponseTransport()
			p := requestBindingPlanner(t, transport)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			value := testSecurityAgentPlannerContext()
			switch mode {
			case "invalid":
				value.AllowedTargets = nil
			case "closed":
				_ = p.Close()
			case "cancelled":
				cancel()
			}
			a := &budgetRuntimeAuthority{events: &events}
			processor := &securityAgentProcessor{config: securityAgentProcessorConfig{Authority: a, Planner: p}}
			_, err := processor.planWithBudget(ctx, apiserver.SecurityAgentRunClaim{}, "lease", "canonical", value)
			if err == nil || len(events) != 0 || transport.calls != 0 {
				t.Fatalf("invalid preparation reserved/sent: %v %v calls=%d", err, events, transport.calls)
			}
		})
	}
}

func TestSecurityAgentPreparedPlanMissingAuthorityReachesReservation(t *testing.T) {
	events := []string{}
	transport := bindingResponseTransport()
	p := requestBindingPlanner(t, transport)
	a := &budgetRuntimeAuthority{events: &events, reserveErr: apiserver.ErrSecurityAgentBudgetStopped}
	processor := &securityAgentProcessor{config: securityAgentProcessorConfig{Authority: a, Planner: p}}
	claim := apiserver.SecurityAgentRunClaim{RunID: "test-run", Attempt: 4}
	_, err := processor.planWithBudget(context.Background(), claim, "lease", "canonical-database-digest", testSecurityAgentPlannerContext())
	if err != apiserver.ErrSecurityAgentBudgetStopped || !reflect.DeepEqual(events, []string{"reserve"}) || transport.calls != 0 {
		t.Fatalf("missing authority did not stop at reservation: %v %v calls=%d", err, events, transport.calls)
	}
	if a.request.ReservationID != "test-run/planner/4" || a.request.InputDigest != "canonical-database-digest" || a.request.Model != "openai/gpt-5-mini" || a.request.CostUnit != "openrouter_credit" || a.request.MaximumTokens != 0 || a.request.MaximumCostNanoCredits != 0 || a.request.CostPolicyVersion != "" {
		t.Fatalf("unknown reservation identity changed: %+v", a.request)
	}
}

func TestSecurityAgentPreparedPlanWorkerPermitRefusals(t *testing.T) {
	for _, mode := range []string{"reservation", "input_digest", "model", "policy", "unit", "tokens", "cost", "version", "version_range", "expired", "cancelled", "config_drift"} {
		t.Run(mode, func(t *testing.T) {
			events := []string{}
			transport := bindingResponseTransport()
			p := requestBindingPlanner(t, transport)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a := &budgetRuntimeAuthority{events: &events, permitChange: func(permit *apiserver.SecurityAgentBudgetPermit) {
				switch mode {
				case "reservation":
					permit.Reservation.ReservationID = "other"
				case "input_digest":
					permit.Reservation.InputDigest = "other"
				case "model":
					permit.Reservation.Model = "other/model"
				case "policy":
					permit.Reservation.CostPolicyVersion = "other"
				case "unit":
					permit.Reservation.CostUnit = "usd"
				case "tokens":
					permit.Reservation.MaximumTokens++
				case "cost":
					permit.Reservation.MaximumCostNanoCredits++
				case "version":
					permit.Version--
				case "version_range":
					permit.Version = 1000001
				case "expired":
					permit.ExpiresAt = time.Now().Add(-time.Second)
				case "cancelled":
					cancel()
				case "config_drift":
					p.mu.Lock()
					p.model = "other/model"
					p.mu.Unlock()
				}
			}}
			processor := &securityAgentProcessor{config: securityAgentProcessorConfig{Authority: a, Planner: &budgetFixturePlanner{p}}}
			_, err := processor.planWithBudget(ctx, apiserver.SecurityAgentRunClaim{RunID: "test-run", Attempt: 1, Version: 3}, "lease", "canonical-digest", testSecurityAgentPlannerContext())
			want := []string{"reserve"}
			if mode == "config_drift" {
				want = append(want, "settle")
			}
			if err == nil || transport.calls != 0 || !reflect.DeepEqual(events, want) {
				t.Fatalf("invalid permit sent: err=%v calls=%d events=%v", err, transport.calls, events)
			}
		})
	}
}

func TestSecurityAgentPreparedPlanDoesNotHoldPlannerLockDuringSend(t *testing.T) {
	transport := bindingResponseTransport()
	var p *productionSecurityAgentPlanner
	p = requestBindingPlanner(t, &plannerMutationTransport{transport: transport, mutate: func() { _ = p.Close() }})
	prepared, err := p.Prepare(context.Background(), testSecurityAgentPlannerContext())
	if err != nil {
		t.Fatal(err)
	}
	result := prepared.Dispatch(context.Background())
	if result.Failure != "" || transport.calls != 1 {
		t.Fatalf("in-flight request lost: %+v calls=%d", result, transport.calls)
	}
}
