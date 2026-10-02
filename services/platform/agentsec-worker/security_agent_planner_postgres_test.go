package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// The apiserver parent owns/migrates the disposable database and independently
// inspects durable results. Provider transport and its request-cost bound are
// controlled; this is tenant isolation evidence, not live pricing authority.
func TestSecurityAgentPlannerWorkerOwnedPostgres(t *testing.T) {
	dsn := os.Getenv("ZASP_PLANNER_TENANT_TEST_DSN")
	if dsn == "" {
		t.Skip("requires parent-owned planner tenant database")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid owned database configuration")
	}
	local := func(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
	if !local(config.Host) || config.User != "security_agent_v33_worker_login" || config.Database != "postgres" {
		t.Fatal("requires loopback registered planner worker database")
	}
	for _, fallback := range config.Fallbacks {
		if !local(fallback.Host) {
			t.Fatal("nonlocal database fallback refused")
		}
	}
	target := os.Getenv("ZASP_PLANNER_TENANT_TEST_TARGET")
	definition := os.Getenv("ZASP_PLANNER_TENANT_TEST_DEFINITION")
	if !slices.Contains([]string{"pid_9a000020-0000-4000-8000-000000000020", "pid_9a000003-0000-4000-8000-000000000003", "pid_6a000003-0000-4000-8000-000000000003"}, target) || !slices.Contains([]string{"pid_6a000004-0000-4000-8000-000000000004", "pid_6a000030-0000-4000-8000-000000000001", "pid_6a000030-0000-4000-8000-000000000002"}, definition) {
		t.Fatal("unknown parent fixture candidate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	database := combinedE2ERecoveryDatabase(t, ctx, dsn)
	authority, err := apiserver.NewSecurityAgentWorkerRepository(database)
	if err != nil {
		t.Fatal("registered planner authority unavailable", err)
	}
	if err := authority.Ready(ctx); err != nil {
		t.Fatal("registered release planner not ready", err)
	}
	transport := &securityAgentPlannerTransport{responseBody: openRouterPlannerResponse(`{"version":1,"summary":"Apply bounded containment","steps":[{"index":0,"action":"create_temporary_policy","target_id":"` + target + `"}]}`)}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(transport.responseBody, &response); err != nil {
		t.Fatal(err)
	}
	response["usage"] = json.RawMessage(`{"prompt_tokens":120,"completion_tokens":40,"total_tokens":160,"cost":0.0000001}`)
	transport.responseBody, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := newSecurityAgentPlanner(securityAgentPlannerConfig{
		Endpoint: "https://openrouter.ai/api/v1/chat/completions", Model: "openai/gpt-5-mini", Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: "security-agent-planner-v1", Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = planner.Close() })
	processor, err := newSecurityAgentProcessor(securityAgentProcessorConfig{
		Authority: authority, Planner: &budgetFixturePlanner{planner}, WorkerID: "security-agent-tenant-worker", LeaseSeconds: 60, BatchSize: 1, HeartbeatInterval: time.Second,
		Now:           func() time.Time { return time.Now().UTC() },
		NewLeaseToken: func() (string, error) { return strings.Repeat("tenant-lease-", 3), nil },
		NewProductID:  func() (string, error) { id, err := domain.NewProductID(); return id.String(), err },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatal("actual processor failed", err)
	}
	if transport.calls != 1 || transport.request == nil {
		t.Fatalf("actual planner provider requests=%d", transport.calls)
	}
	var request struct {
		Messages []struct{ Role, Content string } `json:"messages"`
	}
	if err := json.Unmarshal(transport.requestBody, &request); err != nil || len(request.Messages) != 2 || request.Messages[1].Role != "user" {
		t.Fatal("planner request omitted scoped context", err)
	}
	var scoped struct {
		Scope          map[string]string `json:"scope"`
		AllowedTargets []string          `json:"allowed_targets"`
		AllowedActions []string          `json:"allowed_actions"`
	}
	if err := json.Unmarshal([]byte(request.Messages[1].Content), &scoped); err != nil || scoped.Scope["organization_id"] != "pid_6a000001-0000-4000-8000-000000000001" || scoped.Scope["definition_id"] != definition || !slices.Equal(scoped.AllowedTargets, []string{"pid_6a000003-0000-4000-8000-000000000003"}) || !slices.Equal(scoped.AllowedActions, []string{"create_temporary_policy"}) {
		t.Fatalf("planner received unexpected scoped authority: %+v err=%v", scoped, err)
	}
	t.Log("actual planner and processor completed one scoped database run")
}
