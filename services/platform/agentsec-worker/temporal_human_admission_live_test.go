package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/protobuf/types/known/durationpb"
)

func runHumanAdmissionLiveRuntime(t *testing.T, ctx context.Context, owner *pgx.Conn, binding securityAgentMultistepPricingBinding, planner *productionSecurityAgentPlanner, store artifactstore.ObjectReferencingArtifactStore, parent string, providerCalls *atomic.Int32) {
	t.Helper()
	t.Setenv("ZASP_TEST74_NATIVE", "true")
	t.Setenv("ZASP_TEST74_UNSAFE", "true")
	t.Setenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN", owner.Config().ConnString())
	t.Setenv("ZASP_ORDERED_ORG", binding.OrganizationID)
	t.Setenv("ZASP_ORDERED_WORKSPACE", binding.WorkspaceID)
	t.Setenv("ZASP_ORDERED_ENVIRONMENT", binding.EnvironmentID)
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	namespace := fmt.Sprintf("human-admission76-%d", time.Now().UnixNano())
	nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal(err)
	}
	err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
	nc.Close()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cfg := validSecurityAgentRuntimeConfig()
	dsn := func(user string) string {
		v := owner.Config()
		return (&url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(v.Host, strconv.Itoa(int(v.Port))), Path: "/" + v.Database, RawQuery: "sslmode=disable"}).String()
	}
	cfg.PostgresDSN = dsn("security_agent_v33_worker_login")
	cfg.TemporalExecutorDSN = dsn("temporal_test_executor_login")
	cfg.TemporalCompensationDSN = dsn("temporal_test_compensation_login")
	root := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(root, name)
		if os.WriteFile(p, b, 0400) != nil {
			t.Fatal("fixture file")
		}
		return p
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.GatewaySigningKeyID = "selector75-key"
	cfg.GatewaySigningPrivateFile = write("key", []byte(base64.RawURLEncoding.EncodeToString(key)))
	pricing, _ := json.Marshal([]securityAgentMultistepPricingBinding{binding})
	cfg.TemporalPricingBindingsFile = write("pricing", pricing)
	fga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controlled-fga-token" || r.URL.Path != "/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models/01ARZ3NDEKTSV4RRFFQ69G5FAW" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer fga.Close()
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: namespace, TaskQueue: namespace + "-tests", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: write("token", []byte("controlled-fga-token")), Timeout: 10 * time.Second}
	ref := orchestration.TestSelectorRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, DefinitionID: os.Getenv("ZASP_TEST76_DEFINITION")}
	external := workerExternalIO{planner: func(workerRuntimeConfig) (*productionSecurityAgentPlanner, error) {
		planner.mu.RLock()
		transport := planner.client.Transport
		planner.mu.RUnlock()
		return newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: cfg.SecurityAgentPlannerEndpoint, Model: cfg.SecurityAgentPlannerModel, Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: cfg.SecurityAgentPlannerPolicy, Transport: transport})
	}, temporal: func(workerRuntimeConfig) (temporalExecutionIO, error) {
		return temporalExecutionIO{runner: runner, store: store, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error { return nil }}, nil
	}}
	deps, err := buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("actual76 worker composition", err)
	}
	defer func() {
		started := time.Now()
		if err := deps.Close(); err != nil {
			t.Error("worker close", err)
		}
		t.Log("first worker Close elapsed", time.Since(started))
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("actual76 readiness", err)
	}

	selectorID, err := orchestration.TestSelectorID(ref)
	if err != nil {
		t.Fatal(err)
	}
	defer c.ScheduleClient().GetHandle(ctx, selectorID).Delete(context.Background())
	deadline := time.Now().Add(60 * time.Second)
	for passes := 1; ; passes++ {
		if err := deps.Processor.RunOnce(ctx); err != nil {
			t.Fatal("actual human delivery", err)
		}
		var accepted bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries WHERE run_id=$1 AND accepted_at IS NOT NULL)`, parent).Scan(&accepted); err != nil {
			t.Fatal(err)
		}
		if accepted {
			t.Log("human delivery accepted after passes", passes)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("human committed start not delivered")
		}
		time.Sleep(100 * time.Millisecond)
	}
	workflowID, _ := orchestration.SingleTestWorkflowID(orchestration.RunRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, RunID: parent})
	if err := c.GetWorkflow(ctx, workflowID, "").Get(ctx, nil); err != nil {
		t.Fatal("human specialized execution", err)
	}
	var proof bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts p JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal76.admissions a USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1 AND x.source_kind='resource65' AND a.source_kind='resource65' AND a.requester_id=r.requested_by AND r.completed_at IS NOT NULL AND r.lease_owner IS NULL AND r.lease_token IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions s WHERE s.run_id=r.run_id))`, parent).Scan(&proof); err != nil || !proof || providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		t.Fatal("human child/parent proof", proof, err, providerCalls.Load(), runnerCalls.Load())
	}
	t.Log("actual human HTTP ->76 atomic marker/65 start -> production worker/Temporal -> controlled HTTPS/native adapter -> child and parent receipts", namespace, parent)
}
