package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

func runAutomaticSourceLiveRuntime(t *testing.T, ctx context.Context, owner *pgx.Conn, binding securityAgentMultistepPricingBinding, planner *productionSecurityAgentPlanner, store artifactstore.ObjectReferencingArtifactStore, parent string, providerCalls *atomic.Int32) {
	t.Helper()
	t.Setenv("ZASP_TEST74_NATIVE", "true")
	t.Setenv("ZASP_TEST74_UNSAFE", "true")
	t.Setenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN", owner.Config().ConnString())
	t.Setenv("ZASP_ORDERED_ORG", binding.OrganizationID)
	t.Setenv("ZASP_ORDERED_WORKSPACE", binding.WorkspaceID)
	t.Setenv("ZASP_ORDERED_ENVIRONMENT", binding.EnvironmentID)
	store = automaticFirstErrorStore{ObjectReferencingArtifactStore: store, t: t}
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	namespace := os.Getenv("ZASP_TEST77_NAMESPACE")
	address := os.Getenv("ZASP_TEST77_ADDRESS")
	c, err := client.Dial(client.Options{HostPort: address, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if os.Getenv("ZASP_TEST77_PHASE") == "ambiguous-start" {
		runAutomaticAmbiguousProcess(t, ctx, owner, c, binding, namespace+"-tests")
		return
	}
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
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: address, Namespace: namespace, TaskQueue: namespace + "-tests", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: write("token", []byte("controlled-fga-token")), Timeout: 10 * time.Second}
	ref := orchestration.TestSelectorRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, DefinitionID: os.Getenv("ZASP_TEST77_DEFINITION")}
	external := workerExternalIO{planner: func(workerRuntimeConfig) (*productionSecurityAgentPlanner, error) {
		planner.mu.RLock()
		transport := planner.client.Transport
		planner.mu.RUnlock()
		return newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: cfg.SecurityAgentPlannerEndpoint, Model: cfg.SecurityAgentPlannerModel, Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: cfg.SecurityAgentPlannerPolicy, Transport: transport})
	}, temporal: func(workerRuntimeConfig) (temporalExecutionIO, error) {
		return temporalExecutionIO{runner: runner, store: store, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error { return nil }}, nil
	}}
	external.temporalDiagnostic = &temporalDiagnosticDecorator{
		driver: func(driver apiserver.PostgresDriver) apiserver.PostgresDriver {
			return automaticRawDriver(driver, func(ctx context.Context, record automaticRawRecord) {
				automaticRawLog(t, ctx, record)
			})
		},
		database: func(db apiserver.JSONDatabase) apiserver.JSONDatabase {
			return automaticFirstErrorDatabase{JSONDatabase: db, t: t}
		},
		singleTest: func(p orchestration.SingleTestProduct) orchestration.SingleTestProduct {
			return automaticFirstErrorProduct{SingleTestProduct: p, t: t}
		},
	}
	deps, err := buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("actual77 worker composition", err)
	}
	defer func() {
		started := time.Now()
		if err := deps.Close(); err != nil {
			t.Error("worker close", err)
		}
		t.Log("first worker Close elapsed", time.Since(started))
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("actual77 readiness", err)
	}

	runAutomaticNativeAssertions(t, ctx, owner, c, deps, ref, parent, providerCalls, runnerCalls)
}

type automaticNativeDB struct{ conn *pgx.Conn }

func (d automaticNativeDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	var raw json.RawMessage
	err := d.conn.QueryRow(ctx, q, args...).Scan(&raw)
	return raw, err
}

type automaticAmbiguousStarter struct {
	starter *orchestration.AutomaticSourceStarter
}

func (s automaticAmbiguousStarter) Start(ctx context.Context, r orchestration.AutomaticSourceRef) error {
	if err := s.starter.Start(ctx, r); err != nil {
		return err
	}
	return orchestration.ErrUnavailable
}

func runAutomaticAmbiguousProcess(t *testing.T, ctx context.Context, owner *pgx.Conn, c client.Client, b securityAgentMultistepPricingBinding, queue string) {
	t.Helper()
	config := owner.Config().Copy()
	config.User = "temporal_test_executor_login"
	executor, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())
	starter, err := orchestration.NewAutomaticSourceStarter(c, queue, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	relay := orchestration.AutomaticSourceRelay{Store: orchestration.AutomaticSourceSQLStore{Database: automaticNativeDB{executor}, Timeout: 10 * time.Second}, Starter: automaticAmbiguousStarter{starter}}
	if err := relay.RunOnce(ctx); !errors.Is(err, orchestration.ErrUnavailable) {
		t.Fatal("controlled post-acceptance interruption", err)
	}
	ref := orchestration.AutomaticSourceRef{OrganizationID: b.OrganizationID, WorkspaceID: b.WorkspaceID, EnvironmentID: b.EnvironmentID, EventID: os.Getenv("ZASP_TEST77_EVENT")}
	id, _ := orchestration.AutomaticSourceWorkflowID(ref)
	description, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil || description.WorkflowExecutionInfo.GetType().GetName() != "AutomaticSourceWorkflow" {
		t.Fatal("first process failed durable native start", description, err)
	}
	var pending bool
	if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal77.source_pending WHERE event_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_acceptances WHERE event_id=$1)`, ref.EventID).Scan(&pending); err != nil || !pending {
		t.Fatal("ambiguous start acknowledged", pending, err)
	}
	t.Log("first owned worker process exits after durable Temporal acceptance with source still pending", id, description.WorkflowExecutionInfo.GetExecution().GetRunId())
}

func runAutomaticNativeAssertions(t *testing.T, ctx context.Context, owner *pgx.Conn, c client.Client, deps workerRuntimeDependencies, ref orchestration.TestSelectorRef, parent string, providerCalls, runnerCalls *atomic.Int32) {
	t.Helper()
	selectorID, _ := orchestration.TestSelectorID(ref)
	handle := c.ScheduleClient().GetHandle(ctx, selectorID)
	defer handle.Delete(context.Background())
	settle := func(run string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for passes := 1; ; passes++ {
			if err := deps.Processor.RunOnce(ctx); err != nil {
				t.Fatal("actual77 production processor", err)
			}
			var accepted bool
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries WHERE run_id=$1 AND accepted_at IS NOT NULL)`, run).Scan(&accepted); err != nil {
				t.Fatal(err)
			}
			if accepted {
				t.Log("automatic execution delivered after passes", passes)
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("automatic product start not delivered", run)
			}
			time.Sleep(100 * time.Millisecond)
		}
		id, _ := orchestration.SingleTestWorkflowID(orchestration.RunRef{OrganizationID: ref.OrganizationID, WorkspaceID: ref.WorkspaceID, EnvironmentID: ref.EnvironmentID, RunID: run})
		if err := c.GetWorkflow(ctx, id, "").Get(ctx, nil); err != nil {
			var phases json.RawMessage
			diagnosticErr := owner.QueryRow(ctx, `SELECT jsonb_build_object('run_state',r.state,'run_error',r.last_error_code,'planning',(SELECT state FROM zasp_temporal74.planning_jobs WHERE run_id=r.run_id),'effect',(SELECT state FROM zasp_temporal74.effects WHERE run_id=r.run_id),'link',(SELECT reconcile_state FROM zasp_security_agent_test_links WHERE run_id=r.run_id),'input_present',EXISTS(SELECT 1 FROM zasp_temporal74.test_inputs WHERE run_id=r.run_id),'invocation_count',(SELECT count(*) FROM zasp_temporal74.invocations WHERE test_run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=r.run_id))) FROM zasp_security_agent_runs r WHERE r.run_id=$1`, run).Scan(&phases)
			t.Log("automatic77 terminal phase diagnostic", run, string(phases), diagnosticErr, "provider_calls", providerCalls.Load(), "native_calls", runnerCalls.Load())
			t.Fatal("actual automatic single-test execution", err)
		}
	}
	settle(parent)
	description, err := handle.Describe(ctx)
	if err != nil {
		t.Fatal("configured Schedule missing", err)
	}
	action, ok := description.Schedule.Action.(*client.ScheduleWorkflowAction)
	if !ok || action.Workflow != "AutomaticCatchupWorkflow" || action.WorkflowExecutionTimeout != 0 || description.Schedule.State.Paused {
		t.Fatal("configured Schedule routed to legacy workflow", description.Schedule)
	}
	for _, event := range []string{os.Getenv("ZASP_TEST77_EVENT"), os.Getenv("ZASP_TEST77_RUNTIME_EVENT")} {
		r := orchestration.AutomaticSourceRef{OrganizationID: ref.OrganizationID, WorkspaceID: ref.WorkspaceID, EnvironmentID: ref.EnvironmentID, EventID: event}
		id, _ := orchestration.AutomaticSourceWorkflowID(r)
		if err := c.GetWorkflow(ctx, id, "").Get(ctx, nil); err != nil {
			t.Fatal("native source dispatcher incomplete", err)
		}
		var accepted bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal77.source_acceptances WHERE event_id=$1 AND workflow_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.source_pending WHERE event_id=$1)`, event, id).Scan(&accepted); err != nil || !accepted {
			t.Fatal("restarted exact native acceptance", accepted, err)
		}
	}
	// Consume the real configured periodic action, even though the occurrence is
	// already admitted by the event workflow. It must replay the same receipt.
	if err := handle.Trigger(ctx, client.ScheduleTriggerOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var catchupID, catchupRun string
	for {
		list, err := c.ListWorkflow(ctx, &workflowservice.ListWorkflowExecutionsRequest{Namespace: os.Getenv("ZASP_TEST77_NAMESPACE"), Query: "WorkflowType = 'AutomaticCatchupWorkflow'"})
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Executions) > 0 {
			catchupID = list.Executions[0].GetExecution().GetWorkflowId()
			catchupRun = list.Executions[0].GetExecution().GetRunId()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("configured catch-up was not registered/consumed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := c.GetWorkflow(ctx, catchupID, catchupRun).Get(ctx, nil); err != nil {
		t.Fatal("native configured catch-up", err)
	}
	history := c.GetWorkflowHistory(ctx, catchupID, catchupRun, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	activitySeen := false
	for history.HasNext() {
		event, err := history.Next()
		if err != nil {
			t.Fatal(err)
		}
		if a := event.GetActivityTaskScheduledEventAttributes(); a != nil && a.GetActivityType().GetName() == "AutomaticCatchupPage" {
			activitySeen = true
			if a.GetStartToCloseTimeout().AsDuration() != 30*time.Second {
				t.Fatal("native Activity budget changed")
			}
		}
	}
	if !activitySeen {
		t.Fatal("catch-up workflow completed without product Activity")
	}
	var count int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal77.occurrences WHERE definition_id=$1 AND disposition='admitted'`, ref.DefinitionID).Scan(&count); err != nil || count != 1 || providerCalls.Load() != 1 || runnerCalls.Load() != 1 {
		t.Fatal("event/periodic duplicate execution", count, err, providerCalls.Load(), runnerCalls.Load())
	}
	// Settle through the actual executor, then create a genuinely later canonical
	// occurrence after the one-second configured cooldown. No deadline fixture edit.
	config := owner.Config().Copy()
	config.User = "security_agent_v33_discovery_api_login"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	for i, status := range []string{"under_review", "open"} {
		var raw json.RawMessage
		id := func(n int) string { return fmt.Sprintf("pid_f0773000-0000-4000-8000-%012d", n) }
		if err := api.QueryRow(ctx, `SELECT zasp_temporal77.risk_mutate('updateFinding',$1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,$10,$11)`, os.Getenv("ZASP_TEST77_FINDING"), ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, os.Getenv("ZASP_TEST77_ACTOR"), "automatic77-native-later-"+status, i+2, status, id(8100+i*3), id(8101+i*3), id(8102+i*3)).Scan(&raw); err != nil {
			t.Fatal("later actual finding writer", err)
		}
	}
	var later string
	if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_run',concat_ws(chr(31),$4::text,4,'finding',$5::text,4))`, ref.OrganizationID, ref.WorkspaceID, ref.EnvironmentID, ref.DefinitionID, os.Getenv("ZASP_TEST77_FINDING")).Scan(&later); err != nil || later == parent {
		t.Fatal("later canonical run", later, err)
	}
	settle(later)
	var proof bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(r.completed_at IS NOT NULL AND r.lease_owner IS NULL AND r.lease_token IS NULL AND r.lease_expires_at IS NULL AND x.source_kind='automatic73') FROM zasp_temporal77.occurrences a JOIN zasp_temporal74.parent_receipts p USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE a.definition_id=$1 AND a.disposition='admitted'`, ref.DefinitionID).Scan(&proof); err != nil || !proof || providerCalls.Load() != 2 || runnerCalls.Load() != 2 {
		t.Fatal("distinct post-settlement occurrence proof", proof, err, providerCalls.Load(), runnerCalls.Load())
	}
	t.Log("second owned worker process recovered native pending start; configured periodic duplicate and later post-expiry occurrence settled", parent, later)
}
