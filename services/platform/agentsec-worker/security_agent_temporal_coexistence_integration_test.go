package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/sdk/client"
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
)

func runShippedTemporalCoexistence(t *testing.T, ctx context.Context, owner *pgx.Conn, binding securityAgentMultistepPricingBinding, namespace, queue string, c client.Client, planner *productionSecurityAgentPlanner, runner *productionRedTeamRunner, store artifactstore.ObjectReferencingArtifactStore, private ed25519.PrivateKey, providers, runners *atomic.Int32) {
	t.Helper()
	cfg := validSecurityAgentRuntimeConfig()
	dsn := func(user string) string {
		v := owner.Config()
		return (&url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(v.Host, strconv.Itoa(int(v.Port))), Path: "/" + v.Database, RawQuery: "sslmode=disable"}).String()
	}
	cfg.PostgresDSN = dsn("security_agent_v33_worker_login")
	cfg.TemporalExecutorDSN = dsn("temporal_executor_test_login")
	cfg.TemporalCompensationDSN = dsn("temporal_compensation_test_login")
	root := t.TempDir()
	write := func(name string, body []byte) string {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, body, 0400); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg.GatewaySigningKeyID = "p3c-current-key"
	cfg.GatewaySigningPrivateFile = write("signing", []byte(base64.RawURLEncoding.EncodeToString(private)))
	raw, _ := json.Marshal([]securityAgentMultistepPricingBinding{binding})
	cfg.TemporalPricingBindingsFile = write("pricing", raw)
	fga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controlled-fga-token" || r.URL.Path != "/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models/01ARZ3NDEKTSV4RRFFQ69G5FAW" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer fga.Close()
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: "127.0.0.1:7233", Namespace: namespace, TaskQueue: queue, DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: write("fga-token", []byte("controlled-fga-token")), Timeout: 10 * time.Second}
	if !validWorkerRuntimeConfig(cfg) {
		t.Fatal("owned runtime config rejected")
	}
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
		t.Fatal("shipped installed startup", err)
	}
	defer func() {
		if err := deps.Close(); err != nil {
			t.Error("shipped shutdown", err)
		}
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("shipped installed readiness", err)
	}
	manualTick := shippedManualRuntime(t, ctx, owner, dsn, runner, store)
	run := os.Getenv("ZASP_TEMPORAL_PARENT")
	ref := orchestration.RunRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, RunID: run}
	id, _ := orchestration.WorkflowID(ref)
	if err := deps.Processor.RunOnce(ctx); err != nil {
		t.Fatal("shipped nonempty first poll", err)
	}
	var manualState, manualReason string
	if err := owner.QueryRow(ctx, `SELECT state,coalesce(last_error_code,'') FROM zasp_security_agent_runs WHERE run_id=$1`, os.Getenv("ZASP_P3C_MANUAL_PARENT")).Scan(&manualState, &manualReason); err != nil {
		t.Fatal(err)
	}
	t.Log("manual first poll state", manualState, "reason", manualReason)
	var diagnostic string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('eligible',r.available_at<=clock_timestamp(),'owner',(SELECT execution_owner FROM zasp_temporal66.run_owners WHERE run_id=r.run_id),'attempt',r.attempt,'webhook',(SELECT count(*) FROM zasp_security_agent_webhook_deliveries WHERE run_id=r.run_id),'budgets',(SELECT jsonb_agg(jsonb_build_object('state',rr.state,'limit',b.concurrency_limit,'stop',b.stop_reason)) FROM zasp_security_agent_run_budgets b JOIN zasp_security_agent_runs rr USING(organization_id,workspace_id,environment_id,run_id) WHERE b.organization_id=r.organization_id))::text FROM zasp_security_agent_runs r WHERE run_id=$1`, os.Getenv("ZASP_P3C_MANUAL_PARENT")).Scan(&diagnostic); err != nil {
		t.Fatal(err)
	}
	t.Log("manual eligibility", diagnostic)
	done := make(chan error, 1)
	go func() { done <- c.GetWorkflow(ctx, id, "").Get(ctx, nil) }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("shipped Temporal completion", err)
			}
			var state string
			if err := owner.QueryRow(ctx, `SELECT state,coalesce(last_error_code,'') FROM zasp_security_agent_runs WHERE run_id=$1`, os.Getenv("ZASP_P3C_MANUAL_PARENT")).Scan(&state, &manualReason); err != nil {
				t.Fatal(err)
			}
			if providers.Load() != 2 || runners.Load() != 2 {
				t.Fatal("coexistence providers", providers.Load(), runners.Load(), "manual state", state, "reason", manualReason)
			}
			if state != "remediated" && state != "needs_human" {
				t.Fatal("manual terminal receipt missing", state)
			}
			if err := deps.Close(); err != nil {
				t.Fatal("shipped joined shutdown", err)
			}
			if deps.Ready(context.Background()) == nil {
				t.Fatal("closed shipped worker ready")
			}
			var digest string
			if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start'`, run).Scan(&digest); err != nil {
				t.Fatal(err)
			}
			assertTemporalRetainedHistory(t, ctx, c, id, orchestration.StartRequest{Ref: ref, DefinitionVersion: 2, InputDigest: digest})
			return
		case <-ticker.C:
			if err := deps.Processor.RunOnce(ctx); err != nil {
				t.Fatal("shipped coexistence poll", err)
			}
			manualTick()
		case <-ctx.Done():
			t.Fatal("shipped coexistence deadline", ctx.Err())
		}
	}
}

func shippedManualRuntime(t *testing.T, ctx context.Context, owner *pgx.Conn, dsn func(string) string, runner *productionRedTeamRunner, store artifactstore.ObjectReferencingArtifactStore) func() {
	t.Helper()
	db := func(user string) *apiserver.PostgresJSONDatabase {
		pool, err := pgxpool.New(ctx, dsn(user))
		if err != nil {
			t.Fatal(err)
		}
		result, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
		if err != nil {
			pool.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { result.Close() })
		return result
	}
	queue := &shippedManualQueue{owner: owner, parent: os.Getenv("ZASP_P3C_MANUAL_PARENT")}
	redCfg := validRedTeamRuntimeConfig()
	redCfg.PostgresDSN = dsn("ordered_test_red_worker")
	red, err := composeRedTeamWorkerRuntime(redCfg, db("ordered_test_red_worker"), &productionRedTeamDependencies{Queue: queue, Runner: runner, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error { return nil }})
	if err != nil || red.Ready(ctx) != nil {
		t.Fatal("installed linked composition", err)
	}
	t.Cleanup(func() {
		if err := red.Close(); err != nil {
			t.Error(err)
		}
	})
	recCfg := loadExistingTestRuntimeFixture(t)
	recCfg.PostgresDSN = dsn("security_agent_v33_worker_login")
	rec, err := composeExistingTestRuntime(recCfg, db("security_agent_v33_worker_login"), existingTestRuntimeDependencies{Artifacts: &existingTestReadOnlyArtifacts{get: store.Get, reference: store.ObjectReference}, Ready: func(ctx context.Context) error { return ctx.Err() }, Close: func() error { return nil }})
	if err != nil || rec.Ready(ctx) != nil {
		t.Fatal("installed reconciler composition", err)
	}
	t.Cleanup(func() {
		if err := rec.Close(); err != nil {
			t.Error(err)
		}
	})
	return func() {
		if err := red.Processor.RunOnce(ctx); err != nil {
			t.Fatal("actual linked execution", err)
		}
		if err := rec.Processor.RunOnce(ctx); err != nil {
			t.Fatal("actual linked reconciliation", err)
		}
	}
}

// Controlled queue transport reads the exact committed product outbox payload.
// It cannot admit children, synthesize completion, or acknowledge SQL outbox.
type shippedManualQueue struct {
	owner  *pgx.Conn
	parent string
	acked  bool
}

func (q *shippedManualQueue) ConsumeBatch(ctx context.Context, _ int) ([]jobqueue.Delivery, error) {
	if q.acked {
		return nil, nil
	}
	var raw []byte
	err := q.owner.QueryRow(ctx, `SELECT b.payload FROM zasp_red_team_outbox b JOIN zasp_security_agent_test_links l ON b.payload->>'run_id'=l.test_run_id WHERE l.run_id=$1`, q.parent).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p redTeamOutboxPayload
	if decodeStrictWorkerJSON(raw, &p) != nil {
		return nil, errWorkerExecution
	}
	ids := make([]domain.ProductID, 4)
	for i, s := range []string{p.OrganizationID, p.WorkspaceID, p.EnvironmentID, p.RunID} {
		v, err := domain.ParseProductID(s)
		if err != nil {
			return nil, err
		}
		ids[i] = v
	}
	scope, err := domain.NewScope(ids[0], ids[1], ids[2])
	if err != nil {
		return nil, err
	}
	digest, err := hex.DecodeString(p.InputDigest)
	if err != nil || len(digest) != 32 {
		return nil, errWorkerExecution
	}
	job := jobqueue.Job{Scope: scope, JobID: ids[3], Kind: "red-team", Payload: raw}
	copy(job.AuthorityDigest[:], digest)
	return []jobqueue.Delivery{{Job: job}}, nil
}
func (q *shippedManualQueue) AcknowledgeBatch(context.Context, []jobqueue.Receipt) error {
	q.acked = true
	return nil
}
func (q *shippedManualQueue) ExtendVisibility(ctx context.Context, _ []jobqueue.Receipt, d time.Duration) error {
	if d < time.Second {
		return errWorkerExecution
	}
	return ctx.Err()
}
