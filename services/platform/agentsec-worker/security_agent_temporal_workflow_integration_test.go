package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"github.com/zasp-ai/zasp-sec/services/platform/redteamadapter"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestTemporalOwnedWorkflow(t *testing.T) {
	dsn := os.Getenv("ZASP_TEMPORAL_JOURNAL_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned69 database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(cfg.Host) == nil || !net.ParseIP(cfg.Host).IsLoopback() {
		t.Fatal("owned loopback required")
	}
	for _, f := range cfg.Fallbacks {
		if net.ParseIP(f.Host) == nil || !net.ParseIP(f.Host).IsLoopback() {
			t.Fatal("foreign fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	var binding securityAgentMultistepPricingBinding
	if decodeStrictWorkerJSON([]byte(os.Getenv("ZASP_TEMPORAL_PLANNER_BINDING")), &binding) != nil {
		t.Fatal("binding")
	}
	run := os.Getenv("ZASP_TEMPORAL_PARENT")
	var providerCalls atomic.Int32
	candidate := `{"version":1,"summary":"Contain and retest","steps":[{"index":0,"action":"create_temporary_policy","target_id":"` + binding.EnvironmentID + `"},{"index":1,"action":"run_test","target_id":"` + os.Getenv("ZASP_TEMPORAL_TEST_ID") + `"}]}`
	var fields map[string]json.RawMessage
	json.Unmarshal(openRouterPlannerResponse(candidate), &fields)
	fields["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
	response, _ := json.Marshal(fields)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if os.Getenv("ZASP_P3C_SHIPPED_COEXISTENCE") == "true" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
			if strings.Contains(string(body), `manual_trigger`) {
				manual := `{"version":1,"summary":"Run the existing test","steps":[{"index":0,"action":"run_test","target_id":"` + os.Getenv("ZASP_TEMPORAL_TEST_ID") + `"}]}`
				var envelope map[string]json.RawMessage
				json.Unmarshal(openRouterPlannerResponse(manual), &envelope)
				envelope["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
				body, _ := json.Marshal(envelope)
				w.Write(body)
				return
			}
		}
		w.Write(response)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	httpClient := server.Client()
	defer httpClient.CloseIdleConnections()
	planner := orderedRequestBindingPlanner(t, &release61TLSTransport{base: httpClient.Transport, target: target})
	defer planner.Close()
	store, err := artifactstore.New(&release61ArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"p3c-current-key": public})
	if err != nil {
		t.Fatal(err)
	}
	openDB := func(user string) *apiserver.PostgresJSONDatabase {
		pc, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal("pool config")
		}
		pc.ConnConfig.User = user
		pc.MaxConns = 3
		pool, err := pgxpool.NewWithConfig(ctx, pc)
		if err != nil {
			t.Fatal("pool")
		}
		db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
		if err != nil {
			pool.Close()
			t.Fatal(err)
		}
		return db
	}
	executor, compensation, relayDB := openDB("temporal_executor_test_login"), openDB("temporal_compensation_test_login"), openDB("security_agent_v33_worker_login")
	defer relayDB.Close()
	p := &temporalSecurityAgentProduct{executor: executor, compensation: compensation, planner: planner, runner: runner, store: store, bindings: []securityAgentMultistepPricingBinding{binding}, signing: func() (string, ed25519.PrivateKey, policy.GatewayPolicyKeys, error) {
		return "p3c-current-key", private, keys, nil
	}, workerID: "p3c-local-worker"}
	cancelStage := os.Getenv("ZASP_P3C_RAW_CANCEL")
	if cancelStage == "reserved" {
		p.executor = &temporalCancelBeforeDispatchDB{JSONDatabase: executor}
	}
	ready := func(ctx context.Context) error {
		for i, db := range []*apiserver.PostgresJSONDatabase{executor, compensation} {
			raw, err := db.QueryJSON(ctx, `SELECT to_jsonb(zasp_temporal69.ready($1,$2) AND zasp_temporal69.principal_ready($3))`, migrations.ProductionTemporalWorkflow().Checksum(), migrations.TemporalWorkflowFingerprint(), []string{"zasp_temporal_executor", "zasp_temporal_compensation"}[i])
			if err != nil || string(raw) != "true" {
				return errRuntimeUnavailable
			}
		}
		return nil
	}
	namespace := fmt.Sprintf("p3c-owned-%d", time.Now().UnixNano())
	nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal("local Temporal unavailable", err)
	}
	if err := nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: "P3C controlled local worker integration, owned namespace", WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)}); err != nil {
		nc.Close()
		t.Fatal("owned namespace", err)
	}
	nc.Close()
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal("Temporal connect", err)
	}
	defer c.Close()
	info, err := c.WorkflowService().GetSystemInfo(ctx, &workflowservice.GetSystemInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("local Temporal server", info.ServerVersion, "namespace", namespace)
	queue := namespace + "-security-agent"
	if os.Getenv("ZASP_P3C_SHIPPED_COEXISTENCE") == "true" {
		executor.Close()
		compensation.Close()
		runShippedTemporalCoexistence(t, ctx, owner, binding, namespace, queue, c, planner, runner, store, private, &providerCalls, runnerCalls)
		return
	}
	runtime, err := newTemporalSecurityAgentWorker(c, queue, p, ready, func() error { executor.Close(); compensation.Close(); return nil }, 5*time.Second, 2)
	if err != nil {
		executor.Close()
		compensation.Close()
		t.Fatal("real worker startup", err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error("worker drain", err)
		}
	}()
	engine, err := orchestration.NewTemporalEngine(c, queue, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	retained := retainedTemporalEngine{engine: engine, product: p}
	relay := orchestration.Relay{Store: orchestration.SQLStore{Database: relayDB, Timeout: 10 * time.Second}, Engine: retained}
	var digest string
	if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start'`, run).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	request := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, RunID: run}, DefinitionVersion: 2, InputDigest: digest}
	id, _ := orchestration.WorkflowID(request.Ref)
	if err := relay.RunOnce(ctx); err != nil {
		t.Fatal("outbox initial delivery", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.GetWorkflow(ctx, id, "").Get(ctx, nil) }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	cancelMode := cancelStage != ""
	cancelled := false
	for {
		select {
		case err := <-done:
			if !cancelMode && err != nil || cancelMode && (!cancelled || !temporal.IsCanceledError(err)) {
				t.Fatal("workflow completion", err)
			}
			wantRunner := int32(1)
			if cancelMode {
				wantRunner = 0
			}
			if providerCalls.Load() != 1 || runnerCalls.Load() != wantRunner {
				t.Fatal("duplicate or missing providers", providerCalls.Load(), runnerCalls.Load())
			}
			if err := retained.Start(ctx, request); err != nil {
				t.Fatal("retained start replay", err)
			}
			if err := relay.RunOnce(ctx); err != nil {
				t.Fatal("late retained messages", err)
			}
			state, err := p.inspect(ctx, request, executor)
			if err != nil || !state.Terminal || state.CleanupRequired {
				t.Fatal("verified terminal cleanup", state.RunState, state.CleanupRequired, err)
			}
			assertTemporalRetainedHistory(t, ctx, c, id, request)
			// Product retention is authoritative even when engine history is absent.
			offline := &temporalUnavailableEngine{}
			retained.engine = offline
			if err := retained.Start(ctx, request); err != nil {
				t.Fatal("offline retained start", err)
			}
			var m orchestration.Message
			m.Ref = request.Ref
			if err := owner.QueryRow(ctx, `SELECT event_id,decision_id,kind FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='approval' ORDER BY created_at LIMIT 1`, run).Scan(&m.EventID, &m.DecisionID, &m.Kind); err != nil {
				t.Fatal("retained decision", err)
			}
			if err := retained.Notify(ctx, m); err != nil {
				t.Fatal("offline retained decision", err)
			}
			m.DecisionID = request.Ref.RunID
			if err := retained.Notify(ctx, m); err == nil {
				t.Fatal("foreign retained decision accepted")
			}
			if offline.calls != 0 {
				t.Fatal("retained product outcome consulted missing engine history")
			}
			t.Log("real registered worker completed; planner_calls", providerCalls.Load(), "runner_calls", runnerCalls.Load(), "raw_cancel", cancelMode, "receipt-bound effects and signed cleanup; retained start did not resend")
			return
		case <-ticker.C:
			if cancelMode && !cancelled {
				v, err := p.inspect(ctx, request, executor)
				if err != nil {
					t.Fatal("cancel observation", err)
				}
				cancelNow := v.Admitted && v.Projection.Steps[0].State == "succeeded"
				if cancelStage == "reserved" {
					cancelNow = false
					for _, effect := range v.Effects {
						if effect.Action == "run_test" && effect.State == "reserved" {
							cancelNow = true
						}
					}
				}
				if cancelNow {
					if err := c.CancelWorkflow(ctx, id, ""); err != nil {
						t.Fatal("raw SDK cancel", err)
					}
					cancelled = true
				}
			}
			if err := relay.RunOnce(ctx); err != nil {
				t.Fatal("committed decision relay", err)
			}
		case <-ctx.Done():
			t.Fatal("actual workflow deadline", ctx.Err())
		}
	}
}

type temporalUnavailableEngine struct{ calls int }

func (e *temporalUnavailableEngine) Start(context.Context, orchestration.StartRequest) error {
	e.calls++
	return orchestration.ErrUnavailable
}
func (e *temporalUnavailableEngine) Notify(context.Context, orchestration.Message) error {
	e.calls++
	return orchestration.ErrUnavailable
}

func assertTemporalRetainedHistory(t *testing.T, ctx context.Context, c client.Client, id string, want orchestration.StartRequest) {
	t.Helper()
	it := c.GetWorkflowHistory(ctx, id, "", false, enums.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	scheduled := 0
	for it.HasNext() {
		event, err := it.Next()
		if err != nil {
			t.Fatal("history", err)
		}
		checkStart := func(raw []byte) {
			var got orchestration.StartRequest
			if len(raw) > 2048 || decodeStrictWorkerJSON(raw, &got) != nil || got != want {
				t.Fatal("history contains non-scoped activity input")
			}
		}
		if started := event.GetWorkflowExecutionStartedEventAttributes(); started != nil {
			if len(started.Input.Payloads) != 1 {
				t.Fatal("workflow history input count")
			}
			checkStart(started.Input.Payloads[0].Data)
		}
		if activity := event.GetActivityTaskScheduledEventAttributes(); activity != nil {
			scheduled++
			if len(activity.Input.Payloads) != 1 {
				t.Fatal("activity history input count")
			}
			raw := activity.Input.Payloads[0].Data
			if activity.ActivityType.Name == "Cleanup" {
				var got orchestration.CleanupRequest
				if len(raw) > 2048 || decodeStrictWorkerJSON(raw, &got) != nil || got.Start != want || (got.Reason != "terminal" && got.Reason != "workflow_cancelled") {
					t.Fatal("cleanup history contains non-scoped input")
				}
			} else {
				checkStart(raw)
			}
		}
		if completed := event.GetActivityTaskCompletedEventAttributes(); completed != nil && completed.Result != nil {
			for _, payload := range completed.Result.Payloads {
				var got orchestration.RunState
				if len(payload.Data) > 128 || decodeStrictWorkerJSON(payload.Data, &got) != nil || got.Phase == "" {
					t.Fatal("history contains product body instead of redacted phase")
				}
			}
		}
		if signaled := event.GetWorkflowExecutionSignaledEventAttributes(); signaled != nil {
			if len(signaled.Input.Payloads) != 1 {
				t.Fatal("signal history input count")
			}
			var got orchestration.Message
			if decodeStrictWorkerJSON(signaled.Input.Payloads[0].Data, &got) != nil || got.Ref != want.Ref || (got.Kind != "approval" && got.Kind != "cancel") {
				t.Fatal("signal history contains unscoped command")
			}
		}
	}
	if scheduled < 5 {
		t.Fatal("missing real activity history")
	}
}

// Controlled failure point after durable effect reservation, before input or
// dispatch. The actual SDK cancellation cancels this outstanding SQL boundary.
type temporalCancelBeforeDispatchDB struct{ apiserver.JSONDatabase }

func (d *temporalCancelBeforeDispatchDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if strings.Contains(q, "zasp_temporal68.linked(") {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.JSONDatabase.QueryJSON(ctx, q, args...)
}

func temporalWorkflowFixtureRunner(t *testing.T, owner *pgx.Conn, store artifactstore.ObjectReferencingArtifactStore) (*productionRedTeamRunner, *atomic.Int32) {
	t.Helper()
	root := t.TempDir()
	token := filepath.Join(root, "token")
	if err := os.WriteFile(token, []byte(strings.Repeat("t", 64)), 0400); err != nil {
		t.Fatal(err)
	}
	calls := new(atomic.Int32)
	command := redTeamCommandFunc(func(ctx context.Context, executable string, args, env []string, dir string) (result error) {
		automaticRawCommandMarker(t, ctx, "command/enter", nil)
		defer func() { automaticRawCommandMarker(t, ctx, "command/exit", result) }()
		observationsDB, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			return err
		}
		defer observationsDB.Close(context.Background())
		calls.Add(1)
		var key, lease string
		for _, v := range env {
			if strings.HasPrefix(v, "ZASP_RED_TEAM_RUN_LEASE=") {
				lease = strings.TrimPrefix(v, "ZASP_RED_TEAM_RUN_LEASE=")
			}
			if strings.HasPrefix(v, "ZASP_RED_TEAM_EFFECT_KEY=") {
				key = strings.TrimPrefix(v, "ZASP_RED_TEAM_EFFECT_KEY=")
			}
		}
		manual := os.Getenv("ZASP_P3C_SHIPPED_COEXISTENCE") == "true" && len(lease) == 32 && key == ""
		if (!manual && (!redteamadapter.ValidEffectKey(key) || lease != "")) || executable != "/usr/local/bin/node" || len(args) != 4 {
			return errWorkerExecution
		}
		body, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var input redTeamRunnerInput
		if decodeStrictWorkerJSON(body, &input) != nil {
			return errWorkerExecution
		}
		observations := map[string]redteamadapter.LinkedObservationResponse{}
		for _, category := range input.Categories {
			child := exec.CommandContext(ctx, "go", "test", "./redteamadapter", "-run", "^TestTemporalOwnedHTTPS$", "-count=1", "-v")
			child.Dir = ".."
			child.WaitDelay = 5 * time.Second
			child.Env = append(os.Environ(), "ZASP_TEMPORAL_JOURNAL_MODE=success", "ZASP_ORDERED_TEST_RUN="+input.RunID, "ZASP_TEMPORAL_EFFECT_KEY="+key, "ZASP_TEMPORAL_CATEGORY="+category, "ZASP_TEMPORAL_TARGET="+input.TargetID, "ZASP_TEMPORAL_KIND="+input.TargetKind)
			if manual {
				child.Env = append(child.Env, "ZASP_P3C_LEGACY_LINKED=true", "ZASP_P3C_LEGACY_LEASE="+lease)
			}
			automaticRawCommandMarker(t, ctx, "child/enter", nil)
			output, err := child.CombinedOutput()
			automaticRawCommandMarker(t, ctx, "child/exit", err)
			t.Log(string(output))
			if err != nil || !strings.Contains(string(output), "provider_calls=1 credential_reads=1") || strings.Contains(string(output), "--- SKIP:") {
				return errWorkerExecution
			}
			var raw []byte
			query := `SELECT jsonb_build_object('schema_version','red-team-linked-observation-v1','run_id',test_run_id,'category',category,'target_comparison',target_resolution->'comparison','credential_version_digest',encode(credential_version_digest,'hex'),'observation',jsonb_build_object('http_status',http_status,'response_digest',encode(response_digest,'hex'),'protected',protected)) FROM zasp_temporal68.invocations WHERE effect_key=$1 AND category=$2 AND state='completed'`
			lookup := key
			if manual {
				query = strings.Replace(query, "zasp_temporal68.invocations WHERE effect_key=", "zasp_security_agent_test_invocations WHERE test_run_id=", 1)
				lookup = input.RunID
			} else if os.Getenv("ZASP_TEST74_NATIVE") == "true" {
				query = strings.Replace(query, "zasp_temporal68.invocations", "zasp_temporal74.invocations", 1)
			}
			if err := observationsDB.QueryRow(ctx, query, lookup, category).Scan(&raw); err != nil {
				return err
			}
			var observed redteamadapter.LinkedObservationResponse
			if json.Unmarshal(raw, &observed) != nil {
				return errWorkerExecution
			}
			observations[category] = observed
		}
		return temporalControlledRunnerOutput(input, observations, dir, args[3])
	})
	runner, err := newProductionRedTeamRunner(productionRedTeamRunnerConfig{RunnerImage: "registry.example/zasp-red-team@sha256:" + strings.Repeat("a", 64), Artifacts: store, Command: command, NodePath: "/usr/local/bin/node", ScriptPath: "/app/redteam-runner.mjs", PromptfooPath: "/app/dist/src/entrypoint.js", TargetEndpoint: "https://agentsec-red-team-adapter.platform.svc.cluster.local/v1/evaluate", TargetTokenFile: token, TargetCAFile: writeRedTeamTestCA(t, root), TempRoot: root, Timeout: 60 * time.Second, Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	return runner, calls
}
