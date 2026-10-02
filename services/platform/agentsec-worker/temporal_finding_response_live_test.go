package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
)

type findingArtifactDriver struct{ temporalPlannerArtifactDriver }

// Test-only observers keep the constructor's delegates, order and deadlines.
// Only static operation labels, error codes and durations leave this boundary.
type findingNativeObservedDB struct {
	apiserver.JSONDatabase
	t *testing.T
}

func (d findingNativeObservedDB) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	raw, err := d.JSONDatabase.QueryJSON(ctx, q, args...)
	if err != nil {
		label := "other"
		for _, candidate := range []string{"zasp_temporal77.pending_sources", "zasp_temporal77.accept_source", "zasp_temporal77.dispatch_page", "zasp_temporal78.pending_controls", "zasp_temporal78.pending", "zasp_temporal78.accept_start", "zasp_temporal78.inspect", "zasp_temporal78.planning_context"} {
			if strings.Contains(q, candidate+"(") {
				label = candidate
				break
			}
		}
		code := "classified"
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			code = pg.Code
		}
		d.t.Log("finding SQL failure", label, "sqlstate", code, "deadline", errors.Is(err, context.DeadlineExceeded))
	}
	return raw, err
}

type findingNativeObservedProcessor struct {
	delegate workerProcessor
	t        *testing.T
}

func (p findingNativeObservedProcessor) RunOnce(ctx context.Context) error {
	started := time.Now()
	err := p.delegate.RunOnce(ctx)
	if err != nil {
		p.t.Log("finding processor failure", fmt.Sprintf("%T", p.delegate), "elapsed", time.Since(started), "deadline", errors.Is(err, context.DeadlineExceeded))
	}
	return err
}
func observeFindingNativeProcessor(t *testing.T, p workerProcessor) workerProcessor {
	if composite, ok := p.(temporalOutboxProcessor); ok {
		composite.legacy = observeFindingNativeProcessor(t, composite.legacy)
		composite.relay = observeFindingNativeProcessor(t, composite.relay)
		return composite
	}
	if gated, ok := p.(readinessGatedWorkerProcessor); ok {
		original := gated.ready
		gated.ready = func(ctx context.Context) error {
			err := original(ctx)
			if err != nil {
				t.Log("finding retained readiness failed")
			}
			return err
		}
		gated.delegate = observeFindingNativeProcessor(t, gated.delegate)
		return gated
	}
	return findingNativeObservedProcessor{delegate: p, t: t}
}

func findingHistoryHasNote(v any) bool {
	const note = "Investigate the credential exposure"
	switch value := v.(type) {
	case string:
		if strings.Contains(value, note) {
			return true
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		return err == nil && strings.Contains(string(decoded), note)
	case []any:
		for _, item := range value {
			if findingHistoryHasNote(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range value {
			if findingHistoryHasNote(item) {
				return true
			}
		}
	}
	return false
}

func TestFindingResponseHistoryNoteInspection(t *testing.T) {
	// Decode the whole payload. Searching for an encoded substring alone would
	// miss notes whose byte offset changes the Base64 grouping.
	for _, prefix := range []string{"", "x", "xx"} {
		value := map[string]any{"payload": base64.StdEncoding.EncodeToString([]byte(prefix + "Investigate the credential exposure"))}
		if !findingHistoryHasNote(value) {
			t.Fatal("history note inspector missed payload alignment")
		}
	}
	if findingHistoryHasNote(map[string]any{"run_id": "pid_00000000-0000-4000-8000-000000000001"}) {
		t.Fatal("identity-only history marked as note")
	}
}

func (d *findingArtifactDriver) ObjectReference(v artifactstore.DriverLocator) (string, error) {
	return "s3://zasp-finding78-component/" + v.Key, nil
}
func (d *findingArtifactDriver) PlannedObjectReference(v artifactstore.DriverLocator) (string, error) {
	return d.ObjectReference(v)
}

func TestFindingResponseNativeWorker(t *testing.T) {
	dsn := os.Getenv("ZASP_FINDING78_OWNER_DSN")
	if dsn == "" {
		t.Skip("requires owned finding78 fixture")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	for _, fallback := range config.Fallbacks {
		if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
			t.Fatal("foreign database fallback")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(context.Background())
	providerDB, err := pgx.ConnectConfig(ctx, config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer providerDB.Close(context.Background())
	var binding securityAgentMultistepPricingBinding
	if decodeStrictWorkerJSON([]byte(os.Getenv("ZASP_FINDING78_BINDING")), &binding) != nil {
		t.Fatal("finding pricing binding")
	}
	parent, finding, actor := os.Getenv("ZASP_FINDING78_RUN"), os.Getenv("ZASP_FINDING78_FINDING"), os.Getenv("ZASP_FINDING78_ACTOR")
	human := os.Getenv("ZASP_FINDING78_HUMAN") == "true"
	if os.Getenv("ZASP_FINDING78_HUMAN") != "" && !human || human && os.Getenv("ZASP_FINDING78_EVENT") != "" {
		t.Fatal("explicit human origin must not supply an automatic event")
	}
	sourceKind := "automatic77"
	if human {
		sourceKind = "human78"
	}
	namespace, address := os.Getenv("ZASP_FINDING78_NAMESPACE"), os.Getenv("ZASP_FINDING78_ADDRESS")
	if !strings.HasPrefix(namespace, "finding-response78-") || address != "127.0.0.1:7233" {
		t.Fatal("owned namespace and verified server required")
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		var bound bool
		if err != nil || providerDB.QueryRow(ctx, `SELECT j.state='started' AND j.input_version IS NOT NULL AND j.lookup_request->>'credential_digest'=$2 AND p.reservation_id=j.reservation_id AND p.settled_at IS NULL AND x.action_key='update_finding_response' AND x.trigger_id=$3 AND x.source_kind=$5
 AND CASE WHEN $5='automatic77' THEN EXISTS(SELECT 1 FROM zasp_temporal77.occurrences a WHERE a.run_id=x.run_id AND a.disposition='admitted')
 WHEN $5='human78' THEN NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences a WHERE a.run_id=x.run_id)
 AND EXISTS(SELECT 1 FROM zasp_security_agent_runs rr JOIN zasp_temporal66.run_owners c USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_temporal65.commands m USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_request_receipts rc ON(rc.organization_id,rc.workspace_id,rc.environment_id,rc.receipt_id)=(m.organization_id,m.workspace_id,m.environment_id,m.event_id)
 JOIN zasp_security_agent_audit a ON(a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=(rc.organization_id,rc.workspace_id,rc.environment_id,rc.audit_id)
 WHERE rr.run_id=x.run_id AND rr.requested_by=$6 AND c.execution_owner='legacy' AND c.input_digest=x.input_digest AND c.definition_version=x.definition_version
 AND m.kind='start' AND m.execution_owner='legacy' AND m.input_digest=x.input_digest AND m.definition_version=x.definition_version
 AND rc.principal_id=$6 AND rc.operation='runSecurityAgent' AND rc.expected_version=x.definition_version AND rc.resource_id=x.definition_id AND rc.response->>'id'=x.run_id
 AND rc.intent_digest=digest(convert_to(rc.intent::text,'UTF8'),'sha256') AND rc.intent->>'trigger_id'=x.trigger_id AND rc.intent->'trigger_version'=to_jsonb(x.trigger_version)
 AND a.actor_id=$6 AND a.event_kind='run_queued' AND a.run_id=x.run_id AND encode(a.event_digest,'hex')=x.input_digest)
 ELSE false END
 FROM zasp_temporal78.planning_jobs j JOIN zasp_temporal78.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal78.run_owners x USING(organization_id,workspace_id,environment_id,run_id) WHERE j.request_body=$1 AND j.run_id=$4`, string(body), orderedPlanningDigest([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))), finding, parent, sourceKind, actor).Scan(&bound) != nil || !bound {
			t.Error("finding provider lacked exact persisted request/credential/reservation/source")
			w.WriteHeader(500)
			return
		}
		candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": actor, "status": "investigating", "note": "Investigate the credential exposure"}}})
		var response map[string]json.RawMessage
		_ = json.Unmarshal(openRouterPlannerResponse(string(candidate)), &response)
		response["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	httpClient := server.Client()
	defer httpClient.CloseIdleConnections()
	planner := orderedRequestBindingPlanner(t, &release61TLSTransport{base: httpClient.Transport, target: target})
	defer planner.Close()
	driver := &findingArtifactDriver{temporalPlannerArtifactDriver: temporalPlannerArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	// The full constructor also registers retained test families. Their real
	// runner dependency must remain unused by a finding action.
	runner, runnerCalls := temporalWorkflowFixtureRunner(t, owner, store)
	c, err := client.Dial(client.Options{HostPort: address, Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cfg := validSecurityAgentRuntimeConfig()
	roleDSN := func(user string) string {
		v := owner.Config()
		return (&url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(v.Host, strconv.Itoa(int(v.Port))), Path: "/" + v.Database, RawQuery: "sslmode=disable"}).String()
	}
	cfg.PostgresDSN = roleDSN("security_agent_v33_worker_login")
	cfg.TemporalExecutorDSN = roleDSN("finding78_executor")
	cfg.TemporalCompensationDSN = roleDSN("finding78_compensation")
	root := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, b, 0400); err != nil {
			t.Fatal(err)
		}
		return p
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.GatewaySigningKeyID = "finding78-key"
	cfg.GatewaySigningPrivateFile = write("signing", []byte(base64.RawURLEncoding.EncodeToString(key)))
	pricing, _ := json.Marshal([]securityAgentMultistepPricingBinding{binding})
	cfg.TemporalPricingBindingsFile = write("pricing", pricing)
	fga := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controlled-fga-token" || r.URL.Path != "/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/authorization-models/01ARZ3NDEKTSV4RRFFQ69G5FAW" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_model":{"id":"01ARZ3NDEKTSV4RRFFQ69G5FAW","schema_version":"1.1","type_definitions":[]}}`))
	}))
	defer fga.Close()
	cfg.RuntimeServices = runtimeservices.Config{Enabled: true, Environment: "test", TemporalAddress: address, Namespace: namespace, TaskQueue: namespace + "-finding", DiscoveryTaskQueue: namespace + "-discovery", FGAURL: fga.URL, StoreID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ModelID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", FGATokenFile: write("fga-token", []byte("controlled-fga-token")), Timeout: 10 * time.Second}
	var closes atomic.Int32
	external := workerExternalIO{planner: func(workerRuntimeConfig) (*productionSecurityAgentPlanner, error) {
		planner.mu.RLock()
		transport := planner.client.Transport
		planner.mu.RUnlock()
		return newSecurityAgentPlanner(securityAgentPlannerConfig{Endpoint: cfg.SecurityAgentPlannerEndpoint, Model: cfg.SecurityAgentPlannerModel, Token: []byte("sk-or-v1-test-token-1234567890"), Timeout: time.Second, MaximumTokens: 512, PolicyVersion: cfg.SecurityAgentPlannerPolicy, Transport: transport})
	}, temporal: func(workerRuntimeConfig) (temporalExecutionIO, error) {
		return temporalExecutionIO{runner: runner, store: store, ready: func(ctx context.Context) error { return ctx.Err() }, close: func() error { closes.Add(1); return nil }}, nil
	}}
	external.temporalDiagnostic = &temporalDiagnosticDecorator{
		database: func(d apiserver.JSONDatabase) apiserver.JSONDatabase {
			return findingNativeObservedDB{JSONDatabase: d, t: t}
		},
		singleTest: func(p orchestration.SingleTestProduct) orchestration.SingleTestProduct { return p },
	}
	deps, err := buildWorkerRuntimeWithIO(ctx, cfg, external)
	if err != nil {
		t.Fatal("actual78 constructor", err)
	}
	deps.Processor = observeFindingNativeProcessor(t, deps.Processor)
	closed := false
	defer func() {
		if !closed {
			if err := deps.Close(); err != nil {
				t.Error("finding worker drain", err)
			}
		}
	}()
	if err := deps.Ready(ctx); err != nil {
		t.Fatal("actual78 readiness", err)
	}
	ref := orchestration.TestSelectorRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, DefinitionID: os.Getenv("ZASP_FINDING78_DEFINITION")}
	scheduleID, _ := orchestration.TestSelectorID(ref)
	defer c.ScheduleClient().GetHandle(context.Background(), scheduleID).Delete(context.Background())
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := deps.Processor.RunOnce(ctx); err != nil {
			t.Fatal("actual78 outbox processor", err)
		}
		var accepted bool
		if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal78.start_deliveries WHERE run_id=$1 AND accepted_at IS NOT NULL)`, parent).Scan(&accepted); err != nil {
			t.Fatal(err)
		}
		if accepted {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("finding start deadline")
		case <-ticker.C:
		}
	}
	workflowID, _ := orchestration.FindingResponseWorkflowID(orchestration.RunRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, RunID: parent})
	decision := os.Getenv("ZASP_FINDING78_DECISION")
	if decision != "" {
		for {
			if err := deps.Processor.RunOnce(ctx); err != nil {
				t.Fatal("actual78 decision relay", err)
			}
			var accepted bool
			if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal78.control_deliveries d JOIN zasp_temporal78.control_intents c USING(organization_id,workspace_id,environment_id,control_id) WHERE c.run_id=$1 AND d.accepted_at IS NOT NULL)`, parent).Scan(&accepted); err != nil {
				t.Fatal(err)
			}
			if accepted {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("native finding control deadline")
			case <-ticker.C:
			}
		}
	}
	if err := c.GetWorkflow(ctx, workflowID, "").Get(ctx, nil); err != nil && !(decision == "cancelled" && temporal.IsCanceledError(err)) {
		var phase json.RawMessage
		_ = owner.QueryRow(context.Background(), `SELECT jsonb_build_object('run_state',r.state,'run_error',r.last_error_code,'planning',(SELECT state FROM zasp_temporal78.planning_jobs WHERE run_id=r.run_id),'effect_present',EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=r.run_id)) FROM zasp_security_agent_runs r WHERE run_id=$1`, parent).Scan(&phase)
		t.Log("finding first native phase", string(phase), "provider_calls", calls.Load())
		t.Fatal("finding native workflow", err)
	}
	if human {
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT x.source_kind='human78' AND r.requested_by=$2 AND NOT EXISTS(SELECT 1 FROM zasp_temporal77.occurrences a WHERE a.run_id=x.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners a WHERE a.run_id=x.run_id) FROM zasp_temporal78.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, parent, actor).Scan(&exact); err != nil || !exact {
			t.Fatal("completed native human provenance", exact, err)
		}
	} else {
		sourceID, _ := orchestration.AutomaticSourceWorkflowID(orchestration.AutomaticSourceRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, EventID: os.Getenv("ZASP_FINDING78_EVENT")})
		if err := c.GetWorkflow(ctx, sourceID, "").Get(ctx, nil); err != nil {
			t.Fatal("native finding source dispatch", err)
		}
	}
	var start orchestration.StartRequest
	start.Ref = orchestration.RunRef{OrganizationID: binding.OrganizationID, WorkspaceID: binding.WorkspaceID, EnvironmentID: binding.EnvironmentID, RunID: parent}
	if err := owner.QueryRow(ctx, `SELECT input_digest,definition_version FROM zasp_temporal78.run_owners WHERE run_id=$1`, parent).Scan(&start.InputDigest, &start.DefinitionVersion); err != nil {
		t.Fatal(err)
	}
	starter, err := orchestration.NewFindingResponseStarter(c, cfg.RuntimeServices.TaskQueue, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := starter.Start(ctx, start); err != nil {
		t.Fatal("completed finding exact replay", err)
	}
	if calls.Load() != 1 || runnerCalls.Load() != 0 || driver.puts != 2 {
		t.Fatal("finding crossed test executor or resent provider", calls.Load(), runnerCalls.Load(), driver.puts)
	}
	history := c.GetWorkflowHistory(ctx, workflowID, "", false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	notified := false
	for history.HasNext() {
		event, err := history.Next()
		if err != nil {
			t.Fatal(err)
		}
		raw, marshalErr := json.Marshal(event)
		var fields any
		if marshalErr != nil || json.Unmarshal(raw, &fields) != nil {
			t.Fatal("finding history decode")
		}
		if findingHistoryHasNote(fields) {
			t.Fatal("finding note leaked into workflow history")
		}
		if decision == "approved" && event.GetWorkflowExecutionSignaledEventAttributes().GetSignalName() == "finding-response-wake" || decision == "cancelled" && event.GetWorkflowExecutionCancelRequestedEventAttributes() != nil {
			notified = true
		}
	}
	if decision != "" && !notified {
		t.Fatal("accepted control lacked native notification history", decision)
	}
	if err := deps.Close(); err != nil {
		t.Fatal("actual78 joined close", err)
	}
	closed = true
	if closes.Load() != 1 {
		t.Fatal("finding client close count", closes.Load())
	}
	t.Log("actual78 constructor:", sourceKind, "-> native finding workflow -> one HTTPS planner request/two artifacts -> atomic finding receipt; exact completed replay, zero test runner calls, joined close")
}
