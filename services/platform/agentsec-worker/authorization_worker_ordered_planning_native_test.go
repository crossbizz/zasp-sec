package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// This child uses the admitted parent fixture, actual registered SQL clients,
// official FGA and the production one-send planner. Only remote provider and
// artifact storage are local fixtures; no provider or audit receipt is seeded.
func TestP7WorkerOrdered68SharedPlannerNative(t *testing.T) {
	dsn := os.Getenv("ZASP_P7_ORDERED_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned Ordered68 parent required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var config runtimeservices.Config
	var selection securityAgentMultistepPricingBinding
	var request struct {
		OrganizationID string `json:"organization_id"`
		WorkspaceID    string `json:"workspace_id"`
		EnvironmentID  string `json:"environment_id"`
		RunID          string `json:"run_id"`
		Version        int64  `json:"definition_version"`
		Digest         string `json:"input_digest"`
	}
	if json.Unmarshal([]byte(os.Getenv("ZASP_P7_ORDERED_CONFIG")), &config) != nil || json.Unmarshal([]byte(os.Getenv("ZASP_P7_ORDERED_SELECTION")), &selection) != nil || json.Unmarshal([]byte(os.Getenv("ZASP_P7_ORDERED_START")), &request) != nil {
		t.Fatal("owned ordered inputs")
	}
	start := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, RunID: request.RunID}, DefinitionVersion: request.Version, InputDigest: request.Digest}
	poolFor := func(principal string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil || net.ParseIP(cfg.ConnConfig.Host) == nil || !net.ParseIP(cfg.ConnConfig.Host).IsLoopback() {
			t.Fatal("owned loopback required")
		}
		for _, fallback := range cfg.ConnConfig.Fallbacks {
			if net.ParseIP(fallback.Host) == nil || !net.ParseIP(fallback.Host).IsLoopback() {
				t.Fatal("foreign fallback")
			}
		}
		if principal != "" {
			cfg.ConnConfig.User = principal
		}
		if principal == "temporal_executor_test_login" || principal == "temporal_compensation_test_login" {
			trace := &orderedPlannerQueryTrace{t: t}
			if cfg.ConnConfig.Tracer != nil {
				cfg.ConnConfig.Tracer = multitracer.New(cfg.ConnConfig.Tracer, trace)
			} else {
				cfg.ConnConfig.Tracer = trace
			}
		}
		cfg.MaxConns = 2
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("owned pool unavailable")
		}
		t.Cleanup(pool.Close)
		return pool
	}
	owner := poolFor("")
	forwardPool, compensationPool := poolFor("temporal_executor_test_login"), poolFor("temporal_compensation_test_login")
	data, err := exec.CommandContext(ctx, "docker", "inspect", "zasp-runtime-services-openfga-1").Output()
	if err != nil {
		t.Fatal("owned FGA unavailable")
	}
	var containers []struct{ Config struct{ Env []string } }
	if json.Unmarshal(data, &containers) != nil || len(containers) != 1 {
		t.Fatal("owned FGA config unavailable")
	}
	token := ""
	for _, value := range containers[0].Config.Env {
		if strings.HasPrefix(value, "OPENFGA_AUTHN_PRESHARED_KEYS=") {
			token = strings.TrimPrefix(value, "OPENFGA_AUTHN_PRESHARED_KEYS=")
		}
	}
	if token == "" || strings.Contains(token, ",") {
		t.Fatal("owned credential unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client, err := fga.NewSdkClient(&fga.ClientConfiguration{ApiUrl: config.FGAURL, Credentials: &credentials.Credentials{Method: credentials.CredentialsMethodApiToken, Config: &credentials.Config{ApiToken: token}}, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	checker, err := authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	observed := &workerNativeCountingChecker{delegate: checker}
	writer, err := authorization.NewOpenFGATupleWriter(client, config)
	if err != nil {
		t.Fatal(err)
	}
	var projector string
	if err := owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&projector); err != nil {
		t.Fatal(err)
	}
	projection, err := authorization.NewPostgresProjectionRepository(poolFor(projector))
	if err != nil {
		t.Fatal(err)
	}
	forwardKey, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
	compensationKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	forward, err := authorization.NewWorkerExecutor(forwardPool, observed, config.StoreID, config.ModelID, forwardKey)
	if err != nil {
		t.Fatal(err)
	}
	compensation, err := authorization.NewWorkerExecutor(compensationPool, nil, "", "", compensationKey)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: forwardPool})
	if err != nil {
		t.Fatal(err)
	}
	db := &orderedPlannerNativeDatabase{workerFindingPlanningDatabase: &workerFindingPlanningDatabase{base: base, forward: forward, compensation: compensation, start: start, family: workerPlanningOrdered68}, t: t}
	db.project = func(callCtx context.Context) error {
		_, err := authorization.Reconcile(callCtx, projection, writer, request.OrganizationID, config.StoreID, config.ModelID)
		return err
	}
	mode := os.Getenv("ZASP_P7_ORDERED_MODE")
	if mode == "current-timing" {
		// Diagnostic only: invoke the same two real boundary methods as
		// workerFindingPlanningDatabase under its unchanged shared 10s budget.
		if err := db.project(ctx); err != nil {
			t.Fatal("actual ordered diagnostic projection", err)
		}
		identity := temporalStartFields(start)
		delete(identity, "input_digest")
		raw, _ := json.Marshal(identity)
		callCtx, done := context.WithTimeout(ctx, 10*time.Second)
		defer done()
		started := time.Now()
		decision, err := forward.Authorize(callCtx, "ordered68.planning.state", raw)
		t.Logf("ordered timing boundary=authorize elapsed_ms=%d checks=%d failed=%t deadline=%t", time.Since(started).Milliseconds(), observed.calls, err != nil, callCtx.Err() != nil)
		if err != nil {
			t.Fatal("actual ordered state authorization failed")
		}
		started = time.Now()
		_, err = forward.Execute(callCtx, decision)
		t.Logf("ordered timing boundary=execute elapsed_ms=%d failed=%t deadline=%t", time.Since(started).Milliseconds(), err != nil, callCtx.Err() != nil)
		if err != nil {
			t.Fatal("actual ordered state execution failed")
		}
		return
	}
	if !stringInWorker(mode, "current", "prepared-revoke", "sent-revoke", "late-usage") {
		t.Fatal("unknown owned mode")
	}
	var revoked atomic.Bool
	revoke := func(callCtx context.Context) error {
		tag, err := owner.Exec(callCtx, `UPDATE zasp_identity_memberships m SET active=false FROM zasp_security_agent_runs r WHERE r.run_id=$1 AND (m.organization_id,m.principal_id)=(r.organization_id,r.requested_by)`, request.RunID)
		if err == nil && tag.RowsAffected() != 1 {
			t.Fatal("actual grantor absent")
		}
		if err == nil {
			revoked.Store(true)
		}
		return err
	}
	identity := temporalStartFields(start)
	delete(identity, "input_digest")
	identityRaw, _ := json.Marshal(identity)
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": request.EnvironmentID}, map[string]any{"index": 1, "action": "run_test", "target_id": os.Getenv("ZASP_P7_ORDERED_TEST_ID")}}})
	var responseFields map[string]json.RawMessage
	if json.Unmarshal(openRouterPlannerResponse(string(candidate)), &responseFields) != nil {
		t.Fatal("owned response")
	}
	responseFields["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
	responseFields["id"] = json.RawMessage(`"ordered68-provider-response"`)
	response, _ := json.Marshal(responseFields)
	var calls atomic.Int32
	var terminalBefore string
	const terminalSQL = `SELECT encode(digest(convert_to(to_jsonb(a)::text,'UTF8'),'sha256'),'hex') FROM zasp_security_agent_audit a WHERE run_id=$1 AND event_kind='temporal_planning_terminal'`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		var committed bool
		if err != nil || len(body) > 65536 || r.Method != "POST" || owner.QueryRow(ctx, `SELECT j.state='started' AND j.request_body=$2 AND j.input_version IS NOT NULL AND j.lookup_request->>'credential_digest'=$3 AND p.reservation_id=j.reservation_id AND p.settled_at IS NULL AND p.released_at IS NULL FROM zasp_temporal68.planning_jobs j JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, request.RunID, string(body), orderedPlanningDigest([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))).Scan(&committed) != nil || !committed {
			t.Error("send before committed native intent")
			w.WriteHeader(500)
			return
		}
		if mode == "sent-revoke" || mode == "late-usage" {
			if err := revoke(ctx); err != nil {
				t.Error("actual revoke", err)
				w.WriteHeader(500)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	httpClient := server.Client()
	defer httpClient.CloseIdleConnections()
	target, _ := url.Parse(server.URL)
	planner := orderedRequestBindingPlanner(t, &release61TLSTransport{base: httpClient.Transport, target: target})
	defer planner.Close()
	if mode == "late-usage" {
		// The response is held in the real planner, while SQL still records a
		// started unknown send. Terminalize that captured debt before result
		// persistence; the retained response must then take late accounting.
		db.beforeResult = func(callCtx context.Context) error {
			if err := db.RecoverCapturedPlanning(callCtx, identityRaw, nil); err != nil {
				return err
			}
			return owner.QueryRow(callCtx, terminalSQL, request.RunID).Scan(&terminalBefore)
		}
	}
	driver := &orderedPlannerNativeArtifacts{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}}
	if mode == "prepared-revoke" {
		driver.beforeGet = func(callCtx context.Context) error {
			if revoked.Load() {
				return nil
			}
			var prepared bool
			if err := owner.QueryRow(callCtx, `SELECT state='prepared' FROM zasp_temporal68.planning_jobs WHERE run_id=$1`, request.RunID).Scan(&prepared); err != nil {
				return err
			}
			if prepared {
				return revoke(callCtx)
			}
			return nil
		}
	}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 524288})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := planner.RunTemporalPlanning(ctx, db, store, selection, request.RunID, request.Version)
	if err != nil {
		t.Fatal("actual signed ordered planner", err)
	}
	if mode == "current" {
		if !bytes.Contains(receipt, []byte(`"admitted"`)) || calls.Load() != 1 || driver.puts != 2 {
			t.Fatal("ordered admitted IO cardinality", calls.Load(), driver.puts)
		}
		again, err := planner.RunTemporalPlanning(ctx, db, store, selection, request.RunID, request.Version)
		if err != nil || !bytes.Equal(receipt, again) || calls.Load() != 1 || driver.puts != 2 {
			t.Fatal("ordered admitted replay", err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=2 FROM zasp_security_agent_steps WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_temporal68.admissions WHERE run_id=$1) AND p.total_tokens=30 AND p.cost_nano_credits=30000 AND p.settled_at IS NOT NULL AND NOT zasp_authorization80_worker.runtime_ready() FROM zasp_temporal68.provider_reservations p WHERE run_id=$1`, request.RunID).Scan(&exact); err != nil || !exact {
			t.Fatal("ordered admitted native accounting", err)
		}
	} else {
		if !revoked.Load() || !bytes.Contains(receipt, []byte(`"needs_human"`)) {
			t.Fatal("actual revocation recovery not reached")
		}
		want := int32(1)
		if mode == "prepared-revoke" {
			want = 0
		}
		if calls.Load() != want || driver.puts != 1 {
			t.Fatal("recovery fresh IO", calls.Load(), driver.puts)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT j.state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal') AND CASE WHEN $2 THEN p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.total_tokens IS NULL ELSE p.settled_at IS NOT NULL AND p.total_tokens=30 AND p.cost_nano_credits=30000 END FROM zasp_temporal68.planning_jobs j JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, request.RunID, mode == "prepared-revoke").Scan(&exact); err != nil || !exact {
			t.Fatal("captured native accounting", err)
		}
		var before, after string
		if err := owner.QueryRow(ctx, terminalSQL, request.RunID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		checks, gets, puts := observed.calls, driver.gets, driver.puts
		var retained []byte
		if mode != "prepared-revoke" {
			retained = response
		}
		if err := db.RecoverCapturedPlanning(ctx, identityRaw, retained); err != nil {
			t.Fatal("held captured retry", err)
		}
		if err := owner.QueryRow(ctx, terminalSQL, request.RunID).Scan(&after); err != nil || before != after || observed.calls != checks || driver.gets != gets || driver.puts != puts || calls.Load() != want {
			t.Fatal("captured retry changed evidence or issued IO", err)
		}
		if mode == "late-usage" {
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_temporal68.planning_late_usage WHERE run_id=$1`, request.RunID).Scan(&count); err != nil || count != 1 || terminalBefore != after {
				t.Fatal("late charge or original audit changed", err)
			}
		}
	}
	t.Logf("actual ordered planner mode=%s provider_calls=%d artifact_puts=%d", mode, calls.Load(), driver.puts)
}

type orderedPlannerNativeDatabase struct {
	*workerFindingPlanningDatabase
	project      func(context.Context) error
	beforeResult func(context.Context) error
	t            *testing.T
}

func (d *orderedPlannerNativeDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	// Explicit test projector runs its real transaction before each independent
	// forward decision. Compensation's promoted method never enters this hook.
	if err := d.project(ctx); err != nil {
		return nil, err
	}
	phase := "ready"
	if len(args) == 1 {
		var value struct {
			Operation string `json:"operation"`
		}
		if b, ok := args[0].([]byte); ok {
			_ = json.Unmarshal(b, &value)
		}
		phase = value.Operation
		if phase == "" {
			phase = "state"
		}
	}
	if phase == "result" && d.beforeResult != nil {
		callback := d.beforeResult
		d.beforeResult = nil
		if err := callback(ctx); err != nil {
			return nil, err
		}
	}
	started := time.Now()
	raw, err := d.workerFindingPlanningDatabase.QueryJSON(ctx, q, args...)
	d.t.Logf("ordered planning phase=%s duration=%s failed=%t", phase, time.Since(started).Round(time.Millisecond), err != nil)
	return raw, err
}

type orderedPlannerNativeArtifacts struct {
	orderedFileArtifactDriver
	beforeGet func(context.Context) error
	gets      int
}

// Diagnose only these owned SQL entry boundaries; never log raw SQL, proof,
// arguments, error messages, context, credentials or provider data.
type orderedPlannerQueryTrace struct{ t *testing.T }
type orderedPlannerTraceKey struct{}
type orderedPlannerTraceState struct {
	entry   string
	started time.Time
}

func (p *orderedPlannerQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	state := orderedPlannerTraceState{started: time.Now()}
	for _, name := range []string{"zasp_authorization80_worker.planning68_source", "zasp_authorization80_worker.revision", "zasp_authorization80_worker.planning68_recovery", "zasp_temporal68.plan", "zasp_temporal68.status", "zasp_temporal68.current_ready"} {
		if strings.Contains(data.SQL, name+"(") {
			state.entry = name
			break
		}
	}
	return context.WithValue(ctx, orderedPlannerTraceKey{}, state)
}

func (p *orderedPlannerQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	state, ok := ctx.Value(orderedPlannerTraceKey{}).(orderedPlannerTraceState)
	if !ok || state.entry == "" {
		return
	}
	code, class := "none", "ok"
	if data.Err != nil {
		class = "query_error"
		var native *pgconn.PgError
		if errors.As(data.Err, &native) {
			class = "database_error"
			if len(native.Code) == 5 && strings.Trim(native.Code, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
				code = native.Code
			}
		} else if errors.Is(data.Err, context.DeadlineExceeded) {
			class = "deadline"
		} else if errors.Is(data.Err, context.Canceled) {
			class = "cancelled"
		}
	}
	p.t.Logf("ordered SQL entry=%s elapsed_ms=%d sqlstate=%s class=%s", state.entry, time.Since(state.started).Milliseconds(), code, class)
}

func (d *orderedPlannerNativeArtifacts) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	d.gets++
	if d.beforeGet != nil {
		if err := d.beforeGet(ctx); err != nil {
			return artifactstore.DriverObject{}, err
		}
	}
	return d.orderedFileArtifactDriver.Get(ctx, v)
}
