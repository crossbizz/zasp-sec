package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

func TestTemporalOwnedPlanner(t *testing.T) {
	dsn := os.Getenv("ZASP_TEMPORAL_PLANNER_DSN")
	if dsn == "" {
		t.Skip("requires owned68 database")
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close(ctx)
	cfg = cfg.Copy()
	cfg.User = "temporal_executor_test_login"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	base := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, t: t}
	mode := os.Getenv("ZASP_TEMPORAL_PLANNER_FAULT")
	var selection securityAgentMultistepPricingBinding
	if json.Unmarshal([]byte(os.Getenv("ZASP_TEMPORAL_PLANNER_BINDING")), &selection) != nil {
		t.Fatal("binding")
	}
	run := os.Getenv("ZASP_TEMPORAL_PARENT")
	candidate := `{"version":1,"summary":"Contain and retest","steps":[{"index":0,"action":"create_temporary_policy","target_id":"` + selection.EnvironmentID + `"},{"index":1,"action":"run_test","target_id":"` + os.Getenv("ZASP_TEMPORAL_TEST_ID") + `"}]}`
	var responseFields map[string]json.RawMessage
	json.Unmarshal(openRouterPlannerResponse(candidate), &responseFields)
	responseFields["usage"] = json.RawMessage(`{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30,"cost":0.00003}`)
	responseFields["id"] = json.RawMessage(`"p3c-provider-known-response"`)
	response, _ := json.Marshal(responseFields)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		var ready bool
		if err != nil || owner.QueryRow(ctx, `SELECT j.state='started' AND j.request_body=$2 AND j.input_version IS NOT NULL AND j.lookup_request->>'credential_digest'=$3 AND p.reservation_id=j.reservation_id AND p.settled_at IS NULL FROM zasp_temporal68.planning_jobs j JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`, run, string(body), orderedPlanningDigest([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))).Scan(&ready) != nil || !ready {
			t.Error("provider before exact committed request/credential/reservation")
			w.WriteHeader(500)
			return
		}
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("wrong provider request")
		}
		if mode == "unknown" {
			w.WriteHeader(502)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client := server.Client()
	defer client.CloseIdleConnections()
	planner := orderedRequestBindingPlanner(t, &release61TLSTransport{base: client.Transport, target: target})
	defer planner.Close()
	db := &temporalPlannerFaultDatabase{release61WorkerPG: base, owner: owner, planner: planner, run: run, mode: mode, cancel: cancel}
	driver := &temporalPlannerArtifactDriver{orderedFileArtifactDriver: orderedFileArtifactDriver{directory: t.TempDir(), t: t}, mode: mode}
	store, err := artifactstore.New(driver, artifactstore.Config{OperationTimeout: time.Second, MaximumBytes: 524288})
	if err != nil {
		t.Fatal(err)
	}
	actual, ok := any(planner).(interface {
		RunTemporalPlanning(context.Context, apiserver.JSONDatabase, artifactstore.ArtifactStore, securityAgentMultistepPricingBinding, string, int64) (json.RawMessage, error)
	})
	if !ok {
		t.Fatal("lease-free Go planner transport operation missing")
	}
	if mode == "short_deadline" {
		bounded, done := context.WithTimeout(ctx, 20*time.Second)
		defer done()
		ctx = bounded
	}
	receipt, err := actual.RunTemporalPlanning(ctx, db, store, selection, run, 2)
	if mode == "cancel_known" {
		if err != nil || !bytes.Contains(receipt, []byte(`"needs_human"`)) || calls.Load() != 1 || !db.fired {
			t.Fatal("cancelled known response recovery", string(receipt), err, calls.Load())
		}
		checkCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		var valid bool
		if err := owner.QueryRow(checkCtx, `SELECT p.cost_nano_credits=30000 AND p.settled_at IS NOT NULL AND j.state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_temporal68.planning_late_usage WHERE run_id=$1) FROM zasp_temporal68.provider_reservations p JOIN zasp_temporal68.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1`, run).Scan(&valid); err != nil || !valid {
			t.Fatal("late known usage proof", valid, err)
		}
		t.Log("cancelled Activity preserved one late known provider charge without admission or resend")
		return
	}
	if mode == "input_get" || mode == "output_get" {
		want := int32(0)
		if mode == "output_get" {
			want = 1
		}
		if err == nil || !driver.fired || calls.Load() != want {
			t.Fatal("artifact readback fault missed", err, driver.fired, calls.Load())
		}
		receipt, err = actual.RunTemporalPlanning(ctx, db, store, selection, run, 2)
		if err != nil || !bytes.Contains(receipt, []byte(`"admitted"`)) || calls.Load() != 1 {
			t.Fatal("artifact retry resent or failed", string(receipt), err, calls.Load())
		}
		entries, err := os.ReadDir(driver.directory)
		if err != nil || len(entries) != 2 {
			t.Fatal("artifact versions overwritten", len(entries), err)
		}
		t.Log("actual artifact fault recovered", mode, "provider_calls", calls.Load())
		return
	}
	if strings.HasPrefix(mode, "wire_") {
		if err == nil || !db.fired || calls.Load() != 0 || driver.puts != 0 {
			t.Fatal("malformed planner wire reached IO", mode, err, calls.Load(), driver.puts)
		}
		return
	}
	if mode != "" {
		if mode == "lost_start" {
			if err == nil || calls.Load() != 0 {
				t.Fatal("lost start ack authorized send", err, calls.Load())
			}
			receipt, err = actual.RunTemporalPlanning(ctx, db, store, selection, run, 2)
		}
		if err != nil || !bytes.Contains(receipt, []byte(`"needs_human"`)) {
			t.Fatal("planner authority/fault did not terminalize", mode, string(receipt), err)
		}
		want := int32(0)
		if mode == "lost_result" || mode == "unknown" {
			want = 1
		}
		if calls.Load() != want {
			t.Fatal("planner fault duplicate send", mode, calls.Load(), want)
		}
		var released, charged bool
		var charge *int64
		var terminal bool
		if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND r.plan_hash IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.admissions WHERE run_id=$1),COALESCE(p.released_at IS NOT NULL,false),COALESCE(p.settled_at IS NOT NULL,false),p.cost_nano_credits FROM zasp_security_agent_runs r LEFT JOIN zasp_temporal68.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&terminal, &released, &charged, &charge); err != nil || !terminal {
			t.Fatal("planner fault terminal", terminal, err)
		}
		if released != (mode == "prepared_lost" || mode == "credential_changed" || mode == "short_deadline") || charged != (mode == "lost_result") || mode == "lost_result" && (charge == nil || *charge != 30000) || mode != "lost_result" && charge != nil {
			t.Fatal("planner fault accounting", mode, released, charged, charge)
		}
		again, replayErr := actual.RunTemporalPlanning(ctx, db, store, selection, run, 2)
		if replayErr != nil || !bytes.Equal(receipt, again) || calls.Load() != want {
			t.Fatal("terminal fault replay", string(again), replayErr, calls.Load())
		}
		t.Log("actual68 planner fault joined", mode, "provider_calls", calls.Load())
		return
	}
	if err != nil || !bytes.Contains(receipt, []byte(`"admitted"`)) {
		var state string
		var fields int
		owner.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM jsonb_object_keys(to_jsonb(j))) FROM zasp_temporal68.planning_jobs j WHERE run_id=$1`, run).Scan(&state, &fields)
		t.Log("planner checkpoint", state, "wire fields", fields, "provider calls", calls.Load(), "artifact writes", driver.puts)
		t.Fatal("actual68 planner", string(receipt), err)
	}
	if calls.Load() != 1 || driver.puts != 2 {
		t.Fatal("real provider/artifact IO count", calls.Load(), driver.puts)
	}
	again, err := actual.RunTemporalPlanning(ctx, db, store, selection, run, 2)
	if err != nil || !bytes.Equal(receipt, again) || calls.Load() != 1 || driver.puts != 2 {
		t.Fatal("admitted planner retry resent or rewrote", string(again), err, calls.Load(), driver.puts)
	}
	t.Log("real68 planner: HTTPS provider_calls=1, input/output ArtifactStore Put/Get, admission replay without resend")
}

type temporalPlannerFaultDatabase struct {
	*release61WorkerPG
	owner     *pgx.Conn
	planner   *productionSecurityAgentPlanner
	run, mode string
	fired     bool
	cancel    context.CancelFunc
}

func (d *temporalPlannerFaultDatabase) QueryJSON(ctx context.Context, q string, args ...any) (json.RawMessage, error) {
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(time.Now().Add(10*time.Second)) {
		return nil, errWorkerExecution
	}
	if d.mode == "cancel_known" && !d.fired && len(args) == 1 && strings.Contains(q, ".plan(") {
		body, _ := json.Marshal(args[0])
		if v, ok := args[0].([]byte); ok {
			body = v
		}
		var request map[string]any
		if json.Unmarshal(body, &request) == nil && request["operation"] == "result" {
			d.fired = true
			request["operation"], request["payload"] = "reconcile", map[string]any{}
			raw, _ := json.Marshal(request)
			if _, err := d.release61WorkerPG.QueryJSON(ctx, q, raw); err != nil {
				return nil, err
			}
			if _, err := d.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, d.run); err != nil {
				return nil, err
			}
			d.cancel()
			return nil, context.Canceled
		}
	}
	raw, err := d.release61WorkerPG.QueryJSON(ctx, q, args...)
	if err != nil || d.fired || len(args) != 1 {
		return raw, err
	}
	var request struct {
		Operation string `json:"operation"`
	}
	var body []byte
	switch v := args[0].(type) {
	case []byte:
		body = v
	case json.RawMessage:
		body = v
	default:
		body, _ = json.Marshal(v)
	}
	json.Unmarshal(body, &request)
	status := strings.Contains(q, ".status(")
	if d.mode == "loaded_lost" && status || d.mode == "prepared_lost" && request.Operation == "prepare" {
		d.fired = true
		_, err := d.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, d.run)
		if err != nil {
			return nil, err
		}
	}
	if d.mode == "credential_changed" && request.Operation == "prepare" {
		d.fired = true
		d.planner.mu.Lock()
		d.planner.token = []byte("sk-or-v1-changed-test-token-1234567890")
		d.planner.mu.Unlock()
	}
	if d.mode == "lost_start" && request.Operation == "start" || d.mode == "lost_result" && request.Operation == "result" {
		d.fired = true
		return nil, errWorkerExecution
	}
	if strings.HasPrefix(d.mode, "wire_") && status {
		d.fired = true
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil, errWorkerExecution
		}
		if d.mode == "wire_missing_receipt" {
			delete(fields, "receipt")
			fields["send_permit"] = json.RawMessage("false")
		}
		if d.mode == "wire_nested_context" {
			value := fields["context_value"]
			fields["context_value"] = append([]byte(`{"definition":null,`), value[1:]...)
		}
		raw, err = json.Marshal(fields)
	}
	return raw, err
}

type temporalPlannerArtifactDriver struct {
	orderedFileArtifactDriver
	mode  string
	fired bool
}

func (d *temporalPlannerArtifactDriver) Get(ctx context.Context, v artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	result, err := d.orderedFileArtifactDriver.Get(ctx, v)
	if err == nil && !d.fired && (d.mode == "input_get" && d.puts == 1 || d.mode == "output_get" && d.puts == 2) {
		d.fired = true
		return artifactstore.DriverObject{}, artifactstore.ErrGet
	}
	return result, err
}
