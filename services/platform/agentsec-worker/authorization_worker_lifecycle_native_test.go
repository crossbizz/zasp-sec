package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
)

type workerLifecycleTrace struct{ t *testing.T }
type workerLifecycleTraceKey struct{}
type workerLifecycleTraceValue struct {
	entry, phase string
	started      time.Time
}

func workerLifecycleTracer(t *testing.T, existing pgx.QueryTracer) pgx.QueryTracer {
	trace := workerLifecycleTrace{t}
	if existing != nil {
		return multitracer.New(existing, trace)
	}
	return trace
}
func (trace workerLifecycleTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	value := workerLifecycleTraceValue{started: time.Now()}
	for _, name := range []string{"test74_lifecycle_source", "test74_recovery_status", "test74_receipt_source", "test74_receipt", "zasp_temporal74.inspect", "zasp_temporal74.cleanup"} {
		if strings.Contains(data.SQL, name+"(") {
			value.entry = name
			break
		}
	}
	if len(data.Args) > 0 {
		if phase, ok := data.Args[0].(string); ok && (phase == "inspect" || phase == "cleanup" || phase == "recovery_status") {
			value.phase = phase
		}
	}
	return context.WithValue(ctx, workerLifecycleTraceKey{}, value)
}
func (trace workerLifecycleTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	value, ok := ctx.Value(workerLifecycleTraceKey{}).(workerLifecycleTraceValue)
	if !ok || value.entry == "" {
		return
	}
	class, code := "ok", "none"
	if data.Err != nil {
		class = "query_error"
		if errors.Is(data.Err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			class = "deadline"
		} else if errors.Is(data.Err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			class = "cancelled"
		}
		var native *pgconn.PgError
		if errors.As(data.Err, &native) && len(native.Code) == 5 && strings.Trim(native.Code, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
			code = native.Code
		}
	}
	trace.t.Log("lifecycle database", value.entry, "phase", value.phase, "elapsed", time.Since(value.started), "class", class, "SQLSTATE", code)
}

// This owns a real native admission before planning or worker materialization.
// No fixture inserts an association, planner receipt or stop journal.
func TestP7WorkerSingleTestQueuedLifecycleNative(t *testing.T) {
	runWorkerLifecycleNative(t, "queued")
}
func TestP7WorkerSingleTestPendingLifecycleNative(t *testing.T) {
	runWorkerLifecycleNative(t, "pending")
}
func TestP7WorkerSingleTestReservedLifecycleNative(t *testing.T) {
	runWorkerLifecycleNative(t, "reserved")
}
func TestP7WorkerSingleTestPreparedLifecycleNative(t *testing.T) {
	runWorkerLifecycleNative(t, "prepared")
}
func TestP7WorkerSingleTestMaximumPendingStatusNative(t *testing.T) {
	runWorkerLifecycleNative(t, "maxpending")
}
func TestP7WorkerSingleTestMaximumCompleteStatusNative(t *testing.T) {
	runWorkerLifecycleNative(t, "maxcomplete")
}
func runWorkerLifecycleNative(t *testing.T, stage string) {
	dsn := os.Getenv("ZASP_P7_WORKER_OWNER_DSN")
	if dsn == "" {
		t.Skip("owned native74 admission fixture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil || net.ParseIP(pc.ConnConfig.Host) == nil || !net.ParseIP(pc.ConnConfig.Host).IsLoopback() {
		t.Fatal("owned loopback database required")
	}
	owner, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	pool := func(login string) *pgxpool.Pool {
		c := pc.Copy()
		c.ConnConfig.User = login
		c.MaxConns = 2
		p, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	var start orchestration.StartRequest
	var actor string
	if err := owner.QueryRow(ctx, `SELECT x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_version,x.input_digest,r.requested_by FROM zasp_temporal74.run_owners x JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, os.Getenv("ZASP_P7_WORKER_PARENT")).Scan(&start.Ref.OrganizationID, &start.Ref.WorkspaceID, &start.Ref.EnvironmentID, &start.Ref.RunID, &start.DefinitionVersion, &start.InputDigest, &actor); err != nil {
		t.Fatal("real admission", err)
	}
	var untouched bool
	const emptyDebt = `SELECT zasp_temporal74.queued_absent($1,$2,$3,$4) AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations WHERE run_id=$4)`
	if err := owner.QueryRow(ctx, emptyDebt, start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID).Scan(&untouched); err != nil || untouched != (stage == "queued") {
		t.Fatal("queued admission already materialized", err)
	}
	forwardPool, compPool := pool("worker_test_executor"), pool("worker_test_compensation")
	forbidden := &recoveryNativeForbiddenIO{}
	fk, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
	ck, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	forward, err := authorization.NewWorkerExecutor(forwardPool, forbidden, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAW", fk)
	if err != nil {
		t.Fatal(err)
	}
	comp, err := authorization.NewWorkerExecutor(compPool, nil, "", "", ck)
	if err != nil {
		t.Fatal(err)
	}
	if forward.Ready(ctx) != nil || comp.Ready(ctx) != nil {
		t.Fatal("registered purpose clients unavailable")
	}
	database := func(p *pgxpool.Pool) apiserver.JSONDatabase {
		d, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: p})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	product := (&temporalSecurityAgentProduct{executor: database(forwardPool), compensation: database(compPool), workerForward: forward, workerCompensation: comp}).SingleTestProduct()
	if stage == "maxpending" || stage == "maxcomplete" {
		want, completed := "pending", 5
		if stage == "maxcomplete" {
			want, completed = "complete", 6
		}
		began := time.Now()
		raw, err := product.(*temporalSingleTestProduct).capturedLifecycle(ctx, "recovery_status", temporalStartFields(start))
		if err != nil || string(raw) != `{"status": "`+want+`"}` || time.Since(began) >= 10*time.Second {
			t.Fatal("actual maximum-category product status under original ten-second budget", want, err)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT count(*)=6 AND count(*) FILTER(WHERE state='completed')=$2 AND bool_and(attempt=1) FROM zasp_temporal74.invocations WHERE test_run_id=(SELECT test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1)`, start.Ref.RunID, completed).Scan(&exact); err != nil || !exact {
			t.Fatal("maximum status changed native cardinality", err)
		}
		if stage == "maxcomplete" {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(ctx, `UPDATE zasp_temporal74.invocations SET request_digest=decode(repeat('e',64),'hex') WHERE test_run_id=(SELECT test_run_id FROM zasp_temporal74.run_owners WHERE run_id=$1) AND category=(SELECT test_categories->>5 FROM zasp_security_agent_test_links WHERE run_id=$1)`, start.Ref.RunID); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION worker_test_compensation`); err != nil {
				t.Fatal(err)
			}
			q, _ := json.Marshal(temporalStartFields(start))
			var value json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source('recovery_status',$1::jsonb)`, q).Scan(&value)
			var native *pgconn.PgError
			if !errors.As(err, &native) || native.Code != "40001" {
				t.Fatal("sixth category binding accepted", err)
			}
		}
		if forbidden.calls.Load() != 0 {
			t.Fatal("captured maximum status performed forward IO")
		}
		return
	}
	activities := orchestration.SingleTestActivities{Product: product}
	// Cleanup owns a real SDK heartbeat loop. A plain context only appeared to
	// work while the native operation completed before its first heartbeat.
	var suite testsuite.WorkflowTestSuite
	activityEnvironment := suite.NewTestActivityEnvironment()
	activityEnvironment.SetWorkerOptions(worker.Options{BackgroundActivityContext: ctx})
	activityEnvironment.SetTestTimeout(4 * time.Minute)
	activityEnvironment.RegisterActivity(activities.Cleanup)
	activityEnvironment.RegisterActivity(activities.Observe)
	observeActivity := func() (orchestration.RunState, error) {
		var state orchestration.RunState
		value, err := activityEnvironment.ExecuteActivity(activities.Observe, start)
		if err == nil {
			err = value.Get(&state)
		}
		return state, err
	}
	cleanupActivity := func(q orchestration.CleanupRequest) error {
		_, err := activityEnvironment.ExecuteActivity(activities.Cleanup, q)
		return err
	}
	blocked, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = blocked.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, start.Ref.RunID); err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(ctx, 30*time.Millisecond)
	began := time.Now()
	_, cancelErr := activities.Observe(short, start)
	cancelShort()
	if rollback := blocked.Rollback(ctx); rollback != nil {
		t.Fatal(rollback)
	}
	if cancelErr == nil || time.Since(began) > 2*time.Second {
		t.Fatal("bounded lifecycle cancellation", cancelErr)
	}
	if stage == "queued" {
		assertWorkerLifecycleBindings(t, ctx, owner, compPool, start, ck)
	}
	if stage == "queued" || stage == "prepared" {
		assertWorkerLifecycleOriginalSource(t, ctx, owner, compPool, start, stage)
	}
	wantPhase := "planning"
	if stage == "pending" || stage == "reserved" {
		wantPhase = "test"
	}
	if state, err := observeActivity(); err != nil || state.Phase != wantPhase {
		t.Errorf("actual queued Observe: phase=%s error=%v", state.Phase, err)
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, start.Ref.OrganizationID, actor); err != nil {
		t.Fatal(err)
	}
	if state, err := observeActivity(); err != nil || state.Phase != "permission_lost" {
		t.Errorf("revoked queued Observe: phase=%s error=%v", state.Phase, err)
	}
	q := orchestration.CleanupRequest{Start: start, Reason: "workflow_cancelled"}
	if stage == "pending" {
		concrete := product.(*temporalSingleTestProduct)
		status, err := concrete.capturedLifecycle(ctx, "recovery_status", temporalStartFields(start))
		if err != nil || string(status) != `{"status": "pending"}` && string(status) != `{"status":"pending"}` {
			t.Fatal("genuine absent observation status", string(status), err)
		}
	}
	if err := cleanupActivity(q); stage == "pending" {
		var application *temporal.ApplicationError
		if !errors.As(err, &application) || application.Type() != "CleanupPending" || !application.NonRetryable() {
			t.Errorf("actual captured pending Cleanup classification: %v", err)
		}
	} else if err != nil {
		t.Errorf("actual captured Cleanup without new delegation: %v", err)
	}
	if t.Failed() {
		return
	}
	if stage == "pending" {
		if err := product.Cleanup(ctx, q); !errors.Is(err, orchestration.ErrCleanupPending) {
			t.Fatal("unknown cleanup debt", err)
		}
		// Dispatch has started, but no runner observation has arrived. Cleanup
		// preserves that state and records the unknown outcome as retained debt.
		var stop, effect, audit, parent, absent, unresolved bool
		if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*)=1 AND bool_and(proof->>'effect_state'='started' AND proof->>'parent_reason'='test_outcome_unknown') FROM zasp_temporal74.stops WHERE run_id=$1),
 (SELECT count(*)=1 AND bool_and(state='started' AND started_at IS NOT NULL AND completed_at IS NULL) FROM zasp_temporal74.effects WHERE run_id=$1),
 (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_test_stopped'),
 EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND last_error_code='test_outcome_unknown'),
 NOT EXISTS(SELECT 1 FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,test_run_id) WHERE x.run_id=$1),
 zasp_temporal74.unresolved($2,$3,$4,$1)`, start.Ref.RunID, start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID).Scan(&stop, &effect, &audit, &parent, &absent, &unresolved); err != nil || !stop || !effect || !audit || !parent || !absent || !unresolved || forbidden.calls.Load() != 0 {
			t.Fatalf("captured pending debt: stop=%t effect=%t audit=%t parent=%t no_observation=%t unresolved=%t forbidden_io=%d error=%v", stop, effect, audit, parent, absent, unresolved, forbidden.calls.Load(), err)
		}
		return
	}
	if err := cleanupActivity(q); err != nil {
		t.Fatal("queued cleanup replay", err)
	}
	if state, err := observeActivity(); err != nil || state.Phase != "terminal" {
		t.Fatal("queued terminal Observe", state, err)
	}
	if stage == "queued" {
		if err := owner.QueryRow(ctx, emptyDebt, start.Ref.OrganizationID, start.Ref.WorkspaceID, start.Ref.EnvironmentID, start.Ref.RunID).Scan(&untouched); err != nil || !untouched {
			t.Fatal("cleanup manufactured forward state", err)
		}
	}
	var exact bool
	wantTerminalState := "cancelled"
	if stage == "prepared" {
		wantTerminalState = "needs_human"
	}
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal74.stops WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_test_stopped') AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state=$2)`, start.Ref.RunID, wantTerminalState).Scan(&exact); err != nil || !exact || forbidden.calls.Load() != 0 {
		t.Fatal("queued stop cardinality/forbidden IO", err, forbidden.calls.Load())
	}
	if stage == "prepared" {
		if err := owner.QueryRow(ctx, `SELECT p.released_at IS NOT NULL AND p.settled_at IS NULL AND p.total_tokens IS NULL AND j.state='needs_human' AND EXISTS(SELECT 1 FROM zasp_security_agent_runs r WHERE r.run_id=j.run_id AND r.state='needs_human' AND r.last_error_code='planner_not_sent') AND (SELECT count(*)=1 FROM zasp_security_agent_audit a WHERE a.run_id=j.run_id AND a.event_kind='temporal_planning_terminal' AND a.body->>'reason'='planner_not_sent') AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects f WHERE f.run_id=j.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans p WHERE p.run_id=j.run_id) FROM zasp_temporal74.provider_reservations p JOIN zasp_temporal74.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE p.run_id=$1`, start.Ref.RunID).Scan(&exact); err != nil || !exact {
			t.Fatal("prepared cleanup no-send released debt", err)
		}
	}
	if stage == "reserved" {
		if err := owner.QueryRow(ctx, `SELECT f.state='stopped' AND f.started_at IS NULL AND c.state='cancelled' AND c.attempt=0 FROM zasp_temporal74.effects f JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id) WHERE f.run_id=$1`, start.Ref.RunID).Scan(&exact); err != nil || !exact {
			t.Fatal("reserved child cancellation", err)
		}
	}
}

// Corruptions are confined to rolled-back owned transactions. Every source
// read must still pass unchanged catalog readiness before interpreting rows.
func assertWorkerRecoveryStatus(t *testing.T, ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, start orchestration.StartRequest, child string) {
	t.Helper()
	concrete := product.SingleTestProduct().(*temporalSingleTestProduct)
	raw, err := concrete.capturedLifecycle(ctx, "recovery_status", temporalStartFields(start))
	var response struct {
		Status string `json:"status"`
	}
	if err != nil || decodeStrictWorkerJSON(raw, &response) != nil || response.Status != "complete" {
		t.Fatal("actual signed complete status", string(raw), err)
	}
	request, _ := json.Marshal(temporalStartFields(start))
	cases := []struct{ name, mutation, want string }{
		{"complete", "", "complete"},
		{"absent", `DELETE FROM zasp_temporal74.invocations WHERE test_run_id=$1`, "pending"},
		{"started", `UPDATE zasp_temporal74.invocations SET state='started',completed_at=NULL,http_status=NULL,response_digest=NULL,protected=NULL,credential_version_digest=NULL WHERE test_run_id=$1`, "pending"},
		{"wrong-request", `UPDATE zasp_temporal74.invocations SET request_digest=decode(repeat('0',64),'hex') WHERE test_run_id=$1`, "refused"},
		{"wrong-input", `UPDATE zasp_temporal74.invocations SET input_digest=decode(repeat('0',64),'hex') WHERE test_run_id=$1`, "refused"},
		{"wrong-resolution", `UPDATE zasp_temporal74.invocations SET target_resolution=jsonb_set(target_resolution,'{binding}','{}'::jsonb) WHERE test_run_id=$1`, "refused"},
		{"unusable-completed", `UPDATE zasp_temporal74.invocations SET http_status=500,protected=NULL WHERE test_run_id=$1`, "refused"},
		{"extra-category", `INSERT INTO zasp_temporal74.invocations SELECT (jsonb_populate_record(NULL::zasp_temporal74.invocations,to_jsonb(j)||jsonb_build_object('category',CASE WHEN j.category='tool_abuse' THEN 'prompt_injection' ELSE 'tool_abuse' END))).* FROM zasp_temporal74.invocations j WHERE test_run_id=$1 LIMIT 1`, "refused"},
	}
	for _, c := range cases {
		t.Run("recovery-status-"+c.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if c.mutation != "" {
				if tag, err := tx.Exec(ctx, c.mutation, child); err != nil || tag.RowsAffected() == 0 {
					t.Fatal("owned status fixture mutation", err)
				}
			}
			var ready bool
			if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal74.current_ready()`).Scan(&ready); err != nil || !ready {
				t.Fatal("status fixture changed catalog", err)
			}
			if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION worker_test_compensation`); err != nil {
				t.Fatal(err)
			}
			var facts json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source('recovery_status',$1::jsonb)`, request).Scan(&facts)
			if c.want == "refused" {
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != "42501" && native.Code != "40001" {
					t.Fatal("corrupt observation status accepted", err)
				}
				return
			}
			var value struct {
				Recovery struct {
					Status string `json:"status"`
				} `json:"recovery"`
			}
			if err != nil || json.Unmarshal(facts, &value) != nil || value.Recovery.Status != c.want {
				t.Fatal("closed status classification", c.want, err)
			}
		})
	}
	t.Run("completion-between-status-and-execute", func(t *testing.T) {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var completion json.RawMessage
		if err := tx.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',test_run_id,'effect_key',effect_key,'operation','complete','checksum',$2::text,'fingerprint',$3::text,'payload',jsonb_build_object('category',category,'request_digest',encode(request_digest,'hex'),'http_status',http_status,'response_digest',encode(response_digest,'hex'),'protected',protected,'credential_version_digest',encode(credential_version_digest,'hex'))) FROM zasp_temporal74.invocations WHERE test_run_id=$1 LIMIT 1`, child, migrations.ProductionTemporalTestExecutor().Checksum(), migrations.TemporalTestExecutorFingerprint()).Scan(&completion); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE zasp_temporal74.invocations SET state='started',completed_at=NULL,http_status=NULL,response_digest=NULL,protected=NULL,credential_version_digest=NULL WHERE test_run_id=$1`, child); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION worker_test_compensation`); err != nil {
			t.Fatal(err)
		}
		sign := func(operation, phase, statement string, q json.RawMessage) []byte {
			var facts json.RawMessage
			var principal string
			if err := tx.QueryRow(ctx, statement, phase, q).Scan(&facts, &principal); err != nil {
				t.Fatal("race captured source", err)
			}
			key, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
			now := time.Now().UnixMilli()
			body, _ := json.Marshal(map[string]any{"purpose": "captured-compensation", "key_version": key.Version(), "operation": operation, "request": nil, "facts": facts, "revision": authorization.Revision{}, "session_user": principal, "issued_at": now, "expires_at": now + 30000})
			mac := hmac.New(sha256.New, key.Verifier())
			_, _ = mac.Write([]byte("zasp-authorization-captured-compensation-v1\x00"))
			_, _ = mac.Write(body)
			envelope, _ := json.Marshal(map[string]any{"body": body, "version": key.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
			return envelope
		}
		old := sign("test74.lifecycle.recovery_status", "recovery_status", `SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb),session_user`, request)
		complete := sign("test74.adapter.complete", "complete", `SELECT zasp_authorization80_worker.test74_completion_source($1,$2::jsonb),session_user`, completion)
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(complete)); err != nil {
			t.Fatal(err)
		}
		var receipt json.RawMessage
		if err := tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_complete($1::jsonb)`, completion).Scan(&receipt); err != nil {
			t.Fatal("actual completion race", err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(old)); err != nil {
			t.Fatal(err)
		}
		err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_recovery_status($1::jsonb)`, request).Scan(&receipt)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "40001" {
			t.Fatal("stale pending status accepted after completion", err)
		}
	})
}

// Privileged, rollback-only source corruption must fail under the unchanged
// installed catalog and actual registered compensation identity.
func assertWorkerLifecycleOriginalSource(t *testing.T, ctx context.Context, owner, pool *pgxpool.Pool, start orchestration.StartRequest, stage string) {
	t.Helper()
	var principal string
	if err := pool.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil {
		t.Fatal(err)
	}
	controls := []struct{ name, statement, code string }{
		{"unchanged", `SELECT 1`, ""},
		{"missing-trigger", `DELETE FROM public.zasp_security_agent_trigger_receipts WHERE run_id=$1`, "40001"},
		{"changed-trigger", `UPDATE public.zasp_security_agent_trigger_receipts SET trigger_digest=decode(repeat('00',32),'hex') WHERE run_id=$1`, "40001"},
	}
	if stage == "queued" {
		controls = append(controls, struct{ name, statement, code string }{"planned-without-capture", `UPDATE public.zasp_security_agent_runs SET state='planning',version=version+1 WHERE run_id=$1`, "42501"})
	} else {
		controls = append(controls, struct{ name, statement, code string }{"prepared-missing-capture", "", "42501"})
	}
	for _, control := range controls {
		t.Run("source-"+control.name, func(t *testing.T) {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if control.name == "planned-without-capture" {
				// This is a corrupt-state control, not a legitimate planner
				// transition. Restore the exact native guard before inspecting
				// authority; the transaction always rolls the row change back.
				if _, err = tx.Exec(ctx, `ALTER TABLE public.zasp_security_agent_runs DISABLE TRIGGER zasp_temporal74_mutation`); err != nil {
					t.Fatal(err)
				}
				if tag, err := tx.Exec(ctx, control.statement, start.Ref.RunID); err != nil || tag.RowsAffected() != 1 {
					t.Fatal("create exact rollback-only corrupt state", err)
				}
				if _, err = tx.Exec(ctx, `ALTER TABLE public.zasp_security_agent_runs ENABLE TRIGGER zasp_temporal74_mutation`); err != nil {
					t.Fatal(err)
				}
			} else if control.name == "prepared-missing-capture" {
				if _, err = tx.Exec(ctx, `ALTER TABLE zasp_authorization80_worker.test_associations DISABLE TRIGGER immutable`); err != nil {
					t.Fatal(err)
				}
				for _, table := range []string{"test_state", "test_associations"} {
					if tag, err := tx.Exec(ctx, `DELETE FROM zasp_authorization80_worker.`+table+` WHERE run_id=$1`, start.Ref.RunID); err != nil || tag.RowsAffected() != 1 {
						t.Fatal("remove exact captured source", table, err)
					}
				}
				if _, err = tx.Exec(ctx, `ALTER TABLE zasp_authorization80_worker.test_associations ENABLE TRIGGER immutable`); err != nil {
					t.Fatal(err)
				}
			} else if control.name == "unchanged" {
				if _, err = tx.Exec(ctx, control.statement); err != nil {
					t.Fatal(err)
				}
			} else if tag, err := tx.Exec(ctx, control.statement, start.Ref.RunID); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("mutate exact original source", control.name, err)
			}
			var ready bool
			if err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND zasp_temporal74.current_ready()`).Scan(&ready); err != nil || !ready {
				t.Fatal("source mutation changed installed catalog", err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{principal}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(temporalStartFields(start))
			var result json.RawMessage
			err = tx.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source('inspect',$1::jsonb)`, request).Scan(&result)
			if control.code == "" {
				if err != nil || len(result) == 0 {
					t.Fatal("unchanged original source control", err)
				}
			} else {
				var native *pgconn.PgError
				if !errors.As(err, &native) || native.Code != control.code {
					t.Fatal("changed original source accepted", control.name, err)
				}
			}
		})
	}
}

func assertWorkerLifecycleBindings(t *testing.T, ctx context.Context, owner, pool *pgxpool.Pool, start orchestration.StartRequest, key *authorization.WorkerKey) {
	t.Helper()
	request, _ := json.Marshal(temporalStartFields(start))
	var facts json.RawMessage
	var principal string
	if err := pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source('inspect',$1::jsonb),session_user`, request).Scan(&facts, &principal); err != nil {
		t.Fatal("lifecycle source", err)
	}
	for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "definition_version", "input_digest"} {
		q := temporalStartFields(start)
		q[field] = "pid_7d000099-0000-4000-8000-000000000099"
		if field == "definition_version" {
			q[field] = start.DefinitionVersion + 1
		}
		if field == "input_digest" {
			q[field] = strings.Repeat("0", 64)
		}
		bad, _ := json.Marshal(q)
		var value json.RawMessage
		err := pool.QueryRow(ctx, `SELECT zasp_authorization80_worker.test74_lifecycle_source('inspect',$1::jsonb)`, bad).Scan(&value)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "22023" && native.Code != "40001" && native.Code != "42501" {
			t.Fatal("lifecycle original scope accepted", field, err)
		}
	}
	for _, field := range []string{"control", "definition_digest", "source_digest", "request_digest", "run_version", "job_digest", "effect", "step_id", "child_run_id", "phase", "purpose", "principal", "key", "expired", "repeatable read", "serializable"} {
		var changed map[string]any
		_ = json.Unmarshal(facts, &changed)
		now := time.Now().UnixMilli()
		body := map[string]any{"purpose": "captured-compensation", "key_version": key.Version(), "operation": "test74.lifecycle.inspect", "request": nil, "facts": changed, "revision": authorization.Revision{}, "session_user": principal, "issued_at": now, "expires_at": now + 30000}
		code, isolation := "40001", pgx.ReadCommitted
		switch field {
		case "control":
			code = ""
		case "phase":
			body["operation"], code = "test74.lifecycle.cleanup", "42501"
		case "purpose":
			body["purpose"], code = "worker-forward", "42501"
		case "principal":
			body["session_user"], code = "worker_test_executor", "42501"
		case "key":
			body["key_version"], code = strings.Repeat("0", 64), "42501"
		case "expired":
			body["issued_at"], body["expires_at"], code = now-31000, now-1000, "42501"
		case "repeatable read":
			isolation, code = pgx.RepeatableRead, "25001"
		case "serializable":
			isolation, code = pgx.Serializable, "25001"
		default:
			changed[field] = "changed"
		}
		raw, _ := json.Marshal(body)
		mac := hmac.New(sha256.New, key.Verifier())
		_, _ = mac.Write([]byte("zasp-authorization-captured-compensation-v1\x00"))
		_, _ = mac.Write(raw)
		envelope, _ := json.Marshal(map[string]any{"body": raw, "version": key.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(envelope)); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_temporal74.inspect($1::jsonb)`, request).Scan(&result)
		var native *pgconn.PgError
		valid := errors.As(err, &native) && native.Code == code
		if code == "" {
			var value temporalSingleState
			valid = err == nil && decodeStrictWorkerJSON(result, &value) == nil && value.Phase == "planning"
		}
		if rollback := tx.Rollback(ctx); rollback != nil {
			t.Fatal(rollback)
		}
		if !valid {
			t.Fatal("lifecycle proof", field, err)
		}
	}
	for _, statement := range []string{
		`CREATE OR REPLACE FUNCTION zasp_temporal74.inspect(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_temporal74.cleanup(q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_lifecycle_source(phase text,q jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`CREATE OR REPLACE FUNCTION zasp_authorization80_worker.test74_recovery_observation(q jsonb,locked_parent jsonb,captured_facts jsonb) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_inspect(jsonb) TO zasp_temporal_compensation`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_recovery_status_facts(jsonb,jsonb,jsonb) TO zasp_temporal_executor`,
		`GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_lifecycle_source(text,jsonb) TO zasp_temporal_executor`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
		var refused bool
		err = tx.QueryRow(ctx, `SELECT NOT zasp_authorization80_worker.catalog_ready() AND NOT zasp_temporal74.current_ready() AND NOT zasp_temporal78.current_ready() AND NOT zasp_authorization80_temporal.ready()`).Scan(&refused)
		if rollback := tx.Rollback(ctx); rollback != nil {
			t.Fatal(rollback)
		}
		if err != nil || !refused {
			t.Fatal("lifecycle catalog drift", err)
		}
	}
}
