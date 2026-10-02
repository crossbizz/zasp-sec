package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type plannerTimezoneNoChecks struct{ calls int }

type plannerTimezoneQueryTrace struct{ t *testing.T }
type plannerTimezoneTraceKey struct{}
type plannerTimezoneTraceState struct {
	entry, phase string
	started      time.Time
}

func plannerTimezoneTracer(t *testing.T, existing pgx.QueryTracer) pgx.QueryTracer {
	trace := &plannerTimezoneQueryTrace{t: t}
	if existing != nil {
		return multitracer.New(existing, trace)
	}
	return trace
}

func (p *plannerTimezoneQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	state := plannerTimezoneTraceState{phase: "none", started: time.Now()}
	for _, name := range []string{"zasp_temporal74.plan", "zasp_temporal78.plan", "zasp_authorization80_worker.planning74_source", "zasp_authorization80_worker.planning78_source", "zasp_authorization80_worker.planning74_recovery", "zasp_authorization80_worker.planning78_recovery", "zasp_authorization80_worker.prepare_test74", "zasp_temporal74.inspect"} {
		if strings.Contains(data.SQL, name+"(") {
			state.entry = name
			break
		}
	}
	allowedPhase := func(value string) bool {
		switch value {
		case "state", "load", "prepare", "start", "result", "settle", "artifacts", "admit", "recovery", "reconcile", "late_usage":
			return true
		}
		return false
	}
	for _, arg := range data.Args {
		var raw []byte
		switch value := arg.(type) {
		case string:
			if allowedPhase(value) {
				state.phase = value
			}
			raw = []byte(value)
		case []byte:
			raw = value
		case json.RawMessage:
			raw = value
		}
		var request struct {
			Operation string `json:"operation"`
		}
		if json.Unmarshal(raw, &request) == nil && allowedPhase(request.Operation) {
			state.phase = request.Operation
		}
	}
	return context.WithValue(ctx, plannerTimezoneTraceKey{}, state)
}

func (p *plannerTimezoneQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	state, ok := ctx.Value(plannerTimezoneTraceKey{}).(plannerTimezoneTraceState)
	if !ok || state.entry == "" {
		return
	}
	code, class := "none", "ok"
	if data.Err != nil {
		class = "query_error"
		var pgerr *pgconn.PgError
		if errors.As(data.Err, &pgerr) {
			if len(pgerr.Code) == 5 && strings.Trim(pgerr.Code, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
				code = pgerr.Code
			}
			class = "database_error"
			// Fixed catalog literals map to fixed labels. Never print Message,
			// Where, SQL, arguments, receipts, contexts or provider data.
			classes := map[string]string{"worker proof rejected": "worker_proof", "worker planning proof binding rejected": "planning_proof_binding", "worker authorization revision changed": "authorization_revision", "worker planning source changed": "planning_source", "worker test source reader rejected": "test_source_reader", "worker test source role rejected": "test_source_role", "worker test task inactive": "test_task_inactive", "worker test capture changed": "test_capture", "worker test association missing": "test_association", "executor planning unavailable": "planning_unavailable", "executor planning authority changed": "planning_authority", "executor input artifact rejected": "input_artifact", "executor pricing scope rejected": "pricing_scope", "executor pricing exceeds budget": "pricing_budget", "executor intent conflict": "intent_conflict", "pricing lookup rejected": "pricing_lookup", "pricing prepared request rejected": "pricing_prepared_request", "pricing worker principal rejected": "pricing_principal", "pricing request authority mismatch": "pricing_authority", "pricing current authority unavailable": "pricing_current_authority"}
			if known := classes[pgerr.Message]; known != "" {
				class = known
			}
		} else if errors.Is(data.Err, context.DeadlineExceeded) {
			class = "deadline"
		} else if errors.Is(data.Err, context.Canceled) {
			class = "cancelled"
		}
	}
	p.t.Logf("timezone SQL entry=%s phase=%s elapsed_ms=%d sqlstate=%s class=%s", state.entry, state.phase, time.Since(state.started).Milliseconds(), code, class)
}

func (c *plannerTimezoneNoChecks) Check(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
	c.calls++
	return authorization.Decision{}, errors.New("captured timezone replay attempted a fresh Check")
}

type workerPlannerTimezone struct {
	t          *testing.T
	dsn        string
	family     workerPlanningFamily
	start      orchestration.StartRequest
	original   *authorization.WorkerExecutor
	pools      []*pgxpool.Pool
	checks     plannerTimezoneNoChecks
	backendIDs map[int32]bool
}

func configureWorkerPlannerTimezone(t *testing.T, ctx context.Context, dsn string, product *temporalSecurityAgentProduct, start orchestration.StartRequest, mode string, family workerPlanningFamily) (string, *workerPlannerTimezone) {
	if !strings.HasSuffix(mode, "-timezone") {
		return mode, nil
	}
	mode = strings.TrimSuffix(mode, "-timezone")
	if mode != "planning-prepared-revoke" && mode != "planning-sent-revoke" && mode != "planning-sent-late" {
		t.Fatal("unknown timezone recovery mode")
	}
	p := &workerPlannerTimezone{t: t, dsn: dsn, family: family, start: start, backendIDs: map[int32]bool{}}
	t.Cleanup(func() {
		for _, pool := range p.pools {
			pool.Close()
		}
	})
	p.original = p.connect(ctx, "America/Los_Angeles")
	product.workerCompensation = p.original
	if mode == "planning-sent-late" {
		// The provider handler terminalizes through original, while the product
		// consumes the arriving late response through a different UTC session.
		product.workerCompensation = p.connect(ctx, "UTC")
	}
	return mode, p
}

func (p *workerPlannerTimezone) connect(ctx context.Context, zone string) *authorization.WorkerExecutor {
	p.t.Helper()
	cfg, err := pgxpool.ParseConfig(p.dsn)
	if err != nil {
		p.t.Fatal("timezone compensation config", err)
	}
	cfg.ConnConfig.User = "finding78_compensation"
	if p.family == workerPlanningTest74 {
		cfg.ConnConfig.User = "worker_test_compensation"
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = zone
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		p.t.Fatal("timezone compensation pool", err)
	}
	p.pools = append(p.pools, pool)
	var actual, principal string
	var backendID int32
	if err := pool.QueryRow(ctx, `SELECT current_setting('TimeZone'),session_user,pg_backend_pid()`).Scan(&actual, &principal, &backendID); err != nil || actual != zone || principal != cfg.ConnConfig.User || p.backendIDs[backendID] {
		p.t.Fatal("timezone or registered compensation session mismatch", err)
	}
	p.backendIDs[backendID] = true
	key, err := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	if err != nil {
		p.t.Fatal(err)
	}
	machine, err := authorization.NewWorkerExecutor(pool, &p.checks, "", "", key)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := machine.Ready(ctx); err != nil {
		p.t.Fatal("timezone compensation readiness", err)
	}
	return machine
}

func workerPlannerTerminalExecutor(product *temporalSecurityAgentProduct, p *workerPlannerTimezone) *authorization.WorkerExecutor {
	if p != nil {
		return p.original
	}
	return product.workerCompensation
}

// Read only bounded state when a case does not reach its intended fault. This
// distinguishes absent preparation from an observer join failure; it never
// changes the run, deadline, receipt or authorization result.
func (p *workerPlannerTimezone) diagnose(ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, stage string, calls int32, fault bool) {
	if p == nil {
		return
	}
	p.t.Helper()
	namespace, association := "zasp_temporal78", "associations"
	if p.family == workerPlanningTest74 {
		namespace, association = "zasp_temporal74", "test_associations"
	}
	var state json.RawMessage
	query := `SELECT jsonb_build_object('run_state',(SELECT state FROM zasp_security_agent_runs WHERE run_id=$1),'terminal_reason',(SELECT last_error_code FROM zasp_security_agent_runs WHERE run_id=$1),'jobs',(SELECT count(*) FROM ` + namespace + `.planning_jobs WHERE run_id=$1),'job_state',(SELECT state FROM ` + namespace + `.planning_jobs WHERE run_id=$1),'reservations',(SELECT count(*) FROM ` + namespace + `.provider_reservations WHERE run_id=$1),'associations',(SELECT count(*) FROM zasp_authorization80_worker.` + association + ` WHERE run_id=$1),'terminal_receipts',(SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal'),'dispatch_state',(SELECT body->>'dispatch_state' FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_terminal'),'budget_future',(SELECT deadline_at>clock_timestamp() FROM zasp_security_agent_run_budgets WHERE run_id=$1),'job_deadline_future',(SELECT budget_deadline_at>clock_timestamp() FROM ` + namespace + `.planning_jobs WHERE run_id=$1))`
	if err := owner.QueryRow(ctx, query, p.start.Ref.RunID).Scan(&state); err != nil {
		p.t.Fatal("timezone bounded state diagnostic", err)
	}
	request, _ := json.Marshal(temporalStartFields(p.start))
	raw, err := product.executor.QueryJSON(ctx, `SELECT `+namespace+`.inspect($1::jsonb)`, request)
	var inspected struct {
		Phase string `json:"phase"`
	}
	if err != nil || json.Unmarshal(raw, &inspected) != nil {
		p.t.Fatal("timezone bounded phase diagnostic", err)
	}
	deadline, hasDeadline := ctx.Deadline()
	p.t.Logf("timezone state stage=%s provider_calls=%d fault=%t phase=%s caller_deadline_future=%t state=%s", stage, calls, fault, inspected.Phase, hasDeadline && time.Until(deadline) > 0, state)
}

func (p *workerPlannerTimezone) assertReplay(ctx context.Context, owner *pgxpool.Pool, product *temporalSecurityAgentProduct, mode string, late any) {
	if p == nil {
		return
	}
	p.t.Helper()
	namespace, association, prefix := "zasp_temporal78", "associations", "finding.planning."
	if p.family == workerPlanningTest74 {
		namespace, association, prefix = "zasp_temporal74", "test_associations", "test74.planning."
	}
	var response []byte
	if mode == "planning-sent-late" {
		var ok bool
		response, ok = late.([]byte)
		if !ok || len(response) == 0 {
			p.t.Fatal("timezone late response unavailable")
		}
	}
	// Only observer reads use the owner. Every recovery and rejection below
	// goes through a fresh registered compensation login and the signed API.
	snapshot := func() string {
		var result string
		q := `SELECT jsonb_build_object('job',to_jsonb(j),'reservation',to_jsonb(p),'association',to_jsonb(x),'audit',(SELECT jsonb_agg(jsonb_build_object('id',audit_id,'body',body,'digest',encode(event_digest,'hex')) ORDER BY event_kind) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind IN('temporal_planning_terminal','temporal_planning_late_usage')),'late',(SELECT jsonb_agg(to_jsonb(l)) FROM ` + namespace + `.planning_late_usage l WHERE run_id=$1),'budget',(SELECT to_jsonb(b) FROM zasp_security_agent_run_budgets b WHERE run_id=$1))::text FROM ` + namespace + `.planning_jobs j JOIN ` + namespace + `.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_authorization80_worker.` + association + ` x USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$1`
		if err := owner.QueryRow(ctx, q, p.start.Ref.RunID).Scan(&result); err != nil {
			p.t.Fatal("timezone evidence snapshot", err)
		}
		return result
	}
	before := snapshot()
	var valid, originalZone bool
	if err := owner.QueryRow(ctx, `SELECT bool_and(event_digest=digest(convert_to(body::text,'UTF8'),'sha256')),bool_and(CASE WHEN event_kind='temporal_planning_terminal' THEN body->'reservation'->>'reserved_at' ~ '-0[78]:00$' ELSE true END) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind IN('temporal_planning_terminal','temporal_planning_late_usage')`, p.start.Ref.RunID).Scan(&valid, &originalZone); err != nil || !valid || !originalZone {
		p.t.Fatal("original-zone terminal evidence/digest", err)
	}
	if mode == "planning-sent-late" {
		if err := owner.QueryRow(ctx, `SELECT body->'reservation'->>'settled_at' ~ '[+]00:00$' FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='temporal_planning_late_usage'`, p.start.Ref.RunID).Scan(&valid); err != nil || !valid {
			p.t.Fatal("late usage did not cross from original zone to UTC", err)
		}
	}
	identity := temporalStartFields(p.start)
	delete(identity, "input_digest")
	encoded, _ := json.Marshal(identity)
	for _, zone := range []string{"UTC", "Asia/Kolkata"} {
		compensation := p.connect(ctx, zone)
		database := &workerFindingPlanningDatabase{base: product.executor, forward: product.workerForward, compensation: compensation, start: p.start, family: p.family}
		for n := 0; n < 2; n++ {
			if err := database.RecoverCapturedPlanning(ctx, encoded, response); err != nil {
				p.t.Fatal("fresh timezone exact captured recovery", zone, err)
			}
		}
		for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id", "definition_version"} {
			changed := map[string]any{}
			for k, v := range identity {
				changed[k] = v
			}
			if field == "definition_version" {
				changed[field] = p.start.DefinitionVersion + 1
			} else {
				changed[field] = "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"
			}
			changed["operation"], changed["payload"] = "reconcile", map[string]any{}
			raw, _ := json.Marshal(changed)
			d, err := compensation.Authorize(ctx, authorization.WorkerOperation(prefix+"reconcile"), raw)
			if err == nil {
				_, err = compensation.Execute(ctx, d)
			}
			if err == nil {
				p.t.Fatal("timezone replay accepted foreign captured association", field)
			}
		}
		if len(response) > 0 {
			var changed map[string]any
			if json.Unmarshal(response, &changed) != nil {
				p.t.Fatal("invalid original provider response")
			}
			changed["id"] = "timezone-foreign-response"
			raw, _ := json.Marshal(changed)
			if err := database.RecoverCapturedPlanning(ctx, encoded, raw); err == nil {
				p.t.Fatal("timezone late replay accepted changed response")
			}
		}
		if after := snapshot(); after != before {
			p.t.Fatal("timezone replay/control changed audit bytes, association or accounting")
		}
	}
	if p.checks.calls != 0 {
		p.t.Fatal("captured timezone recovery performed fresh Checks", p.checks.calls)
	}
	if err := owner.QueryRow(ctx, `SELECT zasp_authorization80_worker.catalog_ready() AND NOT zasp_authorization80_worker.runtime_ready() AND `+namespace+`.current_ready()`).Scan(&valid); err != nil || !valid {
		p.t.Fatal("timezone replay changed catalog or opened partial runtime", err)
	}
	p.t.Log("timezone terminal/replay: original Los Angeles; fresh UTC and Kolkata; immutable audit/accounting/association; no fresh Checks")
}
