package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

// These are actual admitted tasks and native provider journals, not seeded
// allow tuples or fabricated effects. The transport consumer follows separately.
func assertWorkerFindingPlanning(t *testing.T, ctx context.Context, f findingResponseFixture, original, revoked string, revokedRef json.RawMessage, complete string, completeRef json.RawMessage, cleanupOnly bool) {
	t.Helper()
	client, config := newAuthorizationProjectionFGA(t)
	checker, err := authorization.NewOpenFGA(client, config)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := authorization.NewOpenFGATupleWriter(client, config)
	if err != nil {
		t.Fatal(err)
	}
	poolFor := func(login string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(f.owner.Config().ConnString())
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User = login
		cfg.ConnConfig.OnPgError = func(_ *pgconn.PgConn, failure *pgconn.PgError) bool {
			t.Logf("planning SQLSTATE=%s message=%s where=%s", failure.Code, failure.Message, failure.Where)
			return failure.Severity != "FATAL"
		}
		cfg.MaxConns = 2
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	var outbox string
	if err := f.owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	projection, err := authorization.NewPostgresProjectionRepository(poolFor(outbox))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
	compensationKey, _ := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
	for _, item := range []struct {
		purpose authorization.WorkerPurpose
		key     *authorization.WorkerKey
	}{{authorization.WorkerForward, key}, {authorization.CapturedCompensation, compensationKey}} {
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(item.purpose), item.key.Version(), item.key.Verifier()); err != nil {
			t.Fatal(err)
		}
	}
	forward, err := authorization.NewWorkerExecutor(poolFor("finding78_executor"), checker, config.StoreID, config.ModelID, key)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPool := poolFor("finding78_compensation")
	cleanup, err := authorization.NewWorkerExecutor(cleanupPool, nil, "", "", compensationKey)
	if err != nil {
		t.Fatal(err)
	}
	if cleanupOnly {
		var q map[string]any
		if err := json.Unmarshal(completeRef, &q); err != nil {
			t.Fatal(err)
		}
		q["reason"] = "workflow_cancelled"
		raw, _ := json.Marshal(q)
		if _, err := cleanup.Authorize(ctx, authorization.FindingCleanup, raw); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("uncaptured queued admission obtained cleanup", err)
		}
		delete(q, "reason")
		delete(q, "input_digest")
		q["operation"] = "reconcile"
		q["payload"] = map[string]any{}
		raw, _ = json.Marshal(q)
		tx, err := cleanupPool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var body json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_temporal78.recover_plan($1::jsonb)`, raw).Scan(&body)
		var refusal *pgconn.PgError
		private := errors.As(err, &refusal) && refusal.Code == "42501"
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !private {
			t.Fatal("registered compensation could bypass public cleanup fence through private helper", err)
		}
	}
	for _, ref := range []json.RawMessage{revokedRef, completeRef} {
		if err := forward.PrepareFinding(ctx, ref); err != nil {
			t.Fatal(err)
		}
	}
	if cleanupOnly {
		var q, other map[string]any
		json.Unmarshal(completeRef, &q)
		json.Unmarshal(revokedRef, &other)
		q["reason"] = "workflow_cancelled"
		q["input_digest"] = other["input_digest"]
		raw, _ := json.Marshal(q)
		if _, err := cleanup.Authorize(ctx, authorization.FindingCleanup, raw); !errors.Is(err, authorization.ErrConflict) {
			t.Fatal("wrong captured queued reference obtained cleanup", err)
		}
	}
	if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, f.o, config.StoreID, config.ModelID); err != nil {
		t.Fatal(err)
	}
	reconcile := func() {
		t.Helper()
		r, err := authorization.Reconcile(ctx, projection, writer, f.o, config.StoreID, config.ModelID)
		if err != nil || !r.Applied {
			t.Fatal("planning machine projection", err)
		}
	}
	reconcile()
	var selection map[string]any
	var rawSelection json.RawMessage
	if err := f.owner.QueryRow(ctx, `SELECT lookup_request-'body'-'body_digest' FROM zasp_temporal78.planning_jobs WHERE run_id=$1`, original).Scan(&rawSelection); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawSelection, &selection); err != nil {
		t.Fatal(err)
	}
	var identity map[string]any
	if err := json.Unmarshal(completeRef, &identity); err != nil {
		t.Fatal(err)
	}
	delete(identity, "input_digest")
	request := func(run, op string, payload any) json.RawMessage {
		q := map[string]any{}
		for k, v := range identity {
			q[k] = v
		}
		q["run_id"] = run
		if op != "state" {
			q["operation"] = op
			if op != "load" && op != "recovery" {
				q["payload"] = payload
			}
		}
		raw, _ := json.Marshal(q)
		return raw
	}
	if !cleanupOnly {
		assertWorkerPlanningProofBindings(t, ctx, f, forward, cleanupPool, key, compensationKey, request(complete, "load", nil), request(revoked, "load", nil))
	}
	call := func(executor *authorization.WorkerExecutor, run, op string, payload any) map[string]any {
		t.Helper()
		d, err := executor.Authorize(ctx, authorization.WorkerOperation("finding.planning."+op), request(run, op, payload))
		if err != nil {
			t.Fatal("authorize planning", op, err)
		}
		raw, err := executor.Execute(ctx, d)
		if err != nil {
			t.Fatal("execute planning", op, err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	provider := func(run string) string {
		var finding string
		if err := f.owner.QueryRow(ctx, `SELECT trigger_id FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&finding); err != nil {
			t.Fatal(err)
		}
		candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Assign investigation", "steps": []any{map[string]any{"index": 0, "action": "update_finding_response", "target_id": finding, "assignee_id": f.actor, "status": "investigating", "note": "Investigate the credential exposure"}}})
		body, _ := json.Marshal(map[string]any{"id": "worker-planning-" + run, "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
		return string(body)
	}
	runs := []string{complete, revoked}
	if cleanupOnly {
		runs = []string{revoked}
	}
	var heldStart authorization.WorkerDecision
	for _, run := range runs {
		if body := call(forward, run, "state", nil); body != nil {
			t.Fatal("fresh planning state was not null")
		}
		if body := call(forward, run, "load", nil); body["state"] != "loaded" {
			t.Fatal("actual planning load")
		}
		reconcile()
		if body := call(forward, run, "prepare", map[string]any{"pricing": selection, "input_version": "worker-input-v1"}); body["state"] != "prepared" {
			t.Fatal("actual planning preparation")
		}
		if cleanupOnly {
			heldStart, err = forward.Authorize(ctx, authorization.WorkerOperation("finding.planning.start"), request(run, "start", map[string]any{}))
			if err != nil {
				t.Fatal("prepared start decision", err)
			}
			break
		}
		if body := call(forward, run, "start", map[string]any{}); body["send_permit"] != true {
			t.Fatal("actual first send permit")
		}
		if body := call(forward, run, "start", map[string]any{}); body["send_permit"] != false {
			t.Fatal("planning retry obtained another send permit")
		}
		if run == revoked {
			break
		}
		call(forward, run, "result", map[string]any{"raw": provider(run)})
		settled := call(forward, run, "settle", map[string]any{})
		call(forward, run, "artifacts", map[string]any{"input_version": "worker-input-v1", "output_version": "worker-output-v1", "output_digest": settled["output_digest"]})
		receipt := call(forward, run, "admit", map[string]any{})
		if receipt["outcome"] != "admitted" || receipt["contract_version"] != float64(78) {
			t.Fatal("current machine did not admit complete native planning")
		}
		reconcile()
	}
	if _, err := f.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := forward.Authorize(ctx, authorization.WorkerOperation("finding.planning.state"), request(revoked, "state", nil)); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("revoked forward planning read accepted", err)
	}
	if cleanupOnly {
		if _, err := forward.Execute(ctx, heldStart); !errors.Is(err, authorization.ErrConflict) {
			t.Fatal("revoked prepared intent received a send permit", err)
		}
		for _, reference := range []json.RawMessage{revokedRef, completeRef} {
			var q map[string]any
			if err := json.Unmarshal(reference, &q); err != nil {
				t.Fatal(err)
			}
			q["reason"] = "workflow_cancelled"
			raw, _ := json.Marshal(q)
			d, err := cleanup.Authorize(ctx, authorization.FindingCleanup, raw)
			var first json.RawMessage
			if err == nil {
				first, err = cleanup.Execute(ctx, d)
			}
			if err != nil {
				t.Errorf("captured %s cleanup failed: %v", map[bool]string{true: "prepared", false: "queued"}[q["run_id"] == revoked], err)
				continue
			}
			d, err = cleanup.Authorize(ctx, authorization.FindingCleanup, raw)
			if err != nil {
				if q["run_id"] == revoked {
					diagnoseWorkerPlanningTerminal(t, ctx, f, revoked)
				}
				t.Error("captured cleanup repeat authority", err)
				continue
			}
			again, err := cleanup.Execute(ctx, d)
			if err != nil || !bytes.Equal(first, again) {
				t.Fatal("captured cleanup repeat changed receipt", err)
			}
			var settled bool
			if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal78.stops WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations WHERE run_id=$1 AND(settled_at IS NOT NULL OR released_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM zasp_temporal78.planning_jobs WHERE run_id=$1 AND state='started')`, q["run_id"]).Scan(&settled); err != nil || !settled {
				t.Fatal("captured cleanup created a send/effect or retained unsent debt", err)
			}
		}
		return
	}
	recovered := call(cleanup, revoked, "reconcile", map[string]any{"raw": provider(revoked)})
	if recovered["state"] != "needs_human" || recovered["run_id"] != revoked {
		t.Fatal("captured recovery receipt")
	}
	for _, field := range []string{"context_value", "input_body", "request_body", "raw_result", "output_body", "result_value", "send_permit"} {
		if _, exists := recovered[field]; exists {
			t.Fatal("recovery disclosed planning body or permit", field)
		}
	}
	read := call(cleanup, revoked, "recovery", nil)
	if read["state"] != "needs_human" || read["usage_known"] != true {
		t.Fatal("captured recovery metadata")
	}
	var exact bool
	if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_temporal78.provider_reservations WHERE run_id=$1 AND settled_at IS NOT NULL AND total_tokens=30 AND cost_nano_credits=30000) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_temporal78.planning_jobs WHERE run_id=$2 AND state='admitted')`, revoked, complete).Scan(&exact); err != nil || !exact {
		t.Fatal("captured accounting or complete admission changed", err)
	}
	if _, err := cleanup.Authorize(ctx, authorization.WorkerOperation("finding.planning.start"), request(revoked, "start", map[string]any{})); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("compensation obtained forward planning", err)
	}
	t.Log("complete native current-machine planning admitted; exact started request settled after revocation without context or another send permit")
}

// Only equality predicates and differing column names leave the owned fixture.
// Native job/context/provider bodies and timestamp values are never logged.
func diagnoseWorkerPlanningTerminal(t *testing.T, ctx context.Context, f findingResponseFixture, run string) {
	t.Helper()
	const probe = `SELECT jsonb_build_object('timezone',current_setting('TimeZone'),'native_terminal_valid',zasp_temporal78.planning_terminal_valid($1,$2,$3,$4),'job_equal',a.body->'job'=to_jsonb(j),'reservation_equal',a.body->'reservation'=to_jsonb(p),'audit_digest_valid',a.event_digest=digest(convert_to(a.body::text,'UTF8'),'sha256'),'reason_equal',a.body->>'reason'=r.last_error_code,'job_different_fields',(SELECT jsonb_agg(k ORDER BY k) FROM jsonb_object_keys(to_jsonb(j)) k WHERE(a.body->'job')->k IS DISTINCT FROM to_jsonb(j)->k),'reservation_different_fields',(SELECT jsonb_agg(k ORDER BY k) FROM jsonb_object_keys(to_jsonb(p)) k WHERE(a.body->'reservation')->k IS DISTINCT FROM to_jsonb(p)->k)) FROM zasp_temporal78.planning_jobs j JOIN zasp_temporal78.provider_reservations p USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_audit a USING(organization_id,workspace_id,environment_id,run_id) WHERE j.run_id=$4 AND a.event_kind='temporal_planning_terminal'`
	for _, zone := range []string{"original", "UTC"} {
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if zone != "original" {
			if _, err := tx.Exec(ctx, `SELECT set_config('TimeZone',$1,true)`, zone); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(err)
			}
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, probe, f.o, f.w, f.e, run).Scan(&result)
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err != nil {
			t.Fatal("terminal equality diagnostic", err)
		}
		t.Logf("planning terminal equality %s", result)
	}
}
