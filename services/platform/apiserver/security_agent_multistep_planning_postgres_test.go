package apiserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// No lease, budget, reservation, intent or result is seeded by this fixture.
// Removing the private claim authority must leave this test red.
func TestSecurityAgentMultistepPlanningClaimPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, testID, actor string) {
		run := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
		first, err := orderedPlanningCall(ctx, worker, q)
		if err != nil {
			t.Fatal("private planning claim absent", err)
		}
		if first["state"] != "claimed" || first["run_id"] != run || first["attempt"] != float64(1) {
			t.Fatalf("claim state: %v", first)
		}
		if first["input_size"] != float64(len(first["input_body"].(string))) {
			t.Fatal("input intent omitted pinned byte size")
		}
		if first["budget_started_at"] == nil || first["budget_deadline_at"] == nil {
			t.Fatal("planning response omitted authoritative budget window")
		}
		again, err := orderedPlanningCall(ctx, worker, q)
		if err != nil || !jsonEqualMaps(first, again) {
			t.Fatal("claim restart changed stable identities", err)
		}
		var counts string
		if err = owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT count(*) FROM zasp_security_agent_run_budgets WHERE run_id=$1),(SELECT count(*) FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE run_id=$1),(SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1))::text`, run).Scan(&counts); err != nil || counts != "[1, 1, 0, 0]" {
			t.Fatal("claim side effects", counts, err)
		}
		q["lease_token"] = "different-worker-lease-0002"
		if _, err = orderedPlanningCall(ctx, worker, q); err == nil {
			t.Fatal("concurrent foreign lease claimed existing work")
		}
	})
}

func orderedPlanningCall(ctx context.Context, c *pgx.Conn, q map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(q)
	var response []byte
	err := c.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.planning($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&response)
	var result map[string]any
	if err == nil {
		err = json.Unmarshal(response, &result)
	}
	return result, err
}

func TestSecurityAgentMultistepPlanningLegacySettlementPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, testID, actor string) {
		run := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
		job, err := orderedPlanningCall(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		// Owner fault fixture isolates the legacy bypass; it is not provider or
		// positive planning authority evidence. A real claim owns the job first.
		_, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest) VALUES($1,$2,$3,$4,1,$5,decode(substring($6 FROM 8),'hex'),'fault-model','fault-policy','openrouter_credit',1000,10000,'ordered-planner',digest(convert_to('ordered-planner-lease-0001','UTF8'),'sha256')); UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, run, job["reservation_id"], job["input_digest"])
		if err != nil {
			t.Fatal(err)
		}
		var response []byte
		err = worker.QueryRow(ctx, `SELECT zasp_security_agent_budget_settle_planner($1,$2,$3,$4,'ordered-planner','ordered-planner-lease-0001',1,$5,decode(repeat('ab',32),'hex'),50,50,100,500)`, o, w, e, run, job["reservation_id"]).Scan(&response)
		if err == nil {
			t.Fatal("legacy settlement mutated private planning reservation after lease loss", string(response))
		}
		var unsettled bool
		if err = owner.QueryRow(ctx, `SELECT settled_at IS NULL FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, run).Scan(&unsettled); err != nil || !unsettled {
			t.Fatal("legacy settlement changed authority", err)
		}
	})
}

// Missing intent, reusable start permits, fabricated usage and admission before
// immutable artifact settlement must all fail this real SQL lifecycle.
func TestSecurityAgentMultistepPlanningLifecyclePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, testID, actor string) {
		run := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
		config := owner.Config().Copy()
		config.User = "security_agent_v33_discovery_api_login"
		admin, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer admin.Close(ctx)
		if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
			t.Fatal(err)
		}
		policy := orderedPricingAdminRequest(o, w, e, actor)
		created, err := orderedPricingCall(ctx, admin, "pricing_admin", policy)
		if err != nil {
			t.Fatal(err)
		}
		selection := orderedPricingLookupRequest(o, w, e, policy["policy"].(map[string]any), created)
		delete(selection, "body")
		delete(selection, "body_digest")
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "ordered-planner", "lease_token": "ordered-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
		job, err := orderedPlanningCall(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		q["operation"] = "prepare"
		q["payload"] = map[string]any{"pricing": selection, "input_version": "component-input-version-1"}
		job, err = orderedPlanningCall(ctx, worker, q)
		if err != nil {
			t.Fatal("committed intent unavailable", err)
		}
		if job["state"] != "prepared" || job["request_body"] == "" {
			t.Fatal("intent missing exact body", job)
		}
		if again, err := orderedPlanningCall(ctx, worker, q); err != nil || !jsonEqualMaps(job, again) {
			t.Fatal("intent restart changed", err)
		}
		q["operation"] = "admit"
		q["payload"] = map[string]any{}
		if _, err = orderedPlanningCall(ctx, worker, q); err == nil {
			t.Fatal("admission before provider/artifact/usage evidence")
		}
		q["operation"] = "start"
		job, err = orderedPlanningCall(ctx, worker, q)
		if err != nil || job["send_permit"] != true {
			t.Fatal("first start", err, job)
		}
		job, err = orderedPlanningCall(ctx, worker, q)
		if err != nil || job["send_permit"] != false {
			t.Fatal("lost start acknowledgement allowed resend", err, job)
		}
		candidate := map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": e}, map[string]any{"index": 1, "action": "run_test", "target_id": testID}}}
		content, _ := json.Marshal(candidate)
		raw, _ := json.Marshal(map[string]any{"model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(content)}}}, "usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 50, "total_tokens": 100, "cost": 0.0000005}})
		q["operation"] = "result"
		q["payload"] = map[string]any{"raw": string(raw)}
		job, err = orderedPlanningCall(ctx, worker, q)
		if err != nil || job["state"] != "completed" || job["raw_result"] != string(raw) {
			t.Fatal("durable exact provider result", err, job)
		}
		q["operation"] = "settle"
		q["payload"] = map[string]any{}
		job, err = orderedPlanningCall(ctx, worker, q)
		if err != nil || job["state"] != "settled" {
			t.Fatal("actual usage settlement", err, job)
		}
		q["operation"] = "admit"
		if _, err = orderedPlanningCall(ctx, worker, q); err == nil {
			t.Fatal("admission before output artifact")
		}
		q["operation"] = "artifacts"
		q["payload"] = map[string]any{"input_version": "component-input-version-1", "output_version": "component-output-version-1", "output_digest": job["output_digest"]}
		if _, err = orderedPlanningCall(ctx, worker, q); err != nil {
			t.Fatal("artifact receipt", err)
		}
		q["operation"] = "admit"
		q["payload"] = map[string]any{}
		receipt, err := orderedPlanningCall(ctx, worker, q)
		if err != nil || receipt["outcome"] != "admitted" {
			t.Fatal("reviewed admission boundary", err, receipt)
		}
		if again, err := orderedPlanningCall(ctx, worker, q); err != nil || !jsonEqualMaps(receipt, again) {
			t.Fatal("admission replay changed identities", err, again)
		}
		var total, cost int64
		if err = owner.QueryRow(ctx, `SELECT total_tokens,cost_nano_credits FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, run).Scan(&total, &cost); err != nil || total != 100 || cost != 500 {
			t.Fatal("invented settlement", total, cost, err)
		}
	})
}

func seedOrderedPlanningQueue(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, testID, actor string) string {
	t.Helper()
	definition := "pid_8c200001-0000-4000-8000-000000000002"
	finding := "pid_8c300001-0000-4000-8000-000000000003"
	var run string
	if err := owner.QueryRow(ctx, `SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_run',$4||chr(31)||$5||chr(31)||'1')`, o, w, e, definition, finding).Scan(&run); err != nil {
		t.Fatal(err)
	}
	_, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($7,$1,'planning-org','planning-actor','security_engineer') ON CONFLICT DO NOTHING;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($7,$1,$2,$3,'Private planning','["view","manage_workflows","run_tests"]') ON CONFLICT DO NOTHING;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'run_test',true,$7) ON CONFLICT DO NOTHING;
 INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$5,'supervised',1,1,jsonb_build_object('id',$5,'name','Contain and retest','trigger_kind','finding','trigger_source','credential','environment_ids',jsonb_build_array($3),'autonomy','supervised','max_steps',2,'max_duration_seconds',3600,'temporary_policy_seconds',600,'ai_token_budget',4000,'max_ai_cost_nano_credits',10000000,'concurrency_limit',10,'allowed_actions',jsonb_build_array('create_temporary_policy','run_test'),'verification_kind','test_run','definition_version',1,'enabled',true,'existing_test',jsonb_build_object('definition_id',$8,'definition_version',1)),'security-agent-actions-v1');
 INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$6,'posture','credential','Ordered planner trigger','high','open');
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,version,attempt) VALUES($1,$2,$3,$4,$5,1,$6,$7,'queued',1,0);
 INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES($1,$2,$3,$5,$6,'finding',1,decode(repeat('cd',32),'hex'),$4)`, pgx.QueryExecModeSimpleProtocol, o, w, e, run, definition, finding, actor, testID)
	if err != nil {
		t.Fatal(err)
	}
	return run
}
