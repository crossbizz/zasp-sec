package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const public62Definition = "pid_8d200001-0000-4000-8000-000000000002"
const public62Finding = "pid_8d300001-0000-4000-8000-000000000003"

func public62Seed(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, testID, actor string) {
	t.Helper()
	_, err := owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($6,$1,'public62-org','public62-actor','security_engineer') ON CONFLICT DO NOTHING;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($6,$1,$2,$3,'Public62','["view","manage_workflows","run_tests"]') ON CONFLICT DO NOTHING;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'run_test',true,$6) ON CONFLICT DO NOTHING;
 INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version) VALUES($1,$2,$3,$4,'draft',1,1,jsonb_build_object('id',$4,'name','Contain and retest','trigger_kind','finding','trigger_source','credential','environment_ids',jsonb_build_array($3),'autonomy','supervised','max_steps',2,'max_duration_seconds',3600,'temporary_policy_seconds',600,'ai_token_budget',4000,'max_ai_cost_nano_credits',10000000,'concurrency_limit',10,'allowed_actions',jsonb_build_array('create_temporary_policy','run_test'),'verification_kind','test_run','definition_version',1,'enabled',false,'existing_test',jsonb_build_object('definition_id',$7,'definition_version',1)),'security-agent-actions-v1');
 INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$5,'posture','credential','Public trigger','high','open')`, pgx.QueryExecModeSimpleProtocol, o, w, e, public62Definition, public62Finding, actor, testID)
	if err != nil {
		t.Fatal(err)
	}
}

func public62Call(ctx context.Context, c *pgx.Conn, q map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(q)
	var response []byte
	err := c.QueryRow(ctx, `SELECT zasp_ordered_public62.api($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentPublic().Checksum(), migrations.SecurityAgentPublicFingerprint(), raw).Scan(&response)
	var result map[string]any
	if err == nil {
		err = json.Unmarshal(response, &result)
	}
	return result, err
}

func public62Request(o, w, e, actor, op string) map[string]any {
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "actor_id": actor, "operation": op}
}

func TestSecurityAgentRelease62PublicLifecyclePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		if ready, err := public62Call(ctx, api, public62Request(o, w, e, actor, "ready")); err != nil || ready["ready"] != true {
			t.Fatal("authenticated readiness", ready, err)
		}
		for _, extra := range []string{"unknown", strings.Repeat("x", 16385)} {
			invalid := public62Request(o, w, e, actor, "ready")
			invalid["extra"] = extra
			if _, err := public62Call(ctx, api, invalid); err == nil {
				t.Fatal("open or oversized request accepted")
			}
		}
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 1
		activated, err := public62Call(ctx, api, q)
		if err != nil || activated["definition_version"] != float64(2) {
			t.Fatal("exact draft activation", activated, err)
		}
		q = public62Request(o, w, e, actor, "trigger")
		q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "public62-trigger-0001"
		created, err := public62Call(ctx, api, q)
		if err != nil || created["state"] != "queued" {
			t.Fatal("public queued run", created, err)
		}
		run := created["run_id"].(string)
		var fabricated bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) OR EXISTS(SELECT 1 FROM zasp_security_agent_steps WHERE run_id=$1) OR EXISTS(SELECT 1 FROM zasp_security_agent_approvals WHERE run_id=$1) OR EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets WHERE run_id=$1) OR EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) OR EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1)`, run).Scan(&fabricated); err != nil || fabricated {
			t.Fatal("public trigger fabricated execution authority", fabricated, err)
		}
		before := orderedAdmissionSnapshot(t, ctx, owner, run)
		if replay, err := public62Call(ctx, api, q); err != nil || !jsonEqualMaps(created, replay) {
			t.Fatal("exact replay", err)
		}
		if orderedAdmissionSnapshot(t, ctx, owner, run) != before {
			t.Fatal("replay changed authority")
		}
		restarted, err := pgx.ConnectConfig(ctx, api.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restarted.Close(ctx)
		if replay, err := public62Call(ctx, restarted, q); err != nil || !jsonEqualMaps(created, replay) || orderedAdmissionSnapshot(t, ctx, owner, run) != before {
			t.Fatal("restarted trigger replay changed authority", err)
		}
		var savedResponse []byte
		if err = owner.QueryRow(ctx, `SELECT response FROM zasp_security_agent_request_receipts WHERE resource_id=$1`, run).Scan(&savedResponse); err != nil {
			t.Fatal(err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET response=response||'{"credential_reference":"ref:private-secret"}'::jsonb WHERE resource_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		if _, err = public62Call(ctx, api, q); err == nil {
			t.Fatal("malformed replay response returned private fields")
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_request_receipts SET response=$2::jsonb WHERE resource_id=$1`, run, savedResponse); err != nil {
			t.Fatal(err)
		}
		q["trigger_version"] = 2
		if _, err := public62Call(ctx, api, q); err == nil {
			t.Fatal("conflicting replay accepted")
		}
		if orderedAdmissionSnapshot(t, ctx, owner, run) != before {
			t.Fatal("conflicting replay mutated")
		}
		detail := public62Request(o, w, e, actor, "detail")
		detail["run_id"] = run
		projection, err := public62Call(ctx, api, detail)
		if err != nil || projection["state"] != "queued" || len(projection["steps"].([]any)) != 0 {
			t.Fatal("queued projection", projection, err)
		}
		for _, secret := range []string{"lease_token", "lease_owner", "worker_id", "credential_reference", "input_body", "artifact", "envelope", "receipt_body"} {
			raw, _ := json.Marshal(projection)
			if strings.Contains(string(raw), secret) {
				t.Fatal("private field disclosed", secret)
			}
		}
		page := public62Request(o, w, e, actor, "list")
		page["limit"], page["after_run_id"] = 1, ""
		listed, err := public62Call(ctx, api, page)
		if err != nil || len(listed["items"].([]any)) != 1 || listed["items"].([]any)[0].(map[string]any)["run_id"] != run {
			t.Fatal("bounded list absent", listed, err)
		}
		page["limit"] = 26
		if _, err = public62Call(ctx, api, page); err == nil {
			t.Fatal("unbounded page accepted")
		}
		before = public62Snapshot(t, ctx, owner)
		foreign := public62Request("pid_ffffffff-ffff-4fff-8fff-ffffffffffff", w, e, actor, "detail")
		foreign["run_id"] = run
		_, foreignErr := public62Call(ctx, api, foreign)
		missing := public62Request(o, w, e, actor, "detail")
		missing["run_id"] = "pid_ffffffff-ffff-4fff-8fff-ffffffffffff"
		_, missingErr := public62Call(ctx, api, missing)
		if foreignErr == nil || missingErr == nil || foreignErr.Error() != missingErr.Error() {
			t.Fatal("foreign and missing distinguishable", foreignErr, missingErr)
		}
		if public62Snapshot(t, ctx, owner) != before {
			t.Fatal("foreign attempt mutated owner snapshot")
		}
		claim := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "public62-planner", "lease_token": "public62-planner-lease-0001", "operation": "claim", "payload": map[string]any{}}
		if planned, err := orderedPlanningCall(ctx, worker, claim); err != nil || planned["state"] != "claimed" {
			t.Fatal("public input unusable by private planner", planned, err)
		}
		if projection, err = public62Call(ctx, api, detail); err != nil || projection["state"] != "planning" {
			t.Fatal("planning projection", projection, err)
		}
	})
}

func TestSecurityAgentRelease62ActivationRefusalsPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		var original []byte
		if err := owner.QueryRow(ctx, `SELECT body FROM zasp_security_agent_definitions WHERE definition_id=$1`, public62Definition).Scan(&original); err != nil {
			t.Fatal(err)
		}
		for name, patch := range map[string]string{
			"reversed":          `{"allowed_actions":["run_test","create_temporary_policy"]}`,
			"duplicate":         `{"allowed_actions":["create_temporary_policy","create_temporary_policy"]}`,
			"partial":           `{"allowed_actions":[]}`,
			"standalone":        `{"allowed_actions":["run_test"]}`,
			"extra":             `{"allowed_actions":["create_temporary_policy","run_test","update_finding"]}`,
			"autonomous":        `{"autonomy":"autonomous"}`,
			"enabled":           `{"enabled":true}`,
			"verification":      `{"verification_kind":"none"}`,
			"steps":             `{"max_steps":1}`,
			"no-environment":    `{"environment_ids":[]}`,
			"many-environments": `{"environment_ids":["` + e + `","pid_ffffffff-ffff-4fff-8fff-ffffffffffff"]}`,
			"no-reference":      `{"existing_test":null}`,
			"unpinned":          `{"existing_test":{"definition_id":"` + testID + `","definition_version":0}}`,
			"stale-test":        `{"existing_test":{"definition_id":"` + testID + `","definition_version":2}}`,
			"inaccessible-test": `{"existing_test":{"definition_id":"pid_ffffffff-ffff-4fff-8fff-ffffffffffff","definition_version":1}}`,
			"wrong-target":      `{"existing_test":{"definition_id":"` + e + `","definition_version":1}}`,
			"no-cost":           `{"max_ai_cost_nano_credits":null}`,
			"zero-cost":         `{"max_ai_cost_nano_credits":0}`,
			"unbounded-cost":    `{"max_ai_cost_nano_credits":1000000000001}`,
			"wrong-trigger":     `{"trigger_kind":"manual"}`,
			"unknown-field":     `{"private":true}`,
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=$2::jsonb||$3::jsonb WHERE definition_id=$1`, public62Definition, original, patch); err != nil {
					if pg, ok := err.(*pgconn.PgError); name == "autonomous" && ok && pg.Code == "23514" && pg.ConstraintName == "zasp_security_agent_temporary_policy_supervised_check" {
						return
					}
					t.Fatal(err)
				}
				q := public62Request(o, w, e, actor, "activate")
				q["definition_id"], q["definition_version"] = public62Definition, 1
				before := public62Snapshot(t, ctx, owner)
				if _, err := public62Call(ctx, api, q); err == nil {
					t.Fatal("invalid family accepted")
				}
				if public62Snapshot(t, ctx, owner) != before {
					t.Fatal("refusal changed owner state")
				}
			})
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=$2::jsonb WHERE definition_id=$1`, public62Definition, original); err != nil {
			t.Fatal(err)
		}
		q := public62Request(o, w, e, actor, "activate")
		q["definition_id"], q["definition_version"] = public62Definition, 2
		if _, err := public62Call(ctx, api, q); err == nil {
			t.Fatal("stale definition version accepted")
		}
	})
}

func public62Snapshot(t *testing.T, ctx context.Context, owner *pgx.Conn) string {
	t.Helper()
	var result string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t) ORDER BY definition_id) FROM zasp_security_agent_definitions t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY definition_id,version) FROM zasp_security_agent_definition_versions t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY run_id) FROM zasp_security_agent_runs t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY audit_id) FROM zasp_security_agent_audit t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY receipt_id) FROM zasp_security_agent_request_receipts t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY run_id) FROM zasp_security_agent_trigger_receipts t))::text`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
