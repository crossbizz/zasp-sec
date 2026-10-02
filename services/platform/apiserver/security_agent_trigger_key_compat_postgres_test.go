package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityAgentTriggerKeyLegacyDedupPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		const definition = "pid_ffffffff-ffff-4fff-8fff-fffffffffff1"
		triggerKeyLegacyFixture(t, ctx, owner, api, o, w, e, actor, definition, "review-legacy-first-key")
		// Model the established definition-edit sync resetting activation to draft.
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation='draft',version=version+1,body=body||'{"enabled":false}'::jsonb WHERE definition_id=$1`, definition); err != nil {
			t.Fatal(err)
		}
		for i, target := range []string{"validated", "supervised"} {
			var raw []byte
			args := []any{o, w, e, definition, actor, fmt.Sprintf("review-activation-%d", i), i + 4, target, time.Now().UTC().Add(4 * time.Minute), fmt.Sprintf("pid_c%d000001-0000-4000-8000-000000000001", i), fmt.Sprintf("pid_c%d000002-0000-4000-8000-000000000002", i), fmt.Sprintf("pid_c%d000003-0000-4000-8000-000000000003", i)}
			if err := api.QueryRow(ctx, postgresSecurityAgentActivateSQL, args...).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
		const key = "review-legacy-dedup-key"
		args := []any{o, w, e, definition, actor, key, 6, "pid_c2000001-0000-4000-8000-000000000001", "finding", public62Finding, "pid_c2000002-0000-4000-8000-000000000002", "pid_c2000003-0000-4000-8000-000000000003", "pid_c2000004-0000-4000-8000-000000000004"}
		var raw []byte
		if err := api.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		t.Logf("real legacy dedup result: %s", raw)
		if result["replayed"] != true {
			t.Fatal("expected genuine dedup")
		}
		// Confirm the ordinary legacy replay itself succeeds, without owner writes.
		if err := api.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw); err != nil {
			t.Fatal("legacy replay", err)
		}
		got, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, actor, definition, key))
		if err != nil || got["family"] != "legacy_or_missing" {
			t.Fatalf("genuine legacy receipt refused: %v %v", got, err)
		}
	})
}

func TestSecurityAgentTriggerKeyLegacySessionPostgres(t *testing.T) {
	for _, sequence := range []int64{1, 1000001, 9223372036854775807} {
		t.Run(fmt.Sprint(sequence), func(t *testing.T) { triggerKeyLegacySessionSequence(t, sequence) })
	}
}

func triggerKeyLegacySessionSequence(t *testing.T, sequence int64) {
	t.Helper()
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		const definition = "pid_bfffffff-ffff-4fff-8fff-fffffffffff1"
		const session = "pid_bfffffff-ffff-4fff-8fff-fffffffffff2"
		const key = "review-session-trigger-key"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id',$1,'activation','supervised','body',(body-'existing_test')||jsonb_build_object('id',$1,'enabled',true,'trigger_kind','runtime_decision','trigger_source','gateway','allowed_actions',jsonb_build_array('isolate_session'),'verification_kind','gateway_decision','max_steps',1)))).* FROM zasp_security_agent_definitions d WHERE definition_id=$2;
   INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($3,$4,$5,'isolate_session',true,$6);
   INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) VALUES($3,$4,$5,$7,$7,$8,$9,decode(repeat('01',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id',$8),clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, definition, public62Definition, o, w, e, actor, orderedApplicationDevice, session, sequence); err != nil {
			t.Fatal(err)
		}
		args := []any{o, w, e, definition, actor, key, 1, "pid_b2000001-0000-4000-8000-000000000001", "session", session, "pid_b2000002-0000-4000-8000-000000000002", "pid_b2000003-0000-4000-8000-000000000003", "pid_b2000004-0000-4000-8000-000000000004"}
		var raw []byte
		if err := api.QueryRow(ctx, postgresSecurityAgentRunV24SQL, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		got, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, actor, definition, key))
		if err != nil || got["family"] != "legacy_or_missing" {
			t.Fatal("valid session", got, err)
		}
		t.Log("valid genuine session receipt classified legacy")
		for name, mutation := range map[string][2]string{
			"trigger_version":       {"trigger_version", `{}`},
			"version-string":        {"trigger_version", `"1"`},
			"version-zero":          {"trigger_version", `0`},
			"version-negative":      {"trigger_version", `-1`},
			"version-overflow":      {"trigger_version", `9223372036854775808`},
			"version-huge":          {"trigger_version", `1e100`},
			"version-fraction":      {"trigger_version", `1.5`},
			"version-large-unbound": {"trigger_version", `1000002`},
			"version-unbound":       {"trigger_version", `2`},
			"device_id":             {"device_id", `{}`},
			"device-invalid":        {"device_id", `"invalid"`},
			"device-unbound":        {"device_id", `"pid_bfffffff-ffff-4fff-8fff-fffffffffff3"`},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, "ROLLBACK")
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_audit SET body=jsonb_set(body,ARRAY[$1],$2::jsonb) WHERE audit_id='pid_b2000002-0000-4000-8000-000000000002'`, mutation[0], mutation[1]); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{api.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				got, err := public62Call(ctx, owner, triggerKeyRequest(o, w, e, actor, definition, key))
				if pg, ok := err.(*pgconn.PgError); !ok || pg.Code != "40001" {
					t.Errorf("malformed legacy session proof must be unavailable: %v %v", got, err)
				}
			})
		}
		a, id := orderedResourceGo(t, api, o, w, e, actor)
		if err := runner.DownProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		family, err := a.resolver.resolveTriggerKey(ctx, id, definition, key)
		if family != "" || err != ErrRepositoryUnavailable {
			t.Fatal("demotion must refuse unavailable", family, err)
		}
		t.Log("direct typed key resolution after demotion returned ErrRepositoryUnavailable")
	})
}

func TestSecurityAgentTriggerKeyOtherActorDecisionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, api *pgx.Conn, o, w, e, testID, actor string) {
		run, _ := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		const definition = "pid_afffffff-ffff-4fff-8fff-fffffffffff1"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions SELECT (jsonb_populate_record(NULL::zasp_security_agent_definitions,to_jsonb(d)||jsonb_build_object('definition_id',$1,'body',(body-'existing_test')||jsonb_build_object('id',$1,'allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state','max_steps',1)))).* FROM zasp_security_agent_definitions d WHERE definition_id=$2`, pgx.QueryExecModeSimpleProtocol, definition, public62Definition); err != nil {
			t.Fatal(err)
		}
		var approval string
		if err := owner.QueryRow(ctx, `SELECT approval_id FROM zasp_security_agent_approvals WHERE run_id=$1`, run).Scan(&approval); err != nil {
			t.Fatal(err)
		}
		q := public62DecisionRequest(o, w, e, orderedProgressionApprover, run, approval, "approved", 3)
		key := q["idempotency_key"].(string)
		before, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, actor, definition, key))
		if err != nil || before["family"] != "legacy_or_missing" {
			t.Fatal("before decision", before, err)
		}
		decision, err := public62Call(ctx, api, q)
		if err != nil {
			t.Fatal("authentic other actor approval", err)
		}
		got, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, actor, definition, key))
		if err != nil || got["family"] != "legacy_or_missing" {
			t.Fatalf("another actor's approval key claims requester's trigger: %v %v", got, err)
		}
		cancel := public62Request(o, w, e, orderedProgressionApprover, "cancel")
		cancel["run_id"], cancel["run_version"], cancel["idempotency_key"] = run, decision["run_version"], "review-other-actor-cancel"
		if _, err := public62Call(ctx, api, cancel); err != nil {
			t.Fatal("authentic other actor cancellation", err)
		}
		for _, principal := range []string{actor, orderedProgressionApprover} {
			for _, unrelatedKey := range []string{key, cancel["idempotency_key"].(string)} {
				before := public62Snapshot(t, ctx, owner)
				got, err := public62Call(ctx, api, triggerKeyRequest(o, w, e, principal, definition, unrelatedKey))
				if err != nil || got["family"] != "legacy_or_missing" || public62Snapshot(t, ctx, owner) != before {
					t.Fatal("non-trigger mutation claimed trigger key", principal, unrelatedKey, got, err)
				}
			}
		}
	})
}
