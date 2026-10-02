package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
)

// New manual admission occurs on installed71, before the fixture's one-way
// scope activation. Both immutable owners then execute together on that DB.
func seedShippedManualAdmission(t *testing.T, ctx context.Context, owner *pgx.Conn, db *PostgresJSONDatabase, identity RequestIdentity, o, w, e, testID, actor string) string {
	t.Helper()
	const definition = "pid_aa710001-0000-4000-8000-000000000001"
	const run = "pid_aa710002-0000-4000-8000-000000000002"
	const audit = "pid_aa710003-0000-4000-8000-000000000003"
	const receipt = "pid_aa710004-0000-4000-8000-000000000004"
	_, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
 SELECT organization_id,workspace_id,environment_id,$4,'autonomous',1,1,body||jsonb_build_object('id',$4::text,'enabled',true,'autonomy','autonomous','trigger_kind','attack_path','trigger_source','observed','max_steps',1,'allowed_actions',jsonb_build_array('run_test'),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$5::text,'definition_version',1)),'security-agent-actions-v1' FROM zasp_security_agent_definitions WHERE definition_id=$6;
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$7 FROM zasp_security_agent_definitions WHERE definition_id=$4;
 UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","run_tests","view_audit"]' WHERE (organization_id,principal_id)=($1,$7);
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'run_test',true,$7) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, w, e, definition, testID, public62Definition, actor)
	if err != nil {
		t.Fatal("manual prerequisites", err)
	}
	repository := &PostgresRepository{database: db, securityAgentExecution: true}
	input := SecurityAgentRunRequest{DefinitionID: definition, ExpectedVersion: 1, IdempotencyKey: "p3c-fix1-manual-0001", RunID: run, AuditID: audit, CorrelationID: audit, ReceiptID: receipt, TriggerKind: "manual"}
	value, err := repository.runSecurityAgentManual(ctx, identity, input)
	if err != nil || value.ID != run || value.State != "queued" {
		t.Fatal("installed71 new manual admission", err)
	}
	replay, err := repository.runSecurityAgentManual(ctx, identity, input)
	if err != nil || !replay.Replayed || replay.ID != run {
		t.Fatal("manual admission replay", err)
	}
	var owned bool
	if err := owner.QueryRow(ctx, `SELECT execution_owner='legacy' FROM zasp_temporal66.run_owners WHERE run_id=$1`, run).Scan(&owned); err != nil || !owned {
		t.Fatal("manual immutable owner", owned, err)
	}
	return run
}

func assertShippedLegacyCollections(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, manual, temporal string) {
	t.Helper()
	var before, after string
	query := `SELECT to_jsonb(r)::text FROM zasp_security_agent_runs r WHERE run_id=$1`
	if err := owner.QueryRow(ctx, query, temporal).Scan(&before); err != nil {
		t.Fatal(err)
	}
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`SELECT zasp_temporal70.op01($1,$2)`, []any{"coexistence-check", 10}},
		{`SELECT zasp_temporal70.op02($1,$2,$3,$4)`, []any{"coexistence-check", 10, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()}},
		{`SELECT zasp_temporal70.op11($1,$2,$3,$4,$5,$6)`, []any{"coexistence-check", strings.Repeat("a", 32), 60, 10, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()}},
	} {
		var result string
		if err := tx.QueryRow(ctx, q.sql, q.args...).Scan(&result); err != nil {
			t.Fatal("legacy collection", err)
		}
		if strings.Contains(result, temporal) {
			t.Fatal("collection selected Temporal owner")
		}
	}
	var claimed string
	if err := tx.QueryRow(ctx, `SELECT zasp_temporal70.op03($1,$2,$3,$4)`, "coexistence-check", strings.Repeat("a", 32), 60, 10).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(claimed, manual) || strings.Contains(claimed, temporal) {
		t.Fatal("nonempty owner-separated claim", claimed)
	}
	if err := owner.QueryRow(ctx, query, temporal).Scan(&after); err != nil || before != after {
		t.Fatal("legacy scans changed Temporal row", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("nonempty installed70 expiry/schedule/settlement scans exclude Temporal run; claim selects manual only; probe transaction rolled back")
}

func assertShippedLegacyClassifier(t *testing.T, ctx context.Context, owner, adapter *pgx.Conn, o, w, e, manual, temporal string) {
	t.Helper()
	var child string
	if err := owner.QueryRow(ctx, `SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1`, manual).Scan(&child); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := adapter.QueryRow(ctx, `SELECT zasp_temporal71.adapter_protocol($1,$2,$3,$4)`, o, w, e, child).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if json.Unmarshal(raw, &result) != nil || result["protocol"] != "legacy_single_test" {
		t.Fatal("persisted manual classification")
	}
	for _, args := range [][]any{{o, w, w, child}, {o, w, e, temporal}} {
		_, err := adapter.Exec(ctx, `SELECT zasp_temporal71.adapter_protocol($1,$2,$3,$4)`, args...)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatal("wrong scope or Temporal owner classified", err)
		}
	}
}

func assertShippedManualReceipt(t *testing.T, ctx context.Context, owner *pgx.Conn, db *PostgresJSONDatabase, identity RequestIdentity, run string) {
	t.Helper()
	var exact bool
	err := owner.QueryRow(ctx, `SELECT l.reconcile_state='settled' AND r.state='needs_human' AND r.completed_at IS NOT NULL AND r.last_error_code IS NULL
 AND s.state='succeeded' AND f.state='succeeded' AND t.state='complete' AND t.attempt=1 AND t.error_code IS NULL
 AND l.reconcile_settlement->'receipt'->>'outcome'='needs_human' AND l.reconcile_settlement->'receipt'->>'reason'='test_baseline_unavailable'
 AND l.reconcile_settlement->'proof'->'after'->>'run_id'=t.run_id AND l.reconcile_settlement->'proof'->'after'->>'attempt'='1'
 AND l.reconcile_settlement->'snapshot'->'after'->'input_artifact' IS NOT NULL AND l.reconcile_settlement->'snapshot'->'after'->'output_artifact' IS NOT NULL
 AND encode(f.result_digest,'hex')=l.reconcile_settlement->'receipt'->>'proof_sha256'
 AND encode(digest(decode(l.reconcile_settlement->>'proof_hex','hex'),'sha256'),'hex')=l.reconcile_settlement->'receipt'->>'proof_sha256'
 AND (SELECT count(*)=1 FROM zasp_security_agent_test_invocations j WHERE j.test_run_id=t.run_id AND j.state='completed' AND j.attempt=1)
 AND (SELECT count(*)=1 FROM zasp_security_agent_audit a WHERE a.run_id=r.run_id AND a.event_kind='test_reconciled')
 FROM zasp_security_agent_test_links l JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id)
 JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 WHERE l.run_id=$1`, run).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("manual completed test settlement/artifact/journal proof", exact, err)
	}
	repository := &PostgresRepository{database: db, securityAgentExecution: true}
	detail, err := repository.GetSecurityAgentRun(ctx, identity, run)
	if err != nil || detail.Run.ID != run || detail.Run.State != "needs_human" || detail.Run.ManualTrigger == nil {
		t.Fatal("typed manual terminal receipt", err)
	}
	t.Log("manual terminal needs_human/test_baseline_unavailable: succeeded action, completed child, verified after-artifacts and journal, immutable settlement; no remediation claim")
}
