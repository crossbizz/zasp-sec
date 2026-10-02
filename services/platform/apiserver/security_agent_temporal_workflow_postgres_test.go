package apiserver

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestTemporalWorkflowLatePlannerCancellationPostgres(t *testing.T) {
	runTemporalExecutorPlanningTransportFixture(t, "cancel_known")
}

func TestTemporalWorkflowAPICancelCoexistsPostgres(t *testing.T) {
	runTemporalExecutorPlanningFixture(t, nil, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string, selection map[string]any) {
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalWorkflow(ctx); err != nil {
			t.Fatal(err)
		}
		var actor, digest string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT r.requested_by,r.version,c.input_digest FROM zasp_security_agent_runs r JOIN zasp_temporal65.commands c USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND c.kind='start'`, run).Scan(&actor, &version, &digest); err != nil {
			t.Fatal(err)
		}
		_, identity := public62GoRepository(t, api, o, w, e, actor)
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
		if err != nil {
			t.Fatal(err)
		}
		repository := &PostgresRepository{database: database, securityAgentExecution: true}
		const decision = "pid_ab000001-0000-4000-8000-000000000001"
		input := SecurityAgentCancelRequest{RunID: run, IdempotencyKey: "p3c-cancel-coexists-0001", ExpectedVersion: version, AuditID: decision, CorrelationID: decision, ReceiptID: decision}
		first, err := repository.CancelSecurityAgentRun(ctx, identity, input)
		if err != nil {
			t.Fatal("API cancel", err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "temporal_compensation_test_login"
		comp, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer comp.Close(ctx)
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "input_digest": digest, "reason": "workflow_cancelled"})
		for i := 0; i < 2; i++ {
			var raw []byte
			if err := comp.QueryRow(ctx, `SELECT zasp_temporal69.stop($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal("stop after API cancel", err)
			}
		}
		replay, err := repository.CancelSecurityAgentRun(ctx, identity, input)
		if err != nil || !replay.Replayed || first.State != "cancelled" || first.Version != replay.Version {
			t.Fatal("API cancellation replay changed", err)
		}
		var valid bool
		if err := owner.QueryRow(ctx, `SELECT state='cancelled' AND version=$2 AND (SELECT count(*) FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='cancel' AND decision_id=$3)=1 AND (SELECT count(*) FROM zasp_temporal69.stops WHERE run_id=$1)=1 FROM zasp_security_agent_runs WHERE run_id=$1`, run, first.Version, decision).Scan(&valid); err != nil || !valid {
			t.Fatal("worker stop rewrote API terminal evidence", valid, err)
		}
	})
}

func TestTemporalWorkflowAppliedStopPostgres(t *testing.T) {
	runTemporalWorkflowStopFixture(t, false)
}
func TestTemporalWorkflowReservedTestStopPostgres(t *testing.T) {
	runTemporalWorkflowStopFixture(t, true)
}
func runTemporalWorkflowStopFixture(t *testing.T, reserved bool) {
	runTemporalExecutorPolicyFixture(t, true, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, run, step string, keys policy.GatewayPolicyKeys, key ed25519.PrivateKey, call func(*pgx.Conn, string, string, any) (map[string]any, error)) {
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalWorkflow(ctx); err != nil {
			t.Fatal(err)
		}
		if reserved {
			var actor, successor string
			var version int64
			if err := owner.QueryRow(ctx, `SELECT r.requested_by,r.version,p.plan->'steps'->1->>'step_id' FROM zasp_security_agent_runs r JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE run_id=$1`, run).Scan(&actor, &version, &successor); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, actor); err != nil {
				t.Fatal(err)
			}
			seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
			cfg := owner.Config().Copy()
			cfg.User = "temporal_executor_test_login"
			executor, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer executor.Close(ctx)
			q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": successor, "operation": "progress", "actor_id": "p3c-worker", "run_version": version, "approval_version": 1, "fresh_auth_at": ""})
			var raw []byte
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.progress($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var result map[string]any
			json.Unmarshal(raw, &result)
			public62TypedDecision(t, ctx, api, o, w, e, run, int64(result["run_version"].(float64)))
			q, _ = json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "step_id": successor, "generation": 1, "operation": "reserve", "payload": map[string]any{}})
			if err := executor.QueryRow(ctx, `SELECT zasp_temporal68.effect($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal(err)
			}
		}
		cfg := owner.Config().Copy()
		cfg.User = "temporal_compensation_test_login"
		comp, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer comp.Close(ctx)
		var digest string
		if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start'`, run).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "input_digest": digest, "reason": "workflow_cancelled"})
		var raw []byte
		if reserved {
			if err := comp.QueryRow(ctx, `SELECT zasp_temporal69.stop_test('{}'::jsonb)`).Scan(&raw); err == nil {
				t.Fatal("private child stop executable")
			}
			if _, err := comp.Exec(ctx, `INSERT INTO zasp_temporal69.stops SELECT * FROM zasp_temporal69.stops`); err == nil {
				t.Fatal("compensation can forge stop evidence")
			}
			var before []byte
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE run_id=$1`, run).Scan(&before); err != nil {
				t.Fatal(err)
			}
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM zasp_red_team_runs WHERE run_id=(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1) FOR UPDATE`, run); err != nil {
				tx.Rollback(ctx)
				t.Fatal(err)
			}
			bounded, done := context.WithTimeout(ctx, 2*time.Second)
			err = comp.QueryRow(bounded, `SELECT zasp_temporal69.stop($1::jsonb)`, q).Scan(&raw)
			done()
			tx.Rollback(context.Background())
			if err == nil {
				t.Fatal("child lock did not reject stop")
			}
			var unchanged bool
			if err := owner.QueryRow(ctx, `SELECT to_jsonb(r)=$2::jsonb AND NOT EXISTS(SELECT 1 FROM zasp_temporal69.stops WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.test_stops WHERE run_id=$1) FROM zasp_security_agent_runs r WHERE run_id=$1`, run, before).Scan(&unchanged); err != nil || !unchanged {
				t.Fatal("rejected stop partially committed", unchanged, err)
			}
		}
		for i := 0; i < 2; i++ {
			if err := comp.QueryRow(ctx, `SELECT zasp_temporal69.stop($1::jsonb)`, q).Scan(&raw); err != nil {
				t.Fatal("applied69 stop", i, err)
			}
		}
		var valid bool
		if err := owner.QueryRow(ctx, `SELECT state='needs_human' AND (SELECT count(*) FROM zasp_temporal69.stops WHERE run_id=$1)=1 FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&valid); err != nil || !valid {
			t.Fatal("durable stop", valid, err)
		}
	})
}

// A fresh-source compiler checks the independent pin before any registration.
func TestTemporalWorkflowCatalogPostgres(t *testing.T) {
	runTemporalDomainFreshFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-domain")
		runTemporalMigrationCLI(t, ctx, owner, "up-temporal-executor")
		if _, err := owner.Exec(ctx, migrations.ProductionTemporalWorkflow().UpSQL()); err != nil {
			t.Fatal("compile69", err)
		}
		var pin string
		if err := owner.QueryRow(ctx, `SELECT zasp_temporal69.fingerprint()`).Scan(&pin); err != nil {
			t.Fatal(err)
		}
		if pin != migrations.TemporalWorkflowFingerprint() {
			t.Fatalf("compiled69 pin=%s", pin)
		}
	})
}

func TestTemporalWorkflowRetainedStartAndStopPostgres(t *testing.T) {
	runTemporalExecutorPlanningFixture(t, nil, nil, func(ctx context.Context, owner, executor, api *pgx.Conn, o, w, e, run, testID string, selection map[string]any) {
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalWorkflow(ctx); err != nil {
			t.Fatal(err)
		}
		var valid bool
		if err := executor.QueryRow(ctx, `SELECT zasp_temporal69.principal_ready('zasp_temporal_executor') AND NOT zasp_temporal69.principal_ready('zasp_temporal_compensation') AND NOT zasp_temporal69.principal_ready('zasp_security_agent_worker')`).Scan(&valid); err != nil || !valid {
			t.Fatal("exact executor readiness", valid, err)
		}
		if err := api.QueryRow(ctx, `SELECT zasp_temporal69.principal_ready('zasp_temporal_executor')`).Scan(&valid); err == nil {
			t.Fatal("API acquired readiness grant")
		}
		var digest string
		if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start'`, run).Scan(&digest); err != nil {
			t.Fatal(err)
		}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "definition_version": 2, "input_digest": digest}
		query := func(conn *pgx.Conn, statement string, q map[string]any) (map[string]any, error) {
			raw, _ := json.Marshal(q)
			var result []byte
			err := conn.QueryRow(ctx, statement, raw).Scan(&result)
			var v map[string]any
			if err == nil {
				err = json.Unmarshal(result, &v)
			}
			return v, err
		}
		if _, err := query(executor, `SELECT zasp_temporal69.inspect($1::jsonb)`, q); err != nil {
			t.Fatal("retained start", err)
		}
		q["input_digest"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if _, err := query(executor, `SELECT zasp_temporal69.inspect($1::jsonb)`, q); err == nil {
			t.Fatal("foreign digest accepted")
		}
		q["input_digest"] = digest
		for field, replacement := range map[string]any{"definition_version": 3, "environment_id": "pid_ab000002-0000-4000-8000-000000000001", "run_id": "pid_ab000003-0000-4000-8000-000000000001"} {
			original := q[field]
			q[field] = replacement
			if _, err := query(executor, `SELECT zasp_temporal69.inspect($1::jsonb)`, q); err == nil {
				t.Fatal("foreign retained identity accepted", field)
			}
			q[field] = original
		}
		if _, err := query(api, `SELECT zasp_temporal69.inspect($1::jsonb)`, q); err == nil {
			t.Fatal("API acquired runtime authority")
		}
		q["reason"] = "workflow_cancelled"
		if _, err := query(executor, `SELECT zasp_temporal69.stop($1::jsonb)`, q); err == nil {
			t.Fatal("executor acquired compensation-only stop")
		}
		cfg := owner.Config().Copy()
		cfg.User = "temporal_compensation_test_login"
		compensation, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer compensation.Close(ctx)
		if err := compensation.QueryRow(ctx, `SELECT zasp_temporal69.principal_ready('zasp_temporal_compensation') AND NOT zasp_temporal69.principal_ready('zasp_temporal_executor')`).Scan(&valid); err != nil || !valid {
			t.Fatal("exact compensation readiness", valid, err)
		}
		first, err := query(compensation, `SELECT zasp_temporal69.stop($1::jsonb)`, q)
		if err != nil {
			t.Fatal("worker stop", err)
		}
		second, err := query(compensation, `SELECT zasp_temporal69.stop($1::jsonb)`, q)
		if err != nil || first["stop_id"] != second["stop_id"] {
			t.Fatal("stop replay changed", err)
		}
		var stopped bool
		if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND j.state='needs_human' AND r.plan_hash IS NULL AND (SELECT count(*) FROM zasp_temporal69.stops WHERE run_id=$1)=1 FROM zasp_security_agent_runs r JOIN zasp_temporal68.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&stopped); err != nil || !stopped {
			t.Fatal("stop admitted or lost intent", err)
		}
	})
}
