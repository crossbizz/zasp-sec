package apiserver

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"testing"
)

// Owner mutations below are refusal probes inside rolled-back transactions.
func scheduler64Fault(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, sql string, args []any, q map[string]any) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, sql, args...); err != nil {
		t.Fatal("negative fixture", err)
	}
	if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(q)
	var result []byte
	if err = tx.QueryRow(ctx, `SELECT zasp_ordered_scheduler64.scheduler($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentScheduler().Checksum(), migrations.SecurityAgentSchedulerFingerprint(), raw).Scan(&result); err == nil {
		t.Fatal("contradictory authority accepted", sql)
	}
}

// Break: admitted planning rows can be relabeled independently of the immutable
// admission and still be returned as authentic scheduler authority.
func TestSecurityAgentScheduler64PlanningBindingPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, _ := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6440)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		for _, sql := range []string{
			`UPDATE zasp_sa_multistep_prior.planning_jobs SET worker_id='corrupt-planner' WHERE run_id=$1`,
			`UPDATE zasp_sa_multistep_prior.planning_jobs SET lease_token_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1`,
			`UPDATE zasp_sa_multistep_prior.planning_jobs SET input_digest='sha256:'||repeat('ab',32) WHERE run_id=$1`,
			`UPDATE zasp_sa_multistep_prior.planning_jobs SET receipt='{}'::jsonb WHERE run_id=$1`,
			`UPDATE zasp_security_agent_runs SET state='failed' WHERE run_id=$1`,
			`DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_public_triggered'`,
		} {
			t.Run(sql, func(t *testing.T) {
				scheduler64Fault(t, ctx, owner, worker, sql, []any{r}, scheduler64Request("scheduler64-planning-corruption"))
			})
		}
	})
}

func TestSecurityAgentScheduler64SecurityPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		for _, sql := range []string{
			`GRANT EXECUTE ON FUNCTION zasp_ordered_scheduler64.claim(jsonb) TO zasp_security_agent_api`,
			`ALTER TABLE zasp_ordered_scheduler64.schedule_leases NO FORCE ROW LEVEL SECURITY`,
			`DROP POLICY authority ON zasp_ordered_scheduler64.schedule_leases`,
			`ALTER FUNCTION zasp_ordered_scheduler64.scheduler(text,text,jsonb) OWNER TO zasp_security_agent_worker`,
			`SET LOCAL session_replication_role=replica;UPDATE zasp_ordered_scheduler64.registration SET checksum=repeat('0',64)`,
			`SET LOCAL session_replication_role=replica;UPDATE zasp_ordered_worker63.registration SET checksum=repeat('0',64)`,
			`SET LOCAL session_replication_role=replica;UPDATE zasp_ordered_public62.registration SET fingerprint=repeat('0',64)`,
			`UPDATE zasp_schema_versions SET checksum=repeat('0',64) WHERE version=61`,
		} {
			scheduler64Fault(t, ctx, owner, worker, sql, nil, map[string]any{"operation": "ready"})
		}
		for _, role := range []string{"zasp_security_agent_api", "zasp_security_agent_action_worker", "zasp_policy_deployment_worker", "zasp_discovery_api", "zasp_discovery_worker", "zasp_red_team_worker", "zasp_red_team_adapter"} {
			var allowed bool
			if err := owner.QueryRow(ctx, `SELECT has_schema_privilege($1,'zasp_ordered_scheduler64','USAGE') OR EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='zasp_ordered_scheduler64'::regnamespace AND has_function_privilege($1,oid,'EXECUTE')) OR has_table_privilege($1,'zasp_ordered_scheduler64.schedule_leases','SELECT,INSERT,UPDATE,DELETE')`, role).Scan(&allowed); err != nil || allowed {
				t.Fatal("unauthorized scheduler privilege", role, allowed, err)
			}
		}
		var isolated bool
		if err := owner.QueryRow(ctx, `SELECT NOT has_table_privilege('zasp_security_agent_worker','zasp_ordered_scheduler64.schedule_leases','SELECT,INSERT,UPDATE,DELETE') AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='zasp_ordered_scheduler64'::regnamespace AND proname<>'scheduler' AND has_function_privilege('zasp_security_agent_worker',oid,'EXECUTE')) AND (SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE relnamespace='zasp_ordered_scheduler64'::regnamespace AND relkind='r')`).Scan(&isolated); err != nil || !isolated {
			t.Fatal("worker internal/RLS authority", isolated, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_ordered_scheduler64.registration SET checksum=checksum`); err == nil {
			t.Fatal("mutable registration")
		}
	})
}

// Break: scheduler evidence can be rebound in place instead of retaining the
// original process identities and their digests for an auditable recovery.
func TestSecurityAgentScheduler64BindingsImmutablePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, _ := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6441)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		if got, err := scheduler64Call(ctx, worker, scheduler64Request("scheduler64-original-bindings")); err != nil || got["outcome"] != "claimed" {
			t.Fatal(got, err)
		}
		for _, set := range []string{"worker_id='replacement-worker'", "token_digest=decode(repeat('ab',32),'hex')", "action_worker_id='replacement-action'", "deployment_worker_id='replacement-deployment'", "request=request||'{\"limit\":2}'::jsonb", "item=jsonb_set(item,'{pricing,account_version}','2'::jsonb)", "created_at=clock_timestamp()"} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, `UPDATE zasp_ordered_scheduler64.schedule_leases SET `+set+` WHERE run_id=$1`, r)
			tx.Rollback(ctx)
			if err == nil {
				t.Errorf("original binding changed: %s", set)
			}
		}
		// Even a privileged negative probe that bypasses the immutable trigger
		// cannot turn altered evidence into worker-visible ready authority.
		for _, set := range []string{"action_token_digest=decode(repeat('ab',32),'hex')", "item=jsonb_set(item,'{pricing,account_version}','2'::jsonb)", "version=version+1", "lease_expires_at=lease_expires_at+interval '1 second'"} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE zasp_ordered_scheduler64.schedule_leases SET `+set+` WHERE run_id=$1`, r); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			err = tx.QueryRow(ctx, `SELECT zasp_ordered_scheduler64.scheduler($1,$2,'{"operation":"ready"}'::jsonb)`, migrations.ProductionSecurityAgentScheduler().Checksum(), migrations.SecurityAgentSchedulerFingerprint()).Scan(&raw)
			tx.Rollback(ctx)
			if err == nil {
				t.Fatal("tampered retained evidence accepted", set)
			}
		}
	})
}
