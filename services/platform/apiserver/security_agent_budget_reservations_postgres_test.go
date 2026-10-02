package apiserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A durable reservation must retain unknown usage, reject incomplete settlement,
// and remain private. This is storage/release proof, not a dispatch permit test.
func TestProductionSecurityAgentProviderReservationStorage(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		var exists bool
		if err := owner.QueryRow(ctx, `SELECT to_regclass('public.zasp_security_agent_provider_reservations') IS NOT NULL`).Scan(&exists); err != nil || !exists {
			t.Fatalf("durable provider reservation authority missing: exists=%v err=%v", exists, err)
		}
		const organization = "pid_6a000001-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `UPDATE zasp_risk_attack_paths SET state='verified',version=version+1 WHERE organization_id=$1`, organization); err != nil {
			t.Fatal(err)
		}
		config, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, "reservation-worker", 1); err != nil || count != 1 {
			t.Fatalf("schedule=%d: %v", count, err)
		}
		if claims, err := repository.ClaimSecurityAgentRuns(ctx, "reservation-worker", "reservation-worker-lease", 60, 1); err != nil || len(claims) != 1 {
			t.Fatalf("claims=%d: %v", len(claims), err)
		}
		const insert = `INSERT INTO zasp_security_agent_provider_reservations
 (organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest)
 SELECT organization_id,workspace_id,environment_id,run_id,1,'reservation-1',decode(repeat('11',32),'hex'),'fixture-model','fixture-policy','openrouter_credit',100,200,'reservation-worker',decode(repeat('22',32),'hex') FROM zasp_security_agent_run_budgets WHERE organization_id=$1`
		if _, err := owner.Exec(ctx, insert, organization); err != nil {
			t.Fatal(err)
		}
		var private bool
		if err := owner.QueryRow(ctx, `SELECT relrowsecurity AND relforcerowsecurity AND relowner='zasp_discovery_authority'::regrole AND NOT EXISTS(
 SELECT 1 FROM unnest(ARRAY['zasp_discovery_api','zasp_discovery_worker','zasp_security_agent_api','zasp_security_agent_worker','zasp_security_agent_action_worker']) role_name
 WHERE has_table_privilege(role_name,'zasp_security_agent_provider_reservations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 FROM pg_class WHERE oid='zasp_security_agent_provider_reservations'::regclass`).Scan(&private); err != nil || !private {
			t.Fatalf("reservation authority is not private/forced RLS: %v %v", private, err)
		}
		if _, err := owner.Exec(ctx, `CREATE ROLE reservation_rls_member LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT zasp_discovery_authority TO reservation_rls_member`); err != nil {
			t.Fatal(err)
		}
		memberConfig := owner.Config().Copy()
		memberConfig.User = "reservation_rls_member"
		member, err := pgx.ConnectConfig(ctx, memberConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer member.Close(context.Background())
		var visible int
		if err := member.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_provider_reservations`).Scan(&visible); err != nil || visible != 0 {
			t.Fatalf("forced RLS leaked reservation: %d %v", visible, err)
		}
		if err := member.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `DROP ROLE reservation_rls_member`); err != nil {
			t.Fatal(err)
		}
		var workspace, environment, run string
		if err := owner.QueryRow(ctx, `SELECT workspace_id,environment_id,run_id FROM zasp_security_agent_run_budgets WHERE organization_id=$1`, organization).Scan(&workspace, &environment, &run); err != nil {
			t.Fatal(err)
		}
		// Literal VALUES avoids a source-table SELECT denial hiding an INSERT
		// grant. Distinct identities would be valid if the direct write leaked.
		_, err = worker.Exec(ctx, `INSERT INTO zasp_security_agent_provider_reservations
 (organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest)
 VALUES($1,$2,$3,$4,2,'direct-worker-reservation',decode(repeat('11',32),'hex'),'fixture-model','fixture-policy','openrouter_credit',100,200,'reservation-worker',decode(repeat('22',32),'hex'))`, organization, workspace, environment, run)
		var insertError *pgconn.PgError
		if !errors.As(err, &insertError) || insertError.Code != "42501" {
			t.Fatalf("direct reservation insertion permitted: %v", err)
		}
		for _, query := range []string{
			`SELECT * FROM zasp_security_agent_provider_reservations`,
			`UPDATE zasp_security_agent_provider_reservations SET maximum_tokens=12000`,
			`DELETE FROM zasp_security_agent_provider_reservations`,
		} {
			_, err := worker.Exec(ctx, query)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || pgError.Code != "42501" {
				t.Fatalf("direct worker authority access: %s: %v", query, err)
			}
		}
		for _, tc := range []struct{ name, set, code string }{
			{"cross_tenant", `organization_id='pid_6a000001-0000-4000-8000-000000000002'`, "23503"},
			{"cross_workspace", `workspace_id='missing-workspace'`, "23503"},
			{"cross_environment", `environment_id='missing-environment'`, "23503"},
			{"cross_run", `run_id='missing-run'`, "23503"},
			{"attempt_zero", `attempt=0`, "23514"},
			{"empty_id", `reservation_id=''`, "23514"},
			{"short_digest", `input_digest=decode('11','hex')`, "23514"},
			{"null_maximum", `maximum_tokens=NULL`, "23502"},
			{"empty_model", `model=''`, "23514"},
			{"empty_policy", `cost_policy_version=''`, "23514"},
			{"wrong_unit", `cost_unit='USD'`, "23514"},
			{"zero_tokens", `maximum_tokens=0`, "23514"},
			{"excess_tokens", `maximum_tokens=12001`, "23514"},
			{"zero_cost", `maximum_cost_nano_credits=0`, "23514"},
			{"excess_cost", `maximum_cost_nano_credits=1000000000001`, "23514"},
			{"empty_worker", `worker_id=''`, "23514"},
			{"short_lease_digest", `lease_token_digest=decode('22','hex')`, "23514"},
			{"partial_settlement", `total_tokens=0`, "23514"},
			{"settlement_before_reservation", `settled_at=reserved_at-interval '1 second',output_digest=decode(repeat('33',32),'hex'),prompt_tokens=0,completion_tokens=0,total_tokens=0,cost_nano_credits=0`, "23514"},
			{"short_output_digest", `settled_at=clock_timestamp(),output_digest=decode('33','hex'),prompt_tokens=0,completion_tokens=0,total_tokens=0,cost_nano_credits=0`, "23514"},
			{"unknown_not_zero", `settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=0,completion_tokens=0,total_tokens=0`, "23514"},
			{"inconsistent_total", `settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=2,completion_tokens=3,total_tokens=4,cost_nano_credits=1`, "23514"},
			{"overflow_total", `settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=9223372036854775807,completion_tokens=1,total_tokens=0,cost_nano_credits=1`, "23514"},
			{"negative_cost", `settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=0,completion_tokens=0,total_tokens=0,cost_nano_credits=-1`, "23514"},
			{"negative_prompt", `settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=-1,completion_tokens=1,total_tokens=0,cost_nano_credits=0`, "23514"},
			{"negative_completion", `settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=1,completion_tokens=-1,total_tokens=0,cost_nano_credits=0`, "23514"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := owner.Exec(ctx, `UPDATE zasp_security_agent_provider_reservations SET `+tc.set)
				var pgError *pgconn.PgError
				if !errors.As(err, &pgError) || pgError.Code != tc.code {
					t.Fatalf("invalid reservation accepted or wrong failure: %v", err)
				}
			})
		}
		for _, duplicate := range []string{insert, strings.Replace(insert, "'reservation-1'", "'reservation-2'", 1), strings.Replace(insert, "run_id,1,", "run_id,2,", 1)} {
			_, err = owner.Exec(ctx, duplicate, organization)
			var pgError *pgconn.PgError
			if !errors.As(err, &pgError) || pgError.Code != "23505" {
				t.Fatalf("duplicate attempt or reservation identity accepted: %v", err)
			}
		}
		fresh, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close(context.Background())
		var retained bool
		if err := fresh.QueryRow(ctx, `SELECT maximum_tokens=100 AND maximum_cost_nano_credits=200 AND settled_at IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL FROM zasp_security_agent_provider_reservations`).Scan(&retained); err != nil || !retained {
			t.Fatalf("unknown reservation lost across connections: %v %v", retained, err)
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_readiness($1,$2)`, migrations.ProductionSecurityAgentBudgets().Checksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("invalid pre-rollback readiness: %v %v", ready, err)
		}
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentBudgets(ctx); err == nil {
			t.Fatal("rollback accepted retained reservation")
		}
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_provider_reservations`).Scan(&visible); err != nil || visible != 1 {
			t.Fatalf("rollback lost reservation: %d %v", visible, err)
		}
		// Actual usage can exceed a permit. Store reality; settlement logic must
		// stop subsequent starts rather than discard an overage as invalid data.
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_provider_reservations SET settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=100,completion_tokens=1,total_tokens=101,cost_nano_credits=201`); err != nil {
			t.Fatal("cannot retain actual overage", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_provider_reservations SET prompt_tokens=0,completion_tokens=0,total_tokens=0,cost_nano_credits=0`); err != nil {
			t.Fatal("known zero usage rejected", err)
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `ALTER TABLE zasp_security_agent_provider_reservations DISABLE ROW LEVEL SECURITY`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_readiness($1,$2)`, migrations.ProductionSecurityAgentBudgets().Checksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&ready); err != nil || ready {
			t.Fatalf("reservation security drift accepted: %v %v", ready, err)
		}
	})
}
