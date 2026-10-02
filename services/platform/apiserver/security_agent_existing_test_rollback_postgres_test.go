package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Unused candidate rollback must restore the compiled predecessor, including
// function bodies and permissions. This does not register or publish release55.
func TestSecurityAgentExistingTestCandidateRollbackPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, migrations.SecurityAgentExistingTestEnqueueCandidateSQL()); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, migrations.SecurityAgentExistingTestCandidateDownSQL()); err != nil {
			t.Fatal(err)
		}
		var restored bool
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_run_context_readiness($1,$2)
 AND to_regnamespace('zasp_existing_tests_predecessor') IS NULL
 AND to_regclass('public.zasp_security_agent_test_links') IS NULL
 AND to_regprocedure('public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text)') IS NULL
 AND to_regprocedure('public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text)') IS NULL
 AND to_regprocedure('public.zasp_security_agent_test_enqueue_core(text,text,text,text,text,text,bigint,text,text)') IS NULL`, migrations.ProductionSecurityAgentRunContext().Checksum(), migrations.SecurityAgentRunContextFingerprint()).Scan(&restored); err != nil || !restored {
			t.Fatalf("candidate rollback did not restore exact54: %v", err)
		}
	})
}

func TestSecurityAgentExistingTestCandidateRollbackRetainedHistoryPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, migrations.SecurityAgentExistingTestEnqueueCandidateSQL()); err != nil {
			t.Fatal(err)
		}
		// Retain a test-bearing noncurrent version while the current definition is
		// a non-test action. Downgrading must not strand this historical intent.
		command, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id,created_at)
 SELECT organization_id,workspace_id,environment_id,definition_id,99,'draft',body||$1::jsonb,
 digest(convert_to((body||$1::jsonb)::text,'UTF8'),'sha256'),'pid_89000041-0000-4000-8000-000000000001',clock_timestamp()
 FROM zasp_security_agent_definitions WHERE organization_id='pid_6a000001-0000-4000-8000-000000000001'`, `{"existing_test":{"definition_id":"pid_89000042-0000-4000-8000-000000000001","definition_version":1}}`)
		if err != nil || command.RowsAffected() != 1 {
			t.Fatalf("seed retained version: rows=%d err=%v", command.RowsAffected(), err)
		}
		snapshot := func() json.RawMessage {
			t.Helper()
			var value json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY organization_id,workspace_id,environment_id,definition_id,version) FROM zasp_security_agent_definition_versions v),
 'metadata',(SELECT jsonb_agg(to_jsonb(m) ORDER BY key) FROM zasp_schema_metadata m),
 'mutation',pg_get_functiondef('public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure),
 'enqueue',pg_get_functiondef('public.zasp_red_team_run_test(text,text,text,text,text,text,bigint,text,text)'::regprocedure),
 'links',to_regclass('public.zasp_security_agent_test_links')::text,
 'predecessor',to_regnamespace('zasp_existing_tests_predecessor')::text)`).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before := snapshot()
		_, err = owner.Exec(ctx, migrations.SecurityAgentExistingTestCandidateDownSQL())
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "55000" {
			t.Fatalf("rollback accepted retained history or unexpected error: %v", err)
		}
		if !equalIntegrationJSON(snapshot(), before) {
			t.Fatal("refused rollback changed retained history or function authority")
		}
	})
}
