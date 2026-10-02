package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Catches75 filtering out a retained non-test selector or blocking its normal
// registered prepare/execute/settle path. Product source setup is controlled.
func TestTemporalRetainedPeriodicCoexistencePostgres(t *testing.T) {
	runTemporalTestGrantFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, o, w, e, testID, actor string) {
		installTemporalTestExecutorFixture(t, ctx, owner)
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalTestSelector(ctx); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, owner).UpProductionTemporalHumanAdmission(ctx); err != nil {
			t.Fatal(err)
		}
		const definition = "pid_f0760000-0000-4000-8000-000000008001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
SELECT organization_id,workspace_id,environment_id,$2,activation,version,definition_version,(body-'existing_test')||jsonb_build_object('id',$2::text,'allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state'),plan_catalog_version FROM zasp_security_agent_definitions WHERE definition_id=$1;
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$3 FROM zasp_security_agent_definitions WHERE definition_id=$2;
INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($4,$5,$6,'update_finding_response',true,$3) ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, temporalTestLegacyProved, definition, actor, o, w, e); err != nil {
			t.Fatal(err)
		}
		cfg := owner.Config().Copy()
		cfg.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, cfg)
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
		const workerID, lease = "retained-periodic-proof", "retained-periodic-proof-lease"
		if count, err := repository.ScheduleSecurityAgentTriggers(ctx, workerID, 10); err != nil || count != 1 {
			t.Fatal("registered retained non-test selection", count, err)
		}
		claims, err := repository.ClaimSecurityAgentRuns(ctx, workerID, lease, 60, 10)
		if err != nil || len(claims) != 1 || claims[0].DefinitionID != definition {
			t.Fatal("retained non-test claim", claims, err)
		}
		prepared, err := repository.PrepareSecurityAgentRun(ctx, claims[0], workerID, lease, "pid_f0760000-0000-4000-8000-000000008002", time.Now().UTC().Add(time.Minute), "pid_f0760000-0000-4000-8000-000000008003", "pid_f0760000-0000-4000-8000-000000008004")
		if err != nil || prepared.State != "queued" {
			t.Fatal("retained non-test preparation", prepared, err)
		}
		claims, err = repository.ClaimSecurityAgentRuns(ctx, workerID, lease+"-execute", 60, 10)
		if err != nil || len(claims) != 1 || !claims[0].Prepared {
			t.Fatal("retained prepared claim", claims, err)
		}
		settled, err := repository.ExecuteSecurityAgentRun(ctx, claims[0], workerID, lease+"-execute", "pid_f0760000-0000-4000-8000-000000008005", "pid_f0760000-0000-4000-8000-000000008006")
		if err != nil || settled.State != "remediated" {
			t.Fatal("retained non-test settlement", settled, err)
		}
		var proof bool
		if err := owner.QueryRow(ctx, `SELECT r.state='remediated' AND r.completed_at IS NOT NULL AND f.status='under_review' AND s.state='succeeded' AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners x WHERE x.run_id=r.run_id) AND NOT EXISTS(SELECT 1 FROM zasp_temporal75.admissions x WHERE x.run_id=r.run_id) FROM zasp_security_agent_runs r JOIN zasp_risk_findings f ON(f.organization_id,f.workspace_id,f.environment_id,f.id)=(r.organization_id,r.workspace_id,r.environment_id,r.trigger_id) JOIN zasp_security_agent_steps s ON(s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) WHERE r.run_id=$1`, claims[0].RunID).Scan(&proof); err != nil || !proof {
			t.Fatal("retained periodic terminal product evidence", proof, err)
		}
		t.Log("registered75 retained schedule selected one update_finding_response parent; retained preparation/execution settled parent remediated and finding under_review; no74/75 owner")
	})
}
