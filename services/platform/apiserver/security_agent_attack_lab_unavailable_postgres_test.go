package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The mounted browser test creates and triggers through public entrypoints.
// This registered-repository fixture isolates lease and deployment faults.
func TestSecurityAgentAttackLabUnavailableSourcePostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		const run = "pid_8bc10001-0000-4000-8000-000000000001"
		const finding = "pid_8bc10002-0000-4000-8000-000000000002"
		const workerID, lease = "attack-lab-unavailable-worker", "attack-lab-unavailable-original-lease"
		seedExistingTestPreparation(t, ctx, owner, o, w, e, testID, actor, run, finding, "start_attack_lab", workerID, lease)
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{verification_kind}','"attack_lab_run"') WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$4 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
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
		claim := SecurityAgentRunClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, RunID: run, TriggerID: finding, State: "planning", Version: 2, Attempt: 1}
		if err := owner.QueryRow(ctx, `SELECT definition_id,definition_version,lease_expires_at FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&claim.DefinitionID, &claim.DefinitionVersion, &claim.LeaseExpiresAt); err != nil {
			t.Fatal(err)
		}
		claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
		snapshot := func() string { return existingTestAcceptanceSnapshot(t, ctx, owner, o, w, e, run) }
		before := snapshot()
		for _, dimension := range []string{"lease", "organization", "workspace", "environment"} {
			foreign := claim
			token := lease
			switch dimension {
			case "lease":
				token = "wrong-attack-lab-lease-token"
			case "organization":
				foreign.OrganizationID = "pid_8bcfffff-0000-4000-8000-000000000001"
			case "workspace":
				foreign.WorkspaceID = "pid_8bcfffff-0000-4000-8000-000000000002"
			case "environment":
				foreign.EnvironmentID = "pid_8bcfffff-0000-4000-8000-000000000003"
			}
			if _, err := repository.LoadSecurityAgentPlannerContext(ctx, foreign, workerID, token); err == nil || errors.Is(err, ErrSecurityAgentAttackLabPreflightStopped) || snapshot() != before {
				t.Fatalf("%s lost source-stop authority: %v", dimension, err)
			}
		}
		// A corrupt deployment must remain an error, not become a benign source stop.
		var pin string
		if err := owner.QueryRow(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_attack_lab_checksum' RETURNING (SELECT value FROM zasp_schema_metadata WHERE key='production_security_agent_attack_lab_checksum')`).Scan(&pin); err != nil {
			t.Fatal(err)
		}
		_, faultErr := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
		if _, err := owner.Exec(ctx, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_security_agent_attack_lab_checksum'`, pin); err != nil {
			t.Fatal(err)
		}
		if faultErr == nil || errors.Is(faultErr, ErrSecurityAgentAttackLabPreflightStopped) || snapshot() != before {
			t.Fatalf("deployment outage became source stop: %v", faultErr)
		}
		// Revoke the lease while the real call waits for the parent row. The stop
		// must revalidate after the wait and roll back every attempted write.
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, run); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
			result <- err
		}()
		waiting := false
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=$1),false)`, worker.PgConn().PID()).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !waiting {
			tx.Rollback(ctx)
			<-result
			t.Fatal("planner did not wait on parent")
		}
		if _, err := tx.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_token='revoked-attack-lab-lease-token' WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		waitedErr := <-result
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET lease_token=$2 WHERE run_id=$1`, run, lease); err != nil {
			t.Fatal(err)
		}
		if waitedErr == nil || errors.Is(waitedErr, ErrSecurityAgentAttackLabPreflightStopped) || snapshot() != before {
			t.Fatalf("revoked lease persisted source stop: %v", waitedErr)
		}
		if _, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease); !errors.Is(err, ErrSecurityAgentAttackLabPreflightStopped) {
			t.Fatalf("missing source did not persist typed stop: %v", err)
		}
		var raw json.RawMessage
		if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, existingTestReadPins([]any{o, w, e, run})...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		detail, err := decodeSecurityAgentRunContextEnvelope(raw, run)
		if err != nil || detail.Run.State != "needs_human" || detail.RunContext == nil || detail.RunContext.PreflightStopReason != "attack_lab_preflight_unavailable" || detail.Plan != nil || len(detail.Approvals) != 0 || len(detail.Execution) != 0 {
			t.Fatalf("durable unavailable projection rejected: %v", err)
		}
		var effects, links, jobs, approvals, plans, reservations, audits int
		if err := owner.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1),
 (SELECT count(*) FROM zasp_sa_attack_lab_links WHERE run_id=$1),
 (SELECT count(*) FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id)=($2,$3,$4)),
 (SELECT count(*) FROM zasp_security_agent_approvals WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE run_id=$1),
 (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='preflight_unavailable')`, run, o, w, e).Scan(&effects, &links, &jobs, &approvals, &plans, &reservations, &audits); err != nil {
			t.Fatal(err)
		}
		if effects+links+jobs+approvals+plans+reservations != 0 || audits != 1 {
			t.Fatalf("stop created authority: effects=%d links=%d jobs=%d approvals=%d plans=%d reservations=%d audits=%d", effects, links, jobs, approvals, plans, reservations, audits)
		}
		before = snapshot()
		if _, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease); err == nil || snapshot() != before {
			t.Fatalf("retired lease retried source authority: %v", err)
		}
	})
}
