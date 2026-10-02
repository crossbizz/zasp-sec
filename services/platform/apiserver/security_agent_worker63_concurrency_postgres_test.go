package apiserver

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSecurityAgentWorker63ConcurrentOldestPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		// This legacy queue row is a negative fixture only; it must never gain
		// a planning job or dispatch lease, even though it sorts first.
		legacy := "pid_9c000001-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at) SELECT organization_id,workspace_id,environment_id,$4,definition_id,version,$4,$5,'queued',clock_timestamp()-interval '1 day' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND body->'max_steps'='1'::jsonb ORDER BY definition_id LIMIT 1`, o, w, e, legacy, actor); err != nil {
			t.Fatal(err)
		}
		first, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-concurrent-first"})
		if err != nil {
			t.Fatal(err)
		}
		finding := "pid_8d300001-0000-4000-8000-000000000004"
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Second concurrent input','high','open')`, o, w, e, finding); err != nil {
			t.Fatal(err)
		}
		second, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: finding, TriggerVersion: 1, IdempotencyKey: "worker63-concurrent-second"})
		if err != nil {
			t.Fatal(err)
		}
		a, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		b, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close(ctx)
		// Hold selection at its reviewed global lock, then let both independent
		// worker connections race. Exactly two distinct planning claims may commit.
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ordered-worker63-dispatch',0))`); err != nil {
			t.Fatal(err)
		}
		type answer struct {
			result map[string]any
			err    error
		}
		results := make(chan answer, 2)
		for i, c := range []*pgx.Conn{a, b} {
			go func(c *pgx.Conn, index int) {
				q := worker63ClaimRequest([]string{"worker63-concurrent-token-a", "worker63-concurrent-token-b"}[index])
				q["worker_id"] = []string{"worker63-a", "worker63-b"}[index]
				v, err := worker63Call(ctx, c, q)
				results <- answer{v, err}
			}(c, i)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for i := 0; i < 2; i++ {
			result := <-results
			if result.err != nil || result.result["outcome"] != "claimed" {
				t.Fatal(result)
			}
			item := result.result["item"].(map[string]any)
			run := item["run_id"].(string)
			if ids[run] || item["organization_id"] != o || item["workspace_id"] != w || item["environment_id"] != e {
				t.Fatal("duplicate/foreign selection", item)
			}
			ids[run] = true
		}
		if !ids[first.RunID] || !ids[second.RunID] {
			t.Fatal("missed candidates", ids)
		}
		var legacyUntouched bool
		if err = owner.QueryRow(ctx, `SELECT state='queued' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, legacy).Scan(&legacyUntouched); err != nil || !legacyUntouched {
			t.Fatal("legacy row was claimed or fixture absent", err)
		}
		var claimed []string
		if err = owner.QueryRow(ctx, `SELECT array_agg(run_id ORDER BY created_at,dispatch_id) FROM zasp_ordered_worker63.dispatch_leases`).Scan(&claimed); err != nil || len(claimed) != 2 || claimed[0] != first.RunID || claimed[1] != second.RunID {
			t.Fatal("non-oldest ordering", claimed, err)
		}
		fo, fw, fe := "pid_9b000001-0000-4000-8000-000000000001", "pid_9b000002-0000-4000-8000-000000000002", "pid_9b000003-0000-4000-8000-000000000003"
		_, err = owner.Exec(ctx, `INSERT INTO zasp_organizations(id,name,domain) VALUES($5,'Dispatch second tenant','dispatch-second.invalid');
 INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($6,$5,'Dispatch second workspace');
 INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($7,$5,$6,'Dispatch staging','staging');
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 SELECT $5,$6,$7,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND id=(SELECT target_id FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4));
 SELECT zasp_attack_lab_register_credential_binding($5,$6,$7,'pid_9b000013-0000-4000-8000-000000000003',target_id,credential_reference,credential_class,1,decode(repeat('ab',32),'hex'),clock_timestamp()+interval '1 hour') FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 SELECT $5,$6,$7,definition_id,name,target_id,target_kind,categories,safety,created_by FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4);
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($5,$6,$7,'*',true,$8),($5,$6,$7,'create_temporary_policy',true,$8)`, pgx.QueryExecModeSimpleProtocol, o, w, e, testID, fo, fw, fe, actor)
		if err != nil {
			t.Fatal("second tenant setup", err)
		}
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($1,$2,'worker63-second-org','worker63-second-member','security_engineer')`, actor, fo); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, fo, fw, fe, testID, actor)
		foreignRepo, foreignID := public62GoRepository(t, api, fo, fw, fe, actor)
		if _, err = foreignRepo.Activate(ctx, foreignID, public62Definition, 1); err != nil {
			debug := public62Request(fo, fw, fe, actor, "activate")
			debug["definition_id"] = public62Definition
			debug["definition_version"] = 1
			_, cause := public62Call(ctx, api, debug)
			if pg, ok := cause.(*pgconn.PgError); ok {
				t.Log(pg.Where)
			}
			t.Fatal(err, cause)
		}
		foreign, err := foreignRepo.Trigger(ctx, foreignID, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-second-tenant-trigger"})
		if err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, fo, fw, fe, actor)
		foreignClaim, err := worker63Call(ctx, worker, worker63ClaimRequest("worker63-second-tenant-claim"))
		if err != nil || foreignClaim["outcome"] != "claimed" {
			t.Fatal(foreignClaim, err)
		}
		foreignItem := foreignClaim["item"].(map[string]any)
		if foreignItem["run_id"] != foreign.RunID || foreignItem["organization_id"] != fo || foreignItem["workspace_id"] != fw || foreignItem["environment_id"] != fe {
			t.Fatal("global claim mixed tenant identity", foreignItem)
		}
		if _, err = repo.Run(ctx, id, foreign.RunID); err != ErrRepositoryUnavailable {
			t.Fatal("first tenant read foreign dispatch", err)
		}
		// Schema writers and cancellation respect caller deadlines without changing
		// the active lease or handing it to another worker.
		lock, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0))`); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, callErr := worker63Call(bounded, worker, map[string]any{"operation": "ready"})
		cancel()
		if callErr == nil {
			t.Fatal("readiness ignored cancellation")
		}
		if err = lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=ANY($1)`, []string{first.RunID, second.RunID}).Scan(&count); err != nil || count != 2 {
			t.Fatal("duplicate planning", count, err)
		}
	})
}
