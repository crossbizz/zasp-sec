package apiserver

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A read-projection rollback must not refund reservations or rewrite retained
// accounting. Owner-seeded history exercises migration retention, not provider
// execution. Both unknown usage and a complete known-zero settlement survive.
func TestSecurityAgentRunContextBudgetRetentionPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		for _, statement := range []string{
			`INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES($1)`,
			`INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,attempt)
SELECT organization_id,workspace_id,environment_id,'pid_78000008-0000-4000-8000-000000000008',definition_id,definition_version,'pid_6a000005-0000-4000-8000-000000000005','retention-fixture','needs_human',2 FROM zasp_security_agent_definitions WHERE organization_id=$1`,
			`INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit,stop_reason)
SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,clock_timestamp(),clock_timestamp()+interval '1 hour',3,1000,200,1,'budget_usage_unknown' FROM zasp_security_agent_runs WHERE organization_id=$1`,
			`INSERT INTO zasp_security_agent_provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest)
SELECT organization_id,workspace_id,environment_id,run_id,attempt,'retained-'||attempt,decode(repeat('11',32),'hex'),'fixture-model','fixture-policy','openrouter_credit',100,200,'retention-worker',decode(repeat('22',32),'hex') FROM zasp_security_agent_run_budgets CROSS JOIN generate_series(1,2) attempt WHERE organization_id=$1`,
			`UPDATE zasp_security_agent_provider_reservations SET settled_at=clock_timestamp(),output_digest=decode(repeat('33',32),'hex'),prompt_tokens=0,completion_tokens=0,total_tokens=0,cost_nano_credits=0 WHERE organization_id=$1 AND attempt=2`,
			`INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state)
SELECT organization_id,workspace_id,environment_id,run_id,'pid_78000009-0000-4000-8000-000000000009',0,'create_temporary_policy',decode(repeat('44',32),'hex'),'allow','authorized' FROM zasp_security_agent_runs WHERE organization_id=$1`,
			`INSERT INTO zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)
SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest FROM zasp_security_agent_steps WHERE organization_id=$1`,
		} {
			if _, err := owner.Exec(ctx, statement, org); err != nil {
				t.Fatal(err)
			}
		}
		tables := []struct {
			name  string
			count int
		}{
			{"zasp_security_agent_org_admissions", 1},
			{"zasp_security_agent_runs", 1},
			{"zasp_security_agent_run_budgets", 1},
			{"zasp_security_agent_provider_reservations", 2},
			{"zasp_security_agent_steps", 1},
			{"zasp_security_agent_step_reservations", 1},
		}
		snapshot := func(table string) string {
			t.Helper()
			var value string
			// Table identifiers come only from the literal list above. Capture
			// every column, including leases, digests, nulls and timestamps.
			if err := owner.QueryRow(ctx, fmt.Sprintf(`SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM %s r WHERE organization_id=$1`, table), org).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before := make(map[string]string)
		for _, table := range tables {
			var count int
			if err := owner.QueryRow(ctx, "SELECT count(*) FROM "+table.name+" WHERE organization_id=$1", org).Scan(&count); err != nil || count != table.count {
				t.Fatalf("fixture %s count=%d want=%d error=%v", table.name, count, table.count, err)
			}
			before[table.name] = snapshot(table.name)
		}
		runner := precisionMigrationRunner(t, owner)
		for _, phase := range []string{"upgrade54", "rollback53"} {
			var err error
			wantVersion := int64(53)
			if phase == "upgrade54" {
				wantVersion = 54
				err = runner.UpProductionSecurityAgentRunContext(ctx)
			} else {
				err = runner.DownProductionSecurityAgentRunContext(ctx)
			}
			if err != nil {
				t.Fatalf("%s: %v", phase, err)
			}
			if version, err := runner.Version(ctx); err != nil || version != wantVersion {
				t.Fatalf("%s version=%d want=%d error=%v", phase, version, wantVersion, err)
			}
			for _, table := range tables {
				if snapshot(table.name) != before[table.name] {
					t.Fatalf("%s rewrote retained accounting in %s", phase, table.name)
				}
			}
		}
		var ready bool
		if err := owner.QueryRow(ctx, `SELECT zasp_production_security_agent_budgets_client_ready($1,$2)`, migrations.SecurityAgentBudgetCandidateChecksum(), migrations.SecurityAgentBudgetCandidateFingerprint()).Scan(&ready); err != nil || !ready {
			t.Fatalf("retained history did not restore exact53 readiness: %v %v", ready, err)
		}
	})
}
