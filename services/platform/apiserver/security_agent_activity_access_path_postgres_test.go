package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Local cardinality/access-path proof, not a production latency or capacity claim.
func TestSecurityAgentActivityAuditPageAccessPathPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		const org = "pid_6a000001-0000-4000-8000-000000000001"
		const workspace = "pid_6a000002-0000-4000-8000-000000000002"
		const environment = "pid_6a000003-0000-4000-8000-000000000003"
		const run = "pid_8f000001-0000-4000-8000-000000000001"
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit
		 (organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
		 SELECT organization_id,workspace_id,environment_id,
		 'pid_8f'||lpad(to_hex(n),6,'0')||'-0000-4000-8000-'||lpad(to_hex(n),12,'0'),
		 'pid_8f'||lpad(to_hex(n),6,'0')||'-0000-4000-8000-'||lpad(to_hex(n),12,'0'),
		 CASE WHEN n>4950 THEN $1 ELSE 'pid_8f000099-0000-4000-8000-000000000099' END,
		 'activity-page-fixture','run_queued',decode(repeat('a',64),'hex'),'{}'::jsonb
		 FROM zasp_security_agent_definitions CROSS JOIN generate_series(1,5000) n`, run); err != nil {
			t.Fatal(err)
		}
		var total, scoped, matching int
		if err := owner.QueryRow(ctx, `SELECT count(*),
		 count(*) FILTER (WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
		 count(*) FILTER (WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4))
		 FROM zasp_security_agent_audit WHERE actor_id='activity-page-fixture'`, org, workspace, environment, run).Scan(&total, &scoped, &matching); err != nil || total != 10000 || scoped != 5000 || matching != 50 {
			t.Fatalf("access-path fixture total=%d scoped=%d matching=%d error=%v", total, scoped, matching, err)
		}
		if _, err := owner.Exec(ctx, `ANALYZE zasp_security_agent_audit`); err != nil {
			t.Fatal(err)
		}
		// Exercise the installed function's actual candidate SELECT, not a copy
		// that could silently diverge from the production pagination predicate.
		var definition string
		if err := owner.QueryRow(ctx, `SELECT pg_get_functiondef('public.zasp_production_security_agent_run_context_targets(text,text,text,text,bytea,text,text,text,text,integer)'::regprocedure)`).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		_, candidate, found := strings.Cut(definition, "FOR audit_value IN ")
		candidate, _, end := strings.Cut(candidate, "\n  LOOP")
		if !found || !end {
			t.Fatal("forward audit SELECT not found")
		}
		candidate = strings.NewReplacer("org_value", "$1", "workspace_value", "$2", "environment_value", "$3", "run_value", "$4", "after_id_value", "$5", "limit_value", "$6").Replace(candidate)
		if _, err := owner.Exec(ctx, `PREPARE activity_page(text,text,text,text,text,integer) AS `+candidate); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
			if _, err := owner.Exec(ctx, "SET plan_cache_mode="+mode); err != nil {
				t.Fatal(err)
			}
			for _, after := range []any{nil, "pid_8f00136b-0000-4000-8000-00000000136b"} {
				var raw json.RawMessage
				if err := owner.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) EXECUTE activity_page($1,$2,$3,$4,$5,$6)`, pgx.QueryExecModeSimpleProtocol, org, workspace, environment, run, after, 20).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var plan []map[string]any
				if err := json.Unmarshal(raw, &plan); err != nil {
					t.Fatal(err)
				}
				indexed := false
				materialSort := false
				removed := float64(0)
				var inspect func(map[string]any)
				inspect = func(node map[string]any) {
					// PostgreSQL may retain a zero-row Sort for the impossible
					// branch. Reject sorting actual records, not dead plan nodes.
					if node["Node Type"] == "Sort" && node["Actual Rows"].(float64) > 0 {
						materialSort = true
					}
					if node["Index Name"] == "zasp_security_agent_activity_audit_v54_idx" {
						indexed = true
					}
					if value, ok := node["Rows Removed by Filter"].(float64); ok {
						removed += value
					}
					if children, ok := node["Plans"].([]any); ok {
						for _, child := range children {
							inspect(child.(map[string]any))
						}
					}
				}
				root := plan[0]["Plan"].(map[string]any)
				inspect(root)
				if root["Actual Rows"] != float64(21) || !indexed || removed > 0 || materialSort {
					t.Fatalf("audit page lacks bounded ordered run access: %s", raw)
				}
				t.Logf("audit page mode=%s after=%v rows removed=%.0f execution_ms=%v", mode, after, removed, plan[0]["Execution Time"])
			}
		}
	})
}
