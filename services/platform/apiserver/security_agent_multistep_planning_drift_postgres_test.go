package apiserver

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Removing request closure or operation validation must fail before any
// planning job, reservation, artifact intent, audit or admission mutation.
func TestSecurityAgentMultistepPlanningOperationRefusalPostgres(t *testing.T) {
	runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, _ map[string]any, _ string) {
		snapshot := func() string {
			t.Helper()
			var job string
			if err := owner.QueryRow(ctx, `SELECT coalesce((SELECT to_jsonb(j)::text FROM zasp_sa_multistep_prior.planning_jobs j WHERE run_id=$1),'absent')`, q["run_id"]).Scan(&job); err != nil {
				t.Fatal(err)
			}
			return job + orderedAdmissionSnapshot(t, ctx, owner, q["run_id"].(string))
		}
		before := snapshot()
		for _, test := range []struct {
			name      string
			operation any
		}{
			{"null", nil}, {"missing", nil}, {"boolean", true}, {"number", 1}, {"object", map[string]any{}}, {"array", []string{"claim"}}, {"unknown", "unsupported"},
		} {
			t.Run(test.name, func(t *testing.T) {
				q["operation"] = test.operation
				if test.name == "missing" {
					delete(q, "operation")
				}
				_, err := orderedPlanningCall(ctx, worker, q)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "22023" {
					t.Fatalf("invalid operation not refused: %v", err)
				}
				if snapshot() != before {
					t.Fatal("invalid operation mutated authority")
				}
			})
		}
	})
}

func TestSecurityAgentMultistepPlanningDriftPostgres(t *testing.T) {
	for _, mode := range []string{"budget_tokens", "budget_cost", "budget_steps", "budget_start", "budget_window", "reservation_model", "reservation_policy", "reservation_maximum", "input_body", "cross_tenant", "lease", "readiness"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, selection map[string]any, _ string) {
				if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
					t.Fatal(err)
				}
				q["operation"] = "prepare"
				q["payload"] = map[string]any{"pricing": selection, "input_version": "controlled-input-version"}
				if _, err := orderedPlanningCall(ctx, worker, q); err != nil {
					t.Fatal(err)
				}
				// Owner-only corruption fixtures test refusal, not positive authority.
				mutations := map[string]string{
					"budget_tokens":       `UPDATE zasp_security_agent_run_budgets SET max_tokens=1 WHERE run_id=$1`,
					"budget_cost":         `UPDATE zasp_security_agent_run_budgets SET max_cost_nano_credits=1 WHERE run_id=$1`,
					"budget_steps":        `UPDATE zasp_security_agent_run_budgets SET max_steps=1 WHERE run_id=$1`,
					"budget_start":        `UPDATE zasp_security_agent_run_budgets SET started_at=started_at+interval '1 second' WHERE run_id=$1`,
					"budget_window":       `UPDATE zasp_security_agent_run_budgets SET deadline_at=deadline_at+interval '1 second' WHERE run_id=$1`,
					"reservation_model":   `UPDATE zasp_security_agent_provider_reservations SET model='different/model' WHERE run_id=$1`,
					"reservation_policy":  `UPDATE zasp_security_agent_provider_reservations SET cost_policy_version='different-policy' WHERE run_id=$1`,
					"reservation_maximum": `UPDATE zasp_security_agent_provider_reservations SET maximum_tokens=1 WHERE run_id=$1`,
					"input_body":          `UPDATE zasp_sa_multistep_prior.planning_jobs SET input_body=input_body||' ' WHERE run_id=$1`,
					"lease":               `UPDATE zasp_security_agent_runs SET lease_token='replacement-worker-lease' WHERE run_id=$1`,
					"readiness":           `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1<>''`,
				}
				if mutation := mutations[mode]; mutation != "" {
					if _, err := owner.Exec(ctx, mutation, q["run_id"]); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "cross_tenant" {
					q["environment_id"] = "pid_9a000003-0000-4000-8000-000000000003"
				}
				q["operation"] = "start"
				q["payload"] = map[string]any{}
				if response, err := orderedPlanningCall(ctx, worker, q); err == nil {
					t.Fatal("drift permitted provider I/O", mode, response["send_permit"])
				}
			})
		})
	}
}
