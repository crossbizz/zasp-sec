package apiserver

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepPlanningSettlementDriftPostgres(t *testing.T) {
	runOrderedPlanningFixture(t, func(ctx context.Context, owner, worker *pgx.Conn, q map[string]any, selection map[string]any, rawResult string) {
		job, err := orderedPlanningCall(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"prepare", "start", "result", "settle", "artifacts"} {
			q["operation"] = op
			q["payload"] = map[string]any{}
			switch op {
			case "prepare":
				q["payload"] = map[string]any{"pricing": selection, "input_version": "controlled-input-version"}
			case "result":
				q["payload"] = map[string]any{"raw": rawResult}
			case "artifacts":
				q["payload"] = map[string]any{"input_version": "controlled-input-version", "output_version": "controlled-output-version", "output_digest": job["output_digest"]}
			}
			job, err = orderedPlanningCall(ctx, worker, q)
			if err != nil {
				t.Fatal(op, err)
			}
		}
		// Fault changes persisted usage while preserving its structural sum and
		// both digests. Raw provider evidence must remain accounting authority.
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_provider_reservations SET prompt_tokens=49,total_tokens=99 WHERE run_id=$1`, q["run_id"]); err != nil {
			t.Fatal(err)
		}
		q["operation"] = "admit"
		q["payload"] = map[string]any{}
		if _, err = orderedPlanningCall(ctx, worker, q); err == nil {
			t.Fatal("admitted settlement that differs from exact provider usage")
		}
		var plans int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_plans WHERE run_id=$1`, q["run_id"]).Scan(&plans); err != nil || plans != 0 {
			t.Fatal("drift produced plan", plans, err)
		}
	})
}
