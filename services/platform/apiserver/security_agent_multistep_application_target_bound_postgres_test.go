package apiserver

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// A Go response limit must not conceal a committed oversized SQL claim.
func TestSecurityAgentMultistepApplicationTargetBoundPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		for i := 1; i <= 100; i++ {
			seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, fmt.Sprintf("pid_8f001001-0000-4000-8000-%012d", i))
		}
		r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 901, true)
		got, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil || len(got["targets"].([]any)) != 100 {
			t.Fatal("100-target boundary failed", err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
		seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, "pid_8f001001-0000-4000-8000-000000000101")
		r, steps = seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 902, true)
		snapshot := func() string {
			var complete string
			if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('run',(SELECT to_jsonb(x) FROM zasp_security_agent_runs x WHERE run_id=$1),'budget',(SELECT to_jsonb(x) FROM zasp_security_agent_run_budgets x WHERE run_id=$1),'work',(SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id) FROM zasp_policy_deployment_work x WHERE (organization_id,workspace_id,environment_id)=($2,$3,$4)),'fairness',(SELECT to_jsonb(x) FROM zasp_policy_deployment_fairness x WHERE organization_id=$2))::text`, r, o, w, e).Scan(&complete); err != nil {
				t.Fatal(err)
			}
			return orderedApplicationSnapshot(t, ctx, owner, r) + complete
		}
		before := snapshot()
		// Call SQL directly: rejection after a committed QueryJSON is too late.
		_, err = orderedProgressionCall(ctx, action, "application", orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0))
		if err == nil || snapshot() != before {
			t.Fatal("101-target SQL claim changed authority", err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 0, 0, 0, 1)
	})
}
