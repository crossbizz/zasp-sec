package apiserver

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepTestWirePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedTestPredecessor(t, ctx, owner, worker, api, action, o, w, e, testID, actor, 903)
		for _, mode := range []string{"nonhex_token", "wrong_step", "foreign_scope", "zero_version", "high_version", "unapproved"} {
			t.Run(mode, func(t *testing.T) {
				request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
				switch mode {
				case "nonhex_token":
					request["lease_token"] = strings.Repeat("z", 32)
				case "wrong_step":
					request["step_id"] = steps[0]
				case "foreign_scope":
					request["organization_id"] = "pid_79990001-0000-4000-8000-000000000001"
				case "zero_version":
					request["run_version"] = 0
				case "high_version":
					request["run_version"] = 999999
				case "unapproved":
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET state='pending',version=1,approver_id=NULL,fresh_auth_at=NULL,decided_at=NULL WHERE run_id=$1 AND step_id=$2`, r, steps[1]); err != nil {
						t.Fatal(err)
					}
				}
				before := orderedTestSnapshot(t, ctx, owner, r)
				if _, err := orderedProgressionCall(ctx, worker, "test_action", request); err == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
					t.Fatal("SQL accepted unclaimable successor", err)
				}
			})
		}
	})
}
