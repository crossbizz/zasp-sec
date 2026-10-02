package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"testing"
)

// All positive rows come through public62, worker63 admission, public approval,
// and release61 application/deployment calls. Configuration is the only seed.
func scheduler64Applied(t *testing.T, ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) (string, []string, ed25519.PrivateKey) {
	t.Helper()
	worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
	worker63Pricing(t, ctx, owner, o, w, e, actor)
	seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
	r, s := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6420)
	public62TypedDecision(t, ctx, api, o, w, e, r, 3)
	action := orderedActionFenceConnection(t, ctx, owner)
	defer action.Close(ctx)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, s, "claim", 4, 0), keys)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, s, claim, key), keys)
	if err != nil {
		t.Fatal(err)
	}
	deployOrderedApplication(t, ctx, owner, key, stored)
	if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, s, "complete", 5, 2), keys); err != nil {
		t.Fatal(err)
	}
	var successor string
	if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=1`, r).Scan(&successor); err != nil {
		t.Fatal(err)
	}
	return r, []string{s, successor}, key
}

// Break: only initial application is selected; genuine successor, test, stop,
// and retained cleanup work disappear from global scheduling.
func TestSecurityAgentScheduler64StateClassesPostgres(t *testing.T) {
	for _, stage := range []string{"successor", "test", "stop", "cleanup"} {
		t.Run(stage, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				scheduler64Setup(t, ctx, owner)
				r, steps, _ := scheduler64Applied(t, ctx, owner, worker, api, o, w, e, testID, actor)
				if stage == "test" {
					if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
						t.Fatal(err)
					}
					public62TypedDecision(t, ctx, api, o, w, e, r, 7)
				}
				if stage == "stop" {
					// The reviewed safety writer changes current authority.
					if _, err := api.Exec(ctx, `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,'scheduler64-stop-control','environment','*',false,1,clock_timestamp()+interval '4 minutes',$5,$5,$5)`, o, w, e, actor, "pid_64000000-0000-4000-8000-000000000001"); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "cleanup" {
					repo, id := public62GoRepository(t, api, o, w, e, actor)
					if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 6, IdempotencyKey: "scheduler64-retained-cleanup"}); err != nil {
						t.Fatal(err)
					}
				}
				v, err := scheduler64Call(ctx, worker, scheduler64Request("scheduler64-stage-"+stage))
				if err != nil || v["outcome"] != "claimed" {
					t.Fatal("genuine "+stage+" work not selected", v, err)
				}
				if item := v["item"].(map[string]any); item["state_class"] != stage || item["run_id"] != r {
					t.Fatal("wrong state class", item)
				}
			})
		})
	}
}
