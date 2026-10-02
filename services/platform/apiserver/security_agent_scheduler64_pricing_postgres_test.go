package apiserver

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
)

// Break: live planner pricing is consulted after admission, stranding approved
// stop/cleanup or substituting a later account/policy for immutable settlement.
func TestSecurityAgentScheduler64RetainedPricingPostgres(t *testing.T) {
	for _, stage := range []string{"stop", "cleanup"} {
		for _, mutation := range []string{"disable", "rotate"} {
			t.Run(stage+"_"+mutation, func(t *testing.T) {
				runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
					scheduler64Setup(t, ctx, owner)
					r, _, _ := scheduler64Applied(t, ctx, owner, worker, api, o, w, e, testID, actor)
					var retainedRaw []byte
					if err := owner.QueryRow(ctx, `SELECT lookup_request-ARRAY['organization_id','workspace_id','environment_id','body','body_digest'] FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, r).Scan(&retainedRaw); err != nil {
						t.Fatal(err)
					}
					var retained map[string]any
					if json.Unmarshal(retainedRaw, &retained) != nil {
						t.Fatal("retained binding")
					}
					var policyRaw []byte
					if err := owner.QueryRow(ctx, `SELECT policy FROM zasp_sa_multistep_prior.pricing_policies WHERE organization_id=$1 AND version=1`, o).Scan(&policyRaw); err != nil {
						t.Fatal(err)
					}
					var p map[string]any
					_ = json.Unmarshal(policyRaw, &p)
					config := owner.Config().Copy()
					config.User = "security_agent_v33_discovery_api_login"
					admin, err := pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer admin.Close(ctx)
					pq := orderedPricingAdminRequest(o, w, e, actor)
					pq["policy"], pq["operation"], pq["expected_version"], pq["expected_account_version"], pq["idempotency_key"] = p, "disable", 1, 1, "scheduler64-disable-after-admission"
					if mutation == "rotate" {
						pq["operation"] = "version"
						p["credential_digest"] = "sha256:" + strings.Repeat("cd", 32)
						p["credential_reference"] = p["credential_reference"].(string) + "-rotated"
					}
					replacement, err := orderedPricingCall(ctx, admin, "pricing_admin", pq)
					if err != nil {
						t.Fatal("reviewed pricing change", err)
					}
					worker63Trigger(t, ctx, owner, api, o, w, e, actor, 6801)
					if got, err := worker63Call(ctx, worker, worker63ClaimRequest("scheduler64-unavailable-future-planning")); err != nil || got["outcome"] != "empty" {
						t.Fatal("old pricing still starts planning", got, err)
					}
					if stage == "stop" {
						if _, err = api.Exec(ctx, `SELECT zasp_security_agent_mutate_execution_control($1,$2,$3,$4,'scheduler64-price-stop','environment','*',false,1,clock_timestamp()+interval '4 minutes',$5,$5,$5)`, o, w, e, actor, "pid_64000000-0000-4000-8000-000000000002"); err != nil {
							t.Fatal(err)
						}
					} else {
						repo, id := public62GoRepository(t, api, o, w, e, actor)
						if _, err = repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 6, IdempotencyKey: "scheduler64-price-cleanup"}); err != nil {
							t.Fatal(err)
						}
					}
					got, err := scheduler64Call(ctx, worker, scheduler64Request("scheduler64-retained-price-"+stage+mutation))
					if err != nil || got["outcome"] != "claimed" {
						t.Fatal("post-admission work stranded by current planner pricing", got, err)
					}
					item := got["item"].(map[string]any)
					pricing := item["pricing"].(map[string]any)
					if item["state_class"] != stage || item["run_id"] != r || !jsonEqualMaps(pricing, retained) || pricing["policy_digest"] == replacement["policy_digest"] {
						t.Fatal("replacement pricing escaped into admitted work", item)
					}
				})
			})
		}
	}
}
