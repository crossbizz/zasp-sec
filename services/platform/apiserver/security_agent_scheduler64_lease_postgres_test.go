package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"strings"
	"testing"
)

func scheduler64Mutation(q, item map[string]any, op string, runVersion, scheduleVersion int) map[string]any {
	v := map[string]any{"operation": op, "schedule_id": item["schedule_id"], "run_version": runVersion, "schedule_version": scheduleVersion}
	for _, k := range []string{"worker_id", "schedule_token", "action_worker_id", "action_lease_token", "deployment_worker_id", "deployment_lease_token"} {
		v[k] = q[k]
	}
	if op == "heartbeat" {
		v["lease_seconds"] = 60
	}
	return v
}

// Break: heartbeat extends an executor lease, accepts stale versions or token
// substitution, or abandon discards ownership after a durable action claim.
func TestSecurityAgentScheduler64LeasePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, step := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6410)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		q := scheduler64Request("scheduler64-lease-token")
		first, err := scheduler64Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := first["item"].(map[string]any)
		beat := scheduler64Mutation(q, item, "heartbeat", 4, 1)
		v, err := scheduler64Call(ctx, worker, beat)
		if err != nil || v["outcome"] != "extended" {
			t.Fatal("scheduler heartbeat unavailable", v, err)
		}
		if _, err = scheduler64Call(ctx, worker, beat); err == nil {
			t.Fatal("stale schedule version accepted")
		}
		beat["schedule_version"] = 2
		beat["run_version"] = 3
		if _, err = scheduler64Call(ctx, worker, beat); err == nil {
			t.Fatal("stale run version accepted")
		}
		beat["run_version"] = 4
		beat["deployment_lease_token"] = strings.Repeat("c", 32)
		if _, err = scheduler64Call(ctx, worker, beat); err == nil {
			t.Fatal("substituted deployment binding accepted")
		}
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "finish", 4, 2)); err == nil {
			t.Fatal("runnable application finished")
		}
		if v, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 4, 2)); err != nil || v["outcome"] != "released" {
			t.Fatal("side-effect-free abandon", v, err)
		}
		var retained bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases WHERE schedule_id=$1 AND state='reconciled')`, item["schedule_id"]).Scan(&retained); err != nil || !retained {
			t.Fatal("released schedule evidence erased", retained, err)
		}
		q = scheduler64Request("scheduler64-action-token")
		v, err = scheduler64Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item = v["item"].(map[string]any)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		aq := orderedApplicationRequest(o, w, e, r, step, "claim", 4, 0)
		aq["worker_id"], aq["lease_token"], aq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		if _, err = orderedApplicationCall(ctx, action, aq, policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal("authentic action claim", err)
		}
		var before, after string
		const predecessor = `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(x)) FROM zasp_security_agent_effects x WHERE run_id=$1),(SELECT to_jsonb(x) FROM zasp_sa_multistep_prior.planning_jobs x WHERE run_id=$1))::text`
		if err = owner.QueryRow(ctx, predecessor, r).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if v, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "heartbeat", 5, 1)); err != nil || v["outcome"] != "extended" {
			t.Fatal("owned application heartbeat", v, err)
		}
		if err = owner.QueryRow(ctx, predecessor, r).Scan(&after); err != nil || before != after {
			t.Fatal("heartbeat changed predecessor", err)
		}
		if v, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 5, 2)); err != nil || v["outcome"] != "recovery_deferred" {
			t.Fatal("durable intent erased", v, err)
		}
		if err = owner.QueryRow(ctx, predecessor, r).Scan(&after); err != nil || before != after {
			t.Fatal("abandon changed predecessor", err)
		}
		if v, err = scheduler64Call(ctx, worker, scheduler64Request("scheduler64-rival-token")); err != nil || v["outcome"] != "empty" {
			t.Fatal("deferred live action adopted", v, err)
		}
	})
}
