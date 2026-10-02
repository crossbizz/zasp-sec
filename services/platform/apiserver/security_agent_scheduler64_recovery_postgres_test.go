package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"strings"
	"testing"
	"time"
)

// Break: global claim adopts an existing live executor lease, including when
// the caller happens to supply that lease's worker and token.
func TestSecurityAgentScheduler64ForeignExecutorPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, s := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6430)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		q := scheduler64Request("scheduler64-foreign-token")
		aq := orderedApplicationRequest(o, w, e, r, s, "claim", 4, 0)
		aq["worker_id"], aq["lease_token"], aq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		if _, err := orderedApplicationCall(ctx, action, aq, policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal(err)
		}
		v, err := scheduler64Call(ctx, worker, q)
		if err != nil || v["outcome"] != "empty" {
			t.Fatal("fresh scheduler adopted live executor", v, err)
		}
	})
}

// Break: expiry cannot produce a new schedule, replaces the old binding, or
// invents a new effect/reservation instead of reviewed release61 recovery.
func TestSecurityAgentScheduler64ApplicationRecoveryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, s := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6431)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		q := scheduler64Request("scheduler64-crashed-owner")
		v, err := scheduler64Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := v["item"].(map[string]any)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		aq := orderedApplicationRequest(o, w, e, r, s, "claim", 4, 0)
		aq["worker_id"], aq["lease_token"], aq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		if _, err = orderedApplicationCall(ctx, action, aq, policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal(err)
		}
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 5, 1)); err != nil {
			t.Fatal(err)
		}
		restart, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restart.Close(ctx)
		next := scheduler64Request("scheduler64-restarted-owner")
		next["worker_id"] = "scheduler64-restarted"
		next["action_worker_id"] = "scheduler64-restarted-action"
		next["deployment_worker_id"] = "scheduler64-restarted-deployment"
		next["action_lease_token"] = strings.Repeat("c", 32)
		next["deployment_lease_token"] = strings.Repeat("d", 32)
		if got, err := scheduler64Call(ctx, restart, next); err != nil || got["outcome"] != "empty" {
			t.Fatal("live predecessor adopted", got, err)
		}
		var expiry time.Time
		if err = owner.QueryRow(ctx, `SELECT greatest((SELECT max(lease_expires_at) FROM zasp_security_agent_effects WHERE run_id=$1),(SELECT max(lease_expires_at) FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1))`, r).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(time.Until(expiry) + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		v, err = scheduler64Call(ctx, restart, next)
		if err != nil || v["outcome"] != "claimed" {
			t.Fatal("actual-expiry recovery not selected", v, err)
		}
		nextItem := v["item"].(map[string]any)
		if nextItem["schedule_id"] == item["schedule_id"] || nextItem["state_class"] != "recovery" {
			t.Fatal("old schedule overwritten", nextItem)
		}
		var oldState string
		if err = owner.QueryRow(ctx, `SELECT state FROM zasp_ordered_scheduler64.schedule_leases WHERE schedule_id=$1`, item["schedule_id"]).Scan(&oldState); err != nil || oldState != "expired" {
			t.Fatal("expired evidence erased", oldState, err)
		}
		for _, sql := range []string{`UPDATE zasp_ordered_scheduler64.schedule_leases SET version=version+1 WHERE schedule_id=$1`, `DELETE FROM zasp_ordered_scheduler64.schedule_leases WHERE schedule_id=$1`} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, sql, item["schedule_id"])
			tx.Rollback(ctx)
			if err == nil {
				t.Fatal("expired schedule evidence mutable")
			}
		}
		aq = orderedApplicationRequest(o, w, e, r, s, "claim", 5, 1)
		aq["worker_id"], aq["lease_token"], aq["lease_seconds"] = next["action_worker_id"], next["action_lease_token"], 30
		if got, err := orderedApplicationCall(ctx, action, aq, policy.GatewayPolicyKeys{}); err != nil || got["attempt"] != float64(2) {
			t.Fatal("reviewed reclaim unavailable", got, err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 1, 1, 0, 1)
	})
}

// Break: a process crashes after public cancellation but before scheduler
// finish, leaving an expired schedule forever stranded outside runnable work.
func TestSecurityAgentScheduler64ExpiredCleanHistoryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, _ := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6433)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		q := scheduler64Request("scheduler64-clean-crash")
		got, err := scheduler64Call(ctx, worker, q)
		if err != nil || got["outcome"] != "claimed" {
			t.Fatal(got, err)
		}
		item := got["item"].(map[string]any)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err = repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 4, IdempotencyKey: "scheduler64-cancel-before-crash"}); err != nil {
			t.Fatal(err)
		}
		expiry, err := time.Parse(time.RFC3339Nano, item["lease_expires_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		scheduler64Wait(t, ctx, expiry)
		if err = precisionMigrationRunner(t, owner).DownProductionSecurityAgentScheduler(ctx); err == nil {
			t.Fatal("unreconciled expired ownership demoted")
		}
		if got, err = scheduler64Call(ctx, worker, scheduler64RestartRequest("scheduler64-clean-reconcile")); err != nil || got["outcome"] != "empty" {
			t.Fatal("clean run became runnable", got, err)
		}
		var state string
		if err = owner.QueryRow(ctx, `SELECT state FROM zasp_ordered_scheduler64.schedule_leases WHERE schedule_id=$1`, item["schedule_id"]).Scan(&state); err != nil || state != "reconciled" {
			t.Fatal("expired clean history stranded", state, err)
		}
		if err = precisionMigrationRunner(t, owner).DownProductionSecurityAgentScheduler(ctx); err != nil {
			t.Fatal("verified expired history demotion", err)
		}
	})
}
