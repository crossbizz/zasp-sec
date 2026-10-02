package apiserver

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Break: independent global selection locks let scheduler64 inspect A then B
// while worker63's expired-dispatch recovery inspects B then A, deadlocking.
func TestSecurityAgentScheduler64WorkerRecoveryLockOrderPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(_ context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		bo, bw, be := worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 65)
		worker63Activate(t, ctx, owner, api, bo, bw, be, testID, actor)
		a := worker63Trigger(t, ctx, owner, api, o, w, e, actor, 6901)
		b := worker63Trigger(t, ctx, owner, api, bo, bw, be, actor, 6902)
		// Pricing makes B eligible first, without changing queued/planning rows.
		for n, tenant := range [][4]string{{bo, bw, be, b}, {o, w, e, a}} {
			worker63Pricing(t, ctx, owner, tenant[0], tenant[1], tenant[2], actor)
			q := worker63ClaimRequest([]string{"scheduler64-lock-plan-b", "scheduler64-lock-plan-a"}[n])
			v, err := worker63Call(ctx, worker, q)
			if err != nil || v["outcome"] != "claimed" {
				t.Fatal("authentic reverse dispatch", v, err)
			}
			item := v["item"].(map[string]any)
			if item["run_id"] != tenant[3] {
				t.Fatal("wrong reverse dispatch", item)
			}
			worker63Admit(t, ctx, worker, tenant[0], tenant[1], tenant[2], tenant[3], testID, q, item)
		}
		// Approval advances B after A's admission. A remains an authentic approval
		// pause, so recovery hands A off while scheduling selects runnable B.
		public62TypedDecision(t, ctx, api, bo, bw, be, b, 3)
		var runOrder, dispatchOrder []string
		if err := owner.QueryRow(ctx, `SELECT array_agg(run_id ORDER BY ctid) FROM zasp_security_agent_runs WHERE run_id=ANY($1)`, []string{a, b}).Scan(&runOrder); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT array_agg(run_id ORDER BY ctid) FROM zasp_ordered_worker63.dispatch_leases`).Scan(&dispatchOrder); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(runOrder, []string{a, b}) || !reflect.DeepEqual(dispatchOrder, []string{b, a}) {
			t.Fatal("fixture needs opposite physical orders", runOrder, dispatchOrder)
		}
		var expiry time.Time
		if err := owner.QueryRow(ctx, `SELECT max(lease_expires_at) FROM zasp_ordered_worker63.dispatch_leases`).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		worker63Wait(t, ctx, expiry)
		scheduler, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer scheduler.Close(context.Background())
		barrier, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer barrier.Rollback(context.Background())
		if _, err := barrier.Exec(ctx, `SELECT 1 FROM zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) FOR UPDATE`, bo, bw, be, b); err != nil {
			t.Fatal(err)
		}
		type answer struct {
			value map[string]any
			err   error
		}
		recovered, scheduled := make(chan answer, 1), make(chan answer, 1)
		go func() {
			v, err := worker63Call(ctx, worker, worker63ClaimRequest("scheduler64-lock-recovery"))
			recovered <- answer{v, err}
		}()
		scheduler64WaitForBlocker(t, ctx, owner, worker.PgConn().PID(), owner.PgConn().PID())
		q := scheduler64Request("scheduler64-lock-selection")
		go func() {
			v, err := scheduler64Call(ctx, scheduler, q)
			scheduled <- answer{v, err}
		}()
		// Old code holds A and waits for B. Fixed code waits on worker63's
		// global lock before taking any organization lock. Both reach this
		// observed barrier; releasing the row makes only old code form a cycle.
		scheduler64WaitForBlocker(t, ctx, owner, scheduler.PgConn().PID(), worker.PgConn().PID())
		var locks string
		if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('pid',pid,'type',locktype,'mode',mode,'granted',granted,'classid',classid,'objid',objid))::text FROM pg_locks WHERE pid=ANY($1) AND locktype IN('advisory','transactionid')`, []int64{int64(worker.PgConn().PID()), int64(scheduler.PgConn().PID())}).Scan(&locks); err != nil {
			t.Fatal(err)
		}
		t.Log("observed overlap", locks)
		if err := barrier.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		rv, sv := <-recovered, <-scheduled
		if rv.err != nil || sv.err != nil {
			t.Fatalf("cross-extension claim/recovery deadlocked or failed: worker=%v scheduler=%v", rv.err, sv.err)
		}
		if rv.value["outcome"] != "empty" || sv.value["outcome"] != "claimed" || sv.value["item"].(map[string]any)["run_id"] != b {
			t.Fatal("cross-extension selection", rv.value, sv.value)
		}
		if replay, err := scheduler64Call(ctx, scheduler, q); err != nil || !jsonEqualMaps(sv.value, replay) {
			t.Fatal("mixed-extension replay changed", replay, err)
		}
		var valid bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$2) AND NOT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$2) AND (SELECT count(*)=2 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=ANY($3) AND state='admitted') AND (SELECT count(*)=2 FROM zasp_sa_multistep_prior.admissions WHERE run_id=ANY($3))`, a, b, []string{a, b}).Scan(&valid); err != nil || !valid {
			t.Fatal("mixed selection changed predecessor admission or duplicated work", valid, err)
		}
		// Existing scoped mutations must not join the multi-organization dispatch
		// scan's new outer lock. Holding that lock cannot strand an owned heartbeat
		// or pre-effect abandonment. This is an unchanged-behavior check.
		mutationBarrier, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer mutationBarrier.Rollback(context.Background())
		if _, err := mutationBarrier.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ordered-worker63-dispatch',0))`); err != nil {
			t.Fatal(err)
		}
		mutationCtx, mutationCancel := context.WithTimeout(ctx, 10*time.Second)
		defer mutationCancel()
		item := sv.value["item"].(map[string]any)
		beat, err := scheduler64Call(mutationCtx, scheduler, scheduler64Mutation(q, item, "heartbeat", 4, 1))
		if err != nil || beat["outcome"] != "extended" {
			t.Fatal("scoped heartbeat waited for global dispatch", beat, err)
		}
		abandoned, err := scheduler64Call(mutationCtx, scheduler, scheduler64Mutation(q, beat["item"].(map[string]any), "abandon", 4, 2))
		if err != nil || abandoned["outcome"] != "released" {
			t.Fatal("scoped abandon waited for global dispatch", abandoned, err)
		}
		if err := mutationBarrier.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// A database-observed barrier, never a timing delay to induce overlap.
func scheduler64WaitForBlocker(t *testing.T, ctx context.Context, observer *pgx.Conn, waiter, blocker uint32) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for {
		var blocked bool
		if err := observer.QueryRow(waitCtx, `SELECT $2::int=ANY(pg_blocking_pids($1::int))`, waiter, blocker).Scan(&blocked); err != nil {
			t.Fatal("controlled overlap did not reach expected blocker", err)
		}
		if blocked {
			return
		}
	}
}
