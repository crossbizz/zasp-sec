package apiserver

import (
	"context"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

// Break: a bounded pre-eligibility window repeats an ineligible prefix forever,
// or concurrent claimers return duplicate schedules for the same tenant/run.
func TestSecurityAgentScheduler64EligibleWindowPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(_ context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		oldest := ""
		for n := 1; n <= 101; n++ {
			r := worker63Trigger(t, ctx, owner, api, o, w, e, actor, 6500+n)
			if n == 1 {
				oldest = r
			}
		}
		// Legacy rows are explicit negative input, never successful ordered evidence.
		if inserted, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at) SELECT d.organization_id,d.workspace_id,d.environment_id,public.zasp_discovery_canonical_id($1,$2,$3,'scheduler64_legacy',g::text),d.definition_id,d.version,public.zasp_discovery_canonical_id($1,$2,$3,'scheduler64_legacy',g::text),$4,'queued',clock_timestamp()-interval '1 day' FROM (SELECT * FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND body->'max_steps'='1'::jsonb ORDER BY definition_id LIMIT 1) d CROSS JOIN generate_series(1,101) g`, o, w, e, actor); err != nil || inserted.RowsAffected() != 101 {
			t.Fatal("legacy negative backlog", inserted.RowsAffected(), err)
		}
		fo, fw, fe := worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 64)
		worker63Activate(t, ctx, owner, api, fo, fw, fe, testID, actor)
		worker63Pricing(t, ctx, owner, fo, fw, fe, actor)
		foreign, _ := scheduler64Admitted(t, ctx, owner, worker, api, fo, fw, fe, testID, actor, 6701)
		public62TypedDecision(t, ctx, api, fo, fw, fe, foreign, 3)
		q := scheduler64Request("scheduler64-beyond-prefix")
		v, err := scheduler64Call(ctx, worker, q)
		if err != nil || v["outcome"] != "claimed" {
			t.Fatal("ineligible prefix starved eligible tenant", v, err)
		}
		item := v["item"].(map[string]any)
		if item["run_id"] != foreign || item["organization_id"] != fo {
			t.Fatal("wrong eligible tenant", item)
		}
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 4, 1)); err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		pq := worker63ClaimRequest("scheduler64-oldest-planning")
		pv, err := worker63Call(ctx, worker, pq)
		if err != nil || pv["outcome"] != "claimed" {
			t.Fatal(err)
		}
		pi := pv["item"].(map[string]any)
		if pi["run_id"] != oldest {
			t.Fatal("oldest planning eligibility", pi)
		}
		worker63Admit(t, ctx, worker, o, w, e, oldest, testID, pq, pi)
		if _, err = worker63Call(ctx, worker, map[string]any{"operation": "finish", "worker_id": pq["worker_id"], "lease_token": pq["lease_token"], "dispatch_id": pi["dispatch_id"], "run_version": 3, "dispatch_version": 1}); err != nil {
			t.Fatal(err)
		}
		public62TypedDecision(t, ctx, api, o, w, e, oldest, 3)
		v, err = scheduler64Call(ctx, worker, scheduler64Request("scheduler64-oldest-restored"))
		if err != nil || v["outcome"] != "claimed" || v["item"].(map[string]any)["run_id"] != oldest {
			t.Fatal("oldest eligible priority lost", v, err)
		}
		// One eligible run remains. Both callers begin behind the same global lock.
		a, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		b, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close(ctx)
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('ordered-scheduler64-selection',0))`); err != nil {
			t.Fatal(err)
		}
		type answer struct {
			v   map[string]any
			err error
		}
		answers := make(chan answer, 2)
		for n, c := range []*pgx.Conn{a, b} {
			go func(c *pgx.Conn, n int) {
				rq := scheduler64Request([]string{"scheduler64-concurrent-a", "scheduler64-concurrent-b"}[n])
				got, err := scheduler64Call(ctx, c, rq)
				answers <- answer{got, err}
			}(c, n)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		claimed, empty := 0, 0
		for n := 0; n < 2; n++ {
			got := <-answers
			if got.err != nil {
				t.Fatal(got.err)
			}
			switch got.v["outcome"] {
			case "claimed":
				claimed++
				if got.v["item"].(map[string]any)["run_id"] != foreign {
					t.Fatal("cross-tenant selection", got.v)
				}
			case "empty":
				empty++
			default:
				t.Fatal(got.v)
			}
		}
		if claimed != 1 || empty != 1 {
			t.Fatal("duplicate concurrent owners", claimed, empty)
		}
		scheduler64Fault(t, ctx, owner, worker, `DELETE FROM zasp_security_agent_audit WHERE run_id=(SELECT run_id FROM zasp_security_agent_runs WHERE organization_id=$1 AND definition_id=$2 AND state='queued' ORDER BY created_at,run_id LIMIT 1) AND event_kind='ordered_public_triggered'`, []any{o, public62Definition}, scheduler64Request("scheduler64-contradictory-prefix"))
	})
}

// Break: a claim waiting for organization authority uses its old prefilter
// after genuine public cancellation has made the selected run clean terminal.
func TestSecurityAgentScheduler64OrganizationWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, _ := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6702)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		if _, err := api.Exec(ctx, `BEGIN;SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, pgx.QueryExecModeSimpleProtocol, o); err != nil {
			t.Fatal(err)
		}
		defer api.Exec(ctx, `ROLLBACK`)
		type answer struct {
			v   map[string]any
			err error
		}
		done := make(chan answer, 1)
		go func() {
			v, err := scheduler64Call(ctx, worker, scheduler64Request("scheduler64-after-organization-wait"))
			done <- answer{v, err}
		}()
		waitOrderedProgressionBlocked(t, ctx, api, worker)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 4, IdempotencyKey: "scheduler64-wait-cancel"}); err != nil {
			t.Fatal(err)
		}
		if _, err := api.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		got := <-done
		if got.err != nil || got.v["outcome"] != "empty" {
			t.Fatal("stale organization prefilter scheduled cancelled work", got.v, got.err)
		}
		var untouched bool
		if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='cancelled')`, r).Scan(&untouched); err != nil || !untouched {
			t.Fatal("cancelled predecessor rewritten", untouched, err)
		}
	})
}
