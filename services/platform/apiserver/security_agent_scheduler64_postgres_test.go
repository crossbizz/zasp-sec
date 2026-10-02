package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type scheduler64Runner interface {
	UpProductionSecurityAgentScheduler(context.Context) error
	DownProductionSecurityAgentScheduler(context.Context) error
}

func scheduler64Call(ctx context.Context, c *pgx.Conn, q map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(q)
	var response []byte
	err := c.QueryRow(ctx, `SELECT zasp_ordered_scheduler64.scheduler($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentScheduler().Checksum(), migrations.SecurityAgentSchedulerFingerprint(), raw).Scan(&response)
	var v map[string]any
	if err == nil {
		err = json.Unmarshal(response, &v)
	}
	return v, err
}
func scheduler64Request(token string) map[string]any {
	return map[string]any{"operation": "claim", "worker_id": "scheduler64-worker", "schedule_token": token, "action_worker_id": "ordered-application-worker", "action_lease_token": strings.Repeat("a", 32), "deployment_worker_id": "ordered-deployment-worker", "deployment_lease_token": strings.Repeat("b", 32), "lease_seconds": 30, "executor_lease_seconds": 30, "limit": 1}
}
func scheduler64Setup(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	r := precisionMigrationRunner(t, owner)
	for _, call := range []func(context.Context) error{r.UpProductionSecurityAgentPublic, r.UpProductionSecurityAgentWorker, r.UpProductionSecurityAgentScheduler} {
		if err := call(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
func scheduler64Admitted(t *testing.T, ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string, n int) (string, string) {
	t.Helper()
	r := worker63Trigger(t, ctx, owner, api, o, w, e, actor, n)
	q := worker63ClaimRequest("scheduler64-planning-" + r)
	v, err := worker63Call(ctx, worker, q)
	if err != nil || v["outcome"] != "claimed" {
		t.Fatal("authentic planning claim", v, err)
	}
	item := v["item"].(map[string]any)
	if item["run_id"] != r {
		t.Fatal("unexpected planning selection", item)
	}
	worker63Admit(t, ctx, worker, o, w, e, r, testID, q, item)
	_, err = worker63Call(ctx, worker, map[string]any{"operation": "finish", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": 3, "dispatch_version": 1})
	if err != nil {
		t.Fatal("authentic planning handoff", err)
	}
	var step string
	if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0`, r).Scan(&step); err != nil {
		t.Fatal(err)
	}
	return r, step
}

// Break: a scheduler picks an approval pause, trusts caller scope, skips
// retained-public validation, or grants executable authority to the API.
func TestSecurityAgentScheduler64ClaimPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		var callable bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('zasp_ordered_scheduler64.scheduler(text,text,jsonb)') IS NOT NULL`).Scan(&callable); err != nil {
			t.Fatal(err)
		}
		if !callable {
			t.Fatal("scheduler64 claim authority absent")
		}
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		r, _ := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6401)
		q := scheduler64Request("scheduler64-claim-token")
		if v, err := scheduler64Call(ctx, worker, q); err != nil || v["outcome"] != "empty" {
			t.Fatal("approval pause selected", v, err)
		}
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		first, err := scheduler64Call(ctx, worker, q)
		if err != nil || first["outcome"] != "claimed" {
			t.Fatal("approved application not selected", first, err)
		}
		item := first["item"].(map[string]any)
		if item["run_id"] != r || item["organization_id"] != o || item["run_version"] != float64(4) || item["state_class"] != "application" || item["schedule_version"] != float64(1) {
			t.Fatal("wrong selected authority", item)
		}
		if replay, err := scheduler64Call(ctx, worker, q); err != nil || !jsonEqualMaps(first, replay) {
			t.Fatal("unstable replay", replay, err)
		}
		if _, err := scheduler64Call(ctx, api, map[string]any{"operation": "ready"}); err == nil {
			t.Fatal("API received scheduler authority")
		}
		if v, err := scheduler64Call(ctx, worker, scheduler64Request("scheduler64-second-token")); err != nil || v["outcome"] != "empty" {
			t.Fatal("duplicate owner", v, err)
		}
		q["action_lease_token"] = strings.Repeat("c", 32)
		if _, err := scheduler64Call(ctx, worker, q); err == nil {
			t.Fatal("action token substitution accepted")
		}
		for _, sql := range []string{`UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id IN(SELECT approver_id FROM zasp_security_agent_approvals WHERE run_id=$1)`, `UPDATE zasp_security_agent_approvals SET state='rejected' WHERE run_id=$1`} {
			scheduler64Fault(t, ctx, owner, worker, sql, []any{r}, scheduler64Request("scheduler64-claim-token"))
		}
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentScheduler(ctx); err == nil {
			t.Fatal("active ownership discarded")
		}
	})
}

// Break: a scheduler can run without its own pinned extension registration, or
// its install changes predecessor authority or the canonical migration chain.
func TestSecurityAgentScheduler64RegistrationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		ext, ok := any(runner).(scheduler64Runner)
		if !ok {
			t.Fatal("scheduler64 registered extension absent")
		}
		probe, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = probe.Exec(ctx, migrations.ProductionSecurityAgentScheduler().UpSQL()); err != nil {
			t.Fatal(err)
		}
		var probeFingerprint string
		if err = probe.QueryRow(ctx, `SELECT zasp_ordered_scheduler64.fingerprint()`).Scan(&probeFingerprint); err != nil {
			t.Fatal(err)
		}
		t.Log("candidate scheduler64 fingerprint", probeFingerprint)
		if err = probe.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var before, after string
		const predecessors = `SELECT jsonb_build_array(zasp_sa_multistep_registered_live_fingerprint(),zasp_ordered_worker63.fingerprint(),zasp_ordered_public62.fingerprint(),(SELECT jsonb_agg(to_jsonb(x) ORDER BY version) FROM zasp_schema_versions x),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_ordered_worker63.registration x),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_ordered_public62.registration x))::text`
		if err := owner.QueryRow(ctx, predecessors).Scan(&before); err != nil {
			t.Fatal(err)
		}
		for index, call := range []func(context.Context) error{ext.UpProductionSecurityAgentScheduler, ext.UpProductionSecurityAgentScheduler, ext.DownProductionSecurityAgentScheduler, ext.DownProductionSecurityAgentScheduler, ext.UpProductionSecurityAgentScheduler} {
			if err := call(ctx); err != nil {
				if index == 2 {
					diagnostic, _ := owner.Begin(ctx)
					_, cause := diagnostic.Exec(ctx, migrations.ProductionSecurityAgentScheduler().DownSQL())
					diagnostic.Rollback(ctx)
					t.Log("down diagnostic", cause)
				}
				t.Fatal("registration replay", index, err)
			}
		}
		if err := owner.QueryRow(ctx, predecessors).Scan(&after); err != nil || before != after {
			t.Fatal("predecessor drift", err)
		}
		var count int
		if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_schema_versions`).Scan(&count); err != nil || count != 61 {
			t.Fatal("canonical chain changed", count, err)
		}
		var fingerprint string
		if err := owner.QueryRow(ctx, `SELECT zasp_ordered_scheduler64.fingerprint()`).Scan(&fingerprint); err != nil {
			t.Fatal(err)
		}
		t.Log("scheduler64 fingerprint", fingerprint)
	})
}
