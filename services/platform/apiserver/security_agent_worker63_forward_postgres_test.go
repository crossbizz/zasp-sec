package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func worker63NewTenant(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, testID, actor string, n int) (string, string, string) {
	t.Helper()
	fo, fw, fe := fmt.Sprintf("pid_9b%06d-0000-4000-8000-000000000001", n), fmt.Sprintf("pid_9b%06d-0000-4000-8000-000000000002", n), fmt.Sprintf("pid_9b%06d-0000-4000-8000-000000000003", n)
	_, err := owner.Exec(ctx, `INSERT INTO zasp_organizations(id,name,domain) VALUES($5,'Dispatch second tenant','dispatch-second.invalid');
 INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($6,$5,'Dispatch second workspace');
 INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($7,$5,$6,'Dispatch staging','staging');
 INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
 SELECT $5,$6,$7,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes FROM zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND id=(SELECT target_id FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4));
 SELECT zasp_attack_lab_register_credential_binding($5,$6,$7,'pid_9b000013-0000-4000-8000-000000000003',target_id,credential_reference,credential_class,1,decode(repeat('ab',32),'hex'),clock_timestamp()+interval '1 hour') FROM zasp_attack_lab_credential_bindings WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by)
 SELECT $5,$6,$7,definition_id,name,target_id,target_kind,categories,safety,created_by FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4);
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($5,$6,$7,'*',true,$8),($5,$6,$7,'create_temporary_policy',true,$8)`, pgx.QueryExecModeSimpleProtocol, o, w, e, testID, fo, fw, fe, actor)
	if err != nil {
		t.Fatal("tenant prerequisites", err)
	}
	for i, p := range []string{actor, orderedProgressionApprover} {
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($1,$2,$3,$4,'organization_admin'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$5,$6,'Worker63 fixture','["view","manage_identity","manage_workflows","run_tests"]')`, pgx.QueryExecModeSimpleProtocol, p, fo, fmt.Sprintf("worker63-org-%d", n), fmt.Sprintf("worker63-member-%d-%d", n, i), fw, fe); err != nil {
			t.Fatal(err)
		}
	}
	return fo, fw, fe
}

func worker63Activate(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
	t.Helper()
	public62Seed(t, ctx, owner, o, w, e, testID, actor)
	q := public62Request(o, w, e, actor, "activate")
	q["definition_id"] = public62Definition
	q["definition_version"] = 1
	if _, err := public62Call(ctx, api, q); err != nil {
		t.Fatal("activate", err)
	}
}

func worker63Trigger(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, actor string, n int) string {
	t.Helper()
	finding := fmt.Sprintf("pid_9c%06d-0000-4000-8000-000000000001", n)
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Worker63 progress input','high','open')`, o, w, e, finding); err != nil {
		t.Fatal(err)
	}
	q := public62Request(o, w, e, actor, "trigger")
	q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, finding, 1, fmt.Sprintf("worker63-progress-trigger-%d", n)
	got, err := public62Call(ctx, api, q)
	if err != nil {
		t.Fatal("trigger", n, err)
	}
	return got["run_id"].(string)
}

// Removing pre-LIMIT eligibility would trap every call behind the same 101
// authentic unpriced rows. Pricing the oldest row later must restore its priority.
func TestSecurityAgentWorker63EligibleWindowPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		oldest := ""
		for n := 1; n <= 101; n++ {
			r := worker63Trigger(t, ctx, owner, api, o, w, e, actor, n)
			if n == 1 {
				oldest = r
			}
		}
		// The older legacy backlog is a negative input; none of these rows is
		// successful public/planning evidence.
		if inserted, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,created_at) SELECT d.organization_id,d.workspace_id,d.environment_id,public.zasp_discovery_canonical_id($1,$2,$3,'worker63_legacy',g::text),d.definition_id,d.version,public.zasp_discovery_canonical_id($1,$2,$3,'worker63_legacy',g::text),$4,'queued',clock_timestamp()-interval '1 day' FROM (SELECT * FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) AND body->'max_steps'='1'::jsonb ORDER BY definition_id LIMIT 1) d CROSS JOIN generate_series(1,101) g`, o, w, e, actor); err != nil || inserted.RowsAffected() != 101 {
			t.Fatal("expected 101 legacy negative inputs", inserted.RowsAffected(), err)
		}
		fo, fw, fe := worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 1)
		worker63Activate(t, ctx, owner, api, fo, fw, fe, testID, actor)
		worker63Pricing(t, ctx, owner, fo, fw, fe, actor)
		first := worker63Trigger(t, ctx, owner, api, fo, fw, fe, actor, 102)
		second := worker63Trigger(t, ctx, owner, api, fo, fw, fe, actor, 103)
		for _, wanted := range []struct{ token, run, org string }{{"worker63-progress-first", first, fo}, {"worker63-progress-reenabled", oldest, o}, {"worker63-progress-second", second, fo}} {
			if wanted.run == oldest {
				worker63Pricing(t, ctx, owner, o, w, e, actor)
			}
			if wanted.run == second { // Disable the first tenant through reviewed pricing administration.
				config := owner.Config().Copy()
				config.User = "security_agent_v33_discovery_api_login"
				admin, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				q := orderedPricingAdminRequest(o, w, e, actor)
				q["operation"] = "disable"
				q["expected_version"] = 1
				q["expected_account_version"] = 1
				q["idempotency_key"] = "worker63-disable-unpriced-prefix"
				var p []byte
				if err = owner.QueryRow(ctx, `SELECT policy FROM zasp_sa_multistep_prior.pricing_policies WHERE organization_id=$1 ORDER BY version DESC LIMIT 1`, o).Scan(&p); err != nil {
					t.Fatal(err)
				}
				var policy map[string]any
				_ = json.Unmarshal(p, &policy)
				q["policy"] = policy
				if _, err = orderedPricingCall(ctx, admin, "pricing_admin", q); err != nil {
					t.Fatal("disable", err)
				}
				admin.Close(ctx)
			}
			got, err := worker63Call(ctx, worker, worker63ClaimRequest(wanted.token))
			if err != nil || got["outcome"] != "claimed" {
				t.Fatal("persistent ineligible prefix blocked global claim", wanted.run, got, err)
			}
			item := got["item"].(map[string]any)
			if item["run_id"] != wanted.run || item["organization_id"] != wanted.org {
				t.Fatal("oldest eligible/tenant changed", wanted.run, item)
			}
		}
		// An ordered-looking corrupted prefix still fails the call; unpriced is
		// not permission to ignore broken public history.
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `DELETE FROM zasp_security_agent_audit WHERE run_id=(SELECT run_id FROM zasp_security_agent_runs WHERE organization_id=$1 AND definition_id=$2 AND state='queued' ORDER BY created_at,run_id LIMIT 1) AND event_kind='ordered_public_triggered'`, o, public62Definition); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		// This transaction uses the same worker entry with the uncommitted negative mutation.
		raw := worker63RawClaim("worker63-corrupt-prefix")
		var response []byte
		err = tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
		tx.Rollback(ctx)
		if err == nil {
			t.Fatal("contradictory unpriced ordered prefix was skipped")
		}

		raced := worker63Trigger(t, ctx, owner, api, fo, fw, fe, actor, 104)
		lock, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, fo); err != nil {
			t.Fatal(err)
		}
		type racedResult struct {
			got map[string]any
			err error
		}
		done := make(chan racedResult, 1)
		go func() {
			got, err := worker63Call(ctx, worker, worker63ClaimRequest("worker63-revalidated-after-pricing-wait"))
			done <- racedResult{got, err}
		}()
		waitOrderedProgressionBlocked(t, ctx, owner, worker)
		var policyRaw []byte
		if err = lock.QueryRow(ctx, `SELECT policy FROM zasp_sa_multistep_prior.pricing_policies WHERE organization_id=$1 ORDER BY version DESC LIMIT 1`, fo).Scan(&policyRaw); err != nil {
			t.Fatal(err)
		}
		var policy map[string]any
		_ = json.Unmarshal(policyRaw, &policy)
		disable := orderedPricingAdminRequest(fo, fw, fe, actor)
		disable["operation"] = "disable"
		disable["expected_version"] = 1
		disable["expected_account_version"] = 1
		disable["policy"] = policy
		disable["idempotency_key"] = "worker63-disable-after-prefilter"
		raw, _ = json.Marshal(disable)
		if _, err = lock.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION security_agent_v33_discovery_api_login`); err != nil {
			t.Fatal(err)
		}
		if err = lock.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.pricing_admin($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), raw).Scan(&policyRaw); err != nil {
			t.Fatal(err)
		}
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		answer := <-done
		if answer.err != nil || answer.got["outcome"] != "empty" {
			t.Fatal("stale prefilter granted revoked pricing", answer.got, answer.err)
		}
		var untouched bool
		if err = owner.QueryRow(ctx, `SELECT state='queued' AND version=1 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1) FROM zasp_security_agent_runs WHERE run_id=$1`, raced).Scan(&untouched); err != nil || !untouched {
			t.Fatal("prefilter wait changed predecessor", err)
		}
	})
}

func worker63RawClaim(token string) []byte {
	b, _ := json.Marshal(worker63ClaimRequest(token))
	return b
}

// Hold a later organization's lock after the first handoff was classified.
// Clock expiry is real; no predecessor row is rewritten to force the race.
func TestSecurityAgentWorker63RecoveryRevalidationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r := worker63Trigger(t, ctx, owner, api, o, w, e, actor, 700)
		q := worker63ClaimRequest("worker63-revalidation-first")
		got, err := worker63Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		worker63Admit(t, ctx, worker, o, w, e, r, testID, q, got["item"].(map[string]any))
		var step string
		if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0`, r).Scan(&step); err != nil {
			t.Fatal(err)
		}
		if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, step, "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
		fo, fw, fe := worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 40)
		worker63Activate(t, ctx, owner, api, fo, fw, fe, testID, actor)
		worker63Pricing(t, ctx, owner, fo, fw, fe, actor)
		worker63Trigger(t, ctx, owner, api, fo, fw, fe, actor, 701)
		tail := worker63ClaimRequest("worker63-revalidation-tail")
		got, err = worker63Call(ctx, worker, tail)
		if err != nil {
			t.Fatal(err)
		}
		item := got["item"].(map[string]any)
		if _, err = worker63Call(ctx, worker, map[string]any{"operation": "abandon", "worker_id": tail["worker_id"], "lease_token": tail["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": 2, "dispatch_version": 1}); err != nil {
			t.Fatal(err)
		}
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		request := orderedApplicationRequest(o, w, e, r, step, "claim", 4, 0)
		request["lease_seconds"] = 30
		if _, err = orderedApplicationCall(ctx, action, request, policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal(err)
		}
		var expiry time.Time
		if err = owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_security_agent_effects WHERE run_id=$1 AND step_id=$2`, r, step).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		worker63Wait(t, ctx, expiry.Add(-2*time.Second))
		lock, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(ctx)
		if _, err = lock.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, fo); err != nil {
			t.Fatal(err)
		}
		type answer struct {
			value map[string]any
			err   error
		}
		done := make(chan answer, 1)
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		go func() {
			value, err := worker63Call(bounded, worker, worker63ClaimRequest("worker63-revalidation-observer"))
			done <- answer{value, err}
		}()
		waitOrderedProgressionBlocked(t, ctx, owner, worker)
		var firstUnlocked bool
		if err = lock.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o).Scan(&firstUnlocked); err != nil || firstUnlocked {
			t.Fatal("first handoff was not classified before the later lock wait", firstUnlocked, err)
		}
		worker63Wait(t, ctx, expiry)
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result := <-done
		if result.err != nil || result.value["outcome"] != "empty" {
			t.Fatal(result.value, result.err)
		}
		var retained bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1 AND state='active')`, r).Scan(&retained); err != nil || !retained {
			t.Fatal("stale prefilter released expired executor", err)
		}
		if orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("revalidation changed predecessor")
		}
	})
}

func TestSecurityAgentWorker63RecoveryWindowPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		var fo, fw, fe string
		type retainedLease struct{ request, item map[string]any }
		var retained []retainedLease
		for n := 0; n < 101; n++ {
			if n%10 == 0 {
				fo, fw, fe = worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 10+n/10)
				worker63Activate(t, ctx, owner, api, fo, fw, fe, testID, actor)
				worker63Pricing(t, ctx, owner, fo, fw, fe, actor)
			}
			r := worker63Trigger(t, ctx, owner, api, fo, fw, fe, actor, 200+n)
			q := worker63ClaimRequest(fmt.Sprintf("worker63-later-stage-%d", n))
			q["lease_seconds"] = 300
			got, err := worker63Call(ctx, worker, q)
			if err != nil || got["outcome"] != "claimed" {
				t.Fatal(n, got, err)
			}
			item := got["item"].(map[string]any)
			if item["run_id"] != r {
				t.Fatal("unexpected oldest", n, item)
			}
			worker63Admit(t, ctx, worker, fo, fw, fe, r, testID, q, item)
			var step string
			if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0`, r).Scan(&step); err != nil {
				t.Fatal(err)
			}
			if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(fo, fw, fe, r, step, "approve", orderedProgressionApprover, 3)); err != nil {
				t.Fatal(err)
			}
			retained = append(retained, retainedLease{q, item})
			// Keep setup from repeatedly recovering already-built rows. This is
			// the real heartbeat boundary and changes no predecessor lease.
			if n%20 == 19 {
				for i := range retained {
					old := retained[i]
					beat, err := worker63Call(ctx, worker, map[string]any{"operation": "heartbeat", "worker_id": old.request["worker_id"], "lease_token": old.request["lease_token"], "dispatch_id": old.item["dispatch_id"], "run_version": 4, "dispatch_version": old.item["dispatch_version"], "lease_seconds": 300})
					if err != nil {
						t.Fatal("setup heartbeat", n, i, err)
					}
					retained[i].item = beat["item"].(map[string]any)
				}
			}
			if n%10 == 9 {
				t.Log("authentic later-stage prefix", n+1)
			}
		}
		fo, fw, fe = worker63NewTenant(t, ctx, owner, o, w, e, testID, actor, 30)
		worker63Activate(t, ctx, owner, api, fo, fw, fe, testID, actor)
		worker63Pricing(t, ctx, owner, fo, fw, fe, actor)
		var tails, handoffs []string
		for n := 0; n < 4; n++ {
			r := worker63Trigger(t, ctx, owner, api, fo, fw, fe, actor, 400+n)
			q := worker63ClaimRequest(fmt.Sprintf("worker63-recovery-tail-%d", n))
			got, err := worker63Call(ctx, worker, q)
			if err != nil || got["outcome"] != "claimed" {
				t.Fatal(got, err)
			}
			if n < 2 {
				tails = append(tails, r)
			} else {
				handoffs = append(handoffs, r)
				worker63Admit(t, ctx, worker, fo, fw, fe, r, testID, q, got["item"].(map[string]any))
			}
		}
		var expires time.Time
		if err := owner.QueryRow(ctx, `SELECT max(lease_expires_at) FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=ANY($1)`, tails).Scan(&expires); err != nil {
			t.Fatal(err)
		}
		t.Log("101 authentic approved runs retained; waiting for actual planner expiry", expires)
		timer := time.NewTimer(time.Until(expires) + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		for n := 0; n < 2; n++ {
			bounded, stop := context.WithTimeout(ctx, 5*time.Second)
			started := time.Now()
			got, err := worker63Call(bounded, worker, worker63ClaimRequest(fmt.Sprintf("worker63-recovery-tail-restart-%d", n)))
			stop()
			t.Log("bounded maintenance call", n, time.Since(started))
			if err != nil || got["outcome"] != "empty" {
				t.Fatal(got, err)
			}
			var reconciled, remaining int
			if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=ANY($1) AND state='reconciled'),(SELECT count(*) FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=ANY($2))`, tails, handoffs).Scan(&reconciled, &remaining); err != nil || reconciled != n+1 || remaining != 1-n {
				t.Fatal("maintenance failed to advance one item per class", n, reconciled, remaining, err)
			}
			var oldest bool
			if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$1 AND state='reconciled') AND NOT EXISTS(SELECT 1 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=$2)`, tails[n], handoffs[n]).Scan(&oldest); err != nil || !oldest {
				t.Fatal("maintenance did not choose the oldest eligible item in each class", n, err)
			}
		}
		var recovered bool
		if err := owner.QueryRow(ctx, `SELECT (SELECT count(*)=2 FROM zasp_ordered_worker63.dispatch_leases WHERE run_id=ANY($1) AND state='reconciled') AND (SELECT count(*)=2 FROM zasp_security_agent_runs WHERE run_id=ANY($1) AND state='needs_human' AND last_error_code='planner_not_sent') AND (SELECT count(*)=101 FROM zasp_ordered_worker63.dispatch_leases d JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE d.state='active' AND r.state='running')`, tails).Scan(&recovered); err != nil || !recovered {
			t.Fatal("persistent later-stage prefix starved expired planning recovery", err)
		}
	})
}
