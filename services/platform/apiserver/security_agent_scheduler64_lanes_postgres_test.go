package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"strings"
	"testing"
	"time"
)

func scheduler64RestartRequest(token string) map[string]any {
	q := scheduler64Request(token)
	q["worker_id"] = "scheduler64-restarted"
	q["action_worker_id"] = "scheduler64-restarted-action"
	q["action_lease_token"] = strings.Repeat("c", 32)
	q["deployment_worker_id"] = "scheduler64-restarted-deployment"
	q["deployment_lease_token"] = strings.Repeat("d", 32)
	return q
}
func scheduler64Wait(t *testing.T, ctx context.Context, deadline time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline) + 100*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
}
func scheduler64Fresh(t *testing.T, ctx context.Context, worker *pgx.Conn, q map[string]any, prior map[string]any) map[string]any {
	t.Helper()
	restart, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Close(ctx)
	got, err := scheduler64Call(ctx, restart, q)
	if err != nil || got["outcome"] != "claimed" {
		t.Fatal("actual expiry did not permit fresh identity", got, err)
	}
	item := got["item"].(map[string]any)
	if item["schedule_id"] == prior["schedule_id"] {
		t.Fatal("recovery overwrote original schedule")
	}
	return item
}

// Break: an independently live deployment lease can be adopted after the
// scheduler and action leases expire. Recovery must use the retained work.
func TestSecurityAgentScheduler64DeploymentRecoveryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		worker63Activate(t, ctx, owner, api, o, w, e, testID, actor)
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, s := scheduler64Admitted(t, ctx, owner, worker, api, o, w, e, testID, actor, 6432)
		public62TypedDecision(t, ctx, api, o, w, e, r, 3)
		q := scheduler64Request("scheduler64-deployment-crash")
		v, err := scheduler64Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := v["item"].(map[string]any)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
		defer deployment.Close(ctx)
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		aq := orderedApplicationRequest(o, w, e, r, s, "claim", 4, 0)
		aq["worker_id"], aq["lease_token"], aq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		claimed, err := orderedApplicationCall(ctx, action, aq, keys)
		if err != nil {
			t.Fatal(err)
		}
		aq = orderedApplicationStoreRequest(t, o, w, e, r, s, claimed, key)
		aq["worker_id"], aq["lease_token"], aq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		stored, err := orderedApplicationCall(ctx, action, aq, keys)
		if err != nil {
			t.Fatal(err)
		}
		dq := orderedApplicationDeploymentRequest(o, w, e, r, s, stored)
		dq["action_worker_id"], dq["action_lease_token"], dq["worker_id"], dq["lease_token"] = q["action_worker_id"], q["action_lease_token"], q["deployment_worker_id"], q["deployment_lease_token"]
		if _, err = orderedProgressionCall(ctx, deployment, "deployment", dq); err != nil {
			t.Fatal(err)
		}
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 5, 1)); err != nil {
			t.Fatal(err)
		}
		next := scheduler64RestartRequest("scheduler64-deployment-restart")
		var expiry time.Time
		if err = owner.QueryRow(ctx, `SELECT greatest((SELECT max(lease_expires_at) FROM zasp_security_agent_effects WHERE run_id=$1),(SELECT max(lease_expires_at) FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1))`, r).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		scheduler64Wait(t, ctx, expiry)
		if got, err := scheduler64Call(ctx, worker, next); err != nil || got["outcome"] != "empty" {
			t.Fatal("live deployment adopted after action expiry", got, err)
		}
		if err = owner.QueryRow(ctx, `SELECT max(d.lease_expires_at) FROM zasp_policy_deployment_work d JOIN zasp_security_agent_temporary_policy_targets t USING(organization_id,workspace_id,environment_id,device_id) WHERE t.run_id=$1`, r).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		scheduler64Wait(t, ctx, expiry)
		fresh := scheduler64Fresh(t, ctx, worker, next, item)
		if fresh["state_class"] != "stop" {
			t.Fatal("uncertain deployment not conservative", fresh)
		}
		var successor string
		if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=1`, r).Scan(&successor); err != nil {
			t.Fatal(err)
		}
		stop := orderedProgressionRequest(o, w, e, r, successor, "stop", next["action_worker_id"].(string), 5)
		stopped, err := orderedProgressionCall(ctx, worker, "transition", stop)
		if err != nil {
			t.Fatal("reviewed stop", stopped, err)
		}
		var rv, ev int
		if err = owner.QueryRow(ctx, `SELECT r.version,f.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, r).Scan(&rv, &ev); err != nil {
			t.Fatal(err)
		}
		cq := orderedCleanupRequest(o, w, e, r, s, "claim", rv, ev, 0)
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = next["action_worker_id"], next["action_lease_token"], 30
		if got, err := orderedCleanupCall(ctx, action, cq, keys); err != nil || got["attempt"] != float64(1) {
			t.Fatal("reviewed partial handoff", got, err)
		}
		var retained bool
		if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_policy_deployment_work d JOIN zasp_security_agent_temporary_policy_targets t USING(organization_id,workspace_id,environment_id,device_id) WHERE t.run_id=$1 AND t.phase='apply' AND d.attempt=1)=1 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1) AND (SELECT count(*) FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1 AND state='expired')=1`, r).Scan(&retained); err != nil || !retained {
			t.Fatal("duplicate delivery or erased recovery evidence", retained, err)
		}
	})
}

// Break: a dispatched test's expired child/journal is either stranded or sent
// again. The unchanged expiry authority must conservatively close it.
func TestSecurityAgentScheduler64TestRecoveryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		r, steps, _ := scheduler64Applied(t, ctx, owner, worker, api, o, w, e, testID, actor)
		if _, err := orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
			t.Fatal(err)
		}
		public62TypedDecision(t, ctx, api, o, w, e, r, 7)
		q := scheduler64Request("scheduler64-test-crash")
		q["action_worker_id"] = "ordered-test-worker"
		v, err := scheduler64Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := v["item"].(map[string]any)
		tq := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
		tq["lease_seconds"] = 30
		claim, err := orderedTestActionCall(ctx, worker, tq)
		if err != nil {
			t.Fatal(err)
		}
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		store, input := orderedTestInputArtifact(t, ctx, owner, o, w, e, r, steps[1], claim["test_run_id"].(string), testID)
		tq = orderedTestActionRequest(o, w, e, r, steps[1], "dispatch", 9, 1)
		tq["lease_seconds"] = 30
		tq["payload"] = map[string]any{"input_artifact": input}
		raw, _ := json.Marshal(tq)
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
		if _, err = (&securityAgentMultistepAdmissionRepository{database: db}).testDispatch(ctx, raw, store); err != nil {
			t.Fatal(err)
		}
		runOrderedJournalHTTPS(t, ctx, owner, o, w, e, claim["test_run_id"].(string), true)
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 9, 1)); err != nil {
			t.Fatal(err)
		}
		next := scheduler64RestartRequest("scheduler64-test-restart")
		if got, err := scheduler64Call(ctx, worker, next); err != nil || got["outcome"] != "empty" {
			t.Fatal("live test adopted", got, err)
		}
		var expiry time.Time
		if err = owner.QueryRow(ctx, `SELECT greatest((SELECT max(lease_expires_at) FROM zasp_security_agent_effects WHERE run_id=$1),(SELECT max(lease_expires_at) FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1),(SELECT max(c.lease_expires_at) FROM zasp_red_team_runs c JOIN zasp_security_agent_test_links l ON l.test_run_id=c.run_id WHERE l.run_id=$1))`, r).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		scheduler64Wait(t, ctx, expiry)
		scheduler64Fresh(t, ctx, worker, next, item)
		raw, _ = json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": steps[1], "operation": "reconcile_uncertain", "worker_id": next["action_worker_id"], "run_version": 9, "effect_version": 1})
		db, _ = NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		result, err := (&securityAgentMultistepAdmissionRepository{database: db}).testReconcileUncertain(ctx, raw)
		var got map[string]any
		if err != nil || json.Unmarshal(result, &got) != nil || got["run_state"] != "needs_human" || got["receipt_created"] != false {
			t.Fatal("reviewed unknown reconciliation", string(result), err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
		var count int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_test_invocations WHERE test_run_id=$1`, claim["test_run_id"]).Scan(&count); err != nil || count != 1 {
			t.Fatal("test sent twice", count, err)
		}
	})
}

// Break: cleanup recovery replaces durable cleanup identity or requires the
// crashed process's raw token rather than reviewed reconciliation.
func TestSecurityAgentScheduler64CleanupRecoveryPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		scheduler64Setup(t, ctx, owner)
		r, steps, key := scheduler64Applied(t, ctx, owner, worker, api, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Cancel(ctx, id, SecurityAgentPublicCancellation{RunID: r, RunVersion: 6, IdempotencyKey: "scheduler64-cleanup-crash"}); err != nil {
			t.Fatal(err)
		}
		q := scheduler64Request("scheduler64-cleanup-crash")
		v, err := scheduler64Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := v["item"].(map[string]any)
		config := owner.Config().Copy()
		config.User = "ordered_legacy_action_login"
		action, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer action.Close(ctx)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		cq := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 7, 3, 0)
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = q["action_worker_id"], q["action_lease_token"], 30
		claim, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = scheduler64Call(ctx, worker, scheduler64Mutation(q, item, "abandon", 7, 1)); err != nil {
			t.Fatal(err)
		}
		next := scheduler64RestartRequest("scheduler64-cleanup-restart")
		if got, err := scheduler64Call(ctx, worker, next); err != nil || got["outcome"] != "empty" {
			t.Fatal("live cleanup adopted", got, err)
		}
		var expiry time.Time
		if err = owner.QueryRow(ctx, `SELECT greatest((SELECT max(lease_expires_at) FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1),(SELECT max(lease_expires_at) FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1))`, r).Scan(&expiry); err != nil {
			t.Fatal(err)
		}
		scheduler64Wait(t, ctx, expiry)
		fresh := scheduler64Fresh(t, ctx, worker, next, item)
		if err := precisionMigrationRunner(t, owner).DownProductionSecurityAgentScheduler(ctx); err == nil {
			t.Fatal("unresolved expired history demoted")
		}
		var expiredEvidence string
		if err = owner.QueryRow(ctx, `SELECT (to_jsonb(d)-'state')::text FROM zasp_ordered_scheduler64.schedule_leases d WHERE schedule_id=$1`, item["schedule_id"]).Scan(&expiredEvidence); err != nil {
			t.Fatal(err)
		}
		cq = orderedCleanupRequest(o, w, e, r, steps[0], "reconcile", 7, int(claim["effect_version"].(float64)), int(claim["version"].(float64)))
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = next["action_worker_id"], next["action_lease_token"], 30
		reconciled, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil || reconciled["state"] != "retryable" || reconciled["cleanup_id"] != claim["cleanup_id"] {
			t.Fatal("reviewed cleanup reconciliation", reconciled, err)
		}
		cq["operation"], cq["run_version"], cq["effect_version"], cq["version"] = "claim", reconciled["run_version"], reconciled["effect_version"], reconciled["version"]
		recovered, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil || recovered["attempt"] != float64(2) || recovered["cleanup_id"] != claim["cleanup_id"] {
			t.Fatal("reviewed cleanup reclaim", recovered, err)
		}
		var retained bool
		if err = owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1)=1 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1)`, r).Scan(&retained); err != nil || !retained {
			t.Fatal("duplicate cleanup or fabricated receipt", retained, err)
		}
		cq = orderedCleanupStoreRequest(t, o, w, e, r, steps[0], recovered, key)
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = next["action_worker_id"], next["action_lease_token"], 30
		stored, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil {
			t.Fatal(err)
		}
		scheduler64DeliverCleanup(t, ctx, owner, key, stored, next)
		cq = orderedCleanupRequest(o, w, e, r, steps[0], "complete", int(stored["run_version"].(float64)), int(stored["effect_version"].(float64)), int(stored["version"].(float64)))
		cq["worker_id"], cq["lease_token"], cq["lease_seconds"] = next["action_worker_id"], next["action_lease_token"], 30
		completed, err := orderedCleanupCall(ctx, action, cq, keys)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := scheduler64Call(ctx, worker, scheduler64Mutation(next, fresh, "finish", int(completed["run_version"].(float64)), 1)); err != nil || got["outcome"] != "finished" {
			t.Fatal("recovered clean finish", got, err)
		}
		var after string
		var reconciledCount int
		if err = owner.QueryRow(ctx, `SELECT (to_jsonb(d)-'state')::text FROM zasp_ordered_scheduler64.schedule_leases d WHERE schedule_id=$1 AND state='reconciled'`, item["schedule_id"]).Scan(&after); err != nil || after != expiredEvidence {
			t.Fatal("expired evidence not state-only reconciled", err)
		}
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_ordered_scheduler64.schedule_leases WHERE run_id=$1 AND state='reconciled'`, r).Scan(&reconciledCount); err != nil || reconciledCount != 2 {
			t.Fatal("recovery history erased", reconciledCount, err)
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE zasp_ordered_scheduler64.schedule_leases SET action_token_digest=decode(repeat('ab',32),'hex') WHERE schedule_id=$1`, item["schedule_id"]); err != nil {
			t.Fatal(err)
		}
		_, demotionErr := tx.Exec(ctx, migrations.ProductionSecurityAgentScheduler().DownSQL())
		tx.Rollback(ctx)
		if refusal, ok := demotionErr.(*pgconn.PgError); !ok || refusal.Code != "55000" || refusal.Message != "scheduler ownership unresolved" {
			t.Fatal("tampered history lacked exact demotion refusal", demotionErr)
		}
		var beforeCatalog, afterCatalog string
		const predecessor = `SELECT jsonb_build_array(zasp_sa_multistep_registered_live_fingerprint(),zasp_ordered_public62.fingerprint(),zasp_ordered_worker63.fingerprint(),(SELECT jsonb_agg(to_jsonb(x) ORDER BY version) FROM zasp_schema_versions x))::text`
		if err = owner.QueryRow(ctx, predecessor).Scan(&beforeCatalog); err != nil {
			t.Fatal(err)
		}
		runner := precisionMigrationRunner(t, owner)
		if err = runner.DownProductionSecurityAgentScheduler(ctx); err != nil {
			t.Fatal("reconciled history did not permit demotion", err)
		}
		if err = owner.QueryRow(ctx, predecessor).Scan(&afterCatalog); err != nil || beforeCatalog != afterCatalog {
			t.Fatal("demotion predecessor drift", err)
		}
		if err = runner.UpProductionSecurityAgentScheduler(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// This test-only driver makes each reviewed deployment call with the fresh
// scheduler-bound identity, reconnecting at every operation.
func scheduler64DeliverCleanup(t *testing.T, ctx context.Context, owner *pgx.Conn, key ed25519.PrivateKey, stored, identity map[string]any) {
	t.Helper()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	q := orderedApplicationDeploymentRequest(stored["organization_id"].(string), stored["workspace_id"].(string), stored["environment_id"].(string), stored["run_id"].(string), stored["step_id"].(string), stored)
	q["action_worker_id"], q["action_lease_token"], q["worker_id"], q["lease_token"], q["lease_seconds"] = identity["action_worker_id"], identity["action_lease_token"], identity["deployment_worker_id"], identity["deployment_lease_token"], 30
	call := func() map[string]any {
		config := owner.Config().Copy()
		config.User = "ordered_application_deployment"
		c, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		got, err := orderedCleanupDeploymentCall(ctx, c, q, keys)
		if err != nil {
			t.Fatal("reviewed fresh cleanup deployment", q["operation"], err)
		}
		return got
	}
	got := call()
	raw, _ := json.Marshal(got["result"])
	var claim orderedDeploymentClaim
	if json.Unmarshal(raw, &claim) != nil {
		t.Fatal("deployment claim")
	}
	var composition orderedDeploymentComposition
	if json.Unmarshal(claim.Composition, &composition) != nil {
		t.Fatal("deployment composition")
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires, _ := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: composition.Policies}, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := orderedEnvelopeDigest(envelope)
	q["operation"], q["sequence"], q["input_digest"], q["composition"], q["envelope"], q["digest"] = "store", claim.Sequence, claim.InputDigest, claim.Composition, envelope, digest
	call()
	q["operation"], q["envelope"], q["digest"] = "read", map[string]any{}, ""
	call()
	q["operation"], q["digest"] = "finish", digest
	call()
}
