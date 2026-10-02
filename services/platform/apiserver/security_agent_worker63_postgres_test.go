package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

type worker63Runner interface {
	UpProductionSecurityAgentWorker(context.Context) error
	DownProductionSecurityAgentWorker(context.Context) error
}

// Removing the registered extension must prevent the worker from discovering
// an authentic public-triggered run. No successful execution rows are seeded.
func TestSecurityAgentWorker63DispatchPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		extension, ok := any(runner).(worker63Runner)
		if !ok {
			t.Fatal("worker63 registered extension absent")
		}
		probe, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = probe.Exec(ctx, migrations.ProductionSecurityAgentWorker().UpSQL()); err != nil {
			t.Fatal(err)
		}
		var fp string
		if err = probe.QueryRow(ctx, `SELECT zasp_ordered_worker63.fingerprint()`).Scan(&fp); err != nil {
			t.Fatal(err)
		}
		t.Log("worker63 fingerprint", fp)
		if err = probe.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err := extension.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		if err := extension.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("install replay", err)
		}
		if err := extension.DownProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("clean down", err)
		}
		if err := extension.DownProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("down replay", err)
		}
		if err := extension.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("reinstall", err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-public-trigger-0001"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := worker63Call(ctx, worker, map[string]any{"operation": "ready"})
		if err != nil || got["ready"] != true {
			t.Fatal("worker readiness", got, err)
		}
		if _, err = worker63Call(ctx, api, map[string]any{"operation": "ready"}); err == nil {
			t.Fatal("API received worker authority")
		}
		claim := map[string]any{"operation": "claim", "worker_id": "worker63-test", "lease_token": "worker63-lease-token-0001", "lease_seconds": 30, "limit": 1, "planner": map[string]any{"provider": "openrouter", "model": "openai/gpt-5-mini", "request_policy_version": "security-agent-planner-v1", "request_token_limit": 256, "credential_digest": "sha256:" + strings.Repeat("ab", 32)}}
		if empty, err := worker63Call(ctx, worker, claim); err != nil || empty["outcome"] != "empty" || empty["item"] != nil {
			t.Fatal("absent pricing mutated or failed", empty, err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		first, err := worker63Call(ctx, worker, claim)
		if err != nil || first["outcome"] != "claimed" {
			t.Fatal("fresh claim", first, err)
		}
		item := first["item"].(map[string]any)
		if item["run_id"] != created.RunID || item["organization_id"] != o || item["state"] != "planning" || item["run_version"] != float64(2) || item["dispatch_version"] != float64(1) {
			t.Fatal("wrong dispatch scope/state", item)
		}
		if replay, err := worker63Call(ctx, worker, claim); err != nil || !jsonEqualMaps(first, replay) {
			t.Fatal("claim replay", replay, err)
		}
		for _, fault := range []string{
			`UPDATE zasp_sa_multistep_prior.planning_jobs SET worker_id='foreign-worker' WHERE run_id=$1 AND $2<>''`,
			`UPDATE zasp_sa_multistep_prior.pricing_policies SET disabled=true WHERE organization_id=$2 AND $1<>''`,
			`DELETE FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_public_triggered' AND $2<>''`,
		} {
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, fault, pgx.QueryExecModeSimpleProtocol, created.RunID, o); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(claim)
			var result []byte
			callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&result)
			if err = tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if callErr == nil {
				t.Fatal("replay trusted drifted authority", fault)
			}
		}
		var state string
		if err = owner.QueryRow(ctx, `SELECT state FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, created.RunID).Scan(&state); err != nil || state != "claimed" {
			t.Fatal("planning claim absent", state, err)
		}
		if err = extension.DownProductionSecurityAgentWorker(ctx); err == nil {
			t.Fatal("active dispatch down accepted")
		}
		mutation := map[string]any{"operation": "heartbeat", "worker_id": claim["worker_id"], "lease_token": claim["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": 2, "dispatch_version": 1, "lease_seconds": 60}
		var leaseBefore, leaseAfter string
		if err = owner.QueryRow(ctx, `SELECT lease_expires_at::text FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, created.RunID).Scan(&leaseBefore); err != nil {
			t.Fatal(err)
		}
		beat, err := worker63Call(ctx, worker, mutation)
		if err != nil || beat["outcome"] != "extended" {
			t.Fatal("heartbeat", beat, err)
		}
		if err = owner.QueryRow(ctx, `SELECT lease_expires_at::text FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, created.RunID).Scan(&leaseAfter); err != nil || leaseBefore != leaseAfter {
			t.Fatal("heartbeat changed predecessor lease", err)
		}
		if _, err = worker63Call(ctx, worker, mutation); err == nil {
			t.Fatal("stale heartbeat accepted")
		}
		mutation["dispatch_version"] = 2
		mutation["operation"] = "finish"
		delete(mutation, "lease_seconds")
		if _, err = worker63Call(ctx, worker, mutation); err == nil {
			t.Fatal("planning is not a handoff")
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='waiting_approval',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1`, created.RunID); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{worker.Config().User}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(mutation)
		var result []byte
		callErr := tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&result)
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if callErr == nil {
			t.Fatal("fabricated waiting approval accepted as handoff")
		}
		mutation["operation"] = "abandon"
		abandoned, err := worker63Call(ctx, worker, mutation)
		if err != nil || abandoned["outcome"] != "recovery_deferred" {
			t.Fatal("live abandon", abandoned, err)
		}
		if err = owner.QueryRow(ctx, `SELECT lease_expires_at::text FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, created.RunID).Scan(&leaseAfter); err != nil || leaseBefore != leaseAfter {
			t.Fatal("abandon changed predecessor lease", err)
		}
		if empty, err := worker63Call(ctx, worker, claim); err != nil || empty["outcome"] != "empty" {
			t.Fatal("abandon adopted live predecessor", empty, err)
		}
		if err = extension.DownProductionSecurityAgentWorker(ctx); err == nil {
			t.Fatal("unresolved abandoned dispatch down accepted")
		}
	})
}

func worker63Call(ctx context.Context, c *pgx.Conn, q map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(q)
	var response []byte
	// Production and this test helper both use the compiled extension pins.
	err := c.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response)
	var result map[string]any
	if err == nil {
		err = json.Unmarshal(response, &result)
	}
	return result, err
}

// The initial Runner interface probe kept the first RED a behavioral failure.
func worker63Checksum() string    { return migrations.ProductionSecurityAgentWorker().Checksum() }
func worker63Fingerprint() string { return migrations.SecurityAgentWorkerFingerprint() }

func worker63Pricing(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
		t.Fatal(err)
	}
	config := owner.Config().Copy()
	config.User = "security_agent_v33_discovery_api_login"
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	q := orderedPricingAdminRequest(o, w, e, actor)
	q["policy"].(map[string]any)["request_policy_version"] = "security-agent-planner-v1"
	if _, err = orderedPricingCall(ctx, admin, "pricing_admin", q); err != nil {
		t.Fatal(err)
	}
}
