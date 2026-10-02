package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentWorker63HandoffPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-handoff-trigger"})
		if err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		q := worker63ClaimRequest("worker63-handoff-token")
		result, err := worker63Call(ctx, worker, q)
		if err != nil || result["outcome"] != "claimed" {
			t.Fatal(result, err)
		}
		item := result["item"].(map[string]any)
		worker63Admit(t, ctx, worker, o, w, e, created.RunID, testID, q, item)
		mutation := map[string]any{"operation": "finish", "worker_id": q["worker_id"], "lease_token": q["lease_token"], "dispatch_id": item["dispatch_id"], "run_version": 3, "dispatch_version": 1}
		// A successful finish is rolled back here so the same genuine admitted run
		// can exercise the following handoff states without owner-seeded leases.
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(mutation)
		var response []byte
		if err = tx.QueryRow(ctx, `SELECT zasp_ordered_worker63.worker($1,$2,$3::jsonb)`, worker63Checksum(), worker63Fingerprint(), raw).Scan(&response); err != nil {
			t.Fatal("waiting approval handoff", err)
		}
		var got map[string]any
		_ = json.Unmarshal(response, &got)
		if got["outcome"] != "finished" {
			t.Fatal(got)
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var step string
		if err = owner.QueryRow(ctx, `SELECT step_id FROM zasp_security_agent_steps WHERE run_id=$1 AND step_index=0`, created.RunID).Scan(&step); err != nil {
			t.Fatal(err)
		}
		if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, created.RunID, step, "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
		mutation["run_version"] = 4
		if _, err = worker63Call(ctx, worker, mutation); err == nil {
			t.Fatal("authorized work without action lease is not handoff")
		}
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, created.RunID, step, "claim", 4, 0), policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal("separate action lease", err)
		}
		mutation["run_version"] = 5
		got, err = worker63Call(ctx, worker, mutation)
		if err != nil || got["outcome"] != "finished" {
			t.Fatal("action handoff", got, err)
		}
		var count int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_ordered_worker63.dispatch_leases`).Scan(&count); err != nil || count != 0 {
			t.Fatal("finish retained ownership", count, err)
		}
		if err = runner.DownProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal("handoff down", err)
		}
		var version int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_schema_versions`).Scan(&version); err != nil || version != 61 {
			t.Fatal("canonical count", version, err)
		}
	})
}

// Provider bytes are controlled local inputs to the reviewed worker boundary.
// This proves database transitions, not an external provider or artifact store.
func worker63Admit(t *testing.T, ctx context.Context, worker *pgx.Conn, o, w, e, r, testID string, q, item map[string]any) {
	t.Helper()
	selection := item["pricing"].(map[string]any)
	selection["organization_id"] = o
	selection["workspace_id"] = w
	selection["environment_id"] = e
	planning := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": q["worker_id"], "lease_token": q["lease_token"], "operation": "prepare", "payload": map[string]any{"pricing": selection, "input_version": "worker63-controlled-input-v1"}}
	if _, err := orderedPlanningCall(ctx, worker, planning); err != nil {
		t.Fatal(err)
	}
	planning["operation"] = "start"
	planning["payload"] = map[string]any{}
	if v, err := orderedPlanningCall(ctx, worker, planning); err != nil || v["send_permit"] != true {
		t.Fatal(v, err)
	}
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Contain and retest", "steps": []any{map[string]any{"index": 0, "action": "create_temporary_policy", "target_id": e}, map[string]any{"index": 1, "action": "run_test", "target_id": testID}}})
	provider, _ := json.Marshal(map[string]any{"model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 50, "completion_tokens": 50, "total_tokens": 100, "cost": 0.0000005}})
	planning["operation"] = "result"
	planning["payload"] = map[string]any{"raw": string(provider)}
	job, err := orderedPlanningCall(ctx, worker, planning)
	if err != nil {
		t.Fatal(err)
	}
	planning["operation"] = "settle"
	planning["payload"] = map[string]any{}
	if _, err = orderedPlanningCall(ctx, worker, planning); err != nil {
		t.Fatal(err)
	}
	planning["operation"] = "artifacts"
	planning["payload"] = map[string]any{"input_version": "worker63-controlled-input-v1", "output_version": "worker63-controlled-output-v1", "output_digest": job["output_digest"]}
	if _, err = orderedPlanningCall(ctx, worker, planning); err != nil {
		t.Fatal(err)
	}
	planning["operation"] = "admit"
	planning["payload"] = map[string]any{}
	if v, err := orderedPlanningCall(ctx, worker, planning); err != nil || v["outcome"] != "admitted" {
		t.Fatal(v, err)
	}
}

func TestSecurityAgentWorker63ExpiredHandoffPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		created, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-expired-handoff"})
		if err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		q := worker63ClaimRequest("worker63-expired-handoff-token")
		result, err := worker63Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		item := result["item"].(map[string]any)
		worker63Admit(t, ctx, worker, o, w, e, created.RunID, testID, q, item)
		expiry, err := time.Parse(time.RFC3339Nano, item["lease_expires_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(time.Until(expiry) + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		got, err := worker63Call(ctx, worker, worker63ClaimRequest("worker63-observe-expired-handoff"))
		if err != nil || got["outcome"] != "empty" {
			t.Fatal(got, err)
		}
		var count int
		if err = owner.QueryRow(ctx, `SELECT count(*) FROM zasp_ordered_worker63.dispatch_leases`).Scan(&count); err != nil || count != 0 {
			t.Fatal("expired genuine handoff stranded dispatch", count, err)
		}
		var state string
		if err = owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE run_id=$1`, created.RunID).Scan(&state); err != nil || state != "waiting_approval" {
			t.Fatal("handoff recovery changed predecessor", state, err)
		}
	})
}

func TestSecurityAgentWorker63ReplayExpiryAfterWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentPublic(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentWorker(ctx); err != nil {
			t.Fatal(err)
		}
		public62Seed(t, ctx, owner, o, w, e, testID, actor)
		repo, id := public62GoRepository(t, api, o, w, e, actor)
		if _, err := repo.Activate(ctx, id, public62Definition, 1); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Trigger(ctx, id, SecurityAgentPublicTrigger{DefinitionID: public62Definition, DefinitionVersion: 2, TriggerID: public62Finding, TriggerVersion: 1, IdempotencyKey: "worker63-replay-expiry"}); err != nil {
			t.Fatal(err)
		}
		worker63Pricing(t, ctx, owner, o, w, e, actor)
		q := worker63ClaimRequest("worker63-expiring-replay-token")
		got, err := worker63Call(ctx, worker, q)
		if err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse(time.RFC3339Nano, got["item"].(map[string]any)["lease_expires_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := worker63Call(ctx, worker, q); result <- err }()
		blocked := false
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if err = tx.QueryRow(ctx, `SELECT coalesce(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, worker.PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
		}
		if !blocked {
			t.Fatal("replay did not wait at organization authority")
		}
		timer := time.NewTimer(time.Until(expires) + 100*time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err = <-result; err == nil {
			t.Fatal("SQL returned an expired live replay after lock wait")
		}
	})
}
