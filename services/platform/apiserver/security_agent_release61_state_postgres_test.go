//go:build darwin || linux

package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Reading a different run/scope or revealing a lease token must not become a
// way for an orchestration worker to acquire another worker's authority.
func TestSecurityAgentRelease61StatePostgres(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		r, _ := release61PreflightPlan(t, ctx, owner, binary, o, w, e, testID, actor)
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		reader, ok := any(&securityAgentMultistepAdmissionRepository{database: db}).(interface {
			orchestrationState(context.Context, json.RawMessage) (json.RawMessage, error)
		})
		if !ok {
			t.Fatal("authoritative private release61 state boundary absent")
		}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": "ordered-action-worker", "lease_token": "not-the-owned-lease", "deployment_worker_id": "ordered-delivery-worker", "deployment_lease_token": "not-the-deployment-lease"}
		read := func() map[string]any {
			t.Helper()
			raw, err := reader.orchestrationState(ctx, mustJSON(t, q))
			if err != nil {
				t.Fatal("read authoritative ordered state", err)
			}
			if strings.Contains(string(raw), `"lease_token"`) || strings.Contains(string(raw), `"lease_token_digest"`) || strings.Contains(string(raw), "ordered-application-lease") {
				t.Fatal("state read exposed lease secret")
			}
			var state map[string]any
			if err = json.Unmarshal(raw, &state); err != nil || state["run_id"] != r || state["organization_id"] != o || state["contract_version"] != float64(61) {
				t.Fatal("reader scope/version", err)
			}
			return state
		}
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		state := read()
		if state["run_state"] != "waiting_approval" || len(state["steps"].([]any)) != 2 || before != orderedCleanupSnapshot(t, ctx, owner, r) {
			t.Fatal("reader changed admission or lost approval pause", state)
		}
		for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id"} {
			bad := cloneOrderedApplicationRequest(t, q)
			bad[field] = orderedProgressionApprover
			if raw, err := reader.orchestrationState(ctx, mustJSON(t, bad)); err == nil || len(raw) != 0 {
				t.Fatal("foreign state disclosed", field, err)
			}
		}
		step := state["steps"].([]any)[0].(map[string]any)["step_id"].(string)
		approved, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, step, "approve", orderedProgressionApprover, int(state["run_version"].(float64))))
		if err != nil {
			t.Fatal(err)
		}
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, step, "claim", int(approved["run_version"].(float64)), 0), policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal(err)
		}
		if read()["steps"].([]any)[0].(map[string]any)["owned"] != false {
			t.Fatal("reader gave foreign live lease authority")
		}
		q["lease_token"] = "ordered-application-lease"
		if read()["steps"].([]any)[0].(map[string]any)["owned"] != true {
			t.Fatal("reader lost exact owned lease")
		}
	})
}

func TestSecurityAgentRelease61QueuedStatePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		r := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		repo := &securityAgentMultistepAdmissionRepository{database: db}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": "queued-planner", "lease_token": "queued-planning-lease", "deployment_worker_id": "queued-delivery", "deployment_lease_token": "queued-delivery-lease"}
		read := func() map[string]any {
			t.Helper()
			raw, err := repo.orchestrationState(ctx, mustJSON(t, q))
			if err != nil {
				diagnostic, sqlErr := db.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.orchestration_state($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), mustJSON(t, q))
				t.Log("state-only diagnostic", string(diagnostic), sqlErr)
				t.Fatal("queued/planning authoritative state unavailable", err)
			}
			if strings.Contains(string(raw), "queued-planning-lease") || strings.Contains(string(raw), "lease_token") {
				t.Fatal("planning secret disclosed")
			}
			var state map[string]any
			if json.Unmarshal(raw, &state) != nil {
				t.Fatal("state JSON")
			}
			return state
		}
		state := read()
		if state["run_state"] != "queued" || state["admitted"] != false || len(state["steps"].([]any)) != 0 || len(state["planning"].(map[string]any)) != 0 {
			t.Fatal("queued state invented planning authority", state)
		}
		claim := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "worker_id": q["worker_id"], "lease_token": q["lease_token"], "operation": "claim", "payload": map[string]any{}}
		if _, err := db.QueryJSON(ctx, `SELECT zasp_sa_multistep_prior.planning($1,$2,$3::jsonb)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), mustJSON(t, claim)); err != nil {
			t.Fatal("actual planning claim", err)
		}
		state = read()
		job := state["planning"].(map[string]any)
		if state["run_state"] != "planning" || job["state"] != "claimed" || job["owned"] != true {
			t.Fatal("planning claim not observed", state)
		}
		q["lease_token"] = "foreign-planning-lease"
		if read()["planning"].(map[string]any)["owned"] != false {
			t.Fatal("foreign planning lease recovered")
		}
	})
}
