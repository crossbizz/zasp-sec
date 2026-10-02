package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Every positive predecessor receipt is produced through the real private
// application and deployment repositories. Owner writes seed configuration only.
func TestSecurityAgentMultistepTestClaimPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedTestPredecessor(t, ctx, owner, worker, api, action, o, w, e, testID, actor, 900)
		request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
		got, err := orderedTestActionCall(ctx, worker, request)
		if err != nil {
			t.Fatal("approved successor has no private claim authority", err)
		}
		if got["effect_state"] != "leased" || got["run_version"] != float64(9) || got["effect_version"] != float64(1) || got["step_version"] != float64(4) || got["attempt"] != float64(1) {
			t.Fatal("successor claim postconditions", got)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
		var dormant bool
		if err = owner.QueryRow(ctx, `SELECT count(*)=0 FROM zasp_red_team_outbox WHERE payload->>'run_id'=$1`, got["test_run_id"]).Scan(&dormant); err != nil || !dormant {
			t.Fatal("private test claim published generic work", dormant, err)
		}
		before := orderedApplicationSnapshot(t, ctx, owner, r)
		restart, err := pgx.ConnectConfig(ctx, worker.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer restart.Close(ctx)
		replay, err := orderedTestActionCall(ctx, restart, request)
		if err != nil || replay["reservation_id"] != got["reservation_id"] || replay["test_run_id"] != got["test_run_id"] || orderedApplicationSnapshot(t, ctx, owner, r) != before {
			t.Fatal("successor restart duplicated authority", replay, err)
		}
	})
}

func orderedTestActionRequest(o, w, e, r, s, operation string, runVersion, effectVersion int) map[string]any {
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": operation, "worker_id": "ordered-test-worker", "lease_token": strings.Repeat("a", 32), "run_version": runVersion, "effect_version": effectVersion, "lease_seconds": 120, "payload": map[string]any{}}
}

func orderedTestActionCall(ctx context.Context, connection *pgx.Conn, request map[string]any) (map[string]any, error) {
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := (&securityAgentMultistepAdmissionRepository{database: database}).testAction(ctx, raw)
	var result map[string]any
	if err == nil {
		err = json.Unmarshal(response, &result)
	}
	return result, err
}

func TestSecurityAgentMultistepTestLeasePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		r, steps := seedOrderedTestPredecessor(t, ctx, owner, worker, api, action, o, w, e, testID, actor, 901)
		claim, err := orderedTestActionCall(ctx, worker, orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0))
		if err != nil {
			t.Fatal(err)
		}
		beat, err := orderedTestActionCall(ctx, worker, orderedTestActionRequest(o, w, e, r, steps[1], "heartbeat", 9, 1))
		if err != nil || beat["run_version"] != float64(9) || beat["effect_version"] != float64(2) {
			t.Fatal("current successor lease cannot heartbeat", beat, err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND step_id=$2`, r, steps[1]); err != nil {
			t.Fatal(err)
		}
		request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 9, 2)
		request["lease_token"] = strings.Repeat("b", 32)
		recovered, err := orderedTestActionCall(ctx, worker, request)
		if err != nil || recovered["run_version"] != float64(10) || recovered["effect_version"] != float64(3) || recovered["attempt"] != float64(2) || recovered["test_run_id"] != claim["test_run_id"] || recovered["reservation_id"] != claim["reservation_id"] {
			t.Fatal("successor recovery changed durable identity", recovered, err)
		}
		before := orderedApplicationSnapshot(t, ctx, owner, r)
		if _, err = orderedTestActionCall(ctx, worker, orderedTestActionRequest(o, w, e, r, steps[1], "heartbeat", 10, 3)); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
			t.Fatal("stale worker changed recovered lease", err)
		}
		assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
	})
}

func seedOrderedTestPredecessor(t *testing.T, ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, testID, actor string, index int, sourceLifetime ...time.Duration) (string, []string) {
	t.Helper()
	r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, index, true)
	claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	targets := claim["targets"].([]any)
	for i, target := range targets {
		selected := cloneOrderedApplicationRequest(t, claim)
		selected["targets"] = []any{target}
		request := orderedApplicationStoreRequest(t, o, w, e, r, steps[0], selected, key)
		if len(sourceLifetime) > 0 {
			orderedCleanupTestSourceLifetime(t, o, w, e, request, key, sourceLifetime[0])
		}
		request["effect_version"] = i + 1
		stored, err = orderedApplicationCall(ctx, action, request, keys)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range stored["targets"].([]any) {
		selected := cloneOrderedApplicationRequest(t, stored)
		selected["targets"] = []any{target}
		deployOrderedApplication(t, ctx, owner, key, selected)
	}
	if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, len(targets)+1), keys); err != nil {
		t.Fatal(err)
	}
	if _, err = orderedProgressionCall(ctx, worker, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "progress", "ordered-test-worker", 6)); err != nil {
		t.Fatal(err)
	}
	if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[1], "approve", orderedProgressionApprover, 7)); err != nil {
		t.Fatal(err)
	}
	return r, steps
}
