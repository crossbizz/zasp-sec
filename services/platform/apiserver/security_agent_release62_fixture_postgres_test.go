package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Only configuration and a disabled draft are seeded. Public history, trigger
// audit, planning, admission, and every execution result use real boundaries.
func public62PlannedRun(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) (string, []string) {
	t.Helper()
	if err := precisionMigrationRunner(t, owner).UpProductionSecurityAgentPublic(ctx); err != nil {
		t.Fatal(err)
	}
	public62Seed(t, ctx, owner, o, w, e, testID, actor)
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
	pricing := orderedPricingAdminRequest(o, w, e, actor)
	p := pricing["policy"].(map[string]any)
	p["request_token_limit"], p["request_policy_version"] = 512, "security-agent-planner-v1"
	h := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
	p["credential_digest"] = "sha256:" + hex.EncodeToString(h[:])
	created, err := orderedPricingCall(ctx, admin, "pricing_admin", pricing)
	if err != nil {
		t.Fatal(err)
	}
	binding, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "account_profile": p["account_profile"], "credential_reference": p["credential_reference"], "policy_id": created["policy_id"], "policy_version": created["version"], "policy_digest": created["policy_digest"], "account_id": created["account_id"], "account_version": created["account_version"]})
	q := public62Request(o, w, e, actor, "activate")
	q["definition_id"], q["definition_version"] = public62Definition, 1
	if _, err = public62Call(ctx, api, q); err != nil {
		t.Fatal(err)
	}
	q = public62Request(o, w, e, actor, "trigger")
	q["definition_id"], q["definition_version"], q["trigger_id"], q["trigger_version"], q["idempotency_key"] = public62Definition, 2, public62Finding, 1, "public62-execution-0001"
	created, err = public62Call(ctx, api, q)
	if err != nil {
		t.Fatal(err)
	}
	r := created["run_id"].(string)
	release61PreflightInvokePlan(t, ctx, owner, multistepBudgetWorkerBinary(t, ctx), string(binding), r, testID)
	var steps []string
	if err = owner.QueryRow(ctx, `SELECT array_agg(step_id ORDER BY step_index) FROM zasp_security_agent_steps WHERE run_id=$1`, r).Scan(&steps); err != nil || len(steps) != 2 {
		t.Fatal("real public planning handoff", steps, err)
	}
	return r, steps
}

func public62TerminalFixture(t *testing.T, callback func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, []string), many bool) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		if many {
			seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, "pid_8f000008-0000-4000-8000-000000000008")
		}
		r, steps := public62PlannedRun(t, ctx, owner, api, o, w, e, testID, actor)
		if _, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, steps[0], "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
		claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), policy.GatewayPolicyKeys{})
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		var stored map[string]any
		targets := claim["targets"].([]any)
		for i, target := range targets {
			selected := cloneOrderedApplicationRequest(t, claim)
			selected["targets"] = []any{target}
			q := orderedApplicationStoreRequest(t, o, w, e, r, steps[0], selected, key)
			q["effect_version"] = i + 1
			stored, err = orderedApplicationCall(ctx, action, q, keys)
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
		request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
		request["lease_token"] = strings.Repeat("a", 32)
		claim, err = orderedProgressionCall(ctx, worker, "test_action", request)
		if err != nil {
			t.Fatal(err)
		}
		store, input := orderedTestInputArtifact(t, ctx, owner, o, w, e, r, steps[1], claim["test_run_id"].(string), testID)
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
		repo := &securityAgentMultistepAdmissionRepository{database: db}
		request = orderedTestActionRequest(o, w, e, r, steps[1], "dispatch", 9, 1)
		request["payload"] = map[string]any{"input_artifact": input}
		raw, _ := json.Marshal(request)
		if _, err = repo.testDispatch(ctx, raw, store); err != nil {
			t.Fatal(err)
		}
		runOrderedJournalHTTPS(t, ctx, owner, o, w, e, claim["test_run_id"].(string), false)
		output := orderedTestOutputArtifact(t, ctx, owner, store, o, w, e, r, steps[1], claim["test_run_id"].(string), input)
		request = orderedTestActionRequest(o, w, e, r, steps[1], "settle", 9, 1)
		request["payload"] = map[string]any{"input_artifact": input, "output_artifact": output}
		raw, _ = json.Marshal(request)
		if _, err = repo.testSettle(ctx, raw, store); err != nil {
			t.Fatal(err)
		}
		callback(ctx, owner, worker, api, action, o, w, e, r, steps)
	})
}
