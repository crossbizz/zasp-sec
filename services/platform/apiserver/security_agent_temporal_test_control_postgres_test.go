package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func assertTemporalTestStartAndUnknownCapacity(t *testing.T, ctx context.Context, owner, api, executor *pgx.Conn, repository *PostgresRepository, identity RequestIdentity, o, w, e, manual, testID string) {
	t.Helper()
	var pending []byte
	// A retained admission owns the organization lock before parent/delivery
	// rows. The consumer must skip that organization, never invert this order.
	held, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback(ctx)
	if _, err := held.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Exec(ctx, `SET statement_timeout='5s'`); err != nil {
		t.Fatal(err)
	}
	err = executor.QueryRow(ctx, `SELECT zasp_temporal74.pending()`).Scan(&pending)
	if _, resetErr := executor.Exec(ctx, `SET statement_timeout=0`); resetErr != nil {
		t.Fatal(resetErr)
	}
	if err != nil || string(pending) != "[]" {
		t.Fatal("consumer waited behind held admission lock", string(pending), err)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending()`).Scan(&pending); err != nil || !strings.Contains(string(pending), manual) {
		t.Fatal("exact successor durable start delivery", string(pending), err)
	}
	if err := api.QueryRow(ctx, `SELECT zasp_temporal74.pending()`).Scan(&pending); err == nil {
		t.Fatal("API enumerated execution starts")
	}
	var automatic string
	if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_temporal74.run_owners WHERE source_kind='automatic73' AND definition_id=$1`, public62Definition).Scan(&automatic); err != nil {
		t.Fatal(err)
	}
	start := func(run string) map[string]any {
		var raw []byte
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	call := func(entry string, q any) (map[string]any, error) {
		raw, _ := json.Marshal(q)
		var result []byte
		err := executor.QueryRow(ctx, entry, raw).Scan(&result)
		var value map[string]any
		if err == nil {
			err = json.Unmarshal(result, &value)
		}
		return value, err
	}
	manualStart := start(manual)
	if state, err := call(`SELECT zasp_temporal74.inspect($1::jsonb)`, manualStart); err != nil || state["phase"] != "terminal" {
		t.Fatal("terminal workflow requires verified parent receipt", state, err)
	}
	accepted, err := call(`SELECT zasp_temporal74.accept_start($1::jsonb)`, manualStart)
	if err != nil || accepted["workflow_id"] != "security-agent-test/v1/"+o+"/"+w+"/"+e+"/"+manual {
		t.Fatal("durable existing workflow acceptance", accepted, err)
	}
	if again, err := call(`SELECT zasp_temporal74.accept_start($1::jsonb)`, manualStart); err != nil || !jsonEqualMaps(accepted, again) {
		t.Fatal("duplicate start acceptance changed identity", again, err)
	}
	manualStart["input_digest"] = strings.Repeat("f", 64)
	if _, err := call(`SELECT zasp_temporal74.accept_start($1::jsonb)`, manualStart); err == nil {
		t.Fatal("conflicting retained start accepted")
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.pending()`).Scan(&pending); err != nil || strings.Contains(string(pending), manual) || !strings.Contains(string(pending), automatic) {
		t.Fatal("accepted start requeued or automatic start lost", string(pending), err)
	}
	autoStart := start(automatic)
	if state, err := call(`SELECT zasp_temporal74.inspect($1::jsonb)`, autoStart); err != nil || state["phase"] != "planning" {
		t.Fatal("automatic phase", state, err)
	}
	plan := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": automatic, "definition_version": 2, "operation": "load"}
	if _, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil {
		t.Fatal(err)
	}
	var selection json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT lookup_request-ARRAY['body','body_digest'] FROM zasp_temporal74.planning_jobs WHERE run_id=$1`, manual).Scan(&selection); err != nil {
		t.Fatal(err)
	}
	plan["operation"], plan["payload"] = "prepare", map[string]any{"pricing": selection, "input_version": "test74-automatic-prepared-v1"}
	prepared, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan)
	if err != nil {
		t.Fatal("automatic prepared request", err)
	}
	plan["operation"], plan["payload"] = "reconcile", map[string]any{}
	if stopped, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil || stopped["state"] != "needs_human" {
		t.Fatal("never-dispatched planner release", stopped, err)
	}
	var released bool
	if err := owner.QueryRow(ctx, `SELECT released_at IS NOT NULL AND settled_at IS NULL FROM zasp_temporal74.provider_reservations WHERE run_id=$1`, automatic).Scan(&released); err != nil || !released {
		t.Fatal("unsent reservation release proof", released, err)
	}
	input := SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 2, IdempotencyKey: "test74-released-capacity-manual", RunID: "pid_f0740000-0000-4000-8000-000000000081", AuditID: "pid_f0740000-0000-4000-8000-000000000082", CorrelationID: "pid_f0740000-0000-4000-8000-000000000082", ReceiptID: "pid_f0740000-0000-4000-8000-000000000083", TriggerKind: "manual"}
	if admitted, err := repository.runSecurityAgentManual(ctx, identity, input); err != nil || admitted.ID != input.RunID {
		t.Fatal("actual unsent release did not free admission capacity", admitted, err)
	}
	var transferred []byte
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, input.RunID).Scan(&transferred); err != nil || string(transferred) == "null" {
		t.Fatal("successor after unsent release", string(transferred), err)
	}
	automatic = input.RunID
	autoStart = start(automatic)
	plan["run_id"], plan["operation"] = automatic, "load"
	delete(plan, "payload")
	if _, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil {
		t.Fatal(err)
	}
	plan["operation"], plan["payload"] = "prepare", map[string]any{"pricing": selection, "input_version": "test74-unknown-prepared-v1"}
	prepared, err = call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan)
	if err != nil {
		t.Fatal(err)
	}
	plan["operation"], plan["payload"] = "start", map[string]any{}
	if sent, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil || sent["send_permit"] != true {
		t.Fatal("automatic planner one-send", sent, err)
	}
	plan["operation"] = "reconcile"
	if stopped, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil || stopped["state"] != "needs_human" {
		t.Fatal("unknown automatic planner retains evidence", stopped, err)
	}
	if state, err := call(`SELECT zasp_temporal74.inspect($1::jsonb)`, autoStart); err != nil || state["phase"] != "pending" {
		t.Fatal("unknown planning was treated as completed cleanup", state, err)
	}
	input = SecurityAgentRunRequest{DefinitionID: public62Definition, ExpectedVersion: 2, IdempotencyKey: "test74-unknown-capacity-manual", RunID: "pid_f0740000-0000-4000-8000-000000000091", AuditID: "pid_f0740000-0000-4000-8000-000000000092", CorrelationID: "pid_f0740000-0000-4000-8000-000000000092", ReceiptID: "pid_f0740000-0000-4000-8000-000000000093", TriggerKind: "manual"}
	if _, err := repository.runSecurityAgentManual(ctx, identity, input); err == nil {
		t.Fatal("retained admission ignored terminal74 unknown planner reservation")
	}
	var clean bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_temporal65.commands WHERE run_id=$1) AND zasp_temporal73.current_ready()`, input.RunID).Scan(&clean); err != nil || !clean {
		t.Fatal("capacity denial left admission writes or broke73", clean, err)
	}
	// Late usage closes only the original send. It never admits its stale plan.
	candidate, _ := json.Marshal(map[string]any{"version": 1, "summary": "Pinned test", "steps": []any{map[string]any{"index": 0, "action": "run_test", "target_id": testID}}})
	response, _ := json.Marshal(map[string]any{"id": "test74-late-automatic", "model": "openai/gpt-5-mini", "choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(candidate)}}}, "usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30, "cost": 0.00003}})
	responseDigest := sha256.Sum256(response)
	plan["operation"], plan["payload"] = "late_usage", map[string]any{"raw": string(response), "request_digest": prepared["request_digest"], "credential_digest": prepared["lookup_request"].(map[string]any)["credential_digest"], "reservation_id": prepared["reservation_id"], "response_id": "test74-late-automatic", "response_digest": "sha256:" + hex.EncodeToString(responseDigest[:])}
	if _, err := call(`SELECT zasp_temporal74.plan($1::jsonb)`, plan); err != nil {
		t.Fatal("actual late usage reconciliation", err)
	}
	if state, err := call(`SELECT zasp_temporal74.inspect($1::jsonb)`, autoStart); err != nil || state["phase"] != "terminal" {
		t.Fatal("verified late usage did not release pending cleanup", state, err)
	}
	if admitted, err := repository.runSecurityAgentManual(ctx, identity, input); err != nil || admitted.ID != input.RunID {
		t.Fatal("actual settled usage did not release retained admission capacity", admitted, err)
	}
	if err := executor.QueryRow(ctx, `SELECT zasp_temporal74.takeover($1,$2,$3,$4)`, o, w, e, input.RunID).Scan(&transferred); err != nil || string(transferred) == "null" {
		t.Fatal("actual transport successor", err)
	}
	assertTemporalTestTransport(t, ctx, owner, input.RunID, testID, 2, selection)
}

func assertTemporalTestTransport(t *testing.T, ctx context.Context, owner *pgx.Conn, run, testID string, version int64, selection json.RawMessage) {
	t.Helper()
	var pricing map[string]any
	if err := json.Unmarshal(selection, &pricing); err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{}
	for _, k := range []string{"organization_id", "workspace_id", "environment_id", "account_profile", "credential_reference", "policy_id", "policy_version", "policy_digest", "account_id", "account_version"} {
		binding[k] = pricing[k]
	}
	encoded, _ := json.Marshal(binding)
	command := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestTemporalSingleTestPlannerPostgres$", "-count=1", "-v")
	command.Dir = ".."
	command.WaitDelay = 5 * time.Second
	command.Env = append(os.Environ(), "ZASP_TEST74_OWNER_DSN="+owner.Config().ConnString(), "ZASP_TEST74_BINDING="+string(encoded), "ZASP_TEST74_PARENT="+run, "ZASP_TEST74_TEST="+testID, "ZASP_TEST74_VERSION="+strconv.FormatInt(version, 10))
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil || !strings.Contains(string(output), "--- PASS: TestTemporalSingleTestPlannerPostgres") || strings.Contains(string(output), "--- SKIP:") {
		t.Fatal("actual74 planner transport", err)
	}
}
