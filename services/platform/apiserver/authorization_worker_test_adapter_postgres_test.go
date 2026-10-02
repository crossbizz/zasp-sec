package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The adapter's registered principal is not itself a current machine decision.
// Use a real executor-dispatched child and roll back any unproved journal start.
func assertWorkerTest74UnsignedAdapter(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, run string, linked map[string]any, machineFor func() *authorization.WorkerExecutor) {
	t.Helper()
	worker, adapter := orderedTestConnections(t, ctx, owner)
	defer worker.Close(context.Background())
	defer adapter.Close(context.Background())
	child := linked["test_run_id"].(string)
	category := linked["categories"].([]any)[0].(string)
	var prompt string
	if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_prompt($1)`, category).Scan(&prompt); err != nil {
		t.Fatal(err)
	}
	promptJSON, _ := json.Marshal(prompt)
	body := `{"schema_version":"red-team-target-v1","run_id":"` + child + `","target_id":"` + linked["target_id"].(string) + `","target_kind":"` + linked["target_kind"].(string) + `","category":"` + category + `","input":` + string(promptJSON) + `}`
	digest := sha256.Sum256([]byte(body))
	requests := make(map[string]json.RawMessage)
	for _, phase := range []string{"resolve", "start"} {
		payload := map[string]any{"category": category, "request_digest": hex.EncodeToString(digest[:])}
		if phase == "resolve" {
			payload = map[string]any{"category": category, "target_id": linked["target_id"], "target_kind": linked["target_kind"]}
		}
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": linked["effect_key"], "operation": phase, "payload": payload, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()})
		requests[phase] = q
		tx, err := adapter.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_temporal74.invocation($1::jsonb)`, q).Scan(&result)
		var refusal *pgconn.PgError
		if err == nil {
			t.Error("unproved registered adapter reached actual74 invocation", phase)
		} else if !errors.As(err, &refusal) || refusal.Code != "42501" {
			t.Error("native74 adapter refusal class", phase, err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal74.invocations WHERE test_run_id=$1) AND (SELECT count(*)=1 FROM zasp_temporal74.effects WHERE run_id=$2 AND state='started') AND (SELECT count(*)=1 FROM zasp_temporal74.test_inputs WHERE run_id=$2) AND (SELECT count(*)=1 FROM zasp_red_team_runs WHERE run_id=$1)`, child, run).Scan(&exact); err != nil || !exact {
		t.Fatal("rolled-back adapter attempt changed native child/input/effect", err)
	}
	machine := machineFor()
	if err := machine.Ready(ctx); err != nil {
		t.Fatal("registered adapter worker key readiness", err)
	}
	if _, err := machine.Authorize(ctx, "test74.effect.reserve", requests["start"]); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("adapter accepted executor operation", err)
	}
	for _, statement := range []string{`SELECT zasp_authorization80_worker.revision($1::jsonb->>'organization_id')`, `SELECT zasp_authorization80_worker.test74_native_facts(false,$1::jsonb,true)`, `SELECT zasp_authorization80_worker.test74_completion_source('complete',$1::jsonb)`} {
		var value json.RawMessage
		err := adapter.QueryRow(ctx, statement, requests["resolve"]).Scan(&value)
		var native *pgconn.PgError
		if !errors.As(err, &native) || native.Code != "42501" {
			t.Fatal("adapter reached executor/captured/private reader", err)
		}
	}
	revision, err := machine.Revision(ctx, o)
	if err != nil {
		t.Fatal("adapter revision", err)
	}
	assertWorkerAdapterProofBindings(t, ctx, adapter, requests["resolve"], revision, false)
	for _, phase := range []string{"resolve", "start"} {
		decision, err := machine.Authorize(ctx, authorization.WorkerOperation("test74.adapter."+phase), requests[phase])
		if err != nil {
			t.Fatal("actual adapter authorize", phase, err)
		}
		raw, err := machine.Execute(ctx, decision)
		if err != nil {
			t.Fatal("actual signed adapter invocation", phase, err)
		}
		var result map[string]any
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal("adapter native receipt encoding")
		}
		if phase == "resolve" {
			if len(result) != 5 || result["target_id"] != linked["target_id"] || result["target_kind"] != linked["target_kind"] {
				t.Fatal("adapter bound resolution receipt")
			}
		} else if result["state"] != "started" || result["effect_key"] != linked["effect_key"] || result["request_digest"] != hex.EncodeToString(digest[:]) || result["attempt"] != float64(1) {
			t.Fatal("adapter exact native start receipt")
		}
	}
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(state='started' AND attempt=1 AND request_digest=decode($2,'hex')) FROM zasp_temporal74.invocations WHERE test_run_id=$1`, child, hex.EncodeToString(digest[:])).Scan(&exact); err != nil || !exact {
		t.Fatal("adapter native start cardinality", err)
	}
	t.Log("actual adapter current grantor/task proof resolved target and persisted one invocation; no provider send")
}

// Complete records only the held observation on the existing native start.
// Revocation must forbid a fresh send without discarding that captured debt.
func assertWorkerTest74CapturedComplete(t *testing.T, ctx context.Context, owner *pgx.Conn, compensation *authorization.WorkerExecutor, o, w, e, run string, linked map[string]any) {
	t.Helper()
	child := linked["test_run_id"].(string)
	category := linked["categories"].([]any)[0].(string)
	var requestDigest, step string
	if err := owner.QueryRow(ctx, `SELECT encode(j.request_digest,'hex'),x.step_id FROM zasp_temporal74.invocations j JOIN zasp_temporal74.run_owners x USING(organization_id,workspace_id,environment_id,test_run_id) WHERE j.test_run_id=$1 AND j.category=$2 AND j.state='started'`, child, category).Scan(&requestDigest, &step); err != nil {
		t.Fatal("captured native invocation", err)
	}
	payload := map[string]any{"category": category, "request_digest": requestDigest, "http_status": 200, "response_digest": strings.Repeat("d", 64), "protected": true, "credential_version_digest": strings.Repeat("c", 64)}
	request := func() json.RawMessage {
		q, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": linked["effect_key"], "operation": "complete", "payload": payload, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()})
		return q
	}
	config := owner.Config().Copy()
	config.User = "worker_test_compensation"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var inaccessible json.RawMessage
	err = connection.QueryRow(ctx, `SELECT zasp_authorization80_worker.adapter74_source('resolve',$1::jsonb)`, request()).Scan(&inaccessible)
	var native *pgconn.PgError
	if !errors.As(err, &native) || native.Code != "42501" {
		t.Fatal("compensation reached forward adapter metadata", err)
	}
	assertWorkerAdapterProofBindings(t, ctx, connection, request(), authorization.Revision{}, true)
	var original json.RawMessage
	for attempt := 0; attempt < 2; attempt++ {
		decision, err := compensation.Authorize(ctx, "test74.adapter.complete", request())
		if err != nil {
			t.Fatal("captured Complete after revocation authorize", err)
		}
		raw, err := compensation.Execute(ctx, decision)
		if err != nil {
			t.Fatal("captured Complete after revocation execute", err)
		}
		var result map[string]any
		if json.Unmarshal(raw, &result) != nil || len(result) != 16 || result["organization_id"] != o || result["workspace_id"] != w || result["environment_id"] != e || result["parent_run_id"] != run || result["test_run_id"] != child || result["step_id"] != step || result["effect_key"] != linked["effect_key"] || result["category"] != category || result["attempt"] != float64(1) || result["state"] != "completed" || result["request_digest"] != requestDigest || result["response_digest"] != payload["response_digest"] || result["credential_version_digest"] != payload["credential_version_digest"] || result["http_status"] != float64(200) || result["protected"] != true || result["completed_at"] == nil {
			t.Fatal("captured Complete receipt identity or disclosure")
		}
		if attempt == 0 {
			original = raw
		} else if string(raw) != string(original) {
			t.Fatal("captured Complete replay changed receipt")
		}
	}
	payload["response_digest"] = strings.Repeat("e", 64)
	decision, err := compensation.Authorize(ctx, "test74.adapter.complete", request())
	if err == nil {
		_, err = compensation.Execute(ctx, decision)
	}
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatal("changed held observation accepted", err)
	}
	var exact bool
	if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(state='completed' AND attempt=1 AND response_digest=decode($2,'hex')) FROM zasp_temporal74.invocations WHERE test_run_id=$1`, child, strings.Repeat("d", 64)).Scan(&exact); err != nil || !exact {
		t.Fatal("captured completion changed cardinality or original result", err)
	}
	t.Log("captured native completion after revoke and exact retry; controlled held observation, no HTTPS send")
}
