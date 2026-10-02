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
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// The sixth native category must participate in status, not just the first
// completed observation. All journals below use the real signed entry points.
func assertWorkerMaximumRecoveryStatus(t *testing.T, ctx context.Context, owner *pgx.Conn, adapter, compensation *authorization.WorkerExecutor, o, w, e, run string, linked map[string]any) {
	t.Helper()
	categories := linked["categories"].([]any)
	if len(categories) != 6 {
		t.Fatal("maximum native category fixture did not capture six categories")
	}
	child := linked["test_run_id"].(string)
	var last json.RawMessage
	execute := func(client *authorization.WorkerExecutor, phase string, q json.RawMessage) {
		t.Helper()
		decision, err := client.Authorize(ctx, authorization.WorkerOperation("test74.adapter."+phase), q)
		if err != nil {
			t.Fatal("maximum category authorization", phase, err)
		}
		raw, err := client.Execute(ctx, decision)
		var receipt map[string]any
		if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt["state"] != map[string]string{"start": "started", "complete": "completed"}[phase] {
			t.Fatal("maximum category native receipt", phase, err)
		}
	}
	for index, value := range categories {
		category := value.(string)
		var prompt string
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_prompt($1)`, category).Scan(&prompt); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(prompt)
		wire := `{"schema_version":"red-team-target-v1","run_id":"` + child + `","target_id":"` + linked["target_id"].(string) + `","target_kind":"` + linked["target_kind"].(string) + `","category":"` + category + `","input":` + string(encoded) + `}`
		digest := sha256.Sum256([]byte(wire))
		payload := map[string]any{"category": category, "request_digest": hex.EncodeToString(digest[:])}
		q := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": child, "effect_key": linked["effect_key"], "operation": "start", "payload": payload, "checksum": migrations.ProductionTemporalTestExecutor().Checksum(), "fingerprint": migrations.TemporalTestExecutorFingerprint()}
		raw, _ := json.Marshal(q)
		execute(adapter, "start", raw)
		q["operation"] = "complete"
		payload["http_status"], payload["response_digest"], payload["protected"], payload["credential_version_digest"] = 200, strings.Repeat("d", 64), true, strings.Repeat("c", 64)
		last, _ = json.Marshal(q)
		if index < 5 {
			execute(compensation, "complete", last)
		}
	}
	if _, err := owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=(SELECT grantor_id FROM zasp_authorization80_worker.test_associations WHERE run_id=$2)`, o, run); err != nil {
		t.Fatal(err)
	}
	runWorkerTest74ProductChild(t, ctx, owner, run, "TestP7WorkerSingleTestMaximumPendingStatusNative")
	var reference json.RawMessage
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal74.run_owners WHERE run_id=$1`, run).Scan(&reference); err != nil {
		t.Fatal(err)
	}
	stale, err := compensation.Authorize(ctx, "test74.lifecycle.recovery_status", reference)
	if err != nil {
		t.Fatal("pending status before real completion", err)
	}
	execute(compensation, "complete", last)
	if _, err := compensation.Execute(ctx, stale); !errors.Is(err, authorization.ErrConflict) {
		t.Fatal("completion between status authorization and execution did not refuse", err)
	}
	runWorkerTest74ProductChild(t, ctx, owner, run, "TestP7WorkerSingleTestMaximumCompleteStatusNative")
	runWorkerTest74ProductChild(t, ctx, owner, run, "TestP7WorkerSingleTestMaximumRecoveredProductNative")
	t.Log("six native captured categories: pending then complete after revocation; stale status refused; no provider send")
}
