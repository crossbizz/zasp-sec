package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
)

func TestCapturedSnapshotFeedsOriginalAndRecoveredEvidence(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		store, driver, q := fixtureExistingTestEvidence(t)
		capturedEvidenceFixture(t, driver, &q, recovered)
		var old map[string]any
		_ = json.Unmarshal(fixtureExistingTestSnapshot(t, q), &old)
		s := old["snapshot"].(map[string]any)
		s["schema_version"] = "security-agent-test-captured-snapshot-v1"
		a := s["after"].(map[string]any)
		a["observations"] = q.Captured.Observations
		a["completed_receipts"] = []completedTestReceipt{}
		if recovered {
			a["completed_receipts"] = q.Captured.Receipts
		}
		wire := map[string]any{"snapshot_digest": strings.Repeat("d", 64), "snapshot": s}
		raw, _ := json.Marshal(wire)
		now := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
		got, digest, err := decodeCapturedTestSnapshot(raw, q.Scope, snapshotRun, snapshotStep, q.RunID, now)
		if err != nil || got.After == nil || digest != strings.Repeat("d", 64) {
			t.Fatal("captured snapshot rejected", err)
		}
		if _, err := readExistingTestEvidence(context.Background(), store, *got.After); err != nil {
			t.Fatal("captured snapshot cannot consume persisted artifact", err)
		}
		for _, field := range []string{"snapshot_digest", "schema_version", "parent", "run_id", "observations", "completed_receipts", "attempt", "input_artifact", "duplicate", "extra"} {
			var bad map[string]any
			_ = json.Unmarshal(raw, &bad)
			bs := bad["snapshot"].(map[string]any)
			ba := bs["after"].(map[string]any)
			switch field {
			case "snapshot_digest":
				bad[field] = nil
			case "schema_version":
				bs[field] = "foreign"
			case "parent":
				bs["run_id"] = q.RunID
			case "run_id":
				ba[field] = snapshotRun
			case "attempt":
				ba[field] = 0
			case "observations", "completed_receipts", "input_artifact":
				ba[field] = nil
			case "extra":
				ba["target_comparison"] = map[string]any{}
			}
			b, _ := json.Marshal(bad)
			if field == "duplicate" {
				b = append([]byte(`{"snapshot_digest":"`+strings.Repeat("d", 64)+`",`), b[1:]...)
			}
			if _, _, err := decodeCapturedTestSnapshot(b, q.Scope, snapshotRun, snapshotStep, q.RunID, now); err == nil {
				t.Fatal("unsafe captured snapshot accepted", field)
			}
		}
	}
}

func TestWorkerSingleDatabaseRefusesUnclassifiedCalls(t *testing.T) {
	d := &workerSingleTestDatabase{base: singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("unclassified underlying call")
		return nil, nil
	}), forward: &authorization.WorkerExecutor{}, compensation: &authorization.WorkerExecutor{}, start: workerPlanningStartFixture()}
	for _, statement := range []string{`SELECT zasp_temporal68.test_settle($1::jsonb)`, `SELECT zasp_temporal74.context($1::jsonb)`, `SELECT zasp_authorization80_worker.test74_settle_native($1::jsonb)`, `SELECT arbitrary($1::jsonb)`} {
		if _, err := d.QueryJSON(context.Background(), statement, json.RawMessage(`{}`)); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("unclassified SQL accepted", err)
		}
	}
	if err := d.Exec(context.Background(), "SELECT 1"); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("Exec accepted", err)
	}
	if _, err := d.SchemaVersion(context.Background()); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("generic repository accepted", err)
	}
}
