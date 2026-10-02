package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

func workerPlanningStartFixture() orchestration.StartRequest {
	return orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "pid_99200001-0000-4000-8000-000000000001", WorkspaceID: "pid_99200002-0000-4000-8000-000000000002", EnvironmentID: "pid_99200003-0000-4000-8000-000000000003", RunID: "pid_99200004-0000-4000-8000-000000000004"}, DefinitionVersion: 7, InputDigest: strings.Repeat("a", 64)}
}

// A permissive job decoder or inconsistent state flags must not authorize the
// accounting branch. These inputs contain no provider body or context.
func TestWorkerPlanningRecoveryMetadata(t *testing.T) {
	d := &workerFindingPlanningDatabase{start: workerPlanningStartFixture()}
	base := map[string]any{"run_id": d.start.Ref.RunID, "state": "needs_human", "reservation_id": "pid_a8fffa19-5a3a-4855-8a9f-939796704f50", "request_digest": "sha256:" + strings.Repeat("a", 64), "credential_digest": "sha256:" + strings.Repeat("b", 64), "usage_known": true, "has_response": true}
	makeRaw := func(changes map[string]any) json.RawMessage {
		q := map[string]any{}
		for k, v := range base {
			q[k] = v
		}
		for k, v := range changes {
			q[k] = v
		}
		raw, _ := json.Marshal(q)
		return raw
	}
	for _, state := range []string{"prepared", "started", "completed", "settled", "artifacts", "needs_human"} {
		changes := map[string]any{"state": state}
		if state == "prepared" || state == "started" {
			changes["usage_known"] = false
			changes["has_response"] = false
		}
		if _, err := d.recoveryMetadata(makeRaw(changes)); err != nil {
			t.Fatal("valid native metadata", state, err)
		}
	}
	for _, state := range []string{"loaded", "needs_human"} {
		if _, err := d.recoveryMetadata(makeRaw(map[string]any{"state": state, "request_digest": nil, "credential_digest": nil, "usage_known": false, "has_response": false})); err != nil {
			t.Fatal("captured unsent metadata", state, err)
		}
	}
	cases := map[string]json.RawMessage{
		"malformed": json.RawMessage(`{`), "array": json.RawMessage(`[]`), "null": json.RawMessage(`null`),
		"unknown field":              makeRaw(map[string]any{"context_value": map[string]any{}}),
		"unknown state":              makeRaw(map[string]any{"state": "admitted"}),
		"wrong run":                  makeRaw(map[string]any{"run_id": d.start.Ref.EnvironmentID}),
		"wrong reservation":          makeRaw(map[string]any{"reservation_id": d.start.Ref.RunID}),
		"request digest":             makeRaw(map[string]any{"request_digest": "arbitrary"}),
		"credential digest":          makeRaw(map[string]any{"credential_digest": nil}),
		"null flag":                  makeRaw(map[string]any{"usage_known": nil}),
		"null state":                 makeRaw(map[string]any{"state": nil}),
		"typed flag":                 makeRaw(map[string]any{"has_response": "true"}),
		"known without response":     makeRaw(map[string]any{"has_response": false}),
		"loaded request":             makeRaw(map[string]any{"state": "loaded", "usage_known": false, "has_response": false}),
		"prepared response":          makeRaw(map[string]any{"state": "prepared", "usage_known": false}),
		"started response":           makeRaw(map[string]any{"state": "started", "usage_known": false}),
		"completed missing response": makeRaw(map[string]any{"state": "completed", "usage_known": false, "has_response": false}),
		"empty instead of null":      makeRaw(map[string]any{"request_digest": "", "credential_digest": "", "usage_known": false, "has_response": false}),
	}
	valid := makeRaw(nil)
	cases["duplicate field"] = append([]byte(`{"state":"needs_human",`), valid[1:]...)
	var missing map[string]json.RawMessage
	_ = json.Unmarshal(valid, &missing)
	delete(missing, "usage_known")
	cases["missing flag"], _ = json.Marshal(missing)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := d.recoveryMetadata(raw); !errors.Is(err, authorization.ErrConflict) {
				t.Fatal("unsafe metadata accepted", err)
			}
		})
	}
}

func TestWorkerPlanningRefusesUnclassifiedDatabaseCalls(t *testing.T) {
	base := singleDeliveryDatabaseFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		t.Fatal("unclassified call reached underlying database")
		return nil, nil
	})
	d := &workerFindingPlanningDatabase{base: base, forward: &authorization.WorkerExecutor{}, start: workerPlanningStartFixture()}
	q := temporalStartFields(d.start)
	delete(q, "input_digest")
	q["operation"] = "load"
	raw, _ := json.Marshal(q)
	for _, statement := range []string{`SELECT zasp_temporal68.plan($1::jsonb)`, `SELECT zasp_temporal74.plan($1::jsonb)`, `SELECT zasp_temporal78.context($1::jsonb)`, `SELECT arbitrary($1::jsonb)`} {
		if _, err := d.QueryJSON(context.Background(), statement, raw); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("unclassified SQL accepted", err)
		}
	}
	for _, phase := range []string{"reconcile", "late_usage", "recovery", "unknown"} {
		q["operation"] = phase
		raw, _ := json.Marshal(q)
		if _, err := d.QueryJSON(context.Background(), `SELECT zasp_temporal78.plan($1::jsonb)`, raw); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("compensation or unknown phase entered forward adapter", phase, err)
		}
	}
	if err := d.Exec(context.Background(), `SELECT zasp_temporal78.plan($1::jsonb)`, raw); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("Exec bypass accepted", err)
	}
	if _, err := d.SchemaVersion(context.Background()); !errors.Is(err, authorization.ErrInvalid) {
		t.Fatal("generic repository admitted", err)
	}
}

func TestWorkerPlanningFamilyIsolation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		family         workerPlanningFamily
		ready, foreign string
	}{
		{"finding", workerPlanningFinding, `SELECT to_jsonb(zasp_temporal78.client_ready($1,$2))`, `SELECT zasp_temporal74.plan($1::jsonb)`},
		{"test74", workerPlanningTest74, `SELECT to_jsonb(zasp_temporal74.client_ready($1,$2))`, `SELECT zasp_temporal78.plan($1::jsonb)`},
		{"ordered68", workerPlanningOrdered68, `SELECT to_jsonb(zasp_temporal68.ready($1,$2))`, `SELECT zasp_temporal74.plan($1::jsonb)`},
		{"unsupported", workerPlanningFamily(255), "", `SELECT zasp_temporal74.plan($1::jsonb)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := singleDeliveryDatabaseFunc(func(_ context.Context, statement string, args ...any) (json.RawMessage, error) {
				if tc.ready == "" || statement != tc.ready || len(args) != 2 || args[0] != "compiled-checksum" || args[1] != "compiled-fingerprint" {
					t.Fatal("unclassified database access")
				}
				return json.RawMessage(`true`), nil
			})
			d := &workerFindingPlanningDatabase{base: base, forward: &authorization.WorkerExecutor{}, compensation: &authorization.WorkerExecutor{}, start: workerPlanningStartFixture(), family: tc.family}
			if tc.ready != "" {
				raw, err := d.QueryJSON(context.Background(), tc.ready, "compiled-checksum", "compiled-fingerprint")
				if err != nil || string(raw) != "true" {
					t.Fatal("own pinned readiness rejected", err)
				}
			}
			q := temporalStartFields(d.start)
			delete(q, "input_digest")
			q["operation"] = "load"
			raw, _ := json.Marshal(q)
			for _, statement := range []string{tc.foreign, `SELECT zasp_temporal68.plan($1::jsonb)`, `SELECT zasp_temporal74.context($1::jsonb)`} {
				if tc.family == workerPlanningOrdered68 && statement == `SELECT zasp_temporal68.plan($1::jsonb)` {
					statement = `SELECT zasp_temporal78.plan($1::jsonb)`
				}
				if _, err := d.QueryJSON(context.Background(), statement, raw); !errors.Is(err, authorization.ErrInvalid) {
					t.Fatal("foreign family accepted", err)
				}
			}
			if tc.ready == "" {
				if _, err := d.QueryJSON(context.Background(), `SELECT to_jsonb(zasp_temporal78.client_ready($1,$2))`, "compiled-checksum", "compiled-fingerprint"); !errors.Is(err, authorization.ErrInvalid) {
					t.Fatal("unknown family used default readiness", err)
				}
				if err := d.RecoverCapturedPlanning(context.Background(), raw, nil); !errors.Is(err, authorization.ErrInvalid) {
					t.Fatal("unknown family used default recovery", err)
				}
			}
		})
	}
}
