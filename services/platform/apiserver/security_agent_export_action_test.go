package apiserver

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityAgentExportActionArguments(t *testing.T) {
	const raw = `{"target_id":"pid_20000002-0000-4000-8000-000000000002","evidence_ids":[{"source_kind":"finding","source_id":"pid_20000004-0000-4000-8000-000000000004","source_version":7,"association_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`
	got, err := decodeSecurityAgentActionArguments("create_evidence_export", json.RawMessage(raw))
	if err != nil || got == nil {
		t.Fatalf("export selection rejected: %v", err)
	}
	encoded, _ := json.Marshal(got)
	var want, actual any
	_ = json.Unmarshal([]byte(raw), &want)
	_ = json.Unmarshal(encoded, &actual)
	if !reflect.DeepEqual(want, actual) {
		t.Fatalf("selection changed: %s", encoded)
	}
	for _, bad := range []string{
		`null`, `{}`, strings.Replace(raw, `"source_version":7`, `"source_version":0`, 1),
		strings.Replace(raw, `"source_version":7`, `"source_version":7,"key":"private"`, 1),
		strings.Replace(raw, `"source_version":7`, `"source_version":7,"source_version":8`, 1),
		strings.Replace(raw, `"target_id":`, `"target_id":"pid_20000003-0000-4000-8000-000000000003","target_id":`, 1),
	} {
		if value, err := decodeSecurityAgentActionArguments("create_evidence_export", json.RawMessage(bad)); err == nil || value != nil {
			t.Fatalf("unsafe selection accepted: %s", bad)
		}
	}
}

func TestSecurityAgentExportActionProjection(t *testing.T) {
	for _, state := range []string{"", "pending", "succeeded", "known_failure", "cleanup_pending"} {
		t.Run(state, func(t *testing.T) {
			_, _, pin, _ := agentDownloadFixture(t)
			raw, detail := actionProjectionFixture(t, "create_evidence_export", state, [2]int{}, [2]int{}, func(envelope, step map[string]any) {
				step["arguments"] = map[string]any{"target_id": envelope["run_id"], "evidence_ids": pin.Binding.Selection}
			})
			got, err := decodeSecurityAgentActionDetails(raw, detail)
			if err != nil || len(got) != 1 {
				t.Fatalf("export projection unavailable: %v", err)
			}
			detail.ActionDetails = got
			if !validSecurityAgentActionDetails(detail) || got[0].Rollback.Support != "not_supported" || got[0].TTLSeconds != nil {
				t.Fatal("export fabricated control authority")
			}
			want := map[string]string{"": "unavailable", "pending": "pending", "succeeded": "pending", "known_failure": "failed", "cleanup_pending": "inconclusive"}[state]
			if got[0].Verification.State != want {
				t.Fatalf("export verification = %s, want %s", got[0].Verification.State, want)
			}
			got[0].Arguments.TargetID = pin.Binding.StepID
			if validSecurityAgentActionDetails(detail) {
				t.Fatal("foreign parent target accepted")
			}
		})
	}
}

func TestSecurityAgentExportActionRejectsSecurityOutcomeStates(t *testing.T) {
	for _, state := range []string{"verified", "cleaned", "cleanup_failed", "leased", "unknown_outcome"} {
		t.Run(state, func(t *testing.T) {
			_, _, pin, _ := agentDownloadFixture(t)
			raw, detail := actionProjectionFixture(t, "create_evidence_export", state, [2]int{}, [2]int{}, func(envelope, step map[string]any) {
				step["arguments"] = map[string]any{"target_id": envelope["run_id"], "evidence_ids": pin.Binding.Selection}
			})
			if _, err := decodeSecurityAgentActionDetails(raw, detail); err == nil {
				t.Fatal("unsupported export effect state accepted")
			}
		})
	}
}
