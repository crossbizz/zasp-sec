package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func orderedCleanupResponseRefusals(t *testing.T, ctx context.Context, q, result map[string]any, keys policy.GatewayPolicyKeys) {
	t.Helper()
	request, _ := json.Marshal(q)
	for _, mode := range []string{"exact", "extra", "missing_version", "zero_version", "negative_version", "large_version", "run_increment", "effect_increment", "wrong_operation", "cleanup_id", "reservation_id", "control_id", "step_id", "state", "empty_targets", "duplicate_target", "zero_sequence", "bad_target_state", "receipt_digest", "duplicate_key", "oversize"} {
		t.Run(q["operation"].(string)+"_response_"+mode, func(t *testing.T) {
			v := cloneOrderedApplicationRequest(t, result)
			switch mode {
			case "extra":
				v["public_activation"] = true
			case "missing_version":
				delete(v, "version")
			case "zero_version":
				v["version"] = 0
			case "negative_version":
				v["version"] = -1
			case "large_version":
				v["version"] = 1000000
			case "run_increment":
				v["run_version"] = v["run_version"].(float64) + 1
			case "effect_increment":
				v["effect_version"] = v["effect_version"].(float64) + 1
			case "wrong_operation":
				v["operation"] = "heartbeat"
			case "cleanup_id", "reservation_id", "control_id", "step_id":
				v[mode] = v["run_id"]
			case "state":
				v["state"] = "unknown"
			case "empty_targets":
				v["targets"] = []any{}
			case "duplicate_target":
				v["targets"] = append(v["targets"].([]any), v["targets"].([]any)[0])
			case "zero_sequence":
				v["targets"].([]any)[0].(map[string]any)["sequence"] = 0
			case "bad_target_state":
				v["targets"].([]any)[0].(map[string]any)["state"] = "missing"
			case "receipt_digest":
				v["receipt_digest"] = "sha256:" + strings.Repeat("f", 64)
			}
			body, _ := json.Marshal(v)
			if mode == "duplicate_key" {
				body = append([]byte(`{"version":1,`), body[1:]...)
			}
			if mode == "oversize" {
				body = append(body, []byte(strings.Repeat(" ", 262145-len(body)))...)
			}
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`: body}}
			got, err := (&securityAgentMultistepAdmissionRepository{database: db}).cleanup(ctx, request, keys)
			if mode == "exact" {
				if err != nil || string(got) != string(body) {
					t.Fatal("exact cleanup SQL response refused", err)
				}
			} else if err == nil {
				t.Fatal("fabricated cleanup response accepted", mode)
			}
		})
	}
	if q["operation"] != "complete" {
		return
	}
	for _, mode := range []string{"effect", "control_version", "time_order", "attempt", "removed_digest", "empty_targets", "extra", "removed_id", "cleanup_source_id", "credential", "sequence", "generation", "acknowledgement"} {
		t.Run("receipt_"+mode, func(t *testing.T) {
			v := cloneOrderedApplicationRequest(t, result)
			receipt := v["receipt"].(map[string]any)
			ack := receipt["targets"].([]any)[0].(map[string]any)
			switch mode {
			case "effect":
				receipt["effect_id"] = q["run_id"]
			case "control_version":
				receipt["control_version"] = 3
			case "time_order":
				receipt["started_at"] = "2099-01-01T00:00:00.000000Z"
			case "attempt":
				receipt["attempts"] = 2
			case "removed_digest":
				receipt["removed_source_digest"] = "invalid"
			case "empty_targets":
				receipt["targets"] = []any{}
			case "extra":
				receipt["unverified"] = true
			case "removed_id":
				ack["removed_source_id"] = q["run_id"]
			case "cleanup_source_id":
				ack["cleanup_source_id"] = q["run_id"]
			case "credential":
				ack["credential_id"] = q["run_id"]
			case "sequence":
				ack["cleanup_sequence"] = 0
			case "generation":
				ack["desired_generation"] = 0
			case "acknowledgement":
				ack["acknowledgement_id"] = q["run_id"]
			}
			acks, _ := json.Marshal(receipt["targets"])
			receipt["cleanup_deployment_digest"] = strings.TrimPrefix(orderedCleanupDigest(acks), "sha256:")
			rawReceipt, _ := json.Marshal(receipt)
			v["receipt_digest"] = orderedCleanupDigest(rawReceipt)
			body, _ := json.Marshal(v)
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.cleanup($1,$2,$3::jsonb)`: body}}
			if _, err := (&securityAgentMultistepAdmissionRepository{database: db}).cleanup(ctx, request, keys); err == nil {
				t.Fatal("fabricated typed cleanup evidence accepted", mode)
			}
		})
	}
}
