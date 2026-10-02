package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSecurityAgentActionRecognizesOnlyBoundBudgetStop(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	target := TemporaryPolicyTarget{DeviceID: "pid_78000003-0000-4000-8000-000000000003", CredentialID: "pid_78000004-0000-4000-8000-000000000004", Sequence: 2, PolicyVersion: 2}
	claim := TemporaryPolicyEffectClaim{OrganizationID: "pid_70000001-0000-4000-8000-000000000001", WorkspaceID: "pid_70000002-0000-4000-8000-000000000002", EnvironmentID: "pid_70000003-0000-4000-8000-000000000003", RunID: "pid_78000001-0000-4000-8000-000000000001", StepID: "pid_78000002-0000-4000-8000-000000000002", Phase: "apply", InputDigest: "sha256:" + strings.Repeat("a", 64), TTLSeconds: 600, LeaseExpiresAt: now.Add(time.Minute), Targets: []TemporaryPolicyTarget{target}}
	envelope := TemporaryPolicyTargetEnvelope{Target: target, Phase: "apply", KeyID: "gateway-key-01", IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute), FailureMode: "closed", PayloadDigest: "sha256:" + strings.Repeat("b", 64), Policies: json.RawMessage(`[{"id":"temporary-block","name":"Temporary block","rules":[{"field":"http.method","operator":"present","value":""}],"action":"block"}]`), Signature: make([]byte, 64), EnvelopeDigest: "sha256:" + strings.Repeat("c", 64)}
	fields := []string{"organization_id", "workspace_id", "environment_id", "run_id", "step_id", "action_key", "input_digest", "phase", "device_id", "credential_id", "sequence", "policy_version", "state", "reason"}
	cases := append([]string{"valid", "extra outer", "extra inner", "null reason", "cleanup"}, fields...)
	for _, field := range fields {
		cases = append(cases, "wrong "+field)
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			stop := map[string]any{"organization_id": claim.OrganizationID, "workspace_id": claim.WorkspaceID, "environment_id": claim.EnvironmentID, "run_id": claim.RunID, "step_id": claim.StepID, "action_key": "create_temporary_policy", "input_digest": claim.InputDigest, "phase": "apply", "device_id": target.DeviceID, "credential_id": target.CredentialID, "sequence": 2, "policy_version": 2, "state": "needs_human", "reason": "budget_deadline_exceeded"}
			body := map[string]any{"budget_action_stop": stop}
			localClaim, localEnvelope := claim, envelope
			switch name {
			case "valid":
			case "extra outer":
				body["result"] = true
			case "extra inner":
				stop["result"] = true
			case "null reason":
				stop["reason"] = nil
			case "cleanup":
				localClaim.Phase = "cleanup"
				localEnvelope.Phase = "cleanup"
				localEnvelope.ExpiresAt = now.Add(5 * time.Minute)
				localEnvelope.Policies = json.RawMessage(`[]`)
				stop["phase"] = "cleanup"
			default:
				if field, wrong := strings.CutPrefix(name, "wrong "); wrong {
					if field == "sequence" || field == "policy_version" {
						stop[field] = 3
					} else {
						stop[field] = "wrong"
					}
				} else {
					delete(stop, name)
				}
			}
			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{postgresSecurityAgentActionReadySQL: json.RawMessage(`{"release":true,"principal":true}`), postgresSecurityAgentActionStoreSQL: payload}}
			repository, err := NewSecurityAgentActionRepository(db)
			if err != nil {
				t.Fatal(err)
			}
			err = repository.StoreTemporaryPolicyTarget(context.Background(), localClaim, "budget-action-worker", "budget-action-worker-lease", localEnvelope)
			want := ErrRepositoryUnavailable
			if name == "valid" {
				want = ErrSecurityAgentBudgetStopped
			}
			if !errors.Is(err, want) {
				t.Fatalf("stop error=%v want=%v", err, want)
			}
		})
	}
}
