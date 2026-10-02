package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepAdmissionRepositoryBoundary(t *testing.T) {
	claim := multistepBudgetRepositoryClaim()
	value := orderedContextFixture()
	value.Context.InputDigest = "sha256:" + strings.Repeat("1", 64)
	claim.DefinitionID = value.Context.DefinitionID
	claim.TriggerID = value.Context.Evidence[0].ID
	var candidate securityAgentOrderedCandidate
	if err := json.Unmarshal([]byte(orderedCandidateJSON), &candidate); err != nil {
		t.Fatal(err)
	}
	submission := securityAgentOrderedSubmission{InputDigest: value.Context.InputDigest, OutputDigest: "sha256:" + strings.Repeat("a", 64), Model: "ordered-model", PolicyVersion: "ordered-policy", Candidate: candidate}
	// Fixed canonical SQL identities for this tenant/run, not arbitrary valid IDs.
	const receipt = `{"contract_version":61,"outcome":"admitted","organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","version":3,"plan_hash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","step_ids":["pid_2e9322f4-505e-4d5b-8057-a15ead7db914","pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f"],"step_states":["waiting_approval","dependency_blocked"],"approval_id":"pid_eb91594a-05f2-436b-8594-33e3733e6556","dependency_id":"pid_1da0d889-6b6b-4791-8db1-262d582cfd60","provider_reservation_id":"provider-reservation"}`
	for _, mode := range []string{"exact", "release60", "principal", "missing61", "mismatch61", "warm_mismatch", "bad_input", "foreign_receipt", "executed_receipt", "successor_ready", "null_field", "extra_field", "duplicate_field", "duplicate_steps", "invalid_version", "swapped_steps", "unrelated_step", "fabricated_step0", "fabricated_step1", "fabricated_approval", "fabricated_dependency", "swapped_approval_dependency"} {
		t.Run(mode, func(t *testing.T) {
			ready := `{"release":true,"principal":true}`
			switch mode {
			case "release60", "mismatch61":
				ready = `{"release":false,"principal":true}`
			case "principal":
				ready = `{"release":true,"principal":false}`
			case "missing61":
				ready = `{}`
			}
			raw := receipt
			switch mode {
			case "foreign_receipt":
				raw = strings.Replace(raw, claim.OrganizationID, claim.RunID, 1)
			case "executed_receipt":
				raw = strings.Replace(raw, `"admitted"`, `"executed"`, 1)
			case "successor_ready":
				raw = strings.Replace(raw, `"dependency_blocked"`, `"authorized"`, 1)
			case "null_field":
				raw = strings.Replace(raw, `"contract_version":61`, `"contract_version":null`, 1)
			case "extra_field":
				raw = strings.Replace(raw, `"contract_version":61`, `"contract_version":61,"effect_state":"succeeded"`, 1)
			case "duplicate_field":
				raw = strings.Replace(raw, `"contract_version":61`, `"contract_version":60,"contract_version":61`, 1)
			case "duplicate_steps":
				raw = strings.Replace(raw, "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", 1)
			case "invalid_version":
				raw = strings.Replace(raw, `"version":3`, `"version":2`, 1)
			case "swapped_steps":
				raw = strings.NewReplacer("pid_2e9322f4-505e-4d5b-8057-a15ead7db914", "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914").Replace(raw)
			case "unrelated_step":
				raw = strings.Replace(raw, "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", claim.DefinitionID, 1)
			case "fabricated_step0":
				raw = strings.Replace(raw, "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", "pid_78000004-0000-4000-8000-000000000004", 1)
			case "fabricated_step1":
				raw = strings.Replace(raw, "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f", "pid_78000005-0000-4000-8000-000000000005", 1)
			case "fabricated_approval":
				raw = strings.Replace(raw, "pid_eb91594a-05f2-436b-8594-33e3733e6556", "pid_78000006-0000-4000-8000-000000000006", 1)
			case "fabricated_dependency":
				raw = strings.Replace(raw, "pid_1da0d889-6b6b-4791-8db1-262d582cfd60", "pid_78000007-0000-4000-8000-000000000007", 1)
			case "swapped_approval_dependency":
				raw = strings.NewReplacer("pid_eb91594a-05f2-436b-8594-33e3733e6556", "pid_1da0d889-6b6b-4791-8db1-262d582cfd60", "pid_1da0d889-6b6b-4791-8db1-262d582cfd60", "pid_eb91594a-05f2-436b-8594-33e3733e6556").Replace(raw)
			}
			db := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{securityAgentMultistepAdmissionReadySQL: json.RawMessage(ready), securityAgentMultistepAdmissionSQL: json.RawMessage(raw)}}
			repo, err := newSecurityAgentMultistepAdmissionRepository(db)
			if mode == "release60" || mode == "principal" || mode == "missing61" || mode == "mismatch61" {
				if !errors.Is(err, ErrRepositoryUnavailable) || len(db.statements) != 1 {
					t.Fatal("inexact release did not fail before mutation", err, db.statements)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if args := db.arguments[0]; len(args) != 2 || args[0] != migrations.ProductionSecurityAgentMultistep().Checksum() || args[1] != migrations.SecurityAgentMultistepRegisteredFingerprint() {
				t.Fatal("registered identity not pinned", args)
			}
			if mode == "warm_mismatch" {
				db.responses[securityAgentMultistepAdmissionReadySQL] = json.RawMessage(`{"release":false,"principal":true}`)
			}
			input := submission
			if mode == "bad_input" {
				input.Candidate.Steps = append([]securityAgentOrderedStep(nil), input.Candidate.Steps...)
				input.Candidate.Steps[1].TargetID = claim.EnvironmentID
			}
			got, err := repo.admit(context.Background(), claim, "ordered-worker", "ordered-admission-lease", value, input)
			if mode == "exact" {
				if err != nil || got.Outcome != "admitted" || got.StepStates[1] != "dependency_blocked" {
					t.Fatalf("receipt=%+v err=%v", got, err)
				}
				var envelope map[string]json.RawMessage
				if len(db.arguments[len(db.arguments)-1]) != 3 || json.Unmarshal(db.arguments[len(db.arguments)-1][2].(json.RawMessage), &envelope) != nil || len(envelope) != 16 {
					t.Fatal("request envelope is not exact")
				}
			} else if err == nil {
				t.Fatal("invalid boundary accepted", mode)
			}
			if (mode == "bad_input" || mode == "warm_mismatch") && db.statements[len(db.statements)-1] == securityAgentMultistepAdmissionSQL {
				t.Fatal("invalid input or release reached mutation")
			}
		})
	}
	if _, err := newSecurityAgentMultistepAdmissionRepository(nil); !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatal("nil database accepted", err)
	}
}
