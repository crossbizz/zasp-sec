package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentMultistepDeploymentRepositoryBoundary(t *testing.T) {
	const statement = `SELECT zasp_sa_multistep_prior.deployment($1,$2,$3::jsonb)`
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	const r = "pid_78000001-0000-4000-8000-000000000001"
	const s = "pid_2e9322f4-505e-4d5b-8057-a15ead7db914"
	for _, mode := range []string{"exact", "large", "unsignable", "source_id", "work_id", "wrong_credential", "wrong_generation", "wrong_sequence", "wrong_digest", "empty_policy", "legacy_duplicate", "expired_lease", "extra", "null", "composition_missing", "composition_source_id", "composition_source_content", "composition_expiry", "composition_policy_order", "composition_duplicate", "input_foreign", "input_zero", "store_bad_signature", "finish_wrong_generation", "finish_pending"} {
		t.Run(mode, func(t *testing.T) {
			stored := map[string]any{"run_version": 5, "effect_version": 2, "targets": []any{map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": 1, "desired_generation": 3, "envelope_digest": "sha256:" + strings.Repeat("a", 64)}}}
			request := orderedApplicationDeploymentRequest(o, w, e, r, s, stored)
			policies := []policy.CompiledPolicy{}
			for _, definition := range []policy.Policy{{ID: "temporary-containment-http-v1", Trigger: "http_request", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "http.method", Operator: "present"}}}, {ID: "temporary-containment-mcp-v1", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}}} {
				p, err := policy.Compile(definition)
				if err != nil {
					t.Fatal(err)
				}
				policies = append(policies, p)
			}
			issued := time.Now().UTC().Truncate(time.Second)
			expires := issued.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
			source := map[string]any{"source_id": "pid_e78185cb-0d8a-4f9b-8409-edf0187d0a6f", "run_id": r, "step_id": s, "action_key": "create_temporary_policy", "credential_id": orderedApplicationDevice, "sequence": 1, "policy_version": 1, "desired_generation": 3, "envelope_digest": "sha256:" + strings.Repeat("a", 64), "issued_at": issued.Format("2006-01-02T15:04:05.000000Z"), "expires_at": expires, "failure_mode": "closed", "policies": policies}
			composition := map[string]any{"persistent_sources": []any{}, "temporary_sources": []any{source}, "policies": policies, "expires_at": expires}
			if mode == "large" || mode == "unsignable" {
				count, content := 2, "x"
				if mode == "unsignable" {
					count, content = 10, "<"
				}
				persistent := []any{}
				compiled := append([]policy.CompiledPolicy{}, policies...)
				for i := 0; i < count; i++ {
					definition := policy.Policy{ID: fmt.Sprintf("large-persistent-%02d", i), Name: "Large valid policy", Scope: "environment", Trigger: "tool", Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
					for j := 0; j < 32; j++ {
						definition.Conditions = append(definition.Conditions, policy.Condition{Field: "resource", Operator: "equals", Value: fmt.Sprintf("%03d", j) + strings.Repeat(content, 253)})
					}
					value, active, err := policy.CompileGatewayPolicy(definition)
					if err != nil || !active {
						t.Fatal(err)
					}
					persistent = append(persistent, map[string]any{"id": definition.ID, "version": 1, "policy": definition})
					compiled = append(compiled, value)
				}
				sort.Slice(compiled, func(i, j int) bool { return compiled[i].ID < compiled[j].ID })
				composition["persistent_sources"], composition["policies"] = persistent, compiled
			}
			// Independent fixture oracle: the literal scope/source binding plus
			// canonical JSON is hashed here, without a production identity helper.
			fixtureDigest := func() string {
				raw, _ := json.Marshal(composition)
				var jsonValue any
				if err := json.Unmarshal(raw, &jsonValue); err != nil {
					t.Fatal(err)
				}
				canonical, _ := json.Marshal(jsonValue)
				hash := sha256.Sum256([]byte(strings.Join([]string{o, w, e, r, s, orderedApplicationDevice, orderedApplicationDevice, "3", "1", "sha256:" + strings.Repeat("a", 64), string(canonical)}, "\x1f")))
				return "sha256:" + hex.EncodeToString(hash[:])
			}
			claim := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "desired_generation": 3, "sequence": 1, "policy_version": 1, "input_digest": fixtureDigest(), "lease_expires_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), "composition": composition}
			response := map[string]any{"contract_version": 61, "run_id": r, "step_id": s, "operation": "claim", "source_id": "pid_e78185cb-0d8a-4f9b-8409-edf0187d0a6f", "work_id": "pid_eed1b1da-09c2-4b96-888b-e15bd4874900", "result": claim}
			switch mode {
			case "source_id":
				response["source_id"] = r
			case "work_id":
				response["work_id"] = r
			case "wrong_credential":
				claim["credential_id"] = r
			case "wrong_generation":
				claim["desired_generation"] = 4
			case "wrong_sequence":
				claim["sequence"] = 0
			case "wrong_digest":
				claim["input_digest"] = "sha256:" + strings.Repeat("f", 64)
			case "empty_policy":
				composition["policies"] = []any{}
				claim["input_digest"] = fixtureDigest()
			case "legacy_duplicate":
				claim["temporary_policies"] = policies
			case "expired_lease":
				claim["lease_expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
			case "extra":
				response["public"] = true
			case "null":
				claim["sequence"] = nil
			case "composition_missing":
				delete(claim, "composition")
			case "composition_source_id":
				source["source_id"] = r
			case "composition_source_content":
				source["envelope_digest"] = "sha256:" + strings.Repeat("b", 64)
			case "composition_expiry":
				composition["expires_at"] = issued.Add(6 * time.Minute).Format("2006-01-02T15:04:05.000000Z")
			case "composition_policy_order":
				composition["policies"] = []policy.CompiledPolicy{policies[1], policies[0]}
			case "composition_duplicate":
				composition["temporary_sources"] = []any{source, source}
			case "input_foreign":
				request["step_id"] = r
			case "input_zero":
				request["desired_generation"] = 0
			case "store_bad_signature":
				request["operation"] = "store"
				request["sequence"] = 1
				request["input_digest"] = claim["input_digest"]
				request["composition"] = composition
				request["digest"] = "sha256:" + strings.Repeat("b", 64)
			case "finish_wrong_generation", "finish_pending":
				request["operation"] = "finish"
				request["sequence"] = 1
				request["input_digest"] = claim["input_digest"]
				request["composition"] = composition
				request["digest"] = "sha256:" + strings.Repeat("b", 64)
				result := map[string]any{"desired_generation": 3, "applied_generation": 3, "state": "scheduled", "envelope_digest": request["digest"]}
				response["operation"] = "finish"
				response["result"] = result
				if mode == "finish_pending" {
					result["state"] = "pending"
				} else {
					result["applied_generation"] = 4
				}
			}
			if strings.HasPrefix(mode, "composition_") {
				claim["input_digest"] = fixtureDigest()
			}
			input, _ := json.Marshal(request)
			output, _ := json.Marshal(response)
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{statement: output}}
			repository, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				deployment(context.Context, json.RawMessage, policy.GatewayPolicyKeys) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private release61 deployment repository absent")
			}
			got, err := repository.deployment(context.Background(), input, policy.GatewayPolicyKeys{})
			if mode == "exact" || mode == "large" {
				if err != nil || string(got) != string(output) {
					t.Fatal(string(got), err)
				}
			} else if err == nil {
				t.Fatal("fabricated deployment authority accepted", mode)
			}
			if strings.HasPrefix(mode, "input_") || mode == "store_bad_signature" {
				if len(database.statements) != 0 {
					t.Fatal("invalid deployment input reached SQL")
				}
			}
		})
	}
}
