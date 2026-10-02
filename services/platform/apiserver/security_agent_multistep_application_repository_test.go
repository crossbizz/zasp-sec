package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Canonical identities are literal fixtures, independently checked with SHA-256.
func TestSecurityAgentMultistepApplicationRepositoryBoundary(t *testing.T) {
	const statement = `SELECT zasp_sa_multistep_prior.application($1,$2,$3::jsonb)`
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	const r = "pid_78000001-0000-4000-8000-000000000001"
	const s = "pid_2e9322f4-505e-4d5b-8057-a15ead7db914"
	for _, mode := range []string{"exact", "zero", "negative", "large", "versionless", "wrong_increment", "wrong_step", "wrong_state", "fabricated_reservation", "foreign_target", "duplicate_target", "empty_targets", "unexpected_control", "null", "extra", "duplicate", "input_zero", "input_successor", "complete", "complete_control", "complete_deployment", "complete_result", "complete_version"} {
		t.Run(mode, func(t *testing.T) {
			request := orderedApplicationRequest(o, w, e, r, s, "claim", 4, 0)
			response := map[string]any{"contract_version": 61, "organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": "claim", "run_version": 5, "step_version": 3, "effect_version": 1, "effect_state": "leased", "attempt": 1, "reservation_id": "pid_566b734b-2149-44b1-89f9-54756dd2bc75", "plan_hash": "sha256:" + strings.Repeat("b", 64), "input_digest": "sha256:" + strings.Repeat("c", 64), "ttl_seconds": 600, "lease_expires_at": time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), "targets": []any{map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": 1, "policy_version": 1, "state": "planned", "desired_generation": 0, "envelope_digest": ""}}, "control_id": "", "deployment_id": "", "result_digest": ""}
			if strings.HasPrefix(mode, "complete") {
				request["operation"] = "complete"
				request["run_version"] = 5
				request["effect_version"] = 2
				response["operation"] = "complete"
				response["run_version"] = 6
				response["step_version"] = 4
				response["effect_version"] = 3
				response["effect_state"] = "cleanup_pending"
				response["control_id"] = "pid_a2aa254b-65a4-4496-841d-dea4663f634a"
				response["deployment_id"] = "pid_c1ecbb1a-f36b-46e3-8c38-681b453866b5"
				response["result_digest"] = "sha256:14385ce59285a976e7688cb367ad91715f14a2bf07881dd5f0a4371e9c9bde9c"
				target := response["targets"].([]any)[0].(map[string]any)
				target["state"] = "verified"
				target["desired_generation"] = 3
				target["envelope_digest"] = "sha256:" + strings.Repeat("a", 64)
			}
			switch mode {
			case "zero":
				response["effect_version"] = 0
			case "negative":
				response["effect_version"] = -1
			case "large":
				response["effect_version"] = 9999999
			case "versionless":
				delete(response, "effect_version")
			case "wrong_increment":
				response["run_version"] = 4
			case "wrong_step":
				response["step_version"] = 4
			case "wrong_state":
				response["effect_state"] = "cleanup_pending"
			case "fabricated_reservation":
				response["reservation_id"] = r
			case "foreign_target":
				response["targets"].([]any)[0].(map[string]any)["device_id"] = "foreign"
			case "duplicate_target":
				response["targets"] = append(response["targets"].([]any), response["targets"].([]any)[0])
			case "empty_targets":
				response["targets"] = []any{}
			case "unexpected_control":
				response["control_id"] = r
			case "null":
				response["effect_version"] = nil
			case "extra":
				response["public_route"] = true
			case "input_zero":
				request["run_version"] = 0
			case "input_successor":
				request["step_id"] = "pid_53f7d26b-caa5-4049-89a2-fdaca5467c7f"
			case "complete_control":
				response["control_id"] = r
			case "complete_deployment":
				response["deployment_id"] = r
			case "complete_result":
				response["result_digest"] = "sha256:" + strings.Repeat("c", 64)
			case "complete_version":
				response["step_version"] = 3
			}
			input, _ := json.Marshal(request)
			output, _ := json.Marshal(response)
			if mode == "duplicate" {
				output = []byte(strings.Replace(string(output), `"effect_version":1`, `"effect_version":0,"effect_version":1`, 1))
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{statement: output}}
			repository, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				application(context.Context, json.RawMessage, policy.GatewayPolicyKeys) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private release61 application repository absent")
			}
			got, err := repository.application(context.Background(), input, policy.GatewayPolicyKeys{})
			if mode == "exact" || mode == "complete" {
				if err != nil || string(got) != string(output) {
					t.Fatal(string(got), err)
				}
			} else if err == nil {
				t.Fatal("fabricated application authority accepted", mode)
			}
			if strings.HasPrefix(mode, "input_") {
				if len(database.statements) != 0 {
					t.Fatal("invalid request reached SQL")
				}
				return
			}
			if len(database.arguments) != 1 || database.arguments[0][0] != migrations.ProductionSecurityAgentMultistep().Checksum() || database.arguments[0][1] != migrations.SecurityAgentMultistepRegisteredFingerprint() {
				t.Fatal("release61 identity not pinned", database.arguments)
			}
		})
	}
}

func TestSecurityAgentMultistepApplicationSignatureBoundary(t *testing.T) {
	const o = "pid_70000001-0000-4000-8000-000000000001"
	const w = "pid_70000002-0000-4000-8000-000000000002"
	const e = "pid_70000003-0000-4000-8000-000000000003"
	const r = "pid_78000001-0000-4000-8000-000000000001"
	const s = "pid_2e9322f4-505e-4d5b-8057-a15ead7db914"
	claim := map[string]any{"targets": []any{map[string]any{"device_id": orderedApplicationDevice, "credential_id": orderedApplicationDevice, "sequence": float64(1), "policy_version": float64(1)}}, "ttl_seconds": float64(600)}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	for _, mode := range []string{"signature", "digest", "scope", "policy", "key"} {
		t.Run(mode, func(t *testing.T) {
			request := cloneOrderedApplicationRequest(t, orderedApplicationStoreRequest(t, o, w, e, r, s, claim, key))
			envelope := request["envelope"].(map[string]any)
			switch mode {
			case "signature":
				envelope["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "digest":
				envelope["envelope_digest"] = "sha256:" + strings.Repeat("a", 64)
			case "scope":
				envelope["device_id"] = r
			case "policy":
				envelope["policies"] = []any{}
			case "key":
				envelope["key_id"] = "unknown-key-01"
			}
			database := &securityAgentRepositoryDatabase{}
			repository := &securityAgentMultistepAdmissionRepository{database: database}
			raw, _ := json.Marshal(request)
			if _, err := repository.application(context.Background(), raw, keys); !errors.Is(err, ErrRepositoryOperation) || len(database.statements) != 0 {
				t.Fatal("unverified source reached database", err)
			}
		})
	}
}

func TestSecurityAgentMultistepApplicationCancellationResponse(t *testing.T) {
	const request = `{"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_2e9322f4-505e-4d5b-8057-a15ead7db914","operation":"cancel","actor_id":"pid_78000002-0000-4000-8000-000000000002","run_version":5,"approval_version":1,"fresh_auth_at":"2026-09-20T00:00:00Z"}`
	const response = `{"contract_version":61,"organization_id":"pid_70000001-0000-4000-8000-000000000001","workspace_id":"pid_70000002-0000-4000-8000-000000000002","environment_id":"pid_70000003-0000-4000-8000-000000000003","run_id":"pid_78000001-0000-4000-8000-000000000001","step_id":"pid_2e9322f4-505e-4d5b-8057-a15ead7db914","outcome":"blocked","run_state":"cancelled","run_version":6,"step_state":"executing","approval_id":"pid_eb91594a-05f2-436b-8594-33e3733e6556","approval_version":2}`
	for _, mode := range []string{"exact", "command", "step", "approval", "approval_version", "parent", "same_version", "large_increment", "missing_approval"} {
		t.Run(mode, func(t *testing.T) {
			input, output := request, response
			switch mode {
			case "command":
				input = strings.Replace(input, `"cancel"`, `"reject"`, 1)
			case "step":
				// Task9 adds canonical step1; noncanonical steps remain closed.
				input = strings.Replace(input, "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", "pid_78000001-0000-4000-8000-000000000001", 1)
				output = strings.Replace(output, "pid_2e9322f4-505e-4d5b-8057-a15ead7db914", "pid_78000001-0000-4000-8000-000000000001", 1)
			case "approval":
				output = strings.Replace(output, "pid_eb91594a-05f2-436b-8594-33e3733e6556", "pid_78000001-0000-4000-8000-000000000001", 1)
			case "approval_version":
				output = strings.Replace(output, `"approval_version":2`, `"approval_version":1`, 1)
			case "parent":
				output = strings.Replace(output, `"cancelled"`, `"needs_human"`, 1)
			case "same_version":
				output = strings.Replace(output, `"run_version":6`, `"run_version":5`, 1)
			case "large_increment":
				output = strings.Replace(output, `"run_version":6`, `"run_version":7`, 1)
			case "missing_approval":
				output = strings.Replace(output, `"approval_id":"pid_eb91594a-05f2-436b-8594-33e3733e6556","approval_version":2`, `"approval_id":"","approval_version":0`, 1)
			}
			database := &securityAgentRepositoryDatabase{responses: map[string]json.RawMessage{`SELECT zasp_sa_multistep_prior.transition($1,$2,$3::jsonb)`: json.RawMessage(output)}}
			repository := &securityAgentMultistepAdmissionRepository{database: database}
			_, err := repository.transition(context.Background(), json.RawMessage(input))
			if mode == "exact" && err != nil {
				t.Fatal("legitimate cancelled execution rejected", err)
			}
			if mode != "exact" && err == nil {
				t.Fatal("impossible cancellation accepted", mode)
			}
		})
	}
}
