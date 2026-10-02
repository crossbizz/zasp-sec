package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// A valid policy composition must not commit a lease that its Go caller cannot
// decode. This is the reviewer's two-policy, maximum-condition ASCII case.
func TestSecurityAgentMultistepDeploymentWirePostgres(t *testing.T) {
	for _, tc := range []struct {
		name, value, trigger string
		count                int
		unsignable           bool
	}{{"reviewer", "x", "tool", 2, false}, {"large_signed", "<", "tool", 8, false}, {"maximum_provenance", "<", "network", 98, false}, {"gateway_oversize", "<", "tool", 10, true}, {"gateway_exact_limit", "x", "tool", 98, false}, {"max_key_refusal", "x", "tool", 98, true}} {
		t.Run(tc.name, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
				defer deployment.Close(ctx)
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				definitions := []policy.Policy{}
				for i := 0; i < tc.count; i++ {
					definition := policy.Policy{ID: fmt.Sprintf("large-persistent-%02d", i), Name: "Large valid policy", Scope: "environment", Trigger: tc.trigger, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
					for j := 0; j < 32; j++ {
						definition.Conditions = append(definition.Conditions, policy.Condition{Field: "resource", Operator: "equals", Value: fmt.Sprintf("%03d", j) + strings.Repeat(tc.value, 253)})
					}
					if _, active, err := policy.CompileGatewayPolicy(definition); err != nil || active != (tc.trigger == "tool") {
						t.Fatal("invalid large fixture", err)
					}
					definitions = append(definitions, definition)
				}
				if tc.name == "gateway_exact_limit" || tc.name == "max_key_refusal" {
					maximum := 1024 * 1024
					if tc.unsignable {
						maximum++
					}
					orderedWireFitPolicies(t, definitions, o, w, e, maximum)
				}
				for _, definition := range definitions {
					body, _ := json.Marshal(definition)
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, o, w, e, definition.ID, body); err != nil {
						t.Fatal(err)
					}
				}
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey), strings.Repeat("k", 64): key.Public().(ed25519.PublicKey)})
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 932, true)
				claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), keys)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				request := orderedApplicationDeploymentRequest(o, w, e, r, steps[0], stored)
				if tc.name == "reviewer" {
					before := orderedApplicationSnapshot(t, ctx, owner, r)
					request["composition"] = map[string]any{"padding": strings.Repeat("x", 10*1024*1024)}
					if _, err = orderedCompositionDeploymentCall(ctx, deployment, request, keys); err != ErrRepositoryOperation {
						t.Fatal("oversized request reached private SQL", err)
					}
					if _, err = orderedProgressionCall(ctx, deployment, "deployment", request); err == nil || !strings.Contains(err.Error(), "request wire budget exceeded") || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("oversized SQL request changed authority", err)
					}
					request["composition"] = map[string]any{}
				}
				if tc.unsignable {
					before := orderedApplicationSnapshot(t, ctx, owner, r)
					_, err = orderedProgressionCall(ctx, deployment, "deployment", request)
					if err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("unsignable gateway composition committed a lease or audit", err)
					}
					return
				}
				got, err := orderedCompositionDeploymentCall(ctx, deployment, request, keys)
				if err != nil {
					var state string
					var attempt, responseBytes int
					if scanErr := owner.QueryRow(ctx, `SELECT state,attempt FROM zasp_policy_deployment_work WHERE device_id=$1`, orderedApplicationDevice).Scan(&state, &attempt); scanErr != nil {
						t.Fatal(scanErr)
					}
					if scanErr := owner.QueryRow(ctx, `SELECT octet_length((body->'response')::text) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_delivery_claim'`, r).Scan(&responseBytes); scanErr != nil {
						t.Fatal(scanErr)
					}
					_, replayErr := orderedCompositionDeploymentCall(ctx, deployment, request, keys)
					t.Fatalf("valid large claim unavailable: %v; replay=%v; committed state=%s attempt=%d response_bytes=%d", err, replayErr, state, attempt, responseBytes)
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if _, err = orderedCompositionDeploymentCall(ctx, deployment, request, keys); err != nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
					t.Fatal("large claim replay changed authority", err)
				}
				if tc.name == "reviewer" {
					// Corrupt an authority-created claim response, never an external
					// acknowledgement. Exact replay must fence an oversized result.
					if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_audit SET body=jsonb_set(body,'{response,padding}',to_jsonb(repeat('x',8388608))) WHERE run_id=$1 AND event_kind='ordered_delivery_claim'`, r); err != nil {
						t.Fatal(err)
					}
					faultSnapshot := orderedApplicationSnapshot(t, ctx, owner, r)
					if _, err = orderedProgressionCall(ctx, deployment, "deployment", request); err == nil || !strings.Contains(err.Error(), "replay wire budget exceeded") || orderedApplicationSnapshot(t, ctx, owner, r) != faultSnapshot {
						t.Fatal("oversized replay changed authority", err)
					}
					if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_audit SET body=body #- '{response,padding}' WHERE run_id=$1 AND event_kind='ordered_delivery_claim'`, r); err != nil {
						t.Fatal(err)
					}
					if orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("claim fault restoration changed authority")
					}
				}
				encoded, _ := json.Marshal(got["result"])
				var delivery orderedDeploymentClaim
				if err = json.Unmarshal(encoded, &delivery); err != nil {
					t.Fatal(err)
				}
				var composition orderedDeploymentComposition
				compiledCount := 2
				if tc.trigger == "tool" {
					compiledCount += tc.count
				}
				if err = json.Unmarshal(delivery.Composition, &composition); err != nil || len(composition.PersistentSources) != tc.count || len(composition.Policies) != compiledCount {
					t.Fatal("large claim lost policies", err)
				}
				expires, err := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Truncate(time.Second)
				keyID := "ordered-key-01"
				if tc.name == "gateway_exact_limit" {
					keyID = strings.Repeat("k", 64)
				}
				envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: keyID, Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: uint64(delivery.Sequence), PolicyVersion: uint64(delivery.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: composition.Policies}, key)
				if err != nil {
					t.Fatal(err)
				}
				if tc.name == "gateway_exact_limit" {
					raw, _ := json.Marshal(envelope)
					if len(raw) != 1024*1024 {
						t.Fatal("gateway boundary fixture", len(raw))
					}
				}
				request["sequence"], request["input_digest"], request["composition"] = delivery.Sequence, delivery.InputDigest, delivery.Composition
				request["operation"], request["envelope"], request["digest"] = "store", envelope, orderedEnvelopeDigest(envelope)
				for _, operation := range []string{"store", "read", "finish"} {
					request["operation"] = operation
					if operation != "store" {
						request["envelope"] = map[string]any{}
					}
					if operation == "read" {
						request["digest"] = ""
					} else {
						request["digest"] = orderedEnvelopeDigest(envelope)
					}
					if _, err = orderedCompositionDeploymentCall(ctx, deployment, request, keys); err != nil {
						t.Fatal("large roundtrip", operation, err)
					}
					before = orderedApplicationSnapshot(t, ctx, owner, r)
					if _, err = orderedCompositionDeploymentCall(ctx, deployment, request, keys); err != nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("large operation replay changed authority", operation, err)
					}
				}
				if _, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, 2), keys); err != nil {
					t.Fatal("large acknowledged composition completion", err)
				}
			})
		})
	}
}

func TestSecurityAgentMultistepDeploymentWireParityPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		for _, tc := range []struct {
			maximum int
			request bool
		}{{8 * 1024 * 1024, false}, {10 * 1024 * 1024, true}} {
			for _, delta := range []int{-1, 0, 1} {
				raw := `{"value": "` + strings.Repeat("x", tc.maximum-13+delta) + `"}`
				var native string
				var sqlValid bool
				if err := owner.QueryRow(ctx, `SELECT v::text,zasp_sa_multistep_prior.deployment_wire(v,$2) FROM (SELECT $1::jsonb v) input`, raw, tc.request).Scan(&native, &sqlValid); err != nil {
					t.Fatal(err)
				}
				maximum := orderedDeploymentResponseBytes
				if tc.request {
					maximum = orderedDeploymentRequestBytes
				}
				_, goValid := orderedDeploymentClosedObject([]byte(native), maximum, "value")
				if len(native) != tc.maximum+delta || sqlValid != (delta <= 0) || goValid != sqlValid {
					t.Fatal("SQL/Go wire budget mismatch", tc.maximum, delta, len(native), sqlValid, goValid)
				}
			}
		}
		scope, _ := orderedApplicationScope(o, w, e, "pid_78000001-0000-4000-8000-000000000001", "pid_2e9322f4-505e-4d5b-8057-a15ead7db914")
		for _, delta := range []int{-1, 0, 1} {
			definitions := orderedWireBoundaryDefinitions()
			policies := orderedWireFitPolicies(t, definitions, o, w, e, 1024*1024+delta)
			raw, _ := json.Marshal(policies)
			var sqlValid bool
			if err := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.deployment_signable($1,$2,$3,$4,1,$5::jsonb)`, o, w, e, orderedApplicationDevice, raw).Scan(&sqlValid); err != nil {
				t.Fatal(err)
			}
			goValid := orderedDeploymentSignable(scope, orderedApplicationDevice, 1, policies)
			if sqlValid != (delta <= 0) || goValid != sqlValid {
				t.Fatal("gateway canonical budget parity", delta, sqlValid, goValid)
			}
		}
	})
}

func orderedWireBoundaryDefinitions() []policy.Policy {
	var definitions []policy.Policy
	for i := 0; i < 98; i++ {
		value := policy.Policy{ID: fmt.Sprintf("large-persistent-%02d", i), Name: "Gateway boundary", Scope: "environment", Trigger: "tool", Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
		for j := 0; j < 32; j++ {
			value.Conditions = append(value.Conditions, policy.Condition{Field: "resource", Operator: "equals", Value: "x"})
		}
		definitions = append(definitions, value)
	}
	return definitions
}

// Build real valid policies whose fully signed envelope is exactly maximum
// bytes with the longest legal key ID. Each added ASCII value byte appears in
// both conditions and Rego (two bytes); replacing x with < adds eleven bytes.
func orderedWireFitPolicies(t *testing.T, definitions []policy.Policy, o, w, e string, maximum int) []policy.CompiledPolicy {
	t.Helper()
	for i := range definitions {
		for j := range definitions[i].Conditions {
			definitions[i].Conditions[j].Value = "x"
		}
	}
	compiled := func() []policy.CompiledPolicy {
		var result []policy.CompiledPolicy
		for _, definition := range definitions {
			value, active, err := policy.CompileGatewayPolicy(definition)
			if err != nil || !active {
				t.Fatal(err)
			}
			result = append(result, value)
		}
		for _, definition := range []policy.Policy{{ID: "temporary-containment-http-v1", Trigger: "http_request", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "http.method", Operator: "present"}}}, {ID: "temporary-containment-mcp-v1", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}}} {
			value, err := policy.Compile(definition)
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, value)
		}
		sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
		return result
	}
	when := time.Now().UTC().Truncate(time.Second)
	value := policy.GatewayPolicyEnvelope{ContractVersion: 1, KeyID: strings.Repeat("k", 64), Algorithm: "Ed25519", Audience: "runtime-gateway-policy", OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice, Sequence: 1, PolicyVersion: 1, IssuedAt: when, ExpiresAt: when.Add(time.Minute), FailureMode: "closed", PayloadDigest: strings.Repeat("0", 64), Signature: strings.Repeat("A", 86), Policies: compiled()}
	raw, _ := json.Marshal(value)
	remaining := maximum - len(raw)
	if remaining < 11 {
		t.Fatal("boundary fixture has no capacity", remaining)
	}
	if remaining%2 != 0 {
		definitions[0].Conditions[0].Value = "<"
		remaining -= 11
	}
	for i := range definitions {
		for j := range definitions[i].Conditions {
			addition := min(remaining/2, 256-len(definitions[i].Conditions[j].Value))
			definitions[i].Conditions[j].Value += strings.Repeat("x", addition)
			remaining -= 2 * addition
		}
	}
	value.Policies = compiled()
	raw, _ = json.Marshal(value)
	if remaining != 0 || len(raw) != maximum {
		t.Fatal("boundary fixture fill", remaining, len(raw), maximum)
	}
	// Even the +1 max-key case must still be valid with a shorter key, proving
	// that the conservative claim refusal is specifically the unbound key size.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: 1, PolicyVersion: 1, Now: when, IssuedAt: when, ExpiresAt: when.Add(time.Minute), FailureMode: "closed", Policies: value.Policies}, key); err != nil {
		t.Fatal("near-limit policies are not signable", err)
	}
	return value.Policies
}
