package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// Signed does not mean authorized: every claimed policy and source lifetime
// must be checked in SQL, including callers bypassing the private Go adapter.
func TestSecurityAgentMultistepDeploymentCompositionPostgres(t *testing.T) {
	for _, mode := range []string{"exact", "exact_escaped", "invalid_persistent", "omit_persistent", "extra_policy", "persistent_content", "policy_order", "changed_claim", "changed_store", "changed_finish", "changed_complete", "extend_unrelated_source"} {
		t.Run(mode, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
				action := orderedActionFenceConnection(t, ctx, owner)
				defer action.Close(ctx)
				deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
				defer deployment.Close(ctx)
				seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
				definition := policy.Policy{ID: "persistent-block-write", Name: "Persistent block", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "write"}}, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
				if mode == "exact_escaped" {
					definition.Conditions = []policy.Condition{{Field: "resource", Operator: "equals", Value: "write <&> \"\\\u2028\u2029z"}, {Field: "action", Operator: "equals", Value: "write"}}
				}
				if mode == "invalid_persistent" {
					definition.Conditions[0].Value = "write\u2028"
				}
				body, _ := json.Marshal(definition)
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, o, w, e, definition.ID, body); err != nil {
					t.Fatal(err)
				}
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				if mode == "extend_unrelated_source" {
					prior, priorSteps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 920, true)
					claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, prior, priorSteps[0], "claim", 4, 0), keys)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, prior, priorSteps[0], claim, key), keys); err != nil {
						t.Fatal(err)
					}
					unrelated, err := policy.Compile(policy.Policy{ID: "unrelated-short-source", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "equals", Value: "write"}}})
					if err != nil {
						t.Fatal(err)
					}
					policies, _ := json.Marshal([]policy.CompiledPolicy{unrelated})
					// Fault fixture for an independent active source. This does not
					// create a bundle acknowledgement, verification, control or receipt.
					if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_temporary_policy_targets SET policies=$2::jsonb,expires_at=date_trunc('second',clock_timestamp())+interval '2 minutes' WHERE run_id=$1`, prior, policies); err != nil {
						t.Fatal(err)
					}
				}
				r, steps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 921, true)
				claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "claim", 4, 0), keys)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := orderedApplicationCall(ctx, action, orderedApplicationStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				request := orderedApplicationDeploymentRequest(o, w, e, r, steps[0], stored)
				if mode == "invalid_persistent" {
					before := orderedApplicationSnapshot(t, ctx, owner, r)
					if _, err = orderedProgressionCall(ctx, deployment, "deployment", request); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("invalid persistent content committed a lease", err)
					}
					return
				}
				got, err := orderedCompositionDeploymentCall(ctx, deployment, request, keys)
				if err != nil {
					t.Fatal("composition claim", err)
				}
				encoded, _ := json.Marshal(got["result"])
				var delivery orderedDeploymentClaim
				if err = json.Unmarshal(encoded, &delivery); err != nil {
					t.Fatal(err)
				}
				var composition orderedDeploymentComposition
				if err = json.Unmarshal(delivery.Composition, &composition); err != nil {
					t.Fatal(err)
				}
				temporary := []policy.CompiledPolicy{}
				for _, source := range composition.TemporarySources {
					temporary = append(temporary, source.Policies...)
				}
				if mode == "changed_claim" {
					orderedCompositionDrift(t, ctx, owner, o, w, e, definition.ID)
					before := orderedApplicationSnapshot(t, ctx, owner, r)
					if _, err = orderedProgressionCall(ctx, deployment, "deployment", request); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("changed composition claim replay accepted", err)
					}
					return
				}
				compiled, active, err := policy.CompileGatewayPolicy(definition)
				if err != nil || !active {
					t.Fatal(err)
				}
				policies := append([]policy.CompiledPolicy{compiled}, temporary...)
				if mode == "persistent_content" {
					definition.Action = policy.ActionMonitor
					changed, _, compileErr := policy.CompileGatewayPolicy(definition)
					if compileErr != nil {
						t.Fatal(compileErr)
					}
					policies[0] = changed
				}
				if mode == "omit_persistent" {
					policies = temporary
				}
				if mode == "extra_policy" {
					extra, compileErr := policy.Compile(policy.Policy{ID: "unauthorized-extra", Trigger: "tool_call", Action: policy.ActionBlock, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}})
					if compileErr != nil {
						t.Fatal(compileErr)
					}
					policies = append(policies, extra)
				}
				sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
				now := time.Now().UTC().Truncate(time.Second)
				expires, err := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "extend_unrelated_source" {
					if err = owner.QueryRow(ctx, `SELECT expires_at FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1`, r).Scan(&expires); err != nil {
						t.Fatal(err)
					}
					expires = expires.UTC()
				}
				envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, Sequence: uint64(delivery.Sequence), PolicyVersion: uint64(delivery.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: policies}, key)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "policy_order" {
					envelope.Policies[0], envelope.Policies[1] = envelope.Policies[1], envelope.Policies[0]
					if _, verifyErr := policy.VerifyGatewayPolicyEnvelope(envelope, keys, policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: orderedApplicationDevice}, now); verifyErr != nil {
						t.Fatal("unordered test envelope is not signed", verifyErr)
					}
				}
				request["operation"], request["sequence"], request["input_digest"], request["envelope"], request["digest"] = "store", delivery.Sequence, delivery.InputDigest, envelope, orderedEnvelopeDigest(envelope)
				request["composition"] = delivery.Composition
				if mode == "changed_store" {
					orderedCompositionDrift(t, ctx, owner, o, w, e, definition.ID)
				}
				before := orderedApplicationSnapshot(t, ctx, owner, r)
				if mode == "omit_persistent" || mode == "extra_policy" || mode == "persistent_content" || mode == "policy_order" || mode == "changed_store" || mode == "extend_unrelated_source" {
					_, err = orderedProgressionCall(ctx, deployment, "deployment", request)
					if err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("unauthorized composition stored", mode, err)
					}
					return
				}
				if _, err = orderedCompositionDeploymentCall(ctx, deployment, request, keys); err != nil {
					t.Fatal("exact composition store", err)
				}
				request["operation"], request["envelope"] = "finish", map[string]any{}
				if mode == "changed_finish" {
					orderedCompositionDrift(t, ctx, owner, o, w, e, definition.ID)
					before = orderedApplicationSnapshot(t, ctx, owner, r)
					if _, err = orderedProgressionCall(ctx, deployment, "deployment", request); err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("changed composition acknowledged", err)
					}
					return
				}
				if _, err = orderedCompositionDeploymentCall(ctx, deployment, request, keys); err != nil {
					t.Fatal("exact composition finish", err)
				}
				if mode == "changed_complete" {
					orderedCompositionDrift(t, ctx, owner, o, w, e, definition.ID)
				}
				before = orderedApplicationSnapshot(t, ctx, owner, r)
				_, err = orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, r, steps[0], "complete", 5, 2), keys)
				if mode == "changed_complete" {
					if err == nil || orderedApplicationSnapshot(t, ctx, owner, r) != before {
						t.Fatal("changed composition produced receipt", err)
					}
				} else if err != nil {
					t.Fatal("complete exact composition", err)
				}
			})
		})
	}
}

func orderedCompositionDeploymentCall(ctx context.Context, connection *pgx.Conn, request map[string]any, keys policy.GatewayPolicyKeys) (map[string]any, error) {
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		return nil, err
	}
	repository := &securityAgentMultistepAdmissionRepository{database: database}
	raw, _ := json.Marshal(request)
	response, err := repository.deployment(ctx, raw, keys)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	err = json.Unmarshal(response, &value)
	return value, err
}

func orderedCompositionDrift(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, id string) {
	t.Helper()
	// Preserve generation as a named fault: content must be bound independently
	// of the trigger-maintained counter and rechecked at each commit boundary.
	if _, err := owner.Exec(ctx, `DO $fault$ DECLARE prior zasp_policy_deployment_work%ROWTYPE; BEGIN SELECT * INTO prior FROM zasp_policy_deployment_work WHERE device_id='`+orderedApplicationDevice+`'; UPDATE zasp_workflow_records SET body=jsonb_set(body,'{conditions,0,value}','"changed"') WHERE (organization_id,workspace_id,environment_id,kind,id)=('`+o+`','`+w+`','`+e+`','policy','`+id+`'); UPDATE zasp_policy_deployment_work SET desired_generation=prior.desired_generation,updated_at=prior.updated_at WHERE device_id=prior.device_id; END $fault$`); err != nil {
		t.Fatal(err)
	}
}
