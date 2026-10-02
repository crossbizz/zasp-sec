package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentMultistepCleanupConservativePostgres(t *testing.T) {
	for _, mode := range []string{"reproduced", "unknown", "stopped", "test_stopped"} {
		t.Run(mode, func(t *testing.T) {
			exerciseOrderedTestDispatchWithCleanup(t, mode != "unknown", func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				if mode == "stopped" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1;UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$2`, pgx.QueryExecModeSimpleProtocol, r, o); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "test_stopped" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1 AND action_key='run_test'`, o); err != nil {
						t.Fatal(err)
					}
				}
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), keys)
				if err != nil {
					t.Fatal("conservative parent suppressed cleanup", err)
				}
				stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				deployOrderedCleanup(t, ctx, owner, key, stored)
				got, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2), keys)
				if err != nil || got["run_state"] != "needs_human" || got["state"] != "cleaned" {
					t.Fatal("conservative cleanup claimed remediation", got, err)
				}
			}, mode)
		})
	}
}

func TestSecurityAgentMultistepCleanupCompositionPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		persistent := policy.Policy{ID: "retained-persistent", Name: "Retained persistent policy", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "write"}}, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"}
		body, _ := json.Marshal(persistent)
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,$5::jsonb)`, o, w, e, persistent.ID, body); err != nil {
			t.Fatal(err)
		}
		var testID, actor string
		if err := owner.QueryRow(ctx, `SELECT p.plan->'steps'->1->>'target_id',x.requested_by FROM zasp_security_agent_runs x JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, r).Scan(&testID, &actor); err != nil {
			t.Fatal(err)
		}
		unrelated, otherSteps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 905, true)
		otherClaim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, unrelated, otherSteps[0], "claim", 4, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		otherStore := orderedApplicationStoreRequest(t, o, w, e, unrelated, otherSteps[0], otherClaim, key)
		raw, _ := json.Marshal(otherStore["envelope"])
		var source orderedApplicationSource
		if json.Unmarshal(raw, &source) != nil {
			t.Fatal("fixture source")
		}
		// A valid signed source with a shorter remaining lifetime. No owner-made
		// source, bundle, target verification, control or receipt is inserted.
		now := time.Now().UTC().Truncate(time.Second)
		issued := now.Add(-7 * time.Minute)
		value := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "apply"}, TemporaryPolicyTarget{DeviceID: source.DeviceID, CredentialID: source.CredentialID, Sequence: source.Sequence, PolicyVersion: source.PolicyVersion}, "ordered-key-01", key, issued, issued.Add(600*time.Second), source.Policies)
		otherStore["envelope"] = map[string]any{"device_id": source.DeviceID, "credential_id": source.CredentialID, "sequence": source.Sequence, "policy_version": source.PolicyVersion, "key_id": value.KeyID, "issued_at": value.IssuedAt.Format(time.RFC3339Nano), "expires_at": value.ExpiresAt.Format(time.RFC3339Nano), "failure_mode": value.FailureMode, "payload_digest": value.PayloadDigest, "policies": value.Policies, "signature": base64.StdEncoding.EncodeToString(value.Signature), "envelope_digest": value.EnvelopeDigest}
		if _, err = orderedApplicationCall(ctx, action, otherStore, keys); err != nil {
			t.Fatal("real unrelated source", err)
		}
		var beforeOther string
		if err = owner.QueryRow(ctx, `SELECT to_jsonb(x)::text FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1`, unrelated).Scan(&beforeOther); err != nil {
			t.Fatal(err)
		}
		claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
		if err != nil {
			t.Fatal(err)
		}
		request, delivery := deployOrderedCleanup(t, ctx, owner, key, stored, "claimed")
		var composition orderedDeploymentComposition
		if json.Unmarshal(delivery.Composition, &composition) != nil || len(composition.PersistentSources) != 1 || len(composition.TemporarySources) != 1 || composition.TemporarySources[0].RunID != unrelated || len(composition.Policies) != 3 {
			t.Fatal("incomplete remaining composition", string(delivery.Composition))
		}
		expires, _ := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
		if !expires.Equal(value.ExpiresAt) {
			t.Fatal("unrelated minimum expiry lost", expires, value.ExpiresAt)
		}
		config := owner.Config().Copy()
		config.User = "ordered_application_deployment"
		deployment, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer deployment.Close(ctx)
		for _, mode := range []string{"omit_persistent", "extra_policy", "extend_source", "changed_composition"} {
			t.Run(mode, func(t *testing.T) {
				q := cloneOrderedApplicationRequest(t, request)
				policies := append([]policy.CompiledPolicy{}, composition.Policies...)
				until := expires
				if mode == "omit_persistent" {
					policies = policies[1:]
				}
				if mode == "extra_policy" {
					extra, _ := policy.Compile(policy.Policy{ID: "unauthorized-extra", Trigger: "tool_call", Action: policy.ActionMonitor, Conditions: []policy.Condition{{Field: "tool.name", Operator: "present"}}})
					policies = append(policies, extra)
				}
				if mode == "extend_source" {
					until = now.Add(4 * time.Minute)
				}
				if mode == "changed_composition" {
					q["composition"].(map[string]any)["persistent_sources"] = []any{}
				}
				envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: delivery.DeviceID}, Sequence: uint64(delivery.Sequence), PolicyVersion: uint64(delivery.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: until, FailureMode: "closed", Policies: policies}, key)
				if err != nil {
					t.Fatal(err)
				}
				q["envelope"], q["digest"] = envelope, orderedEnvelopeDigest(envelope)
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				if _, err = orderedProgressionCall(ctx, deployment, "cleanup_deployment", q); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Fatal("SQL accepted unauthorized removal composition", mode, err)
				}
				if _, err = orderedCleanupDeploymentCall(ctx, deployment, q, keys); err == nil {
					t.Fatal("Go accepted unauthorized removal composition", mode)
				}
			})
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		got, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2), keys)
		if err != nil || got["run_state"] != "remediated" {
			t.Fatal("complete remaining composition cleanup failed", got, err)
		}
		var afterOther string
		if err = owner.QueryRow(ctx, `SELECT to_jsonb(x)::text FROM zasp_security_agent_temporary_policy_targets x WHERE run_id=$1`, unrelated).Scan(&afterOther); err != nil || beforeOther != afterOther {
			t.Fatal("cleanup mutated unrelated source", err)
		}
	})
}
