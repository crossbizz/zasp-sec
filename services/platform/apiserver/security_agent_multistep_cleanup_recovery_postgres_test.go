package apiserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSecurityAgentMultistepCleanupPublishedRecoveryPostgres(t *testing.T) {
	for _, mode := range []string{"unknown_call", "complete_unsettled", "expired_source"} {
		t.Run(mode, func(t *testing.T) {
			exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), keys)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				stage := ""
				if mode != "complete_unsettled" {
					stage = "stored"
				}
				priorRequest, priorDelivery := deployOrderedCleanup(t, ctx, owner, key, stored, stage)
				if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy';UPDATE zasp_policy_deployment_work SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$2 AND state='leased'`, pgx.QueryExecModeSimpleProtocol, r, o); err != nil {
					t.Fatal(err)
				}
				reconciled, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "reconcile", 10, 5, 2), keys)
				reason := mode
				if mode == "expired_source" {
					reason = "unknown_call"
				}
				if err != nil || reconciled["reason"] != reason || reconciled["run_state"] != "needs_human" || reconciled["receipt_kind"] != "" {
					t.Fatal("published cleanup uncertainty disappeared", reconciled, err)
				}
				q := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 11, 6, 3)
				q["lease_token"] = "ordered-cleanup-recovered-token"
				if mode == "expired_source" {
					// Expiry fault only; never positive acknowledgement evidence.
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_temporary_policy_targets SET expires_at=clock_timestamp()-interval '1 second',issued_at=clock_timestamp()-interval '301 seconds' WHERE run_id=$1 AND phase='cleanup'`, r); err != nil {
						t.Fatal(err)
					}
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					if _, err := orderedCleanupCall(ctx, action, q, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
						t.Fatal("expired source retry manufactured fresh delivery", err)
					}
					var retained bool
					if err := owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='needs_human') AND EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE run_id=$1 AND state='active') AND EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1 AND state='retryable' AND attempt=1) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1)`, r).Scan(&retained); err != nil || !retained {
						t.Fatal("expired cleanup disappeared", retained, err)
					}
					return
				}
				recovered, err := orderedCleanupCall(ctx, action, q, keys)
				if err != nil || recovered["cleanup_id"] != claim["cleanup_id"] || recovered["attempt"] != float64(2) {
					t.Fatal("published cleanup recovery absent", recovered, err)
				}
				if mode == "unknown_call" {
					config := owner.Config().Copy()
					config.User = "ordered_application_deployment"
					deployment, err := pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer deployment.Close(ctx)
					request := cloneOrderedApplicationRequest(t, priorRequest)
					request["run_version"], request["effect_version"], request["action_lease_token"], request["lease_token"] = 11, 7, "ordered-cleanup-recovered-token", "ordered-cleanup-delivery-retry"
					request["operation"], request["sequence"], request["input_digest"], request["composition"], request["envelope"], request["digest"] = "claim", 0, "", map[string]any{}, map[string]any{}, ""
					got, err := orderedCleanupDeploymentCall(ctx, deployment, request, keys)
					if err != nil {
						t.Fatal("stored bundle recovery", err)
					}
					raw, _ := json.Marshal(got["result"])
					var delivery orderedDeploymentClaim
					if json.Unmarshal(raw, &delivery) != nil || delivery.Sequence != priorDelivery.Sequence || delivery.InputDigest != priorDelivery.InputDigest {
						t.Fatal("unknown call allocated a new bundle instead of retaining exact stored bytes", got)
					}
					request["operation"], request["sequence"], request["input_digest"], request["composition"] = "read", delivery.Sequence, delivery.InputDigest, delivery.Composition
					got, err = orderedCleanupDeploymentCall(ctx, deployment, request, keys)
					if err != nil {
						t.Fatal(err)
					}
					raw, _ = json.Marshal(got["result"])
					var envelope policy.GatewayPolicyEnvelope
					if json.Unmarshal(raw, &envelope) != nil {
						t.Fatal(got)
					}
					request["operation"], request["digest"] = "finish", orderedEnvelopeDigest(envelope)
					if _, err = orderedCleanupDeploymentCall(ctx, deployment, request, keys); err != nil {
						t.Fatal("recovered exact bundle acknowledgement", err)
					}
				}
				complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 11, 7, 4)
				complete["lease_token"] = "ordered-cleanup-recovered-token"
				got, err := orderedCleanupCall(ctx, action, complete, keys)
				if err != nil || got["run_state"] != "needs_human" || got["state"] != "cleaned" {
					t.Fatal("uncertain cleanup became remediated or stuck", got, err)
				}
			})
		})
	}
}

func orderedCleanupDeploymentCall(ctx context.Context, connection *pgx.Conn, q map[string]any, keys policy.GatewayPolicyKeys) (map[string]any, error) {
	db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	raw, _ := json.Marshal(q)
	response, err := (&securityAgentMultistepAdmissionRepository{database: db}).cleanupDeployment(ctx, raw, keys)
	var got map[string]any
	if err == nil {
		err = json.Unmarshal(response, &got)
	}
	return got, err
}
