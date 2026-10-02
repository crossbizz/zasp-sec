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

func TestSecurityAgentMultistepCleanupLateStopPostgres(t *testing.T) {
	for _, mode := range []string{"global_stop", "bundle_expiry"} {
		t.Run(mode, func(t *testing.T) {
			exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				claimRequest := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
				claimRequest["lease_seconds"] = 300
				claim, err := orderedCleanupCall(ctx, action, claimRequest, keys)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				stage := ""
				if mode == "bundle_expiry" {
					stage = "short_lived"
				}
				deployOrderedCleanup(t, ctx, owner, key, stored, stage)
				q := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
				raw, _ := json.Marshal(q)
				if _, err = owner.Exec(ctx, `BEGIN;SET LOCAL session_replication_role=replica`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				// Negative lock fixture only. It is rolled back and can never serve as
				// cleanup proof. Skip this fixture's recovery-hold trigger so it holds
				// only the final unique audit key, not the earlier recovery fence.
				if _, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
		 SELECT $1,$2,$3,a,a,$4,$5,'cleanup-wait-fixture','cleanup_wait_fixture',decode(repeat('0',64),'hex'),'{}'::jsonb
		 FROM (SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_ordered_cleanup_operation',$4||chr(31)||$5||chr(31)||encode(digest(convert_to($6::jsonb::text,'UTF8'),'sha256'),'hex')) a) x`, o, w, e, r, steps[0], raw); err != nil {
					t.Fatal(err)
				}
				if _, err = owner.Exec(ctx, `SET LOCAL session_replication_role=origin`); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { _, callErr := orderedCleanupCall(ctx, action, q, keys); done <- callErr }()
				waitOrderedProgressionBlocked(t, ctx, owner, action)
				safety, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
				if err != nil {
					t.Fatal(err)
				}
				defer safety.Close(ctx)
				// Negative current-authority fault, not a public global-control route.
				// Tenant stops serialize on the recovery fence; global stop is separate.
				if mode == "global_stop" {
					if _, err = safety.Exec(ctx, `BEGIN;SET LOCAL statement_timeout='3s';SET LOCAL session_replication_role=replica;UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*');COMMIT`); err != nil {
						t.Fatal("global-stop fault could not commit", err)
					}
				} else if _, err = safety.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM b.expires_at-clock_timestamp()))+0.02) FROM zasp_policy_deployment_work x JOIN zasp_runtime_gateway_policy_bundles b ON(b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.applied_envelope_digest) WHERE x.organization_id=$1`, o); err != nil {
					t.Fatal(err)
				}
				before := orderedCleanupSnapshot(t, ctx, safety, r)
				if _, err = owner.Exec(ctx, `ROLLBACK`); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err == nil || orderedCleanupSnapshot(t, ctx, safety, r) != before {
					t.Fatal("completion used pre-wait safety authority", err)
				}
				if mode == "global_stop" {
					got, err := orderedCleanupCall(ctx, action, q, keys)
					if err != nil || got["run_state"] != "needs_human" || got["state"] != "cleaned" {
						t.Fatal("stopped cleanup lost retained removal authority", got, err)
					}
				}
			})
		})
	}
}

func TestSecurityAgentMultistepCleanupGatewaySafetyPostgres(t *testing.T) {
	for _, mode := range []string{"device_revocation", "credential_rotation"} {
		t.Run(mode, func(t *testing.T) {
			exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				q := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
				if _, err := orderedProgressionCall(ctx, action, "cleanup", q); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `BEGIN;SET LOCAL statement_timeout='3s'`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				lock := `SELECT 1 FROM zasp_gateway_devices WHERE id=$1 FOR UPDATE`
				if mode == "credential_rotation" {
					lock = `SELECT 1 FROM zasp_gateway_credentials WHERE id=$1 FOR UPDATE`
				}
				if _, err := owner.Exec(ctx, lock, orderedApplicationDevice); err != nil {
					t.Fatal(err)
				}
				q = orderedCleanupRequest(o, w, e, r, steps[0], "heartbeat", 10, 4, 1)
				if _, err := orderedProgressionCall(ctx, action, "cleanup", q); err == nil {
					t.Fatal("cleanup waited behind safety source")
				}
				if mode == "device_revocation" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_devices SET state='revoked',revoked_at=clock_timestamp() WHERE id=$1`, orderedApplicationDevice); err != nil {
						t.Fatal("revocation writer aborted", err)
					}
				} else {
					if _, err := owner.Exec(ctx, `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE id=$1`, orderedApplicationDevice); err != nil {
						t.Fatal("credential revocation aborted", err)
					}
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) SELECT organization_id,workspace_id,environment_id,'pid_8f000009-0000-4000-8000-000000000009',device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,2,key_id,algorithm,clock_timestamp() FROM zasp_gateway_credentials WHERE id=$1`, orderedApplicationDevice); err != nil {
						t.Fatal("credential rotation aborted", err)
					}
				}
				if _, err := owner.Exec(ctx, `COMMIT`); err != nil {
					t.Fatal(err)
				}
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				if _, err := orderedProgressionCall(ctx, action, "cleanup", q); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Fatal("cleanup accepted revoked authority", err)
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
					t.Fatal(err)
				}
				q = orderedCleanupRequest(o, w, e, r, steps[0], "reconcile", 10, 4, 1)
				got, err := orderedProgressionCall(ctx, action, "cleanup", q)
				if err != nil || got["run_state"] != "needs_human" || got["state"] != "retryable" || got["receipt_kind"] != "" {
					t.Fatal("inaccessible cleanup remained hidden", got, err)
				}
			})
		})
	}
}
