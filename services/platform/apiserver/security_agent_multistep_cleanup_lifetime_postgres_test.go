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

func TestSecurityAgentMultistepCleanupHeartbeatDeadlinePostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		if _, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), policy.GatewayPolicyKeys{}); err != nil {
			t.Fatal(err)
		}
		// A shortened lease is a negative clock fixture, never completion proof.
		if _, err := owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()+interval '3 seconds' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
			t.Fatal(err)
		}
		q := orderedCleanupRequest(o, w, e, r, steps[0], "heartbeat", 10, 4, 1)
		raw, _ := json.Marshal(q)
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err := owner.Exec(ctx, `BEGIN;SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `ROLLBACK`)
		// Hold only the final audit key. This row is rolled back and cannot
		// supply an acknowledgement or retained cleanup authority.
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
		 SELECT $1,$2,$3,a,a,$4,$5,'cleanup-deadline-fixture','cleanup_wait_fixture',decode(repeat('0',64),'hex'),'{}'::jsonb
		 FROM (SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_ordered_cleanup_operation',$4||chr(31)||$5||chr(31)||encode(digest(convert_to($6::jsonb::text,'UTF8'),'sha256'),'hex')) a) x`, o, w, e, r, steps[0], raw); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := orderedCleanupCall(ctx, action, q, policy.GatewayPolicyKeys{}); done <- err }()
		waitOrderedProgressionBlocked(t, ctx, owner, action)
		if _, err := owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM lease_expires_at-clock_timestamp()))+0.02) FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1`, r); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("heartbeat resurrected expired lease across audit wait", err)
		}
	})
}

func TestSecurityAgentMultistepCleanupRemediatedReplayPostgres(t *testing.T) {
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
		deployOrderedCleanup(t, ctx, owner, key, stored)
		complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
		got, err := orderedCleanupCall(ctx, action, complete, keys)
		if err != nil || got["run_state"] != "remediated" {
			t.Fatal("initial cleanup proof", got, err)
		}
		faults := map[string]string{
			"global_stop":      `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id='*' AND $1<>''`,
			"application_stop": `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=(SELECT organization_id FROM zasp_security_agent_runs WHERE run_id=$1) AND action_key='create_temporary_policy'`,
			"test_stop":        `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=(SELECT organization_id FROM zasp_security_agent_runs WHERE run_id=$1) AND action_key='run_test'`,
			"budget_stop":      `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`,
			"control_active":   `UPDATE zasp_security_agent_controls SET state='active',version=version-1 WHERE run_id=$1`,
			"work_generation":  `UPDATE zasp_policy_deployment_work SET desired_generation=desired_generation+1 WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
			"overdue_refresh":  `UPDATE zasp_policy_deployment_work SET available_at=clock_timestamp()-interval '1 second' WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
			"late_refresh":     `UPDATE zasp_policy_deployment_work x SET available_at=(SELECT expires_at FROM zasp_runtime_gateway_policy_bundles b WHERE b.envelope_digest=x.applied_envelope_digest AND b.device_id=x.device_id) WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1)`,
			"bundle_expired":   `UPDATE zasp_runtime_gateway_policy_bundles SET expires_at=clock_timestamp()-interval '1 second' WHERE envelope_digest IN(SELECT applied_envelope_digest FROM zasp_policy_deployment_work WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1))`,
			"bundle_changed":   `UPDATE zasp_runtime_gateway_policy_bundles SET expires_at=expires_at-interval '1 hour' WHERE envelope_digest IN(SELECT applied_envelope_digest FROM zasp_policy_deployment_work WHERE device_id IN(SELECT device_id FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1))`,
			"readiness":        `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1<>''`,
		}
		for _, mode := range []string{"global_stop", "application_stop", "test_stop", "budget_stop", "control_active", "work_generation", "overdue_refresh", "late_refresh", "bundle_expired", "bundle_changed", "readiness"} {
			t.Run(mode, func(t *testing.T) {
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
					t.Fatal(err)
				}
				defer owner.Exec(ctx, `ROLLBACK`)
				if mode == "global_stop" {
					// Negative current-authority fault; the public global writer
					// requires its separate principal. Restore triggers before call.
					if _, err := owner.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := owner.Exec(ctx, faults[mode], r); err != nil {
					t.Fatal("negative fixture", err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL session_replication_role=origin`); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{action.Config().User}.Sanitize()); err != nil {
					t.Fatal(err)
				}
				_, callErr := orderedProgressionCall(ctx, owner, "cleanup", complete)
				if callErr == nil {
					t.Error("remediated replay accepted changed current authority", mode)
				}
				// SQL errors abort this fault-only transaction. Roll back before
				// observing the unchanged committed owner, effect and audit.
				if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
					t.Fatal(err)
				}
				if orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Fatal("replay changed committed authority")
				}
			})
		}
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err := orderedCleanupCall(ctx, action, complete, keys); err != nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("unchanged replay", err)
		}
	})
}

func TestSecurityAgentMultistepCleanupDeliveryLifetimePostgres(t *testing.T) {
	for _, mode := range []string{"empty", "persistent", "temporary"} {
		t.Run(mode, func(t *testing.T) {
			exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				if mode == "persistent" {
					body, _ := json.Marshal(policy.Policy{ID: "retained-persistent", Name: "Retained", Scope: "environment", Trigger: "tool", Conditions: []policy.Condition{{Field: "action", Operator: "equals", Value: "write"}}, Action: policy.ActionBlock, Rollout: "enforced", FailureMode: "closed"})
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy','retained-persistent',$4::jsonb)`, o, w, e, body); err != nil {
						t.Fatal(err)
					}
				}
				var shorter time.Time
				if mode == "temporary" {
					var testID, actor string
					if err := owner.QueryRow(ctx, `SELECT p.plan->'steps'->1->>'target_id',x.requested_by FROM zasp_security_agent_runs x JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, r).Scan(&testID, &actor); err != nil {
						t.Fatal(err)
					}
					other, otherSteps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 909, true)
					claim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, other, otherSteps[0], "claim", 4, 0), keys)
					if err != nil {
						t.Fatal(err)
					}
					q := orderedApplicationStoreRequest(t, o, w, e, other, otherSteps[0], claim, key)
					shorter = orderedCleanupTestSourceLifetime(t, o, w, e, q, key, 3*time.Minute)
					if _, err = orderedApplicationCall(ctx, action, q, keys); err != nil {
						t.Fatal(err)
					}
				}
				claim, err := orderedCleanupCall(ctx, action, orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0), keys)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := orderedCleanupCall(ctx, action, orderedCleanupStoreRequest(t, o, w, e, r, steps[0], claim, key), keys)
				if err != nil {
					t.Fatal(err)
				}
				deployOrderedCleanup(t, ctx, owner, key, stored)
				var issued, expires, refresh, finished, marker time.Time
				if err := owner.QueryRow(ctx, `SELECT b.issued_at,b.expires_at,x.available_at,x.updated_at,t.expires_at FROM zasp_policy_deployment_work x JOIN zasp_runtime_gateway_policy_bundles b ON(b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.applied_envelope_digest) JOIN zasp_security_agent_temporary_policy_targets t ON(t.organization_id,t.workspace_id,t.environment_id,t.device_id,t.phase)=(x.organization_id,x.workspace_id,x.environment_id,x.device_id,'cleanup') WHERE t.run_id=$1`, r).Scan(&issued, &expires, &refresh, &finished, &marker); err != nil {
					t.Fatal(err)
				}
				if mode != "temporary" && (expires.Sub(issued) < 23*time.Hour || !expires.After(marker)) {
					t.Error("replacement bundle inherited five-minute cleanup marker", expires.Sub(issued))
				}
				if mode == "temporary" && !expires.Equal(shorter) {
					t.Error("replacement omitted earliest remaining source expiry", expires, shorter)
				}
				want := finished.Add(12 * time.Hour)
				if expires.Add(-time.Minute).Before(want) {
					want = expires.Add(-time.Minute)
				}
				if !refresh.Equal(want) || !refresh.After(time.Now()) || refresh.After(expires.Add(-time.Minute)) {
					t.Error("replacement refresh lacks one-minute safety margin", refresh, want, expires)
				}
				complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
				got, err := orderedCleanupCall(ctx, action, complete, keys)
				if err != nil || got["run_state"] != "remediated" {
					t.Fatal("fresh replacement cannot complete", got, err)
				}
			})
		})
	}
}

func TestSecurityAgentMultistepCleanupReplayApplicationExpiryPostgres(t *testing.T) {
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
		deployOrderedCleanup(t, ctx, owner, key, stored)
		q := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
		got, err := orderedCleanupCall(ctx, action, q, keys)
		if err != nil || got["run_state"] != "remediated" {
			t.Fatal("fresh application completion", got, err)
		}
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		// Original application, settlement and cleanup are all real signed proof.
		// Only time advances; no evidence or control row is rewritten.
		if _, err = owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM expires_at-clock_timestamp()))+0.02) FROM zasp_security_agent_controls WHERE run_id=$1`, r); err != nil {
			t.Fatal(err)
		}
		if _, err = orderedCleanupCall(ctx, action, q, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("remediated replay ignored original application expiry", err)
		}
	}, "cleanup_application_expiry")
}

func TestSecurityAgentMultistepCleanupDeliveryWindowWaitPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		var testID, actor string
		if err := owner.QueryRow(ctx, `SELECT p.plan->'steps'->1->>'target_id',x.requested_by FROM zasp_security_agent_runs x JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE x.run_id=$1`, r).Scan(&testID, &actor); err != nil {
			t.Fatal(err)
		}
		other, otherSteps := seedOrderedApplicationRun(t, ctx, owner, worker, api, o, w, e, testID, actor, 910, true)
		otherClaim, err := orderedApplicationCall(ctx, action, orderedApplicationRequest(o, w, e, other, otherSteps[0], "claim", 4, 0), keys)
		if err != nil {
			t.Fatal(err)
		}
		source := orderedApplicationStoreRequest(t, o, w, e, other, otherSteps[0], otherClaim, key)
		orderedCleanupTestSourceLifetime(t, o, w, e, source, key, 75*time.Second)
		if _, err = orderedApplicationCall(ctx, action, source, keys); err != nil {
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
		q := orderedApplicationDeploymentRequest(o, w, e, r, steps[0], stored)
		q["action_worker_id"], q["action_lease_token"] = "ordered-cleanup-worker", "ordered-cleanup-lease"
		raw, _ := json.Marshal(q)
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err = owner.Exec(ctx, `BEGIN;SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		defer owner.Exec(ctx, `ROLLBACK`)
		if _, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
		 SELECT $1,$2,$3,a,a,$4,$5,'cleanup-window-fixture','cleanup_wait_fixture',decode(repeat('0',64),'hex'),'{}'::jsonb
		 FROM (SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_ordered_cleanup_delivery',$4||chr(31)||$5||chr(31)||encode(digest(convert_to($6::jsonb::text,'UTF8'),'sha256'),'hex')) a) x`, o, w, e, r, steps[0], raw); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "ordered_application_deployment"
		deployment, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer deployment.Close(ctx)
		done := make(chan error, 1)
		go func() { _, err := orderedCleanupDeploymentCall(ctx, deployment, q, keys); done <- err }()
		waitOrderedProgressionBlocked(t, ctx, owner, deployment)
		if _, err = owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM expires_at-interval '1 minute'-clock_timestamp()))+0.02) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND phase='apply'`, other); err != nil {
			t.Fatal(err)
		}
		if _, err = owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("deployment claim lost refresh window across audit wait", err)
		}
	})
}

func TestSecurityAgentMultistepCleanupRefreshDeadlinePostgres(t *testing.T) {
	for _, mode := range []string{"complete_overdue", "replay_overdue", "insufficient_margin"} {
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
				stage := "refresh_due"
				if mode == "insufficient_margin" {
					stage = mode
				}
				finish, _ := deployOrderedCleanup(t, ctx, owner, key, stored, stage)
				complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
				if mode == "insufficient_margin" {
					config := owner.Config().Copy()
					config.User = "ordered_application_deployment"
					deployment, err := pgx.ConnectConfig(ctx, config)
					if err != nil {
						t.Fatal(err)
					}
					defer deployment.Close(ctx)
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					if _, err = orderedCleanupDeploymentCall(ctx, deployment, finish, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
						t.Fatal("finish committed without a safe future refresh", err)
					}
					return
				}
				if mode == "replay_overdue" {
					got, err := orderedCleanupCall(ctx, action, complete, keys)
					if err != nil || got["run_state"] != "remediated" {
						t.Fatal("fresh completion", got, err)
					}
				}
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				// Advance the clock past the real signed bundle's stored refresh
				// schedule. No owner-made deadline or acknowledgement is used.
				if _, err = owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM available_at-clock_timestamp()))+0.02) FROM zasp_policy_deployment_work WHERE organization_id=$1`, o); err != nil {
					t.Fatal(err)
				}
				if _, err = orderedCleanupCall(ctx, action, complete, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Fatal("cleanup accepted overdue replacement refresh", mode, err)
				}
			})
		})
	}
}

// Re-sign a real source with the same approved 600-second TTL and a shorter
// remaining lifetime. It still passes the private source/deployment boundary.
func orderedCleanupTestSourceLifetime(t *testing.T, o, w, e string, q map[string]any, key ed25519.PrivateKey, remaining time.Duration) time.Time {
	t.Helper()
	raw, _ := json.Marshal(q["envelope"])
	var source orderedApplicationSource
	if json.Unmarshal(raw, &source) != nil {
		t.Fatal("source fixture")
	}
	issued := time.Now().UTC().Truncate(time.Second).Add(remaining - 10*time.Minute)
	v := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "apply"}, TemporaryPolicyTarget{DeviceID: source.DeviceID, CredentialID: source.CredentialID, Sequence: source.Sequence, PolicyVersion: source.PolicyVersion}, "ordered-key-01", key, issued, issued.Add(10*time.Minute), source.Policies)
	q["envelope"] = map[string]any{"device_id": source.DeviceID, "credential_id": source.CredentialID, "sequence": source.Sequence, "policy_version": source.PolicyVersion, "key_id": v.KeyID, "issued_at": v.IssuedAt.Format(time.RFC3339Nano), "expires_at": v.ExpiresAt.Format(time.RFC3339Nano), "failure_mode": v.FailureMode, "payload_digest": v.PayloadDigest, "policies": v.Policies, "signature": base64.StdEncoding.EncodeToString(v.Signature), "envelope_digest": v.EnvelopeDigest}
	return v.ExpiresAt
}
