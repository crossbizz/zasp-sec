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

// Catch a first completion that commits after its signed execution marker
// expires, without confusing that deadline with a durable completed replay.
func TestSecurityAgentMultistepCleanupMarkerDeadlinePostgres(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wait      bool
		many      bool
		wantError bool
		wantState string
	}{
		{"first_wait", true, false, true, "contained|10|leased|5|leased|2|0|0"},
		{"first_wait_shortest", true, true, true, "contained|10|leased|7|leased|3|0|0"},
		{"already_expired", false, false, true, "contained|10|leased|5|leased|2|0|0"},
		{"completed_replay", false, false, false, "remediated|11|cleaned|6|cleaned|3|1|1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := ""
			claimEffect, completeEffect, completeVersion, targetCount := 3, 5, 2, 1
			if tc.many {
				fixture, claimEffect, completeEffect, completeVersion, targetCount = "cleanup_many", 4, 7, 3, 2
			}
			exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
				q := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, claimEffect, 0)
				q["lease_seconds"] = 300
				claim, err := orderedCleanupRestartCall(ctx, action, q, keys)
				if err != nil {
					t.Fatal(err)
				}
				stored := claim
				for i, target := range claim["targets"].([]any) {
					selected := cloneOrderedApplicationRequest(t, stored)
					selected["targets"] = []any{target}
					store := orderedCleanupStoreRequest(t, o, w, e, r, steps[0], selected, key)
					if i == 0 {
						store = orderedCleanupShortMarker(t, o, w, e, r, steps[0], selected, key)
					}
					stored, err = orderedCleanupRestartCall(ctx, action, store, keys)
					if err != nil {
						t.Fatal("real signed marker rejected", err)
					}
				}
				for _, target := range stored["targets"].([]any) {
					selected := cloneOrderedApplicationRequest(t, stored)
					selected["targets"] = []any{target}
					deployOrderedCleanup(t, ctx, owner, key, selected)
				}
				var ready bool
				if err = owner.QueryRow(ctx, `SELECT count(*)=$2 AND bool_and(t.expires_at=t.issued_at+interval '5 minutes') AND min(t.expires_at)>clock_timestamp() AND min(c.lease_expires_at)>min(t.expires_at)+interval '1 minute' AND (count(*)=1 OR max(t.expires_at)>min(t.expires_at)+interval '1 minute')
				 FROM zasp_security_agent_temporary_policy_targets t JOIN zasp_sa_multistep_prior.cleanups c USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE t.run_id=$1 AND t.phase='cleanup'`, r, targetCount).Scan(&ready); err != nil || !ready {
					t.Fatal("marker/worker deadline fixture", ready, err)
				}
				complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, completeEffect, completeVersion)
				var first map[string]any
				if tc.name == "completed_replay" {
					first, err = orderedCleanupRestartCall(ctx, action, complete, keys)
					if err != nil || first["run_state"] != "remediated" || first["version"] != float64(3) || first["effect_version"] != float64(6) || first["run_version"] != float64(11) {
						t.Fatal("fresh first completion", first, err)
					}
				}
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				var got map[string]any
				if tc.wait {
					raw, _ := json.Marshal(complete)
					if _, err = owner.Exec(ctx, `BEGIN;SET LOCAL session_replication_role=replica`); err != nil {
						t.Fatal(err)
					}
					defer owner.Exec(ctx, `ROLLBACK`)
					// Hold only the final audit key. This negative lock fixture is
					// rolled back and never supplies a receipt or acknowledgement.
					if _, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
					 SELECT $1,$2,$3,a,a,$4,$5,'cleanup-marker-fixture','cleanup_wait_fixture',decode(repeat('0',64),'hex'),'{}'::jsonb
					 FROM (SELECT zasp_discovery_canonical_id($1,$2,$3,'security_agent_ordered_cleanup_operation',$4||chr(31)||$5||chr(31)||encode(digest(convert_to($6::jsonb::text,'UTF8'),'sha256'),'hex')) a) x`, o, w, e, r, steps[0], raw); err != nil {
						t.Fatal(err)
					}
					if _, err = owner.Exec(ctx, `SET LOCAL session_replication_role=origin`); err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { _, callErr := orderedCleanupCall(ctx, action, complete, keys); done <- callErr }()
					waitOrderedProgressionBlocked(t, ctx, owner, action)
					orderedCleanupWaitMarkerExpiry(t, ctx, owner, r)
					if _, err = owner.Exec(ctx, `ROLLBACK`); err != nil {
						t.Fatal(err)
					}
					err = <-done
				} else {
					orderedCleanupWaitMarkerExpiry(t, ctx, owner, r)
					got, err = orderedCleanupRestartCall(ctx, action, complete, keys)
				}
				if (err != nil) != tc.wantError {
					t.Errorf("marker-expiry first-completion/replay distinction: want error %v, got %v", tc.wantError, err)
				}
				if orderedCleanupSnapshot(t, ctx, owner, r) != before {
					t.Error("marker expiry changed owner/effect/run/receipt/audit")
				}
				var state string
				if stateErr := owner.QueryRow(ctx, `SELECT concat_ws('|',r.state,r.version,f.state,f.version,c.state,c.version,
				 (SELECT count(*) FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1),
				 (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='ordered_cleanup_complete'))
				 FROM zasp_security_agent_runs r JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_sa_multistep_prior.cleanups c USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE r.run_id=$1 AND f.action_key='create_temporary_policy'`, r).Scan(&state); stateErr != nil || state != tc.wantState {
					t.Error("literal terminal/rollback postconditions", state, tc.wantState, stateErr)
				}
				if tc.name == "completed_replay" && err == nil {
					original, _ := json.Marshal(first)
					replayed, _ := json.Marshal(got)
					if string(original) != string(replayed) {
						t.Fatal("expired marker changed immutable completed response")
					}
					orderedCleanupExpiredReplayNearMisses(t, ctx, owner, action, o, r, steps, complete, keys)
				} else if tc.wantError && err != nil {
					if _, err = orderedCleanupRestartCall(ctx, action, complete, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
						t.Fatal("uncommitted completion acquired replay authority", err)
					}
				}
			}, fixture)
		})
	}
}

func orderedCleanupShortMarker(t *testing.T, o, w, e, r, s string, claim map[string]any, key ed25519.PrivateKey) map[string]any {
	t.Helper()
	q := orderedCleanupStoreRequest(t, o, w, e, r, s, claim, key)
	raw, _ := json.Marshal(q["envelope"])
	var source orderedApplicationSource
	if json.Unmarshal(raw, &source) != nil {
		t.Fatal("cleanup marker fixture")
	}
	// Keep the required signed TTL. Only its remaining lifetime is shorter.
	expires := time.Now().UTC().Truncate(time.Second).Add(30 * time.Second)
	v := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: source.DeviceID, CredentialID: source.CredentialID, Sequence: source.Sequence, PolicyVersion: source.PolicyVersion}, "ordered-key-01", key, expires.Add(-5*time.Minute), expires, source.Policies)
	q["envelope"] = map[string]any{"device_id": source.DeviceID, "credential_id": source.CredentialID, "sequence": source.Sequence, "policy_version": source.PolicyVersion, "key_id": v.KeyID, "issued_at": v.IssuedAt.Format(time.RFC3339Nano), "expires_at": v.ExpiresAt.Format(time.RFC3339Nano), "failure_mode": v.FailureMode, "payload_digest": v.PayloadDigest, "policies": v.Policies, "signature": base64.StdEncoding.EncodeToString(v.Signature), "envelope_digest": v.EnvelopeDigest}
	return q
}

func orderedCleanupWaitMarkerExpiry(t *testing.T, ctx context.Context, owner *pgx.Conn, r string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `SELECT pg_sleep(GREATEST(0,extract(epoch FROM min(expires_at)-clock_timestamp()))+0.02) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND phase='cleanup'`, r); err != nil {
		t.Fatal(err)
	}
}

func orderedCleanupExpiredReplayNearMisses(t *testing.T, ctx context.Context, owner, action *pgx.Conn, o, r string, steps []string, complete map[string]any, keys policy.GatewayPolicyKeys) {
	t.Helper()
	for _, change := range []struct {
		field string
		value any
	}{
		{"operation", "heartbeat"}, {"step_id", steps[1]}, {"run_version", 11}, {"effect_version", 6}, {"version", 3}, {"lease_token", "different-cleanup-lease"},
	} {
		q := cloneOrderedApplicationRequest(t, complete)
		q[change.field] = change.value
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err := orderedCleanupRestartCall(ctx, action, q, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("expired marker permitted non-exact replay", change.field, err)
		}
	}
	for _, fault := range []string{
		`UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1 AND action_key='run_test'`,
		`UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE organization_id=$1`,
		`UPDATE zasp_policy_deployment_work SET available_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`,
		`UPDATE zasp_runtime_gateway_policy_bundles SET expires_at=clock_timestamp()-interval '1 second' WHERE organization_id=$1`,
		`UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1<>''`,
	} {
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, fault, o); err != nil {
			owner.Exec(ctx, `ROLLBACK`)
			t.Fatal("replay safety fault fixture", err)
		}
		if _, err := owner.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{action.Config().User}.Sanitize()); err != nil {
			owner.Exec(ctx, `ROLLBACK`)
			t.Fatal(err)
		}
		_, callErr := orderedProgressionCall(ctx, owner, "cleanup", complete)
		if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
			t.Fatal(err)
		}
		if callErr == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("expired marker replay skipped current safety", fault, callErr)
		}
	}
	before := orderedCleanupSnapshot(t, ctx, owner, r)
	if _, err := orderedCleanupRestartCall(ctx, action, complete, keys); err != nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
		t.Fatal("unchanged expired-marker replay", err)
	}
}
