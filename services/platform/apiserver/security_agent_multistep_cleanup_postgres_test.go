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

// The predecessor uses real private application/deployment acknowledgement,
// the invocation journal and immutable artifact settlement. No owner-inserted
// receipt, cleanup target or deployment acknowledgement is completion proof.
func TestSecurityAgentMultistepCleanupClaimPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		q := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
		got, err := orderedProgressionCall(ctx, action, "cleanup", q)
		if err != nil {
			t.Fatal("private retained cleanup authority absent", err)
		}
		if got["state"] != "leased" || got["attempt"] != float64(1) || got["version"] != float64(1) || got["effect_version"] != float64(4) || got["run_version"] != float64(10) || got["run_state"] != "contained" {
			t.Fatal("cleanup claim postconditions", got)
		}
	})
}

func TestSecurityAgentMultistepCleanupLeasePostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		q := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
		if _, err := action.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}
		defer action.Exec(ctx, `ROLLBACK`)
		first, err := orderedProgressionCall(ctx, action, "cleanup", q)
		if err != nil {
			t.Fatal(err)
		}
		other, err := pgx.ConnectConfig(ctx, action.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close(ctx)
		rival := cloneOrderedApplicationRequest(t, q)
		rival["lease_token"] = "ordered-cleanup-rival-lease"
		done := make(chan error, 1)
		go func() { _, callErr := orderedProgressionCall(ctx, other, "cleanup", rival); done <- callErr }()
		waitOrderedProgressionBlocked(t, ctx, action, other)
		if _, err = action.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}
		if err = <-done; err == nil {
			t.Fatal("two cleanup owners acquired")
		}
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		replay, err := orderedProgressionCall(ctx, other, "cleanup", q)
		if err != nil || replay["cleanup_id"] != first["cleanup_id"] || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("cleanup restart changed owner", replay, err)
		}
		beat, err := orderedProgressionCall(ctx, other, "cleanup", orderedCleanupRequest(o, w, e, r, steps[0], "heartbeat", 10, 4, 1))
		if err != nil || beat["version"] != float64(2) || beat["attempt"] != float64(1) || beat["effect_version"] != float64(5) {
			t.Fatal("cleanup heartbeat absent", beat, err)
		}
	})
}

func TestSecurityAgentMultistepCleanupRoundtripPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
		q := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
		got, err := orderedCleanupRestartCall(ctx, action, q, keys)
		if err != nil {
			t.Fatal("private cleanup repository absent", err)
		}
		store := orderedCleanupStoreRequest(t, o, w, e, r, steps[0], got, key)
		stored, err := orderedCleanupRestartCall(ctx, action, store, keys)
		if err != nil {
			t.Fatal("exact source removal absent", err)
		}
		complete := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 10, 5, 2)
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err = orderedCleanupRestartCall(ctx, action, complete, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("cleanup completed without deployment acknowledgement", err)
		}
		deployOrderedCleanup(t, ctx, owner, key, stored)
		result, err := orderedCleanupRestartCall(ctx, action, complete, keys)
		if err != nil || result["run_state"] != "remediated" || result["effect_state"] != "cleaned" || result["state"] != "cleaned" {
			t.Fatal("verified cleanup did not remediate", result, err)
		}
		before = orderedCleanupSnapshot(t, ctx, owner, r)
		replay, err := orderedCleanupRestartCall(ctx, action, complete, keys)
		if err != nil || replay["cleanup_id"] != result["cleanup_id"] || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("cleanup replay changed immutable authority", replay, err)
		}
	})
}

func TestSecurityAgentMultistepCleanupRecoveryPostgres(t *testing.T) {
	exerciseOrderedTestDispatchWithCleanup(t, true, func(ctx context.Context, owner, worker, api, action *pgx.Conn, o, w, e, r string, steps []string) {
		claim := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 10, 3, 0)
		first, err := orderedProgressionCall(ctx, action, "cleanup", claim)
		if err != nil {
			t.Fatal(err)
		}
		q := orderedCleanupRequest(o, w, e, r, steps[0], "reconcile", 10, 4, 1)
		before := orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err = orderedProgressionCall(ctx, action, "cleanup", q); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("reconciled a live cleanup lease", err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1;UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.cleanups WHERE run_id=$1) WHERE run_id=$1 AND action_key='create_temporary_policy'`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
			t.Fatal(err)
		}
		got, err := orderedProgressionCall(ctx, action, "cleanup", q)
		if err != nil || got["state"] != "retryable" || got["reason"] != "no_external_call" || got["run_state"] != "needs_human" || got["effect_state"] != "cleanup_failed" || got["receipt_kind"] != "" {
			t.Fatal("expired cleanup has no conservative recovery", got, err)
		}
		before = orderedCleanupSnapshot(t, ctx, owner, r)
		if _, err = orderedProgressionCall(ctx, action, "cleanup", q); err != nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("cleanup reconciliation replay", err)
		}
		recovery := orderedCleanupRequest(o, w, e, r, steps[0], "claim", 11, 5, 2)
		recovery["lease_token"] = "ordered-cleanup-recovery-lease"
		got, err = orderedProgressionCall(ctx, action, "cleanup", recovery)
		if err != nil || got["attempt"] != float64(2) || got["cleanup_id"] != first["cleanup_id"] || got["reservation_id"] != first["reservation_id"] {
			t.Fatal("cleanup retry lost stable identity", got, err)
		}
		before = orderedCleanupSnapshot(t, ctx, owner, r)
		stale := orderedCleanupRequest(o, w, e, r, steps[0], "complete", 11, 6, 3)
		if _, err = orderedProgressionCall(ctx, action, "cleanup", stale); err == nil || orderedCleanupSnapshot(t, ctx, owner, r) != before {
			t.Fatal("stale cleanup worker mutated current owner", err)
		}
	})
}

func orderedCleanupCall(ctx context.Context, connection *pgx.Conn, q map[string]any, keys policy.GatewayPolicyKeys) (map[string]any, error) {
	db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	boundary, ok := any(&securityAgentMultistepAdmissionRepository{database: db}).(interface {
		cleanup(context.Context, json.RawMessage, policy.GatewayPolicyKeys) (json.RawMessage, error)
	})
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	raw, _ := json.Marshal(q)
	response, err := boundary.cleanup(ctx, raw, keys)
	var got map[string]any
	if err == nil {
		err = json.Unmarshal(response, &got)
	}
	return got, err
}

func orderedCleanupRestartCall(ctx context.Context, prior *pgx.Conn, q map[string]any, keys policy.GatewayPolicyKeys) (map[string]any, error) {
	connection, err := pgx.ConnectConfig(ctx, prior.Config().Copy())
	if err != nil {
		return nil, err
	}
	defer connection.Close(ctx)
	return orderedCleanupCall(ctx, connection, q, keys)
}

func orderedCleanupSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, r string) string {
	t.Helper()
	var private string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('owners',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_prior.cleanups x WHERE run_id=$1),'receipts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_prior.cleanup_receipts x WHERE run_id=$1))::text`, r).Scan(&private); err != nil {
		t.Fatal(err)
	}
	return orderedTestSnapshot(t, ctx, owner, r) + private
}

func orderedCleanupStoreRequest(t *testing.T, o, w, e, r, s string, claim map[string]any, key ed25519.PrivateKey) map[string]any {
	t.Helper()
	d := claim["targets"].([]any)[0].(map[string]any)
	target := TemporaryPolicyTarget{DeviceID: d["device_id"].(string), CredentialID: d["credential_id"].(string), Sequence: int64(d["sequence"].(float64)), PolicyVersion: int64(d["policy_version"].(float64))}
	now := time.Now().UTC().Truncate(time.Second)
	v := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, target, "ordered-key-01", key, now, now.Add(5*time.Minute), []policy.CompiledPolicy{})
	q := orderedCleanupRequest(o, w, e, r, s, "store", int(claim["run_version"].(float64)), int(claim["effect_version"].(float64)), int(claim["version"].(float64)))
	q["envelope"] = map[string]any{"device_id": target.DeviceID, "credential_id": target.CredentialID, "sequence": target.Sequence, "policy_version": target.PolicyVersion, "key_id": v.KeyID, "issued_at": v.IssuedAt.Format(time.RFC3339Nano), "expires_at": v.ExpiresAt.Format(time.RFC3339Nano), "failure_mode": v.FailureMode, "payload_digest": v.PayloadDigest, "policies": v.Policies, "signature": base64.StdEncoding.EncodeToString(v.Signature), "envelope_digest": v.EnvelopeDigest}
	return q
}

func deployOrderedCleanup(t *testing.T, ctx context.Context, owner *pgx.Conn, key ed25519.PrivateKey, stored map[string]any, stages ...string) (map[string]any, orderedDeploymentClaim) {
	t.Helper()
	// The application fixture already registered this exact deployment principal.
	config := owner.Config().Copy()
	config.User = "ordered_application_deployment"
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { connection.Close(ctx) }()
	keys, _ := policy.NewGatewayPolicyKeys(map[string]ed25519.PublicKey{"ordered-key-01": key.Public().(ed25519.PublicKey)})
	q := orderedApplicationDeploymentRequest(stored["organization_id"].(string), stored["workspace_id"].(string), stored["environment_id"].(string), stored["run_id"].(string), stored["step_id"].(string), stored)
	q["action_worker_id"], q["action_lease_token"] = "ordered-cleanup-worker", "ordered-cleanup-lease"
	if token, ok := stored["cleanup_lease_token"].(string); ok {
		q["action_lease_token"] = token
	}
	call := func() map[string]any {
		// Reconstruct the connection and private repository at every boundary.
		// Replay never depends on process-local acknowledgement state.
		if err := connection.Close(ctx); err != nil {
			t.Fatal(err)
		}
		connection, err = pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		boundary, ok := any(&securityAgentMultistepAdmissionRepository{database: db}).(interface {
			cleanupDeployment(context.Context, json.RawMessage, policy.GatewayPolicyKeys) (json.RawMessage, error)
		})
		if !ok {
			t.Fatal("private cleanup deployment repository absent")
		}
		raw, _ := json.Marshal(q)
		rawResult, err := boundary.cleanupDeployment(ctx, raw, keys)
		if err != nil {
			t.Fatal("cleanup deployment "+q["operation"].(string), err)
		}
		var got map[string]any
		if json.Unmarshal(rawResult, &got) != nil {
			t.Fatal(string(rawResult))
		}
		return got
	}
	got := call()
	call()
	raw, _ := json.Marshal(got["result"])
	var claim orderedDeploymentClaim
	if json.Unmarshal(raw, &claim) != nil {
		t.Fatal(got)
	}
	var composition orderedDeploymentComposition
	if json.Unmarshal(claim.Composition, &composition) != nil {
		t.Fatal(got)
	}
	for _, source := range composition.TemporarySources {
		if source.RunID == stored["run_id"] && source.StepID == stored["step_id"] {
			t.Fatal("cleanup retained its own source", composition)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires, _ := time.Parse(time.RFC3339Nano, composition.ExpiresAt)
	if len(stages) > 0 && (stages[0] == "short_lived" || stages[0] == "refresh_due") {
		expires = now.Add(75 * time.Second)
	}
	if len(stages) > 0 && stages[0] == "insufficient_margin" {
		expires = now.Add(45 * time.Second)
	}
	envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: claim.OrganizationID, WorkspaceID: claim.WorkspaceID, EnvironmentID: claim.EnvironmentID, DeviceID: claim.DeviceID}, Sequence: uint64(claim.Sequence), PolicyVersion: uint64(claim.PolicyVersion), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: composition.Policies}, key)
	if err != nil {
		t.Fatal(err)
	}
	q["operation"], q["sequence"], q["input_digest"], q["composition"], q["envelope"], q["digest"] = "store", claim.Sequence, claim.InputDigest, claim.Composition, envelope, orderedEnvelopeDigest(envelope)
	if len(stages) > 0 && stages[0] == "claimed" {
		return q, claim
	}
	call()
	call()
	if len(stages) > 0 && stages[0] == "stored" {
		return q, claim
	}
	digest := q["digest"]
	// No finish acknowledgement is accepted without the exact preceding read.
	q["operation"], q["envelope"] = "finish", map[string]any{}
	before := orderedCleanupSnapshot(t, ctx, owner, stored["run_id"].(string))
	if _, err := orderedCleanupDeploymentCall(ctx, connection, q, keys); err == nil || orderedCleanupSnapshot(t, ctx, owner, stored["run_id"].(string)) != before {
		t.Fatal("cleanup finish skipped read acknowledgement", err)
	}
	q["operation"], q["envelope"], q["digest"] = "read", map[string]any{}, ""
	call()
	q["operation"], q["digest"] = "finish", digest
	if len(stages) > 0 && stages[0] == "insufficient_margin" {
		return q, claim
	}
	call()
	call()
	return q, claim
}

func orderedCleanupRequest(o, w, e, r, s, op string, rv, ev, cv int) map[string]any {
	return map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": s, "operation": op, "worker_id": "ordered-cleanup-worker", "lease_token": "ordered-cleanup-lease", "run_version": rv, "effect_version": ev, "version": cv, "lease_seconds": 60, "envelope": map[string]any{}}
}
