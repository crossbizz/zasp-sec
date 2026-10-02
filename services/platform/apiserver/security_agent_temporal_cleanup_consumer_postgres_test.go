package apiserver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTemporalWorkflowCleanupConsumersPostgres(t *testing.T) {
	for _, mode := range []string{"rotated_source", "expired_replacement", "changed_replacement"} {
		t.Run(mode, func(t *testing.T) {
			runTemporalExecutorPolicyFixture(t, true, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, run, step string, keys policy.GatewayPolicyKeys, key ed25519.PrivateKey, call func(*pgx.Conn, string, string, any) (map[string]any, error)) {
				if err := precisionMigrationRunner(t, owner).UpProductionTemporalWorkflow(ctx); err != nil {
					t.Fatal(err)
				}
				cfg := owner.Config().Copy()
				cfg.User = "temporal_compensation_test_login"
				comp, err := pgx.ConnectConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer comp.Close(ctx)
				if _, err := call(comp, "cleanup", "prepare", map[string]any{}); err != nil {
					t.Fatal(err)
				}
				claim, err := call(comp, "cleanup", "read", map[string]any{})
				if err != nil {
					t.Fatal(err)
				}
				target := claim["targets"].([]any)[0].(map[string]any)
				now := time.Now().UTC().Truncate(time.Second)
				if mode == "rotated_source" {
					now = now.Add(-4*time.Minute - 52*time.Second)
				}
				if mode == "expired_replacement" { now=now.Add(-4*time.Minute-30*time.Second) }
				signed := postgresTemporaryPolicyEnvelope(t, TemporaryPolicyEffectClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, Phase: "cleanup"}, TemporaryPolicyTarget{DeviceID: target["device_id"].(string), CredentialID: target["credential_id"].(string), Sequence: int64(target["sequence"].(float64)), PolicyVersion: int64(target["policy_version"].(float64))}, "ordered-key-01", key, now, now.Add(5*time.Minute), []policy.CompiledPolicy{})
				source := map[string]any{"device_id": target["device_id"], "credential_id": target["credential_id"], "sequence": target["sequence"], "policy_version": target["policy_version"], "key_id": signed.KeyID, "issued_at": signed.IssuedAt, "expires_at": signed.ExpiresAt, "failure_mode": signed.FailureMode, "payload_digest": signed.PayloadDigest, "policies": signed.Policies, "signature": base64.StdEncoding.EncodeToString(signed.Signature), "envelope_digest": signed.EnvelopeDigest}
				if _, err := call(comp, "cleanup", "source", source); err != nil {
					t.Fatal(err)
				}
				deadline := signed.ExpiresAt
				if mode != "rotated_source" {
					payload := map[string]any{"device_id": target["device_id"], "phase": "cleanup"}
					delivery, err := call(comp, "delivery", "prepare", payload)
					if err != nil {
						t.Fatal(err)
					}
					composition := delivery["composition"].(map[string]any)
					encoded, _ := json.Marshal(composition["policies"])
					var policies []policy.CompiledPolicy
					json.Unmarshal(encoded, &policies)
					expires, err := time.Parse(time.RFC3339Nano, composition["expires_at"].(string))
					if err != nil {
						t.Fatal(err)
					}
					if mode == "expired_replacement" {
						expires = time.Now().UTC().Truncate(time.Second).Add(65 * time.Second)
					}
					envelope, err := policy.SignGatewayPolicyEnvelope(policy.GatewayPolicySigningInput{KeyID: "ordered-key-01", Binding: policy.GatewayPolicyBinding{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, DeviceID: target["device_id"].(string)}, Sequence: uint64(delivery["sequence"].(float64)), PolicyVersion: uint64(delivery["sequence"].(float64)), Now: now, IssuedAt: now, ExpiresAt: expires, FailureMode: "closed", Policies: policies}, key)
					if err != nil {
						t.Fatal(err)
					}
					payload["envelope"], payload["digest"] = envelope, orderedEnvelopeDigest(envelope)
					if _, err := call(comp, "delivery", "store", payload); err != nil {
						t.Fatal(err)
					}
					delete(payload, "envelope")
					if _, err := call(comp, "delivery", "read", payload); err != nil {
						t.Fatal(err)
					}
					if _, err := call(comp, "delivery", "ack", payload); err != nil {
						t.Fatal(err)
					}
					deadline = expires
					if mode == "changed_replacement" {
						body := `{"id":"pid_79000001-0000-4000-8000-000000000001","name":"Unrelated persistent policy","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"preserve-me"}],"action":"monitor","rollout":"enforced","failure_mode":"closed"}`
						if _, err := owner.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,id,kind,version,body) VALUES($1,$2,$3,'pid_79000001-0000-4000-8000-000000000001','policy',1,$4::jsonb); SELECT zasp_policy_deployment_enqueue_device($1,$2,$3,$5)`, pgx.QueryExecModeSimpleProtocol, o, w, e, body, target["device_id"]); err != nil {
							t.Fatal(err)
						}
						deadline = time.Now()
					}
				}
				var sources, bundles []byte
				if err := owner.QueryRow(ctx, `SELECT (SELECT jsonb_agg(to_jsonb(t)-ARRAY['state','verified_at'] ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(b) ORDER BY sequence) FROM zasp_runtime_gateway_policy_bundles b WHERE device_id=$2)`, run, target["device_id"]).Scan(&sources, &bundles); err != nil {
					t.Fatal(err)
				}
				if delay := time.Until(deadline.Add(20 * time.Millisecond)); delay > 0 {
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Done():
						timer.Stop()
						t.Fatal(ctx.Err())
					case <-timer.C:
					}
				}
				var digest string
				if err := owner.QueryRow(ctx, `SELECT input_digest FROM zasp_temporal65.commands WHERE run_id=$1 AND kind='start'`, run).Scan(&digest); err != nil {
					t.Fatal(err)
				}
				start, _ := json.Marshal(orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, RunID: run}, DefinitionVersion: 2, InputDigest: digest})
				command := exec.CommandContext(ctx, "go", "test", "./agentsec-worker", "-run", "^TestTemporalOwnedCleanup$", "-count=1", "-v")
				command.Dir = ".."
				command.WaitDelay = 5 * time.Second
				command.Env = append(os.Environ(), "ZASP_TEMPORAL_CLEANUP_DSN="+owner.Config().ConnString(), "ZASP_TEMPORAL_CLEANUP_START="+string(start))
				output, err := command.CombinedOutput()
				t.Log(string(output))
				if err != nil || !strings.Contains(string(output), "--- PASS: TestTemporalOwnedCleanup") || strings.Contains(string(output), "--- SKIP:") {
					t.Fatal("actual cleanup consumer", err)
				}
				var unchanged bool
				if err := owner.QueryRow(ctx, `SELECT (SELECT jsonb_agg(to_jsonb(t)-ARRAY['state','verified_at'] ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1)=$2::jsonb AND (SELECT count(*) FROM zasp_temporal68.effects WHERE run_id=$1)=1 AND EXISTS(SELECT 1 FROM zasp_temporal68.effects WHERE run_id=$1 AND state='cleaned') AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements($3::jsonb) old WHERE NOT EXISTS(SELECT 1 FROM zasp_runtime_gateway_policy_bundles b WHERE to_jsonb(b)=old))`, run, sources, bundles).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("cleanup rewrote immutable sources/effect/history", unchanged, err)
				}
				if err:=owner.QueryRow(ctx,`SELECT bool_and(state='verified' AND verified_at IS NOT NULL) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND phase='cleanup'`,run).Scan(&unchanged);err!=nil||!unchanged{t.Fatal("expected verified target projection",unchanged,err)}
				t.Log("actual cleanup consumer", mode, "retained original sources, effects and signed history")
			})
		})
	}
}
