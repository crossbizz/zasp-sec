//go:build darwin || linux

package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentMultistepPlanningWorkerProcessPostgres(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	for _, fault := range []string{"exact", "claim", "prepare", "start", "result", "settle", "artifacts", "admit", "input_put", "output_put", "provider_lost", "wire_size", "invalid_utf8", "budget_short", "pricing_short", "pricing_ack", "pricing_runway_ack", "budget_ack", "budget_cancel", "pricing_cancel", "budget_timely", "pricing_timely", "wire_budget_missing", "wire_budget_null", "wire_budget_malformed", "wire_budget_inconsistent", "wire_pricing", "wire_claim_pricing", "cancel_lookup"} {
		t.Run(fault, func(t *testing.T) {
			runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, _ *pgx.Conn, o, w, e, testID, actor string) {
				run := seedOrderedPlanningQueue(t, ctx, owner, o, w, e, testID, actor)
				if fault == "budget_short" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{max_duration_seconds}','20') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`, run); err != nil {
						t.Fatal(err)
					}
				}
				if fault == "budget_ack" || fault == "budget_cancel" || fault == "budget_timely" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{max_duration_seconds}','45') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$1)`, run); err != nil {
						t.Fatal(err)
					}
				}
				config := owner.Config().Copy()
				config.User = "security_agent_v33_discovery_api_login"
				admin, err := pgx.ConnectConfig(ctx, config)
				if err != nil {
					t.Fatal(err)
				}
				defer admin.Close(ctx)
				if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET role='organization_admin' WHERE principal_id=$1; UPDATE zasp_authorized_scopes SET permissions='["view","manage_identity","manage_workflows","run_tests"]' WHERE principal_id=$1`, pgx.QueryExecModeSimpleProtocol, actor); err != nil {
					t.Fatal(err)
				}
				q := orderedPricingAdminRequest(o, w, e, actor)
				p := q["policy"].(map[string]any)
				p["request_token_limit"] = 512
				p["request_policy_version"] = "security-agent-planner-v1"
				h := sha256.Sum256([]byte("sk-or-v1-test-token-1234567890"))
				p["credential_digest"] = "sha256:" + hex.EncodeToString(h[:])
				if fault == "pricing_short" {
					p["expires_at"] = time.Now().UTC().Add(20 * time.Second).Format("2006-01-02T15:04:05.000000Z")
				}
				if fault == "pricing_ack" || fault == "pricing_runway_ack" {
					p["expires_at"] = time.Now().UTC().Add(40 * time.Second).Format("2006-01-02T15:04:05.000000Z")
				}
				if fault == "pricing_cancel" || fault == "pricing_timely" {
					p["expires_at"] = time.Now().UTC().Add(50 * time.Second).Format("2006-01-02T15:04:05.000000Z")
				}
				created, err := orderedPricingCall(ctx, admin, "pricing_admin", q)
				if err != nil {
					t.Fatal(err)
				}
				binding, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "account_profile": p["account_profile"], "credential_reference": p["credential_reference"], "policy_id": created["policy_id"], "policy_version": created["version"], "policy_digest": created["policy_digest"], "account_id": created["account_id"], "account_version": created["account_version"]})
				artifacts := t.TempDir()
				invoke := func(fault, wantCalls string) {
					t.Helper()
					command := exec.Command(binary, "-test.run=^TestSecurityAgentMultistepPlanningOwnedPostgres$", "-test.v", "-test.timeout=90s")
					command.Dir = "../agentsec-worker"
					for _, entry := range os.Environ() {
						if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
							command.Env = append(command.Env, entry)
						}
					}
					command.Env = append(command.Env, "ZASP_ORDERED_PLANNING_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_PLANNING_BINDING="+string(binding), "ZASP_ORDERED_PLANNING_RUN="+run, "ZASP_ORDERED_PLANNING_TEST_ID="+testID, "ZASP_ORDERED_PLANNING_ARTIFACTS="+artifacts)
					command.Env = append(command.Env, "ZASP_ORDERED_PLANNING_FAULT="+fault)
					output, err := runSandboxWorkerCommand(ctx, command)
					if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "owned planning worker joined: provider_calls="+wantCalls) {
						t.Fatalf("owned planning worker: %v\n%s", err, output)
					}
					t.Log(string(output))
				}
				firstFault := fault
				if fault == "exact" {
					firstFault = ""
				}
				firstCalls := "1"
				if fault == "claim" || fault == "prepare" || fault == "start" || fault == "input_put" || strings.HasPrefix(fault, "wire_") || fault == "budget_short" || fault == "pricing_short" || fault == "pricing_ack" || fault == "pricing_runway_ack" || fault == "budget_ack" || fault == "cancel_lookup" {
					firstCalls = "0"
				}
				invoke(firstFault, firstCalls)
				if strings.HasPrefix(fault, "wire_") || fault == "cancel_lookup" {
					var safe bool
					if err = owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations WHERE run_id=$1 AND settled_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1 AND raw_result IS NOT NULL)`, run).Scan(&safe); err != nil || !safe {
						t.Fatal("malformed deadline response acquired result authority", err)
					}
					return
				}
				if fault == "invalid_utf8" || strings.HasSuffix(fault, "_cancel") || strings.HasSuffix(fault, "_ack") {
					var safe bool
					var outputID string
					if err = owner.QueryRow(ctx, `SELECT j.output_artifact_id,j.state='started' AND j.raw_result IS NULL AND j.result_value IS NULL AND j.output_body IS NULL AND j.output_version IS NULL AND r.settled_at IS NULL AND r.total_tokens IS NULL AND r.cost_nano_credits IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans p WHERE p.run_id=j.run_id) FROM zasp_sa_multistep_prior.planning_jobs j JOIN zasp_security_agent_provider_reservations r USING(run_id) WHERE j.run_id=$1`, run).Scan(&outputID, &safe); err != nil || !safe {
						t.Fatal("invalid UTF-8 persisted or admitted normalized result", err)
					}
					if _, err = os.Stat(filepath.Join(artifacts, outputID+".json")); !os.IsNotExist(err) {
						t.Fatal("invalid UTF-8 wrote output artifact", err)
					}
				}
				if fault == "start" || fault == "provider_lost" || fault == "invalid_utf8" || fault == "budget_short" || fault == "pricing_short" || strings.HasSuffix(fault, "_ack") || strings.HasSuffix(fault, "_cancel") {
					invoke("unknown", "0")
					if _, err = owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.planning_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_security_agent_runs SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, run); err != nil {
						t.Fatal(err)
					}
					recovery := map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": run, "worker_id": "reconciler", "lease_token": "private-recovery-lease-0001", "operation": "reconcile", "payload": map[string]any{}}
					job, err := orderedPlanningCall(ctx, worker, recovery)
					if err != nil || job["state"] != "needs_human" {
						t.Fatal("uncertain process did not conservatively recover", err)
					}
					var safe bool
					if err = owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations WHERE run_id=$1 AND settled_at IS NULL)`, run).Scan(&safe); err != nil || !safe {
						t.Fatal("uncertain process fabricated output or usage", err)
					}
					return
				}
				if fault != "exact" {
					resumeCalls := "0"
					if fault == "claim" || fault == "prepare" || fault == "input_put" {
						resumeCalls = "1"
					}
					invoke("", resumeCalls)
				}
				before := orderedAdmissionSnapshot(t, ctx, owner, run)
				invoke("", "0")
				if orderedAdmissionSnapshot(t, ctx, owner, run) != before {
					t.Fatal("process replay changed admission identities")
				}
				var total, cost int64
				if err = owner.QueryRow(ctx, `SELECT total_tokens,cost_nano_credits FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, run).Scan(&total, &cost); err != nil || total != 100 || cost != 500 {
					t.Fatal("worker settlement", err, total, cost)
				}
				if strings.HasSuffix(fault, "_timely") {
					var retained bool
					if err = owner.QueryRow(ctx, `SELECT state='admitted' AND raw_result IS NOT NULL AND result_value->'usage'->>'total_tokens'='100' AND provider_digest='sha256:'||encode(digest(convert_to(raw_result,'UTF8'),'sha256'),'hex') FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1`, run).Scan(&retained); err != nil || !retained {
						t.Fatal("timely exact response/usage not retained", err)
					}
				}
			})
		})
	}
}
