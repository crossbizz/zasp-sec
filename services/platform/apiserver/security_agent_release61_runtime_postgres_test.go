//go:build darwin || linux

package apiserver

import (
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestSecurityAgentRelease61PlanningTicksPostgres(t *testing.T) {
	runRelease61RuntimeTicks(t, false)
}

func TestSecurityAgentRelease61ApplicationTicksPostgres(t *testing.T) {
	runRelease61RuntimeTicks(t, true)
}

func TestSecurityAgentRelease61ExistingTestTicksPostgres(t *testing.T) {
	runRelease61RuntimeTicks(t, true, true)
}

func TestSecurityAgentRelease61LifecycleTicksPostgres(t *testing.T) {
	runRelease61RuntimeTicks(t, true, true, true)
}

func TestSecurityAgentRelease61CommitAckTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, []bool{true, true}, "ack")
}

func TestSecurityAgentRelease61LeaseTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, []bool{true, true}, "leases")
}

func TestSecurityAgentRelease61HeartbeatTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, []bool{true, true}, "heartbeats")
}

func TestSecurityAgentRelease61PlanningUncertaintyTicksPostgres(t *testing.T) {
	for _, mode := range []string{"planning_start_ack", "planning_provider_unknown", "planning_completed_expiry"} {
		t.Run(mode, func(t *testing.T) { runRelease61RuntimeScenario(t, false, nil, mode) })
	}
}

func TestSecurityAgentRelease61JournalTicksPostgres(t *testing.T) {
	for _, mode := range []string{"journal_start", "journal_complete", "journal_start_expiry", "journal_complete_expiry", "journal_start_second", "journal_complete_second"} {
		t.Run(mode, func(t *testing.T) { runRelease61RuntimeScenario(t, true, []bool{true, true}, mode) })
	}
}

func TestSecurityAgentRelease61PartialTicksPostgres(t *testing.T) {
	for _, boundary := range []string{"application_store", "deployment_claim", "deployment_store", "deployment_read", "deployment_finish"} {
		t.Run(boundary, func(t *testing.T) { runRelease61RuntimeScenario(t, true, nil, "cancel_"+boundary) })
	}
}

func TestSecurityAgentRelease61RevocationTicksPostgres(t *testing.T) {
	for _, authority := range []string{"requester", "definition", "credential", "budget", "plan_integrity", "natural_expiry"} {
		t.Run(authority, func(t *testing.T) { runRelease61RuntimeScenario(t, false, nil, "revoke_"+authority) })
	}
}

func TestSecurityAgentRelease61ArtifactTicksPostgres(t *testing.T) {
	for _, boundary := range []string{"input_put", "input_get", "output_put", "output_get"} {
		t.Run(boundary, func(t *testing.T) { runRelease61RuntimeScenario(t, true, []bool{true}, "artifact_"+boundary) })
	}
}

func TestSecurityAgentRelease61DeploymentUncertaintyTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, nil, "unknown_deployment_store")
}

func TestSecurityAgentRelease61CleanupUncertaintyTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, []bool{true, true}, "cleanup_unknown")
}

func TestSecurityAgentRelease61ScopeTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, []bool{true, true}, "cross_tenant")
}

func TestSecurityAgentRelease61MixedTicksPostgres(t *testing.T) {
	runRelease61RuntimeScenario(t, true, []bool{true, true}, "mixed_binary")
}

func TestSecurityAgentRelease61ApplicationDriftTicksPostgres(t *testing.T) {
	for _, mode := range []string{"device", "credential", "generation"} {
		t.Run(mode, func(t *testing.T) { runRelease61RuntimeScenario(t, true, nil, "app_drift_"+mode) })
	}
}

func TestSecurityAgentRelease61StopTickPostgres(t *testing.T) {
	runRelease61RuntimeTicks(t, false, false)
}

func runRelease61RuntimeTicks(t *testing.T, application bool, existingTest ...bool) {
	runRelease61RuntimeScenario(t, application, existingTest, "")
}

func runRelease61RuntimeScenario(t *testing.T, application bool, existingTest []bool, scenario string) {
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := multistepBudgetWorkerBinary(t, buildCtx)
	adapterBinary := filepath.Join(t.TempDir(), "release61-adapter.test")
	build := exec.Command("go", "test", "-c", "-o", adapterBinary, "../redteamadapter")
	if output, err := runSandboxWorkerCommand(buildCtx, build); err != nil {
		t.Fatalf("adapter build: %v %s", err, output)
	}
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		// The setup fixture's two-minute migration deadline is not the budget
		// for thirty separate joined processes. Preserve test cancellation.
		exerciseBudget := 4 * time.Minute
		if scenario == "cross_tenant" {
			exerciseBudget = 6 * time.Minute
		}
		ctx, exerciseCancel := context.WithTimeout(t.Context(), exerciseBudget)
		defer exerciseCancel()
		action := orderedActionFenceConnection(t, ctx, owner)
		action.Close(ctx)
		deployment := orderedApplicationDeploymentConnection(t, ctx, owner)
		deployment.Close(ctx)
		red, adapter := orderedTestConnections(t, ctx, owner)
		red.Close(ctx)
		adapter.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		const foreign = "pid_8f000002-0000-4000-8000-000000000001"
		if scenario == "cross_tenant" {
			seedOrderedApplicationGatewayAt(t, ctx, owner, foreign, w, e, foreign)
		}
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		if strings.HasSuffix(scenario, "_second") {
			if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET categories='["prompt_injection","tool_abuse"]' WHERE organization_id=$1 AND definition_id=$2`, o, testID); err != nil {
				t.Fatal(err)
			}
		}
		r, binding := release61PreflightQueue(t, ctx, owner, o, w, e, testID, actor)
		if scenario == "revoke_natural_expiry" {
			if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{max_duration_seconds}','60') WHERE organization_id=$1 AND definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$2)`, o, r); err != nil {
				t.Fatal(err)
			}
		}
		artifacts := t.TempDir()
		workerToken := strings.Repeat("a", 32)
		var tick func(string, ...string)
		tick = func(want string, extra ...string) {
			if scenario == "mixed_binary" && (want == "planning_claim" || want == "application_store" || want == "test_settle" || want == "cleanup_complete" || want == "terminal") {
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				tick("mixed_refused", "ZASP_RELEASE61_STALE_PIN=1", "ZASP_RELEASE61_EXPECT_REFUSAL=1")
				if before != orderedCleanupSnapshot(t, ctx, owner, r) {
					t.Fatal("mixed binary altered ordered state")
				}
			}
			if scenario == "cross_tenant" && want != "scope_refused" {
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				tick("scope_refused", "ZASP_RELEASE61_FOREIGN_ORG="+foreign)
				if before != orderedCleanupSnapshot(t, ctx, owner, r) {
					t.Fatal("foreign runtime altered another tenant")
				}
			}
			command := exec.Command(binary, "-test.run=^TestSecurityAgentRelease61OwnedTick$", "-test.v", "-test.timeout=90s")
			command.Dir = "../agentsec-worker"
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "ZASP_") && !strings.HasPrefix(entry, "PG") {
					command.Env = append(command.Env, entry)
				}
			}
			command.Env = append(command.Env, "ZASP_ORDERED_PLANNING_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_PLANNING_BINDING="+binding, "ZASP_ORDERED_PLANNING_RUN="+r, "ZASP_ORDERED_PLANNING_TEST_ID="+testID, "ZASP_ORDERED_PLANNING_ARTIFACTS="+artifacts, "ZASP_RELEASE61_EXPECT="+want)
			command.Env = append(command.Env, "ZASP_RELEASE61_ADAPTER_BINARY="+adapterBinary)
			command.Env = append(command.Env, "ZASP_RELEASE61_WORKER_TOKEN="+workerToken)
			if strings.HasPrefix(scenario, "cancel_") || strings.HasPrefix(scenario, "unknown_deployment_") || scenario == "cleanup_unknown" {
				command.Env = append(command.Env, "ZASP_RELEASE61_DEPLOYMENT_LEASE=30s")
			}
			command.Env = append(command.Env, extra...)
			if strings.HasSuffix(scenario, "_second") {
				command.Env = append(command.Env, "ZASP_RELEASE61_JOURNAL_CATEGORY=tool_abuse")
			}
			if scenario == "ack" && want != "approval_pause" && want != "terminal" {
				command.Env = append(command.Env, "ZASP_RELEASE61_ACK_FAULT="+want)
			}
			output, err := runSandboxWorkerCommand(ctx, command)
			if err != nil || strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "release61 tick joined: "+want) {
				t.Fatalf("actual restart tick %s: %v\n%s", want, err, output)
			}
			t.Log(string(output))
		}
		if strings.HasPrefix(scenario, "planning_") {
			tick("planning_claim")
			tick("planning_prepare")
			switch scenario {
			case "planning_start_ack":
				tick("planning_start", "ZASP_RELEASE61_ACK_FAULT=planning_start")
				tick("uncertain_wait")
			case "planning_provider_unknown":
				tick("planning_result_unknown", "ZASP_RELEASE61_PROVIDER_UNKNOWN=1")
				tick("uncertain_wait")
			case "planning_completed_expiry":
				tick("planning_result")
			}
			if _, err := owner.Exec(ctx, `UPDATE zasp_sa_multistep_prior.planning_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_security_agent_runs SET lease_expires_at=(SELECT lease_expires_at FROM zasp_sa_multistep_prior.planning_jobs WHERE run_id=$1) WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
				t.Fatal(err)
			}
			tick("planning_reconcile")
			tick("terminal")
			tick("terminal")
			var safe bool
			if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.admissions WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_steps WHERE run_id=$1) FROM zasp_security_agent_runs r WHERE run_id=$1`, r).Scan(&safe); err != nil || !safe {
				t.Fatal("planning uncertainty became execution", safe, err)
			}
			return
		}
		for _, want := range []string{"planning_claim", "planning_prepare", "planning_result", "planning_settle", "planning_artifacts", "planning_admit", "approval_pause", "approval_pause"} {
			tick(want)
		}
		var exact bool
		if err := owner.QueryRow(ctx, `SELECT r.state='waiting_approval' AND count(s.step_id)=2 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 GROUP BY r.state`, r).Scan(&exact); err != nil || !exact {
			t.Fatal("planning ticks bypassed approval", exact, err)
		}
		if !application {
			if strings.HasPrefix(scenario, "revoke_") {
				query := map[string]string{
					"revoke_requester":      `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$2)`,
					"revoke_definition":     `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE organization_id=$1 AND definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$2)`,
					"revoke_credential":     `UPDATE zasp_attack_lab_credential_bindings SET state='revoked' WHERE organization_id=$1 AND environment_id=(SELECT environment_id FROM zasp_security_agent_runs WHERE run_id=$2)`,
					"revoke_budget":         `UPDATE zasp_security_agent_run_budgets SET deadline_at=started_at+interval '1 microsecond' WHERE organization_id=$1 AND run_id=$2`,
					"revoke_plan_integrity": `WITH expired AS(UPDATE zasp_security_agent_plans SET expires_at=created_at+interval '1 microsecond' WHERE organization_id=$1 AND run_id=$2 RETURNING expires_at) UPDATE zasp_security_agent_approvals SET expires_at=(SELECT expires_at FROM expired) WHERE organization_id=$1 AND run_id=$2`,
				}[scenario]
				if scenario == "revoke_natural_expiry" {
					var expiry time.Time
					if err := owner.QueryRow(ctx, `SELECT expires_at FROM zasp_security_agent_plans WHERE run_id=$1`, r).Scan(&expiry); err != nil || time.Until(expiry) > 60*time.Second {
						t.Fatal("natural expiry absent", err)
					}
					timer := time.NewTimer(time.Until(expiry) + 10*time.Millisecond)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						t.Fatal(ctx.Err())
					}
				} else if _, err := owner.Exec(ctx, query, o, r); err != nil {
					t.Fatal(err)
				}
				if scenario == "revoke_plan_integrity" {
					before := orderedCleanupSnapshot(t, ctx, owner, r)
					tick("integrity_refused", "ZASP_RELEASE61_EXPECT_REFUSAL=1")
					if before != orderedCleanupSnapshot(t, ctx, owner, r) {
						t.Fatal("integrity refusal changed state")
					}
					return
				}
				tick("stopped")
				tick("terminal")
				tick("terminal")
				if err := owner.QueryRow(ctx, `SELECT state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_audit WHERE run_id=$1 AND body->'response'->>'outcome'='blocked') FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&exact); err != nil || !exact {
					t.Fatal("revocation did not durably stop", exact, err)
				}
			}
			if len(existingTest) > 0 {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3`, o, w, e); err != nil {
					t.Fatal(err)
				}
				tick("stopped")
			}
			return
		}
		var step string
		var rv int
		if err := owner.QueryRow(ctx, `SELECT s.step_id,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND s.step_index=0`, r).Scan(&step, &rv); err != nil {
			t.Fatal(err)
		}
		if _, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, step, "approve", orderedProgressionApprover, rv)); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"application_claim", "application_store", "deployment_claim", "deployment_store", "deployment_read", "deployment_finish", "application_complete", "successor_ready", "approval_pause", "approval_pause"} {
			tick(want)
			if want == "application_store" && strings.HasPrefix(scenario, "app_drift_") {
				query := map[string]string{
					"app_drift_device":     `UPDATE zasp_gateway_devices SET state='revoked',revoked_at=clock_timestamp(),version=version+1 WHERE organization_id=$1 AND id=$2`,
					"app_drift_credential": `UPDATE zasp_gateway_credentials SET revoked_at=clock_timestamp() WHERE organization_id=$1 AND device_id=$2`,
					"app_drift_generation": `UPDATE zasp_policy_deployment_work SET desired_generation=desired_generation+1 WHERE organization_id=$1 AND device_id=$2`,
				}[scenario]
				if _, err := owner.Exec(ctx, query, o, orderedApplicationDevice); err != nil {
					t.Fatal(err)
				}
				tick("stopped")
				if err := owner.QueryRow(ctx, `SELECT state='needs_human' AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='run_test') AND EXISTS(SELECT 1 FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND phase='apply' AND state='stored') FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&exact); err != nil || !exact {
					t.Fatal("application drift erased uncertainty", exact, err)
				}
				return
			}
			if scenario == "cancel_"+want || scenario == "unknown_"+want {
				if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&rv); err != nil {
					t.Fatal(err)
				}
				terminal := "needs_human"
				if strings.HasPrefix(scenario, "cancel_") {
					q := orderedProgressionRequest(o, w, e, r, step, "cancel", orderedProgressionApprover, rv)
					q["approval_version"] = 2
					if _, err := orderedProgressionCall(ctx, api, "transition", q); err != nil {
						t.Fatal("actual partial cancellation", err)
					}
					terminal = "cancelled"
				}
				if want == "deployment_claim" || want == "deployment_store" || want == "deployment_read" {
					var expiry time.Time
					if err := owner.QueryRow(ctx, `SELECT d.lease_expires_at FROM zasp_policy_deployment_work d JOIN zasp_security_agent_temporary_policy_targets t USING(organization_id,workspace_id,environment_id,device_id) WHERE t.run_id=$1 AND t.phase='apply'`, r).Scan(&expiry); err != nil || time.Until(expiry) > 30*time.Second || !expiry.After(time.Now()) {
						t.Fatal("configured genuine deployment deadline unavailable", err)
					}
					tick("lease_wait", "ZASP_RELEASE61_DELIVERY_TOKEN="+strings.Repeat("d", 32))
					timer := time.NewTimer(time.Until(expiry) + 10*time.Millisecond)
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						t.Fatal(ctx.Err())
					}
				}
				if strings.HasPrefix(scenario, "unknown_") {
					tick("stopped")
				}
				for _, next := range []string{"cleanup_claim", "cleanup_store", "cleanup_deployment_claim", "cleanup_deployment_store", "cleanup_deployment_read", "cleanup_deployment_finish", "cleanup_complete", "terminal", "terminal"} {
					tick(next)
				}
				if err := owner.QueryRow(ctx, `SELECT state=$2 AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_receipts WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='run_test') AND (SELECT count(*) FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1 AND receipt_kind='temporary_policy_partial_cleaned.v1')=1 FROM zasp_security_agent_runs WHERE run_id=$1`, r, terminal).Scan(&exact); err != nil || !exact {
					t.Fatal("partial cleanup manufactured success", exact, err)
				}
				return
			}
			if scenario == "leases" && want == "application_claim" {
				tick("lease_wait", "ZASP_RELEASE61_WORKER_TOKEN="+strings.Repeat("c", 32))
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='create_temporary_policy'`, r); err != nil {
					t.Fatal(err)
				}
				workerToken = strings.Repeat("c", 32)
				tick("application_claim")
			}
			if scenario == "leases" && want == "deployment_claim" {
				tick("lease_wait", "ZASP_RELEASE61_DELIVERY_TOKEN="+strings.Repeat("d", 32))
			}
			if scenario == "heartbeats" && want == "application_claim" {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE run_id=$1 AND action_key='create_temporary_policy'`, r); err != nil {
					t.Fatal(err)
				}
				tick("application_heartbeat")
			}
		}
		if err := owner.QueryRow(ctx, `SELECT r.state='waiting_approval' AND s.state='waiting_approval' AND (SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND receipt_kind='temporary_policy_applied.v1')=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='run_test') FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND s.step_index=1`, r).Scan(&exact); err != nil || !exact {
			t.Fatal("application tick lost successor approval gate", exact, err)
		}
		if len(existingTest) == 0 {
			return
		}
		if err := owner.QueryRow(ctx, `SELECT s.step_id,r.version FROM zasp_security_agent_runs r JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1 AND s.step_index=1`, r).Scan(&step, &rv); err != nil {
			t.Fatal(err)
		}
		if _, err := orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, step, "approve", orderedProgressionApprover, rv)); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"test_claim", "test_dispatch", "test_settle"} {
			var beforeArtifacts string
			if want == "test_settle" && strings.HasPrefix(scenario, "artifact_output_") || want == "test_dispatch" && strings.HasPrefix(scenario, "artifact_input_") {
				tick("test_artifact_fault", "ZASP_RELEASE61_ARTIFACT_FAULT="+strings.TrimPrefix(scenario, "artifact_"))
				beforeArtifacts = release61ArtifactSnapshot(t, artifacts)
			}
			if want == "test_settle" && strings.HasPrefix(scenario, "journal_") {
				fault := "start"
				if strings.HasPrefix(scenario, "journal_complete") {
					fault = "complete"
				}
				tick("test_journal_fault", "ZASP_RELEASE61_JOURNAL_FAULT="+fault)
				if strings.HasSuffix(scenario, "_expiry") {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test'; UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
						t.Fatal(err)
					}
					workerToken = strings.Repeat("e", 32)
					tick("test_reconcile")
					break
				}
				if fault == "start" {
					tick("test_uncertain")
					break
				}
			}
			tick(want)
			if beforeArtifacts != "" && beforeArtifacts != release61ArtifactSnapshot(t, artifacts) {
				t.Fatal("reconstruction changed immutable artifact identity or digest")
			}
			if scenario == "leases" && want == "test_claim" {
				tick("lease_wait", "ZASP_RELEASE61_WORKER_TOKEN="+strings.Repeat("e", 32))
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test'`, r); err != nil {
					t.Fatal(err)
				}
				workerToken = strings.Repeat("e", 32)
				tick("test_claim")
			}
			if scenario == "heartbeats" && want == "test_dispatch" {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE run_id=$1 AND action_key='run_test'; UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
					t.Fatal(err)
				}
				tick("test_heartbeat")
			}
		}
		expectedReceipts := 1
		if strings.HasPrefix(scenario, "journal_") && (!strings.HasPrefix(scenario, "journal_complete") || strings.HasSuffix(scenario, "_expiry")) {
			expectedReceipts = 0
		}
		if err := owner.QueryRow(ctx, `SELECT count(*)=$2 FROM zasp_sa_multistep_receipts WHERE run_id=$1 AND receipt_kind='existing_test_settled.v1'`, r, expectedReceipts).Scan(&exact); err != nil || !exact {
			t.Fatal("test ticks lacked verified private settlement", exact, err)
		}
		if len(existingTest) < 2 {
			return
		}
		for _, want := range []string{"cleanup_claim", "cleanup_store", "cleanup_deployment_claim", "cleanup_deployment_store", "cleanup_deployment_read", "cleanup_deployment_finish", "cleanup_complete", "terminal", "terminal"} {
			tick(want)
			if scenario == "cleanup_unknown" && want == "cleanup_deployment_store" {
				var expiry time.Time
				if err := owner.QueryRow(ctx, `SELECT lease_expires_at FROM zasp_policy_deployment_work WHERE organization_id=$1 AND environment_id=$2`, o, e).Scan(&expiry); err != nil || time.Until(expiry) > 30*time.Second {
					t.Fatal("cleanup deployment expiry absent", err)
				}
				timer := time.NewTimer(time.Until(expiry) + 10*time.Millisecond)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					t.Fatal(ctx.Err())
				}
				// Negative owned-cleanup clock injection only; deployment lease,
				// claim/store audits and immutable bundle remain untouched.
				if _, err := owner.Exec(ctx, `WITH expiry AS(SELECT clock_timestamp()+interval '30 seconds' AS deadline),updated AS(UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=(SELECT deadline FROM expiry) WHERE run_id=$1 RETURNING lease_expires_at) UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM updated) WHERE run_id=$1 AND action_key='create_temporary_policy'`, r); err != nil {
					t.Fatal(err)
				}
				before := orderedCleanupSnapshot(t, ctx, owner, r)
				tick("lease_wait")
				if before != orderedCleanupSnapshot(t, ctx, owner, r) {
					t.Fatal("unknown cleanup delivery renewed ownership")
				}
				if _, err := owner.Exec(ctx, `WITH expiry AS(SELECT clock_timestamp()-interval '1 second' AS deadline),updated AS(UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=(SELECT deadline FROM expiry) WHERE run_id=$1 RETURNING lease_expires_at) UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM updated) WHERE run_id=$1 AND action_key='create_temporary_policy'`, r); err != nil {
					t.Fatal(err)
				}
				tick("cleanup_reconcile")
				before = orderedCleanupSnapshot(t, ctx, owner, r)
				tick("cleanup_requires_review", "ZASP_RELEASE61_EXPECT_REFUSAL=1")
				tick("cleanup_requires_review", "ZASP_RELEASE61_EXPECT_REFUSAL=1")
				if before != orderedCleanupSnapshot(t, ctx, owner, r) {
					t.Fatal("unknown cleanup replay changed evidence")
				}
				if err := owner.QueryRow(ctx, `SELECT r.state='needs_human' AND c.state='retryable' AND c.reason='unknown_call' AND NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_sa_multistep_prior.cleanups c USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, r).Scan(&exact); err != nil || !exact {
					t.Fatal("cleanup uncertainty hidden", exact, err)
				}
				return
			}
			if scenario == "leases" && want == "cleanup_claim" {
				tick("lease_wait", "ZASP_RELEASE61_WORKER_TOKEN="+strings.Repeat("f", 32))
				if _, err := owner.Exec(ctx, `WITH expiry AS(SELECT clock_timestamp()-interval '1 second' AS deadline),updated AS(UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=(SELECT deadline FROM expiry) WHERE run_id=$1 RETURNING lease_expires_at) UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM updated) WHERE run_id=$1 AND action_key='create_temporary_policy'`, r); err != nil {
					t.Fatal(err)
				}
				workerToken = strings.Repeat("f", 32)
				tick("cleanup_reconcile")
				tick("cleanup_claim")
			}
			if scenario == "heartbeats" && want == "cleanup_claim" {
				if _, err := owner.Exec(ctx, `WITH expiry AS(SELECT clock_timestamp()+interval '30 seconds' AS deadline),updated AS(UPDATE zasp_sa_multistep_prior.cleanups SET lease_expires_at=(SELECT deadline FROM expiry) WHERE run_id=$1 RETURNING lease_expires_at) UPDATE zasp_security_agent_effects SET lease_expires_at=(SELECT lease_expires_at FROM updated) WHERE run_id=$1 AND action_key='create_temporary_policy'`, r); err != nil {
					t.Fatal(err)
				}
				tick("cleanup_heartbeat")
			}
		}
		terminal := "remediated"
		if scenario == "leases" || expectedReceipts == 0 {
			terminal = "needs_human"
		}
		if err := owner.QueryRow(ctx, `SELECT r.state=$2 AND (SELECT count(*) FROM zasp_sa_multistep_prior.cleanup_receipts WHERE run_id=$1 AND receipt_kind='temporary_policy_cleaned.v1')=1 AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 AND lease_token IS NOT NULL) FROM zasp_security_agent_runs r WHERE run_id=$1`, r, terminal).Scan(&exact); err != nil || !exact {
			t.Fatal("runtime lacked terminal cleanup receipt", exact, err)
		}
	})
}

func release61ArtifactSnapshot(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("unexpected artifact directory")
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte(entry.Name()))
		h.Write([]byte{0})
		h.Write(body)
	}
	return string(h.Sum(nil))
}
