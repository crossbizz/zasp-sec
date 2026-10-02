package apiserver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentMultistepTestDispatchPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false)
}

func TestSecurityAgentMultistepTestSettlementPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true)
}

func TestSecurityAgentMultistepTestDispatchedLeasePostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "heartbeat")
}

func TestSecurityAgentMultistepTestDispatchedRecoveryPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "recovery")
}

func TestSecurityAgentMultistepTestUnknownPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "unknown")
}

func TestSecurityAgentMultistepTestEvidencePostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "evidence")
}

func TestSecurityAgentMultistepTestReproducedPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "reproduced")
}

func TestSecurityAgentMultistepTestMixedPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "mixed")
}

func TestSecurityAgentMultistepTestBoundsPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "bounds")
}

func TestSecurityAgentMultistepTestSettlementWaitPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "settlement_wait")
}

func TestSecurityAgentMultistepTestCancellationPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "cancel")
}

func TestSecurityAgentMultistepTestExpiredUnknownPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "expired_unknown")
}

func TestSecurityAgentMultistepTestExpiredCompletedPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "expired_completed")
}

func TestSecurityAgentMultistepTestExpiryRacePostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "expiry_race")
}
func TestSecurityAgentMultistepTestExpiryStopPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "expiry_stop")
}
func TestSecurityAgentMultistepTestExpiryCancelPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "expiry_cancel")
}
func TestSecurityAgentMultistepTestExpirySettlementPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "expiry_settlement")
}

func TestSecurityAgentMultistepTestExpiryCompletedRacePostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "expiry_completed_race")
}
func TestSecurityAgentMultistepTestExpiryCompletedStopPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "expiry_completed_stop")
}
func TestSecurityAgentMultistepTestExpiryCompletedCancelPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, true, "expiry_completed_cancel")
}

func TestSecurityAgentMultistepTestExpiryNoJournalPostgres(t *testing.T) {
	exerciseOrderedTestDispatch(t, false, "expiry_no_journal")
}

func exerciseOrderedTestDispatch(t *testing.T, settle bool, modes ...string) {
	exerciseOrderedTestDispatchWithCleanup(t, settle, nil, modes...)
}

func exerciseOrderedTestDispatchWithCleanup(t *testing.T, settle bool, cleanup func(context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn, *pgx.Conn, string, string, string, string, []string), modes ...string) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		seedOrderedApplicationGateway(t, ctx, owner, o, w, e)
		seedOrderedTestSource(t, ctx, owner, o, w, e, actor)
		mode := ""
		if len(modes) > 0 {
			mode = modes[0]
		}
		if mode == "cleanup_many" {
			seedOrderedApplicationGatewayAt(t, ctx, owner, o, w, e, "pid_8f000008-0000-4000-8000-000000000008")
		}
		completedExpiry := mode == "expired_completed" || strings.HasPrefix(mode, "expiry_completed_")
		if mode == "mixed" || completedExpiry {
			if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET categories='["prompt_injection","tool_abuse"]' WHERE definition_id=$1`, testID); err != nil {
				t.Fatal(err)
			}
		}
		redWorker, adapter := orderedTestConnections(t, ctx, owner)
		defer redWorker.Close(ctx)
		defer adapter.Close(ctx)
		var sourceLifetime []time.Duration
		if mode == "cleanup_application_expiry" {
			sourceLifetime = []time.Duration{45 * time.Second}
		}
		r, steps := seedOrderedTestPredecessor(t, ctx, owner, worker, api, action, o, w, e, testID, actor, 902, sourceLifetime...)
		request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 8, 0)
		request["lease_token"] = strings.Repeat("a", 32)
		claim, err := orderedProgressionCall(ctx, worker, "test_action", request)
		if err != nil {
			t.Fatal(err)
		}
		store, inputArtifact := orderedTestInputArtifact(t, ctx, owner, o, w, e, r, steps[1], claim["test_run_id"].(string), testID)
		if mode == "bounds" {
			inputArtifact = orderedTestPadArtifact(t, ctx, store, o, w, e, r, steps[1], inputArtifact, 65536, true)
		}
		database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: redWorker})
		boundary, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
			testDispatch(context.Context, json.RawMessage, artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error)
		})
		if !ok {
			t.Fatal("private artifact-bound test dispatch repository absent")
		}
		dispatchRequest := orderedTestActionRequest(o, w, e, r, steps[1], "dispatch", 9, 1)
		dispatchRequest["payload"] = map[string]any{"input_artifact": inputArtifact}
		dispatchRaw, _ := json.Marshal(dispatchRequest)
		var result json.RawMessage
		if result, err = boundary.testDispatch(ctx, dispatchRaw, store); err != nil {
			t.Fatal("private pinned successor dispatch absent", err)
		}
		var got map[string]any
		if json.Unmarshal(result, &got) != nil || got["test_run_id"] != claim["test_run_id"] || got["attempt"] != float64(1) || got["state"] != "leased" {
			t.Fatal("dispatch postconditions", string(result))
		}
		before := orderedTestSnapshot(t, ctx, owner, r)
		var replay json.RawMessage
		if replay, err = boundary.testDispatch(ctx, dispatchRaw, store); err != nil || string(replay) != string(result) || orderedTestSnapshot(t, ctx, owner, r) != before {
			t.Fatal("dispatch replay changed invocation identity", string(replay), err)
		}
		if mode == "expiry_no_journal" {
			if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test';UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(map[string]any{"organization_id": o, "workspace_id": w, "environment_id": e, "run_id": r, "step_id": steps[1], "operation": "reconcile_uncertain", "worker_id": "ordered-test-reconciler", "run_version": 9, "effect_version": 1})
			db, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
			before := orderedTestSnapshot(t, ctx, owner, r)
			if _, err := (&securityAgentMultistepAdmissionRepository{database: db}).testReconcileUncertain(ctx, raw); err == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("expiry reconciler manufactured provider uncertainty", err)
			}
			return
		}
		lease := strings.Repeat("a", 32)
		if mode == "recovery" {
			if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test';UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
				t.Fatal(err)
			}
			request := orderedTestActionRequest(o, w, e, r, steps[1], "claim", 9, 1)
			request["lease_token"] = strings.Repeat("b", 32)
			recovered, err := orderedTestActionCall(ctx, worker, request)
			if err != nil || recovered["attempt"] != float64(2) || recovered["test_run_id"] != claim["test_run_id"] || recovered["reservation_id"] != claim["reservation_id"] {
				t.Fatal("dispatched recovery changed identity", recovered, err)
			}
			lease = strings.Repeat("b", 32)
			dispatchRequest["run_version"], dispatchRequest["effect_version"], dispatchRequest["lease_token"] = 10, 2, lease
			dispatchRaw, _ = json.Marshal(dispatchRequest)
			if _, err = boundary.testDispatch(ctx, dispatchRaw, store); err != nil {
				t.Fatal("recovered dispatch absent", err)
			}
		}
		if mode == "heartbeat" {
			beat, err := orderedTestActionCall(ctx, worker, orderedTestActionRequest(o, w, e, r, steps[1], "heartbeat", 9, 1))
			if err != nil || beat["effect_version"] != float64(2) || beat["attempt"] != float64(1) {
				t.Fatal("dispatched successor heartbeat absent", beat, err)
			}
			var bound bool
			if err = owner.QueryRow(ctx, `SELECT c.lease_expires_at=f.lease_expires_at AND c.attempt=f.attempt FROM zasp_red_team_runs c JOIN zasp_security_agent_test_links l ON l.test_run_id=c.run_id JOIN zasp_security_agent_effects f ON (f.run_id,f.step_id)=(l.run_id,l.step_id) WHERE l.run_id=$1`, r).Scan(&bound); err != nil || !bound {
				t.Fatal("heartbeat failed to renew exact child", bound, err)
			}
		}
		if err = adapter.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_invocation_resolve($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, o, w, e, "pid_89000011-0000-4000-8000-000000000001", "agent_endpoint", claim["test_run_id"], []byte(lease), "prompt_injection", migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&result); err != nil {
			t.Fatal("private pinned invocation resolution absent", err)
		}
		if json.Unmarshal(result, &got) != nil || got["target_id"] != "pid_89000011-0000-4000-8000-000000000001" {
			t.Fatal("resolution association", string(result))
		}
		runOrderedJournalHTTPS(t, ctx, owner, o, w, e, claim["test_run_id"].(string), mode == "unknown" || mode == "expired_unknown" || strings.HasPrefix(mode, "expiry_") && mode != "expiry_settlement" && !completedExpiry, mode == "reproduced", mode == "mixed" || completedExpiry)
		if mode == "expired_unknown" {
			orderedTestExpiredUnknown(t, ctx, owner, worker, redWorker, o, w, e, r, steps[1])
			return
		}
		if mode == "expired_completed" {
			artifact := orderedTestOutputArtifact(t, ctx, owner, store, o, w, e, r, steps[1], claim["test_run_id"].(string), inputArtifact)
			scope, _ := orderedTestScope(o, w, e, r, steps[1])
			before, err := orderedTestReadArtifact(ctx, store, scope, claim["test_run_id"].(string), artifact, 1048576)
			if err != nil {
				t.Fatal(err)
			}
			orderedTestExpiredUnknown(t, ctx, owner, worker, redWorker, o, w, e, r, steps[1], true)
			after, err := orderedTestReadArtifact(ctx, store, scope, claim["test_run_id"].(string), artifact, 1048576)
			if err != nil || string(after) != string(before) {
				t.Fatal("expiry reconciliation changed retained artifact bytes", err)
			}
			return
		}
		if strings.HasPrefix(mode, "expiry_") && mode != "expiry_settlement" && !completedExpiry {
			orderedTestExpiryWait(t, ctx, owner, worker, redWorker, store, o, w, e, r, steps[1], mode, nil)
			return
		}
		if mode == "unknown" {
			uncertain, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				testUncertain(context.Context, json.RawMessage) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private uncertain invocation settlement absent")
			}
			request := orderedTestActionRequest(o, w, e, r, steps[1], "uncertain", 9, 1)
			raw, _ := json.Marshal(request)
			result, err := uncertain.testUncertain(ctx, raw)
			var got map[string]any
			if err != nil || json.Unmarshal(result, &got) != nil || got["run_state"] != "needs_human" || got["step_state"] != "inconclusive" || got["effect_state"] != "unknown_outcome" || got["receipt_created"] != false {
				t.Fatal("unknown provider outcome claimed terminal proof", string(result), err)
			}
			before := orderedTestSnapshot(t, ctx, owner, r)
			replay, err := uncertain.testUncertain(ctx, raw)
			if err != nil || string(replay) != string(result) || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("uncertainty replay mutated authority", string(replay), err)
			}
			orderedTestTerminalReplayRefusals(t, ctx, owner, r, steps[1], raw, false)
			assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 1, 2)
		}
		if settle {
			outputArtifact := orderedTestOutputArtifact(t, ctx, owner, store, o, w, e, r, steps[1], claim["test_run_id"].(string), inputArtifact)
			if mode == "bounds" {
				outputArtifact = orderedTestPadArtifact(t, ctx, store, o, w, e, r, steps[1], outputArtifact, 1048576, false)
			}
			settler, ok := any(&securityAgentMultistepAdmissionRepository{database: database}).(interface {
				testSettle(context.Context, json.RawMessage, artifactstore.ObjectReferencingArtifactStore) (json.RawMessage, error)
			})
			if !ok {
				t.Fatal("private immutable existing-test settlement absent")
			}
			request := orderedTestActionRequest(o, w, e, r, steps[1], "settle", 9, 1)
			request["payload"] = map[string]any{"input_artifact": inputArtifact, "output_artifact": outputArtifact}
			raw, _ := json.Marshal(request)
			if strings.HasPrefix(mode, "expiry_completed_") {
				orderedTestExpiryWait(t, ctx, owner, worker, redWorker, store, o, w, e, r, steps[1], strings.Replace(mode, "expiry_completed_", "expiry_", 1), raw, true)
				return
			}
			if mode == "expiry_settlement" {
				orderedTestExpiryWait(t, ctx, owner, worker, redWorker, store, o, w, e, r, steps[1], mode, raw)
				return
			}
			if mode == "evidence" {
				orderedTestEvidenceRefusals(t, ctx, owner, redWorker, store, o, w, e, r, steps[1], claim["test_run_id"].(string), inputArtifact, outputArtifact)
			}
			if mode == "settlement_wait" || mode == "cancel" {
				orderedTestSettlementWait(t, ctx, owner, redWorker, store, o, w, e, r, steps[1], raw, mode == "cancel")
				if mode == "cancel" && cleanup != nil {
					cleanup(ctx, owner, worker, api, action, o, w, e, r, steps)
				}
				return
			}
			result, err := settler.testSettle(ctx, raw, store)
			var got map[string]any
			wantState, wantOutcome := "contained", "not_reproduced"
			if mode == "reproduced" || mode == "mixed" {
				wantState, wantOutcome = "needs_human", "reproduced"
			}
			if err != nil || json.Unmarshal(result, &got) != nil || got["run_state"] != wantState || got["step_state"] != "succeeded" || got["effect_state"] != "verified" || got["receipt_kind"] != "existing_test_settled.v1" || got["outcome"] != wantOutcome || got["run_version"] != float64(10) || got["step_version"] != float64(5) || got["effect_version"] != float64(2) {
				t.Fatal("test settlement did not atomically aggregate", string(result), err)
			}
			if mode == "evidence" {
				orderedTestSettlementResponseRefusals(t, ctx, raw, result, store)
			}
			assertOrderedApplicationCounts(t, ctx, owner, r, 2, 2, 2, 2)
			var cleanup bool
			if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_controls WHERE run_id=$1 AND state='active') AND EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='create_temporary_policy' AND state='cleanup_pending')`, r).Scan(&cleanup); err != nil || !cleanup {
				t.Fatal("settlement suppressed cleanup", cleanup, err)
			}
			before := orderedTestSnapshot(t, ctx, owner, r)
			replay, err := settler.testSettle(ctx, raw, store)
			if err != nil || string(replay) != string(result) || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("settlement replay changed immutable authority", string(replay), err)
			}
			if mode == "evidence" {
				orderedTestTerminalReplayRefusals(t, ctx, owner, r, steps[1], raw, true)
			}
			if _, err := orderedTestActionCall(ctx, worker, orderedTestActionRequest(o, w, e, r, steps[1], "claim", 10, 2)); err == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("terminal parent reopened", err)
			}
		}
		if cleanup != nil {
			cleanup(ctx, owner, worker, api, action, o, w, e, r, steps)
		}
	})
}

func runOrderedJournalHTTPS(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, child string, unknown bool, reproduced ...bool) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "ordered-journal.test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "../redteamadapter")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build private journal proof: %s %v", output, err)
	}
	command := exec.CommandContext(ctx, binary, "-test.run=^TestOrderedJournalOwnedHTTPS$", "-test.v")
	command.Env = append(os.Environ(), "ZASP_ORDERED_JOURNAL_OWNER_DSN="+owner.Config().ConnString(), "ZASP_ORDERED_ORG="+o, "ZASP_ORDERED_WORKSPACE="+w, "ZASP_ORDERED_ENVIRONMENT="+e, "ZASP_ORDERED_TEST_RUN="+child)
	var token []byte
	if err := owner.QueryRow(ctx, `SELECT lease_token FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, child).Scan(&token); err != nil {
		t.Fatal(err)
	}
	command.Env = append(command.Env, "ZASP_ORDERED_LEASE="+string(token))
	if unknown {
		command.Env = append(command.Env, "ZASP_ORDERED_UNKNOWN=1")
	}
	if len(reproduced) > 0 && reproduced[0] {
		command.Env = append(command.Env, "ZASP_ORDERED_REPRODUCED=1")
	}
	if len(reproduced) > 1 && reproduced[1] {
		command.Env = append(command.Env, "ZASP_ORDERED_MIXED=1")
	}
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "--- PASS: TestOrderedJournalOwnedHTTPS") {
		t.Fatalf("owned private database-to-TLS journal proof: %s %v", output, err)
	}
	t.Log(string(output))
}

func orderedTestConnections(t *testing.T, ctx context.Context, owner *pgx.Conn) (*pgx.Conn, *pgx.Conn) {
	t.Helper()
	if _, err := owner.Exec(ctx, `CREATE ROLE ordered_test_red_worker LOGIN INHERIT; CREATE ROLE ordered_test_red_outbox LOGIN INHERIT; CREATE ROLE ordered_test_red_adapter LOGIN INHERIT;
 SELECT zasp_red_team_register_principals(session_user,'ordered_test_red_worker','ordered_test_red_outbox','ordered_test_red_adapter')`); err != nil {
		t.Fatal(err)
	}
	connect := func(user string) *pgx.Conn {
		config := owner.Config().Copy()
		config.User = user
		connection, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		return connection
	}
	return connect("ordered_test_red_worker"), connect("ordered_test_red_adapter")
}

// Controlled discovery projection, not provider or invocation evidence. It is
// installed before admission so the real ordered context pins the whole source.
func seedOrderedTestSource(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, actor string) {
	t.Helper()
	multistepSeedExistingTestSimulationEvidence(t, ctx, owner, o, w, e, actor)
	if _, err := owner.Exec(ctx, `UPDATE zasp_discovery_snapshots SET state='complete',complete=true,is_last_good=true,apply_result='{}',committed_at=clock_timestamp() WHERE id='pid_89e23800-0000-4000-8000-000000000003';
 UPDATE zasp_inventory_evidence SET source='kubernetes',generation=1 WHERE id='pid_89e23800-0000-4000-8000-000000000004';
 UPDATE zasp_inventory_entities SET winning_integration_id='pid_89e23800-0000-4000-8000-000000000001',winning_snapshot_id='pid_89e23800-0000-4000-8000-000000000003',winning_evidence_id='pid_89e23800-0000-4000-8000-000000000004',winning_provider='kubernetes',winning_source='kubernetes',winning_source_native_id='invocation-agent',winning_generation=1 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,'pid_89000011-0000-4000-8000-000000000001');
 INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,attributes,first_seen_at,last_seen_at,provider,source_kind,display_name,stable_fields,identity_namespace,product_kind,generation,content_digest,evidence_id,confidence_basis_points,observed_at,fresh_until,identity_rule_version,identity_priority,source_projection_version)
 VALUES($1,$2,$3,'pid_89e23800-0000-4000-8000-000000000001','kubernetes','pid_89000011-0000-4000-8000-000000000001','invocation-agent','pid_89e23800-0000-4000-8000-000000000003','present','{}',clock_timestamp(),clock_timestamp(),'kubernetes','kubernetes_agent','Invocation target','{}','kubernetes_agent','agent',1,decode(repeat('ab',32),'hex'),'pid_89e23800-0000-4000-8000-000000000004',9500,clock_timestamp(),clock_timestamp()+interval '1 hour',1,80,1)`, pgx.QueryExecModeSimpleProtocol, o, w, e); err != nil {
		t.Fatal(err)
	}
}

func orderedTestSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, r string) string {
	t.Helper()
	var value string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('links',(SELECT jsonb_agg(to_jsonb(l) ORDER BY step_id) FROM zasp_security_agent_test_links l WHERE run_id=$1),'children',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.run_id) FROM zasp_red_team_runs c WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)),'invocations',(SELECT jsonb_agg(to_jsonb(j) ORDER BY test_run_id,attempt,category) FROM zasp_security_agent_test_invocations j WHERE test_run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)),'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY run_id,attempt) FROM zasp_red_team_attempts a WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)))::text`, r).Scan(&value); err != nil {
		t.Fatal(err)
	}
	var private string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('inputs',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_prior.test_inputs x WHERE run_id=$1),'settlements',(SELECT jsonb_agg(to_jsonb(x) ORDER BY step_id) FROM zasp_sa_multistep_prior.test_settlements x WHERE run_id=$1))::text`, r).Scan(&private); err != nil {
		t.Fatal(err)
	}
	return orderedApplicationSnapshot(t, ctx, owner, r) + value + private
}
