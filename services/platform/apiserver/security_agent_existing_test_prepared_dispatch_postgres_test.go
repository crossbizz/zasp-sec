package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Admission and current definition history are controlled inputs. Preparation,
// approval decision and claim use real registered roles. Dispatch gets only a
// temporary fixture grant after those calls; the release must keep it private.
func TestSecurityAgentExistingTestPreparedDispatchPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true)
}

func TestSecurityAgentExistingTestRegisteredDispatchPostgres(t *testing.T) {
	t.Setenv("ZASP_EXISTING_TEST_REGISTERED_DISPATCH", "true")
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true)
}

func TestSecurityAgentExistingTestPreparedApprovalPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, false)
}

func TestSecurityAgentExistingTestLegacyWorkerFencePostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true)
}

func TestSecurityAgentExistingTestInvocationStartPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true, true)
}

func TestSecurityAgentExistingTestInvocationTerminalPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true, true, true)
}

func TestSecurityAgentExistingTestJournalClientPostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, true, false, false, true)
}

func TestSecurityAgentExistingTestBaselinePostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, false, false, false, false, false, false, false, true)
}

func TestSecurityAgentExistingTestReconcileLeasePostgres(t *testing.T) {
	exerciseSecurityAgentExistingTestPreparedDispatch(t, true, false, false, false, false, false, false, false, false, true)
}

func exerciseSecurityAgentExistingTestPreparedDispatch(t *testing.T, dispatch bool, legacyFence ...bool) {
	t.Helper()
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		checkLegacy := len(legacyFence) >= 1 && legacyFence[0]
		checkStart := len(legacyFence) >= 2 && legacyFence[1]
		checkTerminal := len(legacyFence) == 3 && legacyFence[2]
		checkJournal := len(legacyFence) == 4 && legacyFence[3]
		checkClaim := len(legacyFence) >= 5 && legacyFence[4]
		checkFinish := len(legacyFence) >= 6 && legacyFence[5]
		checkCancel := len(legacyFence) >= 7 && legacyFence[6]
		checkBaseline := len(legacyFence) >= 8 && legacyFence[7]
		checkReconcile := len(legacyFence) >= 9 && legacyFence[8]
		if checkTerminal || checkFinish || checkCancel {
			if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET categories='["prompt_injection","tool_abuse","data_leakage"]' WHERE (organization_id,workspace_id,environment_id,definition_id)=($1,$2,$3,$4)`, org, ws, env, testID); err != nil {
				t.Fatal(err)
			}
		}
		var redWorker *pgx.Conn
		if checkLegacy {
			if _, err := owner.Exec(ctx, `CREATE ROLE existing_test_red_worker LOGIN INHERIT; CREATE ROLE existing_test_red_outbox LOGIN INHERIT; CREATE ROLE existing_test_red_adapter LOGIN INHERIT; SELECT zasp_red_team_register_principals(session_user,'existing_test_red_worker','existing_test_red_outbox','existing_test_red_adapter')`); err != nil {
				t.Fatal(err)
			}
			redConfig := owner.Config().Copy()
			redConfig.User = "existing_test_red_worker"
			redWorker, err = pgx.ConnectConfig(ctx, redConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer redWorker.Close(context.Background())
		}
		for i, mode := range []struct{ action, autonomy, refusal string }{
			{"run_test", "supervised", ""}, {"rerun_test", "supervised", ""},
			{"run_test", "autonomous", ""}, {"rerun_test", "autonomous", ""},
			{"run_test", "supervised", "missing_approval"}, {"run_test", "supervised", "expired_approval"},
			{"rerun_test", "supervised", "pending_approval"}, {"run_test", "supervised", "wrong_hash"},
			{"run_test", "autonomous", "unexpected_approval"}, {"run_test", "autonomous", "other_step_approval"},
			{"run_test", "autonomous", "forged_authorization"}, {"rerun_test", "supervised", "audit_wait_approval"},
			{"run_test", "supervised", "enqueue_wait_approval"}, {"rerun_test", "supervised", "link_wait_approval"},
		} {
			if os.Getenv("ZASP_TEST_EXISTING_SETTLEMENT_RECOVERY") == "true" && i != 2 {
				continue
			}
			if os.Getenv("ZASP_TEST_EXISTING_SETTLEMENT_STOPPED") == "true" && i != 0 {
				continue
			}
			if !dispatch && (mode.autonomy != "supervised" || mode.refusal != "") {
				continue
			}
			if (checkLegacy || checkBaseline || checkReconcile) && mode.refusal != "" {
				continue
			}
			name := mode.action + "_" + mode.autonomy
			if mode.refusal != "" {
				name += "_" + mode.refusal
			}
			t.Run(name, func(t *testing.T) {
				run := fmt.Sprintf("pid_89c001%02d-0000-4000-8000-000000000001", i)
				finding := fmt.Sprintf("pid_89c002%02d-0000-4000-8000-000000000002", i)
				approval := fmt.Sprintf("pid_89c003%02d-0000-4000-8000-000000000003", i)
				const workerID, prepareLease, dispatchLease = "prepared-dispatch-worker", "prepared-dispatch-prepare-lease", "prepared-dispatch-execution-lease"
				seedExistingTestPreparation(t, ctx, owner, org, ws, env, testID, actor, run, finding, mode.action, workerID, prepareLease)
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET activation=$4,body=jsonb_set(body,'{autonomy}',to_jsonb($4::text)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$5 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)
 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by)
 VALUES($1,$2,$3,$6,true,$5)
 ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, org, ws, env, mode.autonomy, actor, mode.action); err != nil {
					t.Fatal(err)
				}
				var raw json.RawMessage
				if err := worker.QueryRow(ctx, existingTestPrepareSQL, org, ws, env, run, workerID, prepareLease, approval, time.Now().UTC().Add(10*time.Minute), fmt.Sprintf("pid_89c004%02d-0000-4000-8000-000000000004", i), "pid_89c00500-0000-4000-8000-000000000005").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var prepared SecurityAgentPrepareResult
				if err := json.Unmarshal(raw, &prepared); err != nil || prepared.RunID != run || prepared.StepID == "" {
					t.Fatalf("preparation=%s %v", raw, err)
				}
				if mode.autonomy == "supervised" {
					if prepared.State != "waiting_approval" || prepared.ApprovalID != approval {
						t.Fatalf("supervised preparation skipped approval: %s", raw)
					}
					if !dispatch {
						exerciseExistingTestApprovalReads(t, ctx, api, org, ws, env, run, approval, prepared.StepID, testID, mode.action)
					}
					beforeDecision := existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run)
					decisionReceipts := func() string {
						var value string
						if err := owner.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY principal_id,operation,idempotency_key),'[]'::jsonb)::text FROM zasp_security_agent_request_receipts r WHERE (organization_id,workspace_id,environment_id,resource_id)=($1,$2,$3,$4)`, org, ws, env, approval).Scan(&value); err != nil {
							t.Fatal(err)
						}
						return value
					}
					beforeReceipts := decisionReceipts()
					fingerprint := migrations.SecurityAgentExistingTestsFingerprint()
					throughRepository := false
					decide := func() error {
						if throughRepository {
							db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
							if err != nil {
								return err
							}
							repo, err := NewSecurityAgentPostgresRepository(db)
							if err != nil {
								return err
							}
							identity := fixtureRequestIdentity(t)
							o, _ := domain.ParseProductID(org)
							w, _ := domain.ParseProductID(ws)
							e, _ := domain.ParseProductID(env)
							identity.Scope, err = domain.NewScope(o, w, e)
							if err != nil {
								return err
							}
							identity.PrincipalID, _ = domain.ParseProductID("pid_89c00600-0000-4000-8000-000000000006")
							identity.FreshAuthExpiresAt = time.Now().UTC().Add(time.Minute)
							value, err := repo.DecideSecurityAgentApproval(ctx, identity, SecurityAgentApprovalDecisionRequest{ApprovalID: approval, IdempotencyKey: fmt.Sprintf("prepared-dispatch-approval-%04d", i), ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: fmt.Sprintf("pid_89c007%02d-0000-4000-8000-000000000007", i), CorrelationID: "pid_89c00800-0000-4000-8000-000000000008", ReceiptID: fmt.Sprintf("pid_89c009%02d-0000-4000-8000-000000000009", i)})
							if err != nil {
								return err
							}
							raw, err = json.Marshal(value)
							return err
						}
						return api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_decide_approval($1,$2,$3,$4,$5,$6,1,'approved',clock_timestamp(),$7,$8,$9,$10,$11)`, org, ws, env, approval,
							"pid_89c00600-0000-4000-8000-000000000006", fmt.Sprintf("prepared-dispatch-approval-%04d", i),
							fmt.Sprintf("pid_89c007%02d-0000-4000-8000-000000000007", i), "pid_89c00800-0000-4000-8000-000000000008", fmt.Sprintf("pid_89c009%02d-0000-4000-8000-000000000009", i), migrations.ProductionSecurityAgentExistingTests().Checksum(), fingerprint).Scan(&raw)
					}
					fingerprint = "invalid-release"
					var refused *pgconn.PgError
					if err := decide(); !errors.As(err, &refused) || refused.Code != "55000" {
						t.Fatalf("stale approval release accepted: %v", err)
					}
					fingerprint = migrations.SecurityAgentExistingTestsFingerprint()
					if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_approval_value($1,$2,$3,$4)`, org, ws, env, approval).Scan(&raw); !errors.As(err, &refused) || refused.Code != "42501" {
						t.Fatalf("private approval projection exposed: %v", err)
					}
					if existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) != beforeDecision || decisionReceipts() != beforeReceipts {
						t.Fatal("refused approval changed authority")
					}
					throughRepository = !dispatch
					if err := decide(); err != nil {
						if afterDecision := existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run); afterDecision != beforeDecision {
							t.Fatalf("failed approval decision changed run authority: %v\nbefore=%s\nafter=%s", err, beforeDecision, afterDecision)
						}
						if afterReceipts := decisionReceipts(); afterReceipts != beforeReceipts {
							t.Fatalf("failed approval decision changed request receipts: %v\nbefore=%s\nafter=%s", err, beforeReceipts, afterReceipts)
						}
						t.Fatalf("registered approval decision: %v", err)
					}
					var result map[string]any
					if err := json.Unmarshal(raw, &result); err != nil {
						t.Fatal(err)
					}
					wantEffect := "Run existing test"
					if mode.action == "rerun_test" {
						wantEffect = "Rerun existing test"
					}
					if result["id"] != approval || result["run_id"] != run || result["step_id"] != prepared.StepID || result["state"] != "approved" || result["version"] != float64(2) || result["expected_effect"] != wantEffect || result["reversible"] != false || result["ttl_seconds"] != float64(0) || result["replayed"] != false {
						t.Fatalf("incorrect test approval: %s", raw)
					}
					if !dispatch {
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET expires_at=expires_at+interval '1 minute',version=version+1 WHERE (organization_id,workspace_id,environment_id,approval_id)=($1,$2,$3,$4)`, org, ws, env, approval); err != nil {
							t.Fatal(err)
						}
						beforeReplay := existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run)
						receiptsBeforeReplay := decisionReceipts()
						if err := decide(); err != nil {
							t.Fatal(err)
						}
						result["replayed"] = true
						want, err := json.Marshal(result)
						if err != nil {
							t.Fatal(err)
						}
						var equal bool
						if err := owner.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, raw, want).Scan(&equal); err != nil || !equal {
							t.Fatalf("immutable approval replay=%s want=%s err=%v", raw, want, err)
						}
						if existingTestAcceptanceSnapshot(t, ctx, owner, org, ws, env, run) != beforeReplay || decisionReceipts() != receiptsBeforeReplay {
							t.Fatal("replay mutated authority")
						}
						for _, version := range []string{"1.5", `"invalid"`, "null"} {
							t.Run("malformed_version_"+version, func(t *testing.T) {
								tx, err := owner.Begin(ctx)
								if err != nil {
									t.Fatal(err)
								}
								defer tx.Rollback(context.Background())
								if _, err := tx.Exec(ctx, `WITH changed AS (
 UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,test_definition_version}',$5::jsonb),plan_hash=digest(convert_to(jsonb_set(plan,'{steps,0,test_definition_version}',$5::jsonb)::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4) RETURNING plan,plan_hash),
 runs AS (UPDATE zasp_security_agent_runs SET plan_hash=changed.plan_hash FROM changed WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 approvals AS (UPDATE zasp_security_agent_approvals SET plan_hash=changed.plan_hash FROM changed WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4))
 UPDATE zasp_security_agent_steps SET input_digest=digest(convert_to((changed.plan->'steps'->0)::text,'UTF8'),'sha256') FROM changed WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run, version); err != nil {
									t.Fatal(err)
								}
								var pg *pgconn.PgError
								err = tx.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_approval_value($1,$2,$3,$4)`, org, ws, env, approval).Scan(&raw)
								if !errors.As(err, &pg) || pg.Code != "55000" {
									t.Fatalf("malformed version accepted or unsafe error: %s %v", version, err)
								}
							})
						}
						return
					}
				} else if prepared.State != "queued" || prepared.ApprovalID != "" {
					t.Fatalf("autonomous preparation=%s", raw)
				}
				if err := worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, workerID, dispatchLease, 60, 25).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var claimed struct {
					Items []SecurityAgentRunClaim `json:"items"`
				}
				if err := json.Unmarshal(raw, &claimed); err != nil {
					t.Fatal(err)
				}
				found := false
				var executionClaim SecurityAgentRunClaim
				for _, claim := range claimed.Items {
					if claim.RunID == run && claim.OrganizationID == org && claim.WorkspaceID == ws && claim.EnvironmentID == env && claim.Prepared && claim.State == "planning" {
						found = true
						executionClaim = claim
					}
				}
				if !found {
					t.Fatalf("prepared run not claimed: %s", raw)
				}
				mutation := map[string]string{
					"missing_approval":     `DELETE FROM zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`,
					"expired_approval":     `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`,
					"pending_approval":     `UPDATE zasp_security_agent_approvals SET state='pending' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`,
					"wrong_hash":           `UPDATE zasp_security_agent_approvals SET plan_hash=decode(repeat('ff',32),'hex') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`,
					"forged_authorization": `UPDATE zasp_security_agent_steps SET authorization_result='allow' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`,
				}[mode.refusal]
				if mutation != "" {
					if _, err := owner.Exec(ctx, mutation, org, ws, env, run); err != nil {
						t.Fatal(err)
					}
				}
				if mode.refusal == "unexpected_approval" || mode.refusal == "other_step_approval" {
					s := prepared.StepID
					if mode.refusal == "other_step_approval" {
						s = "pid_89c0ffff-0000-4000-8000-000000000001"
					}
					if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at) SELECT $1,$2,$3,$5,$4,$6,plan_hash,'pending',requested_by,clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run, approval, s); err != nil {
						t.Fatal(err)
					}
				}
				beforeDispatch := existingTestDispatchSnapshot(t, ctx, owner, org, ws, env, run)
				var baselineWant string
				invoke := func() error {
					return worker.QueryRow(ctx, `SELECT zasp_security_agent_test_dispatch($1,$2,$3,$4,$5,$6,$7,$8)`, org, ws, env, run, workerID, dispatchLease, fmt.Sprintf("pid_89c00a%02d-0000-4000-8000-00000000000a", i), "pid_89c00b00-0000-4000-8000-00000000000b").Scan(&raw)
				}
				var pg *pgconn.PgError
				if err := invoke(); !errors.As(err, &pg) || pg.Code != "42501" {
					t.Fatalf("production dispatch exposed: %v", err)
				}
				if os.Getenv("ZASP_EXISTING_TEST_REGISTERED_DISPATCH") == "true" {
					assertRegisteredExistingTestDispatchRefusals(t, ctx, owner, api, worker, org, ws, env, run, workerID, dispatchLease)
					invoke = func() error {
						if mode.refusal == "" {
							db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
							if err != nil {
								return err
							}
							repository, err := NewSecurityAgentWorkerRepository(db)
							if err != nil {
								return err
							}
							result, err := repository.ExecuteSecurityAgentRun(ctx, executionClaim, workerID, dispatchLease, fmt.Sprintf("pid_89c00a%02d-0000-4000-8000-00000000000a", i), "pid_89c00b00-0000-4000-8000-00000000000b")
							if err != nil {
								return err
							}
							raw, err = json.Marshal(result)
							return err
						}
						return worker.QueryRow(ctx, `SELECT public.zasp_production_security_agent_existing_tests_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, org, ws, env, run, workerID, dispatchLease, fmt.Sprintf("pid_89c00a%02d-0000-4000-8000-00000000000a", i), "pid_89c00b00-0000-4000-8000-00000000000b", migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&raw)
					}
				} else {
					if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) TO security_agent_v33_worker_login`); err != nil {
						t.Fatal(err)
					}
					defer owner.Exec(context.Background(), `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`)
				}
				err = nil
				if checkBaseline && mode.refusal == "" {
					// Completion after transaction start but before enqueue is eligible.
					// queued_at's transaction timestamp must not act as the cutoff.
					if _, err := worker.Exec(ctx, `BEGIN`); err != nil {
						t.Fatal(err)
					}
					defer worker.Exec(context.Background(), `ROLLBACK`)
					baselineWant = seedExistingTestBaseline(t, ctx, owner, org, ws, env, testID, actor, i)
				}
				if mode.refusal == "audit_wait_approval" || mode.refusal == "enqueue_wait_approval" || mode.refusal == "link_wait_approval" {
					err = existingTestAcceptanceWait(t, ctx, owner, worker, run, mode.refusal, invoke)
				} else {
					err = invoke()
				}
				if mode.refusal != "" {
					if !errors.As(err, &pg) || pg.Code != "40001" {
						t.Fatalf("missing dispatch authorization refusal %s: %v", mode.refusal, err)
					}
					if after := existingTestDispatchSnapshot(t, ctx, owner, org, ws, env, run); after != beforeDispatch {
						t.Fatalf("refused dispatch left authority: before=%s after=%s", beforeDispatch, after)
					}
					return
				}
				if err != nil {
					t.Fatalf("dispatch prepared %s/%s: %v", mode.action, mode.autonomy, err)
				}
				if checkBaseline {
					if _, err := worker.Exec(ctx, `COMMIT`); err != nil {
						t.Fatal(err)
					}
				}
				var executed SecurityAgentExecuteResult
				if err := json.Unmarshal(raw, &executed); err != nil || executed.RunID != run || executed.State != "running" || executed.StepID != prepared.StepID || executed.EffectState != "pending" {
					t.Fatalf("dispatch envelope=%s %v", raw, err)
				}
				var linked bool
				if err := owner.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(l.test_definition_id=$5 AND l.test_definition_version=1 AND l.action_key=$6 AND s.state='executing' AND f.state='pending' AND t.state='queued'
 AND (SELECT count(*)=1 AND bool_and(state='pending') FROM zasp_red_team_outbox q WHERE (q.organization_id,q.workspace_id,q.environment_id)=(l.organization_id,l.workspace_id,l.environment_id) AND q.payload->>'run_id'=l.test_run_id)
 AND (SELECT count(*)=1 FROM zasp_red_team_request_receipts r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.resource_id,r.operation)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id,'runTest'))
 AND (SELECT count(*)=1 AND bool_and(b.action_key=l.action_key AND b.input_digest=s.input_digest) FROM zasp_security_agent_step_reservations b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id,b.step_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)))
 FROM zasp_security_agent_test_links l JOIN zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id)
 JOIN zasp_red_team_runs t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=($1,$2,$3,$4)`, org, ws, env, run, testID, mode.action).Scan(&linked); err != nil || !linked {
					t.Fatalf("missing exact pending test association: %t %v", linked, err)
				}
				if checkBaseline {
					assertExistingTestBaseline(t, ctx, owner, org, ws, env, run, prepared.StepID, baselineWant)
				}
				if os.Getenv("ZASP_EXISTING_TEST_PUBLIC_PROOF") == "true" {
					assertExistingTestPublicProof(t, ctx, owner, org, ws, env, run, prepared.StepID, false)
				}
				if checkReconcile {
					if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`); err != nil {
						t.Fatal(err)
					}
					assertExistingTestReconcileLease(t, ctx, owner, worker, org, ws, env, run, prepared.StepID)
				}
				if checkLegacy {
					var testRun string
					if err := owner.QueryRow(ctx, `SELECT test_run_id FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, org, ws, env, run).Scan(&testRun); err != nil {
						t.Fatal(err)
					}
					before := existingTestDispatchSnapshot(t, ctx, owner, org, ws, env, run)
					err := redWorker.QueryRow(ctx, `SELECT zasp_red_team_claim_run($1,$2,$3,$4,'existing-test-legacy-worker',convert_to(repeat('a',32),'UTF8'),60)`, org, ws, env, testRun).Scan(&raw)
					var refused *pgconn.PgError
					if !errors.As(err, &refused) || refused.Code != "55000" {
						t.Fatalf("legacy Red Team worker claimed linked test before invocation protocol: %s %v", raw, err)
					}
					if existingTestDispatchSnapshot(t, ctx, owner, org, ws, env, run) != before {
						t.Fatal("legacy linked claim changed durable state")
					}
					exerciseExistingTestLegacyInvocationFence(t, ctx, owner, redWorker, org, ws, env, testRun, i)
					if checkClaim {
						if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`); err != nil {
							t.Fatal(err)
						}
						finishMode := -1
						if checkFinish {
							finishMode = i
						}
						if checkCancel {
							finishMode = i + 4
						}
						exerciseExistingTestWorkerClaim(t, ctx, owner, redWorker, org, ws, env, testRun, finishMode)
					}
					if checkJournal {
						if _, err := owner.Exec(ctx, `REVOKE EXECUTE ON FUNCTION public.zasp_security_agent_test_dispatch(text,text,text,text,text,text,text,text) FROM security_agent_v33_worker_login`); err != nil {
							t.Fatal(err)
						}
						exerciseExistingTestJournalClient(t, ctx, owner, org, ws, env, testRun)
					}
					if checkStart {
						exerciseExistingTestInvocationStart(t, ctx, owner, org, ws, env, testRun, checkTerminal)
					}
				}
			})
		}
		if checkReconcile {
			assertReconcileBatchBound(t, ctx, owner, worker, org, ws, env)
		}
	})
}

func existingTestDispatchSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, org, ws, env, run string) string {
	t.Helper()
	var value string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
 'run',(SELECT to_jsonb(r) FROM zasp_security_agent_runs r WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'steps',(SELECT jsonb_agg(to_jsonb(s) ORDER BY step_id) FROM zasp_security_agent_steps s WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'effects',(SELECT count(*) FROM zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'reservations',(SELECT count(*) FROM zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'links',(SELECT count(*) FROM zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'audit',(SELECT count(*) FROM zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)),
 'test_runs',(SELECT count(*) FROM zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'outbox',(SELECT count(*) FROM zasp_red_team_outbox WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)),
 'receipts',(SELECT count(*) FROM zasp_red_team_request_receipts WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)))::text`, org, ws, env, run).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
