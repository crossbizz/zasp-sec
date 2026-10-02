package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const existingTestReserveSQL = `SELECT zasp_production_security_agent_existing_tests_reserve_planner($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`

// Owner-seeded admission, real registered worker reservation and durable readback.
// The model and request-price bounds are controlled inputs, not provider proof.
func TestSecurityAgentExistingTestPlannerReservationPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, org, ws, env, testID, actor string) {
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		const workerID, lease = "existing-test-reservation-worker", "existing-test-reservation-lease"
		for i, mode := range []string{"run_test", "rerun_test", "wrong_digest", "changed_version", "disabled_test", "wrong_scope", "wrong_attempt", "wrong_lease", "expired", "tokens_exceeded", "cost_exceeded", "missing_bound", "replay", "insert_wait_lease", "insert_wait_budget", "insert_wait_target", "unauthorized_api", "repository_run_test", "repository_rerun_test"} {
			t.Run(mode, func(t *testing.T) {
				run := fmt.Sprintf("pid_897001%02d-0000-4000-8000-000000000001", i)
				finding := fmt.Sprintf("pid_897002%02d-0000-4000-8000-000000000002", i)
				action := "run_test"
				if strings.HasSuffix(mode, "rerun_test") {
					action = "rerun_test"
				}
				if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=1,enabled=true WHERE definition_id=$4;
 UPDATE zasp_security_agent_definitions SET activation='supervised',body=body||jsonb_build_object('enabled',true,'autonomy','supervised','trigger_kind','finding','trigger_source','credential','allowed_actions',jsonb_build_array($9),'verification_kind','test_run','existing_test',jsonb_build_object('definition_id',$4,'definition_version',1)) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$6,'posture','credential','Reservation trigger','high','open');
 INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,attempt,lease_owner,lease_token,lease_expires_at)
 SELECT organization_id,workspace_id,environment_id,$5,definition_id,version,$6,$7,'planning',1,$8,$10,clock_timestamp()+interval '60 seconds' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit)
 SELECT organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,created_at,created_at+interval '60 seconds',1,100,200,10 FROM zasp_security_agent_runs WHERE run_id=$5;
 INSERT INTO zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,$6,'finding',1,decode(repeat('cd',32),'hex'),run_id FROM zasp_security_agent_runs WHERE run_id=$5`, pgx.QueryExecModeSimpleProtocol, org, ws, env, testID, run, finding, actor, workerID, action, lease); err != nil {
					t.Fatal(err)
				}
				var contextRaw json.RawMessage
				if err := worker.QueryRow(ctx, existingTestPlannerContextSQL, org, ws, env, run, workerID, lease).Scan(&contextRaw); err != nil {
					t.Fatal(err)
				}
				var contextEnvelope struct {
					Digest string `json:"input_digest"`
				}
				if err := json.Unmarshal(contextRaw, &contextEnvelope); err != nil {
					t.Fatal(err)
				}
				digest, ok := decodeSecurityAgentDigest(contextEnvelope.Digest)
				if !ok {
					t.Fatal("invalid context digest")
				}
				args := []any{org, ws, env, run, workerID, lease, 1, "new-reservation", digest, "fixture-model", "fixture-policy", "openrouter_credit", int64(100), int64(200)}
				wantCode, wantReason := "", ""
				caller := worker
				switch mode {
				case "wrong_digest":
					digest[0] ^= 1
					wantCode = "40001"
				case "changed_version":
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET version=2 WHERE definition_id=$1; UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{existing_test,definition_version}','2') WHERE definition_id=(SELECT definition_id FROM zasp_security_agent_runs WHERE run_id=$2)`, pgx.QueryExecModeSimpleProtocol, testID, run); err != nil {
						t.Fatal(err)
					}
					wantCode = "40001"
				case "disabled_test":
					if _, err := owner.Exec(ctx, `UPDATE zasp_red_team_definitions SET enabled=false WHERE definition_id=$1`, testID); err != nil {
						t.Fatal(err)
					}
					wantCode = "40001"
				case "wrong_scope":
					args[2] = "pid_89709999-0000-4000-8000-000000000001"
					wantCode = "40001"
				case "wrong_attempt":
					args[6] = 2
					wantCode = "40001"
				case "wrong_lease":
					args[5] = "wrong-reservation-lease-token"
					wantCode = "40001"
				case "expired":
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_run_budgets SET started_at=clock_timestamp()-interval '60 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, run); err != nil {
						t.Fatal(err)
					}
					wantReason = "budget_deadline_exceeded"
				case "tokens_exceeded":
					args[12] = int64(101)
					wantReason = "budget_tokens_exceeded"
				case "cost_exceeded":
					args[13] = int64(201)
					wantReason = "budget_cost_exceeded"
				case "missing_bound":
					args[13] = nil
					wantReason = "budget_usage_unknown"
				case "replay":
					wantReason = "budget_usage_unknown"
				case "insert_wait_lease", "insert_wait_target":
					wantCode = "40001"
				case "insert_wait_budget":
					wantReason = "budget_deadline_exceeded"
				case "unauthorized_api":
					caller = api
					wantCode = "42501"
				}
				claim := SecurityAgentRunClaim{OrganizationID: org, WorkspaceID: ws, EnvironmentID: env, RunID: run, Attempt: 1, Version: 1}
				var repository *SecurityAgentWorkerRepository
				var repositoryPermit SecurityAgentBudgetPermit
				request := SecurityAgentBudgetReservation{ReservationID: "new-reservation", InputDigest: contextEnvelope.Digest, Model: "fixture-model", CostPolicyVersion: "fixture-policy", CostUnit: "openrouter_credit", MaximumTokens: 100, MaximumCostNanoCredits: 200}
				if strings.HasPrefix(mode, "repository_") {
					claim.TriggerID = finding
					claim.State = "planning"
					// A claimed run has advanced past the initial queued version.
					if err := owner.QueryRow(ctx, `UPDATE zasp_security_agent_runs SET version=2 WHERE run_id=$1 RETURNING definition_id,definition_version,version,lease_expires_at`, run).Scan(&claim.DefinitionID, &claim.DefinitionVersion, &claim.Version, &claim.LeaseExpiresAt); err != nil {
						t.Fatal(err)
					}
					claim.LeaseExpiresAt = claim.LeaseExpiresAt.UTC()
					db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
					if err != nil {
						t.Fatal(err)
					}
					repository, err = NewSecurityAgentWorkerRepository(db)
					if err != nil {
						t.Fatal(err)
					}
					loaded, err := repository.LoadSecurityAgentPlannerContext(ctx, claim, workerID, lease)
					if err != nil || loaded.InputDigest != contextEnvelope.Digest || loaded.ExistingTest == nil || loaded.ExistingTest.DefinitionID != testID || loaded.ExistingTest.DefinitionVersion != 1 {
						t.Fatalf("repository lost database reference: %+v %v", loaded, err)
					}
				}
				var raw json.RawMessage
				invoke := func() error {
					if repository != nil {
						var err error
						repositoryPermit, err = repository.ReserveSecurityAgentPlannerBudget(ctx, claim, workerID, lease, request)
						return err
					}
					return caller.QueryRow(ctx, existingTestReserveSQL, args...).Scan(&raw)
				}
				var err error
				if mode == "run_test" {
					var pg *pgconn.PgError
					if err := worker.QueryRow(ctx, reservePlannerBudgetTestSQL, args...).Scan(&raw); !errors.As(err, &pg) || pg.Code != "22023" {
						t.Fatalf("legacy reservation unexpectedly admits test context: %s %v", raw, err)
					}
				}
				if strings.HasPrefix(mode, "insert_wait_") {
					err = existingTestReservationWait(t, ctx, owner, worker, run, mode, invoke)
				} else {
					err = invoke()
				}
				if mode == "replay" && err == nil {
					if !validReservationTestPermit(raw, claim, contextEnvelope.Digest, 100, 200) {
						t.Fatalf("first permit invalid: %s", raw)
					}
					err = invoke()
				}
				if wantCode != "" {
					var pg *pgconn.PgError
					if !errors.As(err, &pg) || pg.Code != wantCode {
						t.Fatalf("reservation refusal=%s %v want=%s", raw, err, wantCode)
					}
				} else if err != nil {
					t.Fatal(err)
				} else if wantReason != "" {
					if !validSecurityAgentBudgetStop(raw, claim) {
						t.Fatalf("missing durable stop: %s", raw)
					}
					var response struct {
						Stop struct {
							Reason string `json:"reason"`
						} `json:"budget_stop"`
					}
					if err := json.Unmarshal(raw, &response); err != nil || response.Stop.Reason != wantReason {
						t.Fatalf("wrong returned stop reason: %s %v", raw, err)
					}
				} else if repository != nil {
					if repositoryPermit.Reservation != request || repositoryPermit.Version != claim.Version {
						t.Fatalf("repository permit lost request binding: %+v", repositoryPermit)
					}
				} else if !validReservationTestPermit(raw, claim, contextEnvelope.Digest, 100, 200) {
					t.Fatalf("invalid bound permit: %s", raw)
				}
				if wantCode == "" && wantReason == "" {
					var expiryMatches bool
					expirySQL := `SELECT ($2::jsonb->'budget_permit'->>'expires_at')::timestamptz=least(r.lease_expires_at,b.deadline_at) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`
					var expiryArg any = raw
					if repository != nil {
						expirySQL = `SELECT $2::timestamptz=least(r.lease_expires_at,b.deadline_at) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`
						expiryArg = repositoryPermit.ExpiresAt
					}
					if err := owner.QueryRow(ctx, expirySQL, run, expiryArg).Scan(&expiryMatches); err != nil || !expiryMatches {
						t.Fatalf("permit expiry not bound to current authority: %v", err)
					}
				}
				var count int
				var state, reason string
				var cleared bool
				if err := owner.QueryRow(ctx, `SELECT r.state,coalesce(b.stop_reason,''),r.lease_token IS NULL,(SELECT count(*) FROM zasp_security_agent_provider_reservations WHERE run_id=$1) FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) WHERE r.run_id=$1`, run).Scan(&state, &reason, &cleared, &count); err != nil {
					t.Fatal(err)
				}
				wantCount := 0
				if wantCode == "" && wantReason == "" || mode == "replay" {
					wantCount = 1
				}
				if count != wantCount || reason != wantReason || wantReason != "" && (state != "needs_human" || !cleared) || wantReason == "" && (state != "planning" || cleared) {
					t.Fatalf("durable state=%s reason=%s count=%d cleared=%v", state, reason, count, cleared)
				}
				if wantCount == 1 {
					var bound bool
					if err := owner.QueryRow(ctx, `SELECT input_digest=$2 AND attempt=1 AND reservation_id='new-reservation' AND model='fixture-model' AND cost_policy_version='fixture-policy' AND cost_unit='openrouter_credit' AND maximum_tokens=100 AND maximum_cost_nano_credits=200 AND worker_id=$3 AND lease_token_digest=digest(convert_to($4::text,'UTF8'),'sha256') AND settled_at IS NULL FROM zasp_security_agent_provider_reservations WHERE run_id=$1`, run, digest, workerID, lease).Scan(&bound); err != nil || !bound {
						t.Fatalf("reservation binding changed: %v", err)
					}
				}
				var noExecution bool
				if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_plans) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_steps) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_test_links) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_runs) AND NOT EXISTS(SELECT 1 FROM zasp_red_team_outbox)`).Scan(&noExecution); err != nil || !noExecution {
					t.Fatalf("reservation executed work: %v", err)
				}
			})
		}
		t.Run("core_acl_and_release_drift", func(t *testing.T) {
			const signature = "public.zasp_production_security_agent_existing_tests_reserve_core(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)"
			var private bool
			if err := owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM unnest(ARRAY['zasp_discovery_api','zasp_discovery_worker','zasp_security_agent_api','zasp_security_agent_worker','zasp_security_agent_action_worker']) role_name WHERE has_function_privilege(role_name,$1,'EXECUTE'))`, signature).Scan(&private); err != nil || !private {
				t.Fatalf("private core grant leaked: %v", err)
			}
			args := []any{org, ws, env, "pid_89700100-0000-4000-8000-000000000001", workerID, lease, 1, "core-denial", make([]byte, 32), "fixture-model", "fixture-policy", "openrouter_credit", int64(100), int64(200)}
			var raw json.RawMessage
			var pg *pgconn.PgError
			if err := worker.QueryRow(ctx, strings.Replace(existingTestReserveSQL, "_reserve_planner(", "_reserve_core(", 1), args...).Scan(&raw); !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatalf("worker reached private reservation core: %v", err)
			}
			if _, err := owner.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+signature+` TO PUBLIC`); err != nil {
				t.Fatal(err)
			}
			defer owner.Exec(context.Background(), `REVOKE ALL ON FUNCTION `+signature+` FROM PUBLIC`)
			if err := worker.QueryRow(ctx, existingTestReserveSQL, args...).Scan(&raw); !errors.As(err, &pg) || pg.Code != "55000" {
				t.Fatalf("corrupt release reached reservation core: %s %v", raw, err)
			}
		})
	})
}

// SHARE allows the core's reservation reads but blocks its INSERT RowExclusive
// relation lock. Observe that exact relation wait before releasing after expiry.
func existingTestReservationWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, run, mode string, invoke func() error) error {
	t.Helper()
	blocker, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	if _, err := blocker.Exec(ctx, `BEGIN; LOCK TABLE zasp_security_agent_provider_reservations IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	defer blocker.Exec(context.Background(), `ROLLBACK`)
	deadlineSQL := `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING lease_expires_at`
	id := run
	if mode == "insert_wait_budget" {
		deadlineSQL = `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1 RETURNING deadline_at`
	}
	if mode == "insert_wait_target" {
		deadlineSQL = `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE id=$1 RETURNING fresh_until`
		id = "pid_89000011-0000-4000-8000-000000000001"
		defer owner.Exec(context.Background(), `UPDATE zasp_inventory_entities SET fresh_until=clock_timestamp()+interval '1 hour' WHERE id=$1`, id)
	}
	var deadline time.Time
	if err := owner.QueryRow(ctx, deadlineSQL, id).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- invoke() }()
	joined := false
	defer func() {
		if !joined {
			blocker.Exec(context.Background(), `ROLLBACK`)
			<-done
		}
	}()
	observed := false
	for time.Now().Before(deadline) {
		if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AND clock_timestamp()<$2::timestamptz AND EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='zasp_security_agent_provider_reservations'::regclass AND mode='RowExclusiveLock' AND NOT granted)`, worker.PgConn().PID(), deadline).Scan(&observed); err != nil {
			t.Fatal(err)
		}
		if observed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("reservation INSERT blocker not observed before expiry")
	}
	for {
		var expired bool
		if err := blocker.QueryRow(ctx, `SELECT clock_timestamp()>$1::timestamptz`, deadline).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := blocker.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	return err
}
