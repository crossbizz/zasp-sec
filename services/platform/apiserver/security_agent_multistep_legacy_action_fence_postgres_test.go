package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// All effect, target, and deployment rows in these tests are owner fixtures.
// They prove a dormant compatibility boundary, not a release61 claim/adapter.
func TestSecurityAgentMultistepLegacyActionSelectionPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		for index, mode := range []string{"pending", "expired_lease", "stopped_partial", "cleanup_due", "cleanup_no_target"} {
			t.Run(mode, func(t *testing.T) {
				r, s := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 500+index, true)
				q := map[string]string{
					"pending":           `UPDATE zasp_security_agent_effects SET state='pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1`,
					"expired_lease":     `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
					"stopped_partial":   `UPDATE zasp_security_agent_effects SET state='pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$1; UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`,
					"cleanup_due":       `UPDATE zasp_security_agent_effects SET state='cleanup_pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
					"cleanup_no_target": `UPDATE zasp_security_agent_effects SET state='cleanup_pending',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_security_agent_runs SET state='contained' WHERE run_id=$1`,
				}[mode]
				if mode == "stopped_partial" || mode == "cleanup_due" {
					seedOrderedActionTarget(t, ctx, owner, o, w, e, r, s, "apply", "stored")
					if mode == "cleanup_due" {
						if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_temporary_policy_targets SET state='verified',verified_at=clock_timestamp() WHERE run_id=$1 AND phase='apply'`, r); err != nil {
							t.Fatal(err)
						}
					}
				}
				if _, err := owner.Exec(ctx, q, pgx.QueryExecModeSimpleProtocol, r); err != nil {
					t.Fatal(err)
				}
				before := orderedActionFenceSnapshot(t, ctx, owner, r)
				var result json.RawMessage
				if err := action.QueryRow(ctx, `SELECT zasp_security_agent_claim_temporary_policy_effects('legacy-action','legacy-action-lease',60,25)`).Scan(&result); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(result), r) || orderedActionFenceSnapshot(t, ctx, owner, r) != before {
					t.Error("legacy claim/recovery selected or mutated ordered work", string(result))
				}
			})
		}
	})
}

func TestSecurityAgentMultistepLegacyActionPointFencePostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		for index, mode := range []string{"heartbeat", "store", "store_v27", "source", "apply", "cleanup", "cleanup_cancelled", "cleanup_failed"} {
			t.Run(mode, func(t *testing.T) {
				r, s := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 510+index, true)
				phase := "apply"
				if strings.HasPrefix(mode, "cleanup") || strings.HasPrefix(mode, "store") || mode == "source" {
					phase = "cleanup"
				}
				seedOrderedActionTarget(t, ctx, owner, o, w, e, r, s, phase, "stored")
				if strings.HasPrefix(mode, "cleanup_") {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state=$2,completed_at=clock_timestamp() WHERE run_id=$1`, r, strings.TrimPrefix(mode, "cleanup_")); err != nil {
						t.Fatal(err)
					}
				}
				before := orderedActionFenceSnapshot(t, ctx, owner, r)
				var result json.RawMessage
				var err error
				switch mode {
				case "heartbeat":
					err = action.QueryRow(ctx, `SELECT zasp_security_agent_heartbeat_temporary_policy_effect($1,$2,$3,$4,$5,'legacy-action','legacy-action-lease',60)`, o, w, e, r, s).Scan(&result)
				case "store", "store_v27", "source":
					// Exact stored replay must still hit the boundary before either old
					// target-first or effect-first row acquisition.
					name := map[string]string{"store": "zasp_security_agent_store_temporary_policy_target", "store_v27": "zasp_security_agent_store_temporary_policy_target_v27", "source": "zasp_policy_deployment_store_temporary_source"}[mode]
					caller := action
					if mode == "source" {
						caller = owner
					}
					err = orderedActionStore(ctx, owner, caller, name, o, w, e, r, s, phase, &result)
				default:
					err = orderedActionFinish(ctx, owner, action, o, w, e, r, s, phase, &result)
				}
				assertOrderedActionRefused(t, err)
				if orderedActionFenceSnapshot(t, ctx, owner, r) != before {
					t.Error("legacy point lane changed ordered effect/target/deployment/parent authority")
				}
			})
		}
	})
}

func TestSecurityAgentMultistepLegacyActionInverseWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		r, s := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 530, true)
		legacyRun, _ := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 531, false)
		seedOrderedActionTarget(t, ctx, owner, o, w, e, r, s, "cleanup", "stored")
		if _, err := action.Exec(ctx, `SET lock_timeout='200ms'`); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"finish", "heartbeat", "recovery"} {
			t.Run(mode, func(t *testing.T) {
				if mode == "recovery" {
					if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN($1,$2)`, r, legacyRun); err != nil {
						t.Fatal(err)
					}
				}
				blocker, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocker.Rollback(ctx)
				// This is the downstream half of the old inverse wait: the ordered
				// writer already owns run/step/effect. No legacy lane may wait here.
				if _, err = blocker.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE; SELECT 1 FROM zasp_security_agent_steps WHERE run_id=$1 ORDER BY step_index FOR UPDATE; SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 FOR UPDATE`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
					t.Fatal(err)
				}
				var result json.RawMessage
				if mode == "finish" {
					err = orderedActionFinish(ctx, owner, action, o, w, e, r, s, "cleanup", &result)
				} else if mode == "heartbeat" {
					err = action.QueryRow(ctx, `SELECT zasp_security_agent_heartbeat_temporary_policy_effect($1,$2,$3,$4,$5,'legacy-action','legacy-action-lease',60)`, o, w, e, r, s).Scan(&result)
				} else {
					err = action.QueryRow(ctx, `SELECT zasp_security_agent_claim_temporary_policy_effects('legacy-action','legacy-action-lease',60,25)`).Scan(&result)
				}
				if mode == "recovery" {
					var claims struct {
						Items []struct {
							RunID string `json:"run_id"`
						} `json:"items"`
					}
					if err != nil || json.Unmarshal(result, &claims) != nil || len(claims.Items) != 1 || claims.Items[0].RunID != legacyRun {
						t.Error("legacy recovery waited on ordered work or starved single-step work", string(result), err)
					}
				} else {
					assertOrderedActionRefused(t, err)
				}
			})
		}
	})
}

func TestSecurityAgentMultistepLegacyActionSingleStepPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		r, s := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 540, false)
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, r); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		if err := action.QueryRow(ctx, `SELECT zasp_security_agent_claim_temporary_policy_effects('legacy-action','legacy-action-lease',60,25)`).Scan(&result); err != nil || !strings.Contains(string(result), r) || !strings.Contains(string(result), `"phase": "apply"`) {
			t.Fatal("legacy recovery/claim changed", string(result), err)
		}
		if err := action.QueryRow(ctx, `SELECT zasp_security_agent_heartbeat_temporary_policy_effect($1,$2,$3,$4,$5,'legacy-action','legacy-action-lease',60)`, o, w, e, r, s).Scan(&result); err != nil {
			t.Fatal("legacy heartbeat changed", err)
		}
		for _, phase := range []string{"apply", "cleanup"} {
			if err := orderedActionStore(ctx, owner, action, "zasp_security_agent_store_temporary_policy_target", o, w, e, r, s, phase, &result); err != nil {
				t.Fatal("legacy store changed", phase, err)
			}
			// The deployment worker is outside this fence packet. Owner evidence
			// models its durable acknowledgement for the legacy completion test.
			if _, err := owner.Exec(ctx, `UPDATE zasp_policy_deployment_work SET applied_generation=desired_generation WHERE device_id=$1`, r); err != nil {
				t.Fatal(err)
			}
			if err := orderedActionFinish(ctx, owner, action, o, w, e, r, s, phase, &result); err != nil {
				t.Fatal("legacy finish changed", phase, err)
			}
			want := "contained"
			if phase == "cleanup" {
				want = "remediated"
			}
			var state string
			if err := owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&state); err != nil || state != want {
				t.Fatal("legacy parent postcondition changed", state, err)
			}
			if phase == "apply" {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET updated_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, r); err != nil {
					t.Fatal(err)
				}
				if err := action.QueryRow(ctx, `SELECT zasp_security_agent_claim_temporary_policy_effects('legacy-action','legacy-action-lease',60,25)`).Scan(&result); err != nil || !strings.Contains(string(result), `"phase": "cleanup"`) {
					t.Fatal("legacy cleanup claim changed", string(result), err)
				}
			}
		}
	})
}

func TestSecurityAgentMultistepLegacyActionAdmissionWaitPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string) {
		action := orderedActionFenceConnection(t, ctx, owner)
		defer action.Close(ctx)
		if _, err := action.Exec(ctx, `SET statement_timeout='5s'`); err != nil {
			t.Fatal(err)
		}
		for index, barrier := range []string{"schema", "organization"} {
			t.Run(barrier, func(t *testing.T) {
				r, s := seedOrderedActionFence(t, ctx, owner, worker, api, o, w, e, testID, actor, 550+index, true)
				tx, err := owner.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				key := "zasp-schema-migrations"
				if barrier == "organization" {
					key = "security-agent-budget-admission:" + o
				}
				if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					var result json.RawMessage
					done <- action.QueryRow(ctx, `SELECT zasp_security_agent_heartbeat_temporary_policy_effect($1,$2,$3,$4,$5,'legacy-action','legacy-action-lease',60)`, o, w, e, r, s).Scan(&result)
				}()
				joined, waiting := false, false
				var finish error
				defer func() {
					tx.Rollback(ctx)
					owner.Exec(ctx, `RESET SESSION AUTHORIZATION`)
					if !joined {
						<-done
					}
				}()
				for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					select {
					case finish = <-done:
						joined = true
					default:
					}
					if joined {
						break
					}
					if err = tx.QueryRow(ctx, `SELECT $1=ANY(pg_blocking_pids($2))`, owner.PgConn().PID(), action.PgConn().PID()).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting {
						break
					}
				}
				if !waiting {
					t.Fatalf("legacy action bypassed %s admission: %v", barrier, finish)
				}
				if _, err = tx.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE NOWAIT; SELECT 1 FROM zasp_security_agent_steps WHERE run_id=$1 ORDER BY step_index FOR UPDATE NOWAIT; SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1 FOR UPDATE NOWAIT`, pgx.QueryExecModeSimpleProtocol, r); err != nil {
					t.Fatal("legacy lane acquired downstream locks ahead of admission", err)
				}
				// Use the actual release61 cancellation authority on the blocker
				// backend. It already holds the ordered fence and remains able to
				// take run/step/effect in order while the legacy lane waits.
				if _, err = tx.Exec(ctx, `SET SESSION AUTHORIZATION security_agent_v33_api_login`); err != nil {
					t.Fatal(err)
				}
				if _, err = orderedProgressionCall(ctx, owner, "transition", orderedProgressionRequest(o, w, e, r, s, "cancel", orderedProgressionApprover, 4)); err != nil {
					t.Fatal("ordered cancellation blocked by legacy lane", err)
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err = owner.Exec(ctx, `RESET SESSION AUTHORIZATION`); err != nil {
					t.Fatal(err)
				}
				finish, joined = <-done, true
				assertOrderedActionRefused(t, finish)
				var state string
				if err = owner.QueryRow(ctx, `SELECT state FROM zasp_security_agent_runs WHERE run_id=$1`, r).Scan(&state); err != nil || state != "cancelled" {
					t.Fatal("legacy writer changed cancellation after its admission wait", state, err)
				}
			})
		}
	})
}

var orderedLegacyActionNames = append([]string{"zasp_security_agent_claim_temporary_policy_effects", "zasp_security_agent_heartbeat_temporary_policy_effect", "zasp_security_agent_finish_temporary_policy_effect", "zasp_security_agent_store_temporary_policy_target", "zasp_security_agent_store_temporary_policy_target_v27", "zasp_policy_deployment_store_temporary_source"}, orderedLegacyExecuteNames...)

func TestSecurityAgentMultistepLegacyActionRestorationPostgres(t *testing.T) {
	runOrderedProgressionFixture(t, func(ctx context.Context, owner, _, _ *pgx.Conn, _, _, _, _, _ string) {
		for _, name := range orderedLegacyActionNames {
			for _, drift := range []string{"definition", "owner", "acl", "saved_definition", "saved_owner", "saved_acl"} {
				t.Run(name+"/"+drift, func(t *testing.T) {
					tx, err := owner.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					var signature, definition string
					if err = tx.QueryRow(ctx, `SELECT signature,definition FROM zasp_sa_multistep_prior.functions WHERE split_part(signature,'(',1)=$1`, "public."+name).Scan(&signature, &definition); err != nil {
						t.Fatal("missing exact action-lane restoration snapshot", err)
					}
					switch drift {
					case "definition":
						_, err = tx.Exec(ctx, definition)
					case "owner":
						_, err = tx.Exec(ctx, `ALTER FUNCTION `+signature+` OWNER TO CURRENT_USER`)
					case "acl":
						_, err = tx.Exec(ctx, `GRANT EXECUTE ON FUNCTION `+signature+` TO PUBLIC`)
					case "saved_definition":
						_, err = tx.Exec(ctx, `UPDATE zasp_sa_multistep_prior.functions SET definition=definition||E'\n-- action drift' WHERE signature=$1`, signature)
					case "saved_owner":
						_, err = tx.Exec(ctx, `UPDATE zasp_sa_multistep_prior.functions SET owner_name=session_user WHERE signature=$1`, signature)
					case "saved_acl":
						_, err = tx.Exec(ctx, `UPDATE zasp_sa_multistep_prior.functions SET acl='[]' WHERE signature=$1`, signature)
					}
					if err != nil {
						t.Fatal(err)
					}
					var ready bool
					if err = tx.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&ready); err != nil || ready {
						t.Fatal("unfingerprinted legacy action fence", ready, err)
					}
					runner, _ := migrations.NewRunner(&registeredMultistepDatabase{connection: owner, t: t, outer: tx})
					if err = runner.DownProductionSecurityAgentMultistep(ctx); !errors.Is(err, migrations.ErrInvalidState) {
						t.Fatal("rollback accepted action-lane restoration drift", err)
					}
				})
			}
		}
	})
}

func TestSecurityAgentMultistepLegacyActionRoundTripPostgres(t *testing.T) {
	multistepVersionedExistingTestFixture(t, func(ctx context.Context, owner, _ *pgx.Conn, _, _, _, _, _ string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		snapshot := func(body bool) string {
			t.Helper()
			var value string
			if err := owner.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_array(p.proname,CASE WHEN $2 THEN pg_get_functiondef(p.oid) END,p.proowner::regrole::text,p.proacl::text) ORDER BY p.proname)::text FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname=ANY($1)`, orderedLegacyActionNames, body).Scan(&value); err != nil {
				t.Fatal(err)
			}
			return value
		}
		before, grants := snapshot(true), snapshot(false)
		for cycle := 0; cycle < 2; cycle++ {
			if err := runner.UpProductionSecurityAgentMultistep(ctx); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM zasp_sa_multistep_prior.functions WHERE substring(split_part(signature,'(',1) FROM 8)=ANY($1)`, orderedLegacyActionNames).Scan(&count); err != nil || count != len(orderedLegacyActionNames) {
				t.Error("legacy action restoration evidence incomplete", count, err)
			}
			if snapshot(true) == before {
				t.Error("registered action lanes have no ordered boundary")
			}
			if snapshot(false) != grants {
				t.Fatal("promotion changed historical action owners or public execute ACL bytes/order")
			}
			if err := runner.DownProductionSecurityAgentMultistep(ctx); err != nil {
				t.Fatal(err)
			}
			if snapshot(true) != before {
				t.Fatal("legacy definitions, owner or execute ACL bytes/order not restored")
			}
		}
	})
}

func orderedActionFenceConnection(t *testing.T, ctx context.Context, owner *pgx.Conn) *pgx.Conn {
	t.Helper()
	if _, err := owner.Exec(ctx, `CREATE ROLE ordered_legacy_action_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; SELECT zasp_security_agent_register_action_principal(session_user,'ordered_legacy_action_login')`); err != nil {
		t.Fatal(err)
	}
	config := owner.Config().Copy()
	config.User = "ordered_legacy_action_login"
	action, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	var ready bool
	if err = action.QueryRow(ctx, `SELECT zasp_security_agent_action_principal_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatal("action principal", ready, err)
	}
	return action
}

func seedOrderedActionFence(t *testing.T, ctx context.Context, owner, worker, api *pgx.Conn, o, w, e, testID, actor string, index int, ordered bool) (string, string) {
	t.Helper()
	request := seedOrderedAdmission(t, ctx, owner, o, w, e, testID, actor, index)
	r := request["run_id"].(string)
	s := r
	if ordered {
		admitted, err := orderedProgressionCall(ctx, worker, "admit", request)
		if err != nil {
			t.Fatal(err)
		}
		s = admitted["step_ids"].([]any)[0].(string)
		if _, err = orderedProgressionCall(ctx, api, "transition", orderedProgressionRequest(o, w, e, r, s, "approve", orderedProgressionApprover, 3)); err != nil {
			t.Fatal(err)
		}
	} else if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(jsonb_set(body,'{allowed_actions}','["create_temporary_policy"]'),'{max_steps}','1') WHERE definition_id=$5;
 INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at) VALUES($1,$2,$3,$4,$5,1,decode(repeat('cd',32),'hex'),'security-agent-actions-v1',jsonb_build_object('steps',jsonb_build_array(jsonb_build_object('step_id',$4,'action','create_temporary_policy','ttl_seconds',600))),digest(convert_to($4,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour');
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES($1,$2,$3,$4,$4,0,'create_temporary_policy',digest(convert_to($4,'UTF8'),'sha256'),'approval_required','executing');
 UPDATE zasp_security_agent_runs SET state='running',plan_hash=digest(convert_to($4,'UTF8'),'sha256'),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE run_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, request["definition_id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state) VALUES($1,$2,$3,$4,'Legacy fence fixture','active');
 INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES($1,$2,$3,$4,$4,'runtime-gateway-enroll',decode(repeat('01',16),'hex'),digest(convert_to($4,'UTF8'),'sha256'),clock_timestamp()+interval '1 hour');
 INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES($1,$2,$3,$4,$4,$4,decode(repeat('03',32),'hex'),'runtime-gateway','ref:gateway/public/gateway-device-key-01',decode(repeat('04',32),'hex'),clock_timestamp()+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',clock_timestamp());
 INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,lease_owner,lease_token,lease_expires_at) SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,'leased','legacy-action','legacy-action-lease',clock_timestamp()+interval '1 hour' FROM zasp_security_agent_steps WHERE run_id=$4 AND step_id=$5;
 INSERT INTO zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) SELECT organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest FROM zasp_security_agent_steps WHERE run_id=$4 AND step_id=$5`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, s); err != nil {
		t.Fatal(err)
	}
	return r, s
}

func seedOrderedActionTarget(t *testing.T, ctx context.Context, owner *pgx.Conn, o, w, e, r, s, phase, state string) {
	t.Helper()
	if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version,state,key_id,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest,stored_at,desired_generation) VALUES($1,$2,$3,$4,$5,$6,$4,$4,1,1,$7,'fixture-key-01',transaction_timestamp(),transaction_timestamp()+CASE WHEN $6='apply' THEN interval '10 minutes' ELSE interval '5 minutes' END,'closed',decode(repeat('ab',32),'hex'),'[]',decode(repeat('ab',64),'hex'),decode(repeat('ab',32),'hex'),transaction_timestamp(),1) ON CONFLICT DO NOTHING;
 UPDATE zasp_policy_deployment_work SET applied_generation=desired_generation WHERE device_id=$4`, pgx.QueryExecModeSimpleProtocol, o, w, e, r, s, phase, state); err != nil {
		t.Fatal(err)
	}
}

func orderedActionStore(ctx context.Context, owner, action *pgx.Conn, name, o, w, e, r, s, phase string, result *json.RawMessage) error {
	var issued, expires time.Time
	var sequence, version int64
	if err := owner.QueryRow(ctx, `SELECT sequence,policy_version,COALESCE(issued_at,clock_timestamp()),COALESCE(expires_at,clock_timestamp()+CASE WHEN phase='apply' THEN interval '10 minutes' ELSE interval '5 minutes' END) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$1 AND step_id=$2 AND phase=$3 AND device_id=$1`, r, s, phase).Scan(&sequence, &version, &issued, &expires); err != nil {
		return err
	}
	// Planned claim rows have no signed timestamps. Derive the exact TTL.
	if phase == "apply" {
		expires = issued.Add(10 * time.Minute)
	} else {
		expires = issued.Add(5 * time.Minute)
	}
	return action.QueryRow(ctx, `SELECT `+name+`($1,$2,$3,$4,$5,$6,'legacy-action','legacy-action-lease',$4,$4,$7,$8,'fixture-key-01',$9,$10,'closed',decode(repeat('ab',32),'hex'),'[]',decode(repeat('ab',64),'hex'),decode(repeat('ab',32),'hex'))`, o, w, e, r, s, phase, sequence, version, issued, expires).Scan(result)
}

func orderedActionFinish(ctx context.Context, owner, action *pgx.Conn, o, w, e, r, s, phase string, result *json.RawMessage) error {
	// Build the legacy wire result from owner fixture evidence. Action workers
	// have no direct table reads; only the production finish function mutates.
	var digest []byte
	var audit string
	if err := owner.QueryRow(ctx, `SELECT digest(input_digest||decode(repeat('ab',32),'hex'),'sha256'),zasp_discovery_canonical_id($1,$2,$3,'security_agent_audit',$4||$6) FROM zasp_security_agent_steps WHERE run_id=$4 AND step_id=$5`, o, w, e, r, s, phase).Scan(&digest, &audit); err != nil {
		return err
	}
	return action.QueryRow(ctx, `SELECT zasp_security_agent_finish_temporary_policy_effect($1,$2,$3,$4,$5,$6,'legacy-action','legacy-action-lease',$7,$8,$8)`, o, w, e, r, s, phase, digest, audit).Scan(result)
}

func orderedActionFenceSnapshot(t *testing.T, ctx context.Context, owner *pgx.Conn, r string) string {
	t.Helper()
	var extra string
	if err := owner.QueryRow(ctx, `SELECT jsonb_build_object('targets',(SELECT jsonb_agg(to_jsonb(t) ORDER BY phase,device_id) FROM zasp_security_agent_temporary_policy_targets t WHERE run_id=$1),'work',(SELECT to_jsonb(w) FROM zasp_policy_deployment_work w WHERE device_id=$1),'bundles',(SELECT jsonb_agg(to_jsonb(b) ORDER BY sequence) FROM zasp_runtime_gateway_policy_bundles b WHERE device_id=$1),'controls',(SELECT jsonb_agg(to_jsonb(c) ORDER BY control_id) FROM zasp_security_agent_controls c WHERE run_id=$1))::text`, r).Scan(&extra); err != nil {
		t.Fatal(err)
	}
	return orderedAdmissionSnapshot(t, ctx, owner, r) + extra
}

func assertOrderedActionRefused(t *testing.T, err error) {
	t.Helper()
	var provider *pgconn.PgError
	if !errors.As(err, &provider) || provider.Code != "55000" || !strings.Contains(provider.Message, "ordered") {
		t.Errorf("expected early ordered action refusal, got %v", err)
	}
}
