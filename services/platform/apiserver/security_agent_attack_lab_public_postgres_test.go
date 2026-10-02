package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestSecurityAgentAttackLabControlHistoryBlocksRollbackPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, definition, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		var result json.RawMessage
		args := []any{o, w, e, actor, "attack-control-rollback-0001", "action", "start_attack_lab", false, int64(0), time.Now().UTC().Add(time.Minute), "pid_8ba20000-0000-4000-8000-000000000001", "pid_8ba20000-0000-4000-8000-000000000002", "pid_8ba20000-0000-4000-8000-000000000003"}
		if err := api.QueryRow(ctx, postgresExistingTestSetControlSQL, existingTestReadPins(args)...).Scan(&result); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentAttackLab(ctx); err == nil {
			t.Fatal("rollback concealed disabled Attack Lab control history")
		}
		// Fault injection isolates the receipt-only guard. No browser workflow
		// uses this owner mutation, and the fixture is discarded afterwards.
		if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=($1,$2,$3,'start_attack_lab')`, o, w, e); err != nil {
			t.Fatal(err)
		}
		if err := runner.DownProductionSecurityAgentAttackLab(ctx); err == nil {
			t.Fatal("rollback concealed Attack Lab control receipt history")
		}
	})
}

func TestSecurityAgentAttackLabRegisteredPublicProjectionPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, definition, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		var controlsJSON json.RawMessage
		if err := api.QueryRow(ctx, postgresExistingTestControlsSQL, existingTestReadPins([]any{o, w, e})...).Scan(&controlsJSON); err != nil {
			t.Fatal(err)
		}
		var controls SecurityAgentExecutionControls
		if json.Unmarshal(controlsJSON, &controls) != nil || len(controls.Actions) != 7 || controls.Actions[5].ActionKey != "start_attack_lab" {
			t.Fatalf("registered57 controls omit Attack Lab: %s", controlsJSON)
		}
		exerciseAttackLabRegisteredDispatch(t, ctx, owner, api, o, w, e, definition, actor, true, false, func(approval, approver string) {
			identity := fixtureRequestIdentity(t)
			org, _ := domain.ParseProductID(o)
			workspace, _ := domain.ParseProductID(w)
			environment, _ := domain.ParseProductID(e)
			identity.Scope, _ = domain.NewScope(org, workspace, environment)
			identity.PrincipalID, _ = domain.ParseProductID(approver)
			identity.FreshAuthenticated = true
			identity.FreshAuthExpiresAt = time.Now().UTC().Add(time.Minute)
			db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
			if err != nil {
				t.Fatal(err)
			}
			observed := &attackLabReplayDatabase{PostgresJSONDatabase: db}
			repository, err := NewSecurityAgentPostgresRepository(observed)
			if err != nil {
				t.Fatal(err)
			}
			input := SecurityAgentApprovalDecisionRequest{ApprovalID: approval, IdempotencyKey: "attack-lab-approval-0001", ExpectedVersion: 1, Decision: "approved", FreshAuthAt: time.Now().UTC(), AuditID: "pid_8a100008-0000-4000-8000-000000000008", CorrelationID: "pid_8a100009-0000-4000-8000-000000000009", ReceiptID: "pid_8a10000a-0000-4000-8000-00000000000a"}
			for _, replay := range []bool{false, true} {
				result, err := repository.DecideSecurityAgentApproval(ctx, identity, input)
				if err != nil {
					var safe struct {
						Reversible bool   `json:"reversible"`
						TTL        int    `json:"ttl_seconds"`
						State      string `json:"state"`
						Version    int    `json:"version"`
					}
					_ = json.Unmarshal(observed.last, &safe)
					t.Fatalf("registered decision replay=%v rejected: %v; safe fields=%+v", replay, err, safe)
				}
				if result.Replayed != replay || result.Reversible || result.TTLSeconds != 0 || result.Version != 2 || len(result.AttackLab) == 0 {
					t.Fatal("decision lost bounded immutable approval semantics")
				}
				read, err := repository.GetSecurityAgentApproval(ctx, identity, approval)
				if err != nil || read.Reversible || read.TTLSeconds != 0 || read.Version != 2 || string(read.AttackLab) != string(result.AttackLab) {
					t.Fatalf("decision/read mismatch: %v", err)
				}
			}
			var receipts, audits, version int
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_request_receipts WHERE principal_id=$1 AND operation='decideSecurityAgentApproval' AND idempotency_key='attack-lab-approval-0001'),(SELECT count(*) FROM zasp_security_agent_audit WHERE audit_id=$2),(SELECT version FROM zasp_security_agent_approvals WHERE approval_id=$3)`, approver, input.AuditID, approval).Scan(&receipts, &audits, &version); err != nil || receipts != 1 || audits != 1 || version != 2 {
				t.Fatalf("decision replay changed durable history: receipts=%d audits=%d version=%d error=%v", receipts, audits, version, err)
			}
		})
		var run string
		if err := owner.QueryRow(ctx, `SELECT run_id FROM zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&run); err != nil {
			t.Fatal(err)
		}
		var raw json.RawMessage
		if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, existingTestReadPins([]any{o, w, e, run})...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		detail, err := decodeSecurityAgentRunContextEnvelope(raw, run)
		if err != nil {
			t.Fatalf("registered read rejected linked pending projection: %v", err)
		}
		if len(detail.ActionDetails) != 1 || detail.ActionDetails[0].AttackLab == nil {
			t.Fatal("registered read omitted linked Attack Lab execution")
		}
		public, err := json.Marshal(detail)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"s3://", "source_evidence", "credential_reference", "sandbox_reference", "\"key\"", "decision_digest"} {
			if strings.Contains(string(public), secret) {
				t.Fatalf("private authority escaped: %s", secret)
			}
		}
		if detail.ActionDetails[0].AttackLab.CleanupComplete || detail.ActionDetails[0].AttackLab.Settlement != nil {
			t.Fatal("pending cleanup reported settled")
		}
		exerciseAttackLabPublicCancellation(t, ctx, owner, api, o, w, e, run, "pid_8a100005-0000-4000-8000-000000000005")
		if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, existingTestReadPins([]any{o, w, e, run})...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		stopped, err := decodeSecurityAgentRunContextEnvelope(raw, run)
		if err != nil || len(stopped.ActionDetails) != 1 || stopped.ActionDetails[0].AttackLab == nil || stopped.ActionDetails[0].AttackLab.ExecutionID != detail.ActionDetails[0].AttackLab.ExecutionID {
			t.Fatalf("stopped parent hid cleanup: %v", err)
		}
		for i := 0; i < 3; i++ {
			args := []any{o, w, e, run}
			args[i] = "pid_89ffffff-0000-4000-8000-000000000001"
			if err := api.QueryRow(ctx, postgresExistingTestRunContextSQL, existingTestReadPins(args)...).Scan(&raw); err != pgx.ErrNoRows {
				t.Fatalf("foreign scope %d returned linked proof: %v", i, err)
			}
		}
	})
}

func exerciseAttackLabPublicCancellation(t *testing.T, ctx context.Context, owner, api *pgx.Conn, o, w, e, run, actor string) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	org, _ := domain.ParseProductID(o)
	workspace, _ := domain.ParseProductID(w)
	environment, _ := domain.ParseProductID(e)
	identity.Scope, _ = domain.NewScope(org, workspace, environment)
	identity.PrincipalID, _ = domain.ParseProductID(actor)
	db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewSecurityAgentPostgresRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	var version int64
	var parentState string
	var admissionDigest []byte
	if err := owner.QueryRow(ctx, `SELECT result_digest FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='start_attack_lab'`, run).Scan(&admissionDigest); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(ctx, `SELECT version,state FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&version, &parentState); err != nil {
		t.Fatal(err)
	}
	if parentState != "running" && parentState != "verifying" {
		t.Fatalf("public cancellation requires a pending parent, got %s", parentState)
	}
	input := SecurityAgentCancelRequest{RunID: run, ExpectedVersion: version, IdempotencyKey: "attack-parent-stop-0001", AuditID: "pid_8bc10000-0000-4000-8000-000000000001", CorrelationID: "pid_8bc10000-0000-4000-8000-000000000002", ReceiptID: "pid_8bc10000-0000-4000-8000-000000000003"}
	snapshot := func() string {
		var value string
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(r)) FROM zasp_security_agent_runs r WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(f)) FROM zasp_security_agent_effects f WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(l)) FROM zasp_sa_attack_lab_links l WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(s)) FROM zasp_security_agent_steps s WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(a)) FROM zasp_security_agent_approvals a WHERE run_id=$1),(SELECT jsonb_agg(to_jsonb(x)) FROM zasp_attack_lab_runs x WHERE (organization_id,workspace_id,environment_id)=($2,$3,$4)),(SELECT jsonb_agg(to_jsonb(q)) FROM zasp_attack_lab_outbox q WHERE (organization_id,workspace_id,environment_id)=($2,$3,$4)),(SELECT jsonb_agg(to_jsonb(c)) FROM zasp_attack_lab_cleanup_checkpoints c WHERE (organization_id,workspace_id,environment_id)=($2,$3,$4)),(SELECT count(*) FROM zasp_security_agent_request_receipts),(SELECT count(*) FROM zasp_security_agent_audit))::text`, run, o, w, e).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, mode := range []string{"stale", "foreign", "completed_effect", "mixed_effect"} {
		t.Run("cancel_refuses_"+mode, func(t *testing.T) {
			candidate := input
			who := identity
			switch mode {
			case "stale":
				candidate.ExpectedVersion--
			case "foreign":
				foreign, _ := domain.ParseProductID("pid_8bffffff-0000-4000-8000-000000000001")
				who.Scope, _ = domain.NewScope(org, workspace, foreign)
			case "completed_effect":
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET state='succeeded',result_digest=digest('complete','sha256') WHERE run_id=$1`, run); err != nil {
					t.Fatal(err)
				}
			case "mixed_effect":
				if _, err := owner.Exec(ctx, `INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state) SELECT organization_id,workspace_id,environment_id,run_id,step_id,'run_test',input_digest,'pending' FROM zasp_security_agent_effects WHERE run_id=$1`, run); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshot()
			if _, err := repository.CancelSecurityAgentRun(ctx, who, candidate); err == nil || snapshot() != before {
				t.Fatalf("unsafe cancellation accepted/changed rows: %v", err)
			}
			if mode == "completed_effect" {
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_effects SET state='pending',result_digest=$2 WHERE run_id=$1`, run, admissionDigest); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "mixed_effect" {
				if _, err := owner.Exec(ctx, `DELETE FROM zasp_security_agent_effects WHERE run_id=$1 AND action_key='run_test'`, run); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, replay := range []bool{false, true} {
		{
			// Real lock wait: permission revocation commits while cancellation is
			// waiting on the parent. No rejected call may touch the child.
			var permissions json.RawMessage
			if err := owner.QueryRow(ctx, `SELECT permissions FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor).Scan(&permissions); err != nil {
				t.Fatal(err)
			}
			tx, err := owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, run); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := repository.CancelSecurityAgentRun(ctx, identity, input); done <- err }()
			blocked := false
			for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
				if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=$1),false)`, api.PgConn().PID()).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !blocked {
				_ = tx.Rollback(ctx)
				<-done
				t.Fatal("cancellation did not wait on parent lock")
			}
			if _, err := tx.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions='["view"]' WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor); err != nil {
				t.Fatal(err)
			}
			before := snapshot()
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			cancelErr := <-done
			if _, err := owner.Exec(ctx, `UPDATE zasp_authorized_scopes SET permissions=$5 WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, o, w, e, actor, permissions); err != nil {
				t.Fatal(err)
			}
			if cancelErr == nil || snapshot() != before {
				t.Fatalf("revoked-while-waiting cancellation mutated authority: %v", cancelErr)
			}
			t.Logf("registered cancellation replay=%v refused revoked authority after parent lock wait with full rows unchanged", replay)
		}
		var result SecurityAgentRunResult
		if !replay {
			// Dispatch replay and public cancellation must serialize on the same
			// parent/admission locks. Neither order may create another effect.
			raceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			config := owner.Config().Copy()
			config.User = "security_agent_v33_worker_login"
			worker, connectErr := pgx.ConnectConfig(raceCtx, config)
			if connectErr != nil {
				t.Fatal(connectErr)
			}
			defer worker.Close(context.Background())
			gate, gateErr := owner.Begin(raceCtx)
			if gateErr != nil {
				t.Fatal(gateErr)
			}
			defer gate.Rollback(context.Background())
			if _, gateErr = gate.Exec(raceCtx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, run); gateErr != nil {
				t.Fatal(gateErr)
			}
			cancelDone, dispatchDone := make(chan error, 1), make(chan error, 1)
			go func() {
				var callErr error
				result, callErr = repository.CancelSecurityAgentRun(raceCtx, identity, input)
				cancelDone <- callErr
			}()
			go func() {
				var raw json.RawMessage
				dispatchDone <- worker.QueryRow(raceCtx, `SELECT zasp_sa_attack_lab_execute_run($1,$2,$3,$4,'attack-lab-worker','attack-lab-dispatch-lease','pid_8bc20000-0000-4000-8000-000000000001','pid_8bc20000-0000-4000-8000-000000000002',$5,$6)`, o, w, e, run, migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint()).Scan(&raw)
			}()
			waiting := 0
			for raceCtx.Err() == nil {
				if err := gate.QueryRow(raceCtx, `SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1) AND wait_event_type='Lock'`, []int32{int32(api.PgConn().PID()), int32(worker.PgConn().PID())}).Scan(&waiting); err != nil {
					break
				}
				if waiting == 2 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if gateErr = gate.Commit(ctx); gateErr != nil {
				t.Fatal(gateErr)
			}
			err = <-cancelDone
			dispatchErr := <-dispatchDone
			if waiting != 2 || dispatchErr != nil {
				t.Fatalf("dispatch/cancel did not serialize: waiting=%d dispatch=%v", waiting, dispatchErr)
			}
			before := snapshot()
			var raw json.RawMessage
			if err := worker.QueryRow(ctx, `SELECT zasp_sa_attack_lab_execute_run($1,$2,$3,$4,'attack-lab-worker','attack-lab-dispatch-lease','pid_8bc20000-0000-4000-8000-000000000001','pid_8bc20000-0000-4000-8000-000000000002',$5,$6)`, o, w, e, run, migrations.ProductionSecurityAgentAttackLab().Checksum(), migrations.SecurityAgentAttackLabFingerprint()).Scan(&raw); err != nil || snapshot() != before {
				t.Fatalf("stopped dispatch replay changed durable rows: %v", err)
			}
			t.Log("public cancellation serialized with registered dispatch replay; stopped replay created no further effect")
		} else {
			result, err = repository.CancelSecurityAgentRun(ctx, identity, input)
		}
		if err != nil || result.Replayed != replay || result.State != "cancelled" || result.Version != version+1 {
			t.Fatalf("pending linked cancellation/replay=%v refused: %v", replay, err)
		}
	}
	var preserved bool
	if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_effects WHERE run_id=$1 AND state='pending' AND result_digest=$2)=1 AND (SELECT count(*) FROM zasp_sa_attack_lab_links WHERE run_id=$1 AND settled_at IS NULL)=1 AND (SELECT count(*) FROM zasp_security_agent_request_receipts WHERE operation='cancelSecurityAgentRun' AND resource_id=$1)=1 AND (SELECT count(*) FROM zasp_security_agent_audit WHERE run_id=$1 AND event_kind='run_cancelled')=1 AND (SELECT lease_owner IS NULL AND lease_token IS NULL AND state='cancelled' FROM zasp_security_agent_runs WHERE run_id=$1)`, run, admissionDigest).Scan(&preserved); err != nil || !preserved {
		t.Fatalf("cancellation discarded cleanup or dispatch fence: %v", err)
	}
}
