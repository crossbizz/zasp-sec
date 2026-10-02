package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Missing dedicated authority must fail, never fall back to an execution login.
func TestSecurityAgentAttackLabSettlementPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, definition, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, migrations.ProductionSecurityAgentAttackLab().UpSQL()); err != nil {
			t.Fatal(err)
		}
		var fingerprint string
		if err := owner.QueryRow(ctx, `SELECT zasp_sa_attack_lab_live_fingerprint()`).Scan(&fingerprint); err != nil {
			t.Fatal(err)
		}
		t.Logf("observed57 fingerprint=%s", fingerprint)
		if fingerprint != migrations.SecurityAgentAttackLabFingerprint() {
			t.Fatal("compiled57 fingerprint differs")
		}
		m := migrations.ProductionSecurityAgentAttackLab()
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_security_agent_attack_lab_checksum',$1),('production_security_agent_attack_lab_fingerprint',$2); INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(57,'production_security_agent_attack_lab',$1); CREATE ROLE attack_lab_settlement_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, pgx.QueryExecModeSimpleProtocol, m.Checksum(), fingerprint); err != nil {
			t.Fatal(err)
		}
		if err := runner.RegisterSecurityAgentAttackLabReconciler(ctx, "attack_lab_settlement_login"); err != nil {
			t.Fatal(err)
		}
		config := owner.Config().Copy()
		config.User = "attack_lab_settlement_login"
		reconciler, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer reconciler.Close(context.Background())
		var raw json.RawMessage
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_scopes('','','','attack-lab-reconciler',$1,$2)`, m.Checksum(), fingerprint).Scan(&raw); err != nil {
			t.Fatalf("dedicated scope authority missing: %v", err)
		}
		if string(raw) != "[]" {
			t.Fatalf("empty scope result=%s", raw)
		}
		if _, err := reconciler.Exec(ctx, `SELECT * FROM zasp_sa_attack_lab_links`); err == nil {
			t.Fatal("reconciler read private links")
		}
		if _, err := reconciler.Exec(ctx, `SELECT zasp_sa_attack_lab_create_run_core(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`); err == nil {
			t.Fatal("reconciler invoked admission core")
		}
		exerciseAttackLabRegisteredDispatch(t, ctx, owner, api, o, w, e, definition, actor, true, false)
		var claims []struct {
			Run        string `json:"run_id"`
			Step       string `json:"step_id"`
			Execution  string `json:"execution_id"`
			Version    int64  `json:"version"`
			Generation string `json:"generation"`
		}
		token := make([]byte, 32)
		token[0] = 1
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_claim($1,$2,$3,'attack-lab-reconciler',$4,60,1,$5,$6)`, o, w, e, token, m.Checksum(), fingerprint).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &claims); err != nil || len(claims) != 1 {
			t.Fatalf("claim=%s %v", raw, err)
		}
		c := claims[0]
		// Stop through registered public authority, without inheriting another
		// test's rollback fault injection as an implicit stopped-parent fixture.
		var parentVersion int64
		if err := owner.QueryRow(ctx, `SELECT version FROM zasp_security_agent_runs WHERE run_id=$1`, c.Run).Scan(&parentVersion); err != nil {
			t.Fatal(err)
		}
		if err := api.QueryRow(ctx, `SELECT zasp_sa_attack_lab_cancel_parent($1,$2,$3,$4,'pid_8a100005-0000-4000-8000-000000000005','settlement-parent-stop-0001',$5,'pid_8bc30000-0000-4000-8000-000000000001','pid_8bc30000-0000-4000-8000-000000000002','pid_8bc30000-0000-4000-8000-000000000003',$6,$7)`, o, w, e, c.Run, parentVersion, m.Checksum(), fingerprint).Scan(&raw); err != nil {
			t.Fatalf("registered parent cancellation: %v", err)
		}
		var admissionReceipt json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT result FROM zasp_sa_attack_lab_links WHERE run_id=$1`, c.Run).Scan(&admissionReceipt); err != nil {
			t.Fatal(err)
		}
		args := []any{o, w, e, c.Run, c.Step, "attack-lab-reconciler", token, c.Version, c.Generation, m.Checksum(), fingerprint}
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_heartbeat($1,$2,$3,$4,$5,$6,$7,$8,$9,60,$10,$11)`, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var renewed struct {
			Version    int64  `json:"version"`
			Generation string `json:"generation"`
		}
		if err := json.Unmarshal(raw, &renewed); err != nil || renewed.Version <= c.Version || renewed.Generation == c.Generation {
			t.Fatalf("replacement heartbeat=%s %v", raw, err)
		}
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&raw); err == nil {
			t.Fatal("superseded heartbeat read evidence")
		}
		args[7], args[8] = renewed.Version, renewed.Generation
		foreign := append([]any(nil), args...)
		foreign[2] = w
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, foreign...).Scan(&raw); err == nil {
			t.Fatal("foreign scope read")
		}
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Snapshot json.RawMessage `json:"snapshot"`
		}
		json.Unmarshal(raw, &envelope)
		var snap map[string]any
		json.Unmarshal(envelope.Snapshot, &snap)
		execution := snap["execution"].(map[string]any)
		if execution["state"] != "queued" || execution["cleanup_complete"] != false || snap["source_valid"] != true {
			t.Fatalf("pending evidence=%s", raw)
		}
		proof := attackLabSettlementFixtureProof(t, execution, "cancelled", "attack_lab_cancelled")
		settleArgs := append(append([]any(nil), args[:9]...), envelope.Snapshot, proof, m.Checksum(), fingerprint)
		const settleSQL = `SELECT zasp_sa_attack_lab_reconcile_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
		canceller, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer canceller.Close(context.Background())
		control, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close(context.Background())
		gate, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer gate.Rollback(context.Background())
		if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
			t.Fatal(err)
		}
		raceCtx, endRace := context.WithTimeout(ctx, 8*time.Second)
		defer endRace()
		settled, cancelled := make(chan error, 1), make(chan error, 1)
		go func() {
			var v json.RawMessage
			settled <- reconciler.QueryRow(raceCtx, settleSQL, settleArgs...).Scan(&v)
		}()
		go func() {
			var v json.RawMessage
			cancelled <- canceller.QueryRow(raceCtx, `SELECT zasp_sa_attack_lab_reconcile_cancel_stopped($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&v)
		}()
		waiting := 0
		for raceCtx.Err() == nil {
			if err := control.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1) AND wait_event_type='Lock' AND wait_event='advisory'`, []int32{int32(reconciler.PgConn().PID()), int32(canceller.PgConn().PID())}).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting == 2 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if waiting != 2 {
			t.Fatal("cancellation race did not reach both observed waits")
		}
		if err := gate.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-settled; err == nil {
			t.Fatal("queued/stale snapshot won cancellation race")
		}
		if err := <-cancelled; err != nil {
			t.Fatalf("guarded cancellation lost race: %v", err)
		}
		t.Log("observed concurrent registered cancellation and settlement: cancellation retained; queued/stale proof refused")
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(raw, &envelope)
		json.Unmarshal(envelope.Snapshot, &snap)
		execution = snap["execution"].(map[string]any)
		if execution["state"] != "cancelled" || execution["cleanup_complete"] != true {
			t.Fatalf("confirmed cancellation=%s", raw)
		}
		proof = attackLabSettlementFixtureProof(t, execution, "cancelled", "attack_lab_cancelled")
		settleArgs[9], settleArgs[10] = envelope.Snapshot, proof
		if err := reconciler.QueryRow(ctx, settleSQL, settleArgs...).Scan(&raw); err != nil {
			t.Fatalf("cancelled settlement: %v", err)
		}
		first := string(raw)
		var retainedAdmission json.RawMessage
		if err := owner.QueryRow(ctx, `SELECT result FROM zasp_sa_attack_lab_links WHERE run_id=$1`, c.Run).Scan(&retainedAdmission); err != nil || string(retainedAdmission) != string(admissionReceipt) {
			t.Fatalf("settlement overwrote dispatch replay receipt: %v", err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_sa_attack_lab_links SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, c.Run); err != nil {
			t.Fatal(err)
		}
		if err := reconciler.QueryRow(ctx, settleSQL, settleArgs...).Scan(&raw); err != nil || string(raw) != first {
			t.Fatalf("exact lost reply after expiry=%s %v", raw, err)
		}
		// Observe the registered replay blocked after its initial authorization.
		// Revocation while it waits must be rechecked before returning the receipt.
		observer, err := pgx.ConnectConfig(ctx, owner.Config().Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer observer.Close(context.Background())
		blocker, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		if _, err := blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||$1,0))`, o); err != nil {
			t.Fatal(err)
		}
		replayCtx, stopReplay := context.WithTimeout(ctx, 5*time.Second)
		defer stopReplay()
		reply := make(chan error, 1)
		go func() {
			var received json.RawMessage
			reply <- reconciler.QueryRow(replayCtx, settleSQL, settleArgs...).Scan(&received)
		}()
		observed := false
		for replayCtx.Err() == nil {
			if err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, int64(reconciler.PgConn().PID())).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			if observed {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !observed {
			t.Fatal("replay did not reach observed advisory wait")
		}
		if _, err := observer.Exec(ctx, `REVOKE zasp_security_agent_attack_lab_reconciler FROM attack_lab_settlement_login GRANTED BY zasp_discovery_authority`); err != nil {
			t.Fatal(err)
		}
		if err := blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-reply; err == nil {
			t.Fatal("revoked waiting replay returned settled receipt")
		}
		if _, err := observer.Exec(ctx, `GRANT zasp_security_agent_attack_lab_reconciler TO attack_lab_settlement_login WITH INHERIT TRUE, SET FALSE GRANTED BY zasp_discovery_authority`); err != nil {
			t.Fatal(err)
		}
		if err := reconciler.QueryRow(ctx, settleSQL, settleArgs...).Scan(&raw); err != nil || string(raw) != first {
			t.Fatalf("authorized expired replay changed after race: %v", err)
		}
		settleArgs[10] = append([]byte(" "), proof...)
		if err := reconciler.QueryRow(ctx, settleSQL, settleArgs...).Scan(&raw); err == nil {
			t.Fatal("conflicting proof overwrote receipt")
		}
		if err := reconciler.QueryRow(ctx, `SELECT zasp_sa_attack_lab_reconcile_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, args...).Scan(&raw); err == nil {
			t.Fatal("settled link read mutable evidence")
		}
		// Reconstruct the original dispatch claim from its immutable receipt and
		// unchanged parent identity, then retry through the registered repository.
		var admission SecurityAgentExecuteResult
		if err := json.Unmarshal(admissionReceipt, &admission); err != nil {
			t.Fatal(err)
		}
		claim := SecurityAgentRunClaim{OrganizationID: o, WorkspaceID: w, EnvironmentID: e, RunID: c.Run, State: "planning", Version: admission.Version - 1, Prepared: true, LeaseExpiresAt: time.Now().UTC().Add(-time.Minute)}
		if err := owner.QueryRow(ctx, `SELECT definition_id,definition_version,trigger_id,attempt FROM zasp_security_agent_runs WHERE run_id=$1`, c.Run).Scan(&claim.DefinitionID, &claim.DefinitionVersion, &claim.TriggerID, &claim.Attempt); err != nil {
			t.Fatal(err)
		}
		workerConfig := owner.Config().Copy()
		workerConfig.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, workerConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		db, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: worker})
		if err != nil {
			t.Fatal(err)
		}
		repository, err := NewSecurityAgentWorkerRepository(db)
		if err != nil {
			t.Fatal(err)
		}
		replay := func() (SecurityAgentExecuteResult, error) {
			return repository.ExecuteSecurityAgentRun(ctx, claim, "attack-lab-worker", "attack-lab-dispatch-lease", "pid_8a10000b-0000-4000-8000-00000000000b", "pid_8a10000c-0000-4000-8000-00000000000c")
		}
		if got, err := replay(); err != nil || got != admission {
			t.Fatalf("post-settlement dispatch replay changed: %#v %v", got, err)
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET version=version+1 WHERE run_id=$1`, c.Run); err != nil {
			t.Fatal(err)
		}
		if _, err := replay(); err == nil {
			t.Fatal("settled dispatch accepted changed approved intent")
		}
		if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_approvals SET version=version-1 WHERE run_id=$1; REVOKE zasp_security_agent_attack_lab_reconciler FROM attack_lab_settlement_login GRANTED BY zasp_discovery_authority`, pgx.QueryExecModeSimpleProtocol, c.Run); err != nil {
			t.Fatal(err)
		}
		var member bool
		if err := owner.QueryRow(ctx, `SELECT pg_has_role('attack_lab_settlement_login','zasp_security_agent_attack_lab_reconciler','MEMBER')`).Scan(&member); err != nil || member {
			t.Fatalf("fixture failed to revoke actual registration grant: %v", err)
		}
		settleArgs[10] = proof
		if err := reconciler.QueryRow(ctx, settleSQL, settleArgs...).Scan(&raw); err == nil {
			t.Fatal("revoked principal replayed settlement")
		}
		if _, err := owner.Exec(ctx, `GRANT zasp_security_agent_attack_lab_reconciler TO attack_lab_settlement_login WITH INHERIT TRUE, SET FALSE GRANTED BY zasp_discovery_authority`); err != nil {
			t.Fatal(err)
		}
		if err := reconciler.QueryRow(ctx, settleSQL, settleArgs...).Scan(&raw); err != nil || string(raw) != first {
			t.Fatalf("restored principal lost immutable receipt: %v", err)
		}
		if err := runner.DownProductionSecurityAgentAttackLab(ctx); err == nil {
			t.Fatal("settled obligation allowed rollback")
		}
	})
}

func attackLabSettlementFixtureProof(t *testing.T, x map[string]any, outcome, reason string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema_version": "security-agent-attack-lab-verification-v1", "outcome": outcome, "reason": reason, "verdict": x["verdict"], "execution_id": x["run_id"], "attempt": x["attempt"], "input_digest": x["input_digest"], "artifact": x["artifact"], "cleanup_complete": true})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return append(b[:len(b)-1], []byte(`,"sha256":"`+hex.EncodeToString(h[:])+`"}`)...)
}

// This owned parent installs and registers the real authorities. The child
// must exist; a missing binary cannot turn connected coverage into a skip.
func TestSecurityAgentAttackLabRuntimePostgres(t *testing.T) {
	for _, mode := range []string{"lost_create", "lost_running", "missing_job", "expired_job", "cleanup_reply", "artifact_drift", "source_drift", "cancel_cleanup", "action_stopped", "environment_stopped", "global_stopped", "duration_expired", "budget_stopped", "create_denied"} {
		t.Run(mode, func(t *testing.T) {
			runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, definition, actor string) {
				runner := precisionMigrationRunner(t, owner)
				if err := runner.UpProductionCompliance(ctx); err != nil {
					t.Fatal(err)
				}
				if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := owner.Exec(ctx, `CREATE ROLE attack_lab_settlement_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE attack_lab_controller_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE attack_lab_outbox_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE attack_lab_proxy_login LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; SELECT zasp_attack_lab_register_principals(session_user,'attack_lab_controller_login','attack_lab_outbox_login','attack_lab_proxy_login')`); err != nil {
					t.Fatal(err)
				}
				if err := runner.RegisterSecurityAgentAttackLabReconciler(ctx, "attack_lab_settlement_login"); err != nil {
					t.Fatal(err)
				}
				exerciseAttackLabRegisteredDispatch(t, ctx, owner, api, o, w, e, definition, actor, true, false)
				if _, err := owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='running' WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e); err != nil {
					t.Fatal(err)
				}
				binary := os.Getenv("ZASP_ATTACK_LAB_TASK2_WORKER_BINARY")
				if binary == "" {
					t.Fatal("owned worker binary required")
				}
				cmd := exec.CommandContext(ctx, binary, "-test.run=^TestAttackLabLinkedRuntimeOwnedPostgres$", "-test.v", "-test.timeout=90s")
				cmd.Env = append(os.Environ(), "ZASP_ATTACK_LAB_TASK2_DSN="+owner.Config().ConnString(), "ZASP_ATTACK_LAB_TASK2_MODE="+mode, "ZASP_ATTACK_LAB_TASK2_ORG="+o, "ZASP_ATTACK_LAB_TASK2_WORKSPACE="+w, "ZASP_ATTACK_LAB_TASK2_ENVIRONMENT="+e)
				output, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(output), "--- PASS: TestAttackLabLinkedRuntimeOwnedPostgres") {
					t.Fatalf("connected child: %s %v", output, err)
				}
				t.Log(string(output))
			})
		})
	}
}
