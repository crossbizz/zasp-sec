package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const exportFixtureRun = "pid_8e100001-0000-4000-8000-000000000001"
const exportFixtureFinding = "pid_8e100002-0000-4000-8000-000000000002"
const exportFixtureStep = "pid_8e100005-0000-4000-8000-000000000005"
const exportFixtureWorker = "export-database-worker"
const exportFixtureLease = "export-database-lease-token"

type exportDBFixture struct {
	ctx                context.Context
	owner, api, worker *pgx.Conn
	o, w, e, actor     string
	selection          json.RawMessage
}

func TestSecurityAgentExportLifecyclePostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.owner.Exec(f.ctx, `CREATE ROLE export_executor LOGIN INHERIT; CREATE ROLE export_cleanup LOGIN INHERIT`); err != nil {
			t.Fatal(err)
		}
		if err := precisionMigrationRunner(t, f.owner).RegisterComplianceWorkers(f.ctx, "export_executor", "export_cleanup"); err != nil {
			t.Fatal(err)
		}
		cfg := f.owner.Config().Copy()
		cfg.User = "export_executor"
		executor, err := pgx.ConnectConfig(f.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer executor.Close(context.Background())
		raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
		if err != nil {
			t.Fatal(err)
		}
		var admitted map[string]any
		if json.Unmarshal(raw, &admitted) != nil {
			t.Fatal(string(raw))
		}
		id := admitted["export_id"].(string)
		token := strings.Repeat("a", 64)
		var claim map[string]any
		claimJob := func() {
			t.Helper()
			var data json.RawMessage
			err = executor.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'export-executor',$5,'execute',$6,$7)`, f.o, f.w, f.e, id, token, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&data)
			if err != nil || json.Unmarshal(data, &claim) != nil || claim == nil {
				t.Fatalf("registered shared claim=%s error=%v", data, err)
			}
		}
		claimJob()
		if claim["job_origin"] != "agent_run" {
			t.Errorf("claim omitted checked origin: %v", claim)
		}
		binding, _ := claim["binding"].(map[string]any)
		if binding["run_id"] != exportFixtureRun || binding["step_id"] != exportFixtureStep {
			t.Errorf("claim omitted immutable binding: %v", claim)
		}
		mutate := func(fn string, payload any) (map[string]any, error) {
			var data json.RawMessage
			err := executor.QueryRow(f.ctx, fmt.Sprintf(`SELECT %s($1,$2,$3,$4,'export-executor',$5,$6,$7,$8,$9)`, fn), f.o, f.w, f.e, id, token, int64(claim["generation"].(float64)), payload, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&data)
			var result map[string]any
			if err == nil {
				err = json.Unmarshal(data, &result)
			}
			return result, err
		}
		captured, err := mutate("zasp_compliance_export_capture", json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("registered agent capture: %v", err)
		}
		if captured["mapping_revision"] != "security-agent-run-evidence-v1" {
			t.Fatalf("wrong mapping: %v", captured)
		}
		snap, _ := json.Marshal(captured["snapshot"])
		if !strings.Contains(string(snap), `"source_id":"`+exportFixtureFinding+`"`) || strings.Contains(string(snap), `credential_secret`) {
			t.Fatalf("capture source/redaction: %s", snap)
		}
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_risk_findings SET version=2 WHERE id=$1`, exportFixtureFinding); err != nil {
			t.Fatal(err)
		}
		replayed, err := mutate("zasp_compliance_export_capture", json.RawMessage(`{}`))
		next, _ := json.Marshal(replayed["snapshot"])
		if err != nil || string(next) != string(snap) {
			t.Fatalf("frozen capture changed: %s %v", next, err)
		}
		body := []byte("exact-agent-renderer-fixture-bytes")
		sum := sha256.Sum256(body)
		intent := map[string]any{"renderer_revision": "compliance-envelope-v1", "reference": id, "bytes_hex": hex.EncodeToString(body), "sha256": hex.EncodeToString(sum[:]), "size": len(body), "format_sizes": map[string]int{"json": 10, "csv": 10, "readable": 10}}
		if _, err = mutate("zasp_compliance_export_prepare_artifact", intent); !exportExpectedRefusal(err) {
			t.Fatalf("agent accepted browser renderer: %v", err)
		}
		intent["renderer_revision"] = "security-agent-evidence-envelope-v1"
		prepared, err := mutate("zasp_compliance_export_prepare_artifact", intent)
		if err != nil || prepared["bytes_hex"] != intent["bytes_hex"] {
			t.Fatalf("prepare exact agent bytes: %v %v", prepared, err)
		}
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		claimJob()
		prepared, err = mutate("zasp_compliance_export_prepare_artifact", json.RawMessage(`{}`))
		if err != nil || prepared["bytes_hex"] != intent["bytes_hex"] {
			t.Fatalf("prepared restart changed: %v %v", prepared, err)
		}
		receipt := map[string]any{"reference": id, "version": "agent-immutable-version-1", "size": len(body), "sha256": hex.EncodeToString(sum[:])}
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, f.actor); err != nil {
			t.Fatal(err)
		}
		if _, err = mutate("zasp_compliance_export_finish", receipt); !exportExpectedRefusal(err) {
			t.Fatalf("revoked actor published: %v", err)
		}
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, f.actor); err != nil {
			t.Fatal(err)
		}
		finished, err := mutate("zasp_compliance_export_finish", receipt)
		if err != nil || finished["state"] != "completed" {
			t.Fatalf("registered agent finish: %v %v", finished, err)
		}
		exerciseExportBrowserGrant(t, f, id)
		exerciseExportBrowserOrigin(t, f, id)
		// Settlement is a separate restart-safe link lease, not a renewed parent
		// execution lease. Expired budget and revoked actor do not erase facts.
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1; UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$2`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, f.actor); err != nil {
			t.Fatal(err)
		}
		var settlementClaims json.RawMessage
		err = f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim($1,$2,60,1,$3,$4)`, exportFixtureWorker, "export-settlement-lease-token", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&settlementClaims)
		var claimed []map[string]any
		if err != nil || json.Unmarshal(settlementClaims, &claimed) != nil || len(claimed) != 1 || claimed[0]["run_id"] != exportFixtureRun || claimed[0]["run_version"] != float64(4) {
			t.Fatalf("registered settlement claim=%s error=%v", settlementClaims, err)
		}
		settle := func(lease string) (json.RawMessage, error) {
			var data json.RawMessage
			err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, lease, "pid_8e100007-0000-4000-8000-000000000007", "pid_8e100008-0000-4000-8000-000000000008", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&data)
			return data, err
		}
		if _, err = settle("export-foreign-settlement-lease"); !exportExpectedRefusal(err) {
			t.Fatalf("foreign settlement accepted: %v", err)
		}
		settled, err := settle("export-settlement-lease-token")
		var result map[string]any
		if err != nil || json.Unmarshal(settled, &result) != nil || result["state"] != "needs_human" || result["reason"] != "export_available" || result["run_version"] != float64(5) || result["settled"] != true {
			t.Fatalf("registered settlement=%s error=%v", settled, err)
		}
		counts := f.counts(t)
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_sa_export_links SET settlement_lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		replay, err := settle("export-settlement-lease-token")
		var replayResult map[string]any
		if err != nil || json.Unmarshal(replay, &replayResult) != nil || replayResult["run_version"] != float64(5) || replayResult["replayed"] != true || !reflect.DeepEqual(counts, f.counts(t)) {
			t.Fatalf("lost settlement reply not stable: %s %v", replay, err)
		}
	})
}

func exerciseExportBrowserGrant(t *testing.T, f *exportDBFixture, id string) {
	t.Helper()
	const reader = "pid_8e100040-0000-4000-8000-000000000040"
	session := sha256.Sum256([]byte("export-reader-session"))
	csrf := strings.Repeat("c", 32)
	token := strings.Repeat("d", 64)
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'export-fixture-org','export-reader','read_only_viewer',true);
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Export reader','["view"]');
 INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view"]',$6,clock_timestamp()+interval '1 hour',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, reader, session[:], csrf); err != nil {
		t.Fatal(err)
	}
	get := func(run, csrfValue string) (map[string]any, error) {
		var data json.RawMessage
		err := f.api.QueryRow(f.ctx, `SELECT zasp_sa_export_get($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.o, f.w, f.e, run, exportFixtureStep, reader, session[:], csrfValue, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&data)
		var out map[string]any
		if err == nil {
			err = json.Unmarshal(data, &out)
		}
		return out, err
	}
	if _, err := get(exportFixtureStep, csrf); err == nil {
		t.Fatal("foreign run read admitted")
	}
	if _, err := get(exportFixtureRun, strings.Repeat("x", 32)); err == nil {
		t.Fatal("wrong CSRF admitted")
	}
	principal := pgx.Identifier{f.api.Config().User}.Sanitize()
	if _, err := f.owner.Exec(f.ctx, "GRANT zasp_discovery_api TO "+principal); err != nil {
		t.Fatal(err)
	}
	if _, err := get(exportFixtureRun, csrf); !exportExpectedRefusal(err) {
		t.Errorf("mixed API role read admitted: %v", err)
	}
	if _, err := f.owner.Exec(f.ctx, "REVOKE zasp_discovery_api FROM "+principal); err != nil {
		t.Fatal(err)
	}
	status, err := get(exportFixtureRun, csrf)
	if err != nil || status["export_id"] != id || len(status) != 11 || status["cleanup_state"] != "retained" {
		t.Fatalf("source-authorized status=%v error=%v", status, err)
	}
	grant := func(op string) (map[string]any, error) {
		var data json.RawMessage
		err := f.api.QueryRow(f.ctx, `SELECT zasp_sa_export_grant($1,$2,$3,$4,$5,$6,$7,$8,$9,'json',$10,$11,$12)`, f.o, f.w, f.e, exportFixtureRun, exportFixtureStep, reader, session[:], csrf, token, op, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&data)
		var out map[string]any
		if err == nil {
			err = json.Unmarshal(data, &out)
		}
		return out, err
	}
	issued, err := grant("issue")
	if err != nil || len(issued) != 2 || issued["consumed"] != false {
		t.Fatalf("registered grant=%v %v", issued, err)
	}
	denyAfterScopeWait := func(op string) {
		t.Helper()
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(f.ctx, `SELECT 1 FROM zasp_compliance_export_jobs WHERE export_id=$1 FOR UPDATE`, id); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := grant(op); done <- err; close(done) }()
		defer func() {
			tx.Rollback(context.Background())
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}()
		blocked := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if err = tx.QueryRow(f.ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, f.api.PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !blocked {
			t.Fatalf("grant %s did not wait at job lock", op)
		}
		if _, err = tx.Exec(f.ctx, `DELETE FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, reader); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-done:
			if !exportExpectedRefusal(err) {
				t.Fatalf("scope revoked during %s admitted: %v", op, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("grant caller did not join")
		}
		if _, err = f.owner.Exec(f.ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Export reader','["view"]')`, f.o, f.w, f.e, reader); err != nil {
			t.Fatal(err)
		}
	}
	denyAfterScopeWait("read")
	read, err := grant("read")
	if err != nil || len(read) != 7 || read["reference"] != id || read["renderer_revision"] != "security-agent-evidence-envelope-v1" {
		t.Fatalf("registered private read=%v %v", read, err)
	}
	if binding, ok := read["binding"].(map[string]any); !ok || binding["run_id"] != exportFixtureRun || binding["step_id"] != exportFixtureStep {
		t.Fatalf("read binding=%v", read)
	}
	if _, err = grant("read"); err == nil {
		t.Fatal("same bearer read twice")
	}
	if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, reader); err != nil {
		t.Fatal(err)
	}
	if _, err = grant("consume"); err == nil {
		t.Fatal("revoked reader consumed")
	}
	if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$1`, reader); err != nil {
		t.Fatal(err)
	}
	denyAfterScopeWait("consume")
	consumed, err := grant("consume")
	if err != nil || consumed["consumed"] != true {
		t.Fatalf("consume=%v %v", consumed, err)
	}
	if _, err = grant("consume"); err == nil {
		t.Fatal("single-use grant replayed")
	}
}

func exerciseExportBrowserOrigin(t *testing.T, f *exportDBFixture, id string) {
	t.Helper()
	session := sha256.Sum256([]byte("export-origin-browser-session"))
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$4; INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, f.actor, session[:]); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = "security_agent_v33_discovery_api_login"
	browser, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer browser.Close(context.Background())
	var raw json.RawMessage
	if err = browser.QueryRow(f.ctx, `SELECT zasp_compliance_export_get($1,$2,$3,$4,$5,$6,$7,$8)`, f.o, f.w, f.e, f.actor, session[:], id, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err == nil {
		t.Errorf("browser API read agent job: %s", raw)
	}
	if err = browser.QueryRow(f.ctx, `SELECT zasp_compliance_export_grant($1,$2,$3,$4,$5,$6,$7,'json','issue',$8,$9)`, f.o, f.w, f.e, f.actor, session[:], id, strings.Repeat("e", 64), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err == nil {
		t.Errorf("browser API granted agent job: %s", raw)
	}
	create := func() (map[string]any, error) {
		var data json.RawMessage
		err := browser.QueryRow(f.ctx, `SELECT zasp_compliance_export_create($1,$2,$3,$4,$5,$6,'{}',$7,$8)`, f.o, f.w, f.e, f.actor, session[:], "agent-step:"+exportFixtureStep, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&data)
		var out map[string]any
		if err == nil {
			err = json.Unmarshal(data, &out)
		}
		return out, err
	}
	created, err := create()
	if err != nil || created["export_id"] == id || created["mapping_revision"] != "product-evidence-v1" {
		t.Fatalf("browser origin idempotency collided: %v %v", created, err)
	}
	replayed, err := create()
	if err != nil || replayed["export_id"] != created["export_id"] {
		t.Fatalf("browser replay broke: %v %v", replayed, err)
	}
	cfg.User = "export_executor"
	executor, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())
	id = created["export_id"].(string)
	token := strings.Repeat("f", 64)
	err = executor.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'browser-regression-worker',$5,'execute',$6,$7)`, f.o, f.w, f.e, id, token, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
	var claim map[string]any
	if err != nil || json.Unmarshal(raw, &claim) != nil || claim == nil {
		t.Fatalf("browser claim=%s %v", raw, err)
	}
	if _, ok := claim["job_origin"]; ok {
		t.Fatal("browser claim acquired agent discriminator")
	}
	if _, ok := claim["binding"]; ok {
		t.Fatal("browser claim acquired agent binding")
	}
	mutate := func(fn string, payload any) (map[string]any, error) {
		var data json.RawMessage
		err := executor.QueryRow(f.ctx, fmt.Sprintf(`SELECT %s($1,$2,$3,$4,'browser-regression-worker',$5,$6,$7,$8,$9)`, fn), f.o, f.w, f.e, id, token, int64(claim["generation"].(float64)), payload, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&data)
		var out map[string]any
		if err == nil {
			err = json.Unmarshal(data, &out)
		}
		return out, err
	}
	captured, err := mutate("zasp_compliance_export_capture", json.RawMessage(`{}`))
	if err != nil || captured["mapping_revision"] != "product-evidence-v1" {
		t.Fatalf("browser capture=%v %v", captured, err)
	}
	body := []byte("unchanged-browser-artifact-contract")
	sum := sha256.Sum256(body)
	intent := map[string]any{"renderer_revision": "security-agent-evidence-envelope-v1", "reference": id, "bytes_hex": hex.EncodeToString(body), "sha256": hex.EncodeToString(sum[:]), "size": len(body), "format_sizes": map[string]int{"json": 10, "csv": 10, "readable": 10}}
	if _, err = mutate("zasp_compliance_export_prepare_artifact", intent); !exportExpectedRefusal(err) {
		t.Fatalf("browser accepted agent renderer: %v", err)
	}
	intent["renderer_revision"] = "compliance-envelope-v1"
	if _, err = mutate("zasp_compliance_export_prepare_artifact", intent); err != nil {
		t.Fatal(err)
	}
	finished, err := mutate("zasp_compliance_export_finish", map[string]any{"reference": id, "version": "browser-regression-version-1", "sha256": hex.EncodeToString(sum[:]), "size": len(body)})
	if err != nil || finished["state"] != "completed" {
		t.Fatalf("browser finish=%v %v", finished, err)
	}
	if err = browser.QueryRow(f.ctx, `SELECT zasp_compliance_export_grant($1,$2,$3,$4,$5,$6,$7,'json','issue',$8,$9)`, f.o, f.w, f.e, f.actor, session[:], id, strings.Repeat("e", 64), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
		t.Fatalf("browser owner grant: %v", err)
	}
}

func exportExpectedRefusal(err error) bool {
	switch auditExportSQLState(err) {
	case "22023", "40001", "42501", "55000":
		return true
	}
	return false
}

func TestSecurityAgentExportStoppedSettlementPostgres(t *testing.T) {
	for _, state := range []string{"needs_human", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
					t.Fatal(err)
				}
				claim := func(c *pgx.Conn, token string) ([]map[string]any, error) {
					var data json.RawMessage
					err := c.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim($1,$2,30,1,$3,$4)`, exportFixtureWorker, token, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&data)
					var out []map[string]any
					if err == nil {
						err = json.Unmarshal(data, &out)
					}
					return out, err
				}
				before := f.counts(t)
				for i := 0; i < 3; i++ {
					got, err := claim(f.worker, "export-settlement-pending-lease")
					if err != nil || len(got) != 0 {
						t.Fatalf("pending child churned: %v %v", got, err)
					}
				}
				if !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("pending claim mutated budget/effects")
				}
				if _, err := claim(f.api, "export-settlement-foreign-lease"); err == nil {
					t.Fatal("API obtained settlement authority")
				}
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET state=$2,last_error_code='budget_deadline_exceeded' WHERE run_id=$1; UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$3`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, state, f.actor); err != nil {
					t.Fatal(err)
				}
				got, err := claim(f.worker, "export-settlement-old-lease")
				if err != nil || len(got) != 1 {
					t.Fatalf("stopped parent not drainable: %v %v", got, err)
				}
				if got, err = claim(f.worker, "export-settlement-live-stealer"); err != nil || len(got) != 0 {
					t.Fatalf("live settlement lease stolen: %v %v", got, err)
				}
				if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_sa_export_links SET settlement_lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, exportFixtureRun); err != nil {
					t.Fatal(err)
				}
				got, err = claim(f.worker, "export-settlement-new-lease")
				if err != nil || len(got) != 1 {
					t.Fatalf("restart did not reclaim: %v %v", got, err)
				}
				settle := func(token string) (map[string]any, error) {
					var data json.RawMessage
					err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.o, f.w, f.e, exportFixtureRun, exportFixtureWorker, token, "pid_8e100007-0000-4000-8000-000000000007", "pid_8e100008-0000-4000-8000-000000000008", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&data)
					var out map[string]any
					if err == nil {
						err = json.Unmarshal(data, &out)
					}
					return out, err
				}
				if _, err = settle("export-settlement-old-lease"); !exportExpectedRefusal(err) {
					t.Fatalf("stale settlement accepted: %v", err)
				}
				result, err := settle("export-settlement-new-lease")
				reason := "export_parent_stopped"
				if state == "cancelled" {
					reason = "export_cancelled"
				}
				if err != nil || result["state"] != state || result["reason"] != reason || result["run_version"] != float64(4) || result["settled"] != true {
					t.Fatalf("stopped settlement=%v %v", result, err)
				}
				var storedState, storedError, childState string
				var attempts int
				if err = f.owner.QueryRow(f.ctx, `SELECT r.state,r.last_error_code,r.attempt,j.state FROM zasp_security_agent_runs r JOIN zasp_sa_export_links l USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_compliance_export_jobs j USING(organization_id,workspace_id,environment_id,export_id) WHERE r.run_id=$1`, exportFixtureRun).Scan(&storedState, &storedError, &attempts, &childState); err != nil || storedState != state || storedError != "budget_deadline_exceeded" || attempts != 2 || childState != "failed" {
					t.Fatalf("stopped parent changed: %s %s attempts=%d child=%s %v", storedState, storedError, attempts, childState, err)
				}
			})
		})
	}
}

func runExportDBFixture(t *testing.T, exercise func(*exportDBFixture)) {
	t.Helper()
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, testID, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		applyExport58(t, ctx, owner)
		config := owner.Config().Copy()
		config.User = "security_agent_v33_worker_login"
		worker, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close(context.Background())
		f := &exportDBFixture{ctx: ctx, owner: owner, api: api, worker: worker, o: o, w: w, e: e, actor: actor}
		// Only prerequisite plan/source rows are owner-seeded. Dispatch and claims
		// are registered operations; this fixture does not prove planner admission.
		seedExistingTestPreparation(t, ctx, owner, o, w, e, testID, actor, exportFixtureRun, exportFixtureFinding, "create_evidence_export", exportFixtureWorker, exportFixtureLease)
		_, err = owner.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='queued',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '10 minutes' WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_definitions SET activation='autonomous',body=(body-'existing_test')||jsonb_build_object('autonomy','autonomous','verification_kind','export') WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$6 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id;
 UPDATE zasp_security_agent_trigger_receipts SET trigger_digest=digest(convert_to(jsonb_build_object('kind','finding','id',$5::text,'version',1)::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$5,1,'pid_8e100006-0000-4000-8000-000000000006');
 INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($6,$1,'export-fixture-org','export-fixture-actor','security_engineer',true) ON CONFLICT(principal_id,organization_id) DO UPDATE SET active=true;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($6,$1,$2,$3,'Export actor','["view","manage_workflows","investigate_sessions","view_audit"]',false) ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions=excluded.permissions;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'create_evidence_export',true,$6) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, w, e, exportFixtureRun, exportFixtureFinding, actor)
		if err != nil {
			t.Fatal(err)
		}
		var claims json.RawMessage
		if err := worker.QueryRow(ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 60, 1).Scan(&claims); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Items []struct {
				RunID string `json:"run_id"`
			} `json:"items"`
		}
		if err := json.Unmarshal(claims, &got); err != nil || len(got.Items) != 1 || got.Items[0].RunID != exportFixtureRun {
			t.Fatalf("registered claim=%s error=%v", claims, err)
		}
		if err := owner.QueryRow(ctx, `SELECT jsonb_build_array(jsonb_build_object('source_kind','finding','source_id',$5::text,'source_version',1,'association_digest','sha256:'||encode(trigger_digest,'hex'))) FROM zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4)`, o, w, e, exportFixtureRun, exportFixtureFinding).Scan(&f.selection); err != nil {
			t.Fatal(err)
		}
		_, err = owner.Exec(ctx, `INSERT INTO zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_digest,catalog_version,plan,plan_hash,expires_at)
 SELECT r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.definition_id,r.definition_version,tr.trigger_digest,'security-agent-actions-v1',jsonb_build_object('definition_id',r.definition_id,'definition_version',r.definition_version,'catalog_version','security-agent-actions-v1','evidence_ids',jsonb_build_array(r.trigger_id),'steps',jsonb_build_array(jsonb_build_object('index',0,'step_id',$5::text,'action','create_evidence_export','target_id',r.run_id,'evidence_ids',$6::jsonb,'authorization','autonomous')),'verification',jsonb_build_object('kind','export'),'expires_at',clock_timestamp()+interval '10 minutes'),decode(repeat('00',32),'hex'),clock_timestamp()+interval '10 minutes'
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_trigger_receipts tr USING(organization_id,workspace_id,environment_id,run_id) WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$3,$4);
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES($1,$2,$3,$4,$5,0,'create_evidence_export',decode(repeat('00',32),'hex'),'autonomous','authorized')`, pgx.QueryExecModeSimpleProtocol, o, w, e, exportFixtureRun, exportFixtureStep, f.selection)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = owner.Exec(ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{expires_at}',to_jsonb(to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))) WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		f.setSelection(t, f.selection)
		exercise(f)
	})
}

func (f *exportDBFixture) setSelection(t *testing.T, selection json.RawMessage) {
	t.Helper()
	_, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,evidence_ids}',$5::jsonb) WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_plans SET plan_hash=digest(convert_to(plan::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id) AND (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=($1,$2,$3,$4);
 UPDATE zasp_security_agent_steps s SET input_digest=digest(convert_to((p.plan->'steps'->0)::text,'UTF8'),'sha256') FROM zasp_security_agent_plans p WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(p.organization_id,p.workspace_id,p.environment_id,p.run_id) AND (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=($1,$2,$3,$4) AND s.action_key='create_evidence_export'`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, exportFixtureRun, selection)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *exportDBFixture) dispatch(o, w, e, r, lease string) (json.RawMessage, error) {
	var result json.RawMessage
	err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, o, w, e, r, exportFixtureWorker, lease, "pid_8e100003-0000-4000-8000-000000000003", "pid_8e100004-0000-4000-8000-000000000004", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&result)
	return result, err
}

func (f *exportDBFixture) capture(t *testing.T, id string) json.RawMessage {
	t.Helper()
	if _, err := f.owner.Exec(f.ctx, `DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='export_source_executor') THEN CREATE ROLE export_source_executor LOGIN INHERIT; CREATE ROLE export_source_cleanup LOGIN INHERIT; END IF; END $$`); err != nil {
		t.Fatal(err)
	}
	if err := precisionMigrationRunner(t, f.owner).RegisterComplianceWorkers(f.ctx, "export_source_executor", "export_source_cleanup"); err != nil {
		t.Fatal(err)
	}
	cfg := f.owner.Config().Copy()
	cfg.User = "export_source_executor"
	executor, err := pgx.ConnectConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer executor.Close(context.Background())
	var raw json.RawMessage
	if err = executor.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'export-source-worker',$5,'execute',$6,$7)`, f.o, f.w, f.e, id, strings.Repeat("b", 64), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var claim map[string]any
	if json.Unmarshal(raw, &claim) != nil || claim == nil {
		t.Fatal(string(raw))
	}
	if err = executor.QueryRow(f.ctx, `SELECT zasp_compliance_export_capture($1,$2,$3,$4,'export-source-worker',$5,$6,'{}',$7,$8)`, f.o, f.w, f.e, id, strings.Repeat("b", 64), int64(claim["generation"].(float64)), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSecurityAgentExportSourcesPostgres(t *testing.T) {
	for _, kind := range []string{"attack_path", "runtime_decision", "run_audit", "manual"} {
		t.Run(kind, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				id := exportFixtureFinding
				switch kind {
				case "runtime_decision":
					seedExistingTestRuntimeTrigger(t, f.ctx, f.owner, f.o, f.w, f.e, exportFixtureRun, id, "runtime_expired")
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_runtime_gateway_events SET occurred_at=clock_timestamp()-interval '1 hour' WHERE event_id=$1; INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,occurred_at) SELECT organization_id,workspace_id,environment_id,device_id,credential_id,'pid_8e100020-0000-4000-8000-000000000020',2,decode(repeat('fb',32),'hex'),policy_version,'allow',action_kind,classification,clock_timestamp() FROM zasp_runtime_gateway_events WHERE event_id=$1`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun); err != nil {
						t.Fatal(err)
					}
				case "attack_path":
					id = "pid_6a000005-0000-4000-8000-000000000005"
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_trigger_receipts SET trigger_id=$2,trigger_kind='attack_path',trigger_digest=digest(convert_to(jsonb_build_object('kind','attack_path','id',$2::text,'version',1,'state','potential')::text,'UTF8'),'sha256') WHERE run_id=$1; UPDATE zasp_security_agent_runs SET trigger_id=$2 WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, id); err != nil {
						t.Fatal(err)
					}
				case "manual":
					id = strings.Repeat("ab", 32)
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_trigger_receipts SET trigger_id=$2,trigger_kind='manual',trigger_digest=decode($2,'hex') WHERE run_id=$1; UPDATE zasp_security_agent_runs SET trigger_id=$2,requested_by=$3 WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, id, f.actor); err != nil {
						t.Fatal(err)
					}
				case "run_audit":
					id = "pid_8e100021-0000-4000-8000-000000000021"
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$6; INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES($1,$2,$3,$5,$5,$4,$6,'fixture_event',decode(repeat('ac',32),'hex'),'{"credential_secret":"NEVER_EXPORT_AUDIT_BODY"}')`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, exportFixtureRun, id, f.actor); err != nil {
						t.Fatal(err)
					}
				}
				if kind != "run_audit" {
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_plans SET trigger_digest=(SELECT trigger_digest FROM zasp_security_agent_trigger_receipts WHERE run_id=$1),plan=jsonb_set(plan,'{evidence_ids}',jsonb_build_array($2::text)) WHERE run_id=$1`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, id); err != nil {
						t.Fatal(err)
					}
				}
				var selection json.RawMessage
				if kind == "run_audit" {
					selection = json.RawMessage(fmt.Sprintf(`[{"source_kind":"run_audit","source_id":%q,"source_version":1,"association_digest":"sha256:%s"}]`, id, strings.Repeat("ac", 32)))
				} else if err := f.owner.QueryRow(f.ctx, `SELECT jsonb_build_array(jsonb_build_object('source_kind',$2::text,'source_id',$3::text,'source_version',trigger_version,'association_digest','sha256:'||encode(trigger_digest,'hex'))) FROM zasp_security_agent_trigger_receipts WHERE run_id=$1`, exportFixtureRun, kind, id).Scan(&selection); err != nil {
					t.Fatal(err)
				}
				f.setSelection(t, selection)
				if kind == "manual" {
					before := f.counts(t)
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET requested_by=$2 WHERE run_id=$1`, exportFixtureRun, exportFixtureWorker); err != nil {
						t.Fatal(err)
					}
					if raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
						t.Errorf("manual worker-label requester admitted: %s %v", raw, err)
					}
					if !reflect.DeepEqual(before, f.counts(t)) {
						t.Fatal("invalid manual requester reserved export authority")
					}
					if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET requested_by=$2 WHERE run_id=$1`, exportFixtureRun, f.actor); err != nil {
						t.Fatal(err)
					}
				}
				raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
				if err != nil {
					t.Fatalf("selected %s dispatch: %v", kind, err)
				}
				var admitted map[string]any
				if json.Unmarshal(raw, &admitted) != nil {
					t.Fatal(string(raw))
				}
				captured := f.capture(t, admitted["export_id"].(string))
				var envelope struct {
					Snapshot struct {
						Records []struct {
							Kind    string `json:"source_kind"`
							ID      string `json:"source_id"`
							Content string `json:"content_json"`
							Digest  string `json:"content_sha256"`
						} `json:"records"`
					} `json:"snapshot"`
				}
				if json.Unmarshal(captured, &envelope) != nil || len(envelope.Snapshot.Records) != 1 {
					t.Fatalf("source snapshot=%s", captured)
				}
				record := envelope.Snapshot.Records[0]
				sum := sha256.Sum256([]byte(record.Content))
				if record.Kind != kind || record.ID != id || record.Digest != hex.EncodeToString(sum[:]) || strings.Contains(record.Content, "NEVER_EXPORT") {
					t.Fatalf("source binding/redaction=%s", captured)
				}
				if kind == "runtime_decision" && (!strings.Contains(record.Content, `"sequence": 1`) || strings.Contains(record.Content, "pid_8e100020")) {
					t.Fatalf("historical event replaced=%s", record.Content)
				}
				if kind == "manual" && (!strings.Contains(record.Content, `"trigger_kind": "manual"`) || !strings.Contains(record.Content, exportFixtureRun)) {
					t.Fatalf("manual intent omitted=%s", record.Content)
				}
			})
		})
	}
}

func (f *exportDBFixture) counts(t *testing.T) map[string]int64 {
	t.Helper()
	result := map[string]int64{}
	for _, table := range []string{"zasp_compliance_export_jobs", "zasp_sa_export_links", "zasp_security_agent_effects", "zasp_security_agent_audit", "zasp_security_agent_step_reservations"} {
		var exists bool
		if err := f.owner.QueryRow(f.ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			result[table] = 0
			continue
		} // Initial RED has no link table yet.
		var count int64
		if err := f.owner.QueryRow(f.ctx, fmt.Sprintf(`SELECT count(*) FROM public.%s WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, table), f.o, f.w, f.e).Scan(&count); err != nil {
			t.Fatal(err)
		}
		result[table] = count
	}
	return result
}

func TestSecurityAgentExportAuthorityPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		var selected []map[string]any
		if err := json.Unmarshal(f.selection, &selected); err != nil {
			t.Fatal(err)
		}
		selectionWith := func(key string, value any) json.RawMessage {
			m := map[string]any{}
			for k, v := range selected[0] {
				m[k] = v
			}
			m[key] = value
			b, _ := json.Marshal([]any{m})
			return b
		}
		duplicated, _ := json.Marshal([]any{selected[0], selected[0]})
		oversized := make([]any, 101)
		for i := range oversized {
			oversized[i] = selected[0]
		}
		tooMany, _ := json.Marshal(oversized)
		for _, tc := range []struct {
			name      string
			selection json.RawMessage
		}{
			{"empty", json.RawMessage(`[]`)}, {"duplicate", duplicated}, {"101", tooMany},
			{"unrelated_same_tenant", selectionWith("source_id", "pid_8e100099-0000-4000-8000-000000000099")},
			{"forged_run_prefix", selectionWith("source_id", exportFixtureRun+":"+exportFixtureFinding)},
			{"stale_version", selectionWith("source_version", 2)},
			{"forged_association", selectionWith("association_digest", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f.setSelection(t, tc.selection)
				before := f.counts(t)
				result, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
				after := f.counts(t)
				if !reflect.DeepEqual(before, after) {
					t.Errorf("rejected selection mutated scope: before=%v after=%v", before, after)
				}
				if !exportExpectedRefusal(err) {
					t.Errorf("invalid %s selection admitted: %s", tc.name, result)
				}
			})
		}
		f.setSelection(t, f.selection)
		for _, tc := range []struct{ name, mutate, restore string }{
			{"expired_lease", `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, `UPDATE zasp_security_agent_runs SET lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE run_id=$1`},
			{"actor_revoked", `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$2`, `UPDATE zasp_identity_memberships SET active=true WHERE principal_id=$2`},
			{"workflow_permission_removed", `UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE principal_id=$2`, `UPDATE zasp_identity_memberships SET role='security_engineer' WHERE principal_id=$2`},
			{"current_finding_version_drift", `UPDATE zasp_risk_findings SET version=2 WHERE id=$3`, `UPDATE zasp_risk_findings SET version=1 WHERE id=$3`},
			{"definition_digest_drift", `UPDATE zasp_security_agent_definition_versions SET definition_digest=decode(repeat('ab',32),'hex') WHERE actor_id=$2`, `UPDATE zasp_security_agent_definition_versions SET definition_digest=digest(convert_to(definition::text,'UTF8'),'sha256') WHERE actor_id=$2`},
			{"definition_disabled", `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE organization_id=$4`, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE organization_id=$4`},
			{"action_disabled", `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE organization_id=$4 AND action_key='create_evidence_export'`, `UPDATE zasp_security_agent_kill_switches SET execution_enabled=true WHERE organization_id=$4 AND action_key='create_evidence_export'`},
			{"mixed_worker_role", `GRANT zasp_discovery_api TO security_agent_v33_worker_login`, `REVOKE zasp_discovery_api FROM security_agent_v33_worker_login`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// Every parameter is referenced; pgx rejects unused simple-protocol arguments.
				if _, err := f.owner.Exec(f.ctx, tc.mutate+`; SELECT $1::text,$2::text,$3::text,$4::text`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, f.actor, exportFixtureFinding, f.o); err != nil {
					t.Fatal(err)
				}
				before := f.counts(t)
				result, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
				after := f.counts(t)
				if !reflect.DeepEqual(before, after) {
					t.Errorf("rejected authority mutated state: %v -> %v", before, after)
				}
				if !exportExpectedRefusal(err) {
					t.Errorf("invalid %s authority admitted: %s", tc.name, result)
				}
				if _, err := f.owner.Exec(f.ctx, tc.restore+`; SELECT $1::text,$2::text,$3::text,$4::text`, pgx.QueryExecModeSimpleProtocol, exportFixtureRun, f.actor, exportFixtureFinding, f.o); err != nil {
					t.Fatal(err)
				}
			})
		}
		for _, tc := range []struct{ name, o, w, e, r, lease string }{
			{"foreign_org", f.w, f.w, f.e, exportFixtureRun, exportFixtureLease},
			{"foreign_workspace", f.o, f.e, f.e, exportFixtureRun, exportFixtureLease},
			{"foreign_environment", f.o, f.w, f.w, exportFixtureRun, exportFixtureLease},
			{"foreign_run", f.o, f.w, f.e, exportFixtureStep, exportFixtureLease},
			{"wrong_lease", f.o, f.w, f.e, exportFixtureRun, "export-database-wrong-lease"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := f.counts(t)
				result, err := f.dispatch(tc.o, tc.w, tc.e, tc.r, tc.lease)
				after := f.counts(t)
				if !reflect.DeepEqual(before, after) {
					t.Errorf("rejected scope/lease mutated state: %v -> %v", before, after)
				}
				if !exportExpectedRefusal(err) {
					t.Errorf("invalid %s dispatch admitted: %s", tc.name, result)
				}
			})
		}
		// Explicit finding receipt plus checked definition-version actor permits
		// scheduled worker labels, unlike the manual requester regression.
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET requested_by=$2 WHERE run_id=$1`, exportFixtureRun, exportFixtureWorker); err != nil {
			t.Fatal(err)
		}
		result, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
		if err != nil {
			t.Fatalf("registered first admission: %v", err)
		}
		var got struct {
			ExportID string `json:"export_id"`
			Run      string `json:"run_id"`
			Step     string `json:"step_id"`
			Version  int64  `json:"run_version"`
			Replayed bool   `json:"replayed"`
		}
		if err := json.Unmarshal(result, &got); err != nil || got.ExportID == "" || got.Run != exportFixtureRun || got.Step != exportFixtureStep || got.Version != 4 || got.Replayed {
			t.Fatalf("first dispatch did not admit one bound export: %s", result)
		}
		counts := f.counts(t)
		if counts["zasp_compliance_export_jobs"] != 1 || counts["zasp_sa_export_links"] != 1 || counts["zasp_security_agent_effects"] != 1 || counts["zasp_security_agent_step_reservations"] != 1 {
			t.Fatalf("dispatch counts=%v", counts)
		}
		if raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, "unrelated-replay-lease-token"); !exportExpectedRefusal(err) {
			t.Errorf("unrelated dispatch replay lease admitted: %s %v", raw, err)
		}
		replay, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
		var replayed struct {
			ExportID string `json:"export_id"`
			Replayed bool   `json:"replayed"`
		}
		if err != nil || json.Unmarshal(replay, &replayed) != nil || replayed.ExportID != got.ExportID || !replayed.Replayed || !reflect.DeepEqual(counts, f.counts(t)) {
			t.Fatalf("dispatch replay=%s error=%v", replay, err)
		}
		f.setSelection(t, selectionWith("source_version", 2))
		if result, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err == nil {
			t.Errorf("changed input replay admitted: %s", result)
		}
		if !reflect.DeepEqual(counts, f.counts(t)) {
			t.Fatal("changed replay reserved another export")
		}
	})
}

func TestSecurityAgentExportSupervisedPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_definitions SET activation='supervised',body=jsonb_set(body,'{autonomy}','"supervised"') WHERE organization_id=$1;
 UPDATE zasp_security_agent_definition_versions v SET activation=d.activation,definition=d.body,definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') FROM zasp_security_agent_definitions d WHERE (v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) AND v.organization_id=$1;
 UPDATE zasp_security_agent_steps SET authorization_result='approval_required' WHERE run_id=$2;
 UPDATE zasp_security_agent_plans SET plan=jsonb_set(plan,'{steps,0,authorization}','"approval_required"') WHERE run_id=$2`, pgx.QueryExecModeSimpleProtocol, f.o, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		f.setSelection(t, f.selection)
		before := f.counts(t)
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
			t.Fatalf("supervised without approval=%v", err)
		}
		if !reflect.DeepEqual(before, f.counts(t)) {
			t.Fatal("missing approval reserved work")
		}
		if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,approver_id,fresh_auth_at,expires_at) SELECT organization_id,workspace_id,environment_id,$2,run_id,$3,plan_hash,'approved',requested_by,$4,clock_timestamp(),clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs WHERE run_id=$1`, exportFixtureRun, "pid_8e100009-0000-4000-8000-000000000009", exportFixtureStep, "pid_8e100010-0000-4000-8000-000000000010"); err != nil {
			t.Fatal(err)
		}
		for _, mutation := range []string{`plan_hash=decode(repeat('ab',32),'hex')`, `state='rejected'`, `expires_at=clock_timestamp()-interval '1 second'`} {
			if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_approvals SET `+mutation+` WHERE run_id=$1`, exportFixtureRun); err != nil {
				t.Fatal(err)
			}
			if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
				t.Fatalf("invalid approval admitted %s: %v", mutation, err)
			}
			if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_approvals a SET plan_hash=r.plan_hash,state='approved',expires_at=clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs r WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) AND a.run_id=$1`, exportFixtureRun); err != nil {
				t.Fatal(err)
			}
		}
		if result, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatalf("approved supervised dispatch=%s %v", result, err)
		}
	})
}

// The current public planner admits one action. These retained multi-step
// prerequisites exercise collector membership only, not a public planner flow.
func TestSecurityAgentExportProofSourcesPostgres(t *testing.T) {
	for _, kind := range []string{"existing_test", "attack_lab"} {
		t.Run(kind, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				const proofStep = "pid_8e100031-0000-4000-8000-000000000031"
				const sourceRun = "pid_8e100030-0000-4000-8000-000000000030"
				const execution = "pid_8e100032-0000-4000-8000-000000000032"
				action := "run_test"
				if kind == "attack_lab" {
					action = "start_attack_lab"
				}
				_, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) VALUES($1,$2,$3,$4,$5,1,$6,decode(repeat('ad',32),'hex'),'autonomous','executing');
 INSERT INTO zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,outcome_id,result_digest) VALUES($1,$2,$3,$4,$5,$6,decode(repeat('ad',32),'hex'),'pending',$7,decode(repeat('ae',32),'hex'));
 INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest) SELECT organization_id,workspace_id,environment_id,$7,definition_id,version,$8,decode(repeat('ad',32),'hex') FROM zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) LIMIT 1`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, exportFixtureRun, proofStep, action, sourceRun, f.actor)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "existing_test" {
					_, err = f.owner.Exec(f.ctx, `INSERT INTO zasp_security_agent_test_links(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,test_definition_id,test_definition_version,test_run_id,target_id,target_kind,test_categories,result) SELECT d.organization_id,d.workspace_id,d.environment_id,$4,$5,'run_test',decode(repeat('ad',32),'hex'),d.definition_id,d.version,$6,d.target_id,d.target_kind,d.categories,'{}' FROM zasp_red_team_definitions d WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3) LIMIT 1`, f.o, f.w, f.e, exportFixtureRun, proofStep, sourceRun)
				} else {
					_, err = f.owner.Exec(f.ctx, `INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size) VALUES($1,$2,$3,$6,1,decode(repeat('ad',32),'hex'),'fail','component proof','component unsafe result','[]','s3://fixture-bucket/NEVER_EXPORT_PROOF_KEY','NEVER_EXPORT_PROOF_KEY','proof-version',decode(repeat('af',32),'hex'),100);
 INSERT INTO zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id,source_run_id,definition_id,definition_version,target_id,target_kind,environment,credential_class,destination,credential_binding_id,credential_binding_version,credential_binding_digest,requested_by,input_digest) SELECT d.organization_id,d.workspace_id,d.environment_id,$7,$6,d.definition_id,d.version,d.target_id,d.target_kind,'test','read_only','fixture.invalid',b.binding_id,b.version,decode(repeat('ad',32),'hex'),$8,decode(repeat('ad',32),'hex') FROM zasp_red_team_definitions d JOIN zasp_attack_lab_credential_bindings b ON (b.organization_id,b.workspace_id,b.environment_id,b.target_id)=(d.organization_id,d.workspace_id,d.environment_id,d.target_id) WHERE (d.organization_id,d.workspace_id,d.environment_id)=($1,$2,$3) LIMIT 1;
 INSERT INTO zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,approver_id,fresh_auth_at,expires_at) SELECT organization_id,workspace_id,environment_id,$5,run_id,$5,plan_hash,'approved','fixture-requester',$8,clock_timestamp(),clock_timestamp()+interval '1 hour' FROM zasp_security_agent_runs WHERE run_id=$4;
 INSERT INTO zasp_sa_attack_lab_links(organization_id,workspace_id,environment_id,run_id,step_id,input_digest,plan_hash,intent,source_snapshot,source_run_id,source_attempt,execution_id,approval_id,requester_id,approver_id,dispatch_worker,dispatch_lease_digest,result) SELECT d.organization_id,d.workspace_id,d.environment_id,$4,$5,decode(repeat('ad',32),'hex'),decode(repeat('ad',32),'hex'),'{}',jsonb_build_object('definition_id',d.definition_id,'definition_version',d.version,'target_id',d.target_id,'target_kind',d.target_kind),$6,1,$7,$5,'fixture-requester',$8,'fixture-proof-worker',decode(repeat('ad',32),'hex'),'{}' FROM zasp_red_team_definitions d WHERE (d.organization_id,d.workspace_id,d.environment_id)=($1,$2,$3) LIMIT 1`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, exportFixtureRun, proofStep, sourceRun, execution, f.actor)
				}
				if err != nil {
					t.Fatal(err)
				}
				selection := json.RawMessage(fmt.Sprintf(`[{"source_kind":%q,"source_id":%q,"source_version":1,"association_digest":"sha256:%s"}]`, kind, proofStep, strings.Repeat("ae", 32)))
				f.setSelection(t, selection)
				before := f.counts(t)
				for _, mutation := range []string{`version=2`, `input_digest=decode(repeat('ff',32),'hex')`} {
					if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_steps SET `+mutation+` WHERE step_id=$1`, proofStep); err != nil {
						t.Fatal(err)
					}
					if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
						t.Fatalf("proof drift admitted: %s %v", mutation, err)
					}
					if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_steps SET version=1,input_digest=decode(repeat('ad',32),'hex') WHERE step_id=$1`, proofStep); err != nil {
						t.Fatal(err)
					}
				}
				linkTable := "zasp_security_agent_test_links"
				if kind == "attack_lab" {
					linkTable = "zasp_sa_attack_lab_links"
				}
				for _, tc := range []struct{ mutation, restore string }{
					{`UPDATE zasp_security_agent_effects SET result_digest=NULL WHERE step_id=$1`, `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('ae',32),'hex') WHERE step_id=$1`},
					{`UPDATE ` + linkTable + ` SET input_digest=decode(repeat('ff',32),'hex') WHERE step_id=$1`, `UPDATE ` + linkTable + ` SET input_digest=decode(repeat('ad',32),'hex') WHERE step_id=$1`},
				} {
					if _, err = f.owner.Exec(f.ctx, tc.mutation, proofStep); err != nil {
						t.Fatal(err)
					}
					if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
						t.Fatalf("proof missing digest/link mismatch accepted: %v", err)
					}
					if _, err = f.owner.Exec(f.ctx, tc.restore, proofStep); err != nil {
						t.Fatal(err)
					}
				}
				wrongKind := "attack_lab"
				if kind == "attack_lab" {
					wrongKind = "existing_test"
				}
				f.setSelection(t, json.RawMessage(strings.Replace(string(selection), kind, wrongKind, 1)))
				if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
					t.Fatalf("wrong proof kind accepted: %v", err)
				}
				f.setSelection(t, selection)
				if !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("proof refusals mutated authority")
				}
				raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
				if err != nil {
					var diagnostic json.RawMessage
					_ = f.owner.QueryRow(f.ctx, `SELECT jsonb_build_object('step',to_jsonb(s),'effect',to_jsonb(e),'selection',p.plan->'steps'->0->'evidence_ids') FROM zasp_security_agent_steps s JOIN zasp_security_agent_effects e USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE s.step_id=$1`, proofStep).Scan(&diagnostic)
					t.Fatalf("checked pending proof dispatch=%v diagnostic=%s", err, diagnostic)
				}
				var admitted map[string]any
				if json.Unmarshal(raw, &admitted) != nil {
					t.Fatal(string(raw))
				}
				captured := f.capture(t, admitted["export_id"].(string))
				if !strings.Contains(string(captured), kind) || strings.Contains(string(captured), "NEVER_EXPORT_PROOF_KEY") || strings.Contains(string(captured), `\"outcome\": \"verified\"`) {
					t.Fatalf("proof projection lost pending/redaction: %s", captured)
				}
			})
		})
	}
}

func TestSecurityAgentExportCancellationPostgres(t *testing.T) {
	for _, intent := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepared_%t", intent), func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				raw, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
				if err != nil {
					t.Fatal(err)
				}
				var dispatched map[string]any
				if json.Unmarshal(raw, &dispatched) != nil {
					t.Fatal(string(raw))
				}
				id := dispatched["export_id"].(string)
				f.capture(t, id)
				connect := func(user string) *pgx.Conn {
					t.Helper()
					cfg := f.owner.Config().Copy()
					cfg.User = user
					c, err := pgx.ConnectConfig(f.ctx, cfg)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.Close(context.Background()) })
					return c
				}
				executor := connect("export_source_executor")
				cleaner := connect("export_source_cleanup")
				token := strings.Repeat("b", 64)
				body := []byte("cancelled-agent-immutable-bytes")
				sum := sha256.Sum256(body)
				query := func(c *pgx.Conn, fn string, generation int64, payload any) (map[string]any, error) {
					var data json.RawMessage
					err := c.QueryRow(f.ctx, fmt.Sprintf(`SELECT %s($1,$2,$3,$4,'export-source-worker',$5,$6,$7,$8,$9)`, fn), f.o, f.w, f.e, id, token, generation, payload, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&data)
					var out map[string]any
					if err == nil {
						err = json.Unmarshal(data, &out)
					}
					return out, err
				}
				if intent {
					if _, err = query(executor, "zasp_compliance_export_prepare_artifact", 1, map[string]any{"renderer_revision": "security-agent-evidence-envelope-v1", "reference": id, "bytes_hex": hex.EncodeToString(body), "sha256": hex.EncodeToString(sum[:]), "size": len(body), "format_sizes": map[string]int{"json": 10, "csv": 10, "readable": 10}}); err != nil {
						t.Fatal(err)
					}
				}
				err = f.api.QueryRow(f.ctx, `SELECT zasp_security_agent_cancel_run($1,$2,$3,$4,$5,'export-cancel-fixture-0001',4,'pid_8e100051-0000-4000-8000-000000000051','pid_8e100052-0000-4000-8000-000000000052','pid_8e100053-0000-4000-8000-000000000053')`, f.o, f.w, f.e, exportFixtureRun, f.actor).Scan(&raw)
				if err != nil {
					t.Fatalf("registered parent cancel after export admission: %v", err)
				}
				if _, err = query(executor, "zasp_compliance_export_prepare_artifact", 1, json.RawMessage(`{}`)); err == nil {
					t.Fatal("cancelled parent retained PUT authority")
				}
				var retainedBefore int64
				var storageBefore string
				if err = f.owner.QueryRow(f.ctx, `SELECT retained_bytes,storage_state FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&retainedBefore, &storageBefore); err != nil || retainedBefore <= 0 || intent && storageBefore != "reconcile_required" {
					t.Fatalf("uncertain cancellation released quota: %d %s %v", retainedBefore, storageBefore, err)
				}
				if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=$1`, f.actor); err != nil {
					t.Fatal(err)
				}
				claim := func(lane string) int64 {
					t.Helper()
					err := cleaner.QueryRow(f.ctx, `SELECT zasp_compliance_export_claim($1,$2,$3,$4,'export-source-worker',$5,$6,$7,$8)`, f.o, f.w, f.e, id, token, lane, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
					var lease map[string]any
					if err != nil || json.Unmarshal(raw, &lease) != nil || lease == nil {
						t.Fatalf("cancel drain %s claim=%s %v", lane, raw, err)
					}
					return int64(lease["generation"].(float64))
				}
				version := any(nil)
				reference := any(nil)
				if intent {
					gen := claim("reconcile")
					prepared, err := query(cleaner, "zasp_compliance_export_prepare_artifact", gen, json.RawMessage(`{}`))
					if err != nil || prepared["bytes_hex"] != hex.EncodeToString(body) {
						t.Fatalf("revoked reconciliation lost frozen bytes: %v %v", prepared, err)
					}
					result, err := query(cleaner, "zasp_compliance_export_finish", gen, map[string]any{"reference": id, "version": "cancel-version-1", "sha256": hex.EncodeToString(sum[:]), "size": len(body)})
					if err != nil || result["state"] != "failed" {
						t.Fatalf("reconciliation republished cancelled export: %v %v", result, err)
					}
					version = "cancel-version-1"
					reference = id
				}
				gen := claim("cleanup")
				if _, err = query(cleaner, "zasp_compliance_export_cleanup", gen, map[string]any{"outcome": "verified_absent", "reference": reference, "version": version}); err != nil {
					t.Fatal(err)
				}
				var retained int64
				var storage, state string
				if err = f.owner.QueryRow(f.ctx, `SELECT j.retained_bytes,j.storage_state,r.state FROM zasp_compliance_export_jobs j JOIN zasp_security_agent_runs r ON (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(j.organization_id,j.workspace_id,j.environment_id,j.agent_run_id) WHERE j.export_id=$1`, id).Scan(&retained, &storage, &state); err != nil || retained != 0 || storage != "deleted" || state != "cancelled" {
					t.Fatalf("cancel cleanup retained=%d storage=%s parent=%s %v", retained, storage, state, err)
				}
			})
		})
	}
}

func TestSecurityAgentExportAfterLockRevocationPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		before := f.counts(t)
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(f.ctx, `SELECT 1 FROM zasp_compliance_export_policy FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			defer close(done)
			_, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
			done <- err
		}()
		defer func() {
			tx.Rollback(context.Background())
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}()
		deadline := time.Now().Add(3 * time.Second)
		observed := false
		for time.Now().Before(deadline) {
			if err = tx.QueryRow(f.ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, f.worker.PgConn().PID()).Scan(&observed); err != nil {
				t.Fatal(err)
			}
			if observed {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !observed {
			t.Fatal("dispatch did not reach shared quota lock")
		}
		if _, err = tx.Exec(f.ctx, `DELETE FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, f.o, f.w, f.e, f.actor); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-done:
			if !exportExpectedRefusal(err) {
				t.Fatalf("scope revoked during lock admitted: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("dispatch did not join")
		}
		if !reflect.DeepEqual(before, f.counts(t)) {
			t.Fatal("after-lock revocation reserved an export")
		}
	})
}

func TestSecurityAgentExportPlanBindingPostgres(t *testing.T) {
	for _, tc := range []struct{ name, mutation string }{
		{"trigger_digest", `trigger_digest=decode(repeat('ab',32),'hex')`},
		{"unknown_plan_key", `plan=plan||'{"extra_authority":true}'`},
		{"definition_identity", `plan=jsonb_set(plan,'{definition_id}','"pid_8e100099-0000-4000-8000-000000000099"')`},
		{"trigger_ids", `plan=jsonb_set(plan,'{evidence_ids}','[]')`},
		{"verification_shape", `plan=jsonb_set(plan,'{verification}','{"kind":"export","extra":true}')`},
		{"expires_at_binding", `plan=jsonb_set(plan,'{expires_at}','"2099-01-01T00:00:00.000000Z"')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_plans SET `+tc.mutation+` WHERE run_id=$1`, exportFixtureRun); err != nil {
					t.Fatal(err)
				}
				f.setSelection(t, f.selection)
				before := f.counts(t)
				if result, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); !exportExpectedRefusal(err) {
					t.Errorf("invalid bound plan admitted: %s %v", result, err)
				}
				if !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("invalid plan reserved export state")
				}
			})
		})
	}
}

// This seeds another persisted plan, not planner acceptance. Its execution lease
// still comes from the registered shared claimant and every export call uses it.
func seedSecondExportRun(t *testing.T, f *exportDBFixture, run, step, environment string, version int) {
	t.Helper()
	if environment != f.e {
		for _, table := range []string{"zasp_environments", "zasp_security_agent_definitions", "zasp_security_agent_definition_versions", "zasp_risk_findings", "zasp_risk_finding_evidence", "zasp_authorized_scopes", "zasp_security_agent_kill_switches"} {
			column := "environment_id"
			if table == "zasp_environments" {
				column = "id"
			}
			query := fmt.Sprintf(`INSERT INTO %s SELECT (jsonb_populate_record(NULL::%s,to_jsonb(x)||jsonb_build_object(%q,$2::text))).* FROM %s x WHERE %s=$1`, table, table, column, table, column)
			query = strings.ReplaceAll(query, `"`+column+`"`, `'`+column+`'`)
			if table == "zasp_environments" {
				query = strings.Replace(query, "to_jsonb(x)||", "to_jsonb(x)||jsonb_build_object('name',$2::text)||", 1)
			}
			if table == "zasp_authorized_scopes" {
				query = strings.Replace(query, "to_jsonb(x)||", "to_jsonb(x)||jsonb_build_object('is_default',false)||", 1)
			}
			if _, err := f.owner.Exec(f.ctx, query, f.e, environment); err != nil {
				t.Fatalf("clone %s: %v", table, err)
			}
		}
	}
	_, err := f.owner.Exec(f.ctx, `UPDATE zasp_risk_findings SET version=$7 WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$6,$8);
 INSERT INTO zasp_security_agent_runs SELECT (jsonb_populate_record(NULL::zasp_security_agent_runs,to_jsonb(x)||jsonb_build_object('environment_id',$6::text,'run_id',$4::text,'state','queued','version',1,'attempt',0,'plan_hash',NULL,'lease_owner',NULL,'lease_token',NULL,'lease_expires_at',NULL))).* FROM zasp_security_agent_runs x WHERE run_id=$9;
 INSERT INTO zasp_security_agent_run_budgets SELECT (jsonb_populate_record(NULL::zasp_security_agent_run_budgets,to_jsonb(x)||jsonb_build_object('environment_id',$6::text,'run_id',$4::text))).* FROM zasp_security_agent_run_budgets x WHERE run_id=$9;
 INSERT INTO zasp_security_agent_trigger_receipts SELECT (jsonb_populate_record(NULL::zasp_security_agent_trigger_receipts,to_jsonb(x)||jsonb_build_object('environment_id',$6::text,'run_id',$4::text,'trigger_version',$7::bigint,'trigger_digest',digest(convert_to(jsonb_build_object('kind','finding','id',$8::text,'version',$7::bigint)::text,'UTF8'),'sha256')))).* FROM zasp_security_agent_trigger_receipts x WHERE run_id=$9;
 INSERT INTO zasp_security_agent_plans SELECT (jsonb_populate_record(NULL::zasp_security_agent_plans,to_jsonb(x)||jsonb_build_object('environment_id',$6::text,'run_id',$4::text,'trigger_digest',r.trigger_digest,'plan_hash',digest($4,'sha256'),'plan',jsonb_set(x.plan,'{steps}',jsonb_build_array(jsonb_build_object('index',0,'step_id',$5::text,'action','create_evidence_export','target_id',$4::text,'evidence_ids',jsonb_build_array(jsonb_build_object('source_kind','finding','source_id',$8::text,'source_version',$7::bigint,'association_digest','sha256:'||encode(r.trigger_digest,'hex'))),'authorization','autonomous')))))).* FROM zasp_security_agent_plans x CROSS JOIN zasp_security_agent_trigger_receipts r WHERE x.run_id=$9 AND r.run_id=$4;
 UPDATE zasp_security_agent_plans SET plan_hash=digest(convert_to(plan::text,'UTF8'),'sha256') WHERE run_id=$4;
 UPDATE zasp_security_agent_runs r SET plan_hash=p.plan_hash FROM zasp_security_agent_plans p WHERE r.run_id=$4 AND p.run_id=r.run_id;
 INSERT INTO zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,input_digest,authorization_result,state) SELECT $1,$2,$6,$4,$5,0,'create_evidence_export',digest(convert_to((plan->'steps'->0)::text,'UTF8'),'sha256'),'autonomous','authorized' FROM zasp_security_agent_plans WHERE run_id=$4;
 SELECT $3::text`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, run, step, environment, version, exportFixtureFinding, exportFixtureRun)
	if err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err = f.worker.QueryRow(f.ctx, postgresSecurityAgentClaimRunsV24SQL, exportFixtureWorker, exportFixtureLease, 60, 1).Scan(&raw); err != nil || !strings.Contains(string(raw), run) {
		t.Fatalf("second registered claim=%s %v", raw, err)
	}
}

func TestSecurityAgentExportRepeatedFindingPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		first, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
		var admitted map[string]any
		if err != nil || json.Unmarshal(first, &admitted) != nil {
			t.Fatalf("first=%s %v", first, err)
		}
		frozen := f.capture(t, admitted["export_id"].(string))
		const run = "pid_8e100071-0000-4000-8000-000000000071"
		const step = "pid_8e100072-0000-4000-8000-000000000072"
		seedSecondExportRun(t, f, run, step, f.e, 2)
		var raw json.RawMessage
		err = f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,'pid_8e100073-0000-4000-8000-000000000073','pid_8e100074-0000-4000-8000-000000000074',$7,$8)`, f.o, f.w, f.e, run, exportFixtureWorker, exportFixtureLease, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
		if err != nil || json.Unmarshal(raw, &admitted) != nil {
			t.Fatalf("same finding second run=%s %v", raw, err)
		}
		second := f.capture(t, admitted["export_id"].(string))
		for i, data := range []json.RawMessage{frozen, second} {
			var got struct {
				Snapshot struct {
					RunID   string `json:"run_id"`
					Records []struct {
						ID      string `json:"source_id"`
						Version int    `json:"source_version"`
						Content string `json:"content_json"`
					} `json:"records"`
				} `json:"snapshot"`
			}
			if json.Unmarshal(data, &got) != nil || len(got.Snapshot.Records) != 1 || got.Snapshot.Records[0].ID != "pid_8e100002-0000-4000-8000-000000000002" || got.Snapshot.Records[0].Version != i+1 || !strings.Contains(got.Snapshot.Records[0].Content, fmt.Sprintf(`"version": %d`, i+1)) {
				t.Fatalf("exact run-associated finding version%d=%s", i+1, data)
			}
		}
		var count int
		if err = f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_sa_export_links WHERE selection->0->>'source_id'=$1`, exportFixtureFinding).Scan(&count); err != nil || count != 2 {
			t.Fatalf("independent links=%d %v", count, err)
		}
	})
}

func TestSecurityAgentExportTwoScopesPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatal(err)
		}
		const run = "pid_8e100081-0000-4000-8000-000000000081"
		const step = "pid_8e100082-0000-4000-8000-000000000082"
		const env = "pid_8e100083-0000-4000-8000-000000000083"
		seedSecondExportRun(t, f, run, step, env, 1)
		var raw json.RawMessage
		err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_execute_run($1,$2,$3,$4,$5,$6,'pid_8e100084-0000-4000-8000-000000000084','pid_8e100085-0000-4000-8000-000000000085',$7,$8)`, f.o, f.w, env, run, exportFixtureWorker, exportFixtureLease, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
		if err != nil {
			t.Fatalf("second scope dispatch=%s %v", raw, err)
		}
		if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code='budget_deadline_exceeded' WHERE run_id=ANY($1)`, []string{exportFixtureRun, run}); err != nil {
			t.Fatal(err)
		}
		if err = f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim($1,$2,60,2,$3,$4)`, exportFixtureWorker, "two-scope-settlement-token", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var claims []map[string]any
		if json.Unmarshal(raw, &claims) != nil || len(claims) != 2 || claims[0]["environment_id"] == claims[1]["environment_id"] {
			t.Fatalf("two-scope settlement fairness=%s", raw)
		}
		var links int
		if err = f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_sa_export_links WHERE organization_id=$1`, f.o).Scan(&links); err != nil || links != 2 {
			t.Fatalf("two scopes links=%d %v", links, err)
		}
	})
}

func TestSecurityAgentExportCancelRacePostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(f.ctx, `SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 FOR UPDATE`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		cancel := func(version int) error {
			var raw json.RawMessage
			return f.api.QueryRow(f.ctx, `SELECT zasp_security_agent_cancel_run($1,$2,$3,$4,$5,'export-cancel-race-0001',$6,'pid_8e100091-0000-4000-8000-000000000091','pid_8e100092-0000-4000-8000-000000000092','pid_8e100093-0000-4000-8000-000000000093')`, f.o, f.w, f.e, exportFixtureRun, f.actor, version).Scan(&raw)
		}
		dispatched := make(chan error, 1)
		cancelled := make(chan error, 1)
		go func() {
			_, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
			dispatched <- err
			close(dispatched)
		}()
		go func() { cancelled <- cancel(3); close(cancelled) }()
		defer func() {
			tx.Rollback(context.Background())
			for _, ch := range []chan error{dispatched, cancelled} {
				select {
				case <-ch:
				case <-time.After(3 * time.Second):
				}
			}
		}()
		both := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if err = tx.QueryRow(f.ctx, `SELECT cardinality(pg_blocking_pids($1))>0 AND cardinality(pg_blocking_pids($2))>0`, f.worker.PgConn().PID(), f.api.PgConn().PID()).Scan(&both); err != nil {
				t.Fatal(err)
			}
			if both {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !both {
			t.Fatal("dispatch/cancel did not both reach gate")
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		for name, ch := range map[string]chan error{"dispatch": dispatched, "cancel": cancelled} {
			select {
			case err = <-ch:
				if err != nil && !exportExpectedRefusal(err) {
					t.Fatalf("%s race: %v", name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s did not join", name)
			}
		}
		var state string
		var version int
		if err = f.owner.QueryRow(f.ctx, `SELECT state,version FROM zasp_security_agent_runs WHERE run_id=$1`, exportFixtureRun).Scan(&state, &version); err != nil {
			t.Fatal(err)
		}
		if state != "cancelled" {
			if err = cancel(version); err != nil {
				t.Fatal(err)
			}
		}
		var unsafe int
		if err = f.owner.QueryRow(f.ctx, `SELECT count(*) FROM zasp_compliance_export_jobs WHERE agent_run_id=$1 AND (state<>'failed' OR package IS NOT NULL)`, exportFixtureRun).Scan(&unsafe); err != nil || unsafe != 0 {
			t.Fatalf("cancel race retained upload authority=%d %v", unsafe, err)
		}
	})
}

func TestSecurityAgentExportLateBudgetPostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()+interval '2 seconds' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		before := f.counts(t)
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(f.ctx, `LOCK TABLE zasp_security_agent_audit IN SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease)
			done <- err
			close(done)
		}()
		defer func() {
			tx.Rollback(context.Background())
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}()
		blocked := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if err = tx.QueryRow(f.ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, f.worker.PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !blocked {
			t.Fatal("dispatch did not reach audit write lock")
		}
		expired := false
		for !expired && time.Now().Before(deadline) {
			if err = tx.QueryRow(f.ctx, `SELECT deadline_at<=clock_timestamp() FROM zasp_security_agent_run_budgets WHERE run_id=$1`, exportFixtureRun).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if !expired {
				time.Sleep(10 * time.Millisecond)
			}
		}
		if !expired {
			t.Fatal("budget deadline did not expire")
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-done:
			if !exportExpectedRefusal(err) {
				t.Errorf("expired budget admitted after audit wait: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("dispatch did not join")
		}
		if !reflect.DeepEqual(before, f.counts(t)) {
			t.Fatal("late expired budget left durable export authority")
		}
	})
}

func TestSecurityAgentExportSharedQuotaPostgres(t *testing.T) {
	for _, agentFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("agent_first_%t", agentFirst), func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				session := sha256.Sum256([]byte("export-shared-quota-session"))
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET role='security_admin' WHERE principal_id=$4; INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp())`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, f.actor, session[:]); err != nil {
					t.Fatal(err)
				}
				cfg := f.owner.Config().Copy()
				cfg.User = "security_agent_v33_discovery_api_login"
				browser, err := pgx.ConnectConfig(f.ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer browser.Close(context.Background())
				create := func(key string) error {
					var raw json.RawMessage
					return browser.QueryRow(f.ctx, `SELECT zasp_compliance_export_create($1,$2,$3,$4,$5,$6,'{}',$7,$8)`, f.o, f.w, f.e, f.actor, session[:], key, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
				}
				if agentFirst {
					if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
						t.Fatal(err)
					}
				} else {
					if err = create("quota-browser-first"); err != nil {
						t.Fatal(err)
					}
				}
				if err = create("quota-browser-second"); err != nil {
					t.Fatal(err)
				}
				before := f.counts(t)
				if agentFirst {
					if err = create("quota-browser-third"); auditExportSQLState(err) != "54000" {
						t.Fatalf("browser ignored agent active quota: %v", err)
					}
					if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
						t.Fatalf("replay consumed capacity: %v", err)
					}
				} else {
					if _, err = f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); auditExportSQLState(err) != "54000" {
						t.Fatalf("agent ignored browser active quota: %v", err)
					}
				}
				if !reflect.DeepEqual(before, f.counts(t)) {
					t.Fatal("capacity refusal/replay changed quota authority")
				}
			})
		})
	}
}

func TestSecurityAgentExportGroupScopePostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.owner.Exec(f.ctx, `DELETE FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4);
 INSERT INTO zasp_group_mappings(organization_id,workspace_id,environment_id,group_reference,role) VALUES($1,$2,$3,'scim-group-test-export-authority','security_engineer');
 INSERT INTO zasp_identity_member_groups(organization_id,principal_id,group_reference) VALUES($1,$4,'scim-group-test-export-authority')`, pgx.QueryExecModeSimpleProtocol, f.o, f.w, f.e, f.actor); err != nil {
			t.Fatal(err)
		}
		var authorized bool
		if err := f.owner.QueryRow(f.ctx, `SELECT permissions ?& ARRAY['view','manage_workflows'] FROM zasp_identity_admin_effective_scopes($4,$1) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, f.o, f.w, f.e, f.actor).Scan(&authorized); err != nil || !authorized {
			t.Fatalf("effective group prerequisite=%v %v", authorized, err)
		}
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatalf("current effective group scope rejected: %v", err)
		}
	})
}

func TestSecurityAgentExportSettlementTableGatePostgres(t *testing.T) {
	runExportDBFixture(t, func(f *exportDBFixture) {
		if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET state='needs_human' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		claim := func() (json.RawMessage, error) {
			var raw json.RawMessage
			err := f.worker.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim($1,$2,60,1,$3,$4)`, exportFixtureWorker, "table-gate-contender-token", migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
			return raw, err
		}
		// Prime the PL/pgSQL cached plan, then restore an expired eligible lease.
		if _, err := claim(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_sa_export_links SET settlement_lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		tx, err := f.owner.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err = tx.Exec(f.ctx, `LOCK TABLE zasp_sa_export_links IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		type response struct {
			raw json.RawMessage
			err error
		}
		done := make(chan response, 1)
		go func() { raw, err := claim(); done <- response{raw, err}; close(done) }()
		defer func() {
			tx.Rollback(context.Background())
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}()
		blocked := false
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if err = tx.QueryRow(f.ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, f.worker.PgConn().PID()).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !blocked {
			t.Fatal("registered claim did not reach table gate")
		}
		if _, err = tx.Exec(f.ctx, `UPDATE zasp_sa_export_links SET settlement_worker='table-gate-winner',settlement_token_digest=digest('table-gate-winner-token','sha256'),settlement_lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE run_id=$1`, exportFixtureRun); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatal(got.err)
			}
			t.Logf("registered claim after table gate=%s", got.raw)
			if string(got.raw) != "[]" {
				t.Fatalf("committed live lease overwritten: %s", got.raw)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("registered claim did not join")
		}
	})
}

func TestSecurityAgentExportSettlementInterleavePostgres(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("winner_settled_%t", terminal), func(t *testing.T) {
			runExportDBFixture(t, func(f *exportDBFixture) {
				if _, err := f.dispatch(f.o, f.w, f.e, exportFixtureRun, exportFixtureLease); err != nil {
					t.Fatal(err)
				}
				if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_security_agent_runs SET state='needs_human' WHERE run_id=$1`, exportFixtureRun); err != nil {
					t.Fatal(err)
				}
				// The installed function is copied verbatim except for its fixture name
				// and this correlated timing barrier. Production readiness stays intact.
				// No predicate, row lock, update, role check or return path is replaced.
				var definition string
				if err := f.owner.QueryRow(f.ctx, `SELECT pg_get_functiondef('public.zasp_sa_export_settlement_claim(text,text,integer,integer,text,text)'::regprocedure)`).Scan(&definition); err != nil {
					t.Fatal(err)
				}
				const anchor = "  ORDER BY d.ordinal"
				if strings.Count(definition, anchor) != 1 {
					t.Fatal("claim timing-barrier anchor changed")
				}
				definition = strings.Replace(definition, "FUNCTION public.zasp_sa_export_settlement_claim(", "FUNCTION public.export_settlement_claim_interleave_fixture(", 1)
				definition = strings.Replace(definition, anchor, "  CROSS JOIN LATERAL (SELECT pg_advisory_xact_lock(5831000::bigint+CASE WHEN d.run_id IS NOT NULL THEN 0 ELSE 1 END)) timing_barrier\n"+anchor, 1)
				if terminal && os.Getenv("ZASP_TEST_EXPORT_OMIT_SETTLED_GUARD") == "1" {
					const guard = "CONTINUE WHEN l.settled_at IS NOT NULL OR ("
					if strings.Count(definition, guard) != 1 {
						t.Fatal("settled guard mutation anchor changed")
					}
					definition = strings.Replace(definition, guard, "CONTINUE WHEN (", 1)
					t.Log("test-only clone mutation: removed only settled_at guard")
				}
				if _, err := f.owner.Exec(f.ctx, definition+`; ALTER FUNCTION public.export_settlement_claim_interleave_fixture(text,text,integer,integer,text,text) OWNER TO zasp_discovery_authority; REVOKE ALL ON FUNCTION public.export_settlement_claim_interleave_fixture(text,text,integer,integer,text,text) FROM PUBLIC; GRANT EXECUTE ON FUNCTION public.export_settlement_claim_interleave_fixture(text,text,integer,integer,text,text) TO zasp_security_agent_worker`, pgx.QueryExecModeSimpleProtocol); err != nil {
					t.Fatal(err)
				}
				cfg := f.worker.Config().Copy()
				winner, err := pgx.ConnectConfig(f.ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer winner.Close(context.Background())
				if _, err = f.owner.Exec(f.ctx, `SELECT pg_advisory_lock(5831000::bigint)`); err != nil {
					t.Fatal(err)
				}
				defer f.owner.Exec(context.Background(), `SELECT pg_advisory_unlock(5831000::bigint)`)
				type response struct {
					raw json.RawMessage
					err error
				}
				done := make(chan response, 1)
				go func() {
					var raw json.RawMessage
					err := f.worker.QueryRow(f.ctx, `SELECT public.export_settlement_claim_interleave_fixture('interleave-stale-worker','interleave-stale-token',60,1,$1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
					done <- response{raw, err}
					close(done)
				}()
				defer func() {
					f.owner.Exec(context.Background(), `SELECT pg_advisory_unlock(5831000::bigint)`)
					select {
					case <-done:
					case <-time.After(3 * time.Second):
					}
				}()
				blocked := false
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if err = f.owner.QueryRow(f.ctx, `SELECT pg_backend_pid()=ANY(pg_blocking_pids($1))`, f.worker.PgConn().PID()).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if !blocked {
					t.Fatal("candidate did not reach correlated pre-lock barrier")
				}
				var claimed json.RawMessage
				if err = winner.QueryRow(f.ctx, `SELECT zasp_sa_export_settlement_claim('interleave-winning-worker','interleave-winning-token',60,1,$1,$2)`, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&claimed); err != nil {
					t.Fatal(err)
				}
				var claims []map[string]any
				if json.Unmarshal(claimed, &claims) != nil || len(claims) != 1 || claims[0]["run_id"] != exportFixtureRun {
					t.Fatalf("real competing claim=%s", claimed)
				}
				if terminal {
					var receipt json.RawMessage
					if err = winner.QueryRow(f.ctx, `SELECT zasp_sa_export_settle($1,$2,$3,$4,'interleave-winning-worker','interleave-winning-token','pid_8e100007-0000-4000-8000-000000000007','pid_8e100008-0000-4000-8000-000000000008',$5,$6)`, f.o, f.w, f.e, exportFixtureRun, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&receipt); err != nil {
						t.Fatal(err)
					}
					t.Logf("real winner settled before stale row locking: %s", receipt)
					// Isolate settled_at: an expired lease must not make a durable
					// settlement eligible again. Only the test owner changes the clock.
					if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_sa_export_links SET settlement_lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`, exportFixtureRun); err != nil {
						t.Fatal(err)
					}
				}
				var before, after string
				if err = f.owner.QueryRow(f.ctx, `SELECT to_jsonb(l)::text FROM zasp_sa_export_links l WHERE run_id=$1`, exportFixtureRun).Scan(&before); err != nil {
					t.Fatal(err)
				}
				if _, err = f.owner.Exec(f.ctx, `SELECT pg_advisory_unlock(5831000::bigint)`); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-done:
					if got.err != nil {
						t.Fatal(got.err)
					}
					t.Logf("stale candidate claim after winner commit=%s", got.raw)
					if string(got.raw) != "[]" {
						t.Errorf("stale candidate replaced a committed live/settled lease: %s", got.raw)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("stale claimant did not join")
				}
				if err = f.owner.QueryRow(f.ctx, `SELECT to_jsonb(l)::text FROM zasp_sa_export_links l WHERE run_id=$1`, exportFixtureRun).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if before != after {
					t.Error("stale candidate mutated winning lease/receipt")
				}
			})
		})
	}
}
