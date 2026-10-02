package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Removing durable idempotency, lease fencing or retained-byte accounting must
// break these checks against the registered database, not an in-memory fake.
func TestComplianceExportsDurablePostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		for _, up := range []func(context.Context) error{runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance} {
			if err := up(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var exists bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text)') IS NOT NULL`).Scan(&exists); err != nil || !exists {
			t.Fatalf("durable compliance create authority absent: %v", err)
		}
		exec := func(sql string, args ...any) {
			t.Helper()
			if _, err := owner.Exec(ctx, sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
				t.Fatal(err)
			}
		}
		digest := sha256.Sum256([]byte("compliance-export-session"))
		exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'exports','exports','compliance_viewer');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'exports','["view","view_audit","view_compliance"]');
INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp());
INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,$3,'policy','policy-frozen',1,'{"secret":"NEVER_EXPORT"}');
CREATE ROLE compliance_executor LOGIN INHERIT; CREATE ROLE compliance_cleanup LOGIN INHERIT;`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, digest[:])
		exec(`SELECT zasp_compliance_register_workers('compliance_executor','compliance_cleanup',$1,$2)`, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint())
		for _, mutation := range []string{`GRANT SELECT ON zasp_compliance_export_jobs TO zasp_compliance_worker`, `ALTER TABLE zasp_compliance_export_jobs DISABLE ROW LEVEL SECURITY`, `ALTER FUNCTION zasp_compliance_export_capture(text,text,text,text,text,text,bigint,jsonb,text,text) RESET search_path`, `DELETE FROM zasp_compliance_export_policy`, `GRANT zasp_compliance_worker TO security_agent_v33_discovery_api_login`} {
			exec("BEGIN")
			exec(mutation)
			var ready bool
			err := owner.QueryRow(ctx, `SELECT zasp_compliance_readiness($1,$2)`, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&ready)
			exec("ROLLBACK")
			if err != nil || ready {
				t.Fatalf("job catalog/security drift accepted: %s %v", mutation, err)
			}
		}
		connect := func(user string) *pgx.Conn {
			t.Helper()
			config, _ := pgx.ParseConfig(dsn)
			config.User = user
			c, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close(context.Background()) })
			return c
		}
		api := connect("security_agent_v33_discovery_api_login")
		worker := connect("compliance_executor")
		cleaner := connect("compliance_cleanup")
		query := func(c *pgx.Conn, fn string, args ...any) (map[string]any, error) {
			args = append(args, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint())
			holders := make([]string, len(args))
			for i := range holders {
				holders[i] = fmt.Sprintf("$%d", i+1)
			}
			var raw []byte
			err := c.QueryRow(ctx, "SELECT public."+fn+"("+strings.Join(holders, ",")+")", args...).Scan(&raw)
			if err != nil {
				return nil, err
			}
			var out map[string]any
			err = json.Unmarshal(raw, &out)
			return out, err
		}
		create := func(key string, request string) (map[string]any, error) {
			return query(api, "zasp_compliance_export_create", complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, digest[:], key, json.RawMessage(request))
		}
		first, err := create("same-key", `{"framework":"soc2_security"}`)
		if err != nil {
			t.Fatal(err)
		}
		id := first["export_id"].(string)
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "pending", "reserved", false, "")
		replay, err := create("same-key", `{"framework":"soc2_security"}`)
		if err != nil || replay["export_id"] != id {
			t.Fatalf("same-key replay: %v %v", replay, err)
		}
		if _, err = create("same-key", `{"framework":"hipaa"}`); auditExportSQLState(err) != "40001" {
			t.Fatalf("changed request accepted: %v", err)
		}
		second, err := create("second", `{}`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = create("third", `{}`); auditExportSQLState(err) != "54000" {
			t.Fatalf("scope active quota not enforced: %v", err)
		}
		token := strings.Repeat("a", 64)
		claim := func(c *pgx.Conn, job, token string, lane string) (map[string]any, error) {
			return query(c, "zasp_compliance_export_claim", complianceOrg, complianceWorkspace, complianceEnvironment, job, "worker-one", token, lane)
		}
		type claimed struct {
			lease map[string]any
			err   error
		}
		claims := make(chan claimed, 2)
		otherWorker := connect("compliance_executor")
		for _, c := range []*pgx.Conn{worker, otherWorker} {
			go func(c *pgx.Conn) { v, e := claim(c, id, token, "execute"); claims <- claimed{v, e} }(c)
		}
		var lease map[string]any
		wins := 0
		err = nil
		for n := 0; n < 2; n++ {
			v := <-claims
			if v.err != nil {
				err = v.err
			}
			if v.lease != nil {
				wins++
				lease = v.lease
			}
		}
		if err != nil || wins != 1 {
			t.Fatalf("concurrent claims wins=%d error=%v", wins, err)
		}
		if other, err := claim(worker, id, strings.Repeat("b", 64), "execute"); err != nil || other != nil {
			t.Fatalf("second claimer stole lease: %v %v", other, err)
		}
		mutate := func(c *pgx.Conn, fn, token string, gen float64, payload any) (map[string]any, error) {
			return query(c, fn, complianceOrg, complianceWorkspace, complianceEnvironment, id, "worker-one", token, int64(gen), payload)
		}
		gen := lease["generation"].(float64)
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "pending", "reserved", false, "")
		if _, err := mutate(worker, "zasp_compliance_export_capture", strings.Repeat("b", 64), gen, json.RawMessage(`{}`)); auditExportSQLState(err) != "40001" {
			t.Fatalf("stolen token accepted: %v", err)
		}
		exec(`UPDATE zasp_workflow_records SET version=2 WHERE organization_id=$1`, complianceOrg)
		captured, err := mutate(worker, "zasp_compliance_export_capture", token, gen, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		snap, _ := json.Marshal(captured["snapshot"])
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "pending", "reserved", true, "")
		if !strings.Contains(string(snap), `"source_version":2`) || strings.Contains(string(snap), "NEVER_EXPORT") {
			t.Fatalf("capture source version or projection: %s", snap)
		}
		exec(`UPDATE zasp_workflow_records SET version=3 WHERE organization_id=$1`, complianceOrg)
		replay, err = mutate(worker, "zasp_compliance_export_capture", token, gen, json.RawMessage(`{}`))
		next, _ := json.Marshal(replay["snapshot"])
		if err != nil || string(next) != string(snap) {
			t.Fatalf("snapshot changed: %s %v", next, err)
		}
		artifact := []byte("persisted-renderer-v1-exact-bytes")
		hash := sha256.Sum256(artifact)
		intent := map[string]any{"renderer_revision": "compliance-envelope-v1", "reference": id, "bytes_hex": hex.EncodeToString(artifact), "sha256": hex.EncodeToString(hash[:]), "size": len(artifact), "format_sizes": map[string]int{"json": 10, "csv": 10, "readable": 10}}
		prepared, err := mutate(worker, "zasp_compliance_export_prepare_artifact", token, gen, intent)
		if err != nil {
			t.Fatal(err)
		}
		if prepared["bytes_hex"] != hex.EncodeToString(artifact) {
			t.Fatalf("prepared bytes not retained: %v", prepared)
		}
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "pending", "intent", true, hex.EncodeToString(artifact))
		exec(`UPDATE zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		if _, err := mutate(worker, "zasp_compliance_export_finish", token, gen, map[string]any{}); auditExportSQLState(err) != "40001" {
			t.Fatalf("expired finish accepted: %v", err)
		}
		lease, err = claim(worker, id, token, "execute")
		if err != nil {
			t.Fatal(err)
		}
		gen = lease["generation"].(float64)
		prepared, err = mutate(worker, "zasp_compliance_export_prepare_artifact", token, gen, map[string]any{})
		if err != nil || prepared["bytes_hex"] != hex.EncodeToString(artifact) || prepared["renderer_revision"] != "compliance-envelope-v1" {
			t.Fatalf("restart rerendered: %v %v", prepared, err)
		}
		receipt := map[string]any{"reference": id, "version": "immutable-version-1", "size": len(artifact), "sha256": hex.EncodeToString(hash[:])}
		exec(`UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1`, complianceOrg)
		if _, err := mutate(worker, "zasp_compliance_export_finish", token, gen, receipt); auditExportSQLState(err) != "42501" {
			t.Fatalf("revoked requester published: %v", err)
		}
		exec(`UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1`, complianceOrg)
		// Unknown writes never free retained capacity, including the terminal lane.
		for attempt := 2; attempt <= 5; attempt++ {
			if _, err := mutate(worker, "zasp_compliance_export_retry", token, gen, map[string]any{"outcome": "unknown"}); err != nil {
				t.Fatal(err)
			}
			if attempt < 5 {
				if attempt == 2 {
					assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "pending", "unknown", true, hex.EncodeToString(artifact))
				}
				exec(`UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
				lease, err = claim(worker, id, token, "execute")
				if err != nil {
					t.Fatal(err)
				}
				gen = lease["generation"].(float64)
			}
		}
		var state, storage string
		var charged int64
		if err := owner.QueryRow(ctx, `SELECT state,storage_state,retained_bytes FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state, &storage, &charged); err != nil || state != "failed" || storage != "reconcile_required" || charged == 0 {
			t.Fatalf("unknown write capacity lost: %s %s %d %v", state, storage, charged, err)
		}
		if got, err := claim(worker, id, token, "execute"); err != nil || got != nil {
			t.Fatalf("normal execution retried unresolved write: %v %v", got, err)
		}
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "failed", "reconcile_required", true, hex.EncodeToString(artifact))
		exec(`UPDATE zasp_compliance_export_jobs SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		lease, err = claim(cleaner, id, token, "reconcile")
		if err != nil {
			t.Fatal(err)
		}
		gen = lease["generation"].(float64)
		if _, err := mutate(cleaner, "zasp_compliance_export_finish", token, gen, receipt); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT state FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&state); err != nil || state != "failed" {
			t.Fatalf("reconciliation changed public failure: %s %v", state, err)
		}
		if err := runner.DownProductionCompliance(ctx); err == nil {
			t.Fatal("downgrade deleted retained evidence")
		}
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "failed", "verified", true, hex.EncodeToString(artifact))
		// Timeout/denial stays charged. Only exact immutable-version absence
		// releases capacity, and deletion writes a normal durable audit row.
		exec(`UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		lease, err = claim(cleaner, id, token, "cleanup")
		if err != nil || lease == nil {
			t.Fatalf("cleanup claim: %v %v", lease, err)
		}
		gen = lease["generation"].(float64)
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "failed", "delete_pending", true, hex.EncodeToString(artifact))
		if _, err := mutate(cleaner, "zasp_compliance_export_cleanup", token, gen, map[string]any{"outcome": "denied"}); auditExportSQLState(err) != "22023" {
			t.Fatalf("denied cleanup released bytes: %v", err)
		}
		if _, err := mutate(cleaner, "zasp_compliance_export_cleanup", token, gen, map[string]any{"outcome": "verified_absent", "reference": id, "version": "wrong-version"}); auditExportSQLState(err) != "22023" {
			t.Fatalf("wrong-version cleanup: %v", err)
		}
		if _, err := mutate(cleaner, "zasp_compliance_export_cleanup", token, gen, map[string]any{"outcome": "verified_absent", "reference": id, "version": "immutable-version-1"}); err != nil {
			t.Fatal(err)
		}
		var pruned bool
		if err := owner.QueryRow(ctx, `SELECT storage_state='deleted' AND retained_bytes=0 AND package IS NULL AND snapshot IS NULL AND EXISTS(SELECT 1 FROM zasp_admin_audit a WHERE a.id=deletion_audit_id AND a.action='compliance.export.deleted') FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&pruned); err != nil || !pruned {
			t.Fatalf("cleanup retention/audit: %v", err)
		}
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "failed", "deleted", false, "")
		id = second["export_id"].(string)
		lease, err = claim(worker, id, token, "execute")
		if err != nil || lease == nil {
			t.Fatalf("second claim: %v %v", lease, err)
		}
		gen = lease["generation"].(float64)
		exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) SELECT $1,$2,$3,'policy','policy-overflow-'||n,1,'{}' FROM generate_series(1,100)n`, complianceOrg, complianceWorkspace, complianceEnvironment)
		if _, err := mutate(worker, "zasp_compliance_export_capture", token, gen, json.RawMessage(`{}`)); auditExportSQLState(err) != "54000" {
			t.Fatalf("source overflow silently truncated: %v", err)
		}
		if err := owner.QueryRow(ctx, `SELECT snapshot IS NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&pruned); err != nil || !pruned {
			t.Fatalf("overflow snapshot did not roll back: %v", err)
		}
		exec(`DELETE FROM zasp_workflow_records WHERE organization_id=$1 AND id LIKE 'policy-overflow-%'`, complianceOrg)
		for _, postCapture := range []bool{false, true} {
			assertComplianceCaptureRevoked(t, ctx, owner, worker, id, token, int64(gen), postCapture)
		}
		if _, err := worker.Exec(ctx, `BEGIN ISOLATION LEVEL REPEATABLE READ`); err != nil {
			t.Fatal(err)
		}
		_, isolationErr := mutate(worker, "zasp_compliance_export_capture", token, gen, json.RawMessage(`{}`))
		_, rollbackErr := worker.Exec(ctx, `ROLLBACK`)
		if auditExportSQLState(isolationErr) != "25001" || rollbackErr != nil {
			t.Fatalf("capture isolation not enforced: %v %v", isolationErr, rollbackErr)
		}
		assertComplianceCaptureConcurrentSources(t, ctx, owner, worker, id, token, int64(gen))
		if _, err := mutate(worker, "zasp_compliance_export_capture", token, gen, json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		intent["reference"] = id
		receipt["reference"] = id
		if _, err := mutate(worker, "zasp_compliance_export_prepare_artifact", token, gen, intent); err != nil {
			t.Fatal(err)
		}
		assertComplianceFinishExpiredAfterWait(t, ctx, owner, worker, id, token, int64(gen), receipt)
		if _, err := mutate(worker, "zasp_compliance_export_finish", token, gen, receipt); err != nil {
			t.Fatal(err)
		}
		assertComplianceRestartState(t, ctx, owner.Config().ConnString(), id, "completed", "verified", true, hex.EncodeToString(artifact))
		grant := func(token, operation string) (map[string]any, error) {
			return query(api, "zasp_compliance_export_grant", complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, digest[:], id, token, "json", operation)
		}
		for n := 1; n <= 5; n++ {
			if _, err := grant(fmt.Sprintf("%064x", n), "issue"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := grant(fmt.Sprintf("%064x", 6), "issue"); auditExportSQLState(err) != "54000" {
			t.Fatalf("grant quota: %v", err)
		}
		if _, err := grant(fmt.Sprintf("%064x", 1), "read"); err != nil {
			t.Fatal(err)
		}
		if _, err := grant(fmt.Sprintf("%064x", 1), "consume"); err != nil {
			t.Fatal(err)
		}
		if _, err := grant(fmt.Sprintf("%064x", 1), "consume"); auditExportSQLState(err) != "28000" {
			t.Fatalf("grant replay: %v", err)
		}
		if _, err := grant(fmt.Sprintf("%064x", 2), "read"); err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE zasp_compliance_export_jobs SET retrieval_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, id)
		if _, err := grant(fmt.Sprintf("%064x", 2), "consume"); auditExportSQLState(err) != "P0002" {
			t.Fatalf("grant extended retrieval expiry: %v", err)
		}
		if got, err := claim(cleaner, id, token, "cleanup"); err != nil || got != nil {
			t.Fatalf("cleanup ignored live read: %v %v", got, err)
		}
		// Crash on the last attempt must have a durable lane, not a stuck job.
		third, err := create("crashed", `{}`)
		if err != nil {
			t.Fatal(err)
		}
		exec(`UPDATE zasp_compliance_export_jobs SET attempt=5,lease_expires_at=clock_timestamp()-interval '1 second' WHERE export_id=$1`, third["export_id"])
		if _, err := query(cleaner, "zasp_compliance_export_maintenance"); err != nil {
			t.Fatal(err)
		}
		if err := owner.QueryRow(ctx, `SELECT state FROM zasp_compliance_export_jobs WHERE export_id=$1`, third["export_id"]).Scan(&state); err != nil || state != "failed" {
			t.Fatalf("fifth-attempt crash stranded job: %s %v", state, err)
		}
		exec(`UPDATE zasp_compliance_export_jobs SET retained_bytes=268435456 WHERE export_id=$1`, third["export_id"])
		if _, err := create("retained-full", `{}`); auditExportSQLState(err) != "54000" {
			t.Fatalf("retained bytes quota: %v", err)
		}
		exec(`UPDATE zasp_compliance_export_jobs SET retained_bytes=12582912 WHERE export_id=$1`, third["export_id"])
		// Round-robin progress is persisted, not a worker-local counter. A noisy
		// scope cannot take its next claim before a waiting sibling gets a turn.
		noise, err := create("noise-1", `{}`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := create("noise-2", `{}`); err != nil {
			t.Fatal(err)
		}
		const sibling = "pid_6a000003-0000-4000-8000-000000000099"
		siblingDigest := sha256.Sum256([]byte("compliance-sibling-session"))
		exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'sibling','["view","view_audit","view_compliance"]'); INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp())`, complianceOrg, complianceWorkspace, sibling, compliancePrincipal, siblingDigest[:])
		siblingJob, err := query(api, "zasp_compliance_export_create", complianceOrg, complianceWorkspace, sibling, compliancePrincipal, siblingDigest[:], "sibling-1", json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := claim(worker, noise["export_id"].(string), token, "execute"); err != nil || got != nil {
			t.Fatalf("noisy scope bypassed waiting sibling: %v %v", got, err)
		}
		if got, err := query(worker, "zasp_compliance_export_claim", complianceOrg, complianceWorkspace, sibling, siblingJob["export_id"], "worker-one", token, "execute"); err != nil || got == nil {
			t.Fatalf("sibling starved: %v %v", got, err)
		}
		if got, err := claim(worker, noise["export_id"].(string), token, "execute"); err != nil || got == nil {
			t.Fatalf("fair next turn missing: %v %v", got, err)
		}
		if _, err := query(api, "zasp_compliance_export_get", complianceOrg, complianceWorkspace, sibling, compliancePrincipal, siblingDigest[:], noise["export_id"]); auditExportSQLState(err) != "P0002" {
			t.Fatalf("foreign scope got status: %v", err)
		}
		candidates, err := query(worker, "zasp_compliance_export_candidates", "execute", 10)
		if err != nil || candidates["items"] == nil {
			t.Fatalf("bounded worker discovery: %v %v", candidates, err)
		}
	})
}

func assertComplianceCaptureConcurrentSources(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, id, token string, generation int64) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := owner.Exec(waitCtx, `UPDATE zasp_workflow_records SET version=5 WHERE organization_id=$1; INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status,version) VALUES($1,$2,$3,'pid_6a000004-0000-4000-8000-000000000004','posture','safe title','high','open',5)`, pgx.QueryExecModeSimpleProtocol, complianceOrg, complianceWorkspace, complianceEnvironment); err != nil {
		t.Fatal(err)
	}
	blocker, err := pgx.ConnectConfig(waitCtx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	tx, err := blocker.Begin(waitCtx)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	started, joined := false, false
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanupCtx)
		cancel()
		if started && !joined {
			select {
			case <-done:
			case <-cleanupCtx.Done():
				t.Error("source-capture process did not join")
			}
		}
	}()
	if _, err := tx.Exec(waitCtx, `LOCK TABLE zasp_workflow_records IN ACCESS EXCLUSIVE MODE; UPDATE zasp_workflow_records SET version=6 WHERE organization_id=$1; UPDATE zasp_risk_findings SET version=6 WHERE organization_id=$1`, pgx.QueryExecModeSimpleProtocol, complianceOrg); err != nil {
		t.Fatal(err)
	}
	started = true
	go func() {
		var raw []byte
		e := worker.QueryRow(waitCtx, `SELECT zasp_compliance_export_capture($1,$2,$3,$4,$5,$6,$7,'{}',$8,$9)`, complianceOrg, complianceWorkspace, complianceEnvironment, id, "worker-one", token, generation, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
		done <- result{raw, e}
	}()
	for {
		var blocked bool
		if err := owner.QueryRow(waitCtx, `SELECT $1::int=ANY(pg_blocking_pids($2::int))`, blocker.PgConn().PID(), worker.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case r := <-done:
			joined = true
			t.Fatalf("capture returned before source wait: %v", r.err)
		default:
		}
	}
	if err := tx.Commit(waitCtx); err != nil {
		t.Fatal(err)
	}
	var r result
	select {
	case r = <-done:
		joined = true
	case <-waitCtx.Done():
		t.Fatal(waitCtx.Err())
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	var document struct {
		Snapshot struct {
			Controls []struct {
				Records []struct {
					Kind    string `json:"source_kind"`
					Version int    `json:"source_version"`
				} `json:"records"`
			} `json:"controls"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(r.raw, &document); err != nil {
		t.Fatal(err)
	}
	versions := map[string]int{}
	for _, c := range document.Snapshot.Controls {
		for _, r := range c.Records {
			if r.Kind == "finding" || r.Kind == "policy" {
				versions[r.Kind] = r.Version
			}
		}
	}
	if versions["policy"] != versions["finding"] || (versions["policy"] != 5 && versions["policy"] != 6) {
		t.Fatalf("mixed source statement snapshots: %v", versions)
	}
	t.Logf("concurrent policy/finding transaction captured one source snapshot: %v", versions)
}

func assertComplianceFinishExpiredAfterWait(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, id, token string, generation int64, receipt any) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	blocker, err := pgx.ConnectConfig(waitCtx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	tx, err := blocker.Begin(waitCtx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	joined := false
	started := false
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanupCtx)
		cancel()
		if started && !joined {
			select {
			case <-done:
			case <-cleanupCtx.Done():
				t.Error("finish process did not join")
			}
		}
		if _, e := owner.Exec(cleanupCtx, `UPDATE zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()+interval '60 seconds' WHERE export_id=$1`, id); e != nil {
			t.Error(e)
		}
	}()
	if _, err := tx.Exec(waitCtx, `SELECT 1 FROM zasp_identity_memberships WHERE organization_id=$1 FOR UPDATE`, complianceOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(waitCtx, `UPDATE zasp_compliance_export_jobs SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE export_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(receipt)
	started = true
	go func() {
		var raw []byte
		e := worker.QueryRow(waitCtx, `SELECT zasp_compliance_export_finish($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, complianceOrg, complianceWorkspace, complianceEnvironment, id, "worker-one", token, generation, json.RawMessage(payload), migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
		done <- e
	}()
	for {
		var blocked bool
		if err := owner.QueryRow(waitCtx, `SELECT $1::int=ANY(pg_blocking_pids($2::int))`, blocker.PgConn().PID(), worker.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case e := <-done:
			joined = true
			t.Fatalf("finish returned before auth lock: %v", e)
		default:
		}
	}
	if _, err := owner.Exec(waitCtx, `SELECT pg_sleep(2.1)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(waitCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-done:
		joined = true
		if auditExportSQLState(e) != "40001" {
			t.Fatalf("expired worker finalized after authorization wait: %v", e)
		}
	case <-waitCtx.Done():
		t.Fatal(waitCtx.Err())
	}
}

func assertComplianceRestartState(t *testing.T, ctx context.Context, dsn, id, state, storage string, snapshot bool, packageHex string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, binary, "-test.run=^TestComplianceExportRestartProcess$", "-test.timeout=12s", "-test.v")
	cmd.Env = append(os.Environ(), "ZASP_COMPLIANCE_RESTART_DSN="+dsn, "ZASP_COMPLIANCE_RESTART_ID="+id, "ZASP_COMPLIANCE_RESTART_STATE="+state, "ZASP_COMPLIANCE_RESTART_STORAGE="+storage, "ZASP_COMPLIANCE_RESTART_SNAPSHOT="+fmt.Sprint(snapshot), "ZASP_COMPLIANCE_RESTART_PACKAGE="+packageHex)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("joined restart process: %v %s", err, output)
	}
	t.Logf("joined fresh owner state-inspection process, state=%s storage=%s snapshot=%v", state, storage, snapshot)
}

func TestComplianceExportRestartProcess(t *testing.T) {
	dsn := os.Getenv("ZASP_COMPLIANCE_RESTART_DSN")
	if dsn == "" {
		t.Skip("owned parent launches this subprocess")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	var state, storage, packageHex, revision string
	var snapshot bool
	if err := db.QueryRow(ctx, `SELECT state,storage_state,snapshot IS NOT NULL,COALESCE(encode(package,'hex'),''),COALESCE(renderer_revision,'') FROM zasp_compliance_export_jobs WHERE export_id=$1`, os.Getenv("ZASP_COMPLIANCE_RESTART_ID")).Scan(&state, &storage, &snapshot, &packageHex, &revision); err != nil {
		t.Fatal(err)
	}
	if state != os.Getenv("ZASP_COMPLIANCE_RESTART_STATE") || storage != os.Getenv("ZASP_COMPLIANCE_RESTART_STORAGE") || fmt.Sprint(snapshot) != os.Getenv("ZASP_COMPLIANCE_RESTART_SNAPSHOT") || packageHex != os.Getenv("ZASP_COMPLIANCE_RESTART_PACKAGE") {
		t.Fatal("durable state or exact bytes changed across process restart")
	}
	if packageHex != "" && revision != "compliance-envelope-v1" {
		t.Fatal("persisted renderer revision changed")
	}
}

// A database-observed relation wait places revocation after the first auth
// check, inside the source-capture statement. The later auth statement must
// reject it and roll back that statement's saved snapshot.
func assertComplianceCaptureRevoked(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, id, token string, generation int64, postCapture bool) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	blocker, err := pgx.ConnectConfig(waitCtx, owner.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	tx, err := blocker.Begin(waitCtx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	started, joined := false, false
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanupCtx)
		cancel()
		if started && !joined {
			select {
			case <-done:
			case <-cleanupCtx.Done():
				t.Error("capture goroutine failed to join")
			}
		}
		if _, e := owner.Exec(cleanupCtx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1; INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'exports','["view","view_audit","view_compliance"]') ON CONFLICT DO NOTHING`, pgx.QueryExecModeSimpleProtocol, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal); e != nil {
			t.Error(e)
		}
	}()
	if postCapture {
		_, err = tx.Exec(waitCtx, `LOCK TABLE zasp_workflow_records IN ACCESS EXCLUSIVE MODE`)
	} else {
		_, err = tx.Exec(waitCtx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1`, complianceOrg)
	}
	if err != nil {
		t.Fatal(err)
	}
	started = true
	go func() {
		var raw []byte
		e := worker.QueryRow(waitCtx, `SELECT zasp_compliance_export_capture($1,$2,$3,$4,$5,$6,$7,'{}',$8,$9)`, complianceOrg, complianceWorkspace, complianceEnvironment, id, "worker-one", token, generation, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
		done <- e
	}()
	for {
		var blocked bool
		if err := owner.QueryRow(waitCtx, `SELECT $1::int=ANY(pg_blocking_pids($2::int))`, blocker.PgConn().PID(), worker.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case e := <-done:
			joined = true
			t.Fatalf("capture returned before lock observation: %v", e)
		default:
		}
	}
	if postCapture {
		if _, err := owner.Exec(waitCtx, `DELETE FROM zasp_authorized_scopes WHERE (organization_id,workspace_id,environment_id,principal_id)=($1,$2,$3,$4)`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(waitCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-done:
		joined = true
		if auditExportSQLState(e) != "42501" {
			t.Fatalf("postCapture=%v revocation accepted: %v", postCapture, e)
		}
	case <-waitCtx.Done():
		t.Fatal(waitCtx.Err())
	}
	var absent bool
	if err := owner.QueryRow(ctx, `SELECT snapshot IS NULL FROM zasp_compliance_export_jobs WHERE export_id=$1`, id).Scan(&absent); err != nil || !absent {
		t.Fatalf("revoked snapshot persisted postCapture=%v: %v", postCapture, err)
	}
	t.Logf("capture denied and snapshot rolled back after observed lock wait, postCapture=%v", postCapture)
}
