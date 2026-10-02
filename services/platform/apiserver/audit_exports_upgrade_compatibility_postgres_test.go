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
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// Breaks if an additive audit-export migration makes existing, already-warmed
// schema51 application instances unavailable. These are real registered-role
// connections, SQL readiness chains and empty queue operations. This first
// regression does not claim acceptance of queued work or provider effects.
func TestAuditExportsUpgradeKeepsWarmed51Consumers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	databaseFor := func(connection *pgx.Conn) *PostgresJSONDatabase {
		t.Helper()
		database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
		if err != nil {
			t.Fatal(err)
		}
		return database
	}
	apiDatabase := databaseFor(sandboxSessionAPI(t, ctx, admin))
	api, err := NewPostgresRepositoryWithRuntimeSessionSearchIndex(apiDatabase, &sessionQueryIndex{}, "zasp-runtime-sessions-v2")
	if err != nil {
		t.Fatal(err)
	}
	ingest, err := runtimeevent.NewPostgresPreciseProductionIngestRepository(databaseFor(precisionRecoveryIngest(t, ctx, admin)))
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := runtimeevent.NewPostgresPrecisePipelineRepository(databaseFor(sandboxSessionCoordinator(t, ctx, admin)), runtimeevent.ProductionPipelineAuthorityCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := NewPreciseRuntimeOutboxRepository(databaseFor(precisionOutboxWorker(t, ctx, admin)))
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	seedConnectorRiskFinding(t, ctx, admin, identity, "pid_52900004-0000-4000-8000-000000000004")
	riskMutation := RiskFindingMutation{Operation: "updateFinding", FindingID: "pid_52900004-0000-4000-8000-000000000004", IdempotencyKey: "audit-upgrade-risk-key", ExpectedVersion: 1, Status: "under_review", AuditID: "pid_52900005-0000-4000-8000-000000000005", CorrelationID: "pid_52900006-0000-4000-8000-000000000006", ReceiptID: "pid_52900007-0000-4000-8000-000000000007"}
	workflowArgs := []any{"create", "policy", "pid_52900001-0000-4000-8000-000000000001", identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), "createPolicy", "audit-upgrade-workflow", int64(0), json.RawMessage(`{"name":"audit upgrade"}`), json.RawMessage(`{"id":"pid_52900001-0000-4000-8000-000000000001","name":"audit upgrade","scope":"environment","trigger":"tool","conditions":[],"action":"monitor","rollout":"draft","failure_mode":"open"}`), "pid_52900002-0000-4000-8000-000000000002", "pid_52900003-0000-4000-8000-000000000003", ""}
	checks := []struct {
		name string
		run  func() error
	}{
		{"api-schema-marker", func() error {
			version, err := apiDatabase.SchemaVersion(ctx)
			if err != nil || version != ProductionRecoverySchemaVersion {
				return fmt.Errorf("schema marker=%q: %v", version, err)
			}
			return nil
		}},
		{"target2-api-readiness", func() error { return api.Ready(ctx) }},
		{"precise-ingest-readiness", func() error { return ingest.ReadyPrecision(ctx) }},
		{"precise-stage-readiness", func() error { return pipeline.ReadyPrecision(ctx) }},
		{"precise-outbox-readiness", func() error { return outbox.ReadyPrecision(ctx) }},
		{"reconciliation-claim", func() error {
			leases, err := ingest.ClaimReconciliation(ctx, "audit-upgrade-probe", "audit-upgrade-probe-lease", 60, 1)
			if err != nil || len(leases) != 0 {
				return fmt.Errorf("empty reconciliation claim: leases=%d error=%v", len(leases), err)
			}
			return nil
		}},
		{"completion-claim", func() error {
			leases, err := pipeline.ClaimStages(ctx, "audit-upgrade-probe", "audit-upgrade-probe-lease", 30, 1)
			if err != nil || len(leases) != 0 {
				return fmt.Errorf("empty stage claim: leases=%d error=%v", len(leases), err)
			}
			return nil
		}},
		{"runtime-outbox-claim", func() error {
			leases, err := outbox.ClaimOutboxTopic(ctx, RuntimeOutboxTopic, "audit-upgrade-probe", "audit-upgrade-probe-lease", 30, 1)
			if err != nil || len(leases) != 0 {
				return fmt.Errorf("empty outbox claim: leases=%d error=%v", len(leases), err)
			}
			return nil
		}},
		{"workflow-create-replay", func() error {
			body, err := apiDatabase.QueryJSON(ctx, postgresWorkflowMutateSQL, workflowArgs...)
			if err != nil {
				return err
			}
			var result struct {
				Version int `json:"version"`
			}
			if json.Unmarshal(body, &result) != nil || result.Version != 1 {
				return fmt.Errorf("workflow result not version1")
			}
			return nil
		}},
		{"risk-update-replay", func() error {
			result, err := api.MutateRiskFinding(ctx, identity, riskMutation)
			if err != nil {
				return err
			}
			if result.Version != 2 || result.Body.Status != "under_review" {
				return fmt.Errorf("risk mutation lost version/status")
			}
			return nil
		}},
	}
	for _, check := range checks {
		if err := check.run(); err != nil {
			t.Fatalf("schema51 baseline %s: %v", check.name, err)
		}
	}
	t.Log("schema51 baseline: all registered consumer probes passed; retaining the same repository instances")
	before := preciseCompletionRows(t, ctx, admin)

	installAuditExports(t, ctx, admin)
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err != nil {
				t.Fatalf("warmed schema51 consumer unavailable after additive52: %v", err)
			}
		})
	}
	if after := preciseCompletionRows(t, ctx, admin); after != before {
		t.Fatal("empty compatibility probes changed runtime evidence")
	}
	// Each drift is committed so the previously warmed registered connections
	// see it. Restore after each control; never recalculate a trusted fingerprint.
	for _, drift := range []struct{ name, change, restore string }{
		{"unknown53", `INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(53,'unknown',repeat('a',64))`, `DELETE FROM zasp_schema_versions WHERE version=53`},
		{"wrong52name", `UPDATE zasp_schema_versions SET name='wrong' WHERE version=52`, `UPDATE zasp_schema_versions SET name='production_audit_exports' WHERE version=52`},
		{"wrong52checksum", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_audit_exports_checksum'`, `UPDATE zasp_schema_metadata SET value=(SELECT checksum FROM zasp_schema_versions WHERE version=52) WHERE key='production_audit_exports_checksum'`},
		{"wrong52fingerprint", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_audit_exports_fingerprint'`, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_audit_exports_fingerprint'`},
		{"wrong51fingerprint", `UPDATE zasp_schema_metadata SET value=repeat('a',64) WHERE key='production_runtime_precision_fingerprint'`, `UPDATE zasp_schema_metadata SET value=$1 WHERE key='production_runtime_precision_fingerprint'`},
		{"runtime-function", `ALTER FUNCTION zasp_runtime_precision_transport_ready() STABLE`, `ALTER FUNCTION zasp_runtime_precision_transport_ready() VOLATILE`},
		{"unexpected-runtime-trigger", `CREATE TRIGGER audit_export_unexpected BEFORE UPDATE ON zasp_runtime_stage_work FOR EACH ROW EXECUTE FUNCTION zasp_runtime_precision_stage_insert_guard()`, `DROP TRIGGER audit_export_unexpected ON zasp_runtime_stage_work`},
		{"saved-function-grant", `GRANT EXECUTE ON FUNCTION zasp_audit_exports_predecessor.zasp_production_runtime_precision_readiness(text,text) TO PUBLIC`, `REVOKE ALL ON FUNCTION zasp_audit_exports_predecessor.zasp_production_runtime_precision_readiness(text,text) FROM PUBLIC`},
	} {
		t.Run("drift/"+drift.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, drift.change); err != nil {
				t.Fatal(err)
			}
			defer func() {
				var args []any
				if drift.name == "wrong52fingerprint" {
					args = []any{migrations.ProductionAuditExportsSemanticFingerprint()}
				}
				if drift.name == "wrong51fingerprint" {
					args = []any{migrations.ProductionRuntimePrecisionSemanticFingerprint()}
				}
				if _, err := admin.Exec(ctx, drift.restore, args...); err != nil {
					t.Fatal("restore fixture drift", err)
				}
			}()
			for _, check := range checks {
				if err := check.run(); err == nil {
					t.Error("warmed consumer accepted52 drift", check.name)
				}
			}
			var ready52 bool
			if err := admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready52); err != nil || ready52 {
				t.Error("compiled52 readiness did not refuse independently", ready52, err)
			}
			if after := preciseCompletionRows(t, ctx, admin); after != before {
				t.Fatal("refused drift changed runtime evidence")
			}
		})
	}
	for _, check := range checks {
		if err := check.run(); err != nil {
			t.Fatal("restored52 rejected", check.name, err)
		}
	}
}

func installAuditExports(t *testing.T, ctx context.Context, admin *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := precisionMigrationRunner(t, admin)
	if err := runner.UpProductionAuditExports(ctx); err != nil {
		tx, diagnosticErr := admin.Begin(ctx)
		if diagnosticErr == nil {
			_, diagnosticErr = tx.Exec(ctx, migrations.ProductionAuditExports().UpSQL())
			if diagnosticErr == nil {
				var fingerprint string
				var secure bool
				diagnosticErr = tx.QueryRow(ctx, `SELECT zasp_production_audit_exports_live_fingerprint(),zasp_production_runtime_sandbox_binding_security_ready()`).Scan(&fingerprint, &secure)
				t.Log("draft52 fingerprint", fingerprint, "predecessor secure", secure)
			}
			_ = tx.Rollback(context.Background())
		}
		t.Fatal("install audit exports", err, "diagnostic", diagnosticErr)
	}
	return runner
}

// Real SQL completion creates retained precise evidence before installing52.
// Only the established artifact/lease input fixture is seeded. No export work
// exists, so52 Down must preserve that evidence and restore the exact51 graph.
func TestAuditExportsRollbackPreservesRuntimeEvidence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	args, _ := seedSessionProjectionCompletionVersion(t, ctx, admin, true, true)
	coordinator := sandboxSessionCoordinator(t, ctx, admin)
	var result []byte
	if err := coordinator.QueryRow(ctx, `SELECT zasp_runtime_finish_precise_session_projection($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	before := preciseCompletionRows(t, ctx, admin)
	var originalFingerprint string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_precision_live_fingerprint()`).Scan(&originalFingerprint); err != nil {
		t.Fatal(err)
	}
	runner := installAuditExports(t, ctx, admin)
	if version, err := runner.Version(ctx); err != nil || version != 52 {
		t.Fatal("registered52 version", version, err)
	}
	if err := runner.DownProductionAuditExports(ctx); err != nil {
		t.Fatal("runtime evidence wrongly blocks52Down", err)
	}
	if version, err := runner.Version(ctx); err != nil || version != 51 {
		t.Fatal("restored51 version", version, err)
	}
	var afterFingerprint string
	if err := admin.QueryRow(ctx, `SELECT zasp_production_runtime_precision_live_fingerprint()`).Scan(&afterFingerprint); err != nil || afterFingerprint != originalFingerprint {
		t.Fatal("51 graph not restored exactly", err)
	}
	if after := preciseCompletionRows(t, ctx, admin); after != before {
		t.Fatal("52Down changed historical runtime evidence")
	}
	if err := runner.DownProductionRuntimePrecision(ctx); !errors.Is(err, migrations.ErrDatabase) {
		t.Fatal("51Down lost retained precision refusal", err)
	}
	if after := preciseCompletionRows(t, ctx, admin); after != before {
		t.Fatal("rejected51Down changed runtime evidence")
	}
	installAuditExports(t, ctx, admin)
	if after := preciseCompletionRows(t, ctx, admin); after != before {
		t.Fatal("52 reinstall changed runtime evidence")
	}
}

func TestAuditExportsCompatibilityRejectsPostWaitDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	worker := precisionOutboxWorker(t, ctx, admin)
	batch := seedPrecisionOutbox(t, ctx, admin, "runtime-event-v2")[0]
	installAuditExports(t, ctx, admin)
	before := precisionOutboxState(t, ctx, admin, batch)
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, []any{"runtime-events", "new-worker", "new-worker-lease-01", 30, 10},
		`SELECT zasp_runtime_claim_outbox_v2($1,$2,$3,$4,$5)`,
		`SELECT pg_advisory_xact_lock(hashtextextended('zasp_runtime_outbox:runtime-events',0)) WHERE $1::integer=30`,
		func(tx pgx.Tx) {
			if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`); err != nil {
				t.Fatal(err)
			}
		})
	requireSandboxSQLState(t, err, "55000")
	if after := precisionOutboxState(t, ctx, admin, batch); after != before {
		t.Fatal("postwait52 drift consumed precise outbox")
	}
}

func TestAuditExportsMigrationContentionIsAtomic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	migrator, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close(context.Background())
	runner := precisionMigrationRunner(t, migrator)
	for _, direction := range []struct {
		name   string
		run    func(context.Context) error
		before int64
	}{{"up", runner.UpProductionAuditExports, 51}, {"down", runner.DownProductionAuditExports, 52}} {
		for _, table := range []string{"zasp_schema_versions", "zasp_schema_metadata", "zasp_runtime_stage_work", "zasp_discovery_outbox", "zasp_workflow_idempotency", "zasp_risk_findings", "zasp_admin_audit"} {
			t.Run(direction.name+"/"+table, func(t *testing.T) {
				tx, err := admin.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{table}.Sanitize()+" IN ACCESS SHARE MODE"); err != nil {
					t.Fatal(err)
				}
				bounded, stop := context.WithTimeout(ctx, 2*time.Second)
				err = direction.run(bounded)
				expired := bounded.Err() != nil
				stop()
				if expired || !errors.Is(err, migrations.ErrDatabase) {
					t.Fatal("migration did not promptly refuse occupied fence", err)
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				if version, err := runner.Version(ctx); err != nil || version != direction.before {
					t.Fatal("occupied fence changed registry", version, err)
				}
			})
		}
		if err := direction.run(ctx); err != nil {
			t.Fatal(direction.name, err)
		}
	}
}

func TestAuditExportsWorkflowPostWaitDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	worker := sandboxSessionAPI(t, ctx, admin)
	installAuditExports(t, ctx, admin)
	observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `LOCK TABLE zasp_workflow_idempotency IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	done := make(chan error, 1)
	settled := false
	defer func() {
		stop()
		_ = blocker.Rollback(context.Background())
		if !settled {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("workflow query did not settle before provider teardown")
			}
		}
	}()
	identity := fixtureRequestIdentity(t)
	go func() {
		var body []byte
		done <- worker.QueryRow(callCtx, `SELECT zasp_workflow_mutate('create','policy','postwait',$1,$2,$3,$4,'createPolicy','audit-postwait-key',0,'{}','{}','pid_52900101-0000-4000-8000-000000000101','pid_52900102-0000-4000-8000-000000000102','')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()).Scan(&body)
	}()
	waiting := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, worker.PgConn().PID()).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("workflow did not reach mutation fence")
	}
	if _, err := blocker.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		settled = true
		requireSandboxSQLState(t, err, "55000")
	case <-callCtx.Done():
		t.Fatal("workflow did not return after released fence")
	}
	var count int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_workflow_idempotency WHERE idempotency_key='audit-postwait-key')+(SELECT count(*) FROM zasp_workflow_audit WHERE audit_id='pid_52900101-0000-4000-8000-000000000101')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("postwait workflow retained effects", count, err)
	}
}

func TestAuditExportsLateMutationWaitRefusesDrift(t *testing.T) {
	for _, mode := range []string{"workflow-new-receipt", "workflow-receiptless", "workflow-replay", "risk-new", "risk-replay", "risk-row"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			admin, _ := runtimeSandboxPredecessor(t, ctx)
			installRuntimeSandboxDraft(t, ctx, admin)
			installRuntimePrecision(t, ctx, admin)
			worker := sandboxSessionAPI(t, ctx, admin)
			identity := fixtureRequestIdentity(t)
			seedConnectorRiskFinding(t, ctx, admin, identity, "pid_52900201-0000-4000-8000-000000000201")
			installAuditExports(t, ctx, admin)
			operation := "createPolicy"
			if strings.HasPrefix(mode, "risk") {
				operation = "updateFinding"
			}
			key := strings.Join([]string{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), operation, "audit-late-wait-key"}, "\x1f")
			args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), key, identity.PrincipalID.String()}
			query := `SELECT zasp_workflow_mutate('create','policy','pid_52900202-0000-4000-8000-000000000202',$1,$2,$3,$5,'createPolicy','audit-late-wait-key',0,'{}','{"name":"late wait"}','pid_52900203-0000-4000-8000-000000000203','pid_52900204-0000-4000-8000-000000000204','pid_52900205-0000-4000-8000-000000000205') WHERE length($4::text)>0`
			if mode == "workflow-receiptless" {
				query = strings.Replace(query, "'pid_52900205-0000-4000-8000-000000000205'", "''", 1)
			}
			if strings.HasPrefix(mode, "risk") {
				query = `SELECT zasp_risk_mutate('updateFinding','pid_52900201-0000-4000-8000-000000000201',$1,$2,$3,$5,'audit-late-wait-key',1,'under_review',NULL,'pid_52900203-0000-4000-8000-000000000203','pid_52900204-0000-4000-8000-000000000204','pid_52900205-0000-4000-8000-000000000205') WHERE length($4::text)>0`
			}
			if strings.HasSuffix(mode, "replay") {
				var result []byte
				if err := worker.QueryRow(ctx, query, args...).Scan(&result); err != nil {
					t.Fatal("baseline mutation", err)
				}
			}
			snapshot := func() string {
				t.Helper()
				var body string
				if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('records',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM zasp_workflow_records r),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY receipt_id) FROM zasp_workflow_receipts r),'idempotency',(SELECT jsonb_agg(to_jsonb(r) ORDER BY idempotency_key) FROM zasp_workflow_idempotency r),'audit',(SELECT jsonb_agg(to_jsonb(r) ORDER BY audit_id) FROM zasp_workflow_audit r),'risk',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM zasp_risk_findings r))::text`).Scan(&body); err != nil {
					t.Fatal(err)
				}
				return body
			}
			before := snapshot()
			lockSQL := `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`
			if mode == "risk-row" {
				args[3] = "pid_52900201-0000-4000-8000-000000000201"
				lockSQL = `SELECT 1 FROM zasp_risk_findings WHERE id=$1 FOR UPDATE`
			}
			observer, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close(context.Background())
			err = blockedRuntimeCandidateStatement(t, ctx, admin, worker, observer, args, query, lockSQL, func(tx pgx.Tx) {
				if _, err := tx.Exec(ctx, `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_audit_exports_fingerprint'`); err != nil {
					t.Fatal(err)
				}
			})
			if err == nil {
				t.Error("later mutation wait returned success after52 drift")
			} else {
				requireSandboxSQLState(t, err, "55000")
			}
			if snapshot() != before {
				t.Error("later mutation wait committed evidence after52 drift")
			}
		})
	}
}

// A real login is not necessarily the migration owner. In particular, a
// requesting API login must not satisfy owner validation merely because it
// equals session_user inside an inherited readiness function.
func TestAuditExportsOwnerMetadataMustRemainRegistered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, _ := runtimeSandboxPredecessor(t, ctx)
	installRuntimeSandboxDraft(t, ctx, admin)
	installRuntimePrecision(t, ctx, admin)
	api := connectorRiskRepository(t, sandboxSessionAPI(t, ctx, admin))
	if err := api.Ready(ctx); err != nil {
		t.Fatal("warm51 API", err)
	}
	runner := installAuditExports(t, ctx, admin)
	for _, key := range []string{"production_discovery_execution_prior_owner", "red_team_execution_prior_permissions_owner"} {
		var original []byte
		if err := admin.QueryRow(ctx, `SELECT to_jsonb(m) FROM zasp_schema_metadata m WHERE key=$1`, key).Scan(&original); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"missing", "not_a_real_migration_owner", "invocation_discovery_api"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				if _, err := admin.Exec(ctx, `DELETE FROM zasp_schema_metadata WHERE key=$1`, key); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec(ctx, `DELETE FROM zasp_schema_metadata WHERE key=$1`, key); err != nil {
						t.Fatal(err)
					}
					if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_metadata SELECT (jsonb_populate_record(NULL::zasp_schema_metadata,$1::jsonb)).*`, original); err != nil {
						t.Fatal(err)
					}
				}()
				if value != "missing" {
					if _, err := admin.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES($1,$2)`, key, value); err != nil {
						t.Fatal(err)
					}
				}
				if err := api.Ready(ctx); err == nil {
					t.Error("warmed API accepted invalid migration owner")
				}
				var ready bool
				if err := admin.QueryRow(ctx, `SELECT zasp_production_audit_exports_readiness($1,$2)`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready); err != nil || ready {
					t.Error("compiled52 accepted invalid migration owner", ready, err)
				}
				if err := runner.DownProductionAuditExports(ctx); err == nil {
					t.Error("rollback accepted invalid migration owner")
				}
			})
		}
	}
	if err := api.Ready(ctx); err != nil {
		t.Fatal("restored owner refused", err)
	}
}
