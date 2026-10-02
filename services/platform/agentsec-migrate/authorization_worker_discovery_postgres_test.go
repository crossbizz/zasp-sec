package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// A native admission is not current provider authority. This consuming test
// reaches the registered discovery login and real prepared-effect transaction;
// an omitted native proof fence must fail it even if a Go wrapper would deny.
func TestP7WorkerDiscovery72NativeProofRequired(t *testing.T) {
	f := temporalDiscoveryPredecessor(t)
	fixtureBudget := 12 * time.Minute
	if os.Getenv("ZASP_P7_DISCOVERY_SCHEDULE") == "1" {
		fixtureBudget = 15 * time.Minute // Two real300s cadence occurrences, not a product timeout.
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureBudget)
	defer cancel()
	f.ctx = ctx
	f.runner, _ = migrations.NewRunner(&discoveryDiagnosticDatabase{migrationDatabase: &migrationDatabase{connection: f.owner}, t: t})
	runDiscoveryCLI(t, f, false)
	// The retained Discovery fixture installs68 but never runs its optional
	// executor registration. Current captured recovery needs a real, separate
	// registered compensation login, not an inherited executor impersonation.
	if _, err := f.owner.Exec(f.ctx, `CREATE ROLE discovery80_executor LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE discovery80_compensation LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); err != nil {
		t.Fatal("owned temporal runtime logins", err)
	}
	if _, err := f.owner.Exec(f.ctx, `SELECT zasp_temporal68.register_principals($1,$2)`, "discovery80_executor", "discovery80_compensation"); err != nil {
		t.Fatal("registered native temporal principals", err)
	}
	// The retained native fixture supplies connector rows but no public tenant
	// hierarchy. The current checked API/projector requires the real hierarchy.
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Discovery owned fixture','discovery-owned.invalid')`, []any{replayOrg}},
		{`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Discovery')`, []any{replayOrg, replayWorkspace}},
		{`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Discovery','production')`, []any{replayOrg, replayWorkspace, replayEnvironment}},
	} {
		if _, err := f.owner.Exec(f.ctx, statement.query, statement.args...); err != nil {
			t.Fatal("owned tenant hierarchy", err)
		}
	}
	// Complete connector fixture configuration before any admission is captured.
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_integrations SET configuration=jsonb_set(configuration,'{external_id_reference}','"ref:aws/external-id/customer-0001"') WHERE id=$1; UPDATE zasp_integration_connections SET connection_reference='ref:aws/external-id/customer-0001' WHERE integration_id=$1; UPDATE zasp_discovery_connection_subjects SET configuration_digest=(SELECT digest(convert_to(configuration::text,'UTF8'),'sha256') FROM zasp_integrations WHERE id=$1) WHERE integration_id=$1`, pgx.QueryExecModeSimpleProtocol, replayIntegration); err != nil {
		t.Fatal("owned connector configuration", err)
	}
	if _, err := f.owner.Exec(f.ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'discovery-org','discovery-member','security_engineer'); INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Discovery','["view","manage_workflows"]')`, pgx.QueryExecModeSimpleProtocol, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	connect := func(login string) *pgx.Conn {
		t.Helper()
		cfg := f.owner.Config().Copy()
		cfg.User = login
		c, err := pgx.ConnectConfig(f.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	api, worker := connect(f.registration.api), connect(f.registration.discovery)
	compensation := connect("discovery80_compensation")
	var compensationReady bool
	var compensationUser string
	// principal_ready is intentionally private. The granted retained ready
	// entry checks native pins here; current worker key_ready later checks the
	// exact compensation binding from inside its security-definer boundary.
	if err := compensation.QueryRow(f.ctx, `SELECT session_user::text,zasp_temporal68.ready($1,$2)`, migrations.ProductionTemporalExecutor().Checksum(), migrations.TemporalExecutorFingerprint()).Scan(&compensationUser, &compensationReady); err != nil || !compensationReady || compensationUser != "discovery80_compensation" {
		t.Fatal("exact registered compensation login", compensationReady, err)
	}
	var exactBindings bool
	if err := f.owner.QueryRow(f.ctx, `SELECT count(*)=2 AND bool_and((authority,principal::text) IN(('zasp_temporal_executor','discovery80_executor'),('zasp_temporal_compensation','discovery80_compensation'))) FROM zasp_temporal68.principals`).Scan(&exactBindings); err != nil || !exactBindings {
		t.Fatal("owned temporal bindings", exactBindings, err)
	}
	var receipt json.RawMessage
	// The inherited legacy schedule has no human mutation provenance. Disable
	// it through its actual API before installing the worker extension.
	if err := api.QueryRow(f.ctx, `SELECT zasp_temporal72.public_put_schedule($1,$2,$3,$4,$5,$6,1,300,'disabled',$7,$8,$9)`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, "worker-discovery-disable-0001", "pid_72008001-0000-4000-8000-000000000001", "pid_72008002-0000-4000-8000-000000000002", "pid_72008003-0000-4000-8000-000000000003").Scan(&receipt); err != nil {
		t.Fatal("real schedule mutation", err)
	}
	digest := sha256.Sum256([]byte("worker-discovery-manual-admission"))
	const syncID = "pid_72008004-0000-4000-8000-000000000004"
	const jobID = "pid_72008005-0000-4000-8000-000000000005"
	if err := api.QueryRow(f.ctx, `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,'parser_v1','tool_v1',$11,$12,$13)`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, "worker-discovery-manual-0001", syncID, jobID, "pid_72008006-0000-4000-8000-000000000006", digest[:], "pid_72008007-0000-4000-8000-000000000007", "pid_72008008-0000-4000-8000-000000000008", "pid_72008009-0000-4000-8000-000000000009").Scan(&receipt); err != nil {
		t.Fatal("real manual admission", err)
	}
	const terminalJob = "pid_72008015-0000-4000-8000-000000000015"
	if err := api.QueryRow(f.ctx, `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,'parser_v1','tool_v1',$11,$12,'')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, "worker-discovery-terminal-0001", "pid_72008014-0000-4000-8000-000000000014", terminalJob, "pid_72008016-0000-4000-8000-000000000016", digest[:], "pid_72008017-0000-4000-8000-000000000017", "pid_72008018-0000-4000-8000-000000000018").Scan(&receipt); err != nil {
		t.Fatal("retained terminal admission", err)
	}
	if err := worker.QueryRow(f.ctx, `SELECT zasp_temporal72.finish($1,$2,$3,$4,$5,$6,'cancelled','')`, replayOrg, replayWorkspace, replayEnvironment, terminalJob, replayIntegration, fmt.Sprintf("%x", digest)).Scan(&receipt); err != nil {
		t.Fatal("retained terminal finish", err)
	}
	for _, up := range []func(context.Context) error{f.runner.UpProductionTemporalAdmission, f.runner.UpProductionTemporalTestExecutor, f.runner.UpProductionTemporalTestSelector, f.runner.UpProductionTemporalHumanAdmission, f.runner.UpProductionTemporalAutomaticSources, f.runner.UpProductionTemporalFindingResponse, f.runner.UpProductionAuthorizationTemporalProfile} {
		if err := up(f.ctx); err != nil {
			t.Fatal("current profile prerequisite", err)
		}
	}
	// Retention can remove a predecessor receipt. The installer must refuse
	// that terminal recovery gap, never skip the row or invent a grantor.
	retention, err := f.owner.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tag, err := retention.Exec(f.ctx, `DELETE FROM zasp_workflow_idempotency WHERE organization_id=$1 AND idempotency_key='worker-discovery-terminal-0001'`, replayOrg); err != nil || tag.RowsAffected() != 1 {
		_ = retention.Rollback(f.ctx)
		t.Fatal("owned retained-proof removal", err)
	}
	missing := &discoveryRollbackDatabase{migrationTransaction: &migrationTransaction{transaction: retention}, t: t}
	missingRunner, _ := migrations.NewRunner(missing)
	if err := missingRunner.UpProductionAuthorizationWorkerProfile(f.ctx); err == nil || missing.failure != "P0002" {
		_ = retention.Rollback(f.ctx)
		t.Fatal("missing terminal provenance did not refuse installation", missing.failure, err)
	}
	var absent bool
	if err := retention.QueryRow(f.ctx, `SELECT to_regnamespace('zasp_authorization80_worker') IS NULL`).Scan(&absent); err != nil || !absent {
		_ = retention.Rollback(f.ctx)
		t.Fatal("failed capture install left partial authority", err)
	}
	if err := retention.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.UpProductionAuthorizationWorkerProfile(f.ctx); err != nil {
		t.Fatal("current worker profile", err)
	}
	unsigned, err := api.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	err = unsigned.QueryRow(f.ctx, `SELECT zasp_temporal72.public_request_sync($1,$2,$3,$4,$5,$6,1,$7,$8,$9,$10,'parser_v1','tool_v1',$11,$12,'')`, replayOrg, replayWorkspace, replayEnvironment, replayPrincipal, replayIntegration, "discovery72-no-current-proof", "pid_72008024-0000-4000-8000-000000000024", "pid_72008025-0000-4000-8000-000000000025", "pid_72008026-0000-4000-8000-000000000026", digest[:], "pid_72008027-0000-4000-8000-000000000027", "pid_72008028-0000-4000-8000-000000000028").Scan(&receipt)
	if rollbackErr := unsigned.Rollback(f.ctx); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	var refusal *pgconn.PgError
	if err == nil || !errors.As(err, &refusal) || refusal.Code != "42501" {
		t.Fatal("raw registered API created live delegation without current human proof", err)
	}
	var rolledBack bool
	if err := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal72.runs WHERE job_id='pid_72008025-0000-4000-8000-000000000025') AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_associations WHERE job_id='pid_72008025-0000-4000-8000-000000000025') AND NOT EXISTS(SELECT 1 FROM zasp_workflow_audit WHERE audit_id='pid_72008027-0000-4000-8000-000000000027') AND NOT EXISTS(SELECT 1 FROM zasp_workflow_idempotency WHERE idempotency_key='discovery72-no-current-proof')`).Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatal("raw API rejection left audit, receipt or delegation", err)
	}
	var retained bool
	if err := f.owner.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.discovery_associations a JOIN zasp_authorization80_worker.discovery_state s USING(organization_id,workspace_id,environment_id,job_id) WHERE a.job_id=$1 AND s.state='incomplete') AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.active_discovery WHERE job_id=$1)`, terminalJob).Scan(&retained); err != nil || !retained {
		t.Fatal("terminal capture without forward delegation", err)
	}
	var deadline time.Time
	var input string
	if err := f.owner.QueryRow(f.ctx, `SELECT deadline,encode(request_digest,'hex') FROM zasp_temporal72.runs WHERE job_id=$1`, jobID).Scan(&deadline, &input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, replayOrg, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	tx, err := worker.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	var prepared json.RawMessage
	err = tx.QueryRow(f.ctx, `SELECT zasp_temporal72.prepare_page($1,$2,$3,$4,$5,$6,$7,0,'')`, replayOrg, replayWorkspace, replayEnvironment, jobID, replayIntegration, input, deadline).Scan(&prepared)
	rollbackErr := tx.Rollback(f.ctx)
	if rollbackErr != nil {
		t.Fatal("owned rollback", rollbackErr)
	}
	var clean bool
	if readErr := f.owner.QueryRow(f.ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal72.page_effects WHERE job_id=$1) AND (SELECT state='admitted' AND deadline=admitted_at+interval '24 hours' FROM zasp_temporal72.runs WHERE job_id=$1) AND NOT zasp_authorization80_worker.runtime_ready()`, jobID).Scan(&clean); readErr != nil || !clean {
		t.Fatal("rollback/deadline/runtime boundary", readErr)
	}
	var native *pgconn.PgError
	if err == nil {
		t.Fatal("unsigned revoked discovery worker disclosed input and prepared a provider effect")
	}
	if !errors.As(err, &native) || native.Code != "42501" {
		t.Fatal("expected native authorization refusal", err)
	}
	if _, err = f.owner.Exec(f.ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, replayOrg, replayPrincipal); err != nil {
		t.Fatal(err)
	}
	phases := []string{""}
	if os.Getenv("ZASP_P7_DISCOVERY_SCHEDULE") == "1" {
		phases = []string{"1", "2"}
	}
	for _, phase := range phases {
		child := exec.CommandContext(f.ctx, "go", "test", "./apiserver", "-run", "^TestP7Discovery72CurrentAPIAndWorker$", "-count=1", "-v", "-timeout=8m")
		child.Dir = ".."
		child.Env = append(os.Environ(), "ZASP_P7_DISCOVERY_OWNER_DSN="+f.owner.Config().ConnString(), "ZASP_P7_DISCOVERY_SCHEDULE_PHASE="+phase)
		output, childErr := child.CombinedOutput()
		t.Log(string(output))
		if childErr != nil || !strings.Contains(string(output), "--- PASS: TestP7Discovery72CurrentAPIAndWorker") {
			t.Fatal("connected discovery API/worker child", phase, childErr)
		}
	}
}

type discoveryDiagnosticDatabase struct {
	*migrationDatabase
	t *testing.T
}

func (d *discoveryDiagnosticDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.migrationDatabase.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &discoveryDiagnosticTransaction{Transaction: tx, t: d.t}, nil
}

type discoveryDiagnosticTransaction struct {
	migrations.Transaction
	t       *testing.T
	failure *string
}

func (d *discoveryDiagnosticTransaction) Exec(ctx context.Context, q string, args ...any) error {
	err := d.Transaction.Exec(ctx, q, args...)
	var native *pgconn.PgError
	if errors.As(err, &native) {
		if d.failure != nil {
			*d.failure = native.Code
		}
		d.t.Logf("discovery SQLSTATE=%s message=%s position=%d internal_position=%d where=%s", native.Code, native.Message, native.Position, native.InternalPosition, native.Where)
		// Only static migration SQL is inspected here; bound arguments (which
		// can contain verifier material) are deliberately never logged.
		if native.Position > 0 && int(native.Position) <= len(q)+1 {
			at := int(native.Position) - 1
			lo, hi := max(0, at-180), min(len(q), at+180)
			d.t.Logf("discovery static SQL line=%d near=%s", strings.Count(q[:at], "\n")+1, q[lo:hi])
		}
		if native.InternalQuery != "" {
			d.t.Logf("discovery static internal SQL=%s", native.InternalQuery)
		}
	}
	return err
}

// Savepoints let the same owned native fixture test a retention boundary and
// then restore the exact predecessor bytes before the successful installation.
type discoveryRollbackDatabase struct {
	*migrationTransaction
	t       *testing.T
	failure string
}

func (d *discoveryRollbackDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.transaction.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &discoveryDiagnosticTransaction{Transaction: &migrationTransaction{transaction: tx}, t: d.t, failure: &d.failure}, nil
}
