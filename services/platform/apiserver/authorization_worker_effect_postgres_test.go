package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	fga "github.com/openfga/go-sdk/client"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
)

// Only native error class and static SQL diagnostics are logged. Migration
// arguments and connection settings can contain credentials and stay private.
type workerObservedMigrationDatabase struct {
	integrationMigrationDatabase
	t *testing.T
}

func (d *workerObservedMigrationDatabase) Begin(ctx context.Context) (migrations.Transaction, error) {
	tx, err := d.connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &workerObservedMigrationTransaction{integrationMigrationTransaction{transaction: tx}, d.t}, nil
}

type workerObservedMigrationTransaction struct {
	integrationMigrationTransaction
	t *testing.T
}

func (tx *workerObservedMigrationTransaction) Exec(ctx context.Context, q string, args ...any) error {
	err := tx.integrationMigrationTransaction.Exec(ctx, q, args...)
	var native *pgconn.PgError
	if errors.As(err, &native) {
		tx.t.Logf("worker migration SQLSTATE=%s message=%s position=%d internal_position=%d where=%s", native.Code, native.Message, native.Position, native.InternalPosition, native.Where)
	}
	return err
}

func (tx *workerObservedMigrationTransaction) QueryRow(ctx context.Context, q string, args ...any) migrations.Row {
	stage := "migration-read"
	if strings.HasPrefix(q, "SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum=$1)") {
		stage = "worker-final-check"
	}
	return workerObservedMigrationRow{row: tx.integrationMigrationTransaction.QueryRow(ctx, q, args...), t: tx.t, stage: stage}
}

type workerObservedMigrationRow struct {
	row   migrations.Row
	t     *testing.T
	stage string
}

func (r workerObservedMigrationRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	if err != nil {
		code, message, position, internal := workerMigrationSafeDiagnostic(err)
		r.t.Logf("worker migration read stage=%s code=%s class=%s position=%d internal_position=%d", r.stage, code, message, position, internal)
	} else if r.stage == "worker-final-check" && len(dest) == 1 {
		if value, ok := dest[0].(*bool); ok && value != nil && !*value {
			r.t.Log("worker migration read stage=worker-final-check result=false")
		}
	}
	return err
}

// Do not emit native Where, Detail, SQL, arguments, or arbitrary messages.
// Even wrapped driver errors can contain connection credentials.
func workerMigrationSafeDiagnostic(err error) (code, message string, position, internal int32) {
	var native *pgconn.PgError
	if errors.As(err, &native) {
		code = native.Code
		if len(code) != 5 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' && r < 'A' || r > 'Z' }) >= 0 {
			code = "invalid-sqlstate"
		}
		message = "native-error"
		switch native.Message {
		case "stack depth limit exceeded":
			message = "stack-depth"
		case "higher readiness exact predecessor changed":
			message = "higher-predecessor"
		case "higher readiness saved root changed":
			message = "higher-saved-root"
		case "higher readiness region anchor changed":
			message = "higher-region-anchor"
		case "higher readiness definition anchor changed":
			message = "higher-definition-anchor"
		}
		return code, message, native.Position, native.InternalPosition
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "non-native", "deadline", 0, 0
	}
	if errors.Is(err, context.Canceled) {
		return "non-native", "cancelled", 0, 0
	}
	return "non-native", "driver-error", 0, 0
}

func TestWorkerMigrationSafeDiagnostic(t *testing.T) {
	secret := "postgres" + "://user:private-password@secret-host/database"
	for _, tc := range []struct {
		err         error
		code, class string
	}{
		{errors.New(secret), "non-native", "driver-error"},
		{errors.Join(errors.New(secret), context.DeadlineExceeded), "non-native", "deadline"},
		{&pgconn.PgError{Code: "54001", Message: "stack depth limit exceeded", Where: secret}, "54001", "stack-depth"},
		{&pgconn.PgError{Code: "42601", Message: secret, Detail: secret, Where: secret}, "42601", "native-error"},
		{&pgconn.PgError{Code: secret, Message: secret}, "invalid-sqlstate", "native-error"},
	} {
		code, class, _, _ := workerMigrationSafeDiagnostic(tc.err)
		if code != tc.code || class != tc.class {
			t.Fatal("migration error classification did not retain its closed output")
		}
	}
}

func workerMigrationRunner(t *testing.T, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner, err := migrations.NewRunner(&workerObservedMigrationDatabase{integrationMigrationDatabase{connection: connection}, t})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

type workerObservedChecker struct {
	delegate authorization.Checker
	t        *testing.T
}

func (c workerObservedChecker) Check(ctx context.Context, q authorization.CheckRequest) (authorization.Decision, error) {
	d, err := c.delegate.Check(ctx, q)
	c.t.Logf("worker Check principal=%s target=%s permission=%s allowed=%v error=%v", q.PrincipalKind, q.ResourceType, q.Permission, d.Allowed, err)
	return d, err
}

// A registered executor must not create a finding effect merely because the
// legacy admission and native plan are valid. Its current machine decision is
// required at the actual SQL boundary, including callers outside the Go adapter.
func TestP7EffectBoundaryFindingNativeProofRequired(t *testing.T) {
	runFindingResponseFixtureOptions(t, nil, func(ctx context.Context, f findingResponseFixture, run, finding string) {
		runner := workerMigrationRunner(t, f.owner)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal("composed78/79/80 prerequisite", err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal("worker profile installation", err)
		}
		for _, changed := range []struct{ name, sql string }{
			{"private view", `CREATE OR REPLACE VIEW zasp_authorization80_worker.active_associations AS SELECT * FROM zasp_authorization80_worker.associations WHERE false`},
			{"run capture", `ALTER TABLE zasp_security_agent_runs DISABLE TRIGGER zasp_authorization80_worker_run_capture`},
			{"forged fingerprint", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT fingerprint FROM zasp_authorization80_worker.registration $$`},
			{"allow-valued catalog", `CREATE OR REPLACE FUNCTION zasp_authorization80_worker.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$ SELECT true $$`},
			{"planning boundary", `CREATE OR REPLACE FUNCTION zasp_temporal78.plan(q jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
			{"planning read boundary", `CREATE OR REPLACE FUNCTION zasp_temporal78.planning_state(q jsonb) RETURNS jsonb LANGUAGE sql AS $$ SELECT '{}'::jsonb $$`},
		} {
			tx, err := f.owner.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, changed.sql); err != nil {
				_ = tx.Rollback(ctx)
				t.Fatal(changed.name, err)
			}
			var ready78, ready79, ready80 bool
			if err := tx.QueryRow(ctx, `SELECT zasp_temporal78.ready($1,$2),zasp_authorization79.ready($3),zasp_authorization80.ready($4)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint(), migrations.ProductionAuthorizationProjection().Checksum(), migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready78, &ready79, &ready80); err != nil || ready78 || ready79 || ready80 {
				_ = tx.Rollback(ctx)
				t.Fatal("worker drift accepted", changed.name, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var request json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&request); err != nil {
			t.Fatal(err)
		}
		for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable} {
			t.Run(string(isolation), func(t *testing.T) {
				tx, err := f.executor.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				var receipt json.RawMessage
				err = tx.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&receipt)
				if err == nil {
					t.Error("registered executor created finding effect without a current machine proof")
				} else {
					code := "42501"
					if isolation != pgx.ReadCommitted {
						code = "25001"
					}
					if failure, ok := err.(*pgconn.PgError); !ok || failure.Code != code {
						t.Errorf("effect refusal class: want %s, got %v", code, err)
					}
				}
				if err := tx.Rollback(ctx); err != nil {
					t.Fatal("owned refusal transaction rollback", err)
				}
				var unchanged bool
				if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$1) AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_risk_findings WHERE id=$2 AND status='open')`, run, finding).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("refused effect changed product state", err)
				}
			})
		}
		var ready bool
		if err := f.owner.QueryRow(ctx, `SELECT zasp_temporal78.ready($1,$2) AND zasp_authorization80.ready($3)`, migrations.TemporalFindingResponseChecksum(), migrations.TemporalFindingResponseFingerprint(), migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
			t.Fatal("retained composed readiness", err)
		}
	}, false)
}

// This consumer fails if machine projection is omitted, the grantor's current
// Check is ignored, revision changes can commit, or revoked forward authority
// prevents settlement of the exact captured finding effect.
func TestP7EffectBoundaryFindingCurrentMachine(t *testing.T) {
	runFindingResponseFixtureConfigured(t, nil, func(ctx context.Context, f findingResponseFixture, run, finding string) {
		// This is a real product session row for the actual native human
		// admission's grantor, not a browser/Stytch login fixture.
		if _, err := f.owner.Exec(ctx, `INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('worker-session-fixture','sha256'),'session-worker-fixture',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, f.actor, f.o, f.w, f.e); err != nil {
			t.Fatal("owned session before native human admission", err)
		}
		otherRun, otherRequest := admitWorkerFindingTask(t, ctx, f, run)
		runner := workerMigrationRunner(t, f.owner)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal("install worker", err)
		}
		client, config := newAuthorizationProjectionFGA(t)
		checker, err := authorization.NewOpenFGA(client, config)
		if err != nil {
			t.Fatal(err)
		}
		writer, err := authorization.NewOpenFGATupleWriter(client, config)
		if err != nil {
			t.Fatal(err)
		}
		poolFor := func(principal string) *pgxpool.Pool {
			t.Helper()
			cfg, err := pgxpool.ParseConfig(f.owner.Config().ConnString())
			if err != nil {
				t.Fatal(err)
			}
			cfg.ConnConfig.User = principal
			cfg.ConnConfig.OnPgError = func(_ *pgconn.PgConn, err *pgconn.PgError) bool {
				t.Logf("worker native SQLSTATE=%s message=%s where=%s", err.Code, err.Message, err.Where)
				return err.Severity != "FATAL"
			}
			cfg.MaxConns = 2
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			return pool
		}
		var outbox string
		if err := f.owner.QueryRow(ctx, `SELECT principal_name FROM zasp_discovery_principal_bindings WHERE authority_role='zasp_outbox_worker'`).Scan(&outbox); err != nil {
			t.Fatal(err)
		}
		outboxPool := poolFor(outbox)
		projection, err := authorization.NewPostgresProjectionRepository(outboxPool)
		if err != nil {
			t.Fatal(err)
		}
		key, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{41}, 32))
		if err != nil {
			t.Fatal(err)
		}
		cleanupKey, err := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{73}, 32))
		if err != nil {
			t.Fatal(err)
		}
		registerWorkerFixtureCommands(t, ctx, f, outbox, key, cleanupKey)
		forward, err := authorization.NewWorkerExecutor(poolFor("finding78_executor"), workerObservedChecker{checker, t}, config.StoreID, config.ModelID, key)
		if err != nil {
			t.Fatal(err)
		}
		cleanup, err := authorization.NewWorkerExecutor(poolFor("finding78_compensation"), nil, "", "", cleanupKey)
		if err != nil {
			t.Fatal(err)
		}
		var request json.RawMessage
		if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&request); err != nil {
			t.Fatal(err)
		}
		if err := forward.PrepareFinding(ctx, request); err != nil {
			t.Fatal("native source materialization", err)
		}
		if err := forward.PrepareFinding(ctx, otherRequest); err != nil {
			t.Fatal("second native task materialization", err)
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, f.o, config.StoreID, config.ModelID); err != nil {
			t.Fatal(err)
		}
		beforePrepare, err := forward.Revision(ctx, f.o)
		if err != nil {
			t.Fatal(err)
		}
		if err := forward.PrepareFinding(ctx, request); err != nil {
			t.Fatal("idempotent materialization", err)
		}
		afterPrepare, err := forward.Revision(ctx, f.o)
		if err != nil || beforePrepare != afterPrepare {
			t.Fatal("materialization replay changed revision", err)
		}
		var visible int
		readErr := outboxPool.QueryRow(ctx, `SELECT count(*) FROM zasp_security_agent_runs WHERE run_id=$1`, run).Scan(&visible)
		var refused *pgconn.PgError
		if readErr == nil && visible != 0 || readErr != nil && (!errors.As(readErr, &refused) || refused.Code != "42501") {
			t.Fatal("projector public run isolation changed", readErr)
		}
		if _, err := forward.Authorize(ctx, authorization.FindingReplay, request); !errors.Is(err, authorization.ErrConflict) {
			t.Fatal("absent effect replay refusal", err)
		}
		if _, err := forward.Authorize(ctx, authorization.FindingApply, request); !errors.Is(err, authorization.ErrPending) {
			t.Fatalf("unprojected machine decision: %v", err)
		}
		reconcile := func() {
			t.Helper()
			r, err := authorization.Reconcile(ctx, projection, writer, f.o, config.StoreID, config.ModelID)
			if err != nil || !r.Applied {
				t.Fatalf("current machine reconciliation applied=%v error=%v", r.Applied, err)
			}
		}
		reconcile()
		var service string
		if err := f.owner.QueryRow(ctx, `SELECT principal_id FROM zasp_authorization80_worker.associations WHERE run_id=$1`, run).Scan(&service); err != nil {
			t.Fatal(err)
		}
		checkTask := func(task string) (authorization.CheckedDecision, error) {
			return authorization.CheckRevision(ctx, forward, checker, authorization.CheckRequest{PrincipalKind: "service", PrincipalID: service, OrganizationID: f.o, WorkspaceID: f.w, EnvironmentID: f.e, ResourceType: "security_agent", ResourceID: f.definition, Permission: "manage_workflows", TaskID: task}, config.StoreID, config.ModelID)
		}
		for _, task := range []string{run, otherRun} {
			checked, err := checkTask(task)
			if err != nil || !checked.Decision.Allowed {
				t.Fatal("concurrent native delegation missing", err)
			}
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_product_sessions SET expires_at=clock_timestamp()-interval '1 minute' WHERE session_id='session-worker-fixture'`); err != nil {
			t.Fatal(err)
		}
		var expired bool
		if err := f.owner.QueryRow(ctx, `SELECT s.expires_at<clock_timestamp() AND s.revoked_at IS NULL AND r.requested_by=s.principal_id AND x.source_kind='human78' FROM zasp_product_sessions s JOIN zasp_security_agent_runs r ON(r.organization_id,r.workspace_id,r.environment_id,r.requested_by)=(s.organization_id,s.workspace_id,s.environment_id,s.principal_id) JOIN zasp_temporal78.run_owners x ON(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) WHERE s.session_id='session-worker-fixture' AND r.run_id=$1`, otherRun).Scan(&expired); err != nil || !expired {
			t.Fatal("expired session does not match actual native human task", err)
		}
		if err := forward.PrepareFinding(ctx, otherRequest); err != nil {
			t.Fatal("session expiry invalidated native machine source", err)
		}
		if checked, err := checkTask(otherRun); err != nil || !checked.Decision.Allowed {
			t.Fatal("session expiry revoked otherwise current machine delegation", err)
		}
		assertWorkerRunCaptureMutations(t, ctx, f, otherRun)
		if _, err := f.owner.Exec(ctx, `INSERT INTO zasp_authorization80_worker.revocations(organization_id,workspace_id,environment_id,run_id) VALUES($1,$2,$3,$4)`, f.o, f.w, f.e, otherRun); err != nil {
			t.Fatal(err)
		}
		if _, err := checkTask(otherRun); !errors.Is(err, authorization.ErrPending) {
			t.Fatal("task revoke did not pend projection", err)
		}
		reconcile()
		for _, task := range []string{run, otherRun} {
			checked, err := checkTask(task)
			if err != nil || checked.Decision.Allowed != (task == run) {
				t.Fatal("independent task revocation failed", err)
			}
		}
		// Remove only the real projected grantor role in this owned test store.
		// SQL still permits the grantor, so a native-only shortcut would pass.
		grantorRole, err := authorization.ScopedRole(authorization.CheckRequest{PrincipalKind: "user", PrincipalID: f.actor, OrganizationID: f.o, WorkspaceID: f.w, EnvironmentID: f.e, ResourceType: "finding", ResourceID: finding, Permission: "manage_findings"}, "organization_admin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(ctx).Options(fga.ClientWriteOptions{StoreId: &config.StoreID, AuthorizationModelId: &config.ModelID}).Body(fga.ClientWriteRequest{Deletes: []fga.ClientTupleKeyWithoutCondition{{User: grantorRole.User, Relation: grantorRole.Relation, Object: grantorRole.Object}}}).Execute(); err != nil {
			t.Fatal("owned grantor role withdrawal failed")
		}
		if _, err := forward.Authorize(ctx, authorization.FindingApply, request); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("current FGA grantor loss not enforced", err)
		}
		// Repair from actual SQL source via normal reconciliation, never by
		// inserting a hand-written allow tuple.
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3,true)`, f.o, config.StoreID, config.ModelID); err != nil {
			t.Fatal(err)
		}
		reconcile()
		var associationCount, activeCount, memberCount, grantCount int
		if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_authorization80_worker.associations WHERE run_id=$1),(SELECT count(*) FROM zasp_authorization80_worker.active_associations WHERE run_id=$1),(SELECT count(*) FROM zasp_authorization79.members m JOIN zasp_authorization80_worker.associations a ON(m.organization_id,m.kind,m.id)=(a.organization_id,'service',a.principal_id) WHERE a.run_id=$1),(SELECT count(*) FROM zasp_authorization79.current_grants WHERE task_id=$1)`, run).Scan(&associationCount, &activeCount, &memberCount, &grantCount); err != nil {
			t.Fatal("worker projection source diagnostics", err)
		}
		t.Logf("worker source associations=%d active=%d members=%d grants=%d", associationCount, activeCount, memberCount, grantCount)
		if associationCount != 1 || activeCount != 1 || memberCount != 1 || grantCount != 4 {
			var probe json.RawMessage
			if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('run_present',r.run_id IS NOT NULL,'run_state_active',r.state IN('queued','planning','waiting_approval','running','verifying'),'definition_present',d.definition_id IS NOT NULL,'definition_version_equal',d.version=a.definition_version,'definition_active',d.deleted_at IS NULL AND d.activation IN('supervised','autonomous') AND d.body->'enabled'='true'::jsonb,'grantor_present',m.principal_id IS NOT NULL,'grantor_active',m.active,'grantor_matches_native',g.grantor_id=a.grantor_id,'principal_matches_native',g.principal_id=a.principal_id,'task_revoked',EXISTS(SELECT 1 FROM zasp_authorization80_worker.revocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id)),'grant_revoked',EXISTS(SELECT 1 FROM zasp_temporal78.grant_revocations v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.definition_version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version)),'native74_visible',zasp_temporal74.visible(a.organization_id,a.workspace_id,a.environment_id,a.run_id)) FROM zasp_authorization80_worker.associations a LEFT JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) LEFT JOIN zasp_security_agent_definitions d ON(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id) LEFT JOIN zasp_identity_memberships m ON(m.organization_id,m.principal_id)=(a.organization_id,a.grantor_id) LEFT JOIN zasp_temporal78.service_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version) WHERE a.run_id=$1`, run).Scan(&probe); err != nil {
				t.Fatal("active association predicate probe", err)
			}
			t.Logf("active association predicate probe %s", probe)
			if err := f.executor.QueryRow(ctx, `SELECT jsonb_build_object('native_source_current',zasp_authorization80_worker.finding_source('finding.apply',$1::jsonb) IS NOT NULL)`, request).Scan(&probe); err != nil {
				t.Fatal("registered executor predicate probe", err)
			}
			t.Logf("registered executor predicate probe %s", probe)
			t.Fatal("validated finding task missing its exact projection sources")
		}
		if err := projection.WithOrganization(ctx, f.o, func(session authorization.ProjectionSession) error {
			snapshot, err := session.Snapshot(ctx)
			if err != nil {
				return err
			}
			var taskGrants int
			for _, grant := range snapshot.Grants {
				if grant.TaskID == run {
					taskGrants++
				}
			}
			t.Logf("worker projection snapshot task grants=%d total members=%d recorded tuples=%d", taskGrants, len(snapshot.Members), len(snapshot.Known))
			if taskGrants != 4 {
				t.Error("projection snapshot omitted task grants")
			}
			return nil
		}); err != nil {
			t.Fatal("worker projection snapshot diagnostics", err)
		}
		decision, err := forward.Authorize(ctx, authorization.FindingApply, request)
		if err != nil {
			t.Fatal("current grantor and bounded machine Check", err)
		}
		if _, err := cleanup.Execute(ctx, decision); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("compensation adapter accepted forward decision", err)
		}
		var wrong map[string]any
		if json.Unmarshal(request, &wrong) != nil {
			t.Fatal("fixture request")
		}
		for _, field := range []string{"organization_id", "workspace_id", "environment_id", "run_id"} {
			old := wrong[field]
			wrong[field] = f.next()
			changed, _ := json.Marshal(wrong)
			if _, err := forward.Authorize(ctx, authorization.FindingApply, changed); !errors.Is(err, authorization.ErrConflict) {
				t.Fatal("wrong worker reference accepted", field, err)
			}
			wrong[field] = old
		}
		if _, err := forward.Authorize(ctx, authorization.WorkerOperation("policy.monitor"), request); !errors.Is(err, authorization.ErrInvalid) {
			t.Fatal("unsupported mode accepted", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_authorization80_worker.run_state SET run_version=run_version+1 WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		if _, err := forward.Authorize(ctx, authorization.FindingApply, request); !errors.Is(err, authorization.ErrConflict) {
			t.Fatal("capture drift accepted", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_authorization80_worker.run_state SET run_version=run_version-1 WHERE run_id=$1`, run); err != nil {
			t.Fatal(err)
		}
		reconcile()
		decision, err = forward.Authorize(ctx, authorization.FindingApply, request)
		if err != nil {
			t.Fatal("authority after capture drift repair", err)
		}
		assertWorkerConcurrentRevocation(t, ctx, f, forward, decision, run, finding)
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor); err != nil {
			t.Fatal(err)
		}
		reconcile()
		decision, err = forward.Authorize(ctx, authorization.FindingApply, request)
		if err != nil {
			t.Fatal("authority after concurrent revoke repair", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor); err != nil {
			t.Fatal(err)
		}
		if _, err := forward.Execute(ctx, decision); !errors.Is(err, authorization.ErrConflict) {
			t.Fatalf("revoked after Check consumed decision: %v", err)
		}
		if _, err := f.owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor); err != nil {
			t.Fatal(err)
		}
		reconcile()
		decision, err = forward.Authorize(ctx, authorization.FindingApply, request)
		if err != nil {
			t.Fatal("restored current authority", err)
		}
		assertWorkerNativeProofBinding(t, ctx, f, forward, key, cleanupKey, request)
		for _, changed := range []struct {
			name, change, restore string
			args                  []any
		}{
			{"finding version", `UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, `UPDATE zasp_risk_findings SET version=version-1 WHERE id=$1`, []any{finding}},
			{"definition enabled", `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','false') WHERE definition_id=$1`, `UPDATE zasp_security_agent_definitions SET body=jsonb_set(body,'{enabled}','true') WHERE definition_id=$1`, []any{f.definition}},
		} {
			if _, err := f.owner.Exec(ctx, changed.change, changed.args...); err != nil {
				t.Fatal("source change fixture", changed.name, err)
			}
			if _, err := forward.Authorize(ctx, authorization.FindingApply, request); err == nil {
				t.Fatal("changed source authorized", changed.name)
			}
			if _, err := forward.Execute(ctx, decision); !errors.Is(err, authorization.ErrConflict) {
				t.Fatal("source changed after Check consumed", changed.name, err)
			}
			if _, err := f.owner.Exec(ctx, changed.restore, changed.args...); err != nil {
				t.Fatal("source restore fixture", changed.name, err)
			}
			reconcile()
			decision, err = forward.Authorize(ctx, authorization.FindingApply, request)
			if err != nil {
				t.Fatal("restored source authority", changed.name, err)
			}
		}
		rotated, err := authorization.NewWorkerKey(authorization.WorkerForward, bytes.Repeat([]byte{42}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, "worker-forward", rotated.Version(), rotated.Verifier()); err != nil {
			t.Fatal(err)
		}
		if _, err := forward.Execute(ctx, decision); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("rotated forward key accepted old proof", err)
		}
		forward, err = authorization.NewWorkerExecutor(poolFor("finding78_executor"), workerObservedChecker{checker, t}, config.StoreID, config.ModelID, rotated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forward.Authorize(ctx, authorization.FindingApply, request); !errors.Is(err, authorization.ErrPending) {
			t.Fatal("key rotation did not pend projection", err)
		}
		reconcile()
		decision, err = forward.Authorize(ctx, authorization.FindingApply, request)
		if err != nil {
			t.Fatal("rotated current authority", err)
		}
		runWorkerFindingProductChild(t, ctx, f, config, request, "apply")
		decision, err = forward.Authorize(ctx, authorization.FindingReplay, request)
		if err != nil {
			t.Fatal("actual product committed receipt source", err)
		}
		receipt, err := forward.Execute(ctx, decision)
		if err != nil {
			t.Fatal("actual finding effect", err)
		}
		var body struct {
			RunID string `json:"run_id"`
			State string `json:"state"`
		}
		if json.Unmarshal(receipt, &body) != nil || body.RunID != run || body.State != "remediated" {
			t.Fatal("finding effect receipt binding")
		}
		if _, err := f.owner.Exec(ctx, `INSERT INTO zasp_temporal78.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id) SELECT organization_id,workspace_id,environment_id,definition_id,definition_version,$2,$3 FROM zasp_temporal78.run_owners WHERE run_id=$1;UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$4 AND principal_id=$2`, pgx.QueryExecModeSimpleProtocol, run, f.actor, f.next(), f.o); err != nil {
			t.Fatal(err)
		}
		var capturedRevocation bool
		if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.revocations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND run_id=$4)`, f.o, f.w, f.e, run).Scan(&capturedRevocation); err != nil || !capturedRevocation {
			t.Fatal("native grant revocation not captured", err)
		}
		var cleanupFields map[string]any
		if json.Unmarshal(request, &cleanupFields) != nil {
			t.Fatal("cleanup fixture reference")
		}
		cleanupFields["reason"] = "terminal"
		cleanupRequest, _ := json.Marshal(cleanupFields)
		captured, err := cleanup.Authorize(ctx, authorization.FindingCleanup, cleanupRequest)
		if err != nil {
			t.Fatal("captured cleanup after revoke", err)
		}
		rotatedCleanup, err := authorization.NewWorkerKey(authorization.CapturedCompensation, bytes.Repeat([]byte{74}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, "captured-compensation", rotatedCleanup.Version(), rotatedCleanup.Verifier()); err != nil {
			t.Fatal(err)
		}
		if _, err := cleanup.Execute(ctx, captured); !errors.Is(err, authorization.ErrDenied) {
			t.Fatal("rotated cleanup key accepted old proof", err)
		}
		cleanup, err = authorization.NewWorkerExecutor(poolFor("finding78_compensation"), nil, "", "", rotatedCleanup)
		if err != nil {
			t.Fatal(err)
		}
		captured, err = cleanup.Authorize(ctx, authorization.FindingCleanup, cleanupRequest)
		if err != nil {
			t.Fatal("cleanup under pending forward projection", err)
		}
		if _, err := cleanup.Execute(ctx, captured); err != nil {
			t.Fatal("native captured compensation", err)
		}
		var exact bool
		if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal78.response_metadata WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_effects WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_risk_findings WHERE id=$2 AND status='under_review' AND version=2)`, run, finding).Scan(&exact); err != nil || !exact {
			t.Fatal("effect cardinality or cleanup changed finding outcome", err)
		}
		reconcile()
		if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM zasp_authorization79.current_grants WHERE task_id=$1`, run).Scan(&grantCount); err != nil || grantCount != 0 {
			t.Fatal("terminal revoked task retained projected grants", err)
		}
		replay, err := forward.Authorize(ctx, authorization.FindingReplay, request)
		if err != nil {
			t.Fatal("captured receipt replay after revoke", err)
		}
		replayed, err := forward.Execute(ctx, replay)
		if err != nil || !bytes.Equal(receipt, replayed) {
			t.Fatal("captured receipt replay changed", err)
		}
		wrong["workspace_id"] = f.next()
		changed, _ := json.Marshal(wrong)
		if _, err := forward.Authorize(ctx, authorization.FindingReplay, changed); !errors.Is(err, authorization.ErrConflict) {
			t.Fatal("wrong scope replay accepted", err)
		}
		if err := f.owner.QueryRow(ctx, `SELECT (SELECT count(*)=1 FROM zasp_temporal78.response_metadata WHERE run_id=$1) AND (SELECT count(*)=1 FROM zasp_security_agent_effects WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_risk_findings WHERE id=$2 AND status='under_review' AND version=2)`, run, finding).Scan(&exact); err != nil || !exact {
			t.Fatal("replay repeated finding effect", err)
		}
		if _, err := forward.Authorize(ctx, authorization.FindingApply, request); err == nil {
			t.Fatal("revoked terminal task obtained fresh forward authority")
		}
		runWorkerFindingProductChild(t, ctx, f, config, request, "replay")
	}, false, 2)
}

// A revision check without a locking, current read would let this already
// signed decision create a finding effect while revocation is committing.
func assertWorkerConcurrentRevocation(t *testing.T, ctx context.Context, f findingResponseFixture, forward *authorization.WorkerExecutor, decision authorization.WorkerDecision, run, finding string) {
	t.Helper()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1 AND principal_id=$2`, f.o, f.actor); err != nil {
		t.Fatal(err)
	}
	effectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	joined := make(chan error, 1)
	consumed := false
	go func() { _, err := forward.Execute(effectCtx, decision); joined <- err }()
	// Cleanup always releases our revision lock before joining the caller.
	defer func() {
		_ = tx.Rollback(ctx)
		cancel()
		if consumed {
			return
		}
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		if _, err := tx.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='finding78_executor' AND wait_event_type='Lock' AND query LIKE '%zasp_temporal78.apply%' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err := <-joined:
			consumed = true
			t.Fatal("effect returned before held authority change committed", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !blocked {
		t.Fatal("effect never waited on held authority revision")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-joined
	consumed = true
	if !errors.Is(err, authorization.ErrConflict) {
		t.Fatal("concurrent committed revocation did not refuse stale decision", err)
	}
	var unchanged bool
	if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_security_agent_effects WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_risk_findings WHERE id=$2 AND status='open' AND version=1)`, run, finding).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("concurrently revoked decision changed finding", err)
	}
	t.Log("effect waited on uncommitted authority revision; committed revocation refused stale proof without effect")
}

// Public row mutation must update the private capture and revision atomically.
// Native immutable owners also prevent identity deletion/movement; no fixture
// disables those constraints to manufacture a permitted destructive path.
func assertWorkerRunCaptureMutations(t *testing.T, ctx context.Context, f findingResponseFixture, run string) {
	t.Helper()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var before int64
	if err := tx.QueryRow(ctx, `SELECT desired FROM zasp_authorization79.organizations WHERE organization_id=$1`, f.o).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE zasp_security_agent_runs SET state='cancelled',version=version+1 WHERE run_id=$1`, run); err != nil {
		t.Fatal(err)
	}
	var captured bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.run_state s JOIN zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) WHERE s.run_id=$1 AND s.state='cancelled' AND s.run_version=r.version AND s.present) AND NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.active_associations WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_authorization79.organizations WHERE organization_id=$2 AND desired>$3)`, run, f.o, before).Scan(&captured); err != nil || !captured {
		t.Fatal("public termination did not atomically invalidate captured authority", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`DELETE FROM zasp_security_agent_runs WHERE run_id=$1`, `UPDATE zasp_security_agent_runs SET run_id=$2 WHERE run_id=$1`} {
		tx, err := f.owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		args := []any{run}
		if strings.Contains(query, "$2") {
			args = append(args, f.next())
		}
		_, err = tx.Exec(ctx, query, args...)
		if err == nil {
			_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
		}
		var failure *pgconn.PgError
		refused := errors.As(err, &failure) && failure.Code == "23503"
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if !refused {
			t.Fatal("native owned run identity mutation was not constrained", err)
		}
	}
	t.Log("public termination updates capture and revision together; native foreign keys refuse owned run deletion and identity movement")
}

// Load creates a planning intent and discloses context; state discloses the
// stored planning body. Both must refuse an unproved registered executor.
func TestP7PlanningBoundaryFindingNativeProofRequired(t *testing.T) {
	runWorkerFindingPlanningFixture(t, false)
}

func TestP7PlanningFindingCapturedCleanup(t *testing.T) {
	runWorkerFindingPlanningFixture(t, true)
}

// This consumes the actual Activity planner, HTTP transport and artifact store.
// Returning unavailable, bypassing the machine fence or sending twice must fail.
func TestP7PlanningFindingProductNative(t *testing.T) {
	runWorkerFindingPlanningProductFixture(t, "planning")
}

func TestP7PlanningFindingProductRecovery(t *testing.T) {
	for _, phase := range []string{"planning-prepared-revoke", "planning-sent-revoke", "planning-sent-fga"} {
		t.Run(phase, func(t *testing.T) { runWorkerFindingPlanningProductFixture(t, phase) })
	}
}

func TestP7PlanningFindingProductLateUsage(t *testing.T) {
	runWorkerFindingPlanningProductFixture(t, "planning-sent-late")
}

func runWorkerFindingPlanningProductFixture(t *testing.T, phase string) {
	t.Helper()
	runFindingResponseFixtureConfigured(t, nil, func(ctx context.Context, f findingResponseFixture, run, finding string) {
		_, request := admitWorkerFindingTask(t, ctx, f, run)
		runner := workerMigrationRunner(t, f.owner)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		_, config := newAuthorizationProjectionFGA(t)
		if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization79.configure($1,$2,$3)`, f.o, config.StoreID, config.ModelID); err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			purpose authorization.WorkerPurpose
			seed    byte
		}{{authorization.WorkerForward, 42}, {authorization.CapturedCompensation, 73}} {
			key, err := authorization.NewWorkerKey(item.purpose, bytes.Repeat([]byte{item.seed}, 32))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.owner.Exec(ctx, `SELECT zasp_authorization80_worker.register_verifier($1,$2,$3)`, string(item.purpose), key.Version(), key.Verifier()); err != nil {
				t.Fatal(err)
			}
		}
		runWorkerFindingProductChild(t, ctx, f, config, request, phase)
	}, false, 2)
}

func runWorkerFindingPlanningFixture(t *testing.T, cleanupOnly bool) {
	t.Helper()
	runFindingResponseFixtureConfigured(t, nil, func(ctx context.Context, f findingResponseFixture, run, finding string) {
		otherRun, request := admitWorkerFindingTask(t, ctx, f, run)
		completeRun, completeRequest := admitWorkerFindingTask(t, ctx, f, run)
		runner := workerMigrationRunner(t, f.owner)
		if err := runner.UpProductionAuthorizationTemporalProfile(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionAuthorizationWorkerProfile(ctx); err != nil {
			t.Fatal(err)
		}
		var q map[string]any
		if err := json.Unmarshal(request, &q); err != nil {
			t.Fatal(err)
		}
		delete(q, "input_digest")
		for _, phase := range []string{"load", "state"} {
			query := `SELECT zasp_temporal78.plan($1::jsonb)`
			q["operation"] = "load"
			q["run_id"] = otherRun
			if phase == "state" {
				delete(q, "operation")
				q["run_id"] = run
				query = `SELECT zasp_temporal78.planning_state($1::jsonb)`
			}
			body, _ := json.Marshal(q)
			tx, err := f.executor.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			var result json.RawMessage
			err = tx.QueryRow(ctx, query, body).Scan(&result)
			var failure *pgconn.PgError
			if err == nil {
				t.Errorf("unproved executor obtained native planning %s", phase)
			} else if !errors.As(err, &failure) || failure.Code != "42501" {
				t.Errorf("planning %s refusal class: %v", phase, err)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var unchanged bool
		if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal78.planning_jobs WHERE run_id=$1) AND EXISTS(SELECT 1 FROM zasp_security_agent_runs WHERE run_id=$1 AND state='queued' AND version=1)`, otherRun).Scan(&unchanged); err != nil || !unchanged {
			t.Fatal("planning refusal/rollback changed native intent", err)
		}
		assertWorkerFindingPlanning(t, ctx, f, run, otherRun, request, completeRun, completeRequest, cleanupOnly)
	}, false, 3)
}

func admitWorkerFindingTask(t *testing.T, ctx context.Context, f findingResponseFixture, originalRun string) (string, json.RawMessage) {
	t.Helper()
	finding, run := f.next(), f.next()
	if _, err := f.owner.Exec(ctx, `INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status) VALUES($1,$2,$3,$4,'posture','credential','Independent worker task fixture','high','open')`, f.o, f.w, f.e, finding); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := f.owner.QueryRow(ctx, `SELECT definition_version FROM zasp_temporal78.run_owners WHERE run_id=$1`, originalRun).Scan(&version); err != nil {
		t.Fatal(err)
	}
	q, _ := json.Marshal(map[string]any{"organization_id": f.o, "workspace_id": f.w, "environment_id": f.e, "definition_id": f.definition, "actor_id": f.actor, "idempotency_key": "worker80-" + run, "definition_version": version, "run_id": run, "trigger_kind": "finding", "trigger_id": finding, "trigger_version": 1, "trigger_source": "credential", "audit_id": f.next(), "correlation_id": f.next(), "receipt_id": f.next()})
	var receipt, jsonRequest json.RawMessage
	if err := f.api.QueryRow(ctx, `SELECT zasp_temporal78.resource($1::jsonb)`, q).Scan(&receipt); err != nil {
		t.Fatal("second actual native admission", err)
	}
	var body struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if json.Unmarshal(receipt, &body) != nil || body.ID != run || body.State != "queued" {
		t.Fatal("second native admission receipt")
	}
	if err := f.owner.QueryRow(ctx, `SELECT jsonb_build_object('organization_id',organization_id,'workspace_id',workspace_id,'environment_id',environment_id,'run_id',run_id,'definition_version',definition_version,'input_digest',input_digest) FROM zasp_temporal78.run_owners WHERE run_id=$1`, run).Scan(&jsonRequest); err != nil {
		t.Fatal(err)
	}
	return run, jsonRequest
}

func registerWorkerFixtureCommands(t *testing.T, ctx context.Context, f findingResponseFixture, outbox string, forward, compensation *authorization.WorkerKey) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "agentsec-migrate")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "../agentsec-migrate")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("fixture command build failed: %v\n%s", err, output)
	}
	human, err := authorization.NewAttestationKey(bytes.Repeat([]byte{92}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.owner.Exec(ctx, `SELECT zasp_authorization80.register_verifier($1,$2)`, human.Version(), human.Verifier()); err != nil {
		t.Fatal("human fixture registration", err)
	}
	for _, purpose := range []struct {
		name, input string
		seed        byte
		key         *authorization.WorkerKey
	}{
		{"register-worker-authorization-verifier", "ZASP_AUTHORIZATION_WORKER_KEY_FILE", 41, forward},
		{"register-compensation-authorization-verifier", "ZASP_AUTHORIZATION_COMPENSATION_KEY_FILE", 73, compensation},
	} {
		path := filepath.Join(dir, purpose.name)
		if err := os.WriteFile(path, bytes.Repeat([]byte{purpose.seed}, 32), 0o400); err != nil {
			t.Fatal(err)
		}
		for _, login := range []string{f.owner.Config().User, f.api.Config().User, "finding78_executor", "finding78_compensation", outbox} {
			cfg := f.owner.Config().Copy()
			cfg.User = login
			command := exec.CommandContext(ctx, binary, purpose.name)
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "ZASP_") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "ZASP_POSTGRES_DSN="+cfg.ConnString(), "ZASP_MIGRATION_DB_PRINCIPAL="+login, purpose.input+"="+path, "ZASP_MIGRATION_TIMEOUT=30s")
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			if login == f.owner.Config().User {
				if err != nil || stdout.Len() != 0 || stderr.Len() != 0 {
					t.Fatal("registered migration command did not provision exact purpose")
				}
			} else {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || stdout.Len() != 0 || !strings.HasSuffix(strings.TrimSpace(stderr.String()), " release migration failed") || strings.Contains(strings.TrimSpace(stderr.String()), "\n") {
					t.Fatal("non-migration command did not refuse with fixed error")
				}
			}
		}
		var exact bool
		if err := f.owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80_worker.verifiers WHERE version=$1 AND key=$2) AND zasp_authorization80.key_ready($3) AND EXISTS(SELECT 1 FROM zasp_authorization80.verifier WHERE version=$3 AND key=$4)`, purpose.key.Version(), purpose.key.Verifier(), human.Version(), human.Verifier()).Scan(&exact); err != nil || !exact {
			t.Fatal("purpose provisioning changed human verifier or wrong machine key", err)
		}
	}
	t.Log("real migration commands provisioned both machine purposes; API/executor/compensation/outbox commands refused; human verifier unchanged")
}

// Build authenticated fixture bytes independently of the opaque Go decision so
// native tests exercise purpose, phase, lifetime and source binding themselves.
func assertWorkerNativeProofBinding(t *testing.T, ctx context.Context, f findingResponseFixture, forward *authorization.WorkerExecutor, key, compensation *authorization.WorkerKey, request json.RawMessage) {
	t.Helper()
	var facts json.RawMessage
	var principal string
	if err := f.executor.QueryRow(ctx, `SELECT zasp_authorization80_worker.finding_source('finding.apply',$1::jsonb),session_user`, request).Scan(&facts, &principal); err != nil {
		t.Fatal(err)
	}
	revision, err := forward.Revision(ctx, f.o)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, code string }{{"compensation purpose", "42501"}, {"wrong phase", "42501"}, {"wrong principal", "42501"}, {"expired", "42501"}, {"wrong target", "40001"}, {"malformed envelope", "42501"}, {"duplicate body field", "42501"}} {
		now := time.Now().UnixMilli()
		purpose := "worker-forward"
		signing := key
		body := map[string]any{"purpose": purpose, "key_version": key.Version(), "operation": "finding.apply", "request": request, "facts": facts, "revision": revision, "session_user": principal, "issued_at": now, "expires_at": now + 30000}
		switch test.name {
		case "compensation purpose":
			purpose = "captured-compensation"
			signing = compensation
			body["purpose"] = purpose
			body["key_version"] = signing.Version()
		case "wrong phase":
			body["operation"] = "finding.replay"
		case "wrong principal":
			body["session_user"] = "finding78_compensation"
		case "expired":
			body["issued_at"] = now - 30000
			body["expires_at"] = now - 1
		case "wrong target":
			var changed map[string]any
			if json.Unmarshal(facts, &changed) != nil {
				t.Fatal("fixture facts")
			}
			changed["finding_id"] = f.next()
			body["facts"] = changed
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if test.name == "duplicate body field" {
			raw = append([]byte(`{"purpose":"worker-forward",`), raw[1:]...)
		}
		mac := hmac.New(sha256.New, signing.Verifier())
		_, _ = mac.Write([]byte("zasp-authorization-" + purpose + "-v1\x00"))
		_, _ = mac.Write(raw)
		envelope, err := json.Marshal(map[string]any{"body": raw, "version": signing.Version(), "mac": hex.EncodeToString(mac.Sum(nil))})
		if err != nil {
			t.Fatal(err)
		}
		if test.name == "malformed envelope" {
			envelope = []byte(`{"body":false}`)
		}
		tx, err := f.executor.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('zasp.worker_proof',$1,true)`, string(envelope)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		var result json.RawMessage
		err = tx.QueryRow(ctx, `SELECT zasp_temporal78.apply($1::jsonb)`, request).Scan(&result)
		var native *pgconn.PgError
		valid := errors.As(err, &native) && native.Code == test.code
		if rollback := tx.Rollback(ctx); rollback != nil {
			t.Fatal(rollback)
		}
		if !valid {
			t.Fatal("native proof binding refusal", test.name, err)
		}
	}
	var unchanged bool
	if err := f.owner.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE run_id=$1)`, revisionTask(request)).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("refused native proofs produced effect", err)
	}
}

func revisionTask(request json.RawMessage) string {
	var value struct {
		Run string `json:"run_id"`
	}
	_ = json.Unmarshal(request, &value)
	return value.Run
}

func runWorkerFindingProductChild(t *testing.T, ctx context.Context, f findingResponseFixture, config runtimeservices.Config, request json.RawMessage, phase string) {
	runWorkerProductChild(t, ctx, f.owner, config, request, phase, nil)
}

func runWorkerProductChild(t *testing.T, ctx context.Context, owner *pgx.Conn, config runtimeservices.Config, request json.RawMessage, phase string, selection any) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "worker-product-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-o", binary, "../agentsec-worker")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("product fixture build failed: %v\n%s", err, output)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	name := "TestP7FindingProductMachineNative"
	if strings.HasPrefix(phase, "test74-") {
		name = "TestP7Test74ProductMachineNative"
	}
	child := exec.CommandContext(ctx, binary, "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	child.WaitDelay = 5 * time.Second
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ZASP_") {
			child.Env = append(child.Env, value)
		}
	}
	selected, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	child.Env = append(child.Env, "ZASP_P7_WORKER_OWNER_DSN="+owner.Config().ConnString(), "ZASP_P7_WORKER_FGA_CONFIG="+string(raw), "ZASP_P7_WORKER_REQUEST="+string(request), "ZASP_P7_WORKER_PHASE="+phase, "ZASP_P7_WORKER_SELECTION="+string(selected))
	output, err := child.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name)) || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatalf("actual product child %s failed: %v\n%s", phase, err, output)
	}
	t.Logf("actual product child %s joined with native consuming assertions", phase)
}
