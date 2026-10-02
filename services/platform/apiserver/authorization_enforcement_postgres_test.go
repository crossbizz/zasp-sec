package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Canonical61's existing registered fixture owner is zasp_e2e. This helper
// installs the full predecessor and roles, without product rows or model pins.
func migrateP7Authorization(t *testing.T, ctx context.Context, conn *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := migrateToTypedInventoryCutover(t, ctx, conn)
	runner, _ = migrations.NewRunner(&orderedAdmissionMigrationDatabase{connection: conn, t: t})
	if os.Getenv("ZASP_P7_IDENTITY_TEST") == "1" {
		runner, _ = migrations.NewRunner(&identityObservedMigrationDatabase{connection: conn, t: t})
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"auth80_api", "auth80_discovery", "auth80_ingest", "auth80_runtime", "auth80_outbox", "auth80_gateway"} {
		exec(fmt.Sprintf(`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, name))
	}
	exec(`SELECT zasp_discovery_register_principals(session_user,'auth80_api','auth80_discovery','auth80_ingest','auth80_runtime','auth80_outbox','auth80_gateway')`)
	installAuthorization := runner.UpProductionAuthorizationEnforcement
	if os.Getenv("ZASP_P7_AUDIT_TEST") == "1" {
		installAuthorization = func(ctx context.Context) error {
			observe := func(stage string) bool {
				t.Helper()
				var ready, sourceACL bool
				if err := conn.QueryRow(ctx, `SELECT public.zasp_production_audit_exports_readiness($1,$2),public.zasp_audit_export_source_acl_ready()`, migrations.ProductionAuditExports().Checksum(), migrations.ProductionAuditExportsSemanticFingerprint()).Scan(&ready, &sourceACL); err != nil || !sourceACL {
					t.Fatalf("legacy source52 observation %s: ready=%t ACL=%t error=%v", stage, ready, sourceACL, err)
				}
				t.Logf("source52 %s guarded install: legacy_export_ready=%t source_acl_ready=%t", stage, ready, sourceACL)
				return ready
			}
			before := observe("before")
			installAudit := runner.UpProductionAuthorizationAuditProfile
			if os.Getenv("ZASP_P7_IDENTITY_TEST") == "1" {
				installAudit = runner.UpProductionAuthorizationIdentityProfile
			}
			if err := installAudit(ctx); err != nil {
				return err
			}
			if after := observe("after"); after != before {
				t.Fatalf("legacy source52 prerequisite changed: before=%t after=%t", before, after)
			}
			return nil
		}
	}
	for _, up := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration, runner.UpProductionSecurityAgentControls, runner.UpProductionSecurityAgentAutonomousResponse, runner.UpProductionSecurityAgentTemporaryPolicy, runner.UpProductionSecurityAgentConnectorRevocation, runner.UpProductionSecurityAgentSessionIsolation, runner.UpProductionRedTeamExecution,
		runner.UpProductionAttackLabExecution, runner.UpProductionRecovery, runner.UpProductionPolicyDeployment, runner.UpProductionHomeAttention, runner.UpProductionApprovalNotification, runner.UpProductionWorkflowCompatibility, runner.UpProductionSecurityAgentPlanner, runner.UpProductionSecurityAgentAttackPath, runner.UpProductionIntegrationSetup, runner.UpProductionIntegrationWebhook, runner.UpProductionRuntimeQueueReplay, runner.UpProductionRedTeamSafety, runner.UpProductionRedTeamInvocation, runner.UpProductionRedTeamArtifacts, runner.UpProductionRuntimeSessions, runner.UpProductionRuntimeSessionReads, runner.UpProductionRuntimeSessionSearch, runner.UpProductionRuntimeSessionQuery, runner.UpProductionRuntimeSessionEvidence, runner.UpProductionRuntimeEnrollmentPairing, runner.UpProductionReconciliationLanePlan, runner.UpProductionRuntimeCandidateAuthority, runner.UpProductionRuntimeAcceptance, runner.UpProductionRuntimeCorrelationRouting, runner.UpProductionRuntimeSandboxBinding, runner.UpProductionRuntimePrecision, runner.UpProductionAuditExports, runner.UpProductionSecurityAgentBudgets, runner.UpProductionSecurityAgentRunContext, runner.UpProductionSecurityAgentExistingTests, runner.UpProductionCompliance, runner.UpProductionSecurityAgentAttackLab, runner.UpProductionSecurityAgentExports, runner.UpProductionSecurityAgentWebhooks, runner.UpProductionDiscoveryScheduleReplay, runner.UpProductionSecurityAgentMultistep,
		runner.UpProductionAuthorizationProjection, installAuthorization} {
		if err := up(ctx); err != nil {
			version, _ := runner.Version(ctx)
			t.Logf("failed after canonical version %d", version)
			tx, _ := conn.Begin(ctx)
			_, detail := tx.Exec(ctx, migrations.ProductionAuthorizationEnforcement().UpSQL())
			_ = tx.Rollback(ctx)
			t.Logf("installation diagnostic: %v", detail)
			var pgerr *pgconn.PgError
			if errors.As(detail, &pgerr) {
				t.Logf("SQL position=%d internal=%d query=%s context=%s", pgerr.Position, pgerr.InternalPosition, pgerr.InternalQuery, pgerr.Where)
			}
			t.Fatalf("authorization install: %v", err)
		}
	}
	var canonicalReady bool
	if os.Getenv("ZASP_P7_AUDIT_TEST") == "1" {
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE name='canonical61-authorization79-80-v1' AND audit_mode='source52-canonical61-audit-v1') AND zasp_authorization80_audit.guard_ready() AND zasp_authorization80_audit.catalog_ready()`).Scan(&canonicalReady); err != nil || !canonicalReady {
			t.Fatalf("guarded fixture mode/readiness: %t %v", canonicalReady, err)
		}
	}
	if err := conn.QueryRow(ctx, `SELECT zasp_sa_multistep_readiness($1,$2)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint()).Scan(&canonicalReady); err != nil || !canonicalReady {
		t.Fatalf("registered canonical61 readiness after extensions: %v %v", canonicalReady, err)
	}
	key := authorizationFixtureAttestor(t)
	exec(`SELECT zasp_authorization80.register_verifier($1,$2)`, key.Version(), key.Verifier())
	return runner
}

func TestP7AuthorizationPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dsn := startDisposablePostgresAs(t, "zasp_e2e")
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	runner := migrateP7Authorization(t, ctx, conn)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.CSRFToken = strings.Repeat("x", 32)
	o, w, e, p := identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String()
	exec(`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Authorization','authorization.invalid')`, o)
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Authorization')`, o, w)
	exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,'Production','production')`, o, w, e)
	exec(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-auth80','member-auth80','security_admin',true)`, p, o)
	exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]',true)`, p, o, w, e)
	exec(`INSERT INTO zasp_product_sessions(token_digest,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,authenticated_at,expires_at) VALUES(digest('p7-current-session','sha256'),'session-authorization-current',$1,$2,$3,$4,'["view"]',repeat('x',32),clock_timestamp(),clock_timestamp()+interval '1 hour')`, p, o, w, e)
	exec(`INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind) VALUES($1,$2,$3,'pid_83000001-0000-4000-8000-000000000001','Current sensor','otlp')`, o, w, e)
	var catalogComplete bool
	if err = conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_authorization79.resources WHERE organization_id=$1 AND kind='sensor' AND id='pid_83000001-0000-4000-8000-000000000001') AND EXISTS(SELECT 1 FROM zasp_authorization79.resources WHERE organization_id=$1 AND kind='product_session' AND id=zasp_authorization80.object_id($1,$2,$3,'product_session','session-authorization-current'))`, o, w, e).Scan(&catalogComplete); err != nil || !catalogComplete {
		t.Fatalf("canonical61 typed source catalog incomplete: %v %v", catalogComplete, err)
	}
	config, _ := pgxpool.ParseConfig(dsn)
	config.ConnConfig.User = "auth80_outbox"
	config.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	projection, _ := authorization.NewPostgresProjectionRepository(pool)
	store, model := "01K00000000000000000000001", "01K00000000000000000000002"
	exec(`SELECT zasp_authorization79.configure($1,$2,$3)`, o, store, model)
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	api := connectRuntimeDataPlanePrincipal(t, ctx, dsn, "auth80_api")
	defer api.Close(context.Background())
	database, _ := NewPostgresJSONDatabase(&authorizationConnectionDriver{conn: api})
	resolver, _ := NewPostgresAuthorizationResolver(database)
	sensorID := "pid_83000001-0000-4000-8000-000000000001"
	authorizer := &OpenFGAAuthorizer{Reader: projection, Checker: authorizationDecisionFixture{allow: map[string]bool{sensorID: true}, model: model}, Resolver: resolver, StoreID: store, ModelID: model, AttestationKey: authorizationFixtureAttestor(t)}
	binding := CredentialBinding{Kind: CredentialBrowserSession, ID: "session-authorization-current", Digest: sha256.Sum256([]byte("p7-current-session"))}
	grant, err := authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "getSensor", PathParameters: map[string]string{"id": sensorID}})
	if err != nil {
		t.Fatal(err)
	}
	checkedCtx := context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	if _, err = database.QueryJSON(checkedCtx, `SELECT zasp_authorization80.sensor_detail($1,$2,$3,$4)`, o, w, e, sensorID); err != nil {
		t.Fatalf("current fence: %v", err)
	}
	exec(`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE session_id='session-authorization-current'`)
	if _, err = database.QueryJSON(checkedCtx, `SELECT zasp_authorization80.sensor_detail($1,$2,$3,$4)`, o, w, e, sensorID); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("revoked credential used stale allow: %v", err)
	}
	replay := runner.UpProductionAuthorizationEnforcement
	if os.Getenv("ZASP_P7_AUDIT_TEST") == "1" {
		replay = runner.UpProductionAuthorizationAuditProfile
	}
	if err = replay(ctx); err != nil {
		t.Fatalf("repeat installation: %v", err)
	}
	exec(`UPDATE zasp_product_sessions SET revoked_at=NULL WHERE session_id='session-authorization-current'`)
	ids := []string{"pid_81000001-0000-4000-8000-000000000001", "pid_81000002-0000-4000-8000-000000000002", "pid_81000003-0000-4000-8000-000000000003"}
	for _, id := range ids {
		exec(`INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status) VALUES($1,$2,$3,$4,'posture','Authorized collection','high','open')`, o, w, e, id)
		exec(`INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,$4,1,'pid_82000001-0000-4000-8000-000000000001')`, o, w, e, id)
	}
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	authorizer.Checker = authorizationDecisionFixture{allow: map[string]bool{ids[1]: true, ids[2]: true}, model: model}
	grant, err = authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "listFindings"})
	if err != nil {
		t.Fatal(err)
	}
	checkedCtx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	repository := &PostgresRepository{database: database, currentAuthorization: true}
	page, err := repository.ListRiskFindingPage(checkedCtx, identity.Scope, "", 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != ids[1] || page.NextID != ids[1] {
		t.Fatalf("denied first candidate affected authorized page: %+v %v", page, err)
	}
	page, err = repository.ListRiskFindingPage(checkedCtx, identity.Scope, page.NextID, 1)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != ids[2] || page.NextID != "" {
		t.Fatalf("authorized continuation: %+v %v", page, err)
	}
	// The native policy key is never passed to FGA or aliased to an environment.
	policyIDs := []string{"policy-auth80-a", "policy-auth80-b", "policy-auth80-c"}
	policyGrants := map[string]bool{}
	for index, policyID := range policyIDs {
		exec(`INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'policy',$4,jsonb_build_object('id',$4::text))`, o, w, e, policyID)
		var canonical string
		if err = conn.QueryRow(ctx, `SELECT zasp_authorization80.object_id($1,$2,$3,'policy',$4)`, o, w, e, policyID).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		if index > 0 {
			policyGrants[canonical] = true
		}
	}
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	authorizer.Checker = authorizationDecisionFixture{allow: policyGrants, model: model}
	grant, err = authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "listPolicies"})
	if err != nil || len(grant.Allowed) != 2 || grant.Allowed[0].SourceID != policyIDs[1] {
		t.Fatalf("native policy mapping: %+v %v", grant.Allowed, err)
	}
	checkedCtx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	policyPage, err := repository.ListWorkflowPage(checkedCtx, identity.Scope, "policy", "", 1)
	var visiblePolicy struct {
		ID string `json:"id"`
	}
	if err != nil || len(policyPage.Items) != 1 || json.Unmarshal(policyPage.Items[0], &visiblePolicy) != nil || visiblePolicy.ID != policyIDs[1] || policyPage.NextID != policyIDs[1] {
		t.Fatalf("policy pre-pagination restriction: %+v %v", policyPage, err)
	}
	// Compliance selects allowed source parents before count, lookahead and
	// metadata assembly. Old identity permissions contain no compliance allow.
	authorizer.Checker = authorizationDecisionFixture{allow: map[string]bool{ids[1]: true, ids[2]: true}, model: model}
	grant, err = authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "listComplianceEvidence"})
	if err != nil {
		t.Fatal(err)
	}
	checkedCtx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	if err = database.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	if _, err = database.QueryJSON(ctx, `SELECT '{"unfenced":true}'::jsonb`); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("enforced database allowed missing proof: %v", err)
	}
	compliance, err := NewComplianceRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := compliance.ListEvidence(checkedCtx, identity, binding.Digest[:], ComplianceListOptions{Limit: 1})
	if err != nil || len(evidence.Items) != 1 || evidence.Items[0].ID != ids[1] || len(evidence.NextCursor) == 0 {
		t.Fatalf("parent-filtered compliance first page: %+v %v", evidence, err)
	}
	grant, err = authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "getComplianceEvidence", PathParameters: map[string]string{"sourceKind": "finding", "id": ids[1]}})
	if err != nil {
		t.Fatal(err)
	}
	checkedCtx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	item, err := compliance.GetEvidence(checkedCtx, identity, binding.Digest[:], ComplianceTarget{SourceKind: "finding", SourceID: ids[1]})
	if err != nil || item.ID != ids[1] {
		t.Fatalf("parent-filtered compliance detail: %+v %v", item, err)
	}
	exerciseP7FoundationReadContracts(t, ctx, conn, api, database, authorizer, identity, binding, projection, ids, policyIDs)
	// Authentication evidence cannot survive a changed browser CSRF binding,
	// even when membership, FGA tuples and the product version are unchanged.
	exec(`UPDATE zasp_product_sessions SET csrf_token=repeat('y',32) WHERE session_id=$1`, binding.ID)
	if _, err = compliance.GetEvidence(checkedCtx, identity, binding.Digest[:], ComplianceTarget{SourceKind: "finding", SourceID: ids[1]}); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("stale browser CSRF binding used: %v", err)
	}
	exec(`UPDATE zasp_product_sessions SET csrf_token=repeat('x',32) WHERE session_id=$1`, binding.ID)
	// A product version changes without a permission change. The commit fence
	// still rejects the old decision before a second statement can affect data.
	grant, err = authorizer.Authorize(ctx, identity, binding, RoutedOperation{OperationID: "updateFinding", PathParameters: map[string]string{"id": ids[1]}})
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE zasp_risk_findings SET version=version+1 WHERE id=$1`, ids[1])
	checkedCtx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	if _, err = database.QueryJSON(checkedCtx, `WITH changed AS(UPDATE zasp_risk_findings SET title='must not commit' WHERE id=$1 RETURNING id) SELECT to_jsonb(changed) FROM changed`, ids[1]); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("unknown mutation statement admitted: %v", err)
	}
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := api.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, fenceErr := tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof))
	_ = tx.Rollback(ctx)
	var pgerr *pgconn.PgError
	if !errors.As(fenceErr, &pgerr) || pgerr.Code != "40001" {
		t.Fatalf("native stale version fence: %v", fenceErr)
	}
	var title string
	if err = conn.QueryRow(ctx, `SELECT title FROM zasp_risk_findings WHERE id=$1`, ids[1]).Scan(&title); err != nil || title != "Authorized collection" {
		t.Fatalf("stale effect committed: %s %v", title, err)
	}
	otherWorkspace := "pid_87000001-0000-4000-8000-000000000001"
	otherEnvironments := []string{"pid_87000002-0000-4000-8000-000000000001", "pid_87000002-0000-4000-8000-000000000002", "pid_87000002-0000-4000-8000-000000000003"}
	exec(`INSERT INTO zasp_workspaces(organization_id,id,name) VALUES($1,$2,'Other workspace')`, o, otherWorkspace)
	for _, id := range otherEnvironments {
		exec(`INSERT INTO zasp_environments(organization_id,workspace_id,id,name,environment_class) VALUES($1,$2,$3,$3,'production')`, o, otherWorkspace, id)
		exec(`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($1,$2,$3,$4,'Other environment','["view"]')`, p, o, otherWorkspace, id)
	}
	if _, err = authorization.Reconcile(ctx, projection, &authorizationTestWriter{}, o, store, model); err != nil {
		t.Fatal(err)
	}
	authorizer.Checker = authorizationDecisionFixture{allow: map[string]bool{otherEnvironments[1]: true, otherEnvironments[2]: true}, model: model}
	hierarchyCtx := context.WithValue(ctx, authorizationQueryContextKey{}, url.Values{"workspace_id": {otherWorkspace}})
	grant, err = authorizer.Authorize(hierarchyCtx, identity, binding, RoutedOperation{OperationID: "listEnvironments"})
	if err != nil || len(grant.Allowed) != 2 {
		t.Fatalf("actual foreign-workspace environment resolution: allowed=%d error=%v", len(grant.Allowed), err)
	}
	checkedCtx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
	body, err := repository.ReadAdministration(checkedCtx, identity, "listEnvironments", map[string]string{"workspace_id": otherWorkspace, "limit": "1"})
	var environmentPage struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err != nil || json.Unmarshal(body, &environmentPage) != nil || len(environmentPage.Items) != 2 || environmentPage.Items[0].ID != otherEnvironments[1] || environmentPage.Items[1].ID != otherEnvironments[2] {
		t.Fatalf("hierarchy predicate after pagination: %s %v", body, err)
	}
}

type authorizationConnectionDriver struct{ conn *pgx.Conn }

func (d *authorizationConnectionDriver) QueryRow(ctx context.Context, q string, args ...any) PostgresRow {
	return d.conn.QueryRow(ctx, q, args...)
}
func (d *authorizationConnectionDriver) Exec(ctx context.Context, q string, args ...any) error {
	_, err := d.conn.Exec(ctx, q, args...)
	return err
}
func (d *authorizationConnectionDriver) Begin(ctx context.Context) (pgx.Tx, error) {
	return d.conn.Begin(ctx)
}
func (d *authorizationConnectionDriver) Close() error { return nil }
