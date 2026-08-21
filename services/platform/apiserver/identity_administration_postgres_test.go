package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func TestProductionIdentityAdministrationPostgresInstallsExactTenantAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	if err := runner.UpProductionRuntimeDataPlane(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeGatewayReconciliation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionRuntimeIngestReconciliation(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runner.UpProductionSecurityAgentExecution(ctx); err != nil {
		t.Fatal(err)
	}

	metadata := migrations.ProductionIdentityAdministration()
	if err := runner.UpProductionIdentityAdministration(ctx); err != nil {
		t.Fatalf("v19 up: %v", err)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_administration_readiness($1,$2)`, metadata.Checksum(), migrations.ProductionIdentityAdministrationSemanticFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("v19 readiness=%t err=%v", ready, err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil || repository == nil {
		t.Fatalf("v19 repository err=%v", err)
	}
	if repository.schema != IdentityAdministrationSchemaVersion {
		t.Fatalf("v19 repository schema=%q", repository.schema)
	}
	identity := fixtureRequestIdentity(t)
	organization, principal := identity.Scope.OrganizationID().String(), identity.PrincipalID.String()
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-tenant-a','member-test-local','security_admin',true)`, principal, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view"]'::jsonb,true)`, principal, organization, identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()); err != nil {
		t.Fatal(err)
	}
	intent := json.RawMessage(`{"display_name":"Corporate SAML","identity_provider":"okta","protocol":"saml"}`)
	intentDigest := make([]byte, 32)
	leaseToken := make([]byte, 32)
	mutationID := "pid_79000001-0000-4000-8000-000000000001"
	auditID := "pid_79000002-0000-4000-8000-000000000002"
	correlationID := "pid_79000003-0000-4000-8000-000000000003"
	receiptID := "pid_79000004-0000-4000-8000-000000000004"
	idempotency := "identity-sso-create-0001"
	var reserved []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'createSSOConnection',$3,$4,$5,$6::jsonb,$7,$8,$9,$10,60)`, organization, principal, idempotency, mutationID, intentDigest, intent, auditID, correlationID, receiptID, leaseToken).Scan(&reserved); err != nil || !json.Valid(reserved) {
		t.Fatalf("reserve=%s err=%v", reserved, err)
	}
	if !jsonContainsString(reserved, "provider_organization_reference", "organization-tenant-a") {
		t.Fatalf("reserve tenant binding=%s", reserved)
	}
	foreignLeaseToken := make([]byte, 32)
	foreignLeaseToken[0] = 1
	var rejected []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'createSSOConnection',$3,'pid_79000009-0000-4000-8000-000000000009',$4,$5::jsonb,'pid_79000006-0000-4000-8000-000000000006','pid_79000007-0000-4000-8000-000000000007','pid_79000008-0000-4000-8000-000000000008',$6,60)`, organization, principal, idempotency, intentDigest, intent, foreignLeaseToken).Scan(&rejected); err == nil {
		t.Fatalf("live mutation lease was stolen: %s", rejected)
	}
	var providerOrganization *string
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_provider_organization($1,$2)`, organization, principal).Scan(&providerOrganization); err != nil || providerOrganization == nil || *providerOrganization != "organization-tenant-a" {
		t.Fatalf("provider organization=%v err=%v", providerOrganization, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_provider_organization($1,'pid_79999999-0000-4000-8000-000000000099')`, organization).Scan(&providerOrganization); err != nil || providerOrganization != nil {
		t.Fatalf("foreign provider organization=%v err=%v", providerOrganization, err)
	}
	connectionValue := json.RawMessage(`{"reference":"saml-connection-tenant-a","kind":"sso","protocol":"saml","status":"pending","display_name":"Corporate SAML","identity_provider":"okta","base_url":null}`)
	var completed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_complete_mutation($1,$2,'createSSOConnection',$3,$4,$5,$6::jsonb,NULL,NULL,NULL,NULL,NULL)`, organization, principal, idempotency, mutationID, leaseToken, connectionValue).Scan(&completed); err != nil || !json.Valid(completed) || !jsonContainsString(completed, "mutation_id", mutationID) {
		t.Fatalf("complete=%s err=%v", completed, err)
	}
	var replayed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'createSSOConnection',$3,'pid_79000009-0000-4000-8000-000000000009',$4,$5::jsonb,'pid_79000006-0000-4000-8000-000000000006','pid_79000007-0000-4000-8000-000000000007','pid_79000008-0000-4000-8000-000000000008',$6,60)`, organization, principal, idempotency, intentDigest, intent, leaseToken).Scan(&replayed); err != nil || !json.Valid(replayed) || !jsonContainsBoolean(replayed, "replayed", true) || !jsonContainsString(replayed, "mutation_id", mutationID) {
		t.Fatalf("replay=%s err=%v", replayed, err)
	}
	var page, foreignPage []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_connection_page($1,$2,'sso',NULL,50)`, organization, principal).Scan(&page); err != nil || !json.Valid(page) || !jsonContainsString(page, "reference", "saml-connection-tenant-a") {
		t.Fatalf("page=%s err=%v", page, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_connection_page('pid_79999999-0000-4000-8000-000000000099',$1,'sso',NULL,50)`, principal).Scan(&foreignPage); err == nil {
		t.Fatalf("foreign tenant page succeeded: %s", foreignPage)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_connection_page($1,'pid_79999999-0000-4000-8000-000000000099','sso',NULL,50)`, organization).Scan(&foreignPage); err == nil {
		t.Fatalf("unauthorized principal page succeeded: %s", foreignPage)
	}

	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'createSSOConnection','identity-sso-create-hostile','pid_79000010-0000-4000-8000-000000000010',$3,$4::jsonb,'pid_79000011-0000-4000-8000-000000000011','pid_79000012-0000-4000-8000-000000000012','pid_79000013-0000-4000-8000-000000000013',$5,60)`, organization, principal, intentDigest, json.RawMessage(`{"display_name":"Corporate SAML","identity_provider":"okta","protocol":"saml","foreign":true}`), leaseToken).Scan(&rejected); err == nil {
		t.Fatalf("unknown intent field accepted: %s", rejected)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'createSSOConnection','identity-sso-create-mismatch','pid_79000014-0000-4000-8000-000000000014',$3,$4::jsonb,'pid_79000015-0000-4000-8000-000000000015','pid_79000016-0000-4000-8000-000000000016','pid_79000017-0000-4000-8000-000000000017',$5,60)`, organization, principal, intentDigest, intent, leaseToken).Scan(&rejected); err != nil {
		t.Fatalf("reserve mismatch probe: %v", err)
	}
	mismatchedConnection := json.RawMessage(`{"reference":"saml-connection-hostile","kind":"sso","protocol":"saml","status":"pending","display_name":"Corporate SAML","identity_provider":"google-workspace","base_url":null}`)
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_complete_mutation($1,$2,'createSSOConnection','identity-sso-create-mismatch','pid_79000014-0000-4000-8000-000000000014',$3,$4::jsonb,NULL,NULL,NULL,NULL,NULL)`, organization, principal, leaseToken, mismatchedConnection).Scan(&rejected); err == nil {
		t.Fatalf("mismatched provider result accepted: %s", rejected)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_connection_page($1,$2,'sso',NULL,50)`, organization, principal).Scan(&foreignPage); err != nil || jsonContainsString(foreignPage, "reference", "saml-connection-hostile") {
		t.Fatalf("foreign page=%s err=%v", foreignPage, err)
	}

	deleteIntent := json.RawMessage(`{"reference":"saml-connection-tenant-a"}`)
	deleteDigest := make([]byte, 32)
	deleteDigest[0] = 2
	deleteMutationID := "pid_79000020-0000-4000-8000-000000000020"
	deleteIdempotency := "identity-sso-delete-0001"
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'deleteSSOConnection',$3,$4,$5,$6::jsonb,'pid_79000021-0000-4000-8000-000000000021','pid_79000022-0000-4000-8000-000000000022','pid_79000023-0000-4000-8000-000000000023',$7,60)`, organization, principal, deleteIdempotency, deleteMutationID, deleteDigest, deleteIntent, leaseToken).Scan(&reserved); err != nil {
		t.Fatalf("reserve delete: %v", err)
	}
	deleteResult := json.RawMessage(`{"reference":"saml-connection-tenant-a","kind":"sso","deleted":true}`)
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_complete_mutation($1,$2,'deleteSSOConnection',$3,$4,$5,$6::jsonb,NULL,NULL,NULL,NULL,NULL)`, organization, principal, deleteIdempotency, deleteMutationID, foreignLeaseToken, deleteResult).Scan(&rejected); err == nil {
		t.Fatalf("wrong lease completed delete: %s", rejected)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_complete_mutation($1,$2,'deleteSSOConnection',$3,$4,$5,$6::jsonb,NULL,NULL,NULL,NULL,NULL)`, organization, principal, deleteIdempotency, deleteMutationID, leaseToken, deleteResult).Scan(&completed); err != nil || !jsonContainsBoolean(completed, "replayed", false) || !jsonContainsNestedBoolean(completed, "body", "deleted", true) {
		t.Fatalf("complete delete tombstone=%s err=%v", completed, err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_connection_page($1,$2,'sso',NULL,50)`, organization, principal).Scan(&page); err != nil || jsonContainsString(page, "reference", "saml-connection-tenant-a") {
		t.Fatalf("deleted connection remained visible: %s err=%v", page, err)
	}
}

func TestProductionIdentityAdministrationPostgresPreservesPATWorkflowAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, migration := range []struct {
		name string
		up   func(context.Context) error
	}{
		{"runtime data plane", runner.UpProductionRuntimeDataPlane},
		{"runtime gateway reconciliation", runner.UpProductionRuntimeGatewayReconciliation},
		{"runtime ingest reconciliation", runner.UpProductionRuntimeIngestReconciliation},
		{"security agent execution", runner.UpProductionSecurityAgentExecution},
		{"identity administration", runner.UpProductionIdentityAdministration},
	} {
		if err := migration.up(ctx); err != nil {
			t.Fatalf("%s: %v", migration.name, err)
		}
	}
	for _, migration := range []struct {
		name string
		down func(context.Context) error
	}{
		{"identity administration", runner.DownProductionIdentityAdministration},
		{"security agent execution", runner.DownProductionSecurityAgentExecution},
		{"runtime ingest reconciliation", runner.DownProductionRuntimeIngestReconciliation},
	} {
		if err := migration.down(ctx); err != nil {
			t.Fatalf("%s rollback: %v", migration.name, err)
		}
	}
	for _, migration := range []struct {
		name string
		up   func(context.Context) error
	}{
		{"runtime ingest reconciliation", runner.UpProductionRuntimeIngestReconciliation},
		{"security agent execution", runner.UpProductionSecurityAgentExecution},
		{"identity administration", runner.UpProductionIdentityAdministration},
	} {
		if err := migration.up(ctx); err != nil {
			t.Fatalf("%s reapply: %v", migration.name, err)
		}
	}
	identity := fixtureRequestIdentity(t)
	organization := identity.Scope.OrganizationID().String()
	principal := identity.PrincipalID.String()
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-pat-e2e','member-pat-e2e','security_admin',true)`, principal, organization); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions,is_default) VALUES($1,$2,$3,$4,'Production','["view","manage_workflows"]'::jsonb,true)`,
		`INSERT INTO zasp_product_api_tokens(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES(digest('identity-v19-pat-workflow-token','sha256'),$1,$2,$3,$4,'["view","manage_workflows"]'::jsonb,transaction_timestamp()+interval '1 hour')`,
	} {
		if _, err := connection.Exec(ctx, statement, principal, organization, identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()); err != nil {
			t.Fatal(err)
		}
	}
	findingID := "pid_79000072-0000-4000-8000-000000000072"
	seedConnectorRiskFinding(t, ctx, connection, identity, findingID)
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatalf("v19 API repository: %v", err)
	}
	authenticated, err := repository.Authenticate(ctx, Credential{Kind: CredentialBearerToken, Value: "identity-v19-pat-workflow-token"})
	if err != nil {
		t.Fatalf("v19 PAT authenticate: %v", err)
	}
	policy := json.RawMessage(`{"id":"policy-v19-pat-e2e","name":"V19 PAT compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"read"}],"action":"monitor","rollout":"draft","failure_mode":"open"}`)
	result, err := repository.MutateWorkflow(ctx, authenticated, WorkflowMutation{
		Action: "create", Kind: "policy", ID: "policy-v19-pat-e2e", Operation: "createPolicy", IdempotencyKey: "identity-v19-pat-workflow-0001",
		Intent: json.RawMessage(`{"body":` + string(policy) + `,"expected_version":0,"resource_id":""}`), Body: policy,
		AuditID: "pid_79000070-0000-4000-8000-000000000070", CorrelationID: "pid_79000071-0000-4000-8000-000000000071",
	})
	if err != nil || result.Version != 1 || result.Replayed {
		t.Fatalf("v19 PAT workflow mutation=%#v err=%v", result, err)
	}
	browserPolicy := json.RawMessage(`{"id":"policy-v19-browser-e2e","name":"V19 browser compatibility","scope":"environment","trigger":"tool","conditions":[{"field":"action","operator":"equals","value":"write"}],"action":"block","rollout":"draft","failure_mode":"closed"}`)
	browserResult, err := repository.MutateWorkflow(ctx, identity, WorkflowMutation{
		Action: "create", Kind: "policy", ID: "policy-v19-browser-e2e", Operation: "createPolicy", IdempotencyKey: "identity-v19-browser-workflow-0001",
		Intent: json.RawMessage(`{"body":` + string(browserPolicy) + `,"expected_version":0,"resource_id":""}`), Body: browserPolicy,
		AuditID: "pid_79000073-0000-4000-8000-000000000073", CorrelationID: "pid_79000074-0000-4000-8000-000000000074", ReceiptID: "pid_79000075-0000-4000-8000-000000000075",
	})
	if err != nil || browserResult.Version != 1 || browserResult.ReceiptID != "pid_79000075-0000-4000-8000-000000000075" || browserResult.Replayed {
		t.Fatalf("v19 browser workflow mutation=%#v err=%v", browserResult, err)
	}
	riskResult, err := repository.MutateRiskFinding(ctx, authenticated, RiskFindingMutation{
		Operation: "updateFinding", FindingID: findingID, IdempotencyKey: "identity-v19-pat-risk-0001", ExpectedVersion: 1, Status: "resolved",
		AuditID: "pid_79000076-0000-4000-8000-000000000076", CorrelationID: "pid_79000077-0000-4000-8000-000000000077",
	})
	if err != nil || riskResult.Version != 2 || riskResult.Body.Status != "resolved" || riskResult.Replayed {
		t.Fatalf("v19 PAT risk mutation=%#v err=%v", riskResult, err)
	}
}

func TestProductionIdentityAdministrationReconcilesVerifiedGroupsIntoTenantScopes(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	runner := migrateToTypedInventoryCutover(t, ctx, connection)
	for _, apply := range []func(context.Context) error{runner.UpProductionRuntimeDataPlane, runner.UpProductionRuntimeGatewayReconciliation, runner.UpProductionRuntimeIngestReconciliation, runner.UpProductionSecurityAgentExecution, runner.UpProductionIdentityAdministration} {
		if err := apply(ctx); err != nil {
			t.Fatal(err)
		}
	}
	identity := fixtureRequestIdentity(t)
	organization, principal := identity.Scope.OrganizationID().String(), identity.PrincipalID.String()
	workspace, environment := identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String()
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-groups-a','member-groups-a','read_only_viewer',true)`, principal, organization); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []struct {
		statement string
		arguments []any
	}{
		{`INSERT INTO zasp_organizations(id,name,domain) VALUES($1,'Groups tenant','groups.invalid')`, []any{organization}},
		{`INSERT INTO zasp_workspaces(id,organization_id,name) VALUES($2,$1,'Production')`, []any{organization, workspace}},
		{`INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES($3,$1,$2,'Production','production')`, []any{organization, workspace, environment}},
	} {
		if _, err := connection.Exec(ctx, seed.statement, seed.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($1,'scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c39','security_engineer','pid_79000057-0000-4000-8000-000000000057','pid_79000058-0000-4000-8000-000000000058')`, organization); err == nil {
		t.Fatal("group mapping accepted a nonexistent tenant scope")
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_group_mappings(organization_id,group_reference,role,workspace_id,environment_id) VALUES($1,'scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31','security_engineer',$2,$3)`, organization, workspace, environment); err != nil {
		t.Fatal(err)
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	driver := &callbackIdentityDriver{session: platformidentity.DriverSession{MemberReference: "member-groups-a", OrganizationReference: "organization-groups-a", SessionReference: "member-session-groups-a", GroupReferences: []string{"scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31"}, AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour), Active: true}}
	adapter, err := platformidentity.NewAdapter(driver, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	external, err := adapter.Authenticate(ctx, "header.payload.signature")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := repository.ResolveIdentity(ctx, external)
	if err != nil || grant.Scope != identity.Scope || !stringIn("manage_workflows", grant.Permissions...) {
		t.Fatalf("group grant=%#v err=%v", grant, err)
	}
	token, err := repository.CreateSession(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token})
	if err != nil || authenticated.Scope != identity.Scope || !stringIn("manage_workflows", authenticated.Permissions...) {
		t.Fatalf("group session=%#v err=%v", authenticated, err)
	}
	scopes, err := repository.ListScopes(ctx, authenticated)
	if err != nil || !jsonContainsString(scopes, "label", "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31") {
		t.Fatalf("group scope list=%s err=%v", scopes, err)
	}
	groupOnlyPrincipal := "pid_79000055-0000-4000-8000-000000000055"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($1,$2,'organization-groups-a','member-groups-only','read_only_viewer',true)`, groupOnlyPrincipal, organization); err != nil {
		t.Fatal(err)
	}
	groupOnlyDriver := &callbackIdentityDriver{session: platformidentity.DriverSession{MemberReference: "member-groups-only", OrganizationReference: "organization-groups-a", SessionReference: "member-session-groups-only", GroupReferences: []string{"scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31"}, AuthenticatedAt: now, ExpiresAt: now.Add(time.Hour), Active: true}}
	groupOnlyAdapter, err := platformidentity.NewAdapter(groupOnlyDriver, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	groupOnlyExternal, err := groupOnlyAdapter.Authenticate(ctx, "header.payload.signature")
	if err != nil {
		t.Fatal(err)
	}
	groupOnlyGrant, err := repository.ResolveIdentity(ctx, groupOnlyExternal)
	if err != nil || groupOnlyGrant.PrincipalID.String() != groupOnlyPrincipal || groupOnlyGrant.Scope != identity.Scope || !stringIn("manage_workflows", groupOnlyGrant.Permissions...) {
		t.Fatalf("group-only grant=%#v err=%v", groupOnlyGrant, err)
	}
	groupOnlyToken, err := repository.CreateSession(ctx, groupOnlyGrant)
	if err != nil {
		t.Fatal(err)
	}
	groupOnlyIdentity, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: groupOnlyToken})
	if err != nil || groupOnlyIdentity.PrincipalID.String() != groupOnlyPrincipal || groupOnlyIdentity.Scope != identity.Scope {
		t.Fatalf("group-only session=%#v err=%v", groupOnlyIdentity, err)
	}
	bootstrap, err := repository.Bootstrap(ctx, groupOnlyIdentity)
	if err != nil || !jsonContainsString(bootstrap, "id", groupOnlyPrincipal) {
		t.Fatalf("group-only bootstrap=%s err=%v", bootstrap, err)
	}
	groupOnlyWorkspaces, err := repository.ReadAdministration(ctx, groupOnlyIdentity, "listWorkspaces", map[string]string{"limit": "50"})
	if err != nil || !jsonContainsString(groupOnlyWorkspaces, "id", workspace) {
		t.Fatalf("group-only workspaces=%s schema=%s err=%v", groupOnlyWorkspaces, repository.schema, err)
	}
	groupOnlyEnvironments, err := repository.ReadAdministration(ctx, groupOnlyIdentity, "listEnvironments", map[string]string{"workspace_id": workspace, "limit": "50"})
	if err != nil || !jsonContainsString(groupOnlyEnvironments, "id", environment) {
		t.Fatalf("group-only environments=%s err=%v", groupOnlyEnvironments, err)
	}
	apiAuthority, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer apiAuthority.Rollback(context.Background())
	if _, err := apiAuthority.Exec(ctx, `SET LOCAL ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var authorityBootstrap, authorityWorkspaces []byte
	if err := apiAuthority.QueryRow(ctx, postgresBootstrapV19SQL, groupOnlyPrincipal, organization, workspace, environment, "pid_79000056-0000-4000-8000-000000000056").Scan(&authorityBootstrap); err != nil || !jsonContainsString(authorityBootstrap, "id", groupOnlyPrincipal) {
		t.Fatalf("API authority bootstrap=%s err=%v", authorityBootstrap, err)
	}
	if err := apiAuthority.QueryRow(ctx, postgresListWorkspacesV19SQL, organization, groupOnlyPrincipal, "", 51).Scan(&authorityWorkspaces); err != nil || !jsonContainsString(authorityWorkspaces, "id", workspace) {
		t.Fatalf("API authority workspaces=%s err=%v", authorityWorkspaces, err)
	}
	if err := apiAuthority.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var groupCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, organization, principal).Scan(&groupCount); err != nil || groupCount != 1 {
		t.Fatalf("member groups=%d err=%v", groupCount, err)
	}
	var resolved []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_resolve_session('organization-groups-a','member-groups-a','[]'::jsonb)`).Scan(&resolved); err != nil || len(resolved) != 0 {
		t.Fatalf("removed group scope=%s err=%v", resolved, err)
	}
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_identity_member_groups WHERE organization_id=$1 AND principal_id=$2`, organization, principal).Scan(&groupCount); err != nil || groupCount != 0 {
		t.Fatalf("removed member groups=%d err=%v", groupCount, err)
	}
	if _, err := repository.Authenticate(ctx, Credential{Kind: CredentialBrowserSession, Value: token}); err == nil {
		t.Fatal("session survived verified group removal")
	}
	for _, hostile := range []string{`["scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31","scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31"]`, `["idp-group-platform"]`, `{"scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31":true}`} {
		if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_resolve_session('organization-groups-a','member-groups-a',$1::jsonb)`, hostile).Scan(&resolved); err == nil {
			t.Fatalf("hostile group claims accepted: %s", hostile)
		}
	}
	foreign := platformidentity.WebhookEvent{ProjectID: "project-live-platform", EventID: "webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c41", Action: "DELETE", ObjectType: "member", Source: "SCIM", ObjectID: "member-groups-a", Timestamp: now.Format(time.RFC3339Nano), Vertical: "B2B", WorkspaceID: "workspace-live-platform", Details: platformidentity.WebhookDetails{OrganizationReference: "organization-foreign"}}
	if processed, err := repository.ReconcileStytchWebhook(ctx, foreign, make([]byte, 32), "pid_79000054-0000-4000-8000-000000000054"); err == nil || processed {
		t.Fatalf("foreign tenant deprovision=%t err=%v", processed, err)
	}
	webhook := platformidentity.WebhookEvent{ProjectID: "project-live-platform", EventID: "webhook-event-live-018f85a0-2c17-7ba3-91d1-7f0382dd7c40", Action: "DELETE", ObjectType: "member", Source: "SCIM", ObjectID: "member-groups-a", Timestamp: now.Format(time.RFC3339Nano), Vertical: "B2B", WorkspaceID: "workspace-live-platform", Details: platformidentity.WebhookDetails{OrganizationReference: "organization-groups-a"}}
	processed, err := repository.ReconcileStytchWebhook(ctx, webhook, make([]byte, 32), "pid_79000040-0000-4000-8000-000000000040")
	if err != nil || !processed {
		t.Fatalf("deprovision=%t err=%v", processed, err)
	}
	processed, err = repository.ReconcileStytchWebhook(ctx, webhook, make([]byte, 32), "pid_79000041-0000-4000-8000-000000000041")
	if err != nil || processed {
		t.Fatalf("deprovision replay=%t err=%v", processed, err)
	}
	var active bool
	if err := connection.QueryRow(ctx, `SELECT active FROM zasp_identity_memberships WHERE organization_id=$1 AND principal_id=$2`, organization, principal).Scan(&active); err != nil || active {
		t.Fatalf("deprovisioned member active=%t err=%v", active, err)
	}
}

func jsonContainsBoolean(payload []byte, key string, value bool) bool {
	var decoded map[string]any
	return json.Unmarshal(payload, &decoded) == nil && decoded[key] == value
}

func jsonContainsNestedBoolean(payload []byte, objectKey, key string, value bool) bool {
	var decoded map[string]json.RawMessage
	if json.Unmarshal(payload, &decoded) != nil {
		return false
	}
	var nested map[string]any
	return json.Unmarshal(decoded[objectKey], &nested) == nil && nested[key] == value
}

func jsonContainsString(payload []byte, key, value string) bool {
	return string(payload) != "" && json.Valid(payload) && string(payload) != "null" &&
		strings.Contains(string(payload), `"`+key+`"`) && strings.Contains(string(payload), `"`+value+`"`)
}
