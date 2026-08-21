package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_complete_mutation($1,$2,'createSSOConnection',$3,$4,$5,$6::jsonb,NULL,NULL,NULL,NULL,NULL)`, organization, principal, idempotency, mutationID, leaseToken, connectionValue).Scan(&completed); err != nil || !json.Valid(completed) {
		t.Fatalf("complete=%s err=%v", completed, err)
	}
	var replayed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_identity_admin_reserve_mutation($1,$2,'createSSOConnection',$3,'pid_79000009-0000-4000-8000-000000000009',$4,$5::jsonb,'pid_79000006-0000-4000-8000-000000000006','pid_79000007-0000-4000-8000-000000000007','pid_79000008-0000-4000-8000-000000000008',$6,60)`, organization, principal, idempotency, intentDigest, intent, leaseToken).Scan(&replayed); err != nil || !json.Valid(replayed) || !jsonContainsBoolean(replayed, "replayed", true) {
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
