package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func migrateToConnectorAuthorization(t *testing.T, ctx context.Context, connection *pgx.Conn) *migrations.Runner {
	t.Helper()
	runner := migrateToProductionDiscovery(t, ctx, connection)
	if err := runner.UpConnectorAuthorization(ctx); err != nil {
		t.Fatalf("connector authorization migration: %v", err)
	}
	return runner
}

func TestConnectorAuthorizationPostgresOneTimeOAuthUnknownEffectAndReferenceOnlyCredential(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	runner := migrateToConnectorAuthorization(t, ctx, connection)
	if version, versionErr := runner.Version(ctx); versionErr != nil || version != 11 {
		t.Fatalf("connector schema version = %d, %v", version, versionErr)
	}
	fingerprintQuery := postgresSchemaVersionSQL[:strings.Index(postgresSchemaVersionSQL, "SELECT metadata.value")] + "SELECT value FROM semantic_fingerprint"
	var fingerprint string
	if err := connection.QueryRow(ctx, fingerprintQuery).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	if fingerprint != migrations.ConnectorAuthorizationSemanticFingerprint() {
		t.Fatalf("connector semantic fingerprint = %q, marker %q", fingerprint, migrations.ConnectorAuthorizationSemanticFingerprint())
	}
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newDiscoveryRepositoryUnchecked(database); err != nil {
		t.Fatalf("v10 discovery repository on v11 connector schema: %v", err)
	}

	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	if _, err := connection.Exec(ctx, `SELECT zasp_discovery_create_integration($1,$2,$3,$4,'github','1.0.0','GitHub','{}'::jsonb,NULL)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body) VALUES($1,$2,$3,'integration',$4::text,jsonb_build_object('id',$4::text,'connector_key','github','configuration','{}'::jsonb,'status','pending_authorization'))`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	principalID := identity.PrincipalID.String()
	sessionDigest := sha256.Sum256([]byte("session"))
	stateDigest := sha256.Sum256([]byte("state"))
	requestDigest := sha256.Sum256([]byte("request"))
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), attemptID, integrationID, "github", principalID, sessionDigest[:], stateDigest[:], "ref:oauth/pkce/attempt-0001", requestDigest[:], json.RawMessage(`["read:org"]`), time.Now().UTC().Add(10 * time.Minute), int64(1), json.RawMessage(`{}`), connectorDeterministicID(scope, attemptID, "pkce-cleanup"), connectorDeterministicID(scope, attemptID, "oauth-effect")}
	var started, replayed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17)`, args...).Scan(&started); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17)`, args...).Scan(&replayed); err != nil || string(replayed) != string(started) {
		t.Fatalf("exact start replay = %s, %v; first=%s", replayed, err, started)
	}
	conflictArgs := append([]any(nil), args...)
	conflicting := sha256.Sum256([]byte("conflict"))
	conflictArgs[10] = conflicting[:]
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17)`, conflictArgs...).Scan(&replayed); err == nil {
		t.Fatal("same OAuth attempt with changed digest succeeded")
	}
	secondAttemptArgs := append([]any(nil), args...)
	secondAttemptArgs[3] = "pid_70000007-0000-4000-8000-000000000007"
	secondState := sha256.Sum256([]byte("second-state"))
	secondAttemptArgs[8] = secondState[:]
	secondAttemptArgs[9] = "ref:oauth/pkce/attempt-0002"
	secondAttemptArgs[15] = connectorDeterministicID(scope, secondAttemptArgs[3].(string), "pkce-cleanup")
	secondAttemptArgs[16] = connectorDeterministicID(scope, secondAttemptArgs[3].(string), "oauth-effect")
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14,$15::jsonb,$16,$17)`, secondAttemptArgs...).Scan(&replayed); err == nil {
		t.Fatal("second active OAuth attempt succeeded")
	}
	connectorRepository := &ConnectorRepository{database: database}
	foreignIdentity := identity
	foreignIdentity.Scope = alternateScope(t, scope.OrganizationID())
	if _, err := connectorRepository.ConsumeOAuth(ctx, foreignIdentity, stateDigest[:], sessionDigest[:]); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("cross-scope callback consume = %v, want not found", err)
	}
	var pendingStatus string
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), attemptID).Scan(&pendingStatus); err != nil || pendingStatus != "pending" {
		t.Fatalf("cross-scope callback residue status = %q, %v", pendingStatus, err)
	}

	var consumed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_consume_oauth($1,$2,$3,$4,$5,$6)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), stateDigest[:], principalID, sessionDigest[:]).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_consume_oauth($1,$2,$3,$4,$5,$6)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), stateDigest[:], principalID, sessionDigest[:]).Scan(&consumed); err == nil {
		t.Fatal("OAuth state replay succeeded")
	}

	effectID := args[16].(string)
	var effect []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_begin_effect($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), effectID, integrationID, attemptID, "github", "authorize", "oauth-authorize:"+attemptID, requestDigest[:]).Scan(&effect); err != nil {
		t.Fatal(err)
	}
	var claimed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_claim_reconciliation($1,$2,$3)`, "reconciler-a", 30, 10).Scan(&claimed); err != nil || !json.Valid(claimed) {
		t.Fatalf("claim unknown effects = %s, %v", claimed, err)
	}

	credentialID := "pid_70000004-0000-4000-8000-000000000004"
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_put_credential($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), credentialID, integrationID, "github", "github_installation_reference", "ref:github/install/123456", 1, json.RawMessage(`{"installation_id":"123456"}`)).Scan(&effect); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES($1,$2,$3,$4,$5,'github','installation_reference','plaintext-token',2,'{}')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "pid_70000005-0000-4000-8000-000000000005", integrationID); err == nil {
		t.Fatal("plaintext credential residue accepted")
	}

	other := alternateScope(t, scope.OrganizationID())
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_consume_oauth($1,$2,$3,$4,$5,$6)`, other.OrganizationID().String(), other.WorkspaceID().String(), other.EnvironmentID().String(), stateDigest[:], principalID, sessionDigest[:]).Scan(&consumed); err == nil {
		t.Fatal("cross-scope OAuth state disclosed")
	}
	if err := runner.DownConnectorAuthorization(ctx); err == nil {
		t.Fatal("connector data did not block guarded down")
	}
}

func TestConnectorAuthorizationPostgresPublicIntegrationMutationCreatesTypedOAuthParent(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToReferenceAuthorization(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_71000001-0000-4000-8000-000000000001"
	body := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)
	mutation := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-public-connector-0001", ExpectedVersion: 0, Intent: json.RawMessage(`{"body":{"connector_key":"github","configuration":{"authorization_mode":"github_app"},"name":"GitHub"},"expected_version":0,"resource_id":""}`), Body: body, AuditID: "pid_71000002-0000-4000-8000-000000000002", CorrelationID: "pid_71000003-0000-4000-8000-000000000003", ReceiptID: "pid_71000004-0000-4000-8000-000000000004"}
	if _, err := repository.MutateWorkflow(ctx, identity, mutation); err != nil {
		t.Fatalf("public integration mutation: %v", err)
	}
	if replay, err := repository.MutateWorkflow(ctx, identity, mutation); err != nil || !replay.Replayed {
		t.Fatalf("public integration exact replay = %#v, %v", replay, err)
	}
	conflict := mutation
	conflict.Body = json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Changed","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)
	conflict.Intent = json.RawMessage(`{"body":{"connector_key":"github","name":"Changed"},"expected_version":0,"resource_id":""}`)
	if _, err := repository.MutateWorkflow(ctx, identity, conflict); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("changed public integration replay = %v, want conflict", err)
	}
	var typedKind, typedName string
	if err := connection.QueryRow(ctx, `SELECT kind,display_name FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&typedKind, &typedName); err != nil {
		t.Fatalf("typed integration parent: %v", err)
	}
	if typedKind != "github" || typedName != "GitHub" {
		t.Fatalf("typed integration = %q/%q", typedKind, typedName)
	}
	updatedBody := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub Org","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z"}`)
	update := WorkflowMutation{Action: "update", Kind: "integration", ID: integrationID, Operation: "updateIntegration", IdempotencyKey: "idem-public-connector-update-0001", ExpectedVersion: 1, Intent: json.RawMessage(`{"body":{"configuration":{"authorization_mode":"github_app"},"name":"GitHub Org"},"expected_version":1,"resource_id":"` + integrationID + `"}`), Body: updatedBody, AuditID: "pid_71000012-0000-4000-8000-000000000012", CorrelationID: "pid_71000013-0000-4000-8000-000000000013", ReceiptID: "pid_71000014-0000-4000-8000-000000000014"}
	if result, err := repository.MutateWorkflow(ctx, identity, update); err != nil || result.Version != 2 {
		t.Fatalf("public integration update = %#v, %v", result, err)
	}
	var typedVersion int64
	if err := connection.QueryRow(ctx, `SELECT display_name,version FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&typedName, &typedVersion); err != nil || typedName != "GitHub Org" || typedVersion != 2 {
		t.Fatalf("typed integration update = %q/v%d, %v", typedName, typedVersion, err)
	}
	connectorRepository := &ConnectorRepository{database: database}
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte("public bridge"))
	attemptID := "pid_71000005-0000-4000-8000-000000000005"
	_, err = connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: attemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/public-bridge", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: now.Add(5 * time.Minute), IntegrationVersion: 2, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)})
	if err != nil {
		t.Fatalf("start OAuth after public mutation: %v", err)
	}
	consumption, err := connectorRepository.ConsumeOAuth(ctx, identity, digest[:], digest[:])
	if err != nil {
		t.Fatalf("consume public OAuth: %v", err)
	}
	effectID := consumption.EffectID
	if _, err := connectorRepository.ResolveConnectorEffect(ctx, identity.Scope, ConnectorEffectResolution{ID: effectID, Status: "failed", ErrorCode: "provider_access_denied", Metadata: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("resolve denial effect: %v", err)
	}
	var attemptStatus string
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), attemptID).Scan(&attemptStatus); err != nil {
		t.Fatal(err)
	}
	if attemptStatus != "rejected" {
		t.Fatalf("provider denial attempt status = %q, want rejected", attemptStatus)
	}
	successDigest := sha256.Sum256([]byte("public bridge success"))
	successAttemptID := "pid_71000007-0000-4000-8000-000000000007"
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: successAttemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/public-success", SessionDigest: successDigest[:], StateDigest: successDigest[:], RequestDigest: successDigest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: now.Add(5 * time.Minute), IntegrationVersion: 2, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}); err != nil {
		t.Fatalf("start success OAuth: %v", err)
	}
	blockedDeletion := WorkflowMutation{Action: "delete", Kind: "integration", ID: integrationID, Operation: "deleteIntegration", IdempotencyKey: "idem-delete-with-pending-oauth", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{},"expected_version":2,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_71000032-0000-4000-8000-000000000032", CorrelationID: "pid_71000033-0000-4000-8000-000000000033", ReceiptID: "pid_71000034-0000-4000-8000-000000000034"}
	if _, err := repository.MutateWorkflow(ctx, identity, blockedDeletion); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("delete with unresolved authorization = %v, want conflict", err)
	}
	stillPending, err := repository.GetWorkflow(ctx, identity.Scope, "integration", integrationID)
	if err != nil || stillPending.Version != 2 {
		t.Fatalf("delete with unresolved authorization left residue = %#v, %v", stillPending, err)
	}
	successConsumption, err := connectorRepository.ConsumeOAuth(ctx, identity, successDigest[:], successDigest[:])
	if err != nil {
		t.Fatalf("consume success OAuth: %v", err)
	}
	successEffectID := successConsumption.EffectID
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), successEffectID); err != nil {
		t.Fatal(err)
	}
	authorizationLeases, err := connectorRepository.ClaimReconciliation(ctx, "connector-worker-a", 30, 10)
	if err != nil || len(authorizationLeases) != 1 || authorizationLeases[0].OAuthAttemptID != successAttemptID || authorizationLeases[0].PrincipalID != identity.PrincipalID.String() || !equalStringSet(authorizationLeases[0].RequestedScopes, []string{"read:org"}) {
		t.Fatalf("authorization reconciliation claim = %#v, %v", authorizationLeases, err)
	}
	completion := OAuthCompletion{AttemptID: successAttemptID, EffectID: successEffectID, ConnectionID: "pid_71000009-0000-4000-8000-000000000009", ConnectionReference: "ref:github/grant/71000008-0000-4000-8000-000000000008", ProviderSubject: "installation:987654", CredentialID: "pid_71000010-0000-4000-8000-000000000010", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":987654}`)}
	wrongAuthorizationLease := authorizationLeases[0]
	wrongAuthorizationLease.LeaseToken = strings.Repeat("f", 64)
	if _, err := connectorRepository.CompleteOAuthReconciliation(ctx, wrongAuthorizationLease, completion); err == nil {
		t.Fatal("wrong-owner OAuth reconciliation succeeded")
	}
	firstCompletion, err := connectorRepository.CompleteOAuthReconciliation(ctx, authorizationLeases[0], completion)
	if err != nil {
		t.Fatalf("complete OAuth: %v", err)
	}
	var cleanupStatus, cleanupCode string
	if err := connection.QueryRow(ctx, `SELECT status,last_error_code FROM zasp_connector_effects WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), successEffectID).Scan(&cleanupStatus, &cleanupCode); err != nil || cleanupStatus != "unknown" || cleanupCode != "cleanup_pending" {
		t.Fatalf("post-completion cleanup authority = %q/%q, %v", cleanupStatus, cleanupCode, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET updated_at=transaction_timestamp()-interval '16 seconds',lease_expires_at=transaction_timestamp()-interval '1 second' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), successEffectID); err != nil {
		t.Fatal(err)
	}
	cleanupLeases, err := connectorRepository.ClaimReconciliation(ctx, "connector-worker-a", 30, 10)
	if err != nil || len(cleanupLeases) != 1 || cleanupLeases[0].LastErrorCode != "cleanup_pending" {
		t.Fatalf("cleanup claim = %#v, %v", cleanupLeases, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET updated_at=transaction_timestamp()-interval '2 seconds',lease_expires_at=transaction_timestamp()-interval '1 second' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), successEffectID); err != nil {
		t.Fatal(err)
	}
	if _, err := connectorRepository.CompleteConnectorCleanupReconciliation(ctx, cleanupLeases[0]); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("expired cleanup owner = %v, want conflict", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), successEffectID); err != nil {
		t.Fatal(err)
	}
	cleanupLeases, err = connectorRepository.ClaimReconciliation(ctx, "connector-worker-b", 30, 10)
	if err != nil || len(cleanupLeases) != 1 {
		t.Fatalf("cleanup reclaim = %#v, %v", cleanupLeases, err)
	}
	if transition, err := connectorRepository.CompleteConnectorCleanupReconciliation(ctx, cleanupLeases[0]); err != nil || transition.Status != "reconciled" {
		t.Fatalf("complete leased connector cleanup = %#v, %v", transition, err)
	}
	replayedCompletion, err := connectorRepository.CompleteOAuthReconciliation(ctx, authorizationLeases[0], completion)
	if err != nil || replayedCompletion != firstCompletion {
		t.Fatalf("completion replay = %#v, %v; first=%#v", replayedCompletion, err, firstCompletion)
	}
	completion.ConnectionReference = "ref:github/install/changed"
	if _, err := connectorRepository.CompleteOAuthReconciliation(ctx, authorizationLeases[0], completion); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("changed completion replay = %v, want conflict", err)
	}
	active, err := repository.GetWorkflow(ctx, identity.Scope, "integration", integrationID)
	var activeBody map[string]any
	if err != nil || json.Unmarshal(active.Body, &activeBody) != nil {
		t.Fatalf("public OAuth completion status = %#v, %v", active, err)
	}
	activeUpdatedAt, _ := activeBody["updated_at"].(string)
	if active.Version != 3 || activeBody["status"] != "active" || !strings.HasSuffix(activeUpdatedAt, "Z") {
		t.Fatalf("public OAuth completion status = %#v, %v", active, err)
	}
	receipts, err := repository.ListWorkflowMutationReceipts(ctx, identity, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundCompletionReceipt := false
	for _, receipt := range receipts {
		var receiptBody map[string]any
		if receipt.Operation == "completeIntegrationOAuth" && receipt.ResourceID == integrationID && receipt.ResourceVersion == 3 && json.Unmarshal(receipt.Result, &receiptBody) == nil && receiptBody["status"] == "active" {
			foundCompletionReceipt = true
		}
	}
	if !foundCompletionReceipt {
		t.Fatalf("public OAuth receipt missing: %#v", receipts)
	}
	var connectorAuditCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_audit WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&connectorAuditCount); err != nil || connectorAuditCount < 8 {
		t.Fatalf("connector audit count = %d, %v", connectorAuditCount, err)
	}
	deletion := WorkflowMutation{Action: "delete", Kind: "integration", ID: integrationID, Operation: "deleteIntegration", IdempotencyKey: "idem-public-connector-delete-0001", ExpectedVersion: 3, Intent: json.RawMessage(`{"body":{},"expected_version":3,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_71000022-0000-4000-8000-000000000022", CorrelationID: "pid_71000023-0000-4000-8000-000000000023", ReceiptID: "pid_71000024-0000-4000-8000-000000000024"}
	stagedDeletion, err := repository.MutateWorkflow(ctx, identity, deletion)
	var stagedDeletionBody map[string]any
	if err != nil || json.Unmarshal(stagedDeletion.Body, &stagedDeletionBody) != nil || stagedDeletionBody["status"] != "revoking" || stagedDeletion.ReceiptID != deletion.ReceiptID {
		t.Fatalf("public integration delete: %v", err)
	}
	if replay, err := repository.MutateWorkflow(ctx, identity, deletion); err != nil || !replay.Replayed {
		t.Fatalf("public integration delete replay = %#v, %v", replay, err)
	}
	var typedState, effectStatus, effectOperation, credentialStatus string
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&typedState); err != nil || typedState != "degraded" {
		t.Fatalf("typed integration revocation pending = %q, %v", typedState, err)
	}
	if err := connection.QueryRow(ctx, `SELECT operation,status FROM zasp_connector_effects WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND operation='revoke'`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&effectOperation, &effectStatus); err != nil || effectStatus != "unknown" {
		t.Fatalf("durable revoke effect = %q/%q, %v", effectOperation, effectStatus, err)
	}
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_connector_credentials WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&credentialStatus); err != nil || credentialStatus != "active" {
		t.Fatalf("credential revoked before provider confirmation = %q, %v", credentialStatus, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND operation='revoke'`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	leases, err := connectorRepository.ClaimReconciliation(ctx, "connector-worker-a", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].Operation != "revoke" || leases[0].ConnectionReference != "ref:github/grant/71000008-0000-4000-8000-000000000008" {
		t.Fatalf("revoke claim = %#v, %v", leases, err)
	}
	wrongLease := leases[0]
	wrongLease.LeaseToken = strings.Repeat("f", 64)
	if _, err := connectorRepository.CompleteConnectorRevocation(ctx, wrongLease); err == nil {
		t.Fatal("wrong-owner revocation completion succeeded")
	}
	completedRevocation, err := connectorRepository.CompleteConnectorRevocation(ctx, leases[0])
	if err != nil || completedRevocation.Status != "reconciled" {
		t.Fatalf("complete revocation = %#v, %v", completedRevocation, err)
	}
	if replay, err := connectorRepository.CompleteConnectorRevocation(ctx, leases[0]); err != nil || replay != completedRevocation {
		t.Fatalf("revocation replay = %#v, %v; first=%#v", replay, err, completedRevocation)
	}
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&typedState); err != nil || typedState != "deleted" {
		t.Fatalf("typed integration final revocation = %q, %v", typedState, err)
	}
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_connector_credentials WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&credentialStatus); err != nil || credentialStatus != "revoked" {
		t.Fatalf("credential final revocation = %q, %v", credentialStatus, err)
	}
	terminalDeletion, err := repository.MutateWorkflow(ctx, identity, deletion)
	var terminalDeletionBody map[string]any
	if err != nil || !terminalDeletion.Replayed || json.Unmarshal(terminalDeletion.Body, &terminalDeletionBody) != nil || len(terminalDeletionBody) != 2 || terminalDeletionBody["id"] != integrationID || terminalDeletionBody["status"] != "deleted" || terminalDeletion.ReceiptID != deletion.ReceiptID {
		t.Fatalf("terminal public deletion replay = %#v body=%v, %v", terminalDeletion, terminalDeletionBody, err)
	}
	receipts, err = repository.ListWorkflowMutationReceipts(ctx, identity, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundTerminalDeletionReceipt := false
	for _, receipt := range receipts {
		var receiptBody map[string]any
		if receipt.ID == deletion.ReceiptID && receipt.Operation == "deleteIntegration" && json.Unmarshal(receipt.Result, &receiptBody) == nil && len(receiptBody) == 2 && receiptBody["id"] == integrationID && receiptBody["status"] == "deleted" {
			foundTerminalDeletionReceipt = true
		}
	}
	if !foundTerminalDeletionReceipt {
		t.Fatalf("terminal deletion receipt missing: %#v", receipts)
	}
}

func TestConnectorAuthorizationPostgresAmbiguousProviderOutcomeIsPermanentlyQuarantined(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToReferenceAuthorization(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	workflowRepository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	connectorRepository := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72000001-0000-4000-8000-000000000001"
	body := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub Quarantine","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)
	mutation := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-quarantine-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: body, AuditID: "pid_72000002-0000-4000-8000-000000000002", CorrelationID: "pid_72000003-0000-4000-8000-000000000003", ReceiptID: "pid_72000004-0000-4000-8000-000000000004"}
	if _, err := workflowRepository.MutateWorkflow(ctx, identity, mutation); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("ambiguous-provider-outcome"))
	attemptID := "pid_72000005-0000-4000-8000-000000000005"
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: attemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/quarantine", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), IntegrationVersion: 1, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}); err != nil {
		t.Fatal(err)
	}
	consumption, err := connectorRepository.ConsumeOAuth(ctx, identity, digest[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	effectID := consumption.EffectID
	second := sha256.Sum256([]byte("second-attempt-before-quarantine"))
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: "pid_72000007-0000-4000-8000-000000000007", IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/blocked", SessionDigest: second[:], StateDigest: second[:], RequestDigest: second[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), IntegrationVersion: 1, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("fresh authorization while unresolved = %v, want conflict", err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET attempt=99,updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID); err != nil {
		t.Fatal(err)
	}
	leases, err := connectorRepository.ClaimReconciliation(ctx, "connector-worker-a", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].Attempt != 100 || leases[0].LastErrorCode != "provider_effect_started" {
		t.Fatalf("final ambiguous claim = %#v, %v", leases, err)
	}
	if transition, err := connectorRepository.QuarantineConnectorReconciliation(ctx, leases[0], "provider_outcome_ambiguous"); err != nil || transition.Status != "unknown" || transition.Attempt != 100 {
		t.Fatalf("quarantine transition = %#v, %v", transition, err)
	}
	if quarantine, err := connectorRepository.GetConnectorQuarantine(ctx, identity.Scope, integrationID); err != nil || quarantine.ID != effectID || quarantine.Operation != "authorize" || quarantine.ConnectionReference != "" || quarantine.Reason != "provider_outcome_ambiguous" {
		t.Fatalf("quarantine discovery = %#v, %v", quarantine, err)
	}
	var effectStatus, errorCode, integrationState, attemptStatus string
	var auditCount int
	if err := connection.QueryRow(ctx, `SELECT e.status,e.last_error_code,i.state,a.status,(SELECT count(*) FROM zasp_connector_audit audit WHERE audit.organization_id=e.organization_id AND audit.workspace_id=e.workspace_id AND audit.environment_id=e.environment_id AND audit.effect_id=e.id AND audit.reason_code='provider_outcome_ambiguous') FROM zasp_connector_effects e JOIN zasp_integrations i ON (i.organization_id,i.workspace_id,i.environment_id,i.id)=(e.organization_id,e.workspace_id,e.environment_id,e.integration_id) JOIN zasp_connector_oauth_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.id)=(e.organization_id,e.workspace_id,e.environment_id,e.oauth_attempt_id) WHERE (e.organization_id,e.workspace_id,e.environment_id,e.id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID).Scan(&effectStatus, &errorCode, &integrationState, &attemptStatus, &auditCount); err != nil || effectStatus != "unknown" || errorCode != "provider_outcome_ambiguous" || integrationState != "degraded" || attemptStatus != "consuming" || auditCount != 1 {
		t.Fatalf("durable quarantine = %q/%q integration=%q attempt=%q audit=%d err=%v", effectStatus, errorCode, integrationState, attemptStatus, auditCount, err)
	}
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: "pid_72000007-0000-4000-8000-000000000007", IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/blocked", SessionDigest: second[:], StateDigest: second[:], RequestDigest: second[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), IntegrationVersion: 2, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("fresh authorization while quarantined = %v, want conflict", err)
	}
	workflow, err := workflowRepository.GetWorkflow(ctx, identity.Scope, "integration", integrationID)
	var quarantinedBody map[string]any
	if err != nil || json.Unmarshal(workflow.Body, &quarantinedBody) != nil {
		t.Fatalf("operator-visible quarantined workflow = %#v body=%v, %v", workflow, quarantinedBody, err)
	}
	quarantinedUpdatedAt, _ := quarantinedBody["updated_at"].(string)
	if workflow.Version != 2 || quarantinedBody["status"] != "degraded" || !strings.HasSuffix(quarantinedUpdatedAt, "Z") {
		t.Fatalf("operator-visible quarantined workflow = %#v body=%v, %v", workflow, quarantinedBody, err)
	}
	quarantinedBody["status"] = "pending_authorization"
	quarantinedBody["updated_at"] = "2026-08-19T00:02:00Z"
	remediationBody, _ := json.Marshal(quarantinedBody)
	remediation := ConnectorQuarantineRemediation{EffectID: effectID, IntegrationID: integrationID, Acknowledgement: "provider_grant_revoked_manually", IdempotencyKey: "idem-quarantine-remediation-0001", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"acknowledgement":"provider_grant_revoked_manually"},"expected_version":2,"resource_id":"` + integrationID + `"}`), Body: remediationBody, AuditID: "pid_72000008-0000-4000-8000-000000000008", CorrelationID: "pid_72000009-0000-4000-8000-000000000009", ReceiptID: "pid_72000010-0000-4000-8000-000000000010"}
	remediated, err := connectorRepository.RemediateConnectorQuarantine(ctx, identity, remediation)
	var remediatedBody map[string]any
	if err != nil || json.Unmarshal(remediated.Body, &remediatedBody) != nil || remediatedBody["status"] != "pending_authorization" || remediated.Version != 3 || remediated.ReceiptID != remediation.ReceiptID {
		t.Fatalf("explicit quarantine remediation = %#v, %v", remediated, err)
	}
	if replay, err := connectorRepository.RemediateConnectorQuarantine(ctx, identity, remediation); err != nil || !replay.Replayed || replay.Version != remediated.Version || replay.ReceiptID != remediated.ReceiptID {
		t.Fatalf("quarantine remediation replay = %#v, %v; first=%#v", replay, err, remediated)
	}
	if _, err := connectorRepository.GetConnectorQuarantine(ctx, identity.Scope, integrationID); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("remediated history remained an active quarantine: %v", err)
	}
	if replay, found, err := connectorRepository.ReplayConnectorQuarantine(ctx, identity, integrationID, remediation.IdempotencyKey, remediation.ExpectedVersion, remediation.Intent); err != nil || !found || !replay.Replayed || replay.ReceiptID != remediated.ReceiptID {
		t.Fatalf("historical remediation replay=%#v found=%v err=%v", replay, found, err)
	}
	remediation.Acknowledgement = "provider_grant_verified_absent"
	if _, err := connectorRepository.RemediateConnectorQuarantine(ctx, identity, remediation); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("changed quarantine remediation = %v, want conflict", err)
	}
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: "pid_72000011-0000-4000-8000-000000000011", IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/remediated", SessionDigest: second[:], StateDigest: second[:], RequestDigest: second[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), IntegrationVersion: 3, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}); err != nil {
		t.Fatalf("fresh authorization after explicit remediation = %v", err)
	}
}

func TestConnectorAuthorizationPostgresRevocationExhaustionIsVisibleAndRetriable(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72100001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-revoke-quarantine-create", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub Revoke","configuration":{"authorization_mode":"github_app"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72100002-0000-4000-8000-000000000002", CorrelationID: "pid_72100003-0000-4000-8000-000000000003", ReceiptID: "pid_72100004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("revocation-exhaustion"))
	effectID := "pid_72100005-0000-4000-8000-000000000005"
	if _, err := connectors.BeginConnectorEffect(ctx, identity.Scope, ConnectorEffectStart{ID: effectID, IntegrationID: integrationID, Provider: "github", Operation: "revoke", IdempotencyKey: "idem-revoke-quarantine-effect", RequestDigest: digest[:]}); err != nil {
		t.Fatal(err)
	}
	if _, err := connectors.ResolveConnectorEffect(ctx, identity.Scope, ConnectorEffectResolution{ID: effectID, Status: "unknown", ConnectionReference: "ref:github/installation/123456", ErrorCode: "revocation_requested", Metadata: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET attempt=99,updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID); err != nil {
		t.Fatal(err)
	}
	leases, err := connectors.ClaimReconciliation(ctx, "connector-worker-a", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].Operation != "revoke" || leases[0].Attempt != 100 {
		t.Fatalf("final revoke claim = %#v, %v", leases, err)
	}
	if _, err := connectors.QuarantineConnectorReconciliation(ctx, leases[0], "provider_revocation_ambiguous"); err != nil {
		t.Fatal(err)
	}
	quarantine, err := connectors.GetConnectorQuarantine(ctx, identity.Scope, integrationID)
	if err != nil || quarantine.Operation != "revoke" || quarantine.Reason != "provider_revocation_ambiguous" || quarantine.ConnectionReference != "ref:github/installation/123456" {
		raw, _ := database.QueryJSON(ctx, postgresConnectorGetQuarantineSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID)
		t.Fatalf("visible revoke quarantine = %#v, %v raw=%s", quarantine, err, raw)
	}
	remediation := ConnectorQuarantineRemediation{EffectID: effectID, IntegrationID: integrationID, Acknowledgement: "provider_grant_verified_absent", IdempotencyKey: "idem-revoke-quarantine-remediate", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"acknowledgement":"provider_grant_verified_absent"},"expected_version":2,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_72100006-0000-4000-8000-000000000006", CorrelationID: "pid_72100007-0000-4000-8000-000000000007", ReceiptID: "pid_72100008-0000-4000-8000-000000000008"}
	first, err := connectors.RemediateConnectorQuarantine(ctx, identity, remediation)
	var firstBody map[string]any
	if err != nil || first.Version != 3 || json.Unmarshal(first.Body, &firstBody) != nil || firstBody["status"] != "revoking" {
		t.Fatalf("revoke remediation = %#v, %v", first, err)
	}
	if replay, err := connectors.RemediateConnectorQuarantine(ctx, identity, remediation); err != nil || !replay.Replayed || replay.Version != first.Version {
		t.Fatalf("revoke remediation replay = %#v, %v", replay, err)
	}
	leases, err = connectors.ClaimReconciliation(ctx, "connector-worker-b", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].ID != effectID || leases[0].Attempt != 1 || leases[0].LastErrorCode != "provider_revocation_remediated" {
		t.Fatalf("remediated revoke reclaim = %#v, %v", leases, err)
	}

	cleanupIntegrationID := "pid_72100011-0000-4000-8000-000000000011"
	cleanupCreate := WorkflowMutation{Action: "create", Kind: "integration", ID: cleanupIntegrationID, Operation: "createIntegration", IdempotencyKey: "idem-cleanup-quarantine-create", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + cleanupIntegrationID + `","connector_key":"github","name":"GitHub Cleanup","configuration":{"authorization_mode":"github_app"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72100012-0000-4000-8000-000000000012", CorrelationID: "pid_72100013-0000-4000-8000-000000000013", ReceiptID: "pid_72100014-0000-4000-8000-000000000014"}
	if _, err := workflows.MutateWorkflow(ctx, identity, cleanupCreate); err != nil {
		t.Fatal(err)
	}
	cleanupEffectID := "pid_72100015-0000-4000-8000-000000000015"
	if _, err := connectors.BeginConnectorEffect(ctx, identity.Scope, ConnectorEffectStart{ID: cleanupEffectID, IntegrationID: cleanupIntegrationID, Provider: "github", Operation: "authorize", IdempotencyKey: "idem-cleanup-quarantine-effect", RequestDigest: digest[:]}); err != nil {
		t.Fatal(err)
	}
	if _, err := connectors.ResolveConnectorEffect(ctx, identity.Scope, ConnectorEffectResolution{ID: cleanupEffectID, Status: "unknown", ConnectionReference: "ref:github/installation/654321", ErrorCode: "cleanup_pending", Metadata: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	leaseToken := strings.Repeat("a", 64)
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET attempt=100,lease_owner='connector-worker-a',lease_token=$5,updated_at=transaction_timestamp(),lease_expires_at=transaction_timestamp()+interval '30 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), cleanupEffectID, leaseToken); err != nil {
		t.Fatal(err)
	}
	if _, err := database.QueryJSON(ctx, postgresConnectorQuarantineSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), cleanupEffectID, "connector-worker-a", leaseToken, "provider_cleanup_ambiguous"); err != nil {
		t.Fatalf("final cleanup quarantine: %v", err)
	}
	cleanupQuarantine, err := connectors.GetConnectorQuarantine(ctx, identity.Scope, cleanupIntegrationID)
	if err != nil || cleanupQuarantine.Operation != "authorize" || cleanupQuarantine.Reason != "provider_cleanup_ambiguous" || cleanupQuarantine.ConnectionReference != "ref:github/installation/654321" {
		t.Fatalf("visible cleanup quarantine = %#v, %v", cleanupQuarantine, err)
	}
	cleanupRemediation := ConnectorQuarantineRemediation{EffectID: cleanupEffectID, IntegrationID: cleanupIntegrationID, Acknowledgement: "provider_grant_verified_absent", IdempotencyKey: "idem-cleanup-quarantine-remed", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"acknowledgement":"provider_grant_verified_absent"},"expected_version":2,"resource_id":"` + cleanupIntegrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_72100016-0000-4000-8000-000000000016", CorrelationID: "pid_72100017-0000-4000-8000-000000000017", ReceiptID: "pid_72100018-0000-4000-8000-000000000018"}
	cleanupResult, err := connectors.RemediateConnectorQuarantine(ctx, identity, cleanupRemediation)
	var cleanupBody map[string]any
	if err != nil || cleanupResult.Version != 3 || json.Unmarshal(cleanupResult.Body, &cleanupBody) != nil || cleanupBody["status"] != "active" {
		t.Fatalf("cleanup remediation = %#v, %v", cleanupResult, err)
	}
	var cleanupStatus, cleanupReason string
	if err := connection.QueryRow(ctx, `SELECT status,last_error_code FROM zasp_connector_effects WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), cleanupEffectID).Scan(&cleanupStatus, &cleanupReason); err != nil || cleanupStatus != "failed" || cleanupReason != "provider_cleanup_remediated" {
		t.Fatalf("terminal cleanup remediation = %q/%q, %v", cleanupStatus, cleanupReason, err)
	}
}

func TestConnectorAuthorizationPostgresStartAtomicallyStagesAndExpiresPKCECleanup(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72200001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-atomic-pkce-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub PKCE","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72200002-0000-4000-8000-000000000002", CorrelationID: "pid_72200003-0000-4000-8000-000000000003", ReceiptID: "pid_72200004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("atomic-pkce"))
	failingAttemptID := "pid_72200005-0000-4000-8000-000000000005"
	failingCleanupID := connectorDeterministicID(identity.Scope, failingAttemptID, "pkce-cleanup")
	if _, err := connectors.StagePKCECleanup(ctx, identity.Scope, PKCECleanupStage{ID: failingCleanupID, IntegrationID: integrationID, Provider: "github", Reference: "ref:oauth/pkce/conflicting", RequestDigest: digest[:], AvailableAt: time.Now().UTC().Add(5 * time.Minute), Reason: "oauth_start_rejected"}); err != nil {
		t.Fatal(err)
	}
	start := OAuthStart{AttemptID: failingAttemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/atomic-failure", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond), IntegrationVersion: 1, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}
	if _, err := connectors.StartOAuth(ctx, identity, start); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("conflicting atomic cleanup start = %v", err)
	}
	var failedAttemptCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), failingAttemptID).Scan(&failedAttemptCount); err != nil || failedAttemptCount != 0 {
		t.Fatalf("stage failure left attempt residue count=%d err=%v", failedAttemptCount, err)
	}

	attemptID := "pid_72200006-0000-4000-8000-000000000006"
	start.AttemptID = attemptID
	start.PKCEVerifierReference = "ref:oauth/pkce/atomic-success"
	stateDigest := sha256.Sum256([]byte("atomic-pkce-success-state"))
	start.StateDigest = stateDigest[:]
	attempt, err := connectors.StartOAuth(ctx, identity, start)
	if err != nil {
		t.Fatal(err)
	}
	cleanupID := connectorDeterministicID(identity.Scope, attemptID, "pkce-cleanup")
	var cleanupAttemptID, cleanupStatus string
	if err := connection.QueryRow(ctx, `SELECT oauth_attempt_id,status FROM zasp_connector_effects WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), cleanupID).Scan(&cleanupAttemptID, &cleanupStatus); err != nil || cleanupAttemptID != attempt.ID || cleanupStatus != "unknown" {
		t.Fatalf("atomic cleanup effect attempt=%q status=%q err=%v", cleanupAttemptID, cleanupStatus, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET available_at=transaction_timestamp()-interval '1 second',updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), cleanupID); err != nil {
		t.Fatal(err)
	}
	leases, err := connectors.ClaimReconciliation(ctx, "connector-worker-a", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].ID != cleanupID || leases[0].Operation != "pkce_cleanup" {
		t.Fatalf("expired PKCE claim = %#v, %v", leases, err)
	}
	if _, err := connectors.CompletePKCECleanupReconciliation(ctx, leases[0]); err != nil {
		t.Fatal(err)
	}
	var attemptStatus string
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), attemptID).Scan(&attemptStatus); err != nil || attemptStatus != "expired" {
		t.Fatalf("abandoned attempt status=%q err=%v", attemptStatus, err)
	}
	start.AttemptID = "pid_72200007-0000-4000-8000-000000000007"
	start.PKCEVerifierReference = "ref:oauth/pkce/retry-after-expiry"
	retryState := sha256.Sum256([]byte("retry-after-expiry"))
	start.StateDigest = retryState[:]
	if _, err := connectors.StartOAuth(ctx, identity, start); err != nil {
		t.Fatalf("fresh OAuth after expired cleanup = %v", err)
	}
	manualAttemptID := start.AttemptID
	manualCleanupID := connectorDeterministicID(identity.Scope, manualAttemptID, "pkce-cleanup")
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET attempt=99,available_at=transaction_timestamp()-interval '1 second',updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), manualCleanupID); err != nil {
		t.Fatal(err)
	}
	leases, err = connectors.ClaimReconciliation(ctx, "connector-worker-b", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].ID != manualCleanupID || leases[0].Attempt != 100 {
		t.Fatalf("final PKCE claim = %#v, %v", leases, err)
	}
	if _, err := connectors.QuarantineConnectorReconciliation(ctx, leases[0], "pkce_cleanup_ambiguous"); err != nil {
		t.Fatal(err)
	}
	quarantine, err := connectors.GetConnectorQuarantine(ctx, identity.Scope, integrationID)
	if err != nil || quarantine.Operation != "pkce_cleanup" || quarantine.ConnectionReference != start.PKCEVerifierReference || quarantine.Reason != "pkce_cleanup_ambiguous" {
		t.Fatalf("manual PKCE quarantine = %#v, %v", quarantine, err)
	}
	remediation := ConnectorQuarantineRemediation{EffectID: manualCleanupID, IntegrationID: integrationID, Acknowledgement: "provider_grant_verified_absent", IdempotencyKey: "idem-pkce-quarantine-remediate", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"acknowledgement":"provider_grant_verified_absent"},"expected_version":2,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_72200008-0000-4000-8000-000000000008", CorrelationID: "pid_72200009-0000-4000-8000-000000000009", ReceiptID: "pid_72200010-0000-4000-8000-000000000010"}
	if _, err := connectors.RemediateConnectorQuarantine(ctx, identity, remediation); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), manualAttemptID).Scan(&attemptStatus); err != nil || attemptStatus != "expired" {
		t.Fatalf("manually remediated attempt status=%q err=%v", attemptStatus, err)
	}
}

func TestConnectorAuthorizationPostgresConsumedAttemptCannotBeExpiredByPKCECleanup(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72200001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-atomic-pkce-create-0002", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub Recovery","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72300002-0000-4000-8000-000000000002", CorrelationID: "pid_72300003-0000-4000-8000-000000000003", ReceiptID: "pid_72300004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("consuming-pkce"))
	attemptID := "pid_72200015-0000-4000-8000-000000000015"
	start := OAuthStart{AttemptID: attemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/consuming-recovery", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Microsecond), IntegrationVersion: 1, Configuration: json.RawMessage(`{"authorization_mode":"github_app"}`)}
	cleanupID := connectorDeterministicID(identity.Scope, attemptID, "pkce-cleanup")
	if _, err := connectors.StagePKCECleanup(ctx, identity.Scope, PKCECleanupStage{ID: cleanupID, IntegrationID: integrationID, Provider: "github", Reference: start.PKCEVerifierReference, RequestDigest: digest[:], AvailableAt: start.ExpiresAt, Reason: "oauth_attempt_expiry"}); err != nil {
		t.Fatal(err)
	}
	if _, err := connectors.StartOAuth(ctx, identity, start); err != nil {
		t.Fatal(err)
	}
	if record, err := connectors.StartOAuth(ctx, identity, start); err != nil || !record.ExpiresAt.Equal(start.ExpiresAt) {
		t.Fatalf("durable-before-secret replay = %#v, %v", record, err)
	}
	consumption, err := connectors.ConsumeOAuth(ctx, identity, digest[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET available_at=transaction_timestamp()-interval '1 second',updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), cleanupID); err != nil {
		t.Fatal(err)
	}
	leases, err := connectors.ClaimReconciliation(ctx, "connector-worker-consuming", 30, 10)
	if err != nil || len(leases) != 0 {
		t.Fatalf("consuming attempt exposed PKCE cleanup lease = %#v, %v", leases, err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET attempt=99,updated_at=transaction_timestamp()-interval '16 seconds' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), consumption.EffectID); err != nil {
		t.Fatal(err)
	}
	leases, err = connectors.ClaimReconciliation(ctx, "connector-worker-recovery", 30, 10)
	if err != nil || len(leases) != 1 || leases[0].ID != consumption.EffectID || leases[0].Attempt != 100 {
		t.Fatalf("authorize recovery lease = %#v, %v", leases, err)
	}
	completion := OAuthCompletion{AttemptID: attemptID, EffectID: consumption.EffectID, ConnectionID: "pid_72200016-0000-4000-8000-000000000016", ConnectionReference: "ref:github/installation/723000", ProviderSubject: "installation:723000", CredentialID: "pid_72200017-0000-4000-8000-000000000017", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":723000}`)}
	if _, err := connectors.CompleteOAuthReconciliation(ctx, leases[0], completion); err != nil {
		t.Fatal(err)
	}
	var retainedOwner, retainedToken string
	var retainedExpiry time.Time
	if err := connection.QueryRow(ctx, `SELECT lease_owner,lease_token,lease_expires_at FROM zasp_connector_effects WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), consumption.EffectID).Scan(&retainedOwner, &retainedToken, &retainedExpiry); err != nil || retainedOwner != leases[0].LeaseOwner || retainedToken != leases[0].LeaseToken || !retainedExpiry.Equal(leases[0].LeaseExpiresAt) {
		t.Fatalf("completion did not retain finalization lease owner=%q token=%q expiry=%s err=%v", retainedOwner, retainedToken, retainedExpiry, err)
	}
	if _, err := connectors.CompleteConnectorCleanupReconciliation(ctx, leases[0]); err != nil {
		t.Fatal(err)
	}
	var attemptStatus, cleanupStatus string
	if err := connection.QueryRow(ctx, `SELECT a.status,c.status FROM zasp_connector_oauth_attempts a JOIN zasp_connector_effects c ON (c.organization_id,c.workspace_id,c.environment_id,c.oauth_attempt_id)=(a.organization_id,a.workspace_id,a.environment_id,a.id) AND c.operation='pkce_cleanup' WHERE a.organization_id=$1 AND a.workspace_id=$2 AND a.environment_id=$3 AND a.id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), attemptID).Scan(&attemptStatus, &cleanupStatus); err != nil || attemptStatus != "succeeded" || cleanupStatus != "unknown" {
		t.Fatalf("recovered attempt=%q cleanup=%q err=%v", attemptStatus, cleanupStatus, err)
	}
}

func TestConnectorAuthorizationPostgresClaimReturnsOneImmediatelyRunnableLeasePerExactLane(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72400001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-fair-claim-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Fair Claim","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72400002-0000-4000-8000-000000000002", CorrelationID: "pid_72400003-0000-4000-8000-000000000003", ReceiptID: "pid_72400004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("fair-claim"))
	for ordinal := 1; ordinal <= 25; ordinal++ {
		effectID := fmt.Sprintf("pid_724001%02d-0000-4000-8000-%012d", ordinal, ordinal)
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,attempt,available_at,updated_at) VALUES($1,$2,$3,$4,$5,'github','revoke',$6,$7,'unknown','ref:github/installation/123456',99,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID, integrationID, fmt.Sprintf("fair-revoke-%04d", ordinal), digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	otherLaneID := "pid_72400201-0000-4000-8000-000000000001"
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,attempt,available_at,updated_at) VALUES($1,$2,$3,$4,$5,'okta','revoke',$6,$7,'unknown','ref:okta/refresh/customer-0001',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '30 seconds')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), otherLaneID, integrationID, "fair-okta-revoke-0001", digest[:]); err != nil {
		t.Fatal(err)
	}
	otherConnection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer otherConnection.Close(ctx)
	otherDatabase, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: otherConnection})
	otherConnectors := &ConnectorRepository{database: otherDatabase}
	type claimResult struct {
		leases []ConnectorEffectLease
		err    error
	}
	claims := make(chan claimResult, 2)
	start := make(chan struct{})
	for _, candidate := range []struct {
		repository *ConnectorRepository
		owner      string
	}{{connectors, "connector-worker-fair"}, {otherConnectors, "connector-worker-other"}} {
		go func(repository *ConnectorRepository, owner string) {
			<-start
			leases, claimErr := repository.ClaimReconciliation(ctx, owner, 30, 1)
			claims <- claimResult{leases: leases, err: claimErr}
		}(candidate.repository, candidate.owner)
	}
	close(start)
	firstResult, secondResult := <-claims, <-claims
	claimed := append(firstResult.leases, secondResult.leases...)
	if firstResult.err != nil || secondResult.err != nil || len(claimed) != 2 {
		t.Fatalf("simultaneous claims=%#v errors=%v/%v", claimed, firstResult.err, secondResult.err)
	}
	var leases, second []ConnectorEffectLease
	for _, lease := range claimed {
		if lease.Provider == "github" {
			leases = append(leases, lease)
		} else if lease.Provider == "okta" {
			second = append(second, lease)
		}
	}
	if len(leases) != 1 || leases[0].Operation != "revoke" || leases[0].Attempt != 100 || len(second) != 1 || second[0].ID != otherLaneID || second[0].LeaseOwner == leases[0].LeaseOwner || second[0].LeaseToken == leases[0].LeaseToken {
		t.Fatalf("live exact-lane exclusion claims=%#v", claimed)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET updated_at=transaction_timestamp()-interval '2 seconds',lease_expires_at=transaction_timestamp()-interval '1 second' WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, leases[0].OrganizationID, leases[0].WorkspaceID, leases[0].EnvironmentID, leases[0].ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := connectors.RecoverExpiredFinalAttempts(ctx, "connector-worker-restarted", 30, 25)
	if err != nil || recovered != 1 {
		t.Fatalf("restart final-attempt recovery=%d err=%v", recovered, err)
	}
	if _, err := connectors.QuarantineConnectorReconciliation(ctx, leases[0], "provider_revocation_ambiguous"); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("crashed owner retained terminalization authority = %v", err)
	}
	var stranded int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_effects WHERE attempt=100 AND status='unknown' AND last_error_code IS DISTINCT FROM 'provider_revocation_ambiguous'`).Scan(&stranded); err != nil || stranded != 0 {
		t.Fatalf("stranded final attempts=%d err=%v", stranded, err)
	}
}

func TestConnectorAuthorizationPostgresRestartTickQuarantinesExpiredFinalAttemptWithoutProviderCall(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72410001-0000-4000-8000-000000000001"
	effectID := "pid_72410002-0000-4000-8000-000000000002"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "restart-final-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Restart Final","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72410003-0000-4000-8000-000000000003", CorrelationID: "pid_72410004-0000-4000-8000-000000000004", ReceiptID: "pid_72410005-0000-4000-8000-000000000005"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("restart-final"))
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,attempt,lease_owner,lease_token,lease_expires_at,available_at,updated_at) VALUES($1,$2,$3,$4,$5,'github','revoke',$6,$7,'unknown','ref:github/installation/123456',100,'crashed-worker',$8,transaction_timestamp()-interval '1 second',transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID, integrationID, "restart-final-revoke-0001", digest[:], strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	provider := &connectorRecoveryProvider{}
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: connectors, Workflows: workflows, Registry: registry, Secrets: &connectorSecretStub{}, Owner: "restarted-worker", LeaseSeconds: 30, Limit: 25, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.reconcileOnce(ctx); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	providerCalls := provider.recoverCalls + provider.revokeCalls + provider.discardCalls + provider.completeCalls
	provider.mu.Unlock()
	var errorCode, workflowStatus string
	if err := connection.QueryRow(ctx, `SELECT e.last_error_code,w.body->>'status' FROM zasp_connector_effects e JOIN zasp_workflow_records w ON (w.organization_id,w.workspace_id,w.environment_id,w.id)=(e.organization_id,e.workspace_id,e.environment_id,e.integration_id) WHERE e.id=$1`, effectID).Scan(&errorCode, &workflowStatus); err != nil || errorCode != "provider_revocation_ambiguous" || workflowStatus != "degraded" || providerCalls != 0 {
		t.Fatalf("restart recovery error=%q status=%q provider_calls=%d err=%v", errorCode, workflowStatus, providerCalls, err)
	}
}

func TestConnectorAuthorizationPostgresExpiredFinalAttemptRecoveryIsOperationAware(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	tests := []struct {
		operation, priorCode, reference, wantCode string
	}{
		{operation: "authorize", priorCode: "provider_effect_started", wantCode: "provider_outcome_ambiguous"},
		{operation: "authorize", priorCode: "cleanup_pending", reference: "ref:github/installation/123456", wantCode: "provider_cleanup_ambiguous"},
		{operation: "revoke", reference: "ref:github/installation/123456", wantCode: "provider_revocation_ambiguous"},
		{operation: "pkce_cleanup", priorCode: "oauth_attempt_expiry", reference: "ref:oauth/pkce/72440000-0000-4000-8000-000000000000", wantCode: "pkce_cleanup_ambiguous"},
	}
	digest := sha256.Sum256([]byte("operation-aware-final-recovery"))
	for index, test := range tests {
		integrationID := fmt.Sprintf("pid_72440%03d-0000-4000-8000-%012d", index+1, index+1)
		effectID := fmt.Sprintf("pid_72441%03d-0000-4000-8000-%012d", index+1, index+1)
		create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: fmt.Sprintf("operation-recovery-create-%04d", index), Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Recovery","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: fmt.Sprintf("pid_72442%03d-0000-4000-8000-%012d", index+1, index+1), CorrelationID: fmt.Sprintf("pid_72443%03d-0000-4000-8000-%012d", index+1, index+1), ReceiptID: fmt.Sprintf("pid_72444%03d-0000-4000-8000-%012d", index+1, index+1)}
		if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,attempt,last_error_code,lease_owner,lease_token,lease_expires_at,available_at,updated_at) VALUES($1,$2,$3,$4,$5,'github',$6,$7,$8,'unknown',NULLIF($9,''),100,NULLIF($10,''),'crashed-worker',$11,transaction_timestamp()-interval '1 second',transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID, integrationID, test.operation, fmt.Sprintf("operation-recovery-effect-%04d", index), digest[:], test.reference, test.priorCode, strings.Repeat(fmt.Sprintf("%x", index+1), 64)[:64]); err != nil {
			t.Fatal(err)
		}
	}
	if recovered, err := connectors.RecoverExpiredFinalAttempts(ctx, "restart-matrix-worker", 30, 25); err != nil || recovered != len(tests) {
		t.Fatalf("operation-aware recovery=%d err=%v", recovered, err)
	}
	rows, err := connection.Query(ctx, `SELECT operation,last_error_code FROM zasp_connector_effects ORDER BY operation,last_error_code`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int{}
	for rows.Next() {
		var operation, code string
		if err := rows.Scan(&operation, &code); err != nil {
			t.Fatal(err)
		}
		got[operation+":"+code]++
	}
	for index, test := range tests {
		if got[test.operation+":"+test.wantCode] != 1 {
			t.Fatalf("operation-aware quarantine=%#v missing %s/%s", got, test.operation, test.wantCode)
		}
		integrationID := fmt.Sprintf("pid_72440%03d-0000-4000-8000-%012d", index+1, index+1)
		quarantine, quarantineErr := connectors.GetConnectorQuarantine(ctx, identity.Scope, integrationID)
		if quarantineErr != nil || quarantine.Reason != test.wantCode || quarantine.ConnectionReference != test.reference {
			t.Fatalf("operation-aware quarantine lookup for %s = %#v, %v", test.wantCode, quarantine, quarantineErr)
		}
	}
	var degraded, audited int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_integrations WHERE state='degraded'),(SELECT count(*) FROM zasp_connector_audit WHERE event_kind='effect_unknown' AND reason_code IN('provider_outcome_ambiguous','provider_cleanup_ambiguous','provider_revocation_ambiguous','pkce_cleanup_ambiguous'))`).Scan(&degraded, &audited); err != nil || degraded != len(tests) || audited != len(tests) {
		t.Fatalf("operation-aware state degraded=%d audited=%d err=%v", degraded, audited, err)
	}
}

func TestConnectorAuthorizationPostgresEnforcesGlobalLeaseCapAcrossReplicas(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72420001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "global-cap-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Global Cap","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72420002-0000-4000-8000-000000000002", CorrelationID: "pid_72420003-0000-4000-8000-000000000003", ReceiptID: "pid_72420004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("global-cap"))
	for ordinal := 1; ordinal <= 101; ordinal++ {
		effectID := fmt.Sprintf("pid_72421%03d-0000-4000-8000-%012d", ordinal, ordinal)
		provider := fmt.Sprintf("nango:p%03d", ordinal)
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'bind',$7,$8,'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID, integrationID, provider, fmt.Sprintf("global-cap-effect-%04d", ordinal), digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	repositories := make([]*ConnectorRepository, 3)
	connections := make([]*pgx.Conn, 0, 2)
	repositories[0] = &ConnectorRepository{database: database}
	for index := 1; index < 3; index++ {
		candidate, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, candidate)
		candidateDB, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: candidate})
		repositories[index] = &ConnectorRepository{database: candidateDB}
	}
	defer func() {
		for _, candidate := range connections {
			_ = candidate.Close(ctx)
		}
	}()
	var claimed int
	for index, repository := range repositories {
		leases, err := repository.ClaimReconciliation(ctx, fmt.Sprintf("surge-replica-%d", index), 30, 100)
		if err != nil {
			t.Fatal(err)
		}
		claimed += len(leases)
		if index > 0 && len(leases) != 0 {
			t.Fatalf("replica %d exceeded global cap with %d leases", index, len(leases))
		}
	}
	var live int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_effects WHERE status='unknown' AND lease_expires_at>transaction_timestamp()`).Scan(&live); err != nil || claimed != 100 || live != 100 {
		t.Fatalf("global lease cap claimed=%d live=%d err=%v", claimed, live, err)
	}
}

func TestConnectorAuthorizationPostgresClaimsFairlyAcrossScopes(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	firstIdentity := fixtureRequestIdentity(t)
	organizationID := "pid_72450000-0000-4000-8000-000000000000"
	workspaceID := "pid_72450001-0000-4000-8000-000000000001"
	environmentID := "pid_72450002-0000-4000-8000-000000000002"
	organization, _ := domain.ParseProductID(organizationID)
	workspace, _ := domain.ParseProductID(workspaceID)
	environment, _ := domain.ParseProductID(environmentID)
	secondScope, _ := domain.NewScope(organization, workspace, environment)
	secondIdentity := firstIdentity
	secondIdentity.Scope = secondScope
	digest := sha256.Sum256([]byte("scope-fairness"))
	for scopeIndex, identity := range []RequestIdentity{firstIdentity, secondIdentity} {
		integrationID := fmt.Sprintf("pid_72451%03d-0000-4000-8000-%012d", scopeIndex+1, scopeIndex+1)
		create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: fmt.Sprintf("scope-fair-create-%04d", scopeIndex), Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Scope Fair","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: fmt.Sprintf("pid_72452%03d-0000-4000-8000-%012d", scopeIndex+1, scopeIndex+1), CorrelationID: fmt.Sprintf("pid_72453%03d-0000-4000-8000-%012d", scopeIndex+1, scopeIndex+1), ReceiptID: fmt.Sprintf("pid_72454%03d-0000-4000-8000-%012d", scopeIndex+1, scopeIndex+1)}
		if _, err := repository.MutateWorkflow(ctx, identity, create); err != nil {
			t.Fatal(err)
		}
		for ordinal := 0; ordinal < 2; ordinal++ {
			effectID := fmt.Sprintf("pid_7245%d%03d-0000-4000-8000-%012d", scopeIndex+5, ordinal+1, (scopeIndex+1)*10+ordinal)
			provider := fmt.Sprintf("nango:s%d%d", scopeIndex, ordinal)
			age := 60 - scopeIndex*20 - ordinal
			if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'bind',$7,$8,'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-make_interval(secs=>$9))`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID, integrationID, provider, fmt.Sprintf("scope-fair-effect-%d-%d", scopeIndex, ordinal), digest[:], age); err != nil {
				t.Fatal(err)
			}
		}
	}
	leases, err := connectors.ClaimReconciliation(ctx, "scope-fair-worker", 30, 2)
	if err != nil || len(leases) != 2 {
		t.Fatalf("fair scope leases=%#v err=%v", leases, err)
	}
	seen := map[string]bool{}
	for _, lease := range leases {
		seen[lease.EnvironmentID] = true
	}
	if !seen[firstIdentity.Scope.EnvironmentID().String()] || !seen[environmentID] {
		t.Fatalf("oldest scope monopolized bounded claim: %#v", leases)
	}
}

func TestConnectorAuthorizationPostgresOneClaimNeverLeasesSameGlobalLaneAcrossScopes(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	repository, _ := NewPostgresRepository(database)
	connectors := &ConnectorRepository{database: database}
	first := fixtureRequestIdentity(t)
	second := first
	secondOrganization, _ := domain.ParseProductID("pid_72460001-0000-4000-8000-000000000001")
	secondWorkspace, _ := domain.ParseProductID("pid_72460002-0000-4000-8000-000000000002")
	secondEnvironment, _ := domain.ParseProductID("pid_72460003-0000-4000-8000-000000000003")
	second.Scope, _ = domain.NewScope(secondOrganization, secondWorkspace, secondEnvironment)
	digest := sha256.Sum256([]byte("global-lane-across-scopes"))
	for index, identity := range []RequestIdentity{first, second} {
		integrationID := fmt.Sprintf("pid_72460%03d-0000-4000-8000-%012d", index+1, index+1)
		create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: fmt.Sprintf("global-lane-create-%04d", index), Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Global Lane","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: fmt.Sprintf("pid_72461%03d-0000-4000-8000-%012d", index+1, index+1), CorrelationID: fmt.Sprintf("pid_72462%03d-0000-4000-8000-%012d", index+1, index+1), ReceiptID: fmt.Sprintf("pid_72463%03d-0000-4000-8000-%012d", index+1, index+1)}
		if _, err := repository.MutateWorkflow(ctx, identity, create); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,connection_reference,attempt,available_at,updated_at) VALUES($1,$2,$3,$4,$5,'github','revoke',$6,$7,'unknown','ref:github/installation/123456',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute')`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), fmt.Sprintf("pid_72464%03d-0000-4000-8000-%012d", index+1, index+1), integrationID, fmt.Sprintf("global-lane-effect-%04d", index), digest[:]); err != nil {
			t.Fatal(err)
		}
	}
	leases, err := connectors.ClaimReconciliation(ctx, "global-lane-worker", 30, 25)
	if err != nil || len(leases) != 1 || leases[0].Provider != "github" || leases[0].Operation != "revoke" {
		t.Fatalf("same global lane leases=%#v err=%v", leases, err)
	}
}

func TestConnectorAuthorizationPostgresReconciliationIndexesServeHundredThousandRowSkew(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	workflows, _ := NewPostgresRepository(database)
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72430001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "index-skew-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Index Skew","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72430002-0000-4000-8000-000000000002", CorrelationID: "pid_72430003-0000-4000-8000-000000000003", ReceiptID: "pid_72430004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at)
	 SELECT $1,$2,$3,'pid_'||substr(hash,1,8)||'-'||substr(hash,9,4)||'-4'||substr(hash,14,3)||'-8'||substr(hash,18,3)||'-'||substr(hash,21,12),$4,'github','bind','index-skew-'||lpad(ordinal::text,10,'0'),digest(ordinal::text,'sha256'),'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute'
	 FROM (SELECT ordinal,md5(ordinal::text) hash FROM generate_series(1,100000) ordinal) generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at)
	 SELECT $1,$2,$3,'pid_'||substr(hash,1,8)||'-'||substr(hash,9,4)||'-4'||substr(hash,14,3)||'-8'||substr(hash,18,3)||'-'||substr(hash,21,12),$4,'nango:lane'||lpad(ordinal::text,3,'0'),'bind','index-lane-'||lpad(ordinal::text,10,'0'),digest(('lane'||ordinal)::text,'sha256'),'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute'
	 FROM (SELECT ordinal,md5('lane'||ordinal::text) hash FROM generate_series(1,100) ordinal) generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `ANALYZE zasp_connector_effects`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SET enable_seqscan=off`); err != nil {
		t.Fatal(err)
	}
	defer connection.Exec(context.Background(), `RESET enable_seqscan`)
	var candidatePlan, activePlan []byte
	if err := connection.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON)
	 WITH candidates AS (
	   SELECT lane.provider,lane.operation,effect.organization_id,effect.workspace_id,effect.environment_id,effect.id,effect.updated_at
	   FROM zasp_connector_effect_lane_scopes lane CROSS JOIN LATERAL (
	     SELECT candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.id,candidate.updated_at
	     FROM zasp_connector_effects candidate
	     WHERE candidate.provider=lane.provider AND candidate.operation=lane.operation AND candidate.organization_id=lane.organization_id AND candidate.workspace_id=lane.workspace_id AND candidate.environment_id=lane.environment_id
	       AND candidate.status='unknown' AND candidate.attempt<100 AND candidate.available_at<=transaction_timestamp() AND candidate.updated_at<=transaction_timestamp()-interval '15 seconds'
	       AND (candidate.lease_expires_at IS NULL OR candidate.lease_expires_at<=transaction_timestamp())
	       AND NOT EXISTS(SELECT 1 FROM zasp_connector_effects live WHERE live.provider=candidate.provider AND live.operation=candidate.operation AND live.status='unknown' AND live.lease_expires_at>transaction_timestamp())
	       AND (candidate.operation<>'pkce_cleanup' OR candidate.oauth_attempt_id IS NULL OR NOT EXISTS(SELECT 1 FROM zasp_connector_oauth_attempts attempt WHERE (attempt.organization_id,attempt.workspace_id,attempt.environment_id,attempt.id)=(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.oauth_attempt_id) AND attempt.status='consuming'))
	     ORDER BY candidate.updated_at,candidate.id LIMIT 1
	   ) effect
	 ), lane_fair AS (
	   SELECT candidates.*,row_number() OVER(PARTITION BY provider,operation ORDER BY updated_at,id) lane_rank FROM candidates
	 ), fair AS (
	   SELECT lane_fair.*,row_number() OVER(PARTITION BY organization_id,workspace_id,environment_id ORDER BY updated_at,id) organization_rank FROM lane_fair WHERE lane_rank=1
	 )
	 SELECT effect.id FROM zasp_connector_effects effect JOIN fair ON (fair.organization_id,fair.workspace_id,fair.environment_id,fair.id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.id)
	 ORDER BY fair.organization_rank,effect.updated_at,effect.id LIMIT 25`).Scan(&candidatePlan); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `EXPLAIN (FORMAT JSON) SELECT 1 FROM zasp_connector_effects WHERE provider='github' AND operation='bind' AND status='unknown' AND lease_expires_at>transaction_timestamp() LIMIT 1`).Scan(&activePlan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(candidatePlan), "zasp_connector_effect_candidate_lane_idx") || !strings.Contains(string(activePlan), "zasp_connector_effect_active_lane_idx") {
		t.Fatalf("reconciliation plans candidate=%s active=%s", candidatePlan, activePlan)
	}
	var decodedPlan any
	if json.Unmarshal(candidatePlan, &decodedPlan) != nil || maxJSONPlanMetric(decodedPlan, "Actual Rows") > 256 || maxJSONPlanMetric(decodedPlan, "Shared Read Blocks") > 2048 || maxJSONPlanMetric(decodedPlan, "Temp Written Blocks") != 0 || strings.Contains(string(candidatePlan), `"Sort Method": "external`) {
		t.Fatalf("unbounded reconciliation candidate plan=%s", candidatePlan)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET status='failed',last_error_code='provider_access_denied',resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE status='unknown'`); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_connector_effects(organization_id,workspace_id,environment_id,id,integration_id,provider,operation,idempotency_key,request_digest,status,attempt,available_at,updated_at)
	 SELECT $1,$2,$3,'pid_'||substr(hash,1,8)||'-'||substr(hash,9,4)||'-4'||substr(hash,14,3)||'-8'||substr(hash,18,3)||'-'||substr(hash,21,12),$4,'nango:history'||lpad(ordinal::text,6,'0'),'bind','history-lane-'||lpad(ordinal::text,10,'0'),digest(('history'||ordinal)::text,'sha256'),'unknown',0,transaction_timestamp()-interval '1 minute',transaction_timestamp()-interval '1 minute'
	 FROM (SELECT ordinal,md5('history'||ordinal::text) hash FROM generate_series(1,100000) ordinal) generated`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE zasp_connector_effects SET status='failed',last_error_code='provider_access_denied',resolved_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE idempotency_key LIKE 'history-lane-%'`); err != nil {
		t.Fatal(err)
	}
	var activeLanes int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_effect_lane_scopes`).Scan(&activeLanes); err != nil || activeLanes != 0 {
		t.Fatalf("historical lane registry=%d err=%v", activeLanes, err)
	}
	var emptyPlan []byte
	if err := connection.QueryRow(ctx, `EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT provider,operation,organization_id,workspace_id,environment_id FROM zasp_connector_effect_lane_scopes ORDER BY provider,operation,organization_id,workspace_id,environment_id LIMIT 25`).Scan(&emptyPlan); err != nil {
		t.Fatal(err)
	}
	decodedPlan = nil
	if json.Unmarshal(emptyPlan, &decodedPlan) != nil || maxJSONPlanMetric(decodedPlan, "Actual Rows") != 0 || maxJSONPlanMetric(decodedPlan, "Shared Read Blocks") > 2048 || maxJSONPlanMetric(decodedPlan, "Temp Written Blocks") != 0 {
		t.Fatalf("historical empty queue plan=%s", emptyPlan)
	}
}

func maxJSONPlanMetric(value any, key string) float64 {
	maximum := float64(0)
	switch typed := value.(type) {
	case map[string]any:
		for candidate, child := range typed {
			if candidate == key {
				if number, ok := child.(float64); ok && number > maximum {
					maximum = number
				}
			}
			if nested := maxJSONPlanMetric(child, key); nested > maximum {
				maximum = nested
			}
		}
	case []any:
		for _, child := range typed {
			if nested := maxJSONPlanMetric(child, key); nested > maximum {
				maximum = nested
			}
		}
	}
	return maximum
}

func TestConnectorAuthorizationPostgresCompletionRejectsChangedStoredIntentAtomically(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	workflows, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	connectors := &ConnectorRepository{database: database}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72500001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "intent-lock-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Intent Lock","configuration":{"organization":"first"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72500002-0000-4000-8000-000000000002", CorrelationID: "pid_72500003-0000-4000-8000-000000000003", ReceiptID: "pid_72500004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("intent-lock"))
	attemptID := "pid_72500005-0000-4000-8000-000000000005"
	start := OAuthStart{AttemptID: attemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/intent-lock", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), IntegrationVersion: 1, Configuration: json.RawMessage(`{"organization":"first"}`)}
	if _, err := connectors.StartOAuth(ctx, identity, start); err != nil {
		t.Fatal(err)
	}
	update := WorkflowMutation{Action: "update", Kind: "integration", ID: integrationID, Operation: "updateIntegration", IdempotencyKey: "intent-lock-update-0001", ExpectedVersion: 1, Intent: json.RawMessage(`{"body":{"organization":"changed"},"expected_version":1,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Intent Lock","configuration":{"organization":"changed"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z"}`), AuditID: "pid_72500006-0000-4000-8000-000000000006", CorrelationID: "pid_72500007-0000-4000-8000-000000000007", ReceiptID: "pid_72500008-0000-4000-8000-000000000008"}
	if _, err := workflows.MutateWorkflow(ctx, identity, update); err != nil {
		t.Fatal(err)
	}
	consumption, err := connectors.ConsumeOAuth(ctx, identity, digest[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	effectID := consumption.EffectID
	completion := OAuthCompletion{AttemptID: attemptID, EffectID: effectID, ConnectionID: "pid_72500010-0000-4000-8000-000000000010", ConnectionReference: "ref:github/grant/intent-lock", ProviderSubject: "installation:1", CredentialID: "pid_72500011-0000-4000-8000-000000000011", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":1}`)}
	if _, err := connectors.CompleteOAuth(ctx, identity.Scope, completion); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("completion after intent change = %v, want conflict", err)
	}
	var attempts, connections, credentials int
	if err := connection.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4 AND status='consuming'),
		(SELECT count(*) FROM zasp_integration_connections WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$5),
		(SELECT count(*) FROM zasp_connector_credentials WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$5)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), attemptID, integrationID).Scan(&attempts, &connections, &credentials); err != nil || attempts != 1 || connections != 0 || credentials != 0 {
		t.Fatalf("intent conflict residue attempts=%d connections=%d credentials=%d err=%v", attempts, connections, credentials, err)
	}
}

func TestConnectorAuthorizationPostgresDeleteAndStartSerializeOnWorkflowLock(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	second, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(ctx)
	database, _ := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: second})
	workflows, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	integrationID := "pid_72600001-0000-4000-8000-000000000001"
	create := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "serialize-create-0001", Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"Serialized","configuration":{},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`), AuditID: "pid_72600002-0000-4000-8000-000000000002", CorrelationID: "pid_72600003-0000-4000-8000-000000000003", ReceiptID: "pid_72600004-0000-4000-8000-000000000004"}
	if _, err := workflows.MutateWorkflow(ctx, identity, create); err != nil {
		t.Fatal(err)
	}
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback(ctx)
	if _, err := transaction.Exec(ctx, `SELECT 1 FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND kind='integration' AND id=$4 FOR UPDATE`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID); err != nil {
		t.Fatal(err)
	}
	deletion := WorkflowMutation{Action: "delete", Kind: "integration", ID: integrationID, Operation: "deleteIntegration", IdempotencyKey: "serialize-delete-0001", ExpectedVersion: 1, Intent: json.RawMessage(`{"body":{},"expected_version":1,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_72600005-0000-4000-8000-000000000005", CorrelationID: "pid_72600006-0000-4000-8000-000000000006", ReceiptID: "pid_72600007-0000-4000-8000-000000000007"}
	deleteDone := make(chan error, 1)
	go func() { _, deleteErr := workflows.MutateWorkflow(ctx, identity, deletion); deleteDone <- deleteErr }()
	select {
	case err := <-deleteDone:
		t.Fatalf("delete did not wait for workflow lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	digest := sha256.Sum256([]byte("serialized-start"))
	var started []byte
	serializedAttemptID := "pid_72600008-0000-4000-8000-000000000008"
	if err := transaction.QueryRow(ctx, postgresConnectorStartOAuthSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), serializedAttemptID, integrationID, "github", identity.PrincipalID.String(), digest[:], digest[:], "ref:oauth/pkce/serialized-start", digest[:], `["read:org"]`, time.Now().UTC().Add(5*time.Minute), int64(1), `{}`, connectorDeterministicID(identity.Scope, serializedAttemptID, "pkce-cleanup"), connectorDeterministicID(identity.Scope, serializedAttemptID, "oauth-effect")).Scan(&started); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("delete after concurrent start = %v, want conflict", err)
	}
	var activeAttempts int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_connector_oauth_attempts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND integration_id=$4 AND status='pending'`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&activeAttempts); err != nil || activeAttempts != 1 {
		t.Fatalf("serialized active attempts=%d err=%v", activeAttempts, err)
	}
}

func TestConnectorAuthorizationPostgresLegacyWebhookReferenceBridgeRejectsInlineSecretsAtomically(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: connection})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	validID := "pid_73000001-0000-4000-8000-000000000001"
	validConfig := `{"destination_url":"https://example.test/hooks","signing_secret_reference":"secret_ref_combined_e2e"}`
	valid := connectorWebhookMutation(validID, "webhook-reference-create-0001", validConfig, 1)
	if result, err := repository.MutateWorkflow(ctx, identity, valid); err != nil || result.Version != 1 {
		t.Fatalf("legacy webhook reference bridge = %#v, %v", result, err)
	}
	var storedConfigurationMatches bool
	if err := connection.QueryRow(ctx, `SELECT configuration=$5::jsonb FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), validID, validConfig).Scan(&storedConfigurationMatches); err != nil || !storedConfigurationMatches {
		t.Fatalf("typed webhook configuration matches = %t, %v", storedConfigurationMatches, err)
	}

	hostile := []string{
		`{"destination_url":"https://example.test/hooks","signing_secret":"inline-value"}`,
		`{"destination_url":"https://example.test/hooks","signing_secret_reference":"inline-value"}`,
		`{"destination_url":"https://example.test/hooks","signing_secret_reference":{"value":"secret_ref_nested"}}`,
		`{"destination_url":"https://example.test/hooks","nested":{"signing_secret_reference":"secret_ref_nested"}}`,
		`{"destination_url":"https://example.test/hooks","password_reference":"secret_ref_password"}`,
		`{"destination_url":"https://example.test/hooks","signing_secret_reference":"secret_ref_valid","token":"inline-value"}`,
		`{"destination_url":"https://example.test/hooks","signing_secret_reference":"secret_ref_value?query=inline"}`,
	}
	for index, configuration := range hostile {
		id := fmt.Sprintf("pid_730000%02x-0000-4000-8000-0000000000%02x", index+2, index+2)
		mutation := connectorWebhookMutation(id, fmt.Sprintf("webhook-hostile-create-%04d", index+1), configuration, index+2)
		if _, err := repository.MutateWorkflow(ctx, identity, mutation); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("hostile webhook configuration %s = %v, want operation rejection", configuration, err)
		}
		var records, typed, idempotency, audits, receipts int
		if err := connection.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM zasp_workflow_records WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4),
			(SELECT count(*) FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4),
			(SELECT count(*) FROM zasp_workflow_idempotency WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND idempotency_key=$5),
			(SELECT count(*) FROM zasp_workflow_audit WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND resource_id=$4),
			(SELECT count(*) FROM zasp_workflow_receipts WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND resource_id=$4)`,
			identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), id, mutation.IdempotencyKey).Scan(&records, &typed, &idempotency, &audits, &receipts); err != nil || records != 0 || typed != 0 || idempotency != 0 || audits != 0 || receipts != 0 {
			t.Fatalf("hostile webhook residue = records:%d typed:%d idempotency:%d audits:%d receipts:%d err:%v", records, typed, idempotency, audits, receipts, err)
		}
	}
}

func TestConnectorAuthorizationPostgresWorkerHasOnlyLeasedTransitionAuthority(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(ctx)
	migrateToConnectorAuthorization(t, ctx, connection)
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_worker`); err != nil {
		t.Fatal(err)
	}
	var claim, leasedCompletion, unleasedResolution, unleasedCompletion bool
	if err := connection.QueryRow(ctx, `SELECT
		has_function_privilege(current_user,'zasp_connector_claim_reconciliation(text,integer,integer)','EXECUTE'),
		has_function_privilege(current_user,'zasp_connector_complete_reconciliation(text,text,text,text,text,text,text,text,text,text,text,text,jsonb,bytea)','EXECUTE'),
		has_function_privilege(current_user,'zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text)','EXECUTE'),
		has_function_privilege(current_user,'zasp_connector_complete_oauth(text,text,text,text,text,text,text,text,text,text,jsonb,bytea)','EXECUTE')`).Scan(&claim, &leasedCompletion, &unleasedResolution, &unleasedCompletion); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if !claim || !leasedCompletion || unleasedResolution || unleasedCompletion {
		t.Fatalf("worker authority claim=%t leased=%t resolve=%t complete=%t", claim, leasedCompletion, unleasedResolution, unleasedCompletion)
	}
	if _, err := connection.Exec(ctx, `SET ROLE zasp_discovery_api`); err != nil {
		t.Fatal(err)
	}
	var unusedBegin, unusedPut bool
	if err := connection.QueryRow(ctx, `SELECT
		has_function_privilege(current_user,'zasp_connector_begin_effect(text,text,text,text,text,text,text,text,text,bytea)','EXECUTE'),
		has_function_privilege(current_user,'zasp_connector_put_credential(text,text,text,text,text,text,text,text,bigint,jsonb)','EXECUTE')`).Scan(&unusedBegin, &unusedPut); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if unusedBegin || unusedPut {
		t.Fatalf("API retained unused direct authority begin=%t put=%t", unusedBegin, unusedPut)
	}
	var ready bool
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_security_ready()`).Scan(&ready); err != nil || !ready {
		var apiACLs, workerACLs []string
		aclErr := connection.QueryRow(ctx, `SELECT
			array_agg(DISTINCT p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' ORDER BY p.proname||'('||pg_get_function_identity_arguments(p.oid)||')') FILTER (WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')),
			array_agg(DISTINCT p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' ORDER BY p.proname||'('||pg_get_function_identity_arguments(p.oid)||')') FILTER (WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_worker'))
			FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='public' AND p.proname LIKE 'zasp_connector_%' AND a.privilege_type='EXECUTE'`).Scan(&apiACLs, &workerACLs)
		t.Fatalf("baseline connector security ready=%t err=%v acl_err=%v api=%q worker=%q", ready, err, aclErr, apiACLs, workerACLs)
	}
	if _, err := connection.Exec(ctx, `GRANT EXECUTE ON FUNCTION zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text) TO zasp_discovery_worker`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("worker privilege drift ready=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `REVOKE EXECUTE ON FUNCTION zasp_connector_resolve_effect(text,text,text,text,text,text,jsonb,text) FROM zasp_discovery_worker`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_security_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("restored connector security ready=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_connector_effects DISABLE TRIGGER zasp_connector_effect_lanes_update`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_security_ready()`).Scan(&ready); err != nil || ready {
		t.Fatalf("disabled lane trigger ready=%t err=%v", ready, err)
	}
	if _, err := connection.Exec(ctx, migrations.ConnectorAuthorization().DownSQL()); err == nil {
		t.Fatal("trigger drift did not block guarded connector down")
	}
	if _, err := connection.Exec(ctx, `ALTER TABLE zasp_connector_effects ENABLE TRIGGER zasp_connector_effect_lanes_update`); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_security_ready()`).Scan(&ready); err != nil || !ready {
		t.Fatalf("restored lane trigger ready=%t err=%v", ready, err)
	}
}

func connectorWebhookMutation(id, idempotencyKey, configuration string, ordinal int) WorkflowMutation {
	return WorkflowMutation{
		Action: "create", Kind: "integration", ID: id, Operation: "createIntegration", IdempotencyKey: idempotencyKey, ExpectedVersion: 0,
		Intent:  json.RawMessage(`{"body":{"connector_key":"generic-webhook"},"expected_version":0,"resource_id":""}`),
		Body:    json.RawMessage(`{"id":"` + id + `","connector_key":"generic-webhook","name":"Webhook","configuration":` + configuration + `,"status":"authorized","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`),
		AuditID: fmt.Sprintf("pid_731000%02x-0000-4000-8000-0000000000%02x", ordinal, ordinal), CorrelationID: fmt.Sprintf("pid_732000%02x-0000-4000-8000-0000000000%02x", ordinal, ordinal), ReceiptID: fmt.Sprintf("pid_733000%02x-0000-4000-8000-0000000000%02x", ordinal, ordinal),
	}
}
