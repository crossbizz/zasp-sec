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
	attemptID := "pid_70000002-0000-4000-8000-000000000002"
	principalID := identity.PrincipalID.String()
	sessionDigest := sha256.Sum256([]byte("session"))
	stateDigest := sha256.Sum256([]byte("state"))
	requestDigest := sha256.Sum256([]byte("request"))
	args := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), attemptID, integrationID, "github", principalID, sessionDigest[:], stateDigest[:], "ref:oauth/pkce/attempt-0001", requestDigest[:], json.RawMessage(`["read:org"]`), time.Now().UTC().Add(10 * time.Minute)}
	var started, replayed []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, args...).Scan(&started); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, args...).Scan(&replayed); err != nil || string(replayed) != string(started) {
		t.Fatalf("exact start replay = %s, %v; first=%s", replayed, err, started)
	}
	conflictArgs := append([]any(nil), args...)
	conflicting := sha256.Sum256([]byte("conflict"))
	conflictArgs[10] = conflicting[:]
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13)`, conflictArgs...).Scan(&replayed); err == nil {
		t.Fatal("same OAuth attempt with changed digest succeeded")
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

	effectID := "pid_70000003-0000-4000-8000-000000000003"
	effectDigest := sha256.Sum256([]byte("provider exchange"))
	var effect []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_begin_effect($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), effectID, integrationID, attemptID, "github", "authorize", "oauth-effect-key-0001", effectDigest[:]).Scan(&effect); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_connector_resolve_effect($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), effectID, "unknown", "", json.RawMessage(`{}`), "provider_timeout").Scan(&effect); err != nil {
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
	integrationID := "pid_71000001-0000-4000-8000-000000000001"
	body := json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub","configuration":{"authorization_mode":"github_app"},"status":"pending_authorization","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`)
	mutation := WorkflowMutation{Action: "create", Kind: "integration", ID: integrationID, Operation: "createIntegration", IdempotencyKey: "idem-public-connector-0001", ExpectedVersion: 0, Intent: json.RawMessage(`{"body":{"connector_key":"github"},"expected_version":0,"resource_id":""}`), Body: body, AuditID: "pid_71000002-0000-4000-8000-000000000002", CorrelationID: "pid_71000003-0000-4000-8000-000000000003", ReceiptID: "pid_71000004-0000-4000-8000-000000000004"}
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
	update := WorkflowMutation{Action: "update", Kind: "integration", ID: integrationID, Operation: "updateIntegration", IdempotencyKey: "idem-public-connector-update-0001", ExpectedVersion: 1, Intent: json.RawMessage(`{"body":{"name":"GitHub Org"},"expected_version":1,"resource_id":"` + integrationID + `"}`), Body: updatedBody, AuditID: "pid_71000012-0000-4000-8000-000000000012", CorrelationID: "pid_71000013-0000-4000-8000-000000000013", ReceiptID: "pid_71000014-0000-4000-8000-000000000014"}
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
	_, err = connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: attemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/public-bridge", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: now.Add(5 * time.Minute)})
	if err != nil {
		t.Fatalf("start OAuth after public mutation: %v", err)
	}
	if _, err := connectorRepository.ConsumeOAuth(ctx, identity, digest[:], digest[:]); err != nil {
		t.Fatalf("consume public OAuth: %v", err)
	}
	effectID := "pid_71000006-0000-4000-8000-000000000006"
	if _, err := connectorRepository.BeginConnectorEffect(ctx, identity.Scope, ConnectorEffectStart{ID: effectID, IntegrationID: integrationID, OAuthAttemptID: attemptID, Provider: "github", Operation: "authorize", IdempotencyKey: "idem-provider-denial-0001", RequestDigest: digest[:]}); err != nil {
		t.Fatalf("begin denial effect: %v", err)
	}
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
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: successAttemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/public-success", SessionDigest: successDigest[:], StateDigest: successDigest[:], RequestDigest: successDigest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: now.Add(5 * time.Minute)}); err != nil {
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
	if _, err := connectorRepository.ConsumeOAuth(ctx, identity, successDigest[:], successDigest[:]); err != nil {
		t.Fatalf("consume success OAuth: %v", err)
	}
	successEffectID := "pid_71000008-0000-4000-8000-000000000008"
	if _, err := connectorRepository.BeginConnectorEffect(ctx, identity.Scope, ConnectorEffectStart{ID: successEffectID, IntegrationID: integrationID, OAuthAttemptID: successAttemptID, Provider: "github", Operation: "authorize", IdempotencyKey: "idem-provider-success-0001", RequestDigest: successDigest[:]}); err != nil {
		t.Fatalf("begin success effect: %v", err)
	}
	if _, err := connectorRepository.ResolveConnectorEffect(ctx, identity.Scope, ConnectorEffectResolution{ID: successEffectID, Status: "unknown", ErrorCode: "provider_effect_started", Metadata: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("mark success effect unknown: %v", err)
	}
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
	if transition, err := connectorRepository.CompleteConnectorCleanup(ctx, identity.Scope, successEffectID); err != nil || transition.Status != "reconciled" {
		t.Fatalf("complete connector cleanup = %#v, %v", transition, err)
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
	if err != nil || json.Unmarshal(active.Body, &activeBody) != nil || active.Version != 3 || activeBody["status"] != "active" {
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
	migrateToConnectorAuthorization(t, ctx, connection)
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
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: attemptID, IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/quarantine", SessionDigest: digest[:], StateDigest: digest[:], RequestDigest: digest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := connectorRepository.ConsumeOAuth(ctx, identity, digest[:], digest[:]); err != nil {
		t.Fatal(err)
	}
	effectID := "pid_72000006-0000-4000-8000-000000000006"
	if _, err := connectorRepository.BeginConnectorEffect(ctx, identity.Scope, ConnectorEffectStart{ID: effectID, IntegrationID: integrationID, OAuthAttemptID: attemptID, Provider: "github", Operation: "authorize", IdempotencyKey: "oauth-quarantine-effect", RequestDigest: digest[:]}); err != nil {
		t.Fatal(err)
	}
	if _, err := connectorRepository.ResolveConnectorEffect(ctx, identity.Scope, ConnectorEffectResolution{ID: effectID, Status: "unknown", ErrorCode: "provider_effect_started", Metadata: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
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
	var effectStatus, errorCode, integrationState, attemptStatus string
	var auditCount int
	if err := connection.QueryRow(ctx, `SELECT e.status,e.last_error_code,i.state,a.status,(SELECT count(*) FROM zasp_connector_audit audit WHERE audit.organization_id=e.organization_id AND audit.workspace_id=e.workspace_id AND audit.environment_id=e.environment_id AND audit.effect_id=e.id AND audit.reason_code='provider_outcome_ambiguous') FROM zasp_connector_effects e JOIN zasp_integrations i ON (i.organization_id,i.workspace_id,i.environment_id,i.id)=(e.organization_id,e.workspace_id,e.environment_id,e.integration_id) JOIN zasp_connector_oauth_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.id)=(e.organization_id,e.workspace_id,e.environment_id,e.oauth_attempt_id) WHERE (e.organization_id,e.workspace_id,e.environment_id,e.id)=($1,$2,$3,$4)`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), effectID).Scan(&effectStatus, &errorCode, &integrationState, &attemptStatus, &auditCount); err != nil || effectStatus != "unknown" || errorCode != "provider_outcome_ambiguous" || integrationState != "degraded" || attemptStatus != "consuming" || auditCount != 1 {
		t.Fatalf("durable quarantine = %q/%q integration=%q attempt=%q audit=%d err=%v", effectStatus, errorCode, integrationState, attemptStatus, auditCount, err)
	}
	second := sha256.Sum256([]byte("second-attempt"))
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: "pid_72000007-0000-4000-8000-000000000007", IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/blocked", SessionDigest: second[:], StateDigest: second[:], RequestDigest: second[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("fresh authorization while quarantined = %v, want conflict", err)
	}
	workflow, err := workflowRepository.GetWorkflow(ctx, identity.Scope, "integration", integrationID)
	var quarantinedBody map[string]any
	if err != nil || json.Unmarshal(workflow.Body, &quarantinedBody) != nil || workflow.Version != 2 || quarantinedBody["status"] != "degraded" {
		t.Fatalf("operator-visible quarantined workflow = %#v body=%v, %v", workflow, quarantinedBody, err)
	}
	quarantinedBody["status"] = "pending_authorization"
	quarantinedBody["updated_at"] = "2026-08-19T00:02:00Z"
	remediationBody, _ := json.Marshal(quarantinedBody)
	remediation := ConnectorQuarantineRemediation{EffectID: effectID, IntegrationID: integrationID, Acknowledgement: "provider_grant_revoked_manually", IdempotencyKey: "idem-quarantine-remediation-0001", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{"acknowledgement":"provider_grant_revoked_manually","effect_id":"` + effectID + `"},"expected_version":2,"resource_id":"` + integrationID + `"}`), Body: remediationBody, AuditID: "pid_72000008-0000-4000-8000-000000000008", CorrelationID: "pid_72000009-0000-4000-8000-000000000009", ReceiptID: "pid_72000010-0000-4000-8000-000000000010"}
	remediated, err := connectorRepository.RemediateConnectorQuarantine(ctx, identity, remediation)
	var remediatedBody map[string]any
	if err != nil || json.Unmarshal(remediated.Body, &remediatedBody) != nil || remediatedBody["status"] != "pending_authorization" || remediated.Version != 3 || remediated.ReceiptID != remediation.ReceiptID {
		t.Fatalf("explicit quarantine remediation = %#v, %v", remediated, err)
	}
	if replay, err := connectorRepository.RemediateConnectorQuarantine(ctx, identity, remediation); err != nil || !replay.Replayed || replay.Version != remediated.Version || replay.ReceiptID != remediated.ReceiptID {
		t.Fatalf("quarantine remediation replay = %#v, %v; first=%#v", replay, err, remediated)
	}
	remediation.Acknowledgement = "provider_grant_verified_absent"
	if _, err := connectorRepository.RemediateConnectorQuarantine(ctx, identity, remediation); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("changed quarantine remediation = %v, want conflict", err)
	}
	if _, err := connectorRepository.StartOAuth(ctx, identity, OAuthStart{AttemptID: "pid_72000007-0000-4000-8000-000000000007", IntegrationID: integrationID, Provider: "github", PKCEVerifierReference: "ref:oauth/pkce/blocked", SessionDigest: second[:], StateDigest: second[:], RequestDigest: second[:], RequestedScopes: []string{"read:org"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}); err != nil {
		t.Fatalf("fresh authorization after explicit remediation = %v", err)
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

func connectorWebhookMutation(id, idempotencyKey, configuration string, ordinal int) WorkflowMutation {
	return WorkflowMutation{
		Action: "create", Kind: "integration", ID: id, Operation: "createIntegration", IdempotencyKey: idempotencyKey, ExpectedVersion: 0,
		Intent:  json.RawMessage(`{"body":{"connector_key":"generic-webhook"},"expected_version":0,"resource_id":""}`),
		Body:    json.RawMessage(`{"id":"` + id + `","connector_key":"generic-webhook","name":"Webhook","configuration":` + configuration + `,"status":"authorized","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}`),
		AuditID: fmt.Sprintf("pid_731000%02x-0000-4000-8000-0000000000%02x", ordinal, ordinal), CorrelationID: fmt.Sprintf("pid_732000%02x-0000-4000-8000-0000000000%02x", ordinal, ordinal), ReceiptID: fmt.Sprintf("pid_733000%02x-0000-4000-8000-0000000000%02x", ordinal, ordinal),
	}
}
