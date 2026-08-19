package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
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
	if _, err := connectorRepository.ConsumeOAuth(ctx, identity, successDigest[:], successDigest[:]); err != nil {
		t.Fatalf("consume success OAuth: %v", err)
	}
	successEffectID := "pid_71000008-0000-4000-8000-000000000008"
	if _, err := connectorRepository.BeginConnectorEffect(ctx, identity.Scope, ConnectorEffectStart{ID: successEffectID, IntegrationID: integrationID, OAuthAttemptID: successAttemptID, Provider: "github", Operation: "authorize", IdempotencyKey: "idem-provider-success-0001", RequestDigest: successDigest[:]}); err != nil {
		t.Fatalf("begin success effect: %v", err)
	}
	completion := OAuthCompletion{AttemptID: successAttemptID, EffectID: successEffectID, ConnectionID: "pid_71000009-0000-4000-8000-000000000009", ConnectionReference: "ref:github/install/987654", ProviderSubject: "installation:987654", CredentialID: "pid_71000010-0000-4000-8000-000000000010", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":987654}`)}
	firstCompletion, err := connectorRepository.CompleteOAuth(ctx, identity.Scope, completion)
	if err != nil {
		t.Fatalf("complete OAuth: %v", err)
	}
	replayedCompletion, err := connectorRepository.CompleteOAuth(ctx, identity.Scope, completion)
	if err != nil || replayedCompletion != firstCompletion {
		t.Fatalf("completion replay = %#v, %v; first=%#v", replayedCompletion, err, firstCompletion)
	}
	completion.ConnectionReference = "ref:github/install/changed"
	if _, err := connectorRepository.CompleteOAuth(ctx, identity.Scope, completion); !errors.Is(err, ErrRepositoryConflict) {
		t.Fatalf("changed completion replay = %v, want conflict", err)
	}
	deletion := WorkflowMutation{Action: "delete", Kind: "integration", ID: integrationID, Operation: "deleteIntegration", IdempotencyKey: "idem-public-connector-delete-0001", ExpectedVersion: 2, Intent: json.RawMessage(`{"body":{},"expected_version":2,"resource_id":"` + integrationID + `"}`), Body: json.RawMessage(`{}`), AuditID: "pid_71000022-0000-4000-8000-000000000022", CorrelationID: "pid_71000023-0000-4000-8000-000000000023", ReceiptID: "pid_71000024-0000-4000-8000-000000000024"}
	if _, err := repository.MutateWorkflow(ctx, identity, deletion); err != nil {
		t.Fatalf("public integration delete: %v", err)
	}
	if replay, err := repository.MutateWorkflow(ctx, identity, deletion); err != nil || !replay.Replayed {
		t.Fatalf("public integration delete replay = %#v, %v", replay, err)
	}
	var typedState string
	if err := connection.QueryRow(ctx, `SELECT state FROM zasp_integrations WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND id=$4`, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), integrationID).Scan(&typedState); err != nil || typedState != "deleted" {
		t.Fatalf("typed integration delete = %q, %v", typedState, err)
	}
}
