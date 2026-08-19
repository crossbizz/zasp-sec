package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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
