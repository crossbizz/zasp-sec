package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

type connectorCallDatabase struct {
	query     string
	args      []any
	responses map[string]json.RawMessage
}

func (*connectorCallDatabase) SchemaVersion(context.Context) (string, error) {
	return ConnectorSchemaVersion, nil
}
func (*connectorCallDatabase) Exec(context.Context, string, ...any) error { return nil }
func (database *connectorCallDatabase) QueryJSON(_ context.Context, query string, arguments ...any) (json.RawMessage, error) {
	database.query, database.args = query, append([]any(nil), arguments...)
	response, ok := database.responses[query]
	if !ok {
		return nil, errors.New("missing response")
	}
	return response, nil
}

func TestConnectorRepositoryStartsAndConsumesBoundOAuthWithoutSecretBytes(t *testing.T) {
	now := time.Now().UTC()
	database := &connectorCallDatabase{responses: map[string]json.RawMessage{
		postgresConnectorReadySQL:          json.RawMessage(`true`),
		postgresDiscoveryPrincipalReadySQL: json.RawMessage(`true`),
		postgresConnectorStartOAuthSQL:     json.RawMessage(`{"id":"pid_70000002-0000-4000-8000-000000000002","integration_id":"pid_70000001-0000-4000-8000-000000000001","provider":"github","status":"pending","expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339Nano) + `","created_at":"` + now.Format(time.RFC3339Nano) + `"}`),
	}}
	repository, err := NewConnectorRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	sessionDigest := sha256.Sum256([]byte("session"))
	stateDigest := sha256.Sum256([]byte("state"))
	requestDigest := sha256.Sum256([]byte("request"))
	input := OAuthStart{
		AttemptID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001",
		Provider: "github", SessionDigest: sessionDigest[:], StateDigest: stateDigest[:], PKCEVerifierReference: "ref:oauth/pkce/attempt-0001",
		RequestDigest: requestDigest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: now.Add(10 * time.Minute),
	}
	started, err := repository.StartOAuth(context.Background(), identity, input)
	if err != nil || started.ID != input.AttemptID || started.Provider != "github" || started.CreatedAt.Location() != time.UTC {
		t.Fatalf("start OAuth = %#v, %v", started, err)
	}
	wantArgs := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), input.AttemptID, input.IntegrationID, input.Provider, identity.PrincipalID.String(), input.SessionDigest, input.StateDigest, input.PKCEVerifierReference, input.RequestDigest, `["read:org"]`, input.ExpiresAt}
	if database.query != postgresConnectorStartOAuthSQL || !reflect.DeepEqual(database.args, wantArgs) {
		t.Fatalf("start query/args = %q/%#v", database.query, database.args)
	}

	database.responses[postgresConnectorStartOAuthSQL] = json.RawMessage(`{"id":"pid_70000002-0000-4000-8000-000000000002","integration_id":"pid_70000001-0000-4000-8000-000000000001","provider":"github","status":"pending","expires_at":"` + now.Add(10*time.Minute).Format(time.RFC3339Nano) + `","created_at":"` + now.Format(time.RFC3339Nano) + `","access_token":"leak"}`)
	if _, err := repository.StartOAuth(context.Background(), identity, input); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unknown secret-bearing response error = %v", err)
	}
	for _, mutation := range []OAuthStart{
		{AttemptID: input.AttemptID, IntegrationID: input.IntegrationID, Provider: "github", SessionDigest: sessionDigest[:], StateDigest: stateDigest[:], PKCEVerifierReference: "plaintext-verifier", RequestDigest: requestDigest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: input.ExpiresAt},
		{AttemptID: input.AttemptID, IntegrationID: input.IntegrationID, Provider: "nango:github", SessionDigest: sessionDigest[:], StateDigest: stateDigest[:], PKCEVerifierReference: input.PKCEVerifierReference, RequestDigest: requestDigest[:], RequestedScopes: []string{"read:org"}, ExpiresAt: input.ExpiresAt},
		{AttemptID: input.AttemptID, IntegrationID: input.IntegrationID, Provider: "github", SessionDigest: sessionDigest[:], StateDigest: stateDigest[:], PKCEVerifierReference: input.PKCEVerifierReference, RequestDigest: requestDigest[:], RequestedScopes: []string{"repo", "repo"}, ExpiresAt: input.ExpiresAt},
	} {
		if _, err := repository.StartOAuth(context.Background(), identity, mutation); !errors.Is(err, ErrRepositoryOperation) {
			t.Fatalf("hostile OAuth start %#v error = %v", mutation, err)
		}
	}
}

func TestConnectorRepositoryReadinessRechecksLiveSemanticAndPrincipalAuthority(t *testing.T) {
	database := &connectorCallDatabase{responses: map[string]json.RawMessage{postgresConnectorReadySQL: json.RawMessage(`true`), postgresDiscoveryPrincipalReadySQL: json.RawMessage(`true`)}}
	repository, err := NewConnectorRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Ready(context.Background()); err != nil {
		t.Fatalf("ready connector repository: %v", err)
	}
	database.responses[postgresConnectorReadySQL] = json.RawMessage(`false`)
	if err := repository.Ready(context.Background()); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("live connector drift readiness = %v", err)
	}
}

func TestConnectorRepositoryStrictlyDecodesUnknownEffectClaims(t *testing.T) {
	now := time.Now().UTC()
	database := &connectorCallDatabase{responses: map[string]json.RawMessage{
		postgresConnectorReadySQL:               json.RawMessage(`true`),
		postgresDiscoveryPrincipalReadySQL:      json.RawMessage(`true`),
		postgresConnectorClaimReconciliationSQL: json.RawMessage(`{"items":[{"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","id":"pid_70000003-0000-4000-8000-000000000003","integration_id":"pid_70000001-0000-4000-8000-000000000001","provider":"github","operation":"authorize","idempotency_key":"oauth-effect-key-0001","request_digest":"` + string(make([]byte, 64)) + `","attempt":1,"lease_owner":"worker-a","lease_token":"` + string(make([]byte, 64)) + `","lease_expires_at":"` + now.Add(time.Minute).Format(time.RFC3339Nano) + `"}]}`),
	}}
	repository, err := NewConnectorRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ClaimReconciliation(context.Background(), "worker-a", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("malformed claim digest/token error = %v", err)
	}
	database.responses[postgresConnectorClaimReconciliationSQL] = json.RawMessage(`{"items":null}`)
	if _, err := repository.ClaimReconciliation(context.Background(), "worker-a", 30, 10); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("null claim items error = %v", err)
	}
}
