package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type nangoConnectionAPIStub struct {
	start      nango.OAuthStartRequest
	complete   nango.OAuthCompleteRequest
	recover    nango.OAuthCompleteRequest
	revoke     nango.ConnectionRevocationRequest
	connection nango.Connection
	recoverErr error
}

func (stub *nangoConnectionAPIStub) StartOAuth(_ context.Context, request nango.OAuthStartRequest) (nango.OAuthAuthorization, error) {
	stub.start = request
	return nango.OAuthAuthorization{URL: "https://slack.com/oauth/v2/authorize?state=nango_state_12345678", State: "nango_state_12345678", ExpiresAt: requestBindingExpiry}, nil
}
func (stub *nangoConnectionAPIStub) CompleteOAuth(_ context.Context, request nango.OAuthCompleteRequest) (nango.Connection, error) {
	stub.complete = request
	return stub.connection, nil
}
func (stub *nangoConnectionAPIStub) RecoverOAuth(_ context.Context, request nango.OAuthCompleteRequest) (nango.Connection, error) {
	stub.recover = request
	return stub.connection, stub.recoverErr
}
func (stub *nangoConnectionAPIStub) RevokeConnection(_ context.Context, request nango.ConnectionRevocationRequest) error {
	stub.revoke = request
	return nil
}

var requestBindingExpiry = time.Date(2026, 8, 28, 12, 10, 0, 0, time.UTC)

func TestNangoOAuthProviderBindsLifecycleToExactTenantAndPrivateAuthority(t *testing.T) {
	identity := fixtureRuntimeIdentity(t)
	api := &nangoConnectionAPIStub{connection: nango.Connection{Reference: "ref:nango/connection/11111111-1111-4111-8111-111111111111", ProviderSubject: "user_0123456789abcdef", ConnectorKey: "slack"}}
	provider, err := newNangoOAuthProvider(nangoOAuthProviderConfig{
		Client: api, BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production",
		ConnectorKey: "slack", Provider: "slack", AuthorizationHost: "slack.com", AuthorizationPath: "/oauth/v2/authorize", CallbackURL: "https://app.example.test/api/v1/integrations/oauth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	start := apiserver.ConnectorAuthorizationStart{
		Scope: identity.Scope, PrincipalID: identity.PrincipalID.String(), IntegrationID: "pid_44444444-4444-4444-8444-444444444444", AttemptID: "pid_55555555-5555-4555-8555-555555555555",
		ConnectorKey: "slack", AuthorityProvider: "nango:slack", ProposedState: "proposed_state_12345678", Challenge: "challenge_1234567890123456789012345678901234567890123", ExpiresAt: requestBindingExpiry,
	}
	target, err := provider.StartAuthorization(context.Background(), start)
	if err != nil || target.State != "nango_state_12345678" || api.start.Binding.OrganizationID != identity.Scope.OrganizationID().String() || api.start.Binding.AttemptID != start.AttemptID || api.start.ConnectorKey != "slack" || api.start.Provider != "slack" {
		t.Fatalf("target=%#v start=%#v err=%v", target, api.start, err)
	}
	completion := apiserver.ConnectorAuthorizationCompletion{Scope: start.Scope, PrincipalID: start.PrincipalID, IntegrationID: start.IntegrationID, AttemptID: start.AttemptID, ConnectorKey: "slack", AuthorityProvider: "nango:slack", State: target.State, Code: "provider_code_12345678", Verifier: []byte("verifier_1234567890123456789012345678901234567890123")}
	grant, err := provider.CompleteAuthorization(context.Background(), completion)
	if err != nil || grant.ConnectionReference != api.connection.Reference || grant.ProviderSubject != api.connection.ProviderSubject || grant.CredentialClass != "nango_connection_reference" || string(grant.Metadata) != `{"connector_key":"slack","source":"managed_auth_proxy"}` || api.complete.Binding.AttemptID != start.AttemptID {
		t.Fatalf("grant=%#v complete=%#v err=%v", grant, api.complete, err)
	}
	recovery := apiserver.ConnectorAuthorizationRecovery{Scope: start.Scope, PrincipalID: start.PrincipalID, IntegrationID: start.IntegrationID, AttemptID: start.AttemptID, EffectID: "pid_66666666-6666-4666-8666-666666666666", ConnectorKey: "slack", AuthorityProvider: "nango:slack"}
	if _, err := provider.RecoverAuthorization(context.Background(), recovery); err != nil || api.recover.Binding.AttemptID != start.AttemptID {
		t.Fatalf("recover=%#v err=%v", api.recover, err)
	}
	revocation := apiserver.ConnectorAuthorizationRevocation{Scope: start.Scope, IntegrationID: start.IntegrationID, EffectID: recovery.EffectID, ConnectorKey: "slack", AuthorityProvider: "nango:slack", ConnectionReference: api.connection.Reference}
	if err := provider.RevokeAuthorization(context.Background(), revocation); err != nil || api.revoke.Binding.OrganizationID != identity.Scope.OrganizationID().String() || api.revoke.Binding.IntegrationID != start.IntegrationID || api.revoke.ConnectionReference != api.connection.Reference {
		t.Fatalf("revoke=%#v err=%v", api.revoke, err)
	}
	discard := apiserver.ConnectorAuthorizationDiscard{Scope: start.Scope, PrincipalID: start.PrincipalID, IntegrationID: start.IntegrationID, AttemptID: start.AttemptID, EffectID: recovery.EffectID, ConnectorKey: "slack", AuthorityProvider: "nango:slack", Revoke: true}
	if err := provider.DiscardAuthorization(context.Background(), discard); err != nil || api.recover.Binding.AttemptID != start.AttemptID || api.revoke.ConnectionReference != api.connection.Reference || api.revoke.Binding.OrganizationID != identity.Scope.OrganizationID().String() {
		t.Fatalf("discard recover=%#v revoke=%#v err=%v", api.recover, api.revoke, err)
	}
}

func TestNangoOAuthProviderRejectsAuthorityDriftBeforeNangoIO(t *testing.T) {
	identity := fixtureRuntimeIdentity(t)
	api := &nangoConnectionAPIStub{}
	provider, err := newNangoOAuthProvider(nangoOAuthProviderConfig{Client: api, BaseURL: "http://nango.connector.svc.cluster.local:3003", ServiceSecretReference: "ref:nango/service-key-0001", Environment: "production", ConnectorKey: "slack", Provider: "slack", AuthorizationHost: "slack.com", AuthorizationPath: "/oauth/v2/authorize", CallbackURL: "https://app.example.test/api/v1/integrations/oauth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	input := apiserver.ConnectorAuthorizationStart{Scope: identity.Scope, PrincipalID: identity.PrincipalID.String(), IntegrationID: "pid_44444444-4444-4444-8444-444444444444", AttemptID: "pid_55555555-5555-4555-8555-555555555555", ConnectorKey: "slack", AuthorityProvider: "nango:github", ProposedState: "proposed_state_12345678", Challenge: "challenge_1234567890123456789012345678901234567890123", ExpiresAt: requestBindingExpiry}
	if _, err := provider.StartAuthorization(context.Background(), input); !errors.Is(err, errRuntimeUnavailable) || api.start.Binding.OrganizationID != "" {
		t.Fatalf("authority drift err=%v request=%#v", err, api.start)
	}
	api.recoverErr = nango.ErrConnectionNotFound
	_, err = provider.RecoverAuthorization(context.Background(), apiserver.ConnectorAuthorizationRecovery{Scope: input.Scope, PrincipalID: input.PrincipalID, IntegrationID: input.IntegrationID, AttemptID: input.AttemptID, EffectID: "pid_66666666-6666-4666-8666-666666666666", ConnectorKey: "slack", AuthorityProvider: "nango:slack"})
	if !errors.Is(err, apiserver.ErrConnectorOutcomeNotFound) {
		t.Fatalf("missing outcome mapping=%v", err)
	}
}

func TestNangoServiceSecretResolverMapsOnlyExactPrivateReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-key")
	if err := os.WriteFile(path, []byte("nango-service-secret-value"), 0o400); err != nil {
		t.Fatal(err)
	}
	resolver, err := newNangoServiceSecretResolver(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := resolver.Resolve(context.Background(), "ref:nango/service-key-0001")
	if err != nil || string(secret) != "nango-service-secret-value" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	clear(secret)
	for _, reference := range []string{"ref:nango/service-key-../admin", "ref:nango/connection/11111111-1111-4111-8111-111111111111", "ref:nango/service-key-0001/child", "ref:nango/service-key-0001?version=2"} {
		if _, err := resolver.Resolve(context.Background(), reference); !errors.Is(err, errRuntimeUnavailable) {
			t.Fatalf("reference %q accepted: %v", reference, err)
		}
	}
	if _, err := newNangoServiceSecretResolver("/tmp/nango-service-key"); !errors.Is(err, errRuntimeUnavailable) {
		t.Fatalf("untrusted secret path accepted: %v", err)
	}
}

func TestProductionNangoRegistrationIsOptionalAndAddsOnlySlackLongTailAuthority(t *testing.T) {
	providers := map[string]apiserver.ConnectorOAuthProviderDefinition{
		"github": {Provider: &githubOAuthProvider{}, RequestedScopes: []string{"actions:read", "contents:read", "metadata:read"}, CredentialClass: "github_installation_reference"},
	}
	checks := map[string]apiserver.ConnectorCapabilityCheck{"github": func(context.Context) error { return nil }}
	config := fixtureRuntimeConfig()
	config.NangoBaseURL = "http://nango.connector.svc.cluster.local:3003"
	config.NangoServiceSecretReference = "ref:nango/service-key-0001"
	config.NangoEnvironment = "production"
	closer, err := addProductionNangoProvider(config, nangoServiceResolverStub{value: []byte("nango-service-secret-value")}, providers, checks)
	if err != nil || closer == nil {
		t.Fatalf("registration closer=%#v err=%v", closer, err)
	}
	defer closer.Close()
	definition, exists := providers["slack"]
	if !exists || definition.AuthorityProvider != "nango:slack" || definition.CredentialClass != "nango_connection_reference" || len(definition.RequestedScopes) != 2 || checks["slack"] == nil || len(providers) != 2 || len(checks) != 2 {
		t.Fatalf("providers=%#v checks=%#v", providers, checks)
	}
	without := fixtureRuntimeConfig()
	providers = map[string]apiserver.ConnectorOAuthProviderDefinition{"github": providers["github"]}
	checks = map[string]apiserver.ConnectorCapabilityCheck{"github": checks["github"]}
	closer, err = addProductionNangoProvider(without, nangoServiceResolverStub{value: []byte("nango-service-secret-value")}, providers, checks)
	if err != nil || closer != nil || len(providers) != 1 || len(checks) != 1 {
		t.Fatalf("optional registration closer=%#v err=%v providers=%#v checks=%#v", closer, err, providers, checks)
	}
}

func TestNangoCapabilityReadinessCachesOnlySuccessAndRechecksClockRollback(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	calls := 0
	failing := false
	check, err := newCachedNangoCapabilityCheck(func(context.Context) error {
		calls++
		if failing {
			return errRuntimeUnavailable
		}
		return nil
	}, 30*time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		if err := check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("successful live checks=%d", calls)
	}
	now = now.Add(31 * time.Second)
	failing = true
	if err := check(context.Background()); !errors.Is(err, errRuntimeUnavailable) || calls != 2 {
		t.Fatalf("expired check err=%v calls=%d", err, calls)
	}
	if err := check(context.Background()); !errors.Is(err, errRuntimeUnavailable) || calls != 3 {
		t.Fatalf("failure was cached err=%v calls=%d", err, calls)
	}
	failing = false
	now = now.Add(-time.Minute)
	if err := check(context.Background()); err != nil || calls != 4 {
		t.Fatalf("clock rollback check err=%v calls=%d", err, calls)
	}
}

type nangoServiceResolverStub struct{ value []byte }

func (stub nangoServiceResolverStub) Resolve(context.Context, string) ([]byte, error) {
	return append([]byte(nil), stub.value...), nil
}

func fixtureRuntimeIdentity(t *testing.T) apiserver.RequestIdentity {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_11111111-1111-4111-8111-111111111111")
	workspace, _ := domain.ParseProductID("pid_22222222-2222-4222-8222-222222222222")
	environment, _ := domain.ParseProductID("pid_33333333-3333-4333-8333-333333333333")
	principal, _ := domain.ParseProductID("pid_77777777-7777-4777-8777-777777777777")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return apiserver.RequestIdentity{PrincipalID: principal, Scope: scope, CredentialKind: apiserver.CredentialBrowserSession}
}
