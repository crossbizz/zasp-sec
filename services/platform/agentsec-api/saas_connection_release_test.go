package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/nango"
)

type failingSaaSNango struct{ saasSignInNango }

func (client *failingSaaSNango) RevokeConnection(ctx context.Context, request nango.ConnectionRevocationRequest) error {
	_ = client.saasSignInNango.RevokeConnection(ctx, request)
	return nango.ErrConnection
}

// The connection of a released sign-in is deleted at Nango under the Nango
// integration of its platform and the end user of its own integration, so
// the connection client refuses a connection that belongs to anyone else
// (connectors/nango: TestProductionConnectionClientRejectsForeignConnectionBeforeDelete).
func TestSaaSSignInProviderRemovesTheConnectionOfAReleasedSignIn(t *testing.T) {
	client := &saasSignInNango{}
	provider, request := newSaaSSignInProvider(t, client, &saasProbeProxy{})
	release := apiserver.SaaSConnectionRelease{
		OrganizationID: request.Scope.OrganizationID().String(), WorkspaceID: request.Scope.WorkspaceID().String(), EnvironmentID: request.Scope.EnvironmentID().String(),
		ConnectionReference: "ref:nango/connection/11111111-1111-4111-8111-111111111111", IntegrationID: request.IntegrationID, Platform: "servicenow", Reason: "integration_deleted", Attempt: 1,
		LeaseOwner: "release-worker", LeaseToken: "token", LeaseExpiresAt: time.Now().Add(time.Minute),
	}
	if err := provider.RemoveConnection(context.Background(), release); err != nil {
		t.Fatal(err)
	}
	platform, _ := provider.platform("servicenow", "")
	if len(client.revocations) != 1 {
		t.Fatalf("%d revocations", len(client.revocations))
	}
	revocation := client.revocations[0]
	if revocation.ConnectorKey != platform.Nango.Key || revocation.ConnectionReference != release.ConnectionReference || revocation.NangoBaseURL != provider.baseURL || revocation.ServiceSecretReference != provider.serviceSecretReference || revocation.Environment != provider.environment ||
		revocation.Binding != (nango.RevocationBinding{OrganizationID: release.OrganizationID, WorkspaceID: release.WorkspaceID, EnvironmentID: release.EnvironmentID, IntegrationID: release.IntegrationID}) {
		t.Fatalf("revocation = %+v", revocation)
	}

	// A platform this deployment does not serve (or one without sign-in) is
	// reported as such, and Nango is not asked.
	for _, platformToken := range []string{"unknown_platform", ""} {
		unknown := release
		unknown.Platform = platformToken
		if err := provider.RemoveConnection(context.Background(), unknown); !errors.Is(err, apiserver.ErrRepositoryConfiguration) {
			t.Fatalf("platform %q: %v", platformToken, err)
		}
	}
	// Anything that is not the reference of a Nango connection, or not a
	// product scope, is refused before Nango is asked.
	for name, change := range map[string]func(*apiserver.SaaSConnectionRelease){
		"a service secret reference": func(value *apiserver.SaaSConnectionRelease) { value.ConnectionReference = "ref:nango/service-key-0001" },
		"no integration":             func(value *apiserver.SaaSConnectionRelease) { value.IntegrationID = "" },
		"no organization":            func(value *apiserver.SaaSConnectionRelease) { value.OrganizationID = "organization" },
	} {
		hostile := release
		change(&hostile)
		if err := provider.RemoveConnection(context.Background(), hostile); err == nil {
			t.Fatalf("%s was sent to Nango", name)
		}
	}
	if len(client.revocations) != 1 {
		t.Fatalf("Nango was asked %d times", len(client.revocations))
	}
	// Nango refuses or is unavailable: the worker is told, and tries later.
	failing := &failingSaaSNango{}
	refused, _ := newSaaSSignInProvider(t, &failing.saasSignInNango, &saasProbeProxy{})
	refused.client = failing
	if err := refused.RemoveConnection(context.Background(), release); !errors.Is(err, errRuntimeUnavailable) || len(failing.revocations) != 1 {
		t.Fatalf("a refused deletion: %v after %d requests", err, len(failing.revocations))
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.RemoveConnection(cancelled, release); err == nil {
		t.Fatal("a deletion ran on an ended context")
	}
}

// The worker exists only where the sign-in does and the database has the
// release section.
func TestProductionSaaSConnectionReleaserNeedsTheSignIn(t *testing.T) {
	releaser, err := newProductionSaaSConnectionReleaser(context.Background(), nil, nil, "agentsec-api:test:0011223344556677")
	if err != nil || releaser != nil {
		t.Fatalf("without a sign-in: %v %v", releaser, err)
	}
}
