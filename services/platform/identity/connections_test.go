package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestConnectionServiceCoversSSOAndSCIMLifecycle(t *testing.T) {
	driver := newFakeStytchDriver()
	driver.ssoConnections = nil
	driver.scimConnections = nil
	adapter, err := NewAdapter(driver, func() time.Time { return fixtureNow })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewConnectionService(adapter)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	organization := driver.organization.Reference

	sso, err := service.CreateSSO(ctx, organization, SSOConfig{DisplayName: "Corporate SAML", Protocol: "saml", IdentityProvider: "generic"})
	if err != nil || sso.Reference() != "saml-connection-live-created" || sso.DisplayName() != "Corporate SAML" {
		t.Fatalf("CreateSSO() = %#v, %v", sso, err)
	}
	listedSSO, err := service.ListSSO(ctx, organization)
	if err != nil || len(listedSSO) != 1 || listedSSO[0] != sso {
		t.Fatalf("ListSSO() = %#v, %v", listedSSO, err)
	}
	if err := service.TestSSO(ctx, organization, sso.Reference()); err != nil {
		t.Fatal(err)
	}
	if err := service.DeleteSSO(ctx, organization, sso.Reference()); err != nil {
		t.Fatal(err)
	}
	if values, err := service.ListSSO(ctx, organization); err != nil || len(values) != 0 {
		t.Fatalf("ListSSO() after delete = %#v, %v", values, err)
	}

	credential, err := service.CreateSCIM(ctx, organization, SCIMConfig{DisplayName: "Corporate SCIM", IdentityProvider: "generic"})
	if err != nil || credential.Connection.Reference() != "scim-connection-live-created" || credential.BearerToken() != "scim_bearer_token_fixture" {
		t.Fatalf("CreateSCIM() = %#v, %v", credential, err)
	}
	listedSCIM, err := service.ListSCIM(ctx, organization)
	if err != nil || len(listedSCIM) != 1 || listedSCIM[0] != credential.Connection {
		t.Fatalf("ListSCIM() = %#v, %v", listedSCIM, err)
	}
	if reflect.ValueOf(listedSCIM[0]).FieldByName("bearerToken").IsValid() {
		t.Fatal("SCIM list model retained a bearer token field")
	}
	if err := service.DeleteSCIM(ctx, organization, credential.Connection.Reference()); err != nil {
		t.Fatal(err)
	}
	if values, err := service.ListSCIM(ctx, organization); err != nil || len(values) != 0 {
		t.Fatalf("ListSCIM() after delete = %#v, %v", values, err)
	}
}

func TestConnectionServiceFailsClosedOnInvalidConfigAndProviderFailure(t *testing.T) {
	driver := newFakeStytchDriver()
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	service, _ := NewConnectionService(adapter)
	ctx := context.Background()
	organization := driver.organization.Reference

	for _, invalid := range []SSOConfig{
		{},
		{DisplayName: " Corporate", Protocol: "saml", IdentityProvider: "generic"},
		{DisplayName: "Corporate", Protocol: "oauth", IdentityProvider: "generic"},
		{DisplayName: "Corporate", Protocol: "saml", IdentityProvider: "unknown"},
	} {
		if _, err := service.CreateSSO(ctx, organization, invalid); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("CreateSSO(%#v) error = %v", invalid, err)
		}
	}
	driver.connectionErr = errors.New("provider detail")
	if _, err := service.ListSSO(ctx, organization); !errors.Is(err, ErrProvider) {
		t.Fatalf("ListSSO error = %v", err)
	}
	if _, err := service.CreateSCIM(ctx, organization, SCIMConfig{DisplayName: "Corporate", IdentityProvider: "generic"}); !errors.Is(err, ErrProvider) {
		t.Fatalf("CreateSCIM error = %v", err)
	}
}

func TestConnectionServiceAcceptsOnlyProviderFaithfulMicrosoftEntraSCIMQuery(t *testing.T) {
	driver := newFakeStytchDriver()
	driver.scimConnections = []DriverSCIMConnection{{
		Reference: "scim-connection-entra-a", OrganizationReference: driver.organization.Reference, Status: "active",
		DisplayName: "Microsoft Entra SCIM", IdentityProvider: "microsoft-entra",
		BaseURL: "https://scim.stytch.com/v2/entra-a?aadOptscim062020",
	}}
	adapter, _ := NewAdapter(driver, func() time.Time { return fixtureNow })
	service, _ := NewConnectionService(adapter)
	connections, err := service.ListSCIM(context.Background(), driver.organization.Reference)
	if err != nil || len(connections) != 1 || connections[0].BaseURL() != driver.scimConnections[0].BaseURL {
		t.Fatalf("ListSCIM() = %#v, %v", connections, err)
	}
	for _, rawQuery := range []string{"tenant=foreign", "aadOptscim062020=true", "aadOptscim062020&tenant=foreign"} {
		driver.scimConnections[0].BaseURL = "https://scim.stytch.com/v2/entra-a?" + rawQuery
		if _, err := service.ListSCIM(context.Background(), driver.organization.Reference); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("ListSCIM(%q) error = %v", rawQuery, err)
		}
	}
	driver.scimConnections[0].IdentityProvider = "generic"
	driver.scimConnections[0].BaseURL = "https://scim.stytch.com/v2/generic?aadOptscim062020"
	if _, err := service.ListSCIM(context.Background(), driver.organization.Reference); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("ListSCIM(generic query) error = %v", err)
	}
}
