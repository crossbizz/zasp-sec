package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

func TestStytchSessionDriverUsesExactTenantBoundSSOAndSCIMContracts(t *testing.T) {
	const organization = "organization-tenant-a"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		project, secret, ok := request.BasicAuth()
		if !ok || project != "project-test-local" || secret != "secret-test-local" {
			t.Fatal("missing Stytch project authentication")
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/b2b/sso/" + organization:
			writeStytchJSON(t, writer, map[string]any{
				"status_code": 200,
				"request_id":  "request-list-sso",
				"saml_connections": []any{map[string]any{
					"organization_id": organization, "connection_id": "saml-connection-live-a", "status": "active",
					"display_name": "Corporate SAML", "identity_provider": "okta",
				}},
				"oidc_connections": []any{map[string]any{
					"organization_id": organization, "connection_id": "oidc-connection-live-a", "status": "pending",
					"display_name": "Corporate OIDC", "identity_provider": "microsoft-entra",
				}},
				"external_connections": []any{},
			})
		case "POST /v1/b2b/sso/saml/" + organization:
			assertJSONBody(t, request, map[string]any{"display_name": "New SAML", "identity_provider": "generic"})
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "request_id": "request-create-saml", "connection": map[string]any{
				"organization_id": organization, "connection_id": "saml-connection-new-a", "status": "pending",
				"display_name": "New SAML", "identity_provider": "generic",
			}})
		case "POST /v1/b2b/sso/oidc/" + organization:
			assertJSONBody(t, request, map[string]any{"display_name": "New OIDC", "identity_provider": "okta"})
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "request_id": "request-create-oidc", "connection": map[string]any{
				"organization_id": organization, "connection_id": "oidc-connection-new-a", "status": "pending",
				"display_name": "New OIDC", "identity_provider": "okta",
			}})
		case "DELETE /v1/b2b/sso/" + organization + "/connections/saml-connection-live-a":
			assertJSONBody(t, request, map[string]any{})
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "request_id": "request-delete-sso", "connection_id": "saml-connection-live-a"})
		case "GET /v1/b2b/scim/" + organization + "/connection":
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "request_id": "request-list-scim", "connection": map[string]any{
				"organization_id": organization, "connection_id": "scim-connection-live-a", "status": "active",
				"display_name": "Corporate SCIM", "identity_provider": "okta", "base_url": "https://scim.stytch.com/v2/tenant-a",
				"bearer_token_last_four": "1234",
			}})
		case "POST /v1/b2b/scim/" + organization + "/connection":
			assertJSONBody(t, request, map[string]any{"display_name": "New SCIM", "identity_provider": "generic"})
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "request_id": "request-create-scim", "connection": map[string]any{
				"organization_id": organization, "connection_id": "scim-connection-new-a", "status": "active",
				"display_name": "New SCIM", "identity_provider": "generic", "base_url": "https://scim.stytch.com/v2/tenant-new-a",
				"bearer_token": "scim_bearer_token_secret-test-local",
			}})
		case "DELETE /v1/b2b/scim/" + organization + "/connection/scim-connection-live-a":
			assertJSONBody(t, request, map[string]any{})
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "request_id": "request-delete-scim", "connection_id": "scim-connection-live-a"})
		default:
			t.Fatalf("unexpected Stytch request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	driver := newStytchIdentityAdminDriver(t, server.URL)
	ctx := context.Background()
	sso, err := driver.ListSSOConnections(ctx, organization)
	if err != nil || !reflect.DeepEqual(sso, []platformidentity.DriverSSOConnection{
		{Reference: "saml-connection-live-a", OrganizationReference: organization, Status: "active", DisplayName: "Corporate SAML", Protocol: "saml", IdentityProvider: "okta"},
		{Reference: "oidc-connection-live-a", OrganizationReference: organization, Status: "pending", DisplayName: "Corporate OIDC", Protocol: "oidc", IdentityProvider: "microsoft-entra"},
	}) {
		t.Fatalf("ListSSOConnections() = %#v, %v", sso, err)
	}
	createdSAML, err := driver.CreateSSOConnection(ctx, organization, platformidentity.DriverSSOConfig{DisplayName: "New SAML", Protocol: "saml", IdentityProvider: "generic"})
	if err != nil || createdSAML.Reference != "saml-connection-new-a" || createdSAML.OrganizationReference != organization || createdSAML.Protocol != "saml" {
		t.Fatalf("CreateSSOConnection(saml) = %#v, %v", createdSAML, err)
	}
	createdOIDC, err := driver.CreateSSOConnection(ctx, organization, platformidentity.DriverSSOConfig{DisplayName: "New OIDC", Protocol: "oidc", IdentityProvider: "okta"})
	if err != nil || createdOIDC.Reference != "oidc-connection-new-a" || createdOIDC.OrganizationReference != organization || createdOIDC.Protocol != "oidc" {
		t.Fatalf("CreateSSOConnection(oidc) = %#v, %v", createdOIDC, err)
	}
	if deleted, err := driver.DeleteSSOConnection(ctx, organization, "saml-connection-live-a"); err != nil || deleted != "saml-connection-live-a" {
		t.Fatalf("DeleteSSOConnection() = %q, %v", deleted, err)
	}
	if err := driver.TestSSOConnection(ctx, organization, "saml-connection-live-a"); err != nil {
		t.Fatalf("TestSSOConnection() = %v", err)
	}
	scim, err := driver.ListSCIMConnections(ctx, organization)
	if err != nil || !reflect.DeepEqual(scim, []platformidentity.DriverSCIMConnection{{
		Reference: "scim-connection-live-a", OrganizationReference: organization, Status: "active", DisplayName: "Corporate SCIM",
		IdentityProvider: "okta", BaseURL: "https://scim.stytch.com/v2/tenant-a",
	}}) {
		t.Fatalf("ListSCIMConnections() = %#v, %v", scim, err)
	}
	credential, err := driver.CreateSCIMConnection(ctx, organization, platformidentity.DriverSCIMConfig{DisplayName: "New SCIM", IdentityProvider: "generic"})
	if err != nil || credential.Connection.Reference != "scim-connection-new-a" || credential.Connection.OrganizationReference != organization || credential.BearerToken != "scim_bearer_token_secret-test-local" {
		t.Fatalf("CreateSCIMConnection() = %#v, %v", credential, err)
	}
	if deleted, err := driver.DeleteSCIMConnection(ctx, organization, "scim-connection-live-a"); err != nil || deleted != "scim-connection-live-a" {
		t.Fatalf("DeleteSCIMConnection() = %q, %v", deleted, err)
	}
	if got := requests.Load(); got != 8 {
		t.Fatalf("request count = %d", got)
	}
}

func TestStytchSessionDriverFailsClosedOnProviderDrift(t *testing.T) {
	tests := []struct {
		name  string
		serve func(http.ResponseWriter, *http.Request)
	}{
		{name: "foreign organization", serve: func(writer http.ResponseWriter, _ *http.Request) {
			writeStytchJSON(t, writer, map[string]any{"status_code": 200, "saml_connections": []any{map[string]any{
				"organization_id": "organization-foreign", "connection_id": "saml-connection-live-a", "status": "active",
				"display_name": "Corporate SAML", "identity_provider": "okta",
			}}, "oidc_connections": []any{}, "external_connections": []any{}})
		}},
		{name: "wrong media type", serve: func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte(`{"status_code":200,"saml_connections":[],"oidc_connections":[]}`))
		}},
		{name: "oversized response", serve: func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"status_code":200,"saml_connections":[],"oidc_connections":[],"padding":"` + strings.Repeat("x", maximumStytchResponseBytes) + `"}`))
		}},
		{name: "provider failure", serve: func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"status_code":503}`))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(test.serve))
			defer server.Close()
			driver := newStytchIdentityAdminDriver(t, server.URL)
			if _, err := driver.ListSSOConnections(context.Background(), "organization-tenant-a"); !errors.Is(err, platformidentity.ErrProvider) {
				t.Fatalf("ListSSOConnections() error = %v", err)
			}
		})
	}
}

func TestStytchSessionDriverTestsOnlyActiveExactSSOConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeStytchJSON(t, writer, map[string]any{"status_code": 200, "saml_connections": []any{map[string]any{
			"organization_id": "organization-tenant-a", "connection_id": "saml-connection-pending-a", "status": "pending",
			"display_name": "Corporate SAML", "identity_provider": "okta",
		}}, "oidc_connections": []any{}, "external_connections": []any{}})
	}))
	defer server.Close()
	driver := newStytchIdentityAdminDriver(t, server.URL)
	for _, reference := range []string{"saml-connection-pending-a", "saml-connection-missing-a"} {
		if err := driver.TestSSOConnection(context.Background(), "organization-tenant-a", reference); !errors.Is(err, platformidentity.ErrProvider) {
			t.Fatalf("TestSSOConnection(%q) error = %v", reference, err)
		}
	}
}

func newStytchIdentityAdminDriver(t *testing.T, baseURL string) *stytchSessionDriver {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return &stytchSessionDriver{
		baseURL: parsed, client: &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("identity redirect rejected")
		}}, project: "project-test-local", secret: "secret-test-local",
	}
}

func assertJSONBody(t *testing.T, request *http.Request, expected map[string]any) {
	t.Helper()
	if request.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", request.Header.Get("Content-Type"))
	}
	var got map[string]any
	if err := json.NewDecoder(request.Body).Decode(&got); err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatalf("request body = %#v, %v", got, err)
	}
}

func writeStytchJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatal(err)
	}
}
