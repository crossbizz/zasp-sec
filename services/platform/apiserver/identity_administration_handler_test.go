package apiserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	platformidentity "github.com/zasp-ai/zasp-sec/services/platform/identity"
)

type identityAdministrationStoreStub struct {
	organization string
	reservation  identityMutationReservation
	mutation     identityProviderMutation
	completion   identityProviderCompletion
	unknown      int
}

func (store *identityAdministrationStoreStub) identityProviderOrganization(context.Context, RequestIdentity) (string, error) {
	return store.organization, nil
}

func (store *identityAdministrationStoreStub) reserveIdentityProviderMutation(_ context.Context, _ RequestIdentity, mutation identityProviderMutation) (identityMutationReservation, json.RawMessage, error) {
	store.mutation = mutation
	reservation := store.reservation
	if reservation.MutationID == "" {
		reservation = identityMutationReservation{
			MutationID: mutation.MutationID, State: "reserved", ProviderOrganizationReference: store.organization, Version: 1,
			AuditID: mutation.AuditID, CorrelationID: mutation.CorrelationID, ReceiptID: mutation.ReceiptID,
		}
	}
	return reservation, nil, nil
}

func (store *identityAdministrationStoreStub) markIdentityProviderMutationUnknown(_ context.Context, _ RequestIdentity, mutation identityProviderMutation) error {
	store.mutation = mutation
	store.unknown++
	return nil
}

func (store *identityAdministrationStoreStub) completeIdentityProviderMutation(_ context.Context, _ RequestIdentity, completion identityProviderCompletion) (json.RawMessage, error) {
	store.completion = completion
	return json.Marshal(map[string]any{
		"body": json.RawMessage(completion.Connection), "version": 1, "audit_id": completion.AuditID,
		"correlation_id": completion.CorrelationID, "receipt_id": completion.ReceiptID, "replayed": false,
		"mutation_id": completion.MutationID,
		"secret_grant_id": func() any {
			if completion.GrantID == "" {
				return nil
			}
			return completion.GrantID
		}(),
	})
}

func (*identityAdministrationStoreStub) revealIdentityProviderSecret(context.Context, RequestIdentity, string) (json.RawMessage, error) {
	return nil, ErrRepositoryNotFound
}

func (*identityAdministrationStoreStub) acknowledgeIdentityProviderSecret(context.Context, RequestIdentity, string) error {
	return nil
}

type identityAdministrationDriver struct {
	callbackIdentityDriver
	organization  string
	createSSO     int
	lastSSO       platformidentity.DriverSSOConfig
	lastSCIM      platformidentity.DriverSCIMConfig
	createSCIM    int
	deleteSCIM    int
	scim          []platformidentity.DriverSCIMConnection
	connectionErr error
}

func (driver *identityAdministrationDriver) ListSCIMConnections(context.Context, string) ([]platformidentity.DriverSCIMConnection, error) {
	if driver.connectionErr != nil {
		return nil, driver.connectionErr
	}
	return append([]platformidentity.DriverSCIMConnection(nil), driver.scim...), nil
}

func (driver *identityAdministrationDriver) CreateSCIMConnection(_ context.Context, organization string, config platformidentity.DriverSCIMConfig) (platformidentity.DriverSCIMCredential, error) {
	driver.createSCIM++
	driver.lastSCIM = config
	if driver.connectionErr != nil {
		return platformidentity.DriverSCIMCredential{}, driver.connectionErr
	}
	return platformidentity.DriverSCIMCredential{Connection: platformidentity.DriverSCIMConnection{
		Reference: "scim-connection-created", OrganizationReference: organization, Status: "active", DisplayName: config.DisplayName,
		IdentityProvider: config.IdentityProvider, BaseURL: "https://scim.stytch.com/v2/created",
	}, BearerToken: "scim_bearer_token_recoverable"}, nil
}

func (driver *identityAdministrationDriver) DeleteSCIMConnection(_ context.Context, _, reference string) (string, error) {
	driver.deleteSCIM++
	if driver.connectionErr != nil {
		return "", driver.connectionErr
	}
	driver.scim = nil
	return reference, nil
}

func (driver *identityAdministrationDriver) ListSSOConnections(context.Context, string) ([]platformidentity.DriverSSOConnection, error) {
	if driver.connectionErr != nil {
		return nil, driver.connectionErr
	}
	return []platformidentity.DriverSSOConnection{{
		Reference: "saml-connection-zeta", OrganizationReference: driver.organization, Status: "active", DisplayName: "Zeta", Protocol: "saml", IdentityProvider: "okta",
	}, {
		Reference: "oidc-connection-alpha", OrganizationReference: driver.organization, Status: "pending", DisplayName: "Alpha", Protocol: "oidc", IdentityProvider: "microsoft-entra",
	}}, nil
}

func (driver *identityAdministrationDriver) CreateSSOConnection(_ context.Context, organization string, config platformidentity.DriverSSOConfig) (platformidentity.DriverSSOConnection, error) {
	driver.createSSO++
	driver.lastSSO = config
	if driver.connectionErr != nil {
		return platformidentity.DriverSSOConnection{}, driver.connectionErr
	}
	return platformidentity.DriverSSOConnection{
		Reference: "saml-connection-created", OrganizationReference: organization, Status: "pending", DisplayName: config.DisplayName, Protocol: config.Protocol, IdentityProvider: config.IdentityProvider,
	}, nil
}

func newIdentityAdministrationTestProvider(t *testing.T, driver *identityAdministrationDriver, now time.Time) IdentityConnectionProvider {
	t.Helper()
	adapter, err := platformidentity.NewAdapter(driver, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	provider, err := platformidentity.NewConnectionService(adapter)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestIdentityAdministrationCoordinatorBindsTenantAndCompletesSSO(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	store := &identityAdministrationStoreStub{organization: "organization-tenant-a"}
	driver := &identityAdministrationDriver{organization: store.organization}
	ids := []string{
		"pid_79000101-0000-4000-8000-000000000101", "pid_79000102-0000-4000-8000-000000000102",
		"pid_79000103-0000-4000-8000-000000000103", "pid_79000104-0000-4000-8000-000000000104",
	}
	coordinator, err := newIdentityAdministrationCoordinator(store, newIdentityAdministrationTestProvider(t, driver, now), identityAdministrationCoordinatorConfig{
		Clock: func() time.Time { return now }, RevealKey: make([]byte, 32), NewProductID: func() (string, error) {
			value := ids[0]
			ids = ids[1:]
			return value, nil
		}, NewOwnerToken: func() ([]byte, error) { return []byte("01234567890123456789012345678901"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	result, err := coordinator.Mutate(context.Background(), identity, "createSSOConnection", "identity-create-sso-0001", json.RawMessage(`{"display_name":"Corporate SAML","protocol":"saml","identity_provider":"okta"}`))
	if err != nil {
		t.Fatal(err)
	}
	if driver.createSSO != 1 || driver.lastSSO != (platformidentity.DriverSSOConfig{DisplayName: "Corporate SAML", Protocol: "saml", IdentityProvider: "okta"}) {
		t.Fatalf("provider calls/config = %d/%#v", driver.createSSO, driver.lastSSO)
	}
	if store.mutation.Operation != "createSSOConnection" || store.mutation.LeaseSeconds != 60 || len(store.mutation.OwnerToken) != 32 || store.completion.MutationID != store.mutation.MutationID || !reflect.DeepEqual(store.completion.OwnerToken, store.mutation.OwnerToken) {
		t.Fatalf("mutation/completion = %#v/%#v", store.mutation, store.completion)
	}
	var body map[string]any
	if json.Unmarshal(result.Body, &body) != nil || result.Status != 201 || body["id"] != "saml-connection-created" || body["audit_correlation_id"] != store.mutation.AuditID {
		t.Fatalf("result = %#v body=%s", result, result.Body)
	}
}

func TestIdentityAdministrationCoordinatorListsSortedTenantConnectionsAndFailsUnknown(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	store := &identityAdministrationStoreStub{organization: "organization-tenant-a"}
	driver := &identityAdministrationDriver{organization: store.organization}
	coordinator, err := newIdentityAdministrationCoordinator(store, newIdentityAdministrationTestProvider(t, driver, now), identityAdministrationCoordinatorConfig{
		Clock: func() time.Time { return now }, RevealKey: make([]byte, 32), NewProductID: newWorkflowProductID,
		NewOwnerToken: func() ([]byte, error) { return []byte("01234567890123456789012345678901"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	page, err := coordinator.List(context.Background(), identity, "listSSOConnections", "", 1)
	var listed struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err != nil || json.Unmarshal(page, &listed) != nil || len(listed.Items) != 2 || listed.Items[0].ID != "oidc-connection-alpha" || listed.Items[1].ID != "saml-connection-zeta" {
		t.Fatalf("page=%s err=%v", page, err)
	}

	identity.FreshAuthenticated = true
	driver.connectionErr = errors.New("provider detail")
	_, err = coordinator.Mutate(context.Background(), identity, "createSSOConnection", "identity-create-sso-0002", json.RawMessage(`{"display_name":"Corporate SAML","protocol":"saml","identity_provider":"okta"}`))
	if !errors.Is(err, ErrRepositoryUnavailable) || store.unknown != 1 {
		t.Fatalf("provider failure=%v unknown=%d", err, store.unknown)
	}
}

type identityAdministrationSecretStore struct {
	identityAdministrationStoreStub
}

func (store *identityAdministrationSecretStore) revealIdentityProviderSecret(_ context.Context, _ RequestIdentity, grantID string) (json.RawMessage, error) {
	if store.completion.GrantID != grantID {
		return nil, ErrRepositoryNotFound
	}
	return json.Marshal(identityAdministrationSecretEnvelope{
		Ciphertext: base64.StdEncoding.EncodeToString(store.completion.Ciphertext), Nonce: base64.StdEncoding.EncodeToString(store.completion.Nonce),
		AuthenticationTag: base64.StdEncoding.EncodeToString(store.completion.AuthenticationTag), ExpiresAt: store.completion.GrantExpiresAt.Format(time.RFC3339Nano),
	})
}

func TestIdentityAdministrationCoordinatorRecoversSCIMCredentialWithoutPlaintextPersistence(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	store := &identityAdministrationSecretStore{identityAdministrationStoreStub: identityAdministrationStoreStub{organization: "organization-tenant-a"}}
	driver := &identityAdministrationDriver{organization: store.organization}
	sequence := 0
	newID := func() (string, error) {
		sequence++
		return "pid_7900020" + string(rune('0'+sequence)) + "-0000-4000-8000-00000000020" + string(rune('0'+sequence)), nil
	}
	config := identityAdministrationCoordinatorConfig{
		Clock: func() time.Time { return now }, RevealKey: []byte("01234567890123456789012345678901"), NewProductID: newID,
		NewOwnerToken: func() ([]byte, error) { return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil },
	}
	coordinator, err := newIdentityAdministrationCoordinator(store, newIdentityAdministrationTestProvider(t, driver, now), config)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	result, err := coordinator.Mutate(context.Background(), identity, "createSCIMConnection", "identity-create-scim-0001", json.RawMessage(`{"display_name":"Corporate SCIM","identity_provider":"okta"}`))
	if err != nil || driver.createSCIM != 1 || driver.lastSCIM != (platformidentity.DriverSCIMConfig{DisplayName: "Corporate SCIM", IdentityProvider: "okta"}) {
		t.Fatalf("create result=%#v calls=%d config=%#v err=%v", result, driver.createSCIM, driver.lastSCIM, err)
	}
	if !jsonContainsString(result.Body, "bearer_token", "scim_bearer_token_recoverable") || string(store.completion.Ciphertext) == "scim_bearer_token_recoverable" || len(store.completion.AuthenticationTag) != 16 {
		t.Fatalf("secret result=%s completion=%#v", result.Body, store.completion)
	}
	grantID := store.completion.GrantID
	store.reservation = identityMutationReservation{
		MutationID: store.completion.MutationID, State: "completed", Version: 1, AuditID: store.completion.AuditID,
		CorrelationID: store.completion.CorrelationID, ReceiptID: store.completion.ReceiptID, Replayed: true,
		Body: store.completion.Connection, SecretGrantID: &grantID,
	}
	replayed, err := coordinator.Mutate(context.Background(), identity, "createSCIMConnection", "identity-create-scim-0001", json.RawMessage(`{"display_name":"Corporate SCIM","identity_provider":"okta"}`))
	if err != nil || !replayed.Replayed || driver.createSCIM != 1 || !jsonContainsString(replayed.Body, "bearer_token", "scim_bearer_token_recoverable") {
		t.Fatalf("replay=%#v body=%s calls=%d err=%v", replayed, replayed.Body, driver.createSCIM, err)
	}
}

func TestIdentityAdministrationCoordinatorReconcilesUnknownSCIMWithoutLeavingDuplicateConnection(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	store := &identityAdministrationSecretStore{identityAdministrationStoreStub: identityAdministrationStoreStub{
		organization: "organization-tenant-a",
		reservation: identityMutationReservation{
			MutationID: "pid_79000301-0000-4000-8000-000000000301", State: "provider_unknown", ProviderOrganizationReference: "organization-tenant-a", Version: 1,
			AuditID: "pid_79000302-0000-4000-8000-000000000302", CorrelationID: "pid_79000303-0000-4000-8000-000000000303", ReceiptID: "pid_79000304-0000-4000-8000-000000000304",
		},
	}}
	driver := &identityAdministrationDriver{organization: store.organization, scim: []platformidentity.DriverSCIMConnection{{
		Reference: "scim-connection-unknown", OrganizationReference: store.organization, Status: "active", DisplayName: "Corporate SCIM", IdentityProvider: "okta", BaseURL: "https://scim.stytch.com/v2/unknown",
	}}}
	coordinator, err := newIdentityAdministrationCoordinator(store, newIdentityAdministrationTestProvider(t, driver, now), identityAdministrationCoordinatorConfig{
		Clock: func() time.Time { return now }, RevealKey: []byte("01234567890123456789012345678901"), NewProductID: newWorkflowProductID,
		NewOwnerToken: func() ([]byte, error) { return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	result, err := coordinator.Mutate(context.Background(), identity, "createSCIMConnection", "identity-create-scim-unknown-0001", json.RawMessage(`{"display_name":"Corporate SCIM","identity_provider":"okta"}`))
	if err != nil || result.Status != 201 || driver.deleteSCIM != 1 || driver.createSCIM != 1 || len(driver.scim) != 0 {
		t.Fatalf("result=%#v delete/create=%d/%d remaining=%d err=%v", result, driver.deleteSCIM, driver.createSCIM, len(driver.scim), err)
	}
}

func TestIdentityAdministrationHTTPReturnsStrictOneTimeSCIMCredential(t *testing.T) {
	now := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	store := &identityAdministrationSecretStore{identityAdministrationStoreStub: identityAdministrationStoreStub{organization: "organization-tenant-a"}}
	driver := &identityAdministrationDriver{organization: store.organization}
	coordinator, err := newIdentityAdministrationCoordinator(store, newIdentityAdministrationTestProvider(t, driver, now), identityAdministrationCoordinatorConfig{
		Clock: func() time.Time { return now }, RevealKey: []byte("01234567890123456789012345678901"), NewProductID: newWorkflowProductID,
		NewOwnerToken: func() ([]byte, error) { return []byte("abcdefghijklmnopqrstuvwxyz012345"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/admin/scim-connections", strings.NewReader(`{"display_name":"Corporate SCIM","identity_provider":"okta"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Fresh-Auth", "confirmed")
	request.Header.Set("Idempotency-Key", "identity-create-scim-http-0001")
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, "pid_79000401-0000-4000-8000-000000000401"))
	response := httptest.NewRecorder()
	(&identityHTTPHandler{identityAdministration: coordinator}).mutateIdentityConnection(response, request, identity, RoutedOperation{OperationID: "createSCIMConnection"})
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("ETag") != `"1"` || !jsonContainsString(response.Body.Bytes(), "bearer_token", "scim_bearer_token_recoverable") {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
