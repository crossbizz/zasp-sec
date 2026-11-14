package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	saasSignInIntegrationID = "pid_7c000001-0000-4000-8000-000000000001"
	saasSignInReference     = "ref:nango/connection/11111111-1111-4111-8111-111111111111"
	saasSignInSessionCookie = "browser-session-token-0001"
)

// saasSignInStoreStub stands in for the sign-in functions of PostgreSQL.
type saasSignInStoreStub struct {
	integration    SaaSSignInIntegration
	found          bool
	integrationErr error
	started        []SaaSSignInStart
	startErr       error
	attempt        SaaSSignInAttempt
	attemptFound   bool
	consumed       [][]byte
	finished       []string
	finishErr      error
}

func (stub *saasSignInStoreStub) Integration(context.Context, RequestIdentity, string) (SaaSSignInIntegration, bool, error) {
	return stub.integration, stub.found, stub.integrationErr
}

func (stub *saasSignInStoreStub) Start(_ context.Context, _ RequestIdentity, input SaaSSignInStart) error {
	stub.started = append(stub.started, input)
	return stub.startErr
}

func (stub *saasSignInStoreStub) Consume(_ context.Context, _ RequestIdentity, stateDigest, sessionDigest []byte) (SaaSSignInAttempt, bool, error) {
	stub.consumed = append(stub.consumed, stateDigest, sessionDigest)
	return stub.attempt, stub.attemptFound, nil
}

func (stub *saasSignInStoreStub) Finish(_ context.Context, _ RequestIdentity, attemptID, outcome, reference string) error {
	stub.finished = append(stub.finished, attemptID+" "+outcome+" "+reference)
	return stub.finishErr
}

// saasSignInProviderStub stands in for Nango.
type saasSignInProviderStub struct {
	unavailable bool
	target      ConnectorAuthorizationTarget
	startErr    error
	starts      []SaaSSignInRequest
	reference   string
	completeErr error
	completions []SaaSSignInCompletion
}

func (stub *saasSignInProviderStub) Available(context.Context, string) bool { return !stub.unavailable }

func (stub *saasSignInProviderStub) Start(_ context.Context, request SaaSSignInRequest) (ConnectorAuthorizationTarget, error) {
	stub.starts = append(stub.starts, request)
	return stub.target, stub.startErr
}

func (stub *saasSignInProviderStub) Complete(_ context.Context, request SaaSSignInCompletion) (string, error) {
	stub.completions = append(stub.completions, request)
	return stub.reference, stub.completeErr
}

type saasSignInFixture struct {
	handler    http.Handler
	store      *saasSignInStoreStub
	provider   *saasSignInProviderStub
	repository *connectorAuthorizationStub
	identity   RequestIdentity
	now        time.Time
}

func newSaaSSignInFixture(t *testing.T) *saasSignInFixture {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	now := time.Now().UTC()
	fixture := &saasSignInFixture{identity: identity, now: now, repository: &connectorAuthorizationStub{},
		store: &saasSignInStoreStub{found: true, integration: SaaSSignInIntegration{Platform: "servicenow", TenantID: "acme", Version: 3, Status: "pending_authorization"}},
		provider: &saasSignInProviderStub{reference: saasSignInReference,
			target: ConnectorAuthorizationTarget{URL: "https://acme.service-now.com/oauth_auth.do?client_id=zasp&state=" + strings.Repeat("s", 43), State: strings.Repeat("s", 43), ExpiresAt: now.Add(9 * time.Minute)}}}
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"slack": {Provider: &connectorLongTailProviderStub{}, RequestedScopes: []string{"nango:auth", "nango:proxy"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:slack"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler, err = NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: fixture.repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue(saasSignInIntegrationID, "saas")}, Secrets: &connectorSecretStub{}, Registry: registry,
		Clock: func() time.Time { return now }, SaaSSignIn: &SaaSSignIn{Store: fixture.store, Provider: fixture.provider}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *saasSignInFixture) serve(method, target, operation string, parameters map[string]string, headers map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	request := httptest.NewRequest(method, "https://app.zasp.test"+target, body)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: saasSignInSessionCookie})
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, fixture.identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: parameters}))
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	return response
}

func (fixture *saasSignInFixture) authorize() *httptest.ResponseRecorder {
	return fixture.serve(http.MethodPost, "/api/v1/integrations/"+saasSignInIntegrationID+"/authorize", "authorizeIntegration", map[string]string{"id": saasSignInIntegrationID}, map[string]string{"Idempotency-Key": "saas-sign-in-key-0001"})
}

func (fixture *saasSignInFixture) callback(query string) *httptest.ResponseRecorder {
	return fixture.serve(http.MethodGet, "/api/v1/integrations/oauth/callback?"+query, "completeIntegrationOAuthCallback", map[string]string{}, nil)
}

func TestSaaSSignInStartAnswersTheProvidersAuthorizationAddress(t *testing.T) {
	fixture := newSaaSSignInFixture(t)
	response := fixture.authorize()
	var body struct {
		AttemptID string    `json:"authorization_attempt_id"`
		URL       string    `json:"authorization_url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.URL != fixture.provider.target.URL || !validProductID(body.AttemptID) || !body.ExpiresAt.Equal(fixture.provider.target.ExpiresAt) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	// Nango was asked for the platform and the tenant the integration names.
	if len(fixture.provider.starts) != 1 || fixture.provider.starts[0].Platform != "servicenow" || fixture.provider.starts[0].TenantID != "acme" || fixture.provider.starts[0].IntegrationID != saasSignInIntegrationID || fixture.provider.starts[0].AttemptID != body.AttemptID {
		t.Fatalf("provider start = %+v", fixture.provider.starts)
	}
	// The sign-in is recorded with digests of the state and of the session
	// cookie, at the version of the integration that was read.
	if len(fixture.store.started) != 1 {
		t.Fatalf("recorded sign-ins = %d", len(fixture.store.started))
	}
	started := fixture.store.started[0]
	if started.AttemptID != body.AttemptID || started.IntegrationVersion != 3 || string(started.StateDigest) != string(connectorDigest(fixture.provider.target.State)) || string(started.SessionDigest) != string(connectorDigest(saasSignInSessionCookie)) || !started.ExpiresAt.Equal(fixture.provider.target.ExpiresAt) {
		t.Fatalf("recorded sign-in = %+v", started)
	}
	// The OAuth attempt machinery of the other connectors was not used.
	if fixture.repository.started.AttemptID != "" || strings.Contains(response.Body.String(), saasSignInSessionCookie) {
		t.Fatalf("an OAuth attempt was started: %+v", fixture.repository.started)
	}
}

func TestSaaSSignInStartRefusals(t *testing.T) {
	for name, test := range map[string]struct {
		mutate     func(*saasSignInFixture)
		status     int
		starts     int
		recordings int
	}{
		"the platform has no sign-in here":      {func(fixture *saasSignInFixture) { fixture.provider.unavailable = true }, http.StatusServiceUnavailable, 0, 0},
		"the integration is already authorized": {func(fixture *saasSignInFixture) { fixture.store.integration.Status = "active" }, http.StatusConflict, 0, 0},
		"Nango refuses":                         {func(fixture *saasSignInFixture) { fixture.provider.startErr = errors.New("nango") }, http.StatusServiceUnavailable, 1, 0},
		"Nango answers an address without state": {func(fixture *saasSignInFixture) {
			fixture.provider.target.URL = "https://acme.service-now.com/oauth_auth.do"
		}, http.StatusServiceUnavailable, 1, 0},
		"Nango answers a plain HTTP address": {func(fixture *saasSignInFixture) {
			fixture.provider.target.URL = strings.Replace(fixture.provider.target.URL, "https://", "http://", 1)
		}, http.StatusServiceUnavailable, 1, 0},
		"Nango answers an address": {func(fixture *saasSignInFixture) {
			fixture.provider.target.URL = strings.Replace(fixture.provider.target.URL, "acme.service-now.com", "10.0.0.1", 1)
		}, http.StatusServiceUnavailable, 1, 0},
		"an expiry beyond ten minutes": {func(fixture *saasSignInFixture) {
			fixture.provider.target.ExpiresAt = fixture.now.Add(11 * time.Minute)
		}, http.StatusServiceUnavailable, 1, 0},
		"the integration changed":     {func(fixture *saasSignInFixture) { fixture.store.startErr = ErrRepositoryConflict }, http.StatusConflict, 1, 1},
		"the database is unavailable": {func(fixture *saasSignInFixture) { fixture.store.integrationErr = ErrRepositoryUnavailable }, http.StatusServiceUnavailable, 0, 0},
	} {
		fixture := newSaaSSignInFixture(t)
		test.mutate(fixture)
		response := fixture.authorize()
		if response.Code != test.status || len(fixture.provider.starts) != test.starts || len(fixture.store.started) != test.recordings || strings.Contains(response.Body.String(), "authorization_url") {
			t.Fatalf("%s: status=%d starts=%d recordings=%d body=%s", name, response.Code, len(fixture.provider.starts), len(fixture.store.started), response.Body)
		}
	}
}

// An integration that is not a saas integration waiting for its sign-in is
// served exactly as before.
func TestSaaSSignInLeavesOtherIntegrationsToTheOAuthFlow(t *testing.T) {
	fixture := newSaaSSignInFixture(t)
	fixture.store.found = false
	response := fixture.authorize()
	// The workflow stub holds a saas integration, which no OAuth provider
	// serves: the existing path answers not found, and Nango was not asked.
	if response.Code != http.StatusNotFound || len(fixture.provider.starts) != 0 || len(fixture.store.started) != 0 {
		t.Fatalf("status=%d starts=%d body=%s", response.Code, len(fixture.provider.starts), response.Body)
	}
	// A callback whose state is no saas sign-in reaches the OAuth attempts.
	fixture.repository.consumeErr = ErrRepositoryNotFound
	response = fixture.callback("code=provider_code_123&state=" + strings.Repeat("o", 43))
	if response.Code != http.StatusNotFound || len(fixture.store.consumed) != 2 || len(fixture.provider.completions) != 0 || fixture.repository.consumeCalls != 1 {
		t.Fatalf("callback status=%d consumed=%d oauth consume calls=%d", response.Code, len(fixture.store.consumed), fixture.repository.consumeCalls)
	}
}

func TestSaaSSignInCallbackEndsInTheConnectionReference(t *testing.T) {
	fixture := newSaaSSignInFixture(t)
	const attemptID = "pid_7c000002-0000-4000-8000-000000000002"
	state := strings.Repeat("s", 43)
	fixture.store.attemptFound, fixture.store.attempt = true, SaaSSignInAttempt{ID: attemptID, IntegrationID: saasSignInIntegrationID, Platform: "servicenow", TenantID: "acme", Accepted: true}
	response := fixture.callback("code=provider_code_123&state=" + state)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/integrations?saas_connection=11111111-1111-4111-8111-111111111111&saas_sign_in="+saasSignInIntegrationID {
		t.Fatalf("status=%d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body)
	}
	// The sign-in was taken by the digests of this state and this session.
	if len(fixture.store.consumed) != 2 || string(fixture.store.consumed[0]) != string(connectorDigest(state)) || string(fixture.store.consumed[1]) != string(connectorDigest(saasSignInSessionCookie)) {
		t.Fatal("the sign-in was not taken by the state and session digests")
	}
	if len(fixture.provider.completions) != 1 || fixture.provider.completions[0].State != state || fixture.provider.completions[0].Code != "provider_code_123" || fixture.provider.completions[0].TenantID != "acme" || fixture.provider.completions[0].AttemptID != attemptID {
		t.Fatalf("completion = %+v", fixture.provider.completions)
	}
	if len(fixture.store.finished) != 1 || fixture.store.finished[0] != attemptID+" completed "+saasSignInReference {
		t.Fatalf("finished = %v", fixture.store.finished)
	}
	// The OAuth attempt machinery of the other connectors was not used and
	// the integration was not touched: the sign-in ends in a reference.
	if fixture.repository.consumeCalls != 0 || fixture.repository.completed.AttemptID != "" {
		t.Fatalf("OAuth attempts were used: %+v", fixture.repository.completed)
	}
}

func TestSaaSSignInCallbackFailuresEndTheSignInWithoutAReference(t *testing.T) {
	const attemptID = "pid_7c000002-0000-4000-8000-000000000002"
	accepted := SaaSSignInAttempt{ID: attemptID, IntegrationID: saasSignInIntegrationID, Platform: "servicenow", TenantID: "acme", Accepted: true}
	for name, test := range map[string]struct {
		query    string
		mutate   func(*saasSignInFixture)
		status   int
		location string
		finished string
		provider int
	}{
		"the person signed in to another tenant": {"code=provider_code_123&state=" + strings.Repeat("s", 43), func(fixture *saasSignInFixture) { fixture.provider.completeErr = ErrSaaSSignInTenantMismatch },
			http.StatusSeeOther, "/integrations?saas_sign_in=" + saasSignInIntegrationID + "&saas_sign_in_error=tenant_mismatch", attemptID + " tenant_mismatch ", 1},
		"Nango cannot finish the exchange": {"code=provider_code_123&state=" + strings.Repeat("s", 43), func(fixture *saasSignInFixture) { fixture.provider.completeErr = errors.New("nango") },
			http.StatusSeeOther, "/integrations?saas_sign_in=" + saasSignInIntegrationID + "&saas_sign_in_error=provider_unavailable", attemptID + " provider_unavailable ", 1},
		"Nango answers something that is not a connection": {"code=provider_code_123&state=" + strings.Repeat("s", 43), func(fixture *saasSignInFixture) { fixture.provider.reference = "nango-token-0001" },
			http.StatusSeeOther, "/integrations?saas_sign_in=" + saasSignInIntegrationID + "&saas_sign_in_error=provider_unavailable", attemptID + " provider_unavailable ", 1},
		"the person refused at the provider": {"error=access_denied&state=" + strings.Repeat("s", 43), func(*saasSignInFixture) {},
			http.StatusSeeOther, "/integrations?saas_sign_in=" + saasSignInIntegrationID + "&saas_sign_in_error=provider_access_denied", attemptID + " provider_access_denied ", 0},
		"the state was presented by another session or a second time": {"code=provider_code_123&state=" + strings.Repeat("s", 43), func(fixture *saasSignInFixture) { fixture.store.attempt.Accepted = false },
			http.StatusConflict, "", "", 0},
		"the outcome cannot be recorded": {"code=provider_code_123&state=" + strings.Repeat("s", 43), func(fixture *saasSignInFixture) { fixture.store.finishErr = ErrRepositoryUnavailable },
			http.StatusServiceUnavailable, "", attemptID + " completed " + saasSignInReference, 1},
	} {
		fixture := newSaaSSignInFixture(t)
		fixture.store.attemptFound, fixture.store.attempt = true, accepted
		test.mutate(fixture)
		response := fixture.callback(test.query)
		if response.Code != test.status || response.Header().Get("Location") != test.location || strings.Join(fixture.store.finished, "|") != test.finished || len(fixture.provider.completions) != test.provider {
			t.Fatalf("%s: status=%d location=%q finished=%v completions=%d", name, response.Code, response.Header().Get("Location"), fixture.store.finished, len(fixture.provider.completions))
		}
		if strings.Contains(response.Header().Get("Location"), "saas_connection") {
			t.Fatalf("%s: a failed sign-in answered a connection", name)
		}
	}
}

func TestConnectorHandlerRefusesAHalfConfiguredSignIn(t *testing.T) {
	registry, err := NewConnectorProviderRegistry(map[string]ConnectorOAuthProviderDefinition{
		"slack": {Provider: &connectorLongTailProviderStub{}, RequestedScopes: []string{"nango:auth", "nango:proxy"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:slack"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, signIn := range []*SaaSSignIn{{Store: &saasSignInStoreStub{}}, {Provider: &saasSignInProviderStub{}}} {
		if _, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: &connectorAuthorizationStub{}, Workflows: connectorWorkflowStub{}, Secrets: &connectorSecretStub{}, Registry: registry, SaaSSignIn: signIn}); !errors.Is(err, ErrRepositoryConfiguration) {
			t.Fatalf("half-configured sign-in accepted: %v", err)
		}
	}
}
