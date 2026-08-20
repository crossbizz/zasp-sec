package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type connectorAuthorizationStub struct {
	started      OAuthStart
	consumed     OAuthConsumption
	consumeErr   error
	effect       ConnectorEffectStart
	completed    OAuthCompletion
	resolved     ConnectorEffectResolution
	resolveErr   error
	completeErr  error
	cleanupCount int
	remediation  ConnectorQuarantineRemediation
	quarantine   ConnectorQuarantine
	startErr     error
	activatedID  string
	staged       []PKCECleanupStage
}

func (stub *connectorAuthorizationStub) StartOAuth(_ context.Context, _ RequestIdentity, input OAuthStart) (OAuthAttemptRecord, error) {
	stub.started = input
	if stub.startErr != nil {
		return OAuthAttemptRecord{}, stub.startErr
	}
	return OAuthAttemptRecord{ID: input.AttemptID, IntegrationID: input.IntegrationID, Provider: input.Provider, Status: "pending", ExpiresAt: input.ExpiresAt, CreatedAt: time.Now().UTC()}, nil
}

func (stub *connectorAuthorizationStub) ConsumeOAuth(_ context.Context, identity RequestIdentity, _ []byte, _ []byte) (OAuthConsumption, error) {
	if stub.consumed.ID != "" && stub.consumed.EffectID == "" {
		stub.consumed.EffectID = connectorDeterministicID(identity.Scope, stub.consumed.ID, "oauth-effect")
	}
	return stub.consumed, stub.consumeErr
}
func (stub *connectorAuthorizationStub) BeginConnectorEffect(_ context.Context, _ domain.Scope, input ConnectorEffectStart) (ConnectorEffectRecord, error) {
	stub.effect = input
	return ConnectorEffectRecord{ID: input.ID, IntegrationID: input.IntegrationID, Provider: input.Provider, Operation: input.Operation, Status: "pending", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}, nil
}
func (stub *connectorAuthorizationStub) ResolveConnectorEffect(_ context.Context, _ domain.Scope, input ConnectorEffectResolution) (ConnectorEffectRecord, error) {
	stub.resolved = input
	return ConnectorEffectRecord{ID: input.ID, Status: input.Status, UpdatedAt: time.Now().UTC()}, stub.resolveErr
}
func (*connectorAuthorizationStub) PutConnectorCredential(context.Context, domain.Scope, ConnectorCredentialPut) (ConnectorCredentialRecord, error) {
	return ConnectorCredentialRecord{}, nil
}
func (stub *connectorAuthorizationStub) CompleteOAuth(_ context.Context, _ domain.Scope, input OAuthCompletion) (OAuthCompletionRecord, error) {
	stub.completed = input
	if stub.completeErr != nil {
		return OAuthCompletionRecord{}, stub.completeErr
	}
	return OAuthCompletionRecord{AttemptID: input.AttemptID, ConnectionID: input.ConnectionID, Status: "succeeded", CompletedAt: time.Now().UTC()}, nil
}
func (stub *connectorAuthorizationStub) CompleteConnectorCleanup(context.Context, domain.Scope, string) (ConnectorEffectTransition, error) {
	stub.cleanupCount++
	return ConnectorEffectTransition{ID: stub.effect.ID, Status: "reconciled", UpdatedAt: time.Now().UTC()}, nil
}
func (stub *connectorAuthorizationStub) StagePKCECleanup(_ context.Context, _ domain.Scope, input PKCECleanupStage) (ConnectorEffectRecord, error) {
	stub.staged = append(stub.staged, input)
	return ConnectorEffectRecord{ID: input.ID, IntegrationID: input.IntegrationID, Provider: input.Provider, Operation: "pkce_cleanup", Status: "unknown", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}, nil
}
func (stub *connectorAuthorizationStub) ActivatePKCECleanup(_ context.Context, _ domain.Scope, id string) (ConnectorEffectTransition, error) {
	stub.activatedID = id
	return ConnectorEffectTransition{ID: id, Status: "unknown", UpdatedAt: time.Now().UTC()}, nil
}
func (*connectorAuthorizationStub) CompletePKCECleanup(_ context.Context, _ domain.Scope, id string) (ConnectorEffectTransition, error) {
	return ConnectorEffectTransition{ID: id, Status: "reconciled", UpdatedAt: time.Now().UTC()}, nil
}
func (stub *connectorAuthorizationStub) RemediateConnectorQuarantine(_ context.Context, _ RequestIdentity, input ConnectorQuarantineRemediation) (WorkflowMutationResult, error) {
	stub.remediation = input
	status := "pending_authorization"
	if stub.quarantine.Operation == "revoke" {
		status = "revoking"
	}
	body := json.RawMessage(`{"id":"` + input.IntegrationID + `","status":"` + status + `"}`)
	return WorkflowMutationResult{WorkflowValue: WorkflowValue{Body: body, Version: input.ExpectedVersion + 1}, AuditID: input.AuditID, CorrelationID: input.CorrelationID, ReceiptID: input.ReceiptID}, nil
}
func (stub *connectorAuthorizationStub) GetConnectorQuarantine(_ context.Context, _ domain.Scope, integrationID string) (ConnectorQuarantine, error) {
	if stub.quarantine.ID == "" {
		return ConnectorQuarantine{}, ErrRepositoryNotFound
	}
	return stub.quarantine, nil
}
func (*connectorAuthorizationStub) ClaimReconciliation(context.Context, string, int, int) ([]ConnectorEffectLease, error) {
	return nil, nil
}

type connectorWorkflowStub struct{ value WorkflowValue }

func (stub connectorWorkflowStub) GetWorkflow(context.Context, domain.Scope, string, string) (WorkflowValue, error) {
	return stub.value, nil
}

type connectorSecretStub struct {
	reference string
	material  OAuthSecretMaterial
	taken     bool
	deleted   []string
	deleteErr error
}

func (stub *connectorSecretStub) Acquire(_ context.Context, reference string, candidate OAuthSecretMaterial, _ time.Time) (OAuthSecretMaterial, error) {
	stub.reference = reference
	if stub.material.State == "" {
		stub.material = candidate
	}
	return stub.material, nil
}
func (stub *connectorSecretStub) Consume(_ context.Context, reference string) ([]byte, error) {
	if reference != stub.reference || stub.taken {
		return nil, ErrRepositoryConflict
	}
	stub.taken = true
	return append([]byte(nil), stub.material.Verifier...), nil
}
func (stub *connectorSecretStub) Delete(_ context.Context, reference string) error {
	stub.deleted = append(stub.deleted, reference)
	return stub.deleteErr
}

func TestConnectorAuthorizeCleansPKCEAfterRejectedStart(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	repository := &connectorAuthorizationStub{startErr: ErrRepositoryConflict}
	secrets := &connectorSecretStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue(integrationID, "github")}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorize", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request.Header.Set("Idempotency-Key", "oauth-rejected-start-0001")
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationID}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || len(secrets.deleted) != 1 || secrets.deleted[0] != repository.started.PKCEVerifierReference {
		t.Fatalf("rejected start cleanup status=%d deleted=%#v started=%#v", response.Code, secrets.deleted, repository.started)
	}
}

func TestConnectorAuthorizeActivatesAtomicPKCECleanupWhenProviderURLFails(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	repository := &connectorAuthorizationStub{}
	provider := &connectorProviderStub{authorizationErr: ErrRepositoryUnavailable}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue(integrationID, "github")}, Secrets: &connectorSecretStub{}, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorize", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-authorize-url-failure-0001")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationID}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	wantCleanupID := connectorDeterministicID(identity.Scope, repository.started.AttemptID, "pkce-cleanup")
	if response.Code != http.StatusServiceUnavailable || repository.activatedID != wantCleanupID || len(repository.staged) != 0 {
		t.Fatalf("authorization URL failure status=%d activated=%q want=%q staged=%#v", response.Code, repository.activatedID, wantCleanupID, repository.staged)
	}
}

type connectorProviderStub struct {
	state, challenge, code string
	verifier               []byte
	beforeComplete         func()
	discardCalls           int
	discardErr             error
	authorizationErr       error
}

func (stub *connectorProviderStub) AuthorizationURL(state, challenge string) (string, error) {
	stub.state, stub.challenge = state, challenge
	return "https://github.com/login/oauth/authorize?state=" + url.QueryEscape(state), stub.authorizationErr
}
func (stub *connectorProviderStub) Complete(_ context.Context, _ string, code string, verifier []byte) (ConnectorOAuthGrant, error) {
	if stub.beforeComplete != nil {
		stub.beforeComplete()
	}
	stub.code, stub.verifier = code, append([]byte(nil), verifier...)
	return ConnectorOAuthGrant{ConnectionReference: "ref:github/installation-0001", ProviderSubject: "installation:123", CredentialClass: "github_installation_reference", Metadata: json.RawMessage(`{"installation_id":123,"scopes":["read:org","repo"]}`)}, nil
}
func (*connectorProviderStub) Recover(context.Context, string) (ConnectorOAuthGrant, error) {
	return ConnectorOAuthGrant{}, ErrConnectorOutcomeNotFound
}
func (stub *connectorProviderStub) Discard(context.Context, string, bool) error {
	stub.discardCalls++
	return stub.discardErr
}
func (*connectorProviderStub) Revoke(context.Context, string) error { return nil }

func TestConnectorCallbackMarksEffectUnknownBeforeProviderAndRetainsRecoveryAfterPersistenceFailure(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Now().UTC()
	state := strings.Repeat("s", 43)
	workflow := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	repository := &connectorAuthorizationStub{completeErr: ErrRepositoryUnavailable, consumed: OAuthConsumption{
		ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now,
	}}
	digest := connectorAuthorizationIntentDigest(identity, workflow, repository.consumed.IntegrationID, repository.consumed.ID, "github", map[string]string{}, repository.consumed.RequestedScopes)
	repository.consumed.RequestDigest = jsonDigest(digest[:])
	secrets := &connectorSecretStub{reference: repository.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43))}}
	provider := &connectorProviderStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+state, nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || repository.effect.ID != "" || repository.resolved.ID != "" || repository.completed.AttemptID != repository.consumed.ID || repository.completed.EffectID != repository.consumed.EffectID {
		t.Fatalf("atomic crash-window callback = %d effect=%#v resolution=%#v completion=%#v body=%s", response.Code, repository.effect, repository.resolved, repository.completed, response.Body.String())
	}
}

func TestConnectorAuthorizeCreatesStateBoundPKCEAttemptWithoutSecretResponse(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	repository := &connectorAuthorizationStub{}
	secrets := &connectorSecretStub{}
	provider := &connectorProviderStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{
		Repository: repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue(integrationID, "github")}, Secrets: secrets,
		Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: func() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorize", strings.NewReader(`{}`))
	request.Header.Set("Idempotency-Key", "authorize-integration-0001")
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "authorizeIntegration", PathParameters: map[string]string{"id": integrationID}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "verifier") || strings.Contains(response.Body.String(), "ref:oauth") {
		t.Fatalf("authorize response = %d %s", response.Code, response.Body.String())
	}
	if repository.started.Provider != "github" || repository.started.IntegrationID != integrationID || len(repository.started.SessionDigest) != sha256.Size || len(repository.started.StateDigest) != sha256.Size || len(repository.started.RequestDigest) != sha256.Size || repository.started.PKCEVerifierReference != secrets.reference || len(secrets.material.Verifier) < 43 || provider.state == "" || provider.challenge == "" {
		t.Fatalf("durable authorize inputs = %#v / %#v", repository.started, secrets.material)
	}
	if !strings.Contains(response.Body.String(), repository.started.AttemptID) || !strings.Contains(response.Body.String(), url.QueryEscape(provider.state)) {
		t.Fatalf("authorize response does not identify safe attempt: %s", response.Body.String())
	}
}

func TestConnectorOAuthCallbackConsumesStateBeforeProviderAndRedirectsSafely(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Now().UTC()
	state := strings.Repeat("s", 43)
	verifier := []byte(strings.Repeat("v", 43))
	workflow := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	repository := &connectorAuthorizationStub{consumed: OAuthConsumption{
		ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now,
	}}
	digest := connectorAuthorizationIntentDigest(identity, workflow, repository.consumed.IntegrationID, repository.consumed.ID, "github", map[string]string{}, repository.consumed.RequestedScopes)
	repository.consumed.RequestDigest = jsonDigest(digest[:])
	secrets := &connectorSecretStub{reference: repository.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: verifier}}
	provider := &connectorProviderStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+state, nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/connectors" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("callback response = %d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if !secrets.taken || provider.code != "provider-code-0001" || string(provider.verifier) != string(verifier) || repository.effect.ID != "" || repository.completed.EffectID != repository.consumed.EffectID || repository.completed.AttemptID != repository.consumed.ID || repository.completed.ConnectionReference == "" || provider.discardCalls != 1 || repository.cleanupCount != 1 {
		t.Fatalf("callback durable/provider state = taken:%v provider:%#v effect:%#v completion:%#v", secrets.taken, provider, repository.effect, repository.completed)
	}
	for _, rawQuery := range []string{"code=a&code=b&state=" + state, "code=a&state=" + state + "&redirect_uri=https://evil.test", "code=a&state=" + strings.Repeat("x", 513)} {
		request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?"+rawQuery, nil)
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("hostile callback %q = %d %s", rawQuery, response.Code, response.Body.String())
		}
	}
}

func TestConnectorCallbackRejectsChangedIntentAfterConsumingStateAndDestroysVerifier(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Now().UTC()
	state := strings.Repeat("s", 43)
	original := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	changed := original
	changed.Version++
	repository := &connectorAuthorizationStub{consumed: OAuthConsumption{ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now}}
	digest := connectorAuthorizationIntentDigest(identity, original, repository.consumed.IntegrationID, repository.consumed.ID, "github", map[string]string{}, repository.consumed.RequestedScopes)
	repository.consumed.RequestDigest = jsonDigest(digest[:])
	secrets := &connectorSecretStub{reference: repository.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43))}}
	provider := &connectorProviderStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: changed}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+state, nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !secrets.taken || repository.effect.ID != "" || repository.resolved.Status != "failed" || repository.resolved.ErrorCode != "authorization_intent_changed" || provider.code != "" {
		t.Fatalf("changed intent callback=%d taken=%v effect=%#v resolution=%#v provider_code=%q", response.Code, secrets.taken, repository.effect, repository.resolved, provider.code)
	}
}

func TestConnectorCallbackDoesNotReportIntentConflictUntilConsumedAttemptCleanupIsDurable(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Now().UTC()
	state := strings.Repeat("s", 43)
	original := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	changed := original
	changed.Version++
	repository := &connectorAuthorizationStub{resolveErr: ErrRepositoryUnavailable, consumed: OAuthConsumption{ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now}}
	digest := connectorAuthorizationIntentDigest(identity, original, repository.consumed.IntegrationID, repository.consumed.ID, "github", map[string]string{}, repository.consumed.RequestedScopes)
	repository.consumed.RequestDigest = jsonDigest(digest[:])
	secrets := &connectorSecretStub{reference: repository.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43))}}
	provider := &connectorProviderStub{}
	handler, _ := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: changed}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+state, nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !secrets.taken || repository.resolved.ErrorCode != "authorization_intent_changed" || provider.code != "" {
		t.Fatalf("cleanup failure callback=%d taken=%v resolution=%#v provider_code=%q", response.Code, secrets.taken, repository.resolved, provider.code)
	}
}

func TestConnectorCallbackLeavesDurableCleanupPendingWhenDiscardFails(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Now().UTC()
	state := strings.Repeat("s", 43)
	workflow := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	repository := &connectorAuthorizationStub{consumed: OAuthConsumption{ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now}}
	digest := connectorAuthorizationIntentDigest(identity, workflow, repository.consumed.IntegrationID, repository.consumed.ID, "github", map[string]string{}, repository.consumed.RequestedScopes)
	repository.consumed.RequestDigest = jsonDigest(digest[:])
	secrets := &connectorSecretStub{reference: repository.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43))}}
	provider := &connectorProviderStub{discardErr: ErrRepositoryUnavailable}
	handler, _ := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+state, nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || repository.completed.AttemptID == "" || provider.discardCalls != 1 || repository.cleanupCount != 0 {
		t.Fatalf("discard failure callback=%d completion=%#v provider=%#v cleanup=%d", response.Code, repository.completed, provider, repository.cleanupCount)
	}
}

func TestConnectorQuarantineRemediationRequiresFreshExactIntentAndReturnsDurableReceipt(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	effectID := "pid_70000003-0000-4000-8000-000000000003"
	workflow := WorkflowValue{Body: json.RawMessage(`{"id":"` + integrationID + `","connector_key":"github","name":"GitHub","configuration":{"authorization_mode":"github_app"},"status":"degraded","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:01:00Z"}`), Version: 2}
	repository := &connectorAuthorizationStub{quarantine: ConnectorQuarantine{ID: effectID, IntegrationID: integrationID, Provider: "github", Operation: "authorize", Status: "unknown", Reason: "provider_outcome_ambiguous"}}
	handler, _ := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: &connectorSecretStub{}, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: func() time.Time { return time.Date(2026, 8, 19, 0, 2, 0, 0, time.UTC) }})
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorization-remediation", strings.NewReader(`{"acknowledgement":"provider_grant_revoked_manually"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-quarantine-remediation-0001")
	request.Header.Set("If-Match", `"2"`)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, testCorrelationID))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "remediateIntegrationAuthorization", PathParameters: map[string]string{"id": integrationID}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["status"] != "pending_authorization" || response.Header().Get("ETag") != `"3"` || response.Header().Get("X-Audit-ID") == "" || response.Header().Get("X-Mutation-Receipt-ID") == "" {
		t.Fatalf("remediation response=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if repository.remediation.EffectID != effectID || repository.remediation.IntegrationID != integrationID || repository.remediation.Acknowledgement != "provider_grant_revoked_manually" || repository.remediation.ExpectedVersion != 2 || repository.remediation.IdempotencyKey != "idem-quarantine-remediation-0001" || repository.remediation.AuditID == "" || repository.remediation.ReceiptID == "" {
		t.Fatalf("remediation input = %#v", repository.remediation)
	}
	blockedRepository := &connectorAuthorizationStub{quarantine: repository.quarantine}
	blockedHandler, _ := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: blockedRepository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: &connectorSecretStub{}, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: &connectorProviderStub{discardErr: ErrRepositoryUnavailable}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	blockedRequest := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorization-remediation", strings.NewReader(`{"acknowledgement":"provider_grant_revoked_manually"}`))
	blockedRequest.Header.Set("Content-Type", "application/json")
	blockedRequest.Header.Set("Idempotency-Key", "idem-quarantine-remediation-0002")
	blockedRequest.Header.Set("If-Match", `"2"`)
	blockedRequest = blockedRequest.WithContext(context.WithValue(blockedRequest.Context(), identityContextKey{}, identity))
	blockedRequest = blockedRequest.WithContext(context.WithValue(blockedRequest.Context(), correlationContextKey{}, testCorrelationID))
	blockedRequest = blockedRequest.WithContext(context.WithValue(blockedRequest.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "remediateIntegrationAuthorization", PathParameters: map[string]string{"id": integrationID}}))
	blockedResponse := httptest.NewRecorder()
	blockedHandler.ServeHTTP(blockedResponse, blockedRequest)
	if blockedResponse.Code != http.StatusServiceUnavailable || blockedRepository.remediation.EffectID != "" {
		t.Fatalf("cleanup failure changed DB authority: status=%d remediation=%#v", blockedResponse.Code, blockedRepository.remediation)
	}

	identity.FreshAuthenticated = false
	request = httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorization-remediation", strings.NewReader(`{"acknowledgement":"provider_grant_revoked_manually"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-quarantine-remediation-0001")
	request.Header.Set("If-Match", `"2"`)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, testCorrelationID))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "remediateIntegrationAuthorization", PathParameters: map[string]string{"id": integrationID}}))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("stale-auth remediation = %d %s", response.Code, response.Body.String())
	}
}

func TestConnectorOktaRevocationRemediationDoesNotRequireOAuthEffectManifest(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	integrationID := "pid_70000001-0000-4000-8000-000000000001"
	effectID := "pid_70000003-0000-4000-8000-000000000003"
	workflow := connectorWorkflowValue(integrationID, "okta")
	var body map[string]any
	_ = json.Unmarshal(workflow.Body, &body)
	body["status"] = "degraded"
	workflow.Body, _ = json.Marshal(body)
	provider := &connectorProviderStub{discardErr: ErrRepositoryUnavailable}
	repository := &connectorAuthorizationStub{quarantine: ConnectorQuarantine{ID: effectID, IntegrationID: integrationID, Provider: "okta", Operation: "revoke", ConnectionReference: "ref:okta/refresh/attempt-0001", Status: "unknown", Reason: "provider_revocation_ambiguous"}}
	handler, _ := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: &connectorSecretStub{}, Providers: map[string]ConnectorOAuthProviderDefinition{"okta": {Provider: provider, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"}}, Clock: time.Now})
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integrationID+"/authorization-remediation", strings.NewReader(`{"acknowledgement":"provider_grant_verified_absent"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-okta-revoke-remediation")
	request.Header.Set("If-Match", `"2"`)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), correlationContextKey{}, testCorrelationID))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "remediateIntegrationAuthorization", PathParameters: map[string]string{"id": integrationID}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || provider.discardCalls != 0 || repository.remediation.EffectID != effectID {
		t.Fatalf("Okta revoke remediation status=%d discard=%d remediation=%#v body=%s", response.Code, provider.discardCalls, repository.remediation, response.Body.String())
	}
}

func jsonDigest(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2], result[index*2+1] = alphabet[item>>4], alphabet[item&15]
	}
	return string(result)
}

func TestConnectorCallbackReplayNeverCallsProvider(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	repository := &connectorAuthorizationStub{consumeErr: ErrRepositoryConflict}
	provider := &connectorProviderStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")}, Secrets: &connectorSecretStub{}, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+strings.Repeat("s", 43), nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || provider.code != "" {
		t.Fatalf("replayed callback = %d provider_code=%q body=%s", response.Code, provider.code, response.Body.String())
	}
}

func TestConnectorCallbackConsumesFixedProviderDenialWithoutExchange(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	now := time.Now().UTC()
	state := strings.Repeat("s", 43)
	workflow := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
	repository := &connectorAuthorizationStub{consumed: OAuthConsumption{
		ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: now,
	}}
	digest := connectorAuthorizationIntentDigest(identity, workflow, repository.consumed.IntegrationID, repository.consumed.ID, "github", map[string]string{}, repository.consumed.RequestedScopes)
	repository.consumed.RequestDigest = jsonDigest(digest[:])
	secrets := &connectorSecretStub{reference: repository.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43))}}
	provider := &connectorProviderStub{}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: provider, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?error=access_denied&state="+state, nil)
	request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/connectors" || provider.code != "" || repository.resolved.Status != "failed" || repository.resolved.ErrorCode != "provider_access_denied" {
		t.Fatalf("provider denial = %d location=%q provider=%q resolution=%#v body=%s", response.Code, response.Header().Get("Location"), provider.code, repository.resolved, response.Body.String())
	}
	for _, query := range []string{"error=access_denied&error_description=leak&state=" + state, "error=anything&state=" + state, "error=access_denied&code=code-value&state=" + state} {
		request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?"+query, nil)
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("hostile provider denial %q = %d %s", query, response.Code, response.Body.String())
		}
	}
}

var _ ConnectorAuthorizationRepository = (*connectorAuthorizationStub)(nil)

func connectorWorkflowValue(id, provider string) WorkflowValue {
	return WorkflowValue{Body: json.RawMessage(`{"id":"` + id + `","connector_key":"` + provider + `","status":"pending_authorization","configuration":{}}`), Version: 1}
}
