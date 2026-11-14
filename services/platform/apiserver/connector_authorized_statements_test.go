package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// Every connector authorization statement is admitted for its own operations,
// scope, principal, browser session and authorized object, and for nothing
// else. The chain statements they replace stay refused.
func TestConnectorAuthorizedStatementContracts(t *testing.T) {
	i := fixtureRequestIdentity(t)
	i.CredentialKind, i.FreshAuthenticated = CredentialBrowserSession, true
	o, w, e, p := i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String()
	const integration, other, effect, attempt = "pid_50000001-0000-4000-8000-000000000001", "pid_50000002-0000-4000-8000-000000000002", "pid_50000003-0000-4000-8000-000000000003", "pid_50000004-0000-4000-8000-000000000004"
	const key = "remediation-key-0001"
	session := [32]byte{1, 2, 3}
	digest := make([]byte, 32)
	metadata := json.RawMessage(`{}`)
	intent := json.RawMessage(`{"resource_id":"` + integration + `","expected_version":2,"body":{"acknowledgement":"provider_grant_verified_absent"}}`)
	expires := time.Now().Add(5 * time.Minute)
	type contract struct {
		name, query string
		operations  []string
		// integrationAt is the zero-based position of the integration
		// argument, or -1; sessionAt of the session digest, or -1.
		integrationAt, sessionAt int
		args                     func() []any
	}
	contracts := []contract{
		{"integration", currentConnectorIntegrationSQL, []string{connectorAuthorizeOperation, connectorCallbackOperation, connectorRemediateOperation}, 4, -1, func() []any { return []any{o, w, e, p, integration} }},
		{"stage pkce cleanup", currentConnectorStagePKCECleanupSQL, []string{connectorAuthorizeOperation}, 5, -1, func() []any {
			return []any{o, w, e, p, effect, integration, "", "github", "ref:oauth/pkce/0001", digest, expires, "oauth_attempt_expiry"}
		}},
		{"activate pkce cleanup", currentConnectorActivatePKCECleanupSQL, []string{connectorAuthorizeOperation, connectorCallbackOperation}, -1, -1, func() []any { return []any{o, w, e, p, effect} }},
		{"start", currentConnectorStartOAuthSQL, []string{connectorAuthorizeOperation}, 5, 7, func() []any {
			return []any{o, w, e, p, attempt, integration, "github", session[:], digest, "ref:oauth/pkce/0001", digest, `["metadata:read"]`, expires, int64(1), metadata, effect, effect}
		}},
		{"consume", currentConnectorConsumeOAuthSQL, []string{connectorCallbackOperation}, -1, 5, func() []any { return []any{o, w, e, p, digest, session[:]} }},
		{"complete pkce cleanup", currentConnectorCompletePKCECleanupSQL, []string{connectorCallbackOperation}, -1, -1, func() []any { return []any{o, w, e, p, effect} }},
		{"resolve effect", currentConnectorResolveEffectSQL, []string{connectorCallbackOperation}, -1, -1, func() []any { return []any{o, w, e, p, effect, "failed", "", metadata, "provider_access_denied"} }},
		{"complete", currentConnectorCompleteOAuthSQL, []string{connectorCallbackOperation}, -1, -1, func() []any {
			return []any{o, w, e, p, attempt, effect, effect, "ref:github/installation-0001", "installation:1", effect, "github_installation_reference", metadata, digest}
		}},
		{"complete cleanup", currentConnectorCompleteCleanupSQL, []string{connectorCallbackOperation}, -1, -1, func() []any { return []any{o, w, e, p, effect} }},
		{"quarantine", currentConnectorQuarantineSQL, []string{connectorRemediateOperation}, 4, -1, func() []any { return []any{o, w, e, p, integration} }},
		{"quarantine replay", currentConnectorQuarantineReplaySQL, []string{connectorRemediateOperation}, -1, -1, func() []any { return []any{o, w, e, p, key, intent} }},
		{"remediate", currentConnectorRemediateQuarantineSQL, []string{connectorRemediateOperation}, 5, -1, func() []any {
			return []any{o, w, e, p, effect, integration, "provider_grant_verified_absent", key, int64(2), intent, metadata, effect, effect, effect}
		}},
	}
	if len(contracts) != len(connectorStatementRules) {
		t.Fatalf("%d contracts for %d rules", len(contracts), len(connectorStatementRules))
	}
	grant := func(operation string) RequestAuthorization {
		g := RequestAuthorization{OperationID: operation, Identity: i, Credential: CredentialBinding{Kind: CredentialBrowserSession, ID: "session", Digest: session}}
		if operation == connectorCallbackOperation {
			g.PathParameters = map[string]string{}
			g.Allowed = []AuthorizationTarget{{Scope: i.Scope, Kind: "environment", ID: e}}
		} else {
			g.PathParameters = map[string]string{"id": integration}
			g.Allowed = []AuthorizationTarget{{Scope: i.Scope, Kind: "integration", ID: integration}}
		}
		return g
	}
	every := []string{connectorAuthorizeOperation, connectorCallbackOperation, connectorRemediateOperation, "getIntegration", "updateIntegration", "deleteIntegration", "authorizeIntegrationReference", "createIntegration"}
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			for _, operation := range every {
				if got, want := authorizationStatementAllowed(grant(operation), c.query, c.args()), stringIn(operation, c.operations...); got != want {
					t.Fatalf("operation %s admitted=%t, want %t", operation, got, want)
				}
			}
			for _, operation := range c.operations {
				for n, name := range []string{"organization", "workspace", "environment", "principal"} {
					args := c.args()
					args[n] = other
					if authorizationStatementAllowed(grant(operation), c.query, args) {
						t.Fatalf("%s: another %s was admitted", operation, name)
					}
				}
				if authorizationStatementAllowed(grant(operation), c.query, append(c.args(), "extra")) || authorizationStatementAllowed(grant(operation), c.query, c.args()[:len(c.args())-1]) {
					t.Fatalf("%s: another argument count was admitted", operation)
				}
				g := grant(operation)
				g.Identity.CredentialKind = CredentialBearerToken
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatalf("%s: an API token was admitted", operation)
				}
				g = grant(operation)
				g.Collection = true
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatalf("%s: a collection request was admitted", operation)
				}
				g = grant(operation)
				g.Allowed = nil
				if authorizationStatementAllowed(g, c.query, c.args()) {
					t.Fatalf("%s: admitted without an allowed object", operation)
				}
				if operation == connectorCallbackOperation {
					// The callback names no object: a path parameter is not its request.
					g = grant(operation)
					g.PathParameters = map[string]string{"id": integration}
					if authorizationStatementAllowed(g, c.query, c.args()) {
						t.Fatal("a callback with a path object was admitted")
					}
				} else {
					g = grant(operation)
					g.Identity.FreshAuthenticated = false
					if authorizationStatementAllowed(g, c.query, c.args()) {
						t.Fatalf("%s: admitted without fresh authentication", operation)
					}
					g = grant(operation)
					g.Allowed[0].Kind = "environment"
					if authorizationStatementAllowed(g, c.query, c.args()) {
						t.Fatalf("%s: admitted without the integration as the allowed object", operation)
					}
					if c.integrationAt >= 0 {
						args := c.args()
						args[c.integrationAt] = other
						if authorizationStatementAllowed(grant(operation), c.query, args) {
							t.Fatalf("%s: an integration that is not the request path's was admitted", operation)
						}
					}
				}
				if c.sessionAt >= 0 {
					args := c.args()
					args[c.sessionAt] = make([]byte, 32)
					if authorizationStatementAllowed(grant(operation), c.query, args) {
						t.Fatalf("%s: another browser session's digest was admitted", operation)
					}
				}
			}
		})
	}
	// A remediation replay for another integration than the path's.
	foreign := json.RawMessage(`{"resource_id":"` + other + `","expected_version":2}`)
	if authorizationStatementAllowed(grant(connectorRemediateOperation), currentConnectorQuarantineReplaySQL, []any{o, w, e, p, key, foreign}) {
		t.Fatal("a replay that names another integration was admitted")
	}
	// The chain statements have no rule for any of the three operations.
	for _, operation := range []string{connectorAuthorizeOperation, connectorCallbackOperation, connectorRemediateOperation} {
		for _, statement := range []string{postgresConnectorStartOAuthSQL, postgresConnectorConsumeOAuthSQL, postgresConnectorStagePKCECleanupSQL, postgresConnectorActivatePKCECleanupSQL, postgresConnectorResolveEffectSQL, postgresConnectorCompleteOAuthSQL, postgresConnectorCompleteCleanupSQL, postgresConnectorGetQuarantineSQL, postgresConnectorRemediateQuarantineSQL, postgresWorkflowGetSQL, postgresWorkflowReplaySQL} {
			if authorizationStatementAllowed(grant(operation), statement, []any{o, w, e, p, integration}) {
				t.Fatalf("%s admitted the chain statement %s", operation, statement)
			}
		}
	}
}

// A checked connector request is routed to the authorized statements with the
// scope and the principal first; a context without a request authorization
// (the reconciler) keeps the chain statement and its arguments.
func TestConnectorCheckedStatementRouting(t *testing.T) {
	i := fixtureRequestIdentity(t)
	scope := connectorScopeArguments(i.Scope)
	statement, arguments := connectorScopedStatement(context.Background(), i.Scope, postgresConnectorActivatePKCECleanupSQL, currentConnectorActivatePKCECleanupSQL, "effect")
	if statement != postgresConnectorActivatePKCECleanupSQL || len(arguments) != 4 || arguments[3] != "effect" {
		t.Fatalf("unchecked: %s %v", statement, arguments)
	}
	for operation, checked := range map[string]bool{connectorAuthorizeOperation: true, connectorCallbackOperation: true, connectorRemediateOperation: true, "deleteIntegration": false, "getIntegration": false} {
		ctx := context.WithValue(context.Background(), requestAuthorizationContextKey{}, RequestAuthorization{OperationID: operation, Identity: i})
		statement, arguments = connectorScopedStatement(ctx, i.Scope, postgresConnectorActivatePKCECleanupSQL, currentConnectorActivatePKCECleanupSQL, "effect")
		if checked && (statement != currentConnectorActivatePKCECleanupSQL || len(arguments) != 5 || arguments[0] != scope[0] || arguments[3] != i.PrincipalID.String() || arguments[4] != "effect") {
			t.Fatalf("%s: %s %v", operation, statement, arguments)
		}
		if !checked && statement != postgresConnectorActivatePKCECleanupSQL {
			t.Fatalf("%s was routed to the connector statement", operation)
		}
	}
}

type connectorCleanupFailure struct {
	*connectorAuthorizationStub
	err error
}

func (stub connectorCleanupFailure) CompleteConnectorCleanup(context.Context, domain.Scope, string) (ConnectorEffectTransition, error) {
	return ConnectorEffectTransition{}, stub.err
}

// Recording the connection makes the integration active, which moves the
// Organization's authorization revision: the request's proof then no longer
// admits the bookkeeping statement that follows. The person is still returned
// to the product, because the connection is recorded and the reconciler
// completes the pending effect. Any other failure of that statement is still
// an error.
func TestConnectorCallbackReturnsTheBrowserWhenOnlyTheBookkeepingIsRefusedByAMovedRevision(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	identity.CredentialKind = CredentialBrowserSession
	for name, test := range map[string]struct {
		err  error
		code int
	}{
		"the revision moved":      {discoveryProviderError(ErrAuthorizationChanged), http.StatusSeeOther},
		"the database is down":    {discoveryProviderError(ErrRepositoryUnavailable), http.StatusServiceUnavailable},
		"another conflict":        {ErrRepositoryConflict, http.StatusConflict},
		"the bookkeeping is done": {nil, http.StatusSeeOther},
	} {
		state := strings.Repeat("s", 43)
		workflow := connectorWorkflowValue("pid_70000001-0000-4000-8000-000000000001", "github")
		stub := &connectorAuthorizationStub{consumed: OAuthConsumption{
			ID: "pid_70000002-0000-4000-8000-000000000002", IntegrationID: "pid_70000001-0000-4000-8000-000000000001", Provider: "github", PrincipalID: identity.PrincipalID.String(), PKCEVerifierReference: "ref:oauth/pkce/attempt-0001", ReturnPath: "/connectors", RequestedScopes: []string{"read:org", "repo"}, ExpiresAt: time.Now().UTC().Add(5 * time.Minute), ConsumedAt: time.Now().UTC(),
		}}
		digest := connectorAuthorizationIntentDigest(identity, workflow, stub.consumed.IntegrationID, stub.consumed.ID, "github", map[string]string{}, stub.consumed.RequestedScopes)
		stub.consumed.RequestDigest = jsonDigest(digest[:])
		var repository ConnectorAuthorizationRepository = stub
		if test.err != nil {
			repository = connectorCleanupFailure{stub, test.err}
		}
		secrets := &connectorSecretStub{reference: stub.consumed.PKCEVerifierReference, material: OAuthSecretMaterial{State: state, Verifier: []byte(strings.Repeat("v", 43))}}
		handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: repository, Workflows: connectorWorkflowStub{value: workflow}, Secrets: secrets, Providers: map[string]ConnectorOAuthProviderDefinition{"github": {Provider: &connectorProviderStub{}, RequestedScopes: []string{"read:org", "repo"}, CredentialClass: "github_installation_reference"}}})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/oauth/callback?code=provider-code-0001&state="+state, nil)
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "browser-session-token-0001"})
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "completeIntegrationOAuthCallback", PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.code || (test.code == http.StatusSeeOther) != (response.Header().Get("Location") == "/connectors") || stub.completed.AttemptID != stub.consumed.ID {
			t.Fatalf("%s: status=%d location=%q completion=%+v body=%s", name, response.Code, response.Header().Get("Location"), stub.completed, response.Body.String())
		}
	}
}
