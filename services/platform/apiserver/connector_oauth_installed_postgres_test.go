package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// installedOAuthSecrets keeps PKCE material by reference, as the secret store
// of the API server does.
type installedOAuthSecrets struct {
	mu       sync.Mutex
	material map[string]OAuthSecretMaterial
	deleted  []string
}

func (store *installedOAuthSecrets) Acquire(_ context.Context, reference string, candidate OAuthSecretMaterial, _ time.Time) (OAuthSecretMaterial, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.material[reference]; found {
		return existing, nil
	}
	store.material[reference] = candidate
	return candidate, nil
}

func (store *installedOAuthSecrets) Consume(_ context.Context, reference string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	material, found := store.material[reference]
	if !found {
		return nil, ErrRepositoryConflict
	}
	delete(store.material, reference)
	return append([]byte(nil), material.Verifier...), nil
}

func (store *installedOAuthSecrets) Delete(_ context.Context, reference string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.material, reference)
	store.deleted = append(store.deleted, reference)
	return nil
}

// installedOAuthProvider stands for a provider adapter (GitHub, Okta): it
// answers an authorization address for the state and grants a connection for
// a code. The provider's own HTTP exchange is not part of this test.
type installedOAuthProvider struct {
	host, class, reference, subject, metadata string
	failComplete                              bool
	completed, discarded                      int
}

func (provider *installedOAuthProvider) AuthorizationURL(state, challenge string) (string, error) {
	return "https://" + provider.host + "/oauth/authorize?" + url.Values{"state": {state}, "code_challenge": {challenge}}.Encode(), nil
}
func (provider *installedOAuthProvider) Complete(_ context.Context, _ string, code string, verifier []byte) (ConnectorOAuthGrant, error) {
	provider.completed++
	if provider.failComplete || code == "" || !connectorPKCEVerifier(verifier) {
		return ConnectorOAuthGrant{}, ErrRepositoryUnavailable
	}
	return ConnectorOAuthGrant{ConnectionReference: provider.reference, ProviderSubject: provider.subject, CredentialClass: provider.class, Metadata: json.RawMessage(provider.metadata)}, nil
}
func (*installedOAuthProvider) Recover(context.Context, string) (ConnectorOAuthGrant, error) {
	return ConnectorOAuthGrant{}, ErrConnectorOutcomeNotFound
}
func (provider *installedOAuthProvider) Discard(context.Context, string, bool) error {
	provider.discarded++
	return nil
}
func (*installedOAuthProvider) Revoke(context.Context, string) error { return nil }

type installedOAuthFactory struct{ provider *installedOAuthProvider }

func (factory installedOAuthFactory) Provider(configuration map[string]string) (ConnectorOAuthProvider, error) {
	if configuration["issuer"] == "" {
		return nil, ErrRepositoryConfiguration
	}
	return factory.provider, nil
}

func installedSQLState(err error) string {
	var provider *pgconn.PgError
	if errors.As(err, &provider) {
		return provider.Code
	}
	return ""
}

// TestConnectorOAuthOnInstalledBaselinePostgres proves on an installed
// baseline that a person can connect GitHub, Okta and a Nango connector
// (Slack) from the browser under current authorization: every statement of
// POST /integrations/{id}/authorize, GET /integrations/oauth/callback and
// POST /integrations/{id}/authorization-remediation runs as the API login
// inside the fence of a checked request, admitted by the API server's
// statement allow-list (completion.sql section ws10_connector_oauth).
//
// It also proves what stays refused: the connector chain's own functions for
// the API login, a statement under another operation, another integration
// than the one of the request path, a callback from another person's session,
// and a second callback for the same state.
//
// The provider side is a fake of the ConnectorOAuthProvider interface. The
// adapters' own HTTP exchanges with GitHub, Okta and Nango are covered, with
// fakes at the HTTP boundary, by the tests of agentsec-api and connectors/.
func TestConnectorOAuthOnInstalledBaselinePostgres(t *testing.T) {
	const startOAuth = `zasp_authorization80.connector_start_oauth(text,text,text,text,text,text,text,bytea,bytea,text,bytea,jsonb,timestamptz,bigint,jsonb,text,text)`
	if dsn := os.Getenv("ZASP_BASELINE_RELEASE_TEST_DSN"); dsn != "" {
		// Recorded before the sections are applied: whether this database
		// already had the section (a rebuilt baseline has it).
		if before, err := pgx.Connect(context.Background(), dsn); err == nil {
			var present, granted bool
			_ = before.QueryRow(context.Background(), `SELECT to_regprocedure($1) IS NOT NULL,has_function_privilege('zasp_svc_api','public.zasp_connector_start_oauth(text,text,text,text,text,text,text,bytea,bytea,text,bytea,jsonb,timestamptz,bigint,jsonb,text,text)','EXECUTE')`, startOAuth).Scan(&present, &granted)
			t.Logf("before the sections: connector OAuth section installed=%t, API login may execute the chain's start function=%t", present, granted)
			_ = before.Close(context.Background())
		}
	}
	baseline := startInstalledBaseline(t)
	ctx := baseline.ctx
	const permissions = "investigate_sessions manage_findings manage_workflows run_tests view"
	administrator := baseline.member("security_admin", strings.Fields(permissions)...)
	other := baseline.member("security_engineer", strings.Fields(permissions)...)
	if err := baseline.product.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	repository, err := NewPostgresRepository(baseline.product)
	if err != nil {
		t.Fatalf("repository: %v", err)
	}
	connectors, err := NewConnectorRepository(baseline.product)
	if err != nil {
		t.Fatalf("connector repository: %v", err)
	}
	github := &installedOAuthProvider{host: "github.com", class: "github_installation_reference", reference: "ref:github/installation-0001", subject: "installation:123", metadata: `{"account_login":"acme","installation_id":123}`}
	okta := &installedOAuthProvider{host: "acme.okta.com", class: "okta_refresh_reference", reference: "ref:okta/refresh-0001", subject: "00u1abcdefghijklmnop", metadata: `{"tenant":"acme.okta.com"}`}
	slack := &connectorLongTailProviderStub{}
	secrets := &installedOAuthSecrets{material: map[string]OAuthSecretMaterial{}}
	handler, err := NewConnectorHTTPHandler(ConnectorHTTPConfig{Repository: connectors, Workflows: repository, Secrets: secrets, Clock: func() time.Time { return time.Now().UTC() }, Providers: map[string]ConnectorOAuthProviderDefinition{
		"github": {Provider: github, RequestedScopes: []string{"actions:read", "contents:read", "metadata:read"}, CredentialClass: "github_installation_reference"},
		"okta":   {Factory: installedOAuthFactory{okta}, RequestedScopes: []string{"offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"}, CredentialClass: "okta_refresh_reference"},
		"slack":  {Provider: slack, RequestedScopes: []string{"nango:auth", "nango:proxy"}, CredentialClass: "nango_connection_reference", AuthorityProvider: "nango:slack"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	workflows, err := newWorkflowHTTPHandler(repository, bytes.Repeat([]byte{0x31}, 32), nil, handler.(*connectorHTTPHandler).registry)
	if err != nil {
		t.Fatal(err)
	}

	// send serves one request of a signed-in person, with the session cookie
	// the browser presents.
	send := func(principal installedPrincipal, operation, method, target string, parameters map[string]string, body string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		if parameters == nil {
			parameters = map[string]string{}
		}
		checked, err := baseline.checked(principal, RoutedOperation{OperationID: operation, PathParameters: parameters})
		if err != nil {
			t.Fatalf("authorize %s: %v", operation, err)
		}
		request := httptest.NewRequest(method, target, strings.NewReader(body)).WithContext(checked)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		request.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "session-secret-" + principal.identity.PrincipalID.String()})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	create := func(body string) string {
		t.Helper()
		response := baseline.serve(workflows, administrator, "createIntegration", http.MethodPost, "/api/v1/integrations", nil, body, map[string]string{"Idempotency-Key": "create-integration-" + baseline.id()[4:]})
		var created struct {
			ID string `json:"id"`
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || !validProductID(created.ID) {
			t.Fatalf("create %s: status=%d body=%s", body, response.Code, response.Body.String())
		}
		return created.ID
	}
	authorize := func(principal installedPrincipal, integration string) (state, attempt string, response *httptest.ResponseRecorder) {
		t.Helper()
		response = send(principal, "authorizeIntegration", http.MethodPost, "/api/v1/integrations/"+integration+"/authorize", map[string]string{"id": integration}, `{}`, map[string]string{"Idempotency-Key": "authorize-" + baseline.id()[4:]})
		var started struct {
			Attempt string `json:"authorization_attempt_id"`
			URL     string `json:"authorization_url"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &started) != nil {
			return "", "", response
		}
		address, err := url.Parse(started.URL)
		if err != nil || address.Scheme != "https" || address.Query().Get("state") == "" || !validProductID(started.Attempt) {
			t.Fatalf("authorization address %q attempt %q", started.URL, started.Attempt)
		}
		return address.Query().Get("state"), started.Attempt, response
	}
	callback := func(principal installedPrincipal, query string) *httptest.ResponseRecorder {
		t.Helper()
		return send(principal, "completeIntegrationOAuthCallback", http.MethodGet, "/api/v1/integrations/oauth/callback?"+query, nil, "", nil)
	}
	scope := []any{baseline.o, baseline.w, baseline.e}
	scoped := func(rest ...any) []any { return append(append([]any{}, scope...), rest...) }
	status := func(integration string) (workflow, typed string) {
		t.Helper()
		if err := baseline.admin.QueryRow(ctx, `SELECT r.body->>'status',i.state FROM zasp_workflow_records r JOIN zasp_integrations i ON (i.organization_id,i.workspace_id,i.environment_id,i.id)=(r.organization_id,r.workspace_id,r.environment_id,r.id) WHERE (r.organization_id,r.workspace_id,r.environment_id,r.kind,r.id)=($1,$2,$3,'integration',$4)`, scoped(integration)...).Scan(&workflow, &typed); err != nil {
			t.Fatalf("integration %s: %v", integration, err)
		}
		return workflow, typed
	}
	attemptStatus := func(attempt string) string {
		t.Helper()
		return baseline.text(`SELECT status FROM zasp_connector_oauth_attempts WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`, scoped(attempt)...)
	}

	// reconcile runs the API server's connector reconciler until the effects
	// of an attempt are settled. The reconciler waits fifteen seconds before
	// it takes an effect; the wait is skipped here by ageing the effect.
	reconciler, err := NewConnectorReconciler(ConnectorReconcilerConfig{Repository: connectors, Workflows: repository, Registry: handler.(*connectorHTTPHandler).registry, Secrets: secrets, Owner: "installed-reconciler", LeaseSeconds: 30, Limit: 25, Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	reconcile := func(attempt string) {
		t.Helper()
		for pass := 0; pass < 20; pass++ {
			baseline.exec(`UPDATE zasp_connector_effects SET updated_at=clock_timestamp()-interval '20 seconds' WHERE (organization_id,workspace_id,environment_id,oauth_attempt_id)=($1,$2,$3,$4) AND status='unknown' AND lease_owner IS NULL`, scoped(attempt)...)
			if err := reconciler.reconcileOnce(ctx); err != nil {
				t.Fatalf("reconciler: %v", err)
			}
			if baseline.text(`SELECT count(*)::text FROM zasp_connector_effects WHERE (organization_id,workspace_id,environment_id,oauth_attempt_id)=($1,$2,$3,$4) AND status='unknown'`, scoped(attempt)...) == "0" {
				return
			}
		}
		t.Fatalf("the reconciler did not settle the effects of attempt %s", attempt)
	}

	// The connector chain stays closed to the API login: it holds no EXECUTE
	// on the chain's functions, and the API server's allow-list refuses the
	// chain statements of a checked request.
	if granted := baseline.text(`SELECT string_agg(p.oid::regprocedure::text,',') FROM pg_proc p WHERE p.pronamespace='public'::regnamespace
 AND p.proname IN('zasp_connector_start_oauth','zasp_connector_consume_oauth','zasp_connector_stage_pkce_cleanup','zasp_connector_activate_pkce_cleanup','zasp_connector_resolve_effect','zasp_connector_complete_oauth','zasp_connector_get_quarantine','zasp_connector_remediate_quarantine')
 AND has_function_privilege('zasp_svc_api',p.oid,'EXECUTE')`); granted != "" {
		t.Fatalf("the API login may execute chain functions: %s", granted)
	}

	connections := map[string]struct {
		body, provider, reference, class string
	}{
		"github": {`{"connector_key":"github","name":"GitHub","configuration":{"authorization_mode":"github_app"}}`, "github", github.reference, github.class},
		"okta":   {`{"connector_key":"okta","name":"Okta","configuration":{"issuer":"https://acme.okta.com"}}`, "okta", okta.reference, okta.class},
		"slack":  {`{"connector_key":"slack","name":"Slack","configuration":{"workspace_label":"Acme"}}`, "nango:slack", "ref:nango/connection/11111111-1111-4111-8111-111111111111", "nango_connection_reference"},
	}
	for _, key := range []string{"github", "okta", "slack"} {
		connection := connections[key]
		integration := create(connection.body)
		path := map[string]string{"id": integration}
		authorizeRoute := RoutedOperation{OperationID: "authorizeIntegration", PathParameters: path}

		// The chain's own statements are refused for the request, by the
		// allow-list and by PostgreSQL.
		checked, err := baseline.checked(administrator, authorizeRoute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := baseline.product.QueryJSON(checked, postgresWorkflowGetSQL, "integration", integration, baseline.o, baseline.w, baseline.e); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("%s: the chain's workflow read under a checked request: %v", key, err)
		}
		if _, err := baseline.product.QueryJSON(checked, postgresConnectorActivatePKCECleanupSQL, scoped(baseline.id())...); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("%s: a chain statement under a checked request: %v", key, err)
		}
		if _, err := baseline.fenced("zasp_svc_api", administrator, authorizeRoute, postgresConnectorActivatePKCECleanupSQL, scoped(baseline.id())...); installedSQLState(err) != "42501" {
			t.Fatalf("%s: PostgreSQL let the API login call a chain function: %v", key, err)
		}

		// Who may start: not a person the model refuses, not a session that
		// is not freshly authenticated.
		baseline.refused[other.identity.PrincipalID.String()+" manage_workflows"] = true
		if _, err := baseline.checked(other, authorizeRoute); err == nil {
			t.Fatalf("%s: a person without the permission was authorized to start", key)
		}
		delete(baseline.refused, other.identity.PrincipalID.String()+" manage_workflows")
		stale := administrator
		stale.identity.FreshAuthenticated = false
		if staleContext, err := baseline.checked(stale, authorizeRoute); err == nil {
			if _, err := repository.GetWorkflow(staleContext, baseline.scope, "integration", integration); !errors.Is(err, ErrAuthorizationDenied) {
				t.Fatalf("%s: a session without fresh authentication read the integration to authorize: %v", key, err)
			}
		}

		// 1. Start: the provider's authorization address, an attempt bound to
		// the person and the browser session, and the two durable effects.
		state, attempt, started := authorize(administrator, integration)
		if started.Code != http.StatusOK || strings.Contains(started.Body.String(), "verifier") {
			t.Fatalf("%s: start authorization: status=%d body=%s", key, started.Code, started.Body.String())
		}
		var principal, provider, effects string
		if err := baseline.admin.QueryRow(ctx, `SELECT a.principal_id,a.provider,(SELECT string_agg(f.operation||':'||f.status,',' ORDER BY f.operation) FROM zasp_connector_effects f WHERE (f.organization_id,f.workspace_id,f.environment_id,f.oauth_attempt_id)=(a.organization_id,a.workspace_id,a.environment_id,a.id))
 FROM zasp_connector_oauth_attempts a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.id)=($1,$2,$3,$4) AND a.integration_id=$5 AND a.status='pending' AND a.session_digest=$6`, scoped(attempt, integration, administrator.binding.Digest[:])...).Scan(&principal, &provider, &effects); err != nil ||
			principal != administrator.identity.PrincipalID.String() || provider != connection.provider || effects != "authorize:pending,pkce_cleanup:unknown" {
			t.Fatalf("%s: attempt principal=%q provider=%q effects=%q err=%v", key, principal, provider, effects, err)
		}

		// What PostgreSQL itself refuses, as the API login inside a fence.
		callbackRoute := RoutedOperation{OperationID: "completeIntegrationOAuthCallback"}
		for name, refusal := range map[string]struct {
			principal installedPrincipal
			route     RoutedOperation
			statement string
			arguments []any
		}{
			"the integration under another operation":        {administrator, RoutedOperation{OperationID: "getIntegration", PathParameters: path}, currentConnectorIntegrationSQL, scoped(administrator.identity.PrincipalID.String(), integration)},
			"another person's principal":                     {administrator, authorizeRoute, currentConnectorIntegrationSQL, scoped(other.identity.PrincipalID.String(), integration)},
			"an integration that is not the request path's":  {administrator, authorizeRoute, currentConnectorIntegrationSQL, scoped(administrator.identity.PrincipalID.String(), baseline.id())},
			"the callback's consumption while starting":      {administrator, authorizeRoute, currentConnectorConsumeOAuthSQL, scoped(administrator.identity.PrincipalID.String(), connectorDigest(state), administrator.binding.Digest[:])},
			"a consumption for another browser session":      {administrator, callbackRoute, currentConnectorConsumeOAuthSQL, scoped(administrator.identity.PrincipalID.String(), connectorDigest(state), other.binding.Digest[:])},
			"the integration of an attempt not yet consumed": {administrator, callbackRoute, currentConnectorIntegrationSQL, scoped(administrator.identity.PrincipalID.String(), integration)},
			"another person's effect in the callback":        {other, callbackRoute, currentConnectorResolveEffectSQL, scoped(other.identity.PrincipalID.String(), connectorDeterministicID(baseline.scope, attempt, "oauth-effect"), "failed", "", json.RawMessage(`{}`), "provider_access_denied")},
			"another person's completion":                    {other, callbackRoute, currentConnectorCompleteOAuthSQL, scoped(other.identity.PrincipalID.String(), attempt, connectorDeterministicID(baseline.scope, attempt, "oauth-effect"), baseline.id(), connection.reference, "subject", baseline.id(), connection.class, json.RawMessage(`{}`), bytes.Repeat([]byte{7}, 32))},
		} {
			if raw, err := baseline.fenced("zasp_svc_api", refusal.principal, refusal.route, refusal.statement, refusal.arguments...); installedSQLState(err) != "42501" {
				t.Fatalf("%s: %s was not refused by PostgreSQL: %s %v", key, name, raw, err)
			}
		}
		// Outside a checked request the API login reaches nothing.
		var raw json.RawMessage
		if err := baseline.login("zasp_svc_api").QueryRow(ctx, currentConnectorIntegrationSQL, scoped(administrator.identity.PrincipalID.String(), integration)...).Scan(&raw); installedSQLState(err) != "42501" {
			t.Fatalf("%s: the API login read an integration outside a checked request: %s %v", key, raw, err)
		}
		// The allow-list refuses the same before PostgreSQL is asked.
		if _, err := baseline.product.QueryJSON(checked, currentConnectorIntegrationSQL, scoped(administrator.identity.PrincipalID.String(), baseline.id())...); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("%s: the allow-list admitted another integration: %v", key, err)
		}
		if _, err := baseline.product.QueryJSON(checked, currentConnectorConsumeOAuthSQL, scoped(administrator.identity.PrincipalID.String(), connectorDigest(state), administrator.binding.Digest[:])...); !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("%s: the allow-list admitted the callback's statement while starting: %v", key, err)
		}

		// 2. The callback from another person's session is refused and the
		// attempt stays open for the person who started it.
		if response := callback(other, url.Values{"state": {state}, "code": {"provider-code-12345678"}}.Encode()); response.Code == http.StatusSeeOther || attemptStatus(attempt) != "pending" {
			t.Fatalf("%s: callback from another session: status=%d attempt=%s", key, response.Code, attemptStatus(attempt))
		}

		// 3. The callback of the person who started: the connection, the
		// credential reference, the active integration and the audit trail.
		response := callback(administrator, url.Values{"state": {state}, "code": {"provider-code-12345678"}}.Encode())
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/connectors" {
			t.Fatalf("%s: callback: status=%d location=%q body=%s", key, response.Code, response.Header().Get("Location"), response.Body.String())
		}
		workflowStatus, typedState := status(integration)
		var reference, class, audit string
		if err := baseline.admin.QueryRow(ctx, `SELECT c.connection_reference,k.credential_class,(SELECT string_agg(DISTINCT x.event_kind,',' ORDER BY x.event_kind) FROM zasp_connector_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.integration_id)=(c.organization_id,c.workspace_id,c.environment_id,c.integration_id))
 FROM zasp_integration_connections c JOIN zasp_connector_credentials k ON (k.organization_id,k.workspace_id,k.environment_id,k.integration_id)=(c.organization_id,c.workspace_id,c.environment_id,c.integration_id)
 WHERE (c.organization_id,c.workspace_id,c.environment_id,c.integration_id)=($1,$2,$3,$4) AND c.state='verified'`, scoped(integration)...).Scan(&reference, &class, &audit); err != nil {
			t.Fatalf("%s: connection: %v", key, err)
		}
		if workflowStatus != "active" || typedState != "active" || attemptStatus(attempt) != "succeeded" || reference != connection.reference || class != connection.class ||
			!strings.Contains(audit, "authorization_started") || !strings.Contains(audit, "authorization_consumed") || !strings.Contains(audit, "authorization_completed") || !strings.Contains(audit, "credential_created") {
			t.Fatalf("%s: status=%s/%s attempt=%s reference=%s class=%s audit=%s", key, workflowStatus, typedState, attemptStatus(attempt), reference, class, audit)
		}
		// Making the integration active moved the Organization's
		// authorization revision, so the request's proof no longer admits its
		// last bookkeeping statement. The effect is left durable for the
		// reconciler, which completes it under its own lease.
		if pending := baseline.text(`SELECT string_agg(operation||':'||status||':'||COALESCE(last_error_code,''),',' ORDER BY operation) FROM zasp_connector_effects WHERE (organization_id,workspace_id,environment_id,oauth_attempt_id)=($1,$2,$3,$4)`, scoped(attempt)...); pending != "authorize:unknown:cleanup_pending,pkce_cleanup:reconciled:" {
			t.Fatalf("%s: effects after the callback: %s", key, pending)
		}
		reconcile(attempt)
		if open := baseline.text(`SELECT count(*)::text FROM zasp_connector_effects WHERE (organization_id,workspace_id,environment_id,oauth_attempt_id)=($1,$2,$3,$4) AND status<>'reconciled'`, scoped(attempt)...); open != "0" {
			t.Fatalf("%s: %s effects of the attempt are not reconciled", key, open)
		}
		if published := baseline.text(`SELECT count(*)::text FROM zasp_workflow_audit WHERE (organization_id,workspace_id,environment_id,resource_id)=($1,$2,$3,$4) AND operation='completeIntegrationOAuth' AND principal_id=$5`, scoped(integration, administrator.identity.PrincipalID.String())...); published != "1" {
			t.Fatalf("%s: %s audit rows for the completed authorization", key, published)
		}

		// 4. The state is taken once.
		if response := callback(administrator, url.Values{"state": {state}, "code": {"provider-code-12345678"}}.Encode()); response.Code == http.StatusSeeOther {
			t.Fatalf("%s: a second callback for the same state was accepted", key)
		}
	}
	if github.completed != 1 || okta.completed != 1 || slack.complete.Code == "" {
		t.Fatalf("provider completions github=%d okta=%d slack=%+v", github.completed, okta.completed, slack.complete)
	}

	// The provider refuses (the person pressed Cancel): the attempt is
	// rejected, the browser returns, and the integration still waits.
	denied := create(`{"connector_key":"okta","name":"Okta refused","configuration":{"issuer":"https://refused.okta.com"}}`)
	state, attempt, started := authorize(administrator, denied)
	if started.Code != http.StatusOK {
		t.Fatalf("start authorization of the refused integration: %d %s", started.Code, started.Body.String())
	}
	if response := callback(administrator, url.Values{"state": {state}, "error": {"access_denied"}}.Encode()); response.Code != http.StatusSeeOther {
		t.Fatalf("refused callback: status=%d body=%s", response.Code, response.Body.String())
	}
	if workflowStatus, typedState := status(denied); workflowStatus != "pending_authorization" || typedState != "pending" || attemptStatus(attempt) != "rejected" || okta.completed != 1 {
		t.Fatalf("after the provider's refusal: status=%s/%s attempt=%s completions=%d", workflowStatus, typedState, attemptStatus(attempt), okta.completed)
	}

	// An outcome nobody can know (the provider failed during the exchange and
	// the reconciler gave up) quarantines the integration; a person clears it
	// with the remediation operation after checking the provider.
	quarantined := create(`{"connector_key":"okta","name":"Okta ambiguous","configuration":{"issuer":"https://ambiguous.okta.com"}}`)
	state, attempt, started = authorize(administrator, quarantined)
	if started.Code != http.StatusOK {
		t.Fatalf("start authorization of the ambiguous integration: %d %s", started.Code, started.Body.String())
	}
	okta.failComplete = true
	if response := callback(administrator, url.Values{"state": {state}, "code": {"provider-code-12345678"}}.Encode()); response.Code == http.StatusSeeOther || attemptStatus(attempt) != "consuming" {
		t.Fatalf("failed exchange: status=%d attempt=%s", response.Code, attemptStatus(attempt))
	}
	okta.failComplete = false
	effect := connectorDeterministicID(baseline.scope, attempt, "oauth-effect")
	token := strings.Repeat("e", 64)
	// The reconciler's last attempt, then its own quarantine function.
	baseline.exec(`UPDATE zasp_connector_effects SET attempt=100,lease_owner='installed-reconciler',lease_token=$5,lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4) AND status='unknown'`, scoped(effect, token)...)
	baseline.exec(`SELECT zasp_connector_quarantine_reconciliation($1,$2,$3,$4,'installed-reconciler',$5,'provider_outcome_ambiguous')`, scoped(effect, token)...)
	if workflowStatus, typedState := status(quarantined); workflowStatus != "degraded" || typedState != "degraded" {
		t.Fatalf("quarantined integration: %s/%s", workflowStatus, typedState)
	}
	version := baseline.text(`SELECT version::text FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=($1,$2,$3,'integration',$4)`, scoped(quarantined)...)
	remediate := func(principal installedPrincipal, integration, key string) *httptest.ResponseRecorder {
		t.Helper()
		return send(principal, "remediateIntegrationAuthorization", http.MethodPost, "/api/v1/integrations/"+integration+"/authorization-remediation", map[string]string{"id": integration},
			`{"acknowledgement":"provider_grant_verified_absent"}`, map[string]string{"Idempotency-Key": key, "If-Match": `"` + version + `"`})
	}
	remediationKey := "remediate-" + quarantined[4:]
	response := remediate(administrator, quarantined, remediationKey)
	if response.Code != http.StatusOK || !validProductID(response.Header().Get("X-Audit-ID")) {
		t.Fatalf("remediation: status=%d body=%s", response.Code, response.Body.String())
	}
	if workflowStatus, typedState := status(quarantined); workflowStatus != "pending_authorization" || typedState != "pending" || attemptStatus(attempt) != "rejected" {
		t.Fatalf("after remediation: %s/%s attempt=%s", workflowStatus, typedState, attemptStatus(attempt))
	}
	if remediated := baseline.text(`SELECT count(*)::text FROM zasp_connector_audit WHERE (organization_id,workspace_id,environment_id,effect_id)=($1,$2,$3,$4) AND event_kind='quarantine_remediated' AND principal_id=$5`, scoped(effect, administrator.identity.PrincipalID.String())...); remediated != "1" {
		t.Fatalf("%s remediation audit rows", remediated)
	}
	// The same request again answers the recorded result and changes nothing.
	if replay := remediate(administrator, quarantined, remediationKey); replay.Code != http.StatusOK || replay.Header().Get("X-Audit-ID") != response.Header().Get("X-Audit-ID") {
		t.Fatalf("remediation replay: status=%d audit=%q want %q", replay.Code, replay.Header().Get("X-Audit-ID"), response.Header().Get("X-Audit-ID"))
	}
	// The remediation statements are refused for another integration.
	remediateRoute := RoutedOperation{OperationID: "remediateIntegrationAuthorization", PathParameters: map[string]string{"id": quarantined}}
	if raw, err := baseline.fenced("zasp_svc_api", administrator, remediateRoute, currentConnectorQuarantineSQL, scoped(administrator.identity.PrincipalID.String(), denied)...); installedSQLState(err) != "42501" {
		t.Fatalf("the quarantine of another integration was read: %s %v", raw, err)
	}
	// After remediation the person can connect again.
	state, attempt, started = authorize(administrator, quarantined)
	if started.Code != http.StatusOK {
		t.Fatalf("start authorization after remediation: %d %s", started.Code, started.Body.String())
	}
	if response := callback(administrator, url.Values{"state": {state}, "code": {"provider-code-12345678"}}.Encode()); response.Code != http.StatusSeeOther || attemptStatus(attempt) != "succeeded" {
		t.Fatalf("callback after remediation: status=%d attempt=%s body=%s", response.Code, attemptStatus(attempt), response.Body.String())
	}
	if intact := baseline.text(`SELECT zasp_baseline.intact()::text`); intact != "true" {
		t.Fatal("the flow left the catalog not intact")
	}
}
