package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestPostgresProductionSliceSurvivesRepositoryRestartAndIsolatesTenants(t *testing.T) {
	database := newPersistentJSONDatabase(t)
	serverA := newProductionTestServer(t, database)
	client := serverA.Client()

	for _, path := range []string{"/api/v1/home/summary", "/api/v1/agents"} {
		response := productRequest(t, client, http.MethodGet, serverA.URL+path, "session-a", "", "")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, response.StatusCode)
		}
		_ = response.Body.Close()
	}
	serverA.Close()

	serverB := newProductionTestServer(t, database)
	defer serverB.Close()
	persisted := productRequest(t, serverB.Client(), http.MethodGet, serverB.URL+"/api/v1/agents", "session-a", "", "")
	defer persisted.Body.Close()
	var inventory map[string]any
	if err := json.NewDecoder(persisted.Body).Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	if persisted.StatusCode != http.StatusOK || len(inventory["items"].([]any)) != 1 {
		t.Fatalf("persisted inventory = (%d, %#v)", persisted.StatusCode, inventory)
	}
	foreign := productRequest(t, serverB.Client(), http.MethodGet, serverB.URL+"/api/v1/agents/pid_20000001-0000-4000-8000-000000000001", "session-b", "", "")
	defer foreign.Body.Close()
	if foreign.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign tenant status = %d, want 404", foreign.StatusCode)
	}
}

func TestProductionHandlersIssueHostOnlySecureSessionCookie(t *testing.T) {
	database := newPersistentJSONDatabase(t)
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	grant := sessionGrant(t, "3")
	handlers, _, err := NewProductionHandlers(repository, CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) { return grant, nil }), fixtureCookiePolicy())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/callback", strings.NewReader(`{"provider_token":"provider-token","state":"ssssssssssssssssssssssssssssssss"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handlers.Session.ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusOK || len(cookies) != 1 || response.Body.String() != "{\"return_to\":\"/\"}\n" {
		t.Fatalf("callback = (%d, %#v)", response.Code, cookies)
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-zasp_session" || cookie.Value == "" || cookie.Value == "session-a" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("cookie = %#v", cookie)
	}
	identity, err := repository.Authenticate(context.Background(), Credential{Kind: CredentialBrowserSession, Value: cookie.Value})
	if err != nil || identity.PrincipalID != grant.PrincipalID || len(database.sessions) != 3 {
		t.Fatalf("created session = (%#v, %v, count=%d)", identity, err, len(database.sessions))
	}
}

func TestPostgresRepositorySeparatesBrowserSessionsAndProductTokens(t *testing.T) {
	database := newPersistentJSONDatabase(t)
	database.productTokens["pat-a"] = database.sessions["session-a"]
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Authenticate(context.Background(), Credential{Kind: CredentialBearerToken, Value: "session-a"}); err == nil {
		t.Fatal("browser session authenticated as product token")
	}
	identity, err := repository.Authenticate(context.Background(), Credential{Kind: CredentialBearerToken, Value: "pat-a"})
	if err != nil || identity.CSRFToken != "" || identity.PrincipalID.IsZero() {
		t.Fatalf("product token identity = (%#v, %v)", identity, err)
	}
}

func TestProductTokenCanReadMeWithoutBrowserCSRF(t *testing.T) {
	database := newPersistentJSONDatabase(t)
	database.productTokens["pat-a"] = database.sessions["session-a"]
	server := newProductionTestServer(t, database)
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer pat-a")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var principal struct {
		ID     string `json:"id"`
		Role   string `json:"role"`
		Active bool   `json:"active"`
	}
	if json.NewDecoder(response.Body).Decode(&principal) != nil || response.StatusCode != http.StatusOK || principal.ID != "pid_10000004-0000-4000-8000-000000000004" || principal.Role != "security_admin" || !principal.Active {
		t.Fatalf("PAT /me = (%d, %#v)", response.StatusCode, principal)
	}
}

func TestProductionBootstrapAdvertisesOnlyMountedDurableCapabilities(t *testing.T) {
	server := newProductionTestServer(t, newPersistentJSONDatabase(t))
	defer server.Close()
	response := productRequest(t, server.Client(), http.MethodGet, server.URL+"/api/v1/session/bootstrap", "session-a", "", "")
	defer response.Body.Close()
	var bootstrap struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(response.Body).Decode(&bootstrap); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !reflect.DeepEqual(bootstrap.Capabilities, []string{"inventory.read", "scope.switch"}) {
		t.Fatalf("bootstrap = (%d, %#v)", response.StatusCode, bootstrap.Capabilities)
	}
}

func TestProductionSessionListsAndSwitchesOnlyDurableAuthorizedScopes(t *testing.T) {
	database := newPersistentJSONDatabase(t)
	server := newProductionTestServer(t, database)
	defer server.Close()
	response := productRequest(t, server.Client(), http.MethodGet, server.URL+"/api/v1/session/scopes", "session-a", "", "")
	defer response.Body.Close()
	var page struct {
		Items []struct {
			WorkspaceID   string `json:"workspace_id"`
			EnvironmentID string `json:"environment_id"`
		} `json:"items"`
	}
	if json.NewDecoder(response.Body).Decode(&page) != nil || response.StatusCode != http.StatusOK || len(page.Items) != 2 {
		t.Fatalf("scope page = (%d, %#v)", response.StatusCode, page)
	}
	body := fmt.Sprintf(`{"workspace_id":%q,"environment_id":%q}`, page.Items[1].WorkspaceID, page.Items[1].EnvironmentID)
	response = productRequest(t, server.Client(), http.MethodPut, server.URL+"/api/v1/session/scope", "session-a", server.URL, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("switch status = %d", response.StatusCode)
	}
	identity, err := (&PostgresRepository{database: database}).Authenticate(context.Background(), Credential{Kind: CredentialBrowserSession, Value: "session-a"})
	if err != nil || identity.Scope.WorkspaceID().String() != page.Items[1].WorkspaceID {
		t.Fatalf("switched identity = (%#v, %v)", identity, err)
	}
	foreign := testScope(t, "2")
	body = fmt.Sprintf(`{"workspace_id":%q,"environment_id":%q}`, foreign.WorkspaceID(), foreign.EnvironmentID())
	response = productRequest(t, server.Client(), http.MethodPut, server.URL+"/api/v1/session/scope", "session-a", server.URL, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign switch status = %d", response.StatusCode)
	}
}

func TestBootstrapPayloadSourceContainsOnlyMountedDurableCapabilities(t *testing.T) {
	bootstrap := bootstrapJSON(fixtureRequestIdentity(t))
	if !reflect.DeepEqual(bootstrap["permissions"], []string{"view"}) {
		t.Fatalf("permissions = %#v", bootstrap["permissions"])
	}
	if !reflect.DeepEqual(bootstrap["capabilities"], []string{"inventory.read", "scope.switch"}) {
		t.Fatalf("capabilities = %#v", bootstrap["capabilities"])
	}
}

func TestProductionProviderFailureReturnsRetryableErrorWithoutFixtureFallback(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/home/summary", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, fixtureRequestIdentity(t)))
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "getHomeSummary", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	(&coreHTTPHandler{repository: unavailableCoreRepository{}, boundary: riskDependency}).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["code"] != "provider_unavailable" || envelope["retryable"] != true || strings.Contains(response.Body.String(), "items") {
		t.Fatalf("provider envelope = %#v", envelope)
	}
}

func TestProductionConflictUsesFixedNondisclosingEnvelope(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/home/summary", nil)
	response := httptest.NewRecorder()
	writeProductionError(response, request, ErrRepositoryConflict)
	if response.Code != http.StatusConflict || decodeErrorCode(t, response) != "operation_conflict" {
		t.Fatalf("conflict = (%d, %s)", response.Code, response.Body.String())
	}
}

type unavailableCoreRepository struct{}

func (unavailableCoreRepository) Read(context.Context, domain.Scope, string) (json.RawMessage, error) {
	return nil, ErrRepositoryUnavailable
}
func (unavailableCoreRepository) Write(context.Context, domain.Scope, string, json.RawMessage) (json.RawMessage, error) {
	return nil, ErrRepositoryUnavailable
}

func newProductionTestServer(t *testing.T, database *persistentJSONDatabase) *httptest.Server {
	t.Helper()
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handlers, authenticate, err := NewProductionHandlers(repository, CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) { return sessionGrant(t, "3"), nil }), fixtureCookiePolicy())
	if err != nil {
		t.Fatal(err)
	}
	composition, err := NewComposition(handlers)
	if err != nil {
		t.Fatal(err)
	}
	var origin string
	secured, err := NewProductMiddleware(ProductSecurity{
		PublicOrigin: "https://placeholder.invalid", MaximumBodyBytes: 16 * 1024, Authenticate: authenticate,
		GenerateCorrelationID: func() string { return "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" },
	}, composition)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if origin != "" && request.Header.Get("Origin") == origin {
			request.Header.Set("Origin", "https://placeholder.invalid")
		}
		secured.ServeHTTP(writer, request)
	}))
	origin = server.URL
	return server
}

func fixtureCookiePolicy() CookiePolicy {
	return CookiePolicy{Secure: true, WorkflowSigningKey: []byte("0123456789abcdef0123456789abcdef"), Clock: func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }}
}

func productRequest(t *testing.T, client *http.Client, method, target, session, origin, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: session})
	if origin != "" {
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type persistentJSONDatabase struct {
	mu               sync.Mutex
	sessions         map[string]RequestIdentity
	productTokens    map[string]RequestIdentity
	records          map[string]map[string]json.RawMessage
	authorizedScopes map[string][]domain.Scope
}

func newPersistentJSONDatabase(t *testing.T) *persistentJSONDatabase {
	t.Helper()
	scopeA := testScope(t, "1")
	scopeB := testScope(t, "2")
	scopeA2 := alternateScope(t, scopeA.OrganizationID())
	principalA, _ := domain.ParseProductID("pid_10000004-0000-4000-8000-000000000004")
	principalB, _ := domain.ParseProductID("pid_20000004-0000-4000-8000-000000000004")
	return &persistentJSONDatabase{
		sessions: map[string]RequestIdentity{
			"session-a": {PrincipalID: principalA, Scope: scopeA, Permissions: []string{"view", "manage_findings"}, CSRFToken: strings.Repeat("c", 32)},
			"session-b": {PrincipalID: principalB, Scope: scopeB, Permissions: []string{"view"}, CSRFToken: strings.Repeat("d", 32)},
		},
		productTokens:    map[string]RequestIdentity{},
		authorizedScopes: map[string][]domain.Scope{principalA.String(): {scopeA, scopeA2}, principalB.String(): {scopeB}},
		records: map[string]map[string]json.RawMessage{
			scopeKey(scopeA): {
				"home":     json.RawMessage(`{"agent_count":1,"high_risk_paths":1,"verified_changes":0,"blocked_changes":0,"pending_approvals":0,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0,"healthy":true,"attention_required":false}`),
				"agents":   json.RawMessage(`{"items":[{"id":"pid_20000001-0000-4000-8000-000000000001","name":"Support agent","kind":"agent","owner":"security","team":"platform","tags":[],"evidence_id":"pid_20000006-0000-4000-8000-000000000006","first_seen":"2026-08-18T09:00:00Z","last_seen":"2026-08-18T10:00:00Z"}]}`),
				"findings": json.RawMessage(`{"items":[{"id":"pid_20000005-0000-4000-8000-000000000005","source":"posture","title":"Owner missing","severity":"high","status":"open","agent_id":"pid_20000001-0000-4000-8000-000000000001","evidence_ids":["pid_20000006-0000-4000-8000-000000000006"],"risk_factors":[]}]}`),
				"finding:pid_20000005-0000-4000-8000-000000000005": json.RawMessage(`{"id":"pid_20000005-0000-4000-8000-000000000005","source":"posture","title":"Owner missing","severity":"high","status":"open","agent_id":"pid_20000001-0000-4000-8000-000000000001","evidence_ids":["pid_20000006-0000-4000-8000-000000000006"],"risk_factors":[]}`),
				"attack_paths": json.RawMessage(`{"items":[{"id":"pid_20000007-0000-4000-8000-000000000007","entry_id":"pid_20000001-0000-4000-8000-000000000001","sink_id":"pid_20000003-0000-4000-8000-000000000003","node_ids":["pid_20000001-0000-4000-8000-000000000001","pid_20000003-0000-4000-8000-000000000003"],"state":"observed","evidence_ids":["pid_20000006-0000-4000-8000-000000000006"],"blocked_edge":-1}]}`),
			},
			scopeKey(scopeB):  {},
			scopeKey(scopeA2): {"agents": json.RawMessage(`{"items":[]}`), "home": json.RawMessage(`{"agent_count":0,"high_risk_paths":0,"verified_changes":0,"blocked_changes":0,"pending_approvals":0,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0,"healthy":true,"attention_required":false}`)},
		},
	}
}

func sessionGrant(t *testing.T, suffix string) SessionGrant {
	t.Helper()
	scope := testScope(t, suffix)
	principal, _ := domain.ParseProductID("pid_" + suffix + "0000004-0000-4000-8000-000000000004")
	return SessionGrant{PrincipalID: principal, Scope: scope, Permissions: []string{"view"}, ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second)}
}

func (database *persistentJSONDatabase) SchemaVersion(context.Context) (string, error) {
	return CoreSchemaVersion, nil
}
func (database *persistentJSONDatabase) QueryJSON(_ context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	switch statement {
	case postgresAuthenticateSessionSQL:
		identity, ok := database.sessions[arguments[0].(string)]
		if !ok {
			return nil, ErrRepositoryAuthentication
		}
		return json.Marshal(identityJSON(identity))
	case postgresAuthenticatePATSQL:
		identity, ok := database.productTokens[arguments[0].(string)]
		if !ok {
			return nil, ErrRepositoryAuthentication
		}
		identity.CSRFToken = ""
		return json.Marshal(identityJSON(identity))
	case postgresCreateSessionSQL:
		token, csrf := arguments[0].(string), arguments[1].(string)
		principal, _ := domain.ParseProductID(arguments[2].(string))
		organization, _ := domain.ParseProductID(arguments[3].(string))
		workspace, _ := domain.ParseProductID(arguments[4].(string))
		environment, _ := domain.ParseProductID(arguments[5].(string))
		scope, _ := domain.NewScope(organization, workspace, environment)
		var permissions []string
		_ = json.Unmarshal(arguments[6].(json.RawMessage), &permissions)
		identity := RequestIdentity{PrincipalID: principal, Scope: scope, Permissions: permissions, CSRFToken: csrf}
		database.sessions[token] = identity
		return json.Marshal(identityJSON(identity))
	case postgresBootstrapSQL:
		principal := arguments[0].(string)
		for _, identity := range database.sessions {
			if identity.PrincipalID.String() == principal {
				return json.Marshal(bootstrapJSON(identity))
			}
		}
		return nil, ErrRepositoryNotFound
	case postgresCoreReadSQL:
		operation := arguments[0].(string)
		key := arguments[1].(string) + "/" + arguments[2].(string) + "/" + arguments[3].(string)
		value, ok := database.records[key][operation]
		if !ok {
			return nil, ErrRepositoryNotFound
		}
		return append(json.RawMessage(nil), value...), nil
	case postgresListScopesSQL:
		principal := arguments[0].(string)
		scopes := database.authorizedScopes[principal]
		items := make([]map[string]string, 0, len(scopes))
		for index, scope := range scopes {
			items = append(items, map[string]string{"organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "label": fmt.Sprintf("Scope %d", index+1)})
		}
		return json.Marshal(map[string]any{"items": items})
	case postgresSwitchScopeSQL:
		token, csrf, principal := arguments[0].(string), arguments[1].(string), arguments[2].(string)
		identity, ok := database.sessions[token]
		if !ok || identity.PrincipalID.String() != principal {
			return nil, ErrRepositoryNotFound
		}
		workspace, _ := domain.ParseProductID(arguments[4].(string))
		environment, _ := domain.ParseProductID(arguments[5].(string))
		target, _ := domain.NewScope(identity.Scope.OrganizationID(), workspace, environment)
		authorized := false
		for _, scope := range database.authorizedScopes[principal] {
			if scope == target {
				authorized = true
			}
		}
		if !authorized {
			return nil, ErrRepositoryNotFound
		}
		identity.Scope = target
		identity.CSRFToken = csrf
		database.sessions[token] = identity
		return json.Marshal(identityJSON(identity))
	default:
		return nil, errors.New("unexpected SQL")
	}
}

func alternateScope(t *testing.T, organization domain.ProductID) domain.Scope {
	t.Helper()
	workspace, _ := domain.ParseProductID("pid_10000022-0000-4000-8000-000000000022")
	environment, _ := domain.ParseProductID("pid_10000023-0000-4000-8000-000000000023")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
func (database *persistentJSONDatabase) Exec(_ context.Context, statement string, arguments ...any) error {
	if statement != postgresRevokeSessionSQL {
		return errors.New("unexpected SQL")
	}
	database.mu.Lock()
	defer database.mu.Unlock()
	delete(database.sessions, arguments[0].(string))
	return nil
}

func testScope(t *testing.T, suffix string) domain.Scope {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_" + suffix + "0000001-0000-4000-8000-000000000001")
	workspace, _ := domain.ParseProductID("pid_" + suffix + "0000002-0000-4000-8000-000000000002")
	environment, _ := domain.ParseProductID("pid_" + suffix + "0000003-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
