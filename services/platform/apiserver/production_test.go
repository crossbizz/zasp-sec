package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestPostgresProductionSliceSurvivesRepositoryRestartAndIsolatesTenants(t *testing.T) {
	database := newPersistentJSONDatabase(t)
	serverA := newProductionTestServer(t, database)
	client := serverA.Client()

	for _, path := range []string{"/api/v1/home/summary", "/api/v1/agents", "/api/v1/findings", "/api/v1/attack-paths"} {
		response := productRequest(t, client, http.MethodGet, serverA.URL+path, "session-a", "", "")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, response.StatusCode)
		}
		_ = response.Body.Close()
	}
	mutation := productRequest(t, client, http.MethodPatch, serverA.URL+"/api/v1/findings/pid_20000005-0000-4000-8000-000000000005", "session-a", serverA.URL, `{"status":"under_review"}`)
	if mutation.StatusCode != http.StatusOK {
		t.Fatalf("mutation status = %d", mutation.StatusCode)
	}
	_ = mutation.Body.Close()
	serverA.Close()

	serverB := newProductionTestServer(t, database)
	defer serverB.Close()
	persisted := productRequest(t, serverB.Client(), http.MethodGet, serverB.URL+"/api/v1/findings/pid_20000005-0000-4000-8000-000000000005", "session-a", "", "")
	defer persisted.Body.Close()
	var finding map[string]any
	if err := json.NewDecoder(persisted.Body).Decode(&finding); err != nil {
		t.Fatal(err)
	}
	if persisted.StatusCode != http.StatusOK || finding["status"] != "under_review" {
		t.Fatalf("persisted finding = (%d, %#v)", persisted.StatusCode, finding)
	}
	foreign := productRequest(t, serverB.Client(), http.MethodGet, serverB.URL+"/api/v1/findings/pid_20000005-0000-4000-8000-000000000005", "session-b", "", "")
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
	handlers, _, err := NewProductionHandlers(repository, CallbackProviderFunc(func(context.Context, string, string) (string, error) { return "session-a", nil }), CookiePolicy{Secure: true})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/session/callback", strings.NewReader(`{"authorization_code":"code","state":"ssssssssssssssssssssssssssssssss"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handlers.Session.ServeHTTP(response, request)
	cookies := response.Result().Cookies()
	if response.Code != http.StatusNoContent || len(cookies) != 1 {
		t.Fatalf("callback = (%d, %#v)", response.Code, cookies)
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-zasp_session" || cookie.Value != "session-a" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("cookie = %#v", cookie)
	}
}

func newProductionTestServer(t *testing.T, database *persistentJSONDatabase) *httptest.Server {
	t.Helper()
	repository, err := NewPostgresRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	handlers, authenticate, err := NewProductionHandlers(repository, CallbackProviderFunc(func(context.Context, string, string) (string, error) { return "session-a", nil }), CookiePolicy{Secure: true})
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
	mu       sync.Mutex
	sessions map[string]RequestIdentity
	records  map[string]map[string]json.RawMessage
}

func newPersistentJSONDatabase(t *testing.T) *persistentJSONDatabase {
	t.Helper()
	scopeA := testScope(t, "1")
	scopeB := testScope(t, "2")
	principalA, _ := domain.ParseProductID("pid_10000004-0000-4000-8000-000000000004")
	principalB, _ := domain.ParseProductID("pid_20000004-0000-4000-8000-000000000004")
	return &persistentJSONDatabase{
		sessions: map[string]RequestIdentity{
			"session-a": {PrincipalID: principalA, Scope: scopeA, CSRFToken: strings.Repeat("c", 32)},
			"session-b": {PrincipalID: principalB, Scope: scopeB, CSRFToken: strings.Repeat("d", 32)},
		},
		records: map[string]map[string]json.RawMessage{
			scopeKey(scopeA): {
				"home":     json.RawMessage(`{"agent_count":1,"high_risk_paths":1,"verified_changes":0,"blocked_changes":0,"pending_approvals":0,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0,"healthy":true,"attention_required":false}`),
				"agents":   json.RawMessage(`{"items":[{"id":"pid_20000001-0000-4000-8000-000000000001","name":"Support agent","kind":"agent","owner":"security","team":"platform","tags":[],"evidence_id":"pid_20000006-0000-4000-8000-000000000006","first_seen":"2026-08-18T09:00:00Z","last_seen":"2026-08-18T10:00:00Z"}]}`),
				"findings": json.RawMessage(`{"items":[{"id":"pid_20000005-0000-4000-8000-000000000005","source":"posture","title":"Owner missing","severity":"high","status":"open","agent_id":"pid_20000001-0000-4000-8000-000000000001","evidence_ids":["pid_20000006-0000-4000-8000-000000000006"],"risk_factors":[]}]}`),
				"finding:pid_20000005-0000-4000-8000-000000000005": json.RawMessage(`{"id":"pid_20000005-0000-4000-8000-000000000005","source":"posture","title":"Owner missing","severity":"high","status":"open","agent_id":"pid_20000001-0000-4000-8000-000000000001","evidence_ids":["pid_20000006-0000-4000-8000-000000000006"],"risk_factors":[]}`),
				"attack_paths": json.RawMessage(`{"items":[{"id":"pid_20000007-0000-4000-8000-000000000007","entry_id":"pid_20000001-0000-4000-8000-000000000001","sink_id":"pid_20000003-0000-4000-8000-000000000003","node_ids":["pid_20000001-0000-4000-8000-000000000001","pid_20000003-0000-4000-8000-000000000003"],"state":"observed","evidence_ids":["pid_20000006-0000-4000-8000-000000000006"],"blocked_edge":-1}]}`),
			},
			scopeKey(scopeB): {},
		},
	}
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
	case postgresCoreWriteSQL:
		operation, input := arguments[0].(string), arguments[4].(json.RawMessage)
		key := arguments[1].(string) + "/" + arguments[2].(string) + "/" + arguments[3].(string)
		if !strings.HasPrefix(operation, "finding:") {
			return nil, ErrRepositoryNotFound
		}
		value, ok := database.records[key][operation]
		if !ok {
			return nil, ErrRepositoryNotFound
		}
		var finding, patch map[string]any
		_ = json.Unmarshal(value, &finding)
		_ = json.Unmarshal(input, &patch)
		finding["status"] = patch["status"]
		updated, _ := json.Marshal(finding)
		database.records[key][operation] = updated
		var page map[string]any
		_ = json.Unmarshal(database.records[key]["findings"], &page)
		page["items"].([]any)[0] = finding
		database.records[key]["findings"], _ = json.Marshal(page)
		return updated, nil
	default:
		return nil, errors.New("unexpected SQL")
	}
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
