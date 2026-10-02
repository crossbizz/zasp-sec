package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type unusedDiscoveryHTTPBoundary struct{ name string }

func (h *unusedDiscoveryHTTPBoundary) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "outside scoped discovery entrypoint: "+h.name, http.StatusNotImplemented)
}

// External identity authentication is controlled. The real middleware/router
// enforce cookie, expected tenant scope, permissions, origin and CSRF. SQL
// still rechecks the current persisted actor and connector on every mutation.
func productDiscoveryHTTP(t *testing.T, ctx context.Context, other ...[]string) (http.Handler, domain.Scope) {
	t.Helper()
	pool, err := pgxpool.New(ctx, os.Getenv("ZASP_P4B_API_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := apiserver.NewDiscoveryRepositoryForAuthority(db, apiserver.DiscoveryDatabaseAuthorityAPI)
	if err != nil {
		t.Fatal("scoped HTTP authority", err)
	}
	var ids []string
	if json.Unmarshal([]byte(os.Getenv("ZASP_P4B_MUTATION_IDS")), &ids) != nil || len(ids) != 5 {
		t.Fatal("HTTP identity fixture")
	}
	if len(other) > 0 {
		if len(other) != 1 || len(other[0]) != 5 {
			t.Fatal("foreign HTTP identity fixture")
		}
		ids = other[0]
	}
	o, _ := domain.ParseProductID(ids[0])
	w, _ := domain.ParseProductID(ids[1])
	e, _ := domain.ParseProductID(ids[2])
	p, _ := domain.ParseProductID(ids[3])
	scope, _ := domain.NewScope(o, w, e)
	var sequence atomic.Int32
	if len(other) > 0 {
		sequence.Store(10000)
	}
	newID := func() string { return fmt.Sprintf("pid_72710000-0000-4000-8000-%012d", sequence.Add(1)) }
	discovery, err := apiserver.NewDiscoveryPublicHTTPHandler(repo, []byte(strings.Repeat("s", 32)), apiserver.DiscoveryPublicHandlerConfig{ParserVersion: "parser_v1", ToolVersion: "tool_v1", NewProductID: func() (string, error) { return newID(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	surface, err := apiserver.NewDiscoveryWorkflowSurface(&unusedDiscoveryHTTPBoundary{"legacy workflow"}, discovery)
	if err != nil {
		t.Fatal(err)
	}
	router, err := apiserver.NewComposition(apiserver.Dependencies{Session: &unusedDiscoveryHTTPBoundary{"session"}, Identity: &unusedDiscoveryHTTPBoundary{"identity"}, Inventory: &unusedDiscoveryHTTPBoundary{"inventory"}, Risk: &unusedDiscoveryHTTPBoundary{"risk"}, Workflow: surface, Connector: &unusedDiscoveryHTTPBoundary{"connector"}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := apiserver.NewProductMiddleware(apiserver.ProductSecurity{PublicOrigin: "https://app.zasp.test", MaximumBodyBytes: 65536, GenerateCorrelationID: newID, Authenticate: func(_ context.Context, c apiserver.Credential) (apiserver.RequestIdentity, error) {
		if c.Kind != apiserver.CredentialBrowserSession || c.Value != "owned-p4b-session" {
			return apiserver.RequestIdentity{}, apiserver.ErrAuthenticationRequired
		}
		return apiserver.RequestIdentity{PrincipalID: p, Scope: scope, Permissions: []string{"view", "manage_workflows"}, CSRFToken: strings.Repeat("c", 32)}, nil
	}}, router)
	if err != nil {
		t.Fatal(err)
	}
	return handler, scope
}

func productManualHTTP(t *testing.T, handler http.Handler, scope domain.Scope, integration string) string {
	t.Helper()
	request := func(csrf, expected string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "https://app.zasp.test/api/v1/integrations/"+integration+"/sync", strings.NewReader(`{}`))
		r.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: "owned-p4b-session"})
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://app.zasp.test")
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Zasp-Expected-Scope", expected)
		r.Header.Set("If-Match", `"1"`)
		r.Header.Set("Idempotency-Key", "owned-p4b-manual-http")
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		return out
	}
	expected := strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, "/")
	if r := request("wrong", expected); r.Code != http.StatusForbidden {
		t.Fatal("CSRF not enforced", r.Code, r.Body.String())
	}
	if r := request(strings.Repeat("c", 32), expected+"-foreign"); r.Code < 400 {
		t.Fatal("tenant precondition not enforced", r.Code)
	}
	r := request(strings.Repeat("c", 32), expected)
	var sync apiserver.IntegrationSync
	if r.Code != http.StatusAccepted || json.Unmarshal(r.Body.Bytes(), &sync) != nil || sync.TriggerKind != "manual" || sync.Status != "queued" || sync.Attempt != 0 {
		t.Fatal("manual HTTP admission", r.Code, r.Body.String())
	}
	replay := request(strings.Repeat("c", 32), expected)
	var repeated apiserver.IntegrationSync
	if replay.Code != http.StatusAccepted || json.Unmarshal(replay.Body.Bytes(), &repeated) != nil || repeated.ID != sync.ID {
		t.Fatal("manual HTTP replay", replay.Code, replay.Body.String())
	}
	return sync.ID
}

func productSyncHTTP(t *testing.T, handler http.Handler, scope domain.Scope, integration, syncID string) apiserver.IntegrationSync {
	t.Helper()
	out := productSyncHTTPResponse(handler, scope, integration, syncID)
	var value apiserver.IntegrationSync
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &value) != nil || value.ID != syncID || value.IntegrationID != integration {
		t.Fatal("actual HTTP sync readback", out.Code, out.Body.String())
	}
	return value
}

func productSyncHTTPResponse(handler http.Handler, scope domain.Scope, integration, syncID string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/integrations/"+integration+"/syncs/"+syncID, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-zasp_session", Value: "owned-p4b-session"})
	r.Header.Set("X-Zasp-Expected-Scope", strings.Join([]string{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()}, "/"))
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, r)
	return out
}
