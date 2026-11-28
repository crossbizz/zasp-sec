package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/producttelemetry"
)

type workflowTelemetryRecorder struct {
	scopes []domain.Scope
	events []producttelemetry.Event
}

func (rec *workflowTelemetryRecorder) TryTrack(scope domain.Scope, event producttelemetry.Event) {
	rec.scopes = append(rec.scopes, scope)
	rec.events = append(rec.events, event)
}

func TestWorkflowTelemetryCountsSuccessfulBrowserOperations(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	repository := &riskRepositoryStub{finding: fixtureRiskFinding()}
	rec := &workflowTelemetryRecorder{}
	deps := auditExportCompositionDependencies()
	deps.WorkflowTelemetry, deps.Risk = rec, newRiskTestHandler(t, repository)
	router, err := NewComposition(deps)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestMiddleware(t, router, func(context.Context, Credential) (RequestIdentity, error) { return identity, nil })
	getFinding := func() *http.Request {
		r := httptest.NewRequest("GET", "https://app.zasp.test/api/v1/findings/"+riskFindingID, nil)
		r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "private-session"})
		r.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		return r
	}
	updateFinding := func() *http.Request {
		r := httptest.NewRequest("PATCH", "https://app.zasp.test/api/v1/findings/"+riskFindingID, strings.NewReader(`{"status":"resolved"}`))
		r.Header = getFinding().Header
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", identity.CSRFToken)
		r.Header.Set("Origin", "https://app.zasp.test")
		r.Header.Set("Idempotency-Key", "finding-update-00001")
		r.Header.Set("If-Match", `"2"`)
		return r
	}
	serve := func(r *http.Request, wantStatus int) {
		t.Helper()
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != wantStatus {
			t.Fatalf("%s %s: HTTP %d, want %d: %s", r.Method, r.URL.Path, w.Code, wantStatus, w.Body.String())
		}
	}

	serve(getFinding(), http.StatusOK)
	serve(updateFinding(), http.StatusOK)
	repository.replayed = true
	repository.replay = RiskFindingMutationResult{Body: fixtureRiskFinding(), Version: 3, Replayed: true}
	serve(updateFinding(), http.StatusOK)
	for _, header := range []string{"Purpose", "Sec-Purpose"} {
		prefetch := getFinding()
		prefetch.Header.Set(header, "prefetch")
		serve(prefetch, http.StatusOK)
	}
	nested := getFinding()
	serve(nested.WithContext(context.WithValue(nested.Context(), productRouterContextKey{}, router)), http.StatusOK)
	bearer := getFinding()
	bearer.Header.Del("Cookie")
	bearer.Header.Set("Authorization", "Bearer operator-token")
	serve(bearer, http.StatusOK)
	stale := getFinding()
	stale.Header.Del(expectedScopeHeader)
	serve(stale, http.StatusConflict)
	denied := updateFinding()
	denied.Header.Del("X-CSRF-Token")
	serve(denied, http.StatusForbidden)
	anonymous := getFinding()
	anonymous.Header.Del("Cookie")
	serve(anonymous, http.StatusUnauthorized)
	repository.err = ErrRepositoryNotFound
	serve(getFinding(), http.StatusNotFound)

	want := []producttelemetry.Event{
		{Name: producttelemetry.WorkflowUsage, Fields: []producttelemetry.Field{producttelemetry.TextField("source", "finding_detail_read"), producttelemetry.BooleanField("success", true)}},
		{Name: producttelemetry.WorkflowAction, Fields: []producttelemetry.Field{producttelemetry.TextField("source", "finding_updated"), producttelemetry.BooleanField("success", true)}},
	}
	if !reflect.DeepEqual(rec.events, want) || !reflect.DeepEqual(rec.scopes, []domain.Scope{identity.Scope, identity.Scope}) {
		t.Fatalf("unexpected events or scope: %#v %#v", rec.events, rec.scopes)
	}
}

func TestWorkflowTelemetryCatalogMatchesMountedOperations(t *testing.T) {
	mounted := make(map[string]bool)
	for _, op := range CoreOperations() {
		mounted[op.OperationID] = true
	}
	for _, op := range complianceOperations {
		mounted[op.OperationID] = true
	}
	seen := make(map[string]bool)
	for operation, source := range workflowSources {
		if !mounted[operation] || producttelemetry.WorkflowKind(source) == "" || seen[source] {
			t.Errorf("invalid workflow mapping %q -> %q", operation, source)
		}
		seen[source] = true
	}
}

func TestWorkflowTelemetryAuditCountsOnlyFirstPage(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	rec := &workflowTelemetryRecorder{}
	op := Operation{OperationID: "listAuditEvents", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProductionResponse(w, r, http.StatusOK, []byte(`{"items":[]}`), nil)
	})}
	handler := withWorkflowTelemetry(op, rec)
	for _, query := range []string{"?limit=5", "?limit=5&cursor=private-cursor"} {
		r := httptest.NewRequest("GET", "/api/v1/audit-events"+query, nil)
		handler.ServeHTTP(httptest.NewRecorder(), r.WithContext(context.WithValue(r.Context(), identityContextKey{}, identity)))
	}
	if len(rec.events) != 1 || rec.events[0].Name != producttelemetry.WorkflowUsage {
		t.Fatalf("audit events = %#v", rec.events)
	}
}

func TestProductionPostHogExternalFlow(t *testing.T) {
	repository, err := NewPostgresRepository(newPersistentJSONDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	provider := CallbackProviderFunc(func(context.Context, string, string) (SessionGrant, error) { return SessionGrant{}, nil })
	cookie := fixtureCookiePolicy()
	for _, enabled := range []bool{false, true} {
		if enabled {
			tracker, err := producttelemetry.NewPostHog("https://analytics.example", "phc_fixture")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tracker.Close() })
			cookie.WorkflowTelemetry = tracker
		}
		handlers, _, err := NewProductionHandlers(repository, provider, http.NotFoundHandler(), cookie)
		if err != nil || handlers.WorkflowTelemetry != cookie.WorkflowTelemetry {
			t.Fatal("production telemetry configuration was not mounted", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/external-data-flows", nil)
		response := httptest.NewRecorder()
		handlers.Identity.(*identityHTTPHandler).serveLocalAdministration(response, req, RoutedOperation{OperationID: "getExternalDataFlows"})
		var page struct{ Items []optionalModelFlow }
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil {
			t.Fatalf("external data flows response: %d %s", response.Code, response.Body.String())
		}
		found := false
		for _, item := range page.Items {
			if item.ID == "posthog" {
				found = true
				if !item.Enabled || item.Required || item.Health != "unknown" || len(item.Categories) != 1 || item.Categories[0] != "product_usage" {
					t.Fatalf("PostHog flow: %+v", item)
				}
			}
		}
		if found != enabled {
			t.Fatalf("PostHog flow present = %v, configured = %v", found, enabled)
		}
	}
}
