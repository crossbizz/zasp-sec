package apiserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func complianceReadSurfaceFixture(t *testing.T) (http.Handler, *complianceReadSurface, *RequestIdentity) {
	t.Helper()
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "view_audit", "view_compliance"}
	db := &complianceHTTPDatabase{t: t, identity: identity, readDeadline: time.Now().Add(20 * time.Second).UTC()}
	source, err := NewComplianceRepository(db)
	if err != nil {
		t.Fatal(err)
	}
	surface := &complianceReadSurface{&complianceHTTPHandler{source: source}}
	router, err := NewCompositionWithCompliance(auditExportCompositionDependencies(), nil, surface)
	if err != nil {
		t.Fatal(err)
	}
	mounted, err := NewProductMiddleware(ProductSecurity{PublicOrigin: "https://console.example.test", MaximumBodyBytes: 16384, GenerateCorrelationID: func() string { return testCorrelationID }, Authenticate: func(context.Context, Credential) (RequestIdentity, error) { return identity, nil }}, router)
	if err != nil {
		t.Fatal(err)
	}
	return mounted, surface, &identity
}

// Without export storage the surface serves the checked source reads through
// the compliance repository and registers no export route at all.
func TestComplianceReadSurfaceServesOnlySourceReads(t *testing.T) {
	for _, tc := range []struct {
		method, path, body, want string
		status                   int
	}{
		{"GET", "/api/v1/compliance/controls", "", `"id":"soc2_security-policies"`, 200},
		{"GET", "/api/v1/compliance/evidence?framework=soc2_security", "", `"asset_id":"policy-001"`, 200},
		{"GET", "/api/v1/compliance/evidence/policy/policy-001?source_version=7", "", `"source_version":7`, 200},
		{"POST", "/api/v1/compliance/exports", `{"framework":"soc2_security"}`, `"code":"not_found"`, 404},
		{"GET", "/api/v1/compliance/exports/" + complianceHTTPJobID, "", `"code":"not_found"`, 404},
		{"POST", "/api/v1/compliance/exports/" + complianceHTTPJobID + "/download-grants", `{"format":"human"}`, `"code":"not_found"`, 404},
		{"POST", "/api/v1/compliance/exports/" + complianceHTTPJobID + "/download", `{"format":"human","token":"` + complianceHTTPToken + `"}`, `"code":"not_found"`, 404},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			h, _, id := complianceReadSurfaceFixture(t)
			w := complianceHTTPRequest(t, h, *id, tc.method, tc.path, tc.body, nil)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestComplianceReadSurfaceRegistersExactOperations(t *testing.T) {
	dependencies := auditExportCompositionDependencies()
	base, err := NewComposition(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	surface := &complianceReadSurface{&complianceHTTPHandler{}}
	router, err := NewCompositionWithCompliance(dependencies, nil, surface)
	if err != nil {
		t.Fatal(err)
	}
	baseRoutes, extended := base.(*operationRouter).operations, router.(*operationRouter).operations
	if len(extended) != len(baseRoutes)+1 {
		t.Fatalf("read surface registered %d operations beyond the base", len(extended)-len(baseRoutes))
	}
	served := map[string]bool{}
	for _, operation := range extended {
		if operation.handler == http.Handler(surface) {
			served[operation.operationID] = true
			if operation.method != http.MethodGet || operation.requireCSRF || operation.permission != "view_compliance" {
				t.Fatalf("read operation %s has a mutation contract: %#v", operation.operationID, operation)
			}
		}
		if strings.Contains(operation.operationID, "ComplianceExport") || strings.Contains(operation.operationID, "ComplianceDownload") {
			t.Fatalf("export operation %s registered without storage", operation.operationID)
		}
	}
	if len(served) != 3 || !served["listComplianceControls"] || !served["listComplianceEvidence"] || !served["getComplianceEvidence"] {
		t.Fatalf("read surface operations: %v", served)
	}
}

// A request that reaches the surface under any other operation is refused
// before the handler, which holds no export repository or artifact reader.
func TestComplianceReadSurfaceRefusesOtherOperations(t *testing.T) {
	_, surface, identity := complianceReadSurfaceFixture(t)
	for _, tc := range []struct{ method, operation string }{
		{"POST", "createComplianceExport"}, {"GET", "getComplianceExport"}, {"POST", "createComplianceDownloadGrant"},
		{"POST", "downloadComplianceExport"}, {"POST", "listComplianceControls"}, {"GET", "listAuditEvents"},
	} {
		t.Run(tc.method+" "+tc.operation, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/api/v1/compliance/exports", strings.NewReader(`{}`))
			r.AddCookie(&http.Cookie{Name: browserSessionCookie, Value: "compliance-cookie"})
			ctx := context.WithValue(r.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: tc.operation, PathParameters: map[string]string{"id": complianceHTTPJobID}})
			w := httptest.NewRecorder()
			surface.ServeHTTP(w, r.WithContext(ctx))
			if w.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s identity=%v", w.Code, w.Body.String(), identity.PrincipalID)
			}
		})
	}
	w := httptest.NewRecorder()
	(&complianceReadSurface{}).ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/compliance/controls", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("empty surface status=%d", w.Code)
	}
}

// The storage-free constructor exists only for current authorization; a
// legacy database keeps its administration reads and gets no new surface.
func TestComplianceReadHandlerRequiresCurrentAuthorization(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	key := make([]byte, 32)
	key[0] = 1
	legacy := &complianceHTTPDatabase{t: t, identity: identity}
	if h, err := NewComplianceReadHandler(context.Background(), legacy, key); h != nil || !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("legacy database admitted: %v %v", h, err)
	}
	if h, err := NewComplianceReadHandler(context.Background(), nil, key); h != nil || !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("nil database admitted: %v %v", h, err)
	}
	current, err := NewPostgresJSONDatabase(&authorizationDriverFixture{tx: &authorizationTxFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := current.RequireCurrentAuthorization(); err != nil {
		t.Fatal(err)
	}
	if h, err := NewComplianceReadHandler(context.Background(), current, make([]byte, 32)); h != nil || !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("zero cursor key admitted: %v %v", h, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if h, err := NewComplianceReadHandler(cancelled, current, key); h != nil || !errors.Is(err, ErrRepositoryConfiguration) {
		t.Fatalf("cancelled context admitted: %v %v", h, err)
	}
}
