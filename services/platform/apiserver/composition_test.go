package apiserver

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
)

func TestCoreCompositionMatchesPublicOpenAPI(t *testing.T) {
	contract, err := os.ReadFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatalf("ReadFile(openapi) error = %v", err)
	}
	paths := make(map[string]struct{})
	pathPattern := regexp.MustCompile(`(?m)^  (/api/v1/[^:]+):$`)
	for _, match := range pathPattern.FindAllSubmatch(contract, -1) {
		paths[string(match[1])] = struct{}{}
	}

	seen := make(map[string]struct{})
	for _, operation := range CoreOperations() {
		key := operation.Method + " " + operation.Pattern
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate mounted operation %s", key)
		}
		seen[key] = struct{}{}
		if _, documented := paths[operation.Pattern]; !documented {
			t.Errorf("mounted operation %s is absent from public OpenAPI", key)
		}
	}
	if len(seen) != 27 {
		t.Fatalf("mounted operation count = %d, want 27", len(seen))
	}
}

func TestNewCompositionMountsOnlyCoreProductOperations(t *testing.T) {
	composition, err := NewComposition(Dependencies{
		Session: handlerResponse("session"), Identity: handlerResponse("identity"),
		Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"),
	})
	if err != nil {
		t.Fatalf("NewComposition() error = %v", err)
	}

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{method: "GET", path: "/api/v1/session/bootstrap", body: "session"},
		{method: "POST", path: "/api/v1/session/callback", body: "session"},
		{method: "POST", path: "/api/v1/session/sign-out", body: "session"},
		{method: "GET", path: "/api/v1/me", body: "identity"},
		{method: "GET", path: "/api/v1/home/summary", body: "risk"},
		{method: "GET", path: "/api/v1/search?q=agent&limit=10", body: "risk"},
		{method: "GET", path: "/api/v1/agents", body: "inventory"},
		{method: "PATCH", path: "/api/v1/agents/pid_20000001-0000-4000-8000-000000000001", body: "inventory"},
		{method: "GET", path: "/api/v1/tools", body: "inventory"},
		{method: "GET", path: "/api/v1/identities", body: "inventory"},
		{method: "GET", path: "/api/v1/runtimes", body: "inventory"},
		{method: "GET", path: "/api/v1/findings", body: "risk"},
		{method: "POST", path: "/api/v1/findings/pid_20000001-0000-4000-8000-000000000001/accept-risk", body: "risk"},
		{method: "GET", path: "/api/v1/attack-paths", body: "risk"},
		{method: "GET", path: "/api/v1/attack-paths/pid_20000001-0000-4000-8000-000000000001/break-options", body: "risk"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		composition.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != http.StatusOK || response.Body.String() != test.body {
			t.Errorf("%s %s = (%d, %q), want (200, %q)", test.method, test.path, response.Code, response.Body.String(), test.body)
		}
	}

	for _, path := range []string{"/internal/health/live", "/api/v1/sensors/heartbeat", "/api/v1/runtime/events", "/api/v1/policy/bundle", "/api/v1/webhooks/stytch"} {
		response := httptest.NewRecorder()
		composition.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("internal path %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestNewCompositionFailsClosedOnInvalidDependencies(t *testing.T) {
	valid := Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk")}
	tests := []struct {
		name         string
		dependencies Dependencies
	}{
		{name: "missing session", dependencies: Dependencies{Identity: valid.Identity, Inventory: valid.Inventory, Risk: valid.Risk}},
		{name: "missing identity", dependencies: Dependencies{Session: valid.Session, Inventory: valid.Inventory, Risk: valid.Risk}},
		{name: "missing inventory", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Risk: valid.Risk}},
		{name: "missing risk", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Inventory: valid.Inventory}},
		{name: "same handler crosses trust boundary", dependencies: Dependencies{Session: valid.Session, Identity: valid.Session, Inventory: valid.Inventory, Risk: valid.Risk}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewComposition(test.dependencies)
			if !errors.Is(err, ErrInvalidComposition) {
				t.Fatalf("NewComposition() error = %v, want %v", err, ErrInvalidComposition)
			}
		})
	}
}

func handlerResponse(body string) http.Handler {
	return &constantHandler{body: body}
}

type constantHandler struct{ body string }

func (handler *constantHandler) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(handler.body))
}
