package apiserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCoreCompositionMatchesPublicOpenAPI(t *testing.T) {
	contract, err := os.ReadFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatalf("ReadFile(openapi) error = %v", err)
	}
	var document struct {
		Security []map[string][]string           `yaml:"security"`
		Paths    map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(contract, &document); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}

	seen, operationIDs := make(map[string]struct{}), make(map[string]struct{})
	for _, operation := range CoreOperations() {
		key := operation.Method + " " + operation.Pattern
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate mounted operation %s", key)
		}
		seen[key] = struct{}{}
		node, ok := document.Paths[operation.Pattern][strings.ToLower(operation.Method)]
		if !ok {
			t.Fatalf("mounted operation %s is absent from public OpenAPI", key)
		}
		var documented openAPIOperation
		if err := node.Decode(&documented); err != nil {
			t.Fatalf("decode %s: %v", key, err)
		}
		if documented.OperationID != operation.OperationID {
			t.Errorf("%s operationId = %q, want %q", key, documented.OperationID, operation.OperationID)
		}
		if _, duplicate := operationIDs[operation.OperationID]; duplicate {
			t.Fatalf("duplicate operationId %q", operation.OperationID)
		}
		operationIDs[operation.OperationID] = struct{}{}
		security := documented.Security
		if security == nil {
			security = &document.Security
		}
		if got := securityNames(*security); !equalStrings(got, operation.Security) {
			t.Errorf("%s security = %v, want %v", key, got, operation.Security)
		}
	}
	if len(seen) != 41 {
		t.Fatalf("mounted operation count = %d, want 41", len(seen))
	}
}

func TestBatchTwoCompositionExposesOnlyCompleteDurableOperations(t *testing.T) {
	definitions := make(map[string]OperationDefinition)
	for _, operation := range CoreOperations() {
		definitions[operation.OperationID] = operation
	}
	for _, operationID := range []string{
		"listPolicies", "createPolicy", "getPolicy", "updatePolicy", "deletePolicy", "rolloutPolicy", "disablePolicy",
		"listIntegrationCatalog", "listIntegrations", "createIntegration", "getIntegration", "updateIntegration", "deleteIntegration",
		"listSecurityAgentTemplates", "listSecurityAgents", "createSecurityAgent", "getSecurityAgent", "updateSecurityAgent", "deleteSecurityAgent",
	} {
		definition, ok := definitions[operationID]
		if !ok {
			t.Errorf("complete durable operation %q is not mounted", operationID)
			continue
		}
		if !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession", "ProductAPIToken"}) || definition.Permission == "" {
			t.Errorf("operation %q security/permission = %v/%q", operationID, definition.Security, definition.Permission)
		}
	}
	for _, operationID := range []string{"listWorkflowMutationReceipts", "acknowledgeWorkflowMutationReceipt"} {
		definition, ok := definitions[operationID]
		if !ok {
			t.Errorf("receipt recovery operation %q is not mounted", operationID)
			continue
		}
		if !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession"}) || definition.Permission != "view" {
			t.Errorf("receipt recovery operation %q security/permission = %v/%q", operationID, definition.Security, definition.Permission)
		}
	}
	for _, hidden := range []string{
		"simulatePolicy", "listPolicyDecisions",
		"authorizeIntegration", "syncIntegration", "listIntegrationSyncs", "getIntegrationSync",
		"listSensors", "createSensorEnrollment", "getSensor", "updateSensor", "deleteSensor", "rotateSensorToken", "getSensorCoverage",
		"listSecurityActions", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
	} {
		if _, mounted := definitions[hidden]; mounted {
			t.Errorf("provider-owned operation %q mounted without a provider adapter", hidden)
		}
	}
}

type openAPIOperation struct {
	OperationID string                 `yaml:"operationId"`
	Security    *[]map[string][]string `yaml:"security"`
}

func securityNames(values []map[string][]string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		for name := range value {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestNewCompositionMountsOnlyCoreProductOperations(t *testing.T) {
	composition, err := NewComposition(Dependencies{
		Session: handlerResponse("session"), Identity: handlerResponse("identity"),
		Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"),
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
		{method: "GET", path: "/api/v1/agents", body: "inventory"},
		{method: "GET", path: "/api/v1/agents/pid_20000001-0000-4000-8000-000000000001", body: "inventory"},
		{method: "GET", path: "/api/v1/tools", body: "inventory"},
		{method: "GET", path: "/api/v1/identities", body: "inventory"},
		{method: "GET", path: "/api/v1/runtimes", body: "inventory"},
		{method: "GET", path: "/api/v1/policies", body: "workflow"},
		{method: "POST", path: "/api/v1/policies", body: "workflow"},
		{method: "GET", path: "/api/v1/policies/policy-bounded", body: "workflow"},
		{method: "GET", path: "/api/v1/integration-catalog", body: "workflow"},
		{method: "GET", path: "/api/v1/security-agents", body: "workflow"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, test.path, nil)
		identity := fixtureRequestIdentity(t)
		identity.Permissions = []string{"view", "manage_workflows"}
		identity.CredentialKind = CredentialBrowserSession
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
		if test.path != "/api/v1/session/bootstrap" && test.path != "/api/v1/session/callback" && test.path != "/api/v1/session/sign-out" {
			request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		}
		if test.method == http.MethodPost || test.method == http.MethodPatch || test.method == http.MethodPut || test.method == http.MethodDelete {
			request.Header.Set("Origin", "https://app.zasp.test")
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		}
		composition.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.String() != test.body {
			t.Errorf("%s %s = (%d, %q), want (200, %q)", test.method, test.path, response.Code, response.Body.String(), test.body)
		}
	}

	for _, path := range []string{"/internal/health/live", "/api/v1/sensors", "/api/v1/sensors/heartbeat", "/api/v1/security-actions", "/api/v1/security-agent-runs", "/api/v1/security-agent-approvals", "/api/v1/runtime/events", "/api/v1/policy/bundle", "/api/v1/webhooks/stytch", "/api/v1/search", "/api/v1/findings", "/api/v1/attack-paths"} {
		response := httptest.NewRecorder()
		composition.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("internal path %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestWorkflowMutationAllowsPATWithoutBrowserCSRF(t *testing.T) {
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow")})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(`{"id":"policy-bounded"}`))
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"view", "manage_workflows"}
	identity.CredentialKind = CredentialBearerToken
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	response := httptest.NewRecorder()
	composition.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "workflow" {
		t.Fatalf("PAT mutation = %d %q", response.Code, response.Body.String())
	}
}

func TestUnauthenticatedSessionCallbackDoesNotRequirePreexistingCSRF(t *testing.T) {
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow")})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	composition.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/session/callback", nil))
	if response.Code != http.StatusOK || response.Body.String() != "session" {
		t.Fatalf("callback = %d %q", response.Code, response.Body.String())
	}
}

func TestNewCompositionFailsClosedOnInvalidDependencies(t *testing.T) {
	valid := Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow")}
	tests := []struct {
		name         string
		dependencies Dependencies
	}{
		{name: "missing session", dependencies: Dependencies{Identity: valid.Identity, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow}},
		{name: "missing identity", dependencies: Dependencies{Session: valid.Session, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow}},
		{name: "missing inventory", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Risk: valid.Risk, Workflow: valid.Workflow}},
		{name: "missing risk", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Inventory: valid.Inventory, Workflow: valid.Workflow}},
		{name: "missing workflow", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Inventory: valid.Inventory, Risk: valid.Risk}},
		{name: "same handler crosses trust boundary", dependencies: Dependencies{Session: valid.Session, Identity: valid.Session, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow}},
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
