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
	public := make(map[string]string)
	for path, pathItem := range document.Paths {
		for method, node := range pathItem {
			switch strings.ToUpper(method) {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			default:
				continue
			}
			var documented openAPIOperation
			if err := node.Decode(&documented); err != nil {
				t.Fatalf("decode public %s %s: %v", method, path, err)
			}
			key := strings.ToUpper(method) + " " + path
			if documented.OperationID == "" {
				t.Fatalf("public operation %s has no operationId", key)
			}
			if _, duplicate := public[key]; duplicate {
				t.Fatalf("duplicate public operation %s", key)
			}
			public[key] = documented.OperationID
		}
	}
	if len(seen) != 98 || len(public) != 98 {
		t.Fatalf("mounted/public operation counts = %d/%d, want 98/98", len(seen), len(public))
	}
	for key, operationID := range public {
		if _, mounted := seen[key]; !mounted {
			t.Fatalf("public operation %s (%s) is not mounted", key, operationID)
		}
	}
}

func TestTaskSixCompositionHasExactRiskDiscoveryAndSensorSurfacesWithoutLaterOverclaims(t *testing.T) {
	definitions := make(map[string]OperationDefinition)
	for _, operation := range CoreOperations() {
		definitions[operation.OperationID] = operation
	}
	for _, operationID := range []string{"listFindings", "getFinding", "updateFinding", "acceptFindingRisk", "listAttackPaths", "getAttackPath", "getAttackPathBreakOptions"} {
		definition, ok := definitions[operationID]
		if !ok {
			t.Errorf("risk operation %q is not mounted", operationID)
			continue
		}
		permission := "view"
		if operationID == "updateFinding" || operationID == "acceptFindingRisk" {
			permission = "manage_findings"
		}
		if definition.Permission != permission || !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession", "ProductAPIToken"}) {
			t.Errorf("risk operation %q security/permission = %v/%q", operationID, definition.Security, definition.Permission)
		}
	}
	for _, operationID := range []string{"syncIntegration", "putIntegrationSchedule", "deleteIntegrationSchedule"} {
		definition, ok := definitions[operationID]
		if !ok || definition.Permission != "manage_workflows" || !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession", "ProductAPIToken"}) {
			t.Errorf("discovery mutation %q security/permission = %v/%q exists=%v", operationID, definition.Security, definition.Permission, ok)
		}
	}
	for _, operationID := range []string{"listIntegrationSyncs", "getIntegrationSync", "getIntegrationSchedule", "getIntegrationFreshness"} {
		definition, ok := definitions[operationID]
		if !ok || definition.Permission != "view" || !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession", "ProductAPIToken"}) {
			t.Errorf("discovery read %q security/permission = %v/%q exists=%v", operationID, definition.Security, definition.Permission, ok)
		}
	}
	for _, operationID := range []string{"listSensors", "getSensor", "getSensorCoverage"} {
		definition, ok := definitions[operationID]
		if !ok || definition.Permission != "view" || !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession", "ProductAPIToken"}) {
			t.Errorf("sensor read %q security/permission = %v/%q exists=%v", operationID, definition.Security, definition.Permission, ok)
		}
	}
	for _, operationID := range []string{"createSensorEnrollment", "updateSensor", "deleteSensor", "rotateSensorToken"} {
		definition, ok := definitions[operationID]
		if !ok || definition.Permission != "manage_workflows" || !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession", "ProductAPIToken"}) {
			t.Errorf("sensor mutation %q security/permission = %v/%q exists=%v", operationID, definition.Security, definition.Permission, ok)
		}
	}
	for _, operationID := range []string{
		"updateAgent", "createFindingTicket",
		"listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun",
		"listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun", "rerunAttackLabRun",
		"simulatePolicy", "listPolicyDecisions",
		"listSecurityActions", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
		"globalSearch", "createAIExplanation",
	} {
		if _, mounted := definitions[operationID]; mounted {
			t.Errorf("incomplete operation %q remains mounted", operationID)
		}
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
		"listSecurityActions", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval",
	} {
		if _, mounted := definitions[hidden]; mounted {
			t.Errorf("provider-owned operation %q mounted without a provider adapter", hidden)
		}
	}
}

func TestConnectorOAuthOperationsHaveExactBrowserSecurity(t *testing.T) {
	definitions := make(map[string]OperationDefinition)
	for _, operation := range CoreOperations() {
		definitions[operation.OperationID] = operation
	}
	authorize, ok := definitions["authorizeIntegration"]
	if !ok || authorize.Method != http.MethodPost || authorize.Pattern != "/api/v1/integrations/{id}/authorize" || authorize.Permission != "manage_workflows" || !equalStrings(authorize.Security, []string{"BrowserExpectedScope", "BrowserSession"}) {
		t.Fatalf("authorize definition = %#v, exists=%v", authorize, ok)
	}
	reference, ok := definitions["authorizeIntegrationReference"]
	if !ok || reference.Method != http.MethodPost || reference.Pattern != "/api/v1/integrations/{id}/reference-authorization" || reference.Permission != "manage_workflows" || !equalStrings(reference.Security, []string{"BrowserExpectedScope", "BrowserSession"}) {
		t.Fatalf("reference authorize definition = %#v, exists=%v", reference, ok)
	}
	remediation, ok := definitions["remediateIntegrationAuthorization"]
	if !ok || remediation.Method != http.MethodPost || remediation.Pattern != "/api/v1/integrations/{id}/authorization-remediation" || remediation.Permission != "manage_workflows" || !equalStrings(remediation.Security, []string{"BrowserExpectedScope", "BrowserSession"}) {
		t.Fatalf("remediation definition = %#v, exists=%v", remediation, ok)
	}
	callback, ok := definitions["completeIntegrationOAuthCallback"]
	if !ok || callback.Method != http.MethodGet || callback.Pattern != "/api/v1/integrations/oauth/callback" || callback.Permission != "manage_workflows" || !equalStrings(callback.Security, []string{"BrowserSession"}) {
		t.Fatalf("callback definition = %#v, exists=%v", callback, ok)
	}
}

func TestConnectorOAuthCompositionEnforcesFreshScopedAuthorizeAndSessionBoundCallback(t *testing.T) {
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")})
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureRequestIdentity(t)
	identity.Permissions = []string{"manage_workflows"}
	identity.CredentialKind = CredentialBrowserSession
	identity.FreshAuthenticated = true
	authorize := func(identity RequestIdentity, scoped, csrf bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/pid_70000001-0000-4000-8000-000000000001/authorize", nil)
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
		if scoped {
			request.Header.Set(expectedScopeHeader, expectedScopeValue(identity.Scope))
		}
		if csrf {
			request.Header.Set("Origin", "https://app.zasp.test")
			request.Header.Set("X-CSRF-Token", identity.CSRFToken)
		}
		response := httptest.NewRecorder()
		composition.ServeHTTP(response, request)
		return response
	}
	if response := authorize(identity, false, true); response.Code != http.StatusConflict {
		t.Fatalf("authorize without expected scope = %d %s", response.Code, response.Body.String())
	}
	if response := authorize(identity, true, false); response.Code != http.StatusForbidden {
		t.Fatalf("authorize without CSRF = %d %s", response.Code, response.Body.String())
	}
	stale := identity
	stale.FreshAuthenticated = false
	if response := authorize(stale, true, true); response.Code != http.StatusForbidden {
		t.Fatalf("authorize with stale session = %d %s", response.Code, response.Body.String())
	}
	pat := identity
	pat.CredentialKind = CredentialBearerToken
	if response := authorize(pat, true, true); response.Code != http.StatusUnauthorized {
		t.Fatalf("authorize with PAT = %d %s", response.Code, response.Body.String())
	}
	if response := authorize(identity, true, true); response.Code != http.StatusOK || response.Body.String() != "connector" {
		t.Fatalf("valid authorize = %d %s", response.Code, response.Body.String())
	}
	callbackRequest := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/oauth/callback?code=provider-code-0001&state=provider-state-0001", nil)
	callbackRequest = callbackRequest.WithContext(context.WithValue(callbackRequest.Context(), identityContextKey{}, stale))
	callbackResponse := httptest.NewRecorder()
	composition.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusOK || callbackResponse.Body.String() != "connector" {
		t.Fatalf("session-bound callback without scope/fresh headers = %d %s", callbackResponse.Code, callbackResponse.Body.String())
	}
	callbackRequest = httptest.NewRequest(http.MethodGet, "/api/v1/integrations/oauth/callback?error=access_denied&state=provider-state-0001", nil)
	callbackRequest = callbackRequest.WithContext(context.WithValue(callbackRequest.Context(), identityContextKey{}, pat))
	callbackResponse = httptest.NewRecorder()
	composition.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusUnauthorized {
		t.Fatalf("callback with PAT = %d %s", callbackResponse.Code, callbackResponse.Body.String())
	}
}

func TestBatchThreeCompositionExposesOnlyCompleteDurableOperations(t *testing.T) {
	definitions := make(map[string]OperationDefinition)
	for _, operation := range CoreOperations() {
		definitions[operation.OperationID] = operation
	}

	for _, operationID := range []string{
		"getOrganization",
		"listWorkspaces", "createWorkspace", "getWorkspace", "updateWorkspace",
		"listEnvironments", "createEnvironment", "getEnvironment", "updateEnvironment",
		"listMembers", "listBuiltInRoles", "updateMemberRole",
		"listAPITokens", "createAPIToken", "rotateAPIToken", "revokeAPIToken",
		"listAPITokenRevealGrants", "revealAPIToken", "acknowledgeAPITokenRevealGrant",
		"listAuditEvents",
		"listSessions", "getSession", "listSessionEvents", "revokeSession",
		"listComplianceControls", "listComplianceEvidence",
		"getDataControls", "updateDataControls",
		"getExternalDataFlows",
		"getSystemStatus", "listSystemComponents", "getSystemVersion",
	} {
		t.Run("mounted_"+operationID, func(t *testing.T) {
			definition, ok := definitions[operationID]
			if !ok {
				t.Fatalf("complete durable operation %q is not mounted", operationID)
			}
			if !equalStrings(definition.Security, []string{"BrowserExpectedScope", "BrowserSession"}) || definition.Permission == "" {
				t.Fatalf("operation %q security/permission = %v/%q", operationID, definition.Security, definition.Permission)
			}
		})
	}

	for _, operationID := range []string{
		"listGroupMappings", "updateGroupMappings",
		"listSSOConnections", "createSSOConnection", "deleteSSOConnection", "testSSOConnection",
		"listSCIMConnections", "createSCIMConnection", "deleteSCIMConnection",
		"createAuditExport", "getAuditExport",
		"createComplianceExport", "getComplianceExport",
		"updateExternalDataFlows",
	} {
		t.Run("hidden_"+operationID, func(t *testing.T) {
			if _, mounted := definitions[operationID]; mounted {
				t.Fatalf("incomplete provider/job operation %q is mounted", operationID)
			}
		})
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
		Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector"),
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
		{method: "GET", path: "/api/v1/home/summary", body: "inventory"},
		{method: "GET", path: "/api/v1/agents", body: "inventory"},
		{method: "GET", path: "/api/v1/agents/pid_20000001-0000-4000-8000-000000000001", body: "inventory"},
		{method: "GET", path: "/api/v1/tools", body: "inventory"},
		{method: "GET", path: "/api/v1/identities", body: "inventory"},
		{method: "GET", path: "/api/v1/runtimes", body: "inventory"},
		{method: "GET", path: "/api/v1/policies", body: "workflow"},
		{method: "POST", path: "/api/v1/policies", body: "workflow"},
		{method: "GET", path: "/api/v1/policies/policy-bounded", body: "workflow"},
		{method: "GET", path: "/api/v1/integration-catalog", body: "workflow"},
		{method: "GET", path: "/api/v1/sensors", body: "workflow"},
		{method: "POST", path: "/api/v1/sensors", body: "workflow"},
		{method: "GET", path: "/api/v1/security-agents", body: "workflow"},
		{method: "POST", path: "/api/v1/integrations/pid_70000001-0000-4000-8000-000000000001/authorize", body: "connector"},
		{method: "GET", path: "/api/v1/integrations/oauth/callback", body: "connector"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(test.method, test.path, nil)
		identity := fixtureRequestIdentity(t)
		identity.Permissions = []string{"view", "manage_workflows"}
		identity.CredentialKind = CredentialBrowserSession
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), browserSecurityContextKey{}, browserSecurityContext{publicOrigin: "https://app.zasp.test"}))
		if test.path != "/api/v1/session/bootstrap" && test.path != "/api/v1/session/callback" && test.path != "/api/v1/session/sign-out" && test.path != "/api/v1/integrations/oauth/callback" {
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

	for _, path := range []string{"/internal/health/live", "/api/v1/sensors/heartbeat", "/api/v1/security-actions", "/api/v1/security-agent-runs", "/api/v1/security-agent-approvals", "/api/v1/runtime/events", "/api/v1/policy/bundle", "/api/v1/webhooks/stytch", "/api/v1/search"} {
		response := httptest.NewRecorder()
		composition.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("internal path %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestWorkflowMutationAllowsPATWithoutBrowserCSRF(t *testing.T) {
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")})
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
	composition, err := NewComposition(Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")})
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
	valid := Dependencies{Session: handlerResponse("session"), Identity: handlerResponse("identity"), Inventory: handlerResponse("inventory"), Risk: handlerResponse("risk"), Workflow: handlerResponse("workflow"), Connector: handlerResponse("connector")}
	tests := []struct {
		name         string
		dependencies Dependencies
	}{
		{name: "missing session", dependencies: Dependencies{Identity: valid.Identity, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow, Connector: valid.Connector}},
		{name: "missing identity", dependencies: Dependencies{Session: valid.Session, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow, Connector: valid.Connector}},
		{name: "missing inventory", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Risk: valid.Risk, Workflow: valid.Workflow, Connector: valid.Connector}},
		{name: "missing risk", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Inventory: valid.Inventory, Workflow: valid.Workflow, Connector: valid.Connector}},
		{name: "missing workflow", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Inventory: valid.Inventory, Risk: valid.Risk, Connector: valid.Connector}},
		{name: "missing connector", dependencies: Dependencies{Session: valid.Session, Identity: valid.Identity, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow}},
		{name: "same handler crosses trust boundary", dependencies: Dependencies{Session: valid.Session, Identity: valid.Session, Inventory: valid.Inventory, Risk: valid.Risk, Workflow: valid.Workflow, Connector: valid.Connector}},
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
