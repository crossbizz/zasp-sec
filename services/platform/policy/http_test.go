package policy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPolicyLifecycleAndStableError(t *testing.T) {
	capabilities := Capabilities{Triggers: []string{"tool_call"}, Fields: []string{"tool.name"}, Actions: []Action{ActionMonitor, ActionBlock}}
	handler, err := NewHTTPHandler(NewMemoryStore(), capabilities, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	value := `{"id":"policy-1","name":"Block shell","scope":"environment","trigger":"tool_call","conditions":[{"field":"tool.name","operator":"equals","value":"shell"}],"action":"block","rollout":"enforced","failure_mode":"closed"}`
	for _, item := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/api/v1/policies", value, http.StatusCreated},
		{http.MethodGet, "/api/v1/policies", "", http.StatusOK},
		{http.MethodGet, "/api/v1/policies/policy-1", "", http.StatusOK},
	} {
		request := httptest.NewRequest(item.method, item.path, bytes.NewBufferString(item.body))
		if item.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != item.status {
			t.Fatalf("%s %s status=%d body=%s", item.method, item.path, response.Code, response.Body.String())
		}
	}

	denied, _ := NewHTTPHandler(NewMemoryStore(), capabilities, func(*http.Request) bool { return false })
	response := httptest.NewRecorder()
	denied.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil))
	if response.Code != http.StatusForbidden || response.Body.String() != "{\"code\":\"policy_rejected\",\"message\":\"Policy operation rejected\",\"retryable\":false}\n" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
