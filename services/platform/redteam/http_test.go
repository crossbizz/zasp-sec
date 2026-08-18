package redteam

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPAuthorizedLifecycleAndStableError(t *testing.T) {
	store := NewMemoryStore()
	handler, err := NewHTTPHandler(store, func(*http.Request) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	definition := `{"id":"test-1","name":"Tool safety","target_id":"agent-1","categories":["tool_abuse"],"safety":{"environment":"test","credential_class":"read_only","expected_side_effects":["test request"]}}`
	cases := []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/api/v1/tests", definition, http.StatusCreated},
		{http.MethodGet, "/api/v1/tests", "", http.StatusOK},
		{http.MethodGet, "/api/v1/tests/test-1", "", http.StatusOK},
		{http.MethodPatch, "/api/v1/tests/test-1", definition, http.StatusOK},
		{http.MethodPost, "/api/v1/tests/test-1/runs", `{"run_id":"run-1"}`, http.StatusCreated},
		{http.MethodGet, "/api/v1/test-runs", "", http.StatusOK},
		{http.MethodGet, "/api/v1/test-runs/run-1", "", http.StatusOK},
		{http.MethodPost, "/api/v1/test-runs/run-1/cancel", `{}`, http.StatusOK},
	}
	for _, item := range cases {
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
	lab := `{"id":"run-lab-1","environment":"test","credential_class":"test_write","destination":"canary.internal","status":"queued","verdict":"inconclusive"}`
	for _, item := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/api/v1/attack-lab/runs", lab, http.StatusCreated},
		{http.MethodGet, "/api/v1/attack-lab/runs", "", http.StatusOK},
		{http.MethodGet, "/api/v1/attack-lab/runs/run-lab-1", "", http.StatusOK},
		{http.MethodPost, "/api/v1/attack-lab/runs/run-lab-1/rerun", `{"run_id":"run-lab-2"}`, http.StatusCreated},
		{http.MethodPost, "/api/v1/attack-lab/runs/run-lab-1/cancel", `{}`, http.StatusOK},
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
	denied, _ := NewHTTPHandler(store, func(*http.Request) bool { return false })
	response := httptest.NewRecorder()
	denied.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/tests", nil))
	if response.Code != http.StatusForbidden || response.Body.String() != "{\"code\":\"red_team_rejected\",\"message\":\"Red team operation rejected\",\"retryable\":false}\n" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}
