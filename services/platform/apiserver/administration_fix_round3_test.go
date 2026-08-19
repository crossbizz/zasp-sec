package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceDetailTargetsMustMatchTheActiveExactScopeBeforeRepositoryAccess(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	foreignWorkspace := "pid_20000002-0000-4000-8000-000000000002"
	for _, test := range []struct {
		operation string
		method    string
		body      string
	}{
		{operation: "getWorkspace", method: http.MethodGet},
		{operation: "updateWorkspace", method: http.MethodPatch, body: `{"name":"Foreign"}`},
	} {
		repository := &administrationRecorder{}
		handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
		request := httptest.NewRequest(test.method, "/api/v1/workspaces/"+foreignWorkspace, strings.NewReader(test.body))
		if test.body != "" {
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", `"1"`)
		}
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: test.operation, PathParameters: map[string]string{"id": foreignWorkspace}}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || repository.reads != 0 || repository.mutations != 0 {
			t.Fatalf("%s foreign target = %d reads=%d mutations=%d body=%s", test.operation, response.Code, repository.reads, repository.mutations, response.Body.String())
		}
	}
}
