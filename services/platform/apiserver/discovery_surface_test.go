package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryWorkflowSurfaceDispatchesOnlyDiscoveryLifecycle(t *testing.T) {
	workflowCalls, discoveryCalls := 0, 0
	workflow := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		workflowCalls++
		writer.WriteHeader(http.StatusNoContent)
	})
	discovery := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		discoveryCalls++
		writer.WriteHeader(http.StatusAccepted)
	})
	surface, err := NewDiscoveryWorkflowSurface(workflow, discovery)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"syncIntegration", "listIntegrationSyncs", "getIntegrationSync", "getIntegrationSchedule", "putIntegrationSchedule", "deleteIntegrationSchedule", "getIntegrationFreshness"} {
		request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/", nil)
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		surface.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("operation=%s status=%d", operation, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/", nil)
	request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: "listIntegrations", PathParameters: map[string]string{}}))
	response := httptest.NewRecorder()
	surface.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || discoveryCalls != 7 || workflowCalls != 1 {
		t.Fatalf("status=%d discovery=%d workflow=%d", response.Code, discoveryCalls, workflowCalls)
	}
}
