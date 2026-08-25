package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryWorkflowSurfaceRoutesOnlyRecoveryOperations(t *testing.T) {
	workflow := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	recovery := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusAccepted) })
	surface, err := NewRecoveryWorkflowSurface(workflow, recovery)
	if err != nil {
		t.Fatal(err)
	}
	for operation, status := range map[string]int{
		"startRecoveryBackup": http.StatusAccepted,
		"getRecoveryRestore":  http.StatusAccepted,
		"listIntegrations":    http.StatusNoContent,
	} {
		request := httptest.NewRequest(http.MethodGet, "https://app.zasp.test/api/v1/test", nil)
		request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{}}))
		response := httptest.NewRecorder()
		surface.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("operation=%s status=%d", operation, response.Code)
		}
	}
}
