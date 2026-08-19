package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdministrationTimeCursorCanonicalizesNumericOffsets(t *testing.T) {
	for _, test := range []struct {
		operation string
		item      string
	}{
		{operation: "listAuditEvents", item: `{"id":"audit-1","occurred_at":"2026-08-19T01:02:03.123456+01:00"}`},
		{operation: "listSessionEvents", item: `{"id":"event-1","at":"2026-08-18T17:02:03.123456-07:00"}`},
	} {
		position, ok := administrationCursorPosition(test.operation, []byte(test.item))
		if !ok || position.AfterTime != "2026-08-19T00:02:03.123456Z" {
			t.Fatalf("%s cursor = (%#v, %t)", test.operation, position, ok)
		}
	}
}

func TestBodylessRevocationsRejectEveryWireByte(t *testing.T) {
	identity := fixtureRequestIdentity(t)
	for _, test := range []struct {
		operation string
		target    string
		id        string
	}{
		{operation: "revokeAPIToken", target: "/api/v1/admin/api-tokens/pid_10000005-0000-4000-8000-000000000005", id: "pid_10000005-0000-4000-8000-000000000005"},
		{operation: "revokeSession", target: "/api/v1/sessions/session-live", id: "session-live"},
	} {
		for _, body := range []string{"{}", "\n"} {
			repository := &administrationRecorder{}
			handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
			request := httptest.NewRequest(http.MethodDelete, test.target, strings.NewReader(body))
			request.Header.Set("If-Match", `"1"`)
			request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
			request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: test.operation, PathParameters: map[string]string{"id": test.id}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || repository.mutations != 0 {
				t.Fatalf("%s body %q = %d mutations=%d body=%s", test.operation, body, response.Code, repository.mutations, response.Body.String())
			}
		}
	}
}
