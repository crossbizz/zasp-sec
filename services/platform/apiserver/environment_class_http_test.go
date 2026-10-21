package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These are application handler contracts, not native permission acceptance.
// The registered-profile/native group separately proves the physical writes.
func TestEnvironmentClassificationHTTPPreservesOptionalPresenceAndExactKeys(t *testing.T) {
	for _, operation := range []string{"createEnvironment", "updateEnvironment"} {
		for _, mode := range []string{"development", "test", "staging", "production", "omitted", "null", "alias", "duplicate", "invalid", "unknown"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				identity := fixtureRequestIdentity(t)
				repository := &administrationRecorder{}
				handler := &identityHTTPHandler{administration: repository, signingKey: []byte("0123456789abcdef0123456789abcdef"), now: time.Now}
				body := `{"name":"Selected environment"`
				method, path := http.MethodPatch, "/api/v1/environments/"+identity.Scope.EnvironmentID().String()
				if operation == "createEnvironment" {
					method, path = http.MethodPost, "/api/v1/environments"
					body += `,"workspace_id":"` + identity.Scope.WorkspaceID().String() + `"`
				}
				valid := true
				expectedClass := ""
				switch mode {
				case "omitted":
				case "null":
					body += `,"environment_class":null`
					valid = false
				case "alias":
					body += `,"Environment_Class":"production"`
					valid = false
				case "duplicate":
					body += `,"environment_class":"development","environment_class":"production"`
					valid = false
				case "invalid":
					body += `,"environment_class":"preview"`
					valid = false
				case "unknown":
					body += `,"unrecognized":"production"`
					valid = false
				default:
					body += `,"environment_class":"` + mode + `"`
					expectedClass = mode
				}
				body += `}`
				request := httptest.NewRequest(method, path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("If-Match", `"1"`)
				request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
				request = request.WithContext(context.WithValue(request.Context(), routedOperationContextKey{}, RoutedOperation{OperationID: operation, PathParameters: map[string]string{"id": identity.Scope.EnvironmentID().String()}}))
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if !valid {
					if response.Code != http.StatusBadRequest || repository.mutations != 0 {
						t.Fatal("invalid or noncanonical optional field reached a writer")
					}
					return
				}
				expectedStatus := http.StatusOK
				if operation == "createEnvironment" {
					expectedStatus = http.StatusCreated
				}
				if response.Code != expectedStatus || repository.mutations != 1 || repository.last.EnvironmentClass != expectedClass {
					t.Fatal("actual environment mutation lost its optional classification")
				}
			})
		}
	}
}
