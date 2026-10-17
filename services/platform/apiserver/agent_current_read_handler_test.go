package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Successor composition coverage added after the initial dependency-blocked
// attempt: this mounts the real handler and repository, not a browser fixture.
func TestAgentCurrentReadActualHandlerUsesEverySelectedRepositoryRoute(t *testing.T) {
	for _, contract := range agentCurrentReadContracts {
		t.Run(contract.operation, func(t *testing.T) {
			grant := agentCurrentReadGrant(t, contract.operation)
			id := grant.PathParameters["id"]
			database := &inventoryJSONDatabase{responses: map[string]json.RawMessage{contract.query: agentCurrentReadPayload(t, contract.operation, id)}}
			repository := &PostgresInventoryRepository{database: database}
			if err := repository.RequireAgentReadProfile(migrations.AgentReadProfileChecksum()); err != nil {
				t.Fatal(err)
			}
			handler, err := newInventoryHTTPHandler(repository, []byte(strings.Repeat("a", 32)))
			if err != nil {
				t.Fatal(err)
			}
			suffix := map[string]string{"getAgent": "", "getAgentCapabilities": "/capabilities", "getAgentRelationships": "/relationships", "listAgentSessions": "/sessions"}[contract.operation]
			path := "/api/v1/agents/" + id + suffix
			if suffix != "" {
				path += "?limit=1"
			}
			request := httptest.NewRequest(http.MethodGet, path, nil)
			ctx := context.WithValue(request.Context(), identityContextKey{}, grant.Identity)
			ctx = context.WithValue(ctx, routedOperationContextKey{}, RoutedOperation{OperationID: contract.operation, PathParameters: map[string]string{"id": id}})
			ctx = context.WithValue(ctx, requestAuthorizationContextKey{}, grant)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request.WithContext(ctx))
			if response.Code != http.StatusOK || database.statement != contract.query || !strings.Contains(response.Body.String(), id) {
				t.Fatal("selected actual Agent handler did not reach its scoped private reader")
			}
		})
	}
}
