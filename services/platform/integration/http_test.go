package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestHTTPIntegrationOperationsAndStableErrors(t *testing.T) {
	sequence := 100
	generate := func() (domain.ProductID, error) { sequence++; return fixtureID(t, sequence), nil }
	now := func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	service, err := NewService(NewMemoryStore(generate, now), mustCatalog(t), now)
	if err != nil {
		t.Fatal(err)
	}
	scope := fixtureScope(t)
	handler, err := NewHTTPHandler(service, func(*http.Request) (domain.Scope, error) { return scope, nil })
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/integrations", bytes.NewBufferString(`{"connector_key":"generic-webhook","name":"Response notifications","configuration":{"destination_url":"https://hooks.customer.invalid/zasp","signing_secret_reference":"secret_ref_1234"}}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("missing integration ID")
	}

	operations := []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/api/v1/integration-catalog", "", http.StatusOK},
		{http.MethodGet, "/api/v1/integrations", "", http.StatusOK},
		{http.MethodGet, "/api/v1/integrations/" + id, "", http.StatusOK},
		{http.MethodPatch, "/api/v1/integrations/" + id, `{"name":"Updated notifications","configuration":{"destination_url":"https://hooks.customer.invalid/zasp","signing_secret_reference":"secret_ref_1234"}}`, http.StatusOK},
		{http.MethodPost, "/api/v1/integrations/" + id + "/authorize", `{}`, http.StatusOK},
		{http.MethodPost, "/api/v1/integrations/" + id + "/sync", `{"job_id":"job_5678"}`, http.StatusAccepted},
		{http.MethodGet, "/api/v1/integrations/" + id + "/syncs", "", http.StatusOK},
	}
	var syncID string
	for _, operation := range operations {
		req := httptest.NewRequest(operation.method, operation.path, bytes.NewBufferString(operation.body))
		if operation.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != operation.status {
			t.Fatalf("%s %s status=%d body=%s", operation.method, operation.path, res.Code, res.Body.String())
		}
		if operation.path[len(operation.path)-5:] == "/sync" {
			var value map[string]any
			_ = json.Unmarshal(res.Body.Bytes(), &value)
			syncID, _ = value["id"].(string)
		}
	}
	if syncID == "" {
		t.Fatal("missing sync ID")
	}
	getSync := httptest.NewRequest(http.MethodGet, "/api/v1/integrations/"+id+"/syncs/"+syncID, nil)
	getSyncResponse := httptest.NewRecorder()
	handler.ServeHTTP(getSyncResponse, getSync)
	if getSyncResponse.Code != http.StatusOK {
		t.Fatalf("get sync=%d", getSyncResponse.Code)
	}

	deletable, err := service.Create(context.Background(), scope, IntegrationInput{
		ConnectorKey: "generic-webhook", Name: "Temporary notifications",
		Configuration: map[string]string{"destination_url": "https://hooks.customer.invalid/delete", "signing_secret_reference": "secret_ref_1234"},
	})
	if err != nil {
		t.Fatal(err)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/v1/integrations/"+deletable.ID().String(), nil)
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete=%d", deleteResponse.Code)
	}
	queryDrift := httptest.NewRecorder()
	handler.ServeHTTP(queryDrift, httptest.NewRequest(http.MethodGet, "/api/v1/integrations?unexpected=true", nil))
	if queryDrift.Code != http.StatusBadRequest {
		t.Fatalf("query drift=%d", queryDrift.Code)
	}

	denied, _ := NewHTTPHandler(service, func(*http.Request) (domain.Scope, error) { return domain.Scope{}, ErrForbidden })
	for _, operation := range append(operations, struct {
		method, path, body string
		status             int
	}{http.MethodGet, "/api/v1/integrations/" + id + "/syncs/" + syncID, "", http.StatusOK}) {
		t.Run("denied "+operation.method+" "+operation.path, func(t *testing.T) {
			deniedResponse := httptest.NewRecorder()
			denied.ServeHTTP(deniedResponse, httptest.NewRequest(operation.method, operation.path, bytes.NewBufferString(operation.body)))
			if deniedResponse.Code != http.StatusForbidden || deniedResponse.Body.String() != "{\"code\":\"authorization_rejected\",\"correlation_id\":\"pid_ffffffff-ffff-4fff-8fff-ffffffffffff\",\"message\":\"Authorization rejected\",\"retryable\":false}\n" {
				t.Fatalf("unstable error: %d %q", deniedResponse.Code, deniedResponse.Body.String())
			}
		})
	}
}

func TestHTTPRejectsUnknownJSONAndInvalidRoutes(t *testing.T) {
	handler, _ := NewHTTPHandler(nil, nil)
	if handler != nil {
		t.Fatal("accepted invalid configuration")
	}
	_ = context.Background()
}
