package sensor

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestHTTPHandlerCoversSevenProductOperationsAndHeartbeat(t *testing.T) {
	store := NewMemoryStore(func() (domain.ProductID, error) { return fixtureID(7), nil }, sequenceTokens("sensor_token_abcdefghijklmnopqrstuvwxyz012345", "sensor_token_abcdefghijklmnopqrstuvwxyz067890"), fixtureNow)
	handler, err := NewHTTPHandler(store, func(*http.Request) (domain.Scope, error) { return fixtureScope(1), nil })
	if err != nil {
		t.Fatal(err)
	}
	created := requestJSON(t, handler, http.MethodPost, "/api/v1/sensors", `{"name":"cluster-a","mode":"metadata_only"}`, http.StatusCreated)
	id := created["id"].(string)
	token := created["token"].(string)
	requestJSON(t, handler, http.MethodGet, "/api/v1/sensors", "", http.StatusOK)
	requestJSON(t, handler, http.MethodGet, "/api/v1/sensors/"+id, "", http.StatusOK)
	requestJSON(t, handler, http.MethodPatch, "/api/v1/sensors/"+id, `{"name":"cluster-b","mode":"full"}`, http.StatusOK)
	requestJSON(t, handler, http.MethodGet, "/api/v1/sensors/"+id+"/coverage", "", http.StatusOK)
	rotated := requestJSON(t, handler, http.MethodPost, "/api/v1/sensors/"+id+"/rotate-token", `{}`, http.StatusOK)
	if rotated["token"] == token {
		t.Fatal("rotation reused token")
	}
	internal, err := NewHeartbeatHandler(store, func(*http.Request) (domain.Scope, error) { return fixtureScope(1), nil })
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/sensors/"+id+"/heartbeat", bytes.NewBufferString(`{"capabilities":["process","network"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`))
	request.Header.Set("Authorization", "Bearer "+rotated["token"].(string))
	request.Header.Set("Content-Type", "application/json")
	internal.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", recorder.Code, recorder.Body.String())
	}
	requestJSON(t, handler, http.MethodDelete, "/api/v1/sensors/"+id, "", http.StatusNoContent)
}

func TestHTTPHandlerReturnsStableForbiddenError(t *testing.T) {
	handler, err := NewHTTPHandler(fixtureStore(), func(*http.Request) (domain.Scope, error) { return domain.Scope{}, errors.New("denied") })
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/sensors", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("%d", recorder.Code)
	}
	var body map[string]any
	if json.Unmarshal(recorder.Body.Bytes(), &body) != nil || body["code"] != "forbidden" {
		t.Fatalf("%s", recorder.Body.String())
	}
}

func TestHTTPHandlerRejectsOversizeTrailingBytes(t *testing.T) {
	handler, err := NewHTTPHandler(fixtureStore(), func(*http.Request) (domain.Scope, error) { return fixtureScope(1), nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sensors", strings.NewReader(`{"name":"cluster-a","mode":"full"}`+strings.Repeat(" ", maximumBodyBytes)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("accepted oversize body: %d", recorder.Code)
	}
}

func requestJSON(t *testing.T, handler http.Handler, method, path, body string, status int) map[string]any {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != status {
		t.Fatalf("%s %s: %d %s", method, path, recorder.Code, recorder.Body.String())
	}
	if status == http.StatusNoContent {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func sequenceTokens(values ...string) TokenGenerator {
	index := 0
	return func() (string, error) { value := values[index]; index++; return value, nil }
}
func fixtureNow() time.Time { return time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC) }
