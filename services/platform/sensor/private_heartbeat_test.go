package sensor

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateHeartbeatHandlerDerivesAuthorityOnlyFromToken(t *testing.T) {
	credential := fixtureV15Token(t)
	wire, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	credential.Destroy()
	authority := &heartbeatAuthorityStub{}
	handler, err := NewPrivateHeartbeatHandler(authority)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, PrivateHeartbeatPath, strings.NewReader(`{"sequence":7,"status":"healthy","capabilities":["network","process"],"kernel":"6.8.1","btf":true,"event_rate":19,"drops":2}`))
	request.Header.Set("Authorization", "Bearer "+wire)
	request.Header.Set("Content-Type", PrivateHeartbeatMediaType)
	request.Header.Set(PrivateHeartbeatSchemaHeader, PrivateHeartbeatSchemaVersion)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || recorder.Body.Len() != 0 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if authority.calls != 1 || authority.report.Sequence != 7 || authority.report.Status != "healthy" || authority.report.Kernel != "6.8.1" || !authority.report.BTF || authority.report.EventRate != 19 || authority.report.Drops != 2 || strings.Join(authority.report.Capabilities, ",") != "network,process" {
		t.Fatalf("calls=%d report=%#v", authority.calls, authority.report)
	}
	if authority.credential == nil {
		t.Fatal("credential was not provided")
	}
	if _, _, err := authority.credential.Parts(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("handler retained live credential: %v", err)
	}
}

func TestPrivateHeartbeatHandlerRequiresAuthority(t *testing.T) {
	if handler, err := NewPrivateHeartbeatHandler(nil); handler != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("handler=%v err=%v", handler, err)
	}
}

func TestPrivateHeartbeatHandlerRejectsCallerScopeAndAmbiguousAuthorityBeforeRepository(t *testing.T) {
	wire := fixtureV15TokenWire(t)
	tests := []struct {
		name    string
		path    string
		headers http.Header
		body    string
	}{
		{name: "scope query", path: PrivateHeartbeatPath + "?organization_id=pid_10000001-0000-4000-8000-000000000001"},
		{name: "scope body", path: PrivateHeartbeatPath, body: `{"sequence":7,"status":"healthy","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0,"organization_id":"pid_10000001-0000-4000-8000-000000000001"}`},
		{name: "organization header", path: PrivateHeartbeatPath, headers: http.Header{"X-Zasp-Organization-Id": []string{"pid_10000001-0000-4000-8000-000000000001"}}},
		{name: "workspace header", path: PrivateHeartbeatPath, headers: http.Header{"X-Zasp-Workspace-Id": []string{"pid_10000002-0000-4000-8000-000000000002"}}},
		{name: "environment header", path: PrivateHeartbeatPath, headers: http.Header{"X-Zasp-Environment-Id": []string{"pid_10000003-0000-4000-8000-000000000003"}}},
		{name: "generic scope header", path: PrivateHeartbeatPath, headers: http.Header{"X-Scope": []string{"customer-a"}}},
		{name: "duplicate authorization", path: PrivateHeartbeatPath, headers: http.Header{"Authorization": []string{"Bearer " + wire, "Bearer " + wire}}},
		{name: "comma authorization", path: PrivateHeartbeatPath, headers: http.Header{"Authorization": []string{"Bearer " + wire + ",Bearer " + wire}}},
		{name: "forwarded authorization", path: PrivateHeartbeatPath, headers: http.Header{"X-Forwarded-Authorization": []string{"Bearer " + wire}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &heartbeatAuthorityStub{}
			handler, err := NewPrivateHeartbeatHandler(authority)
			if err != nil {
				t.Fatal(err)
			}
			body := test.body
			if body == "" {
				body = `{"sequence":7,"status":"healthy","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`
			}
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+wire)
			for key, values := range test.headers {
				request.Header[key] = values
			}
			request.Header.Set("Content-Type", PrivateHeartbeatMediaType)
			request.Header.Set(PrivateHeartbeatSchemaHeader, PrivateHeartbeatSchemaVersion)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code < 400 || authority.calls != 0 || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), wire) {
				t.Fatalf("response=%d calls=%d headers=%v body=%q", recorder.Code, authority.calls, recorder.Header(), recorder.Body.String())
			}
		})
	}
}

func TestPrivateHeartbeatHandlerRejectsHostileContractBeforeRepository(t *testing.T) {
	wire := fixtureV15TokenWire(t)
	valid := `{"sequence":7,"status":"healthy","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`
	tests := []struct {
		name, method, path, media, schema, body string
	}{
		{name: "wrong path", method: http.MethodPost, path: "/internal/v1/sensors/heartbeat", media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: valid},
		{name: "wrong method", method: http.MethodPut, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: valid},
		{name: "wrong media", method: http.MethodPost, path: PrivateHeartbeatPath, media: "application/json", schema: PrivateHeartbeatSchemaVersion, body: valid},
		{name: "wrong schema", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: "sensor-heartbeat-v2", body: valid},
		{name: "duplicate media", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: valid},
		{name: "duplicate schema", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: valid},
		{name: "duplicate key", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"sequence":8,"status":"healthy","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`},
		{name: "unknown key", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"status":"healthy","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0,"secret":"x"}`},
		{name: "duplicate capability", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"status":"healthy","capabilities":["process","process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`},
		{name: "unsorted capability", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"status":"healthy","capabilities":["process","network"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`},
		{name: "empty capability", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"status":"healthy","capabilities":[],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`},
		{name: "noncanonical kernel", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"status":"healthy","capabilities":["process"],"kernel":" 6.8","btf":true,"event_rate":1,"drops":0}`},
		{name: "invalid status", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: `{"sequence":7,"status":"unknown","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`},
		{name: "trailing JSON", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: valid + `{}`},
		{name: "oversize", method: http.MethodPost, path: PrivateHeartbeatPath, media: PrivateHeartbeatMediaType, schema: PrivateHeartbeatSchemaVersion, body: valid + strings.Repeat(" ", maximumPrivateHeartbeatBytes)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &heartbeatAuthorityStub{}
			handler, err := NewPrivateHeartbeatHandler(authority)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+wire)
			request.Header.Set("Content-Type", test.media)
			request.Header.Set(PrivateHeartbeatSchemaHeader, test.schema)
			if test.name == "duplicate media" {
				request.Header.Add("Content-Type", test.media)
			}
			if test.name == "duplicate schema" {
				request.Header.Add(PrivateHeartbeatSchemaHeader, test.schema)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code < 400 || authority.calls != 0 || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response=%d calls=%d headers=%v body=%q", recorder.Code, authority.calls, recorder.Header(), recorder.Body.String())
			}
		})
	}
}

func TestPrivateHeartbeatHandlerReturnsStableRedactedRepositoryErrorsAndDestroysToken(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "authentication", err: ErrForbidden, want: http.StatusUnauthorized},
		{name: "replay conflict", err: ErrConflict, want: http.StatusConflict},
		{name: "unavailable", err: ErrUnavailable, want: http.StatusServiceUnavailable},
		{name: "panic", want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := &heartbeatAuthorityStub{err: test.err, panic: test.name == "panic"}
			handler, err := NewPrivateHeartbeatHandler(authority)
			if err != nil {
				t.Fatal(err)
			}
			wire := fixtureV15TokenWire(t)
			request := httptest.NewRequest(http.MethodPost, PrivateHeartbeatPath, strings.NewReader(`{"sequence":7,"status":"healthy","capabilities":["process"],"kernel":"6.8","btf":true,"event_rate":1,"drops":0}`))
			request.Header.Set("Authorization", "Bearer "+wire)
			request.Header.Set("Content-Type", PrivateHeartbeatMediaType)
			request.Header.Set(PrivateHeartbeatSchemaHeader, PrivateHeartbeatSchemaVersion)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.want || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), wire) || strings.Contains(recorder.Body.String(), privateHeartbeatTestErrorString(test.err)) {
				t.Fatalf("response=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
			}
			if authority.credential == nil {
				t.Fatal("credential missing")
			}
			if _, _, err := authority.credential.Parts(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("credential remained live: %v", err)
			}
		})
	}
}

func privateHeartbeatTestErrorString(err error) string {
	if err == nil {
		return "provider-secret"
	}
	return err.Error()
}

type heartbeatAuthorityStub struct {
	calls      int
	credential *TokenCredential
	report     PrivateHeartbeat
	err        error
	panic      bool
}

func (stub *heartbeatAuthorityStub) RecordAuthenticatedHeartbeat(_ context.Context, credential *TokenCredential, report PrivateHeartbeat) error {
	stub.calls++
	stub.credential = credential
	stub.report = report
	if stub.panic {
		panic("provider-secret")
	}
	return stub.err
}

func fixtureV15Token(t *testing.T) *TokenCredential {
	t.Helper()
	credential, err := NewTokenCredential(bytes.Repeat([]byte{0x12}, sensorTokenLocatorBytes), bytes.Repeat([]byte{0x34}, sensorTokenSecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func fixtureV15TokenWire(t *testing.T) string {
	t.Helper()
	credential := fixtureV15Token(t)
	wire, err := credential.Wire()
	credential.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

var _ PrivateHeartbeatAuthority = (*heartbeatAuthorityStub)(nil)
