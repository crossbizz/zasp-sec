package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

func TestSignedHTTPControlBindsAuthorityPolicyAndDecisionWithoutCallerScope(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := fixtureGatewayKey(t)
	authority := fixtureAuthority(publicKey)
	repository := &controlRepositoryStub{
		authority: authority,
		policy: &policy.GatewayPolicyEnvelope{
			ContractVersion: 1,
			KeyID:           "policy-key-1",
			Algorithm:       "Ed25519",
			Audience:        PolicyAudience,
			OrganizationID:  authority.OrganizationID,
			WorkspaceID:     authority.WorkspaceID,
			EnvironmentID:   authority.EnvironmentID,
			DeviceID:        authority.DeviceID,
			Sequence:        4,
			PolicyVersion:   3,
			IssuedAt:        now.Add(-time.Minute),
			ExpiresAt:       now.Add(time.Hour),
			FailureMode:     "closed",
			PayloadDigest:   strings.Repeat("a", sha256.Size*2),
			Policies:        []policy.CompiledPolicy{},
			Signature:       base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		},
	}
	if !validAuthority(authority, authority.CredentialID, now) {
		t.Fatalf("fixture authority is invalid: %#v", authority)
	}
	lastStatus, lastBody := 0, ""
	handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repository, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	transport := handlerRoundTripper{handler: handler, inspect: func(request *http.Request, body []byte) {
		for _, name := range []string{"X-Zasp-Organization", "X-Zasp-Workspace", "X-Zasp-Environment", "X-Zasp-Scope"} {
			if request.Header.Get(name) != "" {
				t.Fatalf("client sent caller scope header %s", name)
			}
		}
		if bytes.Contains(body, privateKey) {
			t.Fatal("request exposed private key")
		}
		timestamp, timestampErr := time.Parse(time.RFC3339, request.Header.Get(TimestampHeader))
		canonical, canonicalErr := canonicalRequest(request, authority.CredentialID, timestamp, request.Header.Get(ContentSHA256Header))
		signature, signatureErr := base64.RawURLEncoding.DecodeString(request.Header.Get(SignatureHeader))
		if timestampErr != nil || canonicalErr != nil || signatureErr != nil || !ed25519.Verify(publicKey, canonical, signature) {
			t.Fatalf("client signature timestamp=%v canonical=%v signature=%v", timestampErr, canonicalErr, signatureErr)
		}
	}, inspectResponse: func(status int, body []byte) { lastStatus, lastBody = status, string(body) }}
	client, err := newHTTPClient(HTTPClientConfig{
		BaseURL:          "https://gateway-control.zasp.example",
		OrganizationID:   authority.OrganizationID,
		WorkspaceID:      authority.WorkspaceID,
		EnvironmentID:    authority.EnvironmentID,
		DeviceID:         authority.DeviceID,
		CredentialID:     authority.CredentialID,
		KeyID:            authority.KeyID,
		PrivateKey:       privateKey,
		OperationTimeout: time.Second,
		Clock:            func() time.Time { return now },
	}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}

	actual, err := client.Authority(context.Background(), authority.CredentialID)
	if err != nil || !sameAuthority(actual, authority) || !bytes.Equal(actual.PublicKey, publicKey) {
		t.Fatalf("authority=%#v authority_calls=%d response=%d %q err=%v", actual, repository.authorityCalls, lastStatus, lastBody, err)
	}
	envelope, err := client.Policy(context.Background(), authority.CredentialID, 3)
	if err != nil || envelope == nil || envelope.Sequence != 4 || repository.policyAfter != 3 {
		t.Fatalf("policy=%#v after=%d err=%v", envelope, repository.policyAfter, err)
	}
	event := DecisionEvent{
		CredentialID:  authority.CredentialID,
		DeviceID:      authority.DeviceID,
		EventID:       fixtureID(6),
		ExpectedFloor: 7,
		NextFloor:     8,
		PolicyVersion: 3,
		Decision:      "block",
		ActionKind:    "http",
		Classification: map[string]string{
			"category": "access", "route_class": "admin", "resource_class": "secret", "outcome": "blocked",
		},
		OccurredAt: now,
	}
	if err := client.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if repository.recorded.EventID != event.EventID || repository.recorded.NextFloor != 8 {
		t.Fatalf("recorded=%#v", repository.recorded)
	}
	if repository.authorityCalls != 3 {
		t.Fatalf("authority verification calls=%d, want 3", repository.authorityCalls)
	}
}

func TestHTTPClientRejectsAuthorityKeyIDDrift(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := fixtureGatewayKey(t)
	authority := fixtureAuthority(publicKey)
	authority.KeyID = "gateway-key-2"
	repository := &controlRepositoryStub{authority: authority}
	handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repository, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	client, err := newHTTPClient(HTTPClientConfig{
		BaseURL:          "https://gateway-control.zasp.example",
		OrganizationID:   authority.OrganizationID,
		WorkspaceID:      authority.WorkspaceID,
		EnvironmentID:    authority.EnvironmentID,
		DeviceID:         authority.DeviceID,
		CredentialID:     authority.CredentialID,
		KeyID:            "gateway-key-1",
		PrivateKey:       privateKey,
		OperationTimeout: time.Second,
		Clock:            func() time.Time { return now },
	}, &http.Client{Transport: handlerRoundTripper{handler: handler}})
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := client.Authority(context.Background(), authority.CredentialID); err == nil || actual.CredentialID != "" {
		t.Fatalf("authority=%#v err=%v", actual, err)
	}
}

func TestSignedHTTPControlRejectsMutationReplayWindowAndScopeInjectionBeforeEffects(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := fixtureGatewayKey(t)
	authority := fixtureAuthority(publicKey)
	repository := &controlRepositoryStub{authority: authority}
	handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repository, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	validBody := []byte(`{"credential_id":"` + authority.CredentialID + `","device_id":"` + authority.DeviceID + `","event_id":"` + fixtureID(7) + `","expected_floor":0,"next_floor":1,"policy_version":1,"decision":"monitor","action_kind":"mcp","classification":{"category":"tool","outcome":"monitored","resource_class":"repository","route_class":"mcp"},"occurred_at":"2026-08-20T12:00:00Z"}`)
	valid := httptest.NewRequest(http.MethodPost, DecisionPath, bytes.NewReader(validBody))
	valid.Header.Set("Content-Type", JSONMediaType)
	if err := SignRequest(valid, validBody, authority.CredentialID, privateKey, now); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "body", mutate: func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(validBody), "monitor", "block")))
		}},
		{name: "path", mutate: func(request *http.Request) { request.URL.Path = PolicyPathPrefix + authority.EnvironmentID }},
		{name: "stale timestamp", mutate: func(request *http.Request) {
			request.Header.Set(TimestampHeader, now.Add(-2*time.Minute).Format(time.RFC3339))
		}},
		{name: "duplicate signature", mutate: func(request *http.Request) { request.Header.Add(SignatureHeader, request.Header.Get(SignatureHeader)) }},
		{name: "caller scope", mutate: func(request *http.Request) { request.Header.Set("X-Zasp-Organization", authority.OrganizationID) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid.Clone(context.Background())
			request.Body = io.NopCloser(bytes.NewReader(validBody))
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || response.Body.String() != `{"error":"authentication_rejected"}`+"\n" {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
		})
	}
	if repository.recordCalls != 0 {
		t.Fatalf("hostile requests reached record effect %d times", repository.recordCalls)
	}
}

func TestHTTPControlRejectsCrossEnvironmentPolicyBeforeRead(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := fixtureGatewayKey(t)
	authority := fixtureAuthority(publicKey)
	repository := &controlRepositoryStub{authority: authority}
	handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repository, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, PolicyPathPrefix+fixtureID(99)+"?after_sequence=0", nil)
	if err := SignRequest(request, nil, authority.CredentialID, privateKey, now); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || repository.policyCalls != 0 {
		t.Fatalf("response=%d policy calls=%d", response.Code, repository.policyCalls)
	}
}

func TestHTTPControlReadinessDriftBlocksAuthenticationAndDecisionEffects(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := fixtureGatewayKey(t)
	authority := fixtureAuthority(publicKey)
	repository := &controlRepositoryStub{authority: authority, readyErr: errors.New("v15 authority drift")}
	handler, err := NewHTTPHandler(HTTPHandlerConfig{Repository: repository, Clock: func() time.Time { return now }, OperationTimeout: time.Second, MaximumBodyBytes: 16 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"credential_id":"` + authority.CredentialID + `","device_id":"` + authority.DeviceID + `","event_id":"` + fixtureID(7) + `","expected_floor":0,"next_floor":1,"policy_version":1,"decision":"monitor","action_kind":"mcp","classification":{"category":"tool","outcome":"monitored","resource_class":"repository","route_class":"mcp"},"occurred_at":"2026-08-20T12:00:00Z"}`)
	request := httptest.NewRequest(http.MethodPost, DecisionPath, bytes.NewReader(body))
	request.Header.Set("Content-Type", JSONMediaType)
	if err := SignRequest(request, body, authority.CredentialID, privateKey, now); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != `{"error":"service_unavailable"}`+"\n" || repository.readyCalls != 1 || repository.authorityCalls != 0 || repository.recordCalls != 0 {
		t.Fatalf("response=%d %q ready=%d authority=%d record=%d", response.Code, response.Body.String(), repository.readyCalls, repository.authorityCalls, repository.recordCalls)
	}
}

func TestHTTPClientKeepsOperationContextUntilBoundedResponseIsRead(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := fixtureGatewayKey(t)
	authority := fixtureAuthority(publicKey)
	raw := []byte(fmt.Sprintf(
		`{"organization_id":"%s","workspace_id":"%s","environment_id":"%s","device_id":"%s","device_version":3,"replay_floor":7,"credential_id":"%s","credential_generation":2,"key_id":"gateway-key-1","algorithm":"Ed25519","public_key":"%s","audience":"runtime-gateway","expires_at":"2026-08-21T12:00:00Z"}`,
		authority.OrganizationID,
		authority.WorkspaceID,
		authority.EnvironmentID,
		authority.DeviceID,
		authority.CredentialID,
		base64.RawURLEncoding.EncodeToString(publicKey),
	))
	client, err := newHTTPClient(HTTPClientConfig{
		BaseURL:          "https://gateway-control.zasp.example",
		OrganizationID:   authority.OrganizationID,
		WorkspaceID:      authority.WorkspaceID,
		EnvironmentID:    authority.EnvironmentID,
		DeviceID:         authority.DeviceID,
		CredentialID:     authority.CredentialID,
		KeyID:            authority.KeyID,
		PrivateKey:       privateKey,
		OperationTimeout: time.Second,
		Clock:            func() time.Time { return now },
	}, &http.Client{Transport: delayedResponseTransport{status: http.StatusOK, raw: raw, delay: 10 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}

	actual, err := client.Authority(context.Background(), authority.CredentialID)
	if err != nil || !sameAuthority(actual, authority) {
		t.Fatalf("authority=%#v err=%v", actual, err)
	}
}

type controlRepositoryStub struct {
	authority      Authority
	policy         *policy.GatewayPolicyEnvelope
	recorded       DecisionEvent
	authorityCalls int
	policyCalls    int
	policyAfter    uint64
	recordCalls    int
	readyErr       error
	readyCalls     int
}

func (repository *controlRepositoryStub) Ready(context.Context) error {
	repository.readyCalls++
	return repository.readyErr
}

func (repository *controlRepositoryStub) Authority(_ context.Context, credentialID string) (Authority, error) {
	repository.authorityCalls++
	if credentialID != repository.authority.CredentialID {
		return Authority{}, errors.New("denied")
	}
	return cloneAuthority(repository.authority), nil
}

func (repository *controlRepositoryStub) Policy(_ context.Context, credentialID string, after uint64) (*policy.GatewayPolicyEnvelope, error) {
	repository.policyCalls++
	repository.policyAfter = after
	if credentialID != repository.authority.CredentialID {
		return nil, errors.New("denied")
	}
	if repository.policy == nil {
		return nil, nil
	}
	value := *repository.policy
	value.Policies = append([]policy.CompiledPolicy(nil), value.Policies...)
	return &value, nil
}

func (repository *controlRepositoryStub) Record(_ context.Context, event DecisionEvent) error {
	repository.recordCalls++
	repository.recorded = cloneDecisionEvent(event)
	return nil
}

type handlerRoundTripper struct {
	handler         http.Handler
	inspect         func(*http.Request, []byte)
	inspectResponse func(int, []byte)
}

type delayedResponseTransport struct {
	status int
	raw    []byte
	delay  time.Duration
}

func (transport delayedResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: transport.status,
		Header: http.Header{
			"Content-Type":  []string{JSONMediaType},
			"Cache-Control": []string{"no-store"},
		},
		Body:    &delayedContextBody{ctx: request.Context(), raw: bytes.NewReader(transport.raw), delay: transport.delay},
		Request: request,
	}, nil
}

type delayedContextBody struct {
	ctx   context.Context
	raw   *bytes.Reader
	delay time.Duration
}

func (body *delayedContextBody) Read(destination []byte) (int, error) {
	timer := time.NewTimer(body.delay)
	defer timer.Stop()
	select {
	case <-body.ctx.Done():
		return 0, body.ctx.Err()
	case <-timer.C:
		return body.raw.Read(destination)
	}
}

func (*delayedContextBody) Close() error { return nil }

func (transport handlerRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if transport.inspect != nil {
		transport.inspect(request, body)
	}
	response := httptest.NewRecorder()
	transport.handler.ServeHTTP(response, request)
	if transport.inspectResponse != nil {
		transport.inspectResponse(response.Code, response.Body.Bytes())
	}
	return response.Result(), nil
}

func fixtureGatewayKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...), append(ed25519.PrivateKey(nil), privateKey...)
}

func fixtureAuthority(publicKey ed25519.PublicKey) Authority {
	return Authority{
		OrganizationID: fixtureID(1), WorkspaceID: fixtureID(2), EnvironmentID: fixtureID(3), DeviceID: fixtureID(4),
		DeviceVersion: 3, CredentialID: fixtureID(5), ReplayFloor: 7, CredentialGeneration: 2, KeyID: "gateway-key-1", Algorithm: "Ed25519",
		PublicKey: append(ed25519.PublicKey(nil), publicKey...), Audience: GatewayAudience, ExpiresAt: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
	}
}

func fixtureID(value int) string {
	return fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value)
}
