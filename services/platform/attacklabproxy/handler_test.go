package attacklabproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklab"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestHandlerAuthorizesExactDurableRunBeforeBoundedForward(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	scope := mustProxyScope(t)
	digest := sha256.Sum256([]byte("attack-lab-input"))
	grant := attacklab.EgressGrant{Scope: scope, RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example", Methods: []string{"POST"}, ExpiresAt: now.Add(5 * time.Minute), InputDigest: digest}
	key := []byte("0123456789abcdef0123456789abcdef")
	token, err := attacklab.SignEgressCapability(key, grant, now)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &recordingEgressResolver{authority: apiserver.AttackLabEgressAuthority{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: grant.RunID, Destination: grant.Destination, CredentialReference: "ref:red-team/target-0001", Methods: []string{"POST"}, ExpiresAt: grant.ExpiresAt}}
	forwarder := &recordingEgressForwarder{result: ForwardResult{StatusCode: http.StatusOK, ContentType: "application/json", Body: []byte(`{"schema_version":"attack-lab-canary-v1","criterion_observed":true,"canary_touched":true,"evidence":"bounded canary changed"}`)}}
	handler, err := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return now.Add(time.Minute) }}, resolver, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(Request{Path: "/v1/attack-lab/canary", ContentType: "application/json", BodyBase64: base64.RawURLEncoding.EncodeToString(proxyCanaryBody(t, grant))})
	request := httptest.NewRequest(http.MethodPost, "https://agentsec-attack-lab-proxy.zasp.svc.cluster.local/v1/egress", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(resolver.calls) != 1 || len(forwarder.calls) != 1 {
		t.Fatalf("status=%d resolver=%d forwarder=%d body=%s", response.Code, len(resolver.calls), len(forwarder.calls), response.Body.String())
	}
	if resolver.calls[0].Scope != scope || resolver.calls[0].RunID != grant.RunID || resolver.calls[0].Destination != grant.Destination || forwarder.calls[0].Destination != grant.Destination || forwarder.calls[0].CredentialReference != "ref:red-team/target-0001" || forwarder.calls[0].RunID != grant.RunID || forwarder.calls[0].Path != "/v1/attack-lab/canary" || forwarder.calls[0].Method != http.MethodPost {
		t.Fatal("forward authority drifted")
	}
	var result Response
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.StatusCode != http.StatusOK || result.ContentType != "application/json" || result.BodyBase64 != base64.RawURLEncoding.EncodeToString(forwarder.result.Body) {
		t.Fatalf("response=%#v err=%v", result, err)
	}
	if !reflect.DeepEqual(resolver.calls[0].Scope, scope) {
		t.Fatal("scope drifted")
	}
}

func TestHandlerRejectsExpiredOrDatabaseDriftedCapabilityBeforeForward(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	scope := mustProxyScope(t)
	grant := attacklab.EgressGrant{Scope: scope, RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example", Methods: []string{"POST"}, ExpiresAt: now.Add(5 * time.Minute), InputDigest: sha256.Sum256([]byte("attack-lab-input"))}
	key := []byte("0123456789abcdef0123456789abcdef")
	token, _ := attacklab.SignEgressCapability(key, grant, now)
	for name, clock := range map[string]time.Time{"expired": now.Add(5 * time.Minute), "database drift": now.Add(time.Minute)} {
		t.Run(name, func(t *testing.T) {
			authority := apiserver.AttackLabEgressAuthority{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: grant.RunID, Destination: grant.Destination, CredentialReference: "ref:red-team/target-0001", Methods: []string{"POST"}, ExpiresAt: grant.ExpiresAt}
			if name == "database drift" {
				authority.Destination = "foreign.example"
			}
			resolver := &recordingEgressResolver{authority: authority}
			forwarder := &recordingEgressForwarder{}
			handler, _ := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return clock }}, resolver, forwarder)
			payload, _ := json.Marshal(Request{Path: "/v1/attack-lab/canary", ContentType: "application/json", BodyBase64: base64.RawURLEncoding.EncodeToString(proxyCanaryBody(t, grant))})
			request := httptest.NewRequest(http.MethodPost, "/v1/egress", bytes.NewReader(payload))
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || len(forwarder.calls) != 0 {
				t.Fatalf("status=%d forwards=%d", response.Code, len(forwarder.calls))
			}
		})
	}
}

func proxyCanaryBody(t *testing.T, grant attacklab.EgressGrant) []byte {
	t.Helper()
	body, err := json.Marshal(canaryForwardBody{SchemaVersion: "attack-lab-canary-request-v1", OrganizationID: grant.Scope.OrganizationID().String(), WorkspaceID: grant.Scope.WorkspaceID().String(), EnvironmentID: grant.Scope.EnvironmentID().String(), RunID: grant.RunID, Destination: grant.Destination, InputDigest: hex.EncodeToString(grant.InputDigest[:]), SuccessCriterion: "Observe exact canary touch", ExpectedSideEffects: []string{"one bounded canary mutation"}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type resolverCall struct {
	Scope       domain.Scope
	RunID       string
	Destination string
}

type recordingEgressResolver struct {
	authority apiserver.AttackLabEgressAuthority
	calls     []resolverCall
}

func (*recordingEgressResolver) Ready(context.Context) error { return nil }
func (resolver *recordingEgressResolver) ResolveAttackLabEgress(_ context.Context, scope domain.Scope, runID, destination string) (apiserver.AttackLabEgressAuthority, error) {
	resolver.calls = append(resolver.calls, resolverCall{Scope: scope, RunID: runID, Destination: destination})
	return resolver.authority, nil
}

type recordingEgressForwarder struct {
	result ForwardResult
	calls  []ForwardRequest
}

func (forwarder *recordingEgressForwarder) Forward(_ context.Context, request ForwardRequest) (ForwardResult, error) {
	forwarder.calls = append(forwarder.calls, request)
	return forwarder.result, nil
}

func mustProxyScope(t *testing.T) domain.Scope {
	t.Helper()
	organization, _ := domain.ParseProductID("pid_7d100010-0000-4000-8000-000000000010")
	workspace, _ := domain.ParseProductID("pid_7d100011-0000-4000-8000-000000000011")
	environment, _ := domain.ParseProductID("pid_7d100012-0000-4000-8000-000000000012")
	scope, err := domain.NewScope(organization, workspace, environment)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
