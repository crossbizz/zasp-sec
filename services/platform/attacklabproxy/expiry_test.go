package attacklabproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/attacklab"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type callbackEgressResolver struct {
	resolve func(context.Context) (apiserver.AttackLabEgressAuthority, error)
}

func (r callbackEgressResolver) Ready(context.Context) error { return nil }
func (r callbackEgressResolver) ResolveAttackLabEgress(ctx context.Context, _ domain.Scope, _, _ string) (apiserver.AttackLabEgressAuthority, error) {
	return r.resolve(ctx)
}

type callbackEgressForwarder struct {
	forward func(context.Context) (ForwardResult, error)
}

func (f callbackEgressForwarder) Forward(ctx context.Context, _ ForwardRequest) (ForwardResult, error) {
	return f.forward(ctx)
}

func TestProxyRechecksExpiryAfterDurableResolution(t *testing.T) {
	for _, expiration := range []string{"token", "durable authority"} {
		t.Run(expiration, func(t *testing.T) {
			issued := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
			clock := issued.Add(time.Second)
			grant, authority, request, key := expiryRequest(t, issued)
			if expiration == "durable authority" {
				authority.ExpiresAt = issued.Add(2 * time.Second)
			}
			resolver := callbackEgressResolver{resolve: func(context.Context) (apiserver.AttackLabEgressAuthority, error) {
				if expiration == "token" {
					clock = grant.ExpiresAt
				} else {
					clock = authority.ExpiresAt
				}
				return authority, nil
			}}
			forwarder := &recordingEgressForwarder{}
			handler, err := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return clock }}, resolver, forwarder)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || len(forwarder.calls) != 0 {
				t.Fatalf("expired %s forwarded: status=%d calls=%d", expiration, response.Code, len(forwarder.calls))
			}
		})
	}
}

func TestProxyBoundsResolverAndForwardingByCapabilityExpiry(t *testing.T) {
	for _, boundary := range []string{"resolver", "credential and network"} {
		t.Run(boundary, func(t *testing.T) {
			issued := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
			clock := issued.Add(2 * time.Second)
			_, authority, request, key := expiryRequest(t, issued)
			authority.ExpiresAt = clock.Add(100 * time.Millisecond)
			resolver := callbackEgressResolver{resolve: func(ctx context.Context) (apiserver.AttackLabEgressAuthority, error) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second {
					t.Error("resolver lacks token deadline")
				}
				if boundary == "resolver" && ok {
					<-ctx.Done()
					return apiserver.AttackLabEgressAuthority{}, ctx.Err()
				}
				return authority, nil
			}}
			forwards := 0
			forwarder := callbackEgressForwarder{forward: func(ctx context.Context) (ForwardResult, error) {
				forwards++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 100*time.Millisecond {
					t.Error("forward lacks earlier durable authority deadline")
					return ForwardResult{}, ErrUnavailable
				}
				<-ctx.Done()
				return ForwardResult{}, ctx.Err()
			}}
			handler, err := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return clock }}, resolver, forwarder)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if boundary == "resolver" && forwards != 0 {
				t.Fatal("expired resolution reached forwarding")
			}
			if response.Code == http.StatusOK {
				t.Fatal("expired request succeeded")
			}
		})
	}
}

func expiryRequest(t *testing.T, issued time.Time) (attacklab.EgressGrant, apiserver.AttackLabEgressAuthority, *http.Request, []byte) {
	t.Helper()
	scope := mustProxyScope(t)
	grant := attacklab.EgressGrant{Scope: scope, RunID: "pid_7e300001-0000-4000-8000-000000000001", Destination: "adapter.customer.example", Methods: []string{"POST"}, ExpiresAt: issued.Add(3 * time.Second), InputDigest: sha256.Sum256([]byte("exact-expiry-input"))}
	authority := apiserver.AttackLabEgressAuthority{OrganizationID: scope.OrganizationID().String(), WorkspaceID: scope.WorkspaceID().String(), EnvironmentID: scope.EnvironmentID().String(), RunID: grant.RunID, Destination: grant.Destination, CredentialReference: "ref:red-team/target-0001", Methods: []string{"POST"}, ExpiresAt: grant.ExpiresAt}
	key := []byte("0123456789abcdef0123456789abcdef")
	token, err := attacklab.SignEgressCapability(key, grant, issued)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(Request{Path: "/v1/attack-lab/canary", ContentType: "application/json", BodyBase64: base64.RawURLEncoding.EncodeToString(proxyCanaryBody(t, grant))})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://agentsec-attack-lab-proxy.agentsec.svc.cluster.local/v1/egress", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	return grant, authority, request, key
}

type lateCredentialAuthorizer struct{}

type countedExpiryDNS struct{ calls int }

func (r *countedExpiryDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.calls++
	return []net.IPAddr{{IP: net.ParseIP("203.0.113.11")}}, nil
}

func (lateCredentialAuthorizer) Authorize(ctx context.Context, _ string, _ []byte) (TargetAuthorization, error) {
	<-ctx.Done()
	return TargetAuthorization{PayloadDigest: "sha256:" + strings.Repeat("a", 64), Signature: "sha256:" + strings.Repeat("b", 64)}, nil
}

func TestProxyCredentialExpiryNeverReachesPinnedTargetTransport(t *testing.T) {
	issued := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	clock := issued.Add(2 * time.Second)
	_, authority, request, key := expiryRequest(t, issued)
	authority.ExpiresAt = clock.Add(50 * time.Millisecond)
	resolver := callbackEgressResolver{resolve: func(context.Context) (apiserver.AttackLabEgressAuthority, error) { return authority, nil }}
	networks := 0
	dns := &countedExpiryDNS{}
	forwarder, err := newHTTPSForwarder([]string{"203.0.113.0/24"}, time.Second, 32<<10, lateCredentialAuthorizer{}, dns, func(string, string, time.Duration) http.RoundTripper { networks++; return &recordingProxyTransport{} })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return clock }}, resolver, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusOK || networks != 0 || dns.calls != 0 {
		t.Fatal("late credential authority reached a target")
	}
}

func TestProxyCloseIsSafeDuringTokenVerification(t *testing.T) {
	issued := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	_, _, request, key := expiryRequest(t, issued)
	resolver := callbackEgressResolver{resolve: func(context.Context) (apiserver.AttackLabEgressAuthority, error) {
		return apiserver.AttackLabEgressAuthority{}, ErrUnavailable
	}}
	handler, err := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return issued.Add(time.Second) }}, resolver, &recordingEgressForwarder{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			clone := request.Clone(context.Background())
			clone.Body = io.NopCloser(bytes.NewReader(payload))
			handler.ServeHTTP(httptest.NewRecorder(), clone)
		}()
	}
	handler.Close()
	group.Wait()
	handler.Close()
}

func TestProxyRejectsSuccessReturnedAfterAuthorityExpires(t *testing.T) {
	issued := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	clock := issued.Add(time.Second)
	_, authority, request, key := expiryRequest(t, issued)
	resolver := callbackEgressResolver{resolve: func(context.Context) (apiserver.AttackLabEgressAuthority, error) { return authority, nil }}
	forwarder := callbackEgressForwarder{forward: func(context.Context) (ForwardResult, error) {
		clock = authority.ExpiresAt
		return ForwardResult{StatusCode: 200, ContentType: "application/json", Body: []byte(`{}`)}, nil
	}}
	handler, err := NewHandler(Config{SigningKey: key, MaximumRequestBytes: 32 << 10, MaximumResponseBytes: 32 << 10, Clock: func() time.Time { return clock }}, resolver, forwarder)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatal("late success accepted past authority expiry")
	}
}
