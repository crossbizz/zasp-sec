package attacklabproxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPSForwarderPinsEveryAllowedAnswerAndForwardsExactCanaryOnly(t *testing.T) {
	authorizer := &recordingTargetAuthorizer{reference: "ref:red-team/target-0001", secret: []byte("0123456789abcdef0123456789abcdef")}
	resolver := staticProxyResolver{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.12")}, {IP: net.ParseIP("203.0.113.11")}}}
	transport := &recordingProxyTransport{response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}}
	forwarder, err := newHTTPSForwarder([]string{"203.0.113.0/24"}, time.Second, 32<<10, authorizer, resolver, func(host, address string, _ time.Duration) http.RoundTripper {
		if host != "adapter.customer.example" || address != "203.0.113.11" {
			t.Fatalf("host=%q address=%q", host, address)
		}
		return transport
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"run_id":"pid_7e300001-0000-4000-8000-000000000001"}`)
	result, err := forwarder.Forward(context.Background(), ForwardRequest{Destination: "adapter.customer.example", CredentialReference: "ref:red-team/target-0001", RunID: "pid_7e300001-0000-4000-8000-000000000001", Method: http.MethodPost, Path: "/v1/attack-lab/canary", ContentType: "application/json", Body: body})
	if err != nil || result.StatusCode != http.StatusOK || string(result.Body) != `{"ok":true}` || len(transport.requests) != 1 || transport.requests[0].URL.String() != "https://adapter.customer.example/v1/attack-lab/canary" {
		t.Fatalf("result=%#v requests=%d err=%v", result, len(transport.requests), err)
	}
	digest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, authorizer.secret)
	_, _ = mac.Write(body)
	if authorizer.calls != 1 || transport.requests[0].Header.Get("X-Zasp-Run-ID") != "pid_7e300001-0000-4000-8000-000000000001" || transport.requests[0].Header.Get("X-Zasp-Payload-Digest") != "sha256:"+hex.EncodeToString(digest[:]) || transport.requests[0].Header.Get("X-Zasp-Signature") != "sha256:"+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("authorizer=%d headers=%#v", authorizer.calls, transport.requests[0].Header)
	}
}

func TestHTTPSForwarderRejectsOneForeignOrPrivateDNSAnswerBeforeNetwork(t *testing.T) {
	for name, addresses := range map[string][]net.IPAddr{
		"foreign": {{IP: net.ParseIP("203.0.114.1")}},
		"private": {{IP: net.ParseIP("10.0.0.1")}},
		"mixed":   {{IP: net.ParseIP("203.0.113.11")}, {IP: net.ParseIP("10.0.0.1")}},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			forwarder, err := newHTTPSForwarder([]string{"203.0.113.0/24"}, time.Second, 32<<10, &recordingTargetAuthorizer{reference: "ref:red-team/target-0001", secret: []byte("0123456789abcdef0123456789abcdef")}, staticProxyResolver{addresses: addresses}, func(string, string, time.Duration) http.RoundTripper {
				calls++
				return &recordingProxyTransport{}
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := forwarder.Forward(context.Background(), ForwardRequest{Destination: "adapter.customer.example", CredentialReference: "ref:red-team/target-0001", RunID: "pid_7e300001-0000-4000-8000-000000000001", Method: http.MethodPost, Path: "/v1/attack-lab/canary", ContentType: "application/json", Body: []byte(`{}`)}); err == nil || calls != 0 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

type recordingTargetAuthorizer struct {
	reference string
	secret    []byte
	calls     int
}

func (authorizer *recordingTargetAuthorizer) Authorize(_ context.Context, reference string, payload []byte) (TargetAuthorization, error) {
	authorizer.calls++
	if reference != authorizer.reference {
		return TargetAuthorization{}, ErrUnavailable
	}
	digest := sha256.Sum256(payload)
	mac := hmac.New(sha256.New, authorizer.secret)
	_, _ = mac.Write(payload)
	return TargetAuthorization{PayloadDigest: "sha256:" + hex.EncodeToString(digest[:]), Signature: "sha256:" + hex.EncodeToString(mac.Sum(nil))}, nil
}

type staticProxyResolver struct{ addresses []net.IPAddr }

func (resolver staticProxyResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), resolver.addresses...), nil
}

type recordingProxyTransport struct {
	requests []*http.Request
	response *http.Response
}

func (transport *recordingProxyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests = append(transport.requests, request)
	if transport.response == nil {
		return nil, ErrUnavailable
	}
	transport.response.Request = request
	return transport.response, nil
}
