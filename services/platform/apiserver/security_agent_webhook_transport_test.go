package apiserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type responseWebhookRoundTrip func(*http.Request) (*http.Response, error)

func (f responseWebhookRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The receiver observes the exact input bytes; the expected signature is derived
// independently from that request, not from the sender's signing helper.
func TestSecurityAgentWebhookTransport(t *testing.T) {
	delivery := "pid_00000000-0000-4000-8000-000000000001"
	payload := []byte(`{"type":"security_agent.response","delivery_id":"pid_00000000-0000-4000-8000-000000000001"}`)
	hash := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	key := bytes.Repeat([]byte{'s'}, 32)
	t.Run("receiver", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(body)
			if !bytes.Equal(body, payload) || r.Method != http.MethodPost || r.Header.Get("X-Zasp-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) || r.Header.Get("X-Zasp-Delivery-ID") != delivery || r.Header.Get("X-Zasp-Payload-Digest") != digest || r.Header.Get("X-Zasp-Event") != "security_agent.response" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("signed receiver request did not match immutable input")
			}
			w.WriteHeader(204)
		}))
		defer server.Close()
		webhook, err := newFindingTicketWebhook(server.Client(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := webhook.DeliverSecurityAgentResponse(context.Background(), server.URL+"/response", delivery, digest, payload, key)
		if err != nil || receipt.Outcome != "acknowledged" || receipt.ErrorCode != "" || calls.Load() != 1 {
			t.Fatalf("receipt=%+v err=%v calls=%d", receipt, err, calls.Load())
		}
	})
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		failure    bool
		want, code string
	}{
		{"empty204", 204, "", false, "acknowledged", ""}, {"nonempty204", 204, "x", false, "failed", "response_rejected"},
		{"200", 200, "", false, "failed", "response_rejected"}, {"302", 302, "", false, "failed", "response_rejected"}, {"429", 429, "", false, "failed", "response_rejected"}, {"500", 500, "", false, "failed", "response_rejected"},
		{"oversized", 500, strings.Repeat("PROVIDER_SECRET_SENTINEL", 10000), false, "failed", "response_rejected"},
		{"interrupted", 0, "", true, "uncertain", "delivery_uncertain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			webhook, err := newFindingTicketWebhook(&http.Client{Transport: responseWebhookRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				if tc.failure {
					return nil, errors.New("PROVIDER_SECRET_SENTINEL")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{"https://redirect.example/"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := webhook.DeliverSecurityAgentResponse(context.Background(), "https://receiver.example/response", delivery, digest, payload, key)
			if receipt.Outcome != tc.want || receipt.ErrorCode != tc.code || calls != 1 || (err != nil) != (tc.want == "uncertain") {
				t.Fatalf("receipt=%+v err=%v calls=%d", receipt, err, calls)
			}
			if err != nil && strings.Contains(err.Error(), "SENTINEL") {
				t.Fatal("provider error leaked")
			}
		})
	}
	t.Run("body-read-interrupted", func(t *testing.T) {
		webhook, _ := newFindingTicketWebhook(&http.Client{Transport: responseWebhookRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 204, Body: responseWebhookInterruptedBody{}}, nil
		})}, time.Second)
		receipt, err := webhook.DeliverSecurityAgentResponse(context.Background(), "https://receiver.example/", delivery, digest, payload, key)
		if receipt.Outcome != "uncertain" || err == nil {
			t.Fatal("body interruption invented definitive outcome")
		}
	})
	for _, tc := range []struct {
		name, destination, id, digest string
		payload, key                  []byte
		cancel                        bool
	}{
		{"http", "http://receiver.example/", delivery, digest, payload, key, false},
		{"query", "https://receiver.example/?secret=x", delivery, digest, payload, key, false},
		{"userinfo", "https://user@receiver.example/", delivery, digest, payload, key, false},
		{"fragment", "https://receiver.example/#x", delivery, digest, payload, key, false},
		{"digest", "https://receiver.example/", delivery, "sha256:" + strings.Repeat("0", 64), payload, key, false},
		{"id", "https://receiver.example/", "bad", digest, payload, key, false},
		{"key", "https://receiver.example/", delivery, digest, payload, []byte("short"), false},
		{"oversize", "https://receiver.example/", delivery, digest, bytes.Repeat([]byte{'x'}, 16385), key, false},
		{"cancelled", "https://receiver.example/", delivery, digest, payload, key, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			webhook, _ := newFindingTicketWebhook(&http.Client{Transport: responseWebhookRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected network") })}, time.Second)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			receipt, err := webhook.DeliverSecurityAgentResponse(ctx, tc.destination, tc.id, tc.digest, tc.payload, tc.key)
			if err == nil || receipt.Outcome != "failed" || receipt.ErrorCode != "invalid_request" || calls != 0 {
				t.Fatalf("pre-dispatch refusal=%+v err=%v calls=%d", receipt, err, calls)
			}
		})
	}
	t.Run("production-pinned-client", func(t *testing.T) {
		calls := 0
		webhook, err := newProductionFindingTicketWebhook([]string{"8.8.8.0/24"}, time.Second, func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}, func(host, ip string, _ time.Duration) http.RoundTripper {
			if host != "receiver.example" || ip != "8.8.8.8" {
				t.Fatal("pinning changed")
			}
			return responseWebhookRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := webhook.DeliverSecurityAgentResponse(context.Background(), "https://receiver.example", delivery, digest, payload, key)
		if err != nil || receipt.Outcome != "acknowledged" || calls != 1 {
			t.Fatalf("pinned delivery failed: %+v %v", receipt, err)
		}
	})
}

type responseWebhookInterruptedBody struct{}

func (responseWebhookInterruptedBody) Read([]byte) (int, error) {
	return 0, errors.New("PROVIDER_SECRET_SENTINEL")
}
func (responseWebhookInterruptedBody) Close() error { return nil }
