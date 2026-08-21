package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type findingTicketRoundTripperFunc func(*http.Request) (*http.Response, error)

func (roundTripper findingTicketRoundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

func TestProductionFindingTicketWebhookPinsEveryDNSAnswerToReleaseCIDRs(t *testing.T) {
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	payload := `{"delivery_id":"` + deliveryID + `","version":1}`
	payloadHash := sha256.Sum256([]byte(payload))
	digest := "sha256:" + hex.EncodeToString(payloadHash[:])
	var resolvedHost, factoryHost, pinnedIP string
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolvedHost = host
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}, {IP: net.ParseIP("203.0.113.8")}}, nil
	}
	factory := func(host, pinned string, _ time.Duration) http.RoundTripper {
		factoryHost, pinnedIP = host, pinned
		return findingTicketRoundTripperFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ticket_id":"SEC-1234"}`)), Request: request}, nil
		})
	}
	webhook, err := newProductionFindingTicketWebhook([]string{"203.0.113.0/24"}, time.Second, lookup, factory)
	if err != nil {
		t.Fatal(err)
	}

	ticketID, err := webhook.DeliverFindingTicket(context.Background(), "https://tickets.example.test/zasp", payload, digest, deliveryID, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil || ticketID != "SEC-1234" || resolvedHost != "tickets.example.test" || factoryHost != "tickets.example.test" || pinnedIP != "203.0.113.8" {
		t.Fatalf("delivery=(%q,%v) resolution=%q factory=%q pinned=%q", ticketID, err, resolvedHost, factoryHost, pinnedIP)
	}
}

func TestProductionFindingTicketWebhookRejectsMixedDNSAndUnsafeCIDRsBeforeHTTP(t *testing.T) {
	factoryCalls := 0
	lookup := func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}, {IP: net.ParseIP("10.0.0.8")}}, nil
	}
	factory := func(string, string, time.Duration) http.RoundTripper {
		factoryCalls++
		return findingTicketRoundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	}
	webhook, err := newProductionFindingTicketWebhook([]string{"203.0.113.0/24"}, time.Second, lookup, factory)
	if err != nil {
		t.Fatal(err)
	}
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	payload := `{"delivery_id":"` + deliveryID + `","version":1}`
	payloadHash := sha256.Sum256([]byte(payload))
	if _, err := webhook.DeliverFindingTicket(context.Background(), "https://tickets.example.test/zasp", payload, "sha256:"+hex.EncodeToString(payloadHash[:]), deliveryID, []byte("0123456789abcdef0123456789abcdef")); err != ErrRepositoryUnavailable || factoryCalls != 0 {
		t.Fatalf("mixed DNS error=%v factory_calls=%d", err, factoryCalls)
	}

	for _, cidrs := range [][]string{{}, {"0.0.0.0/0"}, {"10.0.0.0/8"}, {"203.0.113.1/24"}, {"203.0.113.0/24", "203.0.113.0/24"}} {
		if _, err := newProductionFindingTicketWebhook(cidrs, time.Second, lookup, factory); err != ErrRepositoryConfiguration {
			t.Fatalf("CIDRs %#v error=%v", cidrs, err)
		}
	}
}
