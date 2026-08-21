package apiserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFindingTicketWebhookSignsExactPayloadAndStrictlyDecodesTicket(t *testing.T) {
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	payload := `{"delivery_id":"` + deliveryID + `","version":1}`
	payloadHash := sha256.Sum256([]byte(payload))
	digest := "sha256:" + hex.EncodeToString(payloadHash[:])
	secret := []byte("0123456789abcdef0123456789abcdef")
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(body)
		wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if request.Method != http.MethodPost || request.URL.Path != "/ticket" || request.URL.RawQuery != "" || string(body) != payload || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("X-Zasp-Delivery-ID") != deliveryID || request.Header.Get("X-Zasp-Payload-Digest") != digest || request.Header.Get("X-Zasp-Signature") != wantSignature || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Errorf("request = %s %s headers=%#v body=%s", request.Method, request.URL.String(), request.Header, body)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"ticket_id":"SEC-1234"}`))
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }
	webhook, err := newFindingTicketWebhook(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ticketID, err := webhook.DeliverFindingTicket(context.Background(), server.URL+"/ticket", payload, digest, deliveryID, secret)
	if err != nil || ticketID != "SEC-1234" || calls.Load() != 1 {
		t.Fatalf("delivery = (%q, %v), calls=%d", ticketID, err, calls.Load())
	}
}

func TestFindingTicketWebhookFailsClosedOnRedirectProviderTextAndSchemaDrift(t *testing.T) {
	deliveryID := "pid_41000001-0000-4000-8000-000000000001"
	payload := `{"delivery_id":"` + deliveryID + `","version":1}`
	payloadHash := sha256.Sum256([]byte(payload))
	digest := "sha256:" + hex.EncodeToString(payloadHash[:])
	secret := []byte("0123456789abcdef0123456789abcdef")
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	responses := []struct {
		status  int
		body    string
		headers map[string]string
	}{
		{status: http.StatusTemporaryRedirect, headers: map[string]string{"Location": target.URL}},
		{status: http.StatusInternalServerError, body: "provider secret " + string(secret)},
		{status: http.StatusCreated, body: `{"ticket_id":"SEC-1234","secret":"leak"}`},
		{status: http.StatusCreated, body: strings.Repeat("x", 4097)},
	}
	for index, response := range responses {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			for name, value := range response.headers {
				writer.Header().Set(name, value)
			}
			writer.WriteHeader(response.status)
			_, _ = writer.Write([]byte(response.body))
		}))
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }
		webhook, err := newFindingTicketWebhook(client, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if ticketID, err := webhook.DeliverFindingTicket(context.Background(), server.URL, payload, digest, deliveryID, secret); !errors.Is(err, ErrRepositoryUnavailable) || ticketID != "" || strings.Contains(err.Error(), "provider secret") || strings.Contains(err.Error(), string(secret)) {
			t.Fatalf("case %d = (%q, %v)", index, ticketID, err)
		}
		server.Close()
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target calls = %d", redirected.Load())
	}
}
