package sensoradapter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func TestRuntimeEnvelopeUsesCurrentCredentialWithoutChangingEnvelope(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	credential := envelopeCredential(t, 3)
	tokenReads := 0
	var bodies [][]byte
	var headers []http.Header
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Token: func() ([]byte, error) {
		tokenReads++
		return []byte(credential), nil
	}, Now: func() time.Time { return now }, Do: func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		headers = append(headers, request.Header.Clone())
		return envelopeAccepted(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := client.PrepareEnvelope([]RuntimeEvent{event})
	if err != nil || tokenReads != 0 || len(bodies) != 0 {
		t.Fatalf("prepare performed transport: %v, reads=%d", err, tokenReads)
	}
	frozenBody := bytes.Clone(envelope.Body)
	event.Content["binary_digest"] = "changed-after-prepare"
	for attempt := 0; attempt < 2; attempt++ {
		credential = envelopeCredential(t, byte(4+attempt))
		if err := client.IngestEnvelope(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}
	}
	if tokenReads != 2 || len(bodies) != 2 || !bytes.Equal(bodies[0], frozenBody) || !bytes.Equal(bodies[1], frozenBody) || headers[0].Get("Authorization") == headers[1].Get("Authorization") {
		t.Fatal("credential or envelope replay changed unexpectedly")
	}
	for _, header := range headers {
		if header.Get("X-Zasp-Runtime-Schema") != "runtime-event-enrollment-v1" || header.Get("X-Zasp-Expected-Enrollment") != strings.Repeat("a", 64) || header.Get("Idempotency-Key") != envelope.IdempotencyKey {
			t.Fatal("transport lost frozen constraints")
		}
	}
}

func TestRuntimeEnvelopeRejectsDriftBeforeCredentials(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Token: func() ([]byte, error) { t.Fatal("credential read"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("transport called"); return nil, nil }, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	envelope, err := client.PrepareEnvelope([]RuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RuntimeEnvelope){
		"version": func(value *RuntimeEnvelope) { value.Version = "future" },
		"destination": func(value *RuntimeEnvelope) {
			value.Destination = "https://other.example.test/internal/v1/runtime/events"
		},
		"enrollment":  func(value *RuntimeEnvelope) { value.EnrollmentBinding = strings.Repeat("b", 64) },
		"schema":      func(value *RuntimeEnvelope) { value.Schema = "runtime-event-v1" },
		"idempotency": func(value *RuntimeEnvelope) { value.IdempotencyKey += "changed" },
		"body":        func(value *RuntimeEnvelope) { value.Body = append(value.Body, ' ') },
		"unknown body field": func(value *RuntimeEnvelope) {
			value.Body = bytes.Replace(value.Body, []byte(`"source":`), []byte(`"unexpected":true,"source":`), 1)
		},
		"empty": func(value *RuntimeEnvelope) { value.Body = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := envelope
			changed.Body = bytes.Clone(envelope.Body)
			mutate(&changed)
			if !bytes.Equal(changed.Body, envelope.Body) {
				// Reach body validation; do not let a stale digest mask it.
				changed.IdempotencyKey = envelopeIdempotency(changed.Body)
			}
			if err := client.IngestEnvelope(context.Background(), changed); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
	now = now.Add(25 * time.Hour)
	if err := client.IngestEnvelope(context.Background(), envelope); !errors.Is(err, ErrEnvelopeExpired) {
		t.Fatalf("expired envelope needs retained-error outcome: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.IngestEnvelope(ctx, envelope); !errors.Is(err, ErrClientRetryable) {
		t.Fatalf("canceled replay: %v", err)
	}
}

func TestRuntimeEnvelopeRejectsHostileCanonicalBodies(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Token: func() ([]byte, error) { t.Fatal("credential read"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("transport called"); return nil, nil }, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	envelope, err := client.PrepareEnvelope([]RuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"duplicate":        bytes.Replace(envelope.Body, []byte(`"source":`), []byte(`"source":"tetragon","source":`), 1),
		"alias":            bytes.Replace(envelope.Body, []byte(`"source":`), []byte(`"Source":`), 1),
		"escaped key":      bytes.Replace(envelope.Body, []byte(`"source":`), []byte(`"sour\u0063e":`), 1),
		"null":             []byte(`{"source":"tetragon","events":null}`),
		"no events":        []byte(`{"source":"tetragon","events":[]}`),
		"other source":     bytes.Replace(envelope.Body, []byte(`"tetragon"`), []byte(`"otlp"`), 1),
		"future timestamp": bytes.ReplaceAll(envelope.Body, []byte("2026-08-20T12:00:00.000Z"), []byte("2026-08-21T12:00:00.000Z")),
		"oversized":        bytes.Repeat([]byte{' '}, maximumEnvelopeBodyBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			changed := envelope
			changed.Body, changed.IdempotencyKey = body, envelopeIdempotency(body)
			if err := client.IngestEnvelope(context.Background(), changed); !errors.Is(err, ErrClient) {
				t.Fatalf("hostile envelope result: %v", err)
			}
		})
	}
}

func TestRuntimeEnvelopeRequiresExplicitValidEnrollment(t *testing.T) {
	for _, binding := range []string{"", "wrong", strings.Repeat("A", 64), strings.Repeat("a", 65)} {
		config := ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: binding, Token: func() ([]byte, error) { t.Fatal("credential read"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("transport called"); return nil, nil }, Now: time.Now}
		client, err := NewProductionClient(config)
		if binding == "" {
			if err != nil {
				t.Fatal("legacy client construction changed")
			}
			if value, err := client.PrepareEnvelope(nil); err == nil || !reflect.DeepEqual(value, RuntimeEnvelope{}) {
				t.Fatal("unbound client prepared durable envelope")
			}
		} else if err == nil || client != nil {
			t.Fatal("malformed enrollment configuration accepted")
		}
	}
}

func envelopeCredential(t testing.TB, seed byte) string {
	t.Helper()
	credential, err := sensor.NewTokenCredential(bytes.Repeat([]byte{seed}, 16), bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Destroy()
	wire, err := credential.Wire()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func envelopeAccepted() *http.Response {
	return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": []string{"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_78950009-0000-4000-8000-000000000009"}`))}
}
