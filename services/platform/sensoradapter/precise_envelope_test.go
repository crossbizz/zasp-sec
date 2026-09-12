package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func TestPreciseEnvelopeFrozenRetryWithEnrollment(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	token := envelopeCredential(t, 93)
	reads, attempts := 0, 0
	var sent [][]byte
	var auth []string
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { reads++; return []byte(token), nil }, Do: func(request *http.Request) (*http.Response, error) {
		attempts++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if request.Header.Get("X-Zasp-Expected-Enrollment") != strings.Repeat("a", 64) || request.Header.Get("X-Zasp-Runtime-Schema") != "runtime-event-enrollment-v2" || request.Header.Get("Idempotency-Key") != "runtime-v2:"+hex.EncodeToString(digest[:]) {
			t.Fatal("precise transport lost enrollment/schema/idempotency constraint")
		}
		sent = append(sent, body)
		auth = append(auth, request.Header.Get("Authorization"))
		if attempts == 1 {
			return nil, ErrClientRetryable
		}
		return envelopeAccepted(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	event := preciseRecordFixture(t)
	envelope, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{event})
	if err != nil || reads != 0 {
		t.Fatal("prepare rejected precise record or read token", err)
	}
	frozen := bytes.Clone(envelope.Body)
	if err := client.IngestEnvelope(context.Background(), RuntimeEnvelope(envelope)); err != ErrClient || reads != 0 {
		t.Fatal("V1 adopted precise envelope", err)
	}
	if err := client.IngestPreciseEnvelope(context.Background(), envelope); err != ErrClientRetryable {
		t.Fatal("first attempt", err)
	}
	saved, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var restored PreciseRuntimeEnvelope
	if err := json.Unmarshal(saved, &restored); err != nil {
		t.Fatal(err)
	}
	token = envelopeCredential(t, 94)
	event.ObservedLineage.SourceEventTime = "2026-08-20T12:00:00.123111111Z"
	if err := client.IngestPreciseEnvelope(context.Background(), restored); err != nil {
		t.Fatal("retry", err)
	}
	if reads != 2 || len(sent) != 2 || !bytes.Equal(sent[0], frozen) || !bytes.Equal(sent[1], frozen) || auth[0] == auth[1] {
		t.Fatal("retry changed bytes or failed credential rotation")
	}
	var body struct {
		Source string                `json:"source"`
		Events []PreciseRuntimeEvent `json:"events"`
	}
	if err := json.Unmarshal(sent[1], &body); err != nil || len(body.Events) != 1 || body.Events[0].ObservedLineage.SourceEventTime != "2026-08-20T12:00:00.123999999Z" || body.Events[0].ObservedLineage.ProcessStartTime != "2026-08-20T12:00:00.123456789Z" {
		t.Fatal("retry lost exact source identity", err)
	}
	legacyEvent, err := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := client.PrepareEnvelope([]RuntimeEvent{legacyEvent})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.IngestPreciseEnvelope(context.Background(), PreciseRuntimeEnvelope(legacy)); err != ErrClient || reads != 2 {
		t.Fatal("V2 adopted V1 envelope", err)
	}
}

func TestPreciseEnvelopePreparationBoundsAndUnqualifiedFence(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	config := ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { t.Fatal("preparation read token"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) { t.Fatal("preparation used transport"); return nil, nil }}
	client, err := NewProductionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	event := preciseRecordFixture(t)
	for name, events := range map[string][]PreciseRuntimeEvent{
		"empty":       nil,
		"too many":    make([]PreciseRuntimeEvent, 1001),
		"zero record": {{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.PreparePreciseEnvelope(events); err != ErrClient {
				t.Fatal("invalid batch prepared", err)
			}
		})
	}
	for name, change := range map[string]func(*PreciseRuntimeEvent){
		"source bin":     func(e *PreciseRuntimeEvent) { e.EventTime = "2026-08-20T12:00:00.124Z" },
		"process future": func(e *PreciseRuntimeEvent) { e.ObservedLineage.ProcessStartTime = "2026-08-20T12:00:00.124Z" },
		"metadata":       func(e *PreciseRuntimeEvent) { e.Class = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			e := event
			change(&e)
			if _, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{e}); err != ErrClient {
				t.Fatal("invalid record prepared", err)
			}
		})
	}
	now = now.Add(-6 * time.Minute)
	if _, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{event}); err != ErrClient {
		t.Fatal("future record prepared", err)
	}
	now = now.Add(26 * time.Hour)
	if _, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{event}); err != ErrEnvelopeExpired {
		t.Fatal("expired record prepared", err)
	}
	now = time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	event.ObservedLineage = runtimelineage.PreciseObservation{}
	event.RuntimeEvent.ObservedLineage = runtimelineage.Observation{}
	envelope, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{event})
	if err != nil || bytes.Contains(envelope.Body, []byte("observed_lineage")) {
		t.Fatal("unqualified source changed", err)
	}
	if err := client.IngestEnvelope(context.Background(), RuntimeEnvelope(envelope)); err != ErrClient {
		t.Fatal("unqualified precise envelope downgraded", err)
	}
	config.EnrollmentBinding = ""
	unbound, err := NewProductionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbound.PreparePreciseEnvelope([]PreciseRuntimeEvent{event}); err != ErrClient {
		t.Fatal("unbound precise envelope", err)
	}
	var missing *ProductionClient
	if _, err := missing.PreparePreciseEnvelope([]PreciseRuntimeEvent{event}); err != ErrClient {
		t.Fatal("nil client", err)
	}
	if err := missing.IngestPreciseEnvelope(context.Background(), envelope); err != ErrClient {
		t.Fatal("nil ingest client", err)
	}
}

func TestPreciseEnvelopeRejectsDriftBeforeCredentials(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { t.Fatal("invalid envelope read credential"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid envelope reached transport")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{preciseRecordFixture(t)})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PreciseRuntimeEnvelope){
		"destination": func(e *PreciseRuntimeEnvelope) {
			e.Destination = "https://other.example.test/internal/v1/runtime/events"
		},
		"enrollment": func(e *PreciseRuntimeEnvelope) { e.EnrollmentBinding = strings.Repeat("b", 64) },
		"version":    func(e *PreciseRuntimeEnvelope) { e.Version = "sensor-ingest-envelope-v1" },
		"schema":     func(e *PreciseRuntimeEnvelope) { e.Schema = "runtime-event-enrollment-v1" },
		"digest":     func(e *PreciseRuntimeEnvelope) { e.IdempotencyKey = "runtime-v2:" + strings.Repeat("0", 64) },
		"alias": func(e *PreciseRuntimeEnvelope) {
			e.Body = bytes.Replace(e.Body, []byte(`"source":`), []byte(`"Source":`), 1)
		},
		"duplicate": func(e *PreciseRuntimeEnvelope) {
			e.Body = bytes.Replace(e.Body, []byte(`"source":`), []byte(`"source":"tetragon","source":`), 1)
		},
		"wrong bin": func(e *PreciseRuntimeEnvelope) {
			e.Body = bytes.Replace(e.Body, []byte("12:00:00.123Z"), []byte("12:00:00.124Z"), 1)
		},
		"empty": func(e *PreciseRuntimeEnvelope) { e.Body = []byte(`{"source":"tetragon","events":[]}`) },
		"oversized body": func(e *PreciseRuntimeEnvelope) {
			event := preciseRecordFixture(t)
			event.Content = map[string]string{}
			for _, key := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
				event.Content[key] = strings.Repeat("<", 256)
			}
			record, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var verified PreciseRuntimeEvent
			if err := json.Unmarshal(record, &verified); err != nil {
				t.Fatal("oversized fixture contains invalid event", err)
			}
			e.Body = append([]byte(`{"source":"tetragon","events":[`), bytes.Repeat(append(bytes.Clone(record), ','), 999)...)
			e.Body = append(e.Body, record...)
			e.Body = append(e.Body, ']', '}')
			if len(e.Body) <= 8<<20 {
				t.Fatal("fixture does not exceed envelope byte limit")
			}
		},
		"too many events": func(e *PreciseRuntimeEnvelope) {
			record, err := json.Marshal(preciseRecordFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			e.Body = append([]byte(`{"source":"tetragon","events":[`), bytes.Repeat(append(bytes.Clone(record), ','), 1000)...)
			e.Body = append(e.Body, record...)
			e.Body = append(e.Body, ']', '}')
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := envelope
			e.Body = bytes.Clone(e.Body)
			change(&e)
			if name != "digest" {
				digest := sha256.Sum256(e.Body)
				e.IdempotencyKey = "runtime-v2:" + hex.EncodeToString(digest[:])
			}
			if err := client.IngestPreciseEnvelope(context.Background(), e); err != ErrClient {
				t.Fatal("drift accepted", err)
			}
		})
	}
	now = now.Add(25 * time.Hour)
	if err := client.IngestPreciseEnvelope(context.Background(), envelope); err != ErrEnvelopeExpired {
		t.Fatal("expired envelope not retained for recovery", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.IngestPreciseEnvelope(ctx, envelope); err != ErrClientRetryable {
		t.Fatal("cancellation", err)
	}
}

func TestPreciseEnvelopeServerRejectionHasNoFallback(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden} {
		attempts := 0
		client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC) }, Token: func() ([]byte, error) { return []byte(envelopeCredential(t, 93)), nil }, Do: func(request *http.Request) (*http.Response, error) {
			attempts++
			if request.Header.Get("X-Zasp-Runtime-Schema") != "runtime-event-enrollment-v2" {
				t.Fatal("server rejection caused schema downgrade")
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := client.PreparePreciseEnvelope([]PreciseRuntimeEvent{preciseRecordFixture(t)})
		if err != nil {
			t.Fatal(err)
		}
		before, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		want := ErrClientRetryable
		if status == http.StatusForbidden {
			want = ErrClientDenied
		}
		if err := client.IngestPreciseEnvelope(context.Background(), envelope); err != want || attempts != 1 {
			t.Fatal("rejection retried or downgraded", err, attempts)
		}
		after, err := json.Marshal(envelope)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("rejection changed saved envelope", err)
		}
	}
}
