package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"
)

const (
	runtimeEnvelopeVersion  = "sensor-ingest-envelope-v1"
	enrollmentRuntimeSchema = "runtime-event-enrollment-v1"
	// This is a sensor-side bound, not the server's configurable request limit.
	// Oversized batches fail before transport; callers must retain their input.
	maximumEnvelopeBodyBytes = 8 << 20
)

var (
	enrollmentBindingPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ErrEnvelopeExpired       = errors.New("saved sensor envelope expired; recovery required")
)

// RuntimeEnvelope contains no credential. Its constraint binds each freshly
// authenticated attempt to the original scoped enrollment. Body is the exact
// request serialization, not a request to normalize events again after restart.
type RuntimeEnvelope struct {
	Version           string `json:"version"`
	Destination       string `json:"destination"`
	EnrollmentBinding string `json:"enrollment_binding"`
	Schema            string `json:"schema"`
	IdempotencyKey    string `json:"idempotency_key"`
	Body              []byte `json:"body"`
}

type runtimeEnvelopeBody struct {
	Source string         `json:"source"`
	Events []RuntimeEvent `json:"events"`
}

// PrepareEnvelope freezes a request without reading a token or using transport.
func (client *ProductionClient) PrepareEnvelope(events []RuntimeEvent) (RuntimeEnvelope, error) {
	if client == nil || client.enrollment == "" {
		return RuntimeEnvelope{}, ErrClient
	}
	now, err := safeNow(client.now)
	if err != nil {
		return RuntimeEnvelope{}, err
	}
	if err := validateEnvelopeEvents(events, now); err != nil {
		return RuntimeEnvelope{}, err
	}
	body, err := json.Marshal(runtimeEnvelopeBody{Source: "tetragon", Events: events})
	if err != nil || len(body) > maximumEnvelopeBodyBytes {
		clear(body)
		return RuntimeEnvelope{}, ErrClient
	}
	return RuntimeEnvelope{Version: runtimeEnvelopeVersion, Destination: client.base.String() + runtimeEventsPath, EnrollmentBinding: client.enrollment, Schema: enrollmentRuntimeSchema, IdempotencyKey: envelopeIdempotency(body), Body: body}, nil
}

// IngestEnvelope never downgrades transport or changes saved timestamps. A
// failed or expired envelope must remain in the caller's durable checkpoint.
func (client *ProductionClient) IngestEnvelope(ctx context.Context, envelope RuntimeEnvelope) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrClientRetryable
	}
	if client == nil || client.enrollment == "" || envelope.Version != runtimeEnvelopeVersion || envelope.Destination != client.base.String()+runtimeEventsPath || envelope.EnrollmentBinding != client.enrollment || envelope.Schema != enrollmentRuntimeSchema || len(envelope.Body) == 0 || len(envelope.Body) > maximumEnvelopeBodyBytes || envelope.IdempotencyKey != envelopeIdempotency(envelope.Body) {
		return ErrClient
	}
	var decoded runtimeEnvelopeBody
	if !uniqueJSON(envelope.Body) || decodeClosed(envelope.Body, &decoded) != nil || decoded.Source != "tetragon" {
		return ErrClient
	}
	// Pin the serializer as well as the envelope version. Unknown fields, aliases,
	// duplicate keys and alternate JSON spellings cannot silently change on retry.
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return ErrClient
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, envelope.Body) {
		return ErrClient
	}
	now, err := safeNow(client.now)
	if err != nil {
		return err
	}
	if err := validateEnvelopeEvents(decoded.Events, now); err != nil {
		return err
	}
	return client.send(ctx, runtimeEventsPath, "application/json", envelope.Schema, envelope.IdempotencyKey, canonical, http.StatusAccepted, true)
}

func envelopeIdempotency(body []byte) string {
	digest := sha256.Sum256(body)
	return "runtime-v1:" + hex.EncodeToString(digest[:])
}

func validateEnvelopeEvents(events []RuntimeEvent, now time.Time) error {
	if len(events) == 0 || len(events) > maximumBatchEvents {
		return ErrClient
	}
	for _, event := range events {
		when, err := time.Parse(timestampLayout, event.EventTime)
		if err == nil && when.Format(timestampLayout) == event.EventTime && when.Before(now.Add(-24*time.Hour)) {
			return ErrEnvelopeExpired
		}
		if !validRuntimeEvent(event, now) {
			return ErrClient
		}
	}
	return nil
}
