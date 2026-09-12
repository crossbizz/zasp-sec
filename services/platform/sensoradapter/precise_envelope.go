package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

const preciseEnvelopeVersion = "sensor-ingest-envelope-v2"
const preciseEnrollmentSchema = "runtime-event-enrollment-v2"

// PreciseRuntimeEnvelope is deliberately distinct from legacy saved envelopes.
// No credential is retained. Callers own durable persistence before sending.
type PreciseRuntimeEnvelope RuntimeEnvelope

type preciseEnvelopeBody struct {
	Source string                `json:"source"`
	Events []PreciseRuntimeEvent `json:"events"`
}

func (client *ProductionClient) PreparePreciseEnvelope(events []PreciseRuntimeEvent) (PreciseRuntimeEnvelope, error) {
	if client == nil || client.enrollment == "" {
		return PreciseRuntimeEnvelope{}, ErrClient
	}
	now, err := safeNow(client.now)
	if err != nil {
		return PreciseRuntimeEnvelope{}, err
	}
	if err := validatePreciseEnvelopeEvents(events, now); err != nil {
		return PreciseRuntimeEnvelope{}, err
	}
	body, err := json.Marshal(preciseEnvelopeBody{Source: "tetragon", Events: events})
	if err != nil || len(body) > maximumEnvelopeBodyBytes {
		clear(body)
		return PreciseRuntimeEnvelope{}, ErrClient
	}
	return PreciseRuntimeEnvelope{Version: preciseEnvelopeVersion, Destination: client.base.String() + runtimeEventsPath, EnrollmentBinding: client.enrollment, Schema: preciseEnrollmentSchema, IdempotencyKey: preciseEnvelopeIdempotency(body), Body: body}, nil
}

func (client *ProductionClient) IngestPreciseEnvelope(ctx context.Context, envelope PreciseRuntimeEnvelope) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrClientRetryable
	}
	if client == nil || client.enrollment == "" || envelope.Version != preciseEnvelopeVersion || envelope.Destination != client.base.String()+runtimeEventsPath || envelope.EnrollmentBinding != client.enrollment || envelope.Schema != preciseEnrollmentSchema || len(envelope.Body) == 0 || len(envelope.Body) > maximumEnvelopeBodyBytes || envelope.IdempotencyKey != preciseEnvelopeIdempotency(envelope.Body) {
		return ErrClient
	}
	var decoded preciseEnvelopeBody
	// Bound arrays before allocating decoded records. The frozen serializer is
	// compact JSON; alternate spellings aren't valid retry payloads.
	if !checkpointJSONBounded(envelope.Body, maximumBatchEvents) || decodeClosed(envelope.Body, &decoded) != nil || decoded.Source != "tetragon" {
		return ErrClient
	}
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
	if err := validatePreciseEnvelopeEvents(decoded.Events, now); err != nil {
		return err
	}
	return client.send(ctx, runtimeEventsPath, "application/json", envelope.Schema, envelope.IdempotencyKey, canonical, http.StatusAccepted, true)
}

func preciseEnvelopeIdempotency(body []byte) string {
	digest := sha256.Sum256(body)
	return "runtime-v2:" + hex.EncodeToString(digest[:])
}

func validatePreciseEnvelopeEvents(events []PreciseRuntimeEvent, now time.Time) error {
	if len(events) == 0 || len(events) > maximumBatchEvents {
		return ErrClient
	}
	for _, event := range events {
		when, err := time.Parse(timestampLayout, event.EventTime)
		if err == nil && when.Format(timestampLayout) == event.EventTime && when.Before(now.Add(-24*time.Hour)) {
			return ErrEnvelopeExpired
		}
		if err != nil || event.ObservedLineage != (runtimelineage.PreciseObservation{}) && !event.ObservedLineage.ValidAt(when) {
			return ErrClient
		}
		base := event.RuntimeEvent
		base.ObservedLineage = runtimelineage.Observation{}
		if !validRuntimeEvent(base, now) {
			return ErrClient
		}
	}
	return nil
}
