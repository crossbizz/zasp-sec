package sensoradapter

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

// Constructors select the complete immutable generation contract. The shared
// state machine owns cache, progress, filesystem authority and upload barriers.
type chunkRecordContract[E any] struct {
	checkpointVersion, envelopeVersion, schema string
	normalize                                  func([]byte) (E, error)
	prepare                                    func(*ProductionClient, []E) (RuntimeEnvelope, error)
	ingest                                     func(*ProductionClient, context.Context, RuntimeEnvelope) error
	idempotency                                func([]byte) string
	decode                                     func([]byte) ([]E, error)
	eventSize                                  func([]E) (int, error)
	observation                                func(E) runtimelineage.Observation
}

func (p *chunkProcessor[E]) target() streamTarget {
	target := streamSinkTarget(p.client)
	target.Mode = p.contract.envelopeVersion
	return target
}

func legacyChunkContract(normalizer *Normalizer) chunkRecordContract[RuntimeEvent] {
	return chunkRecordContract[RuntimeEvent]{
		checkpointVersion: chunkCheckpointVersion, envelopeVersion: runtimeEnvelopeVersion, schema: enrollmentRuntimeSchema,
		normalize: normalizer.Normalize, idempotency: envelopeIdempotency, eventSize: checkpointEventsSize,
		prepare: func(client *ProductionClient, events []RuntimeEvent) (RuntimeEnvelope, error) {
			return safeStreamEnvelopePrepare(client, cloneRuntimeEvents(events))
		},
		ingest:      safeStreamEnvelopeIngest,
		observation: func(event RuntimeEvent) runtimelineage.Observation { return event.ObservedLineage },
		decode: func(raw []byte) ([]RuntimeEvent, error) {
			var body runtimeEnvelopeBody
			if !checkpointJSONBounded(raw, maximumBatchEvents) || json.Unmarshal(raw, &body) != nil || body.Source != "tetragon" || !canonicalChunkBody(raw, body) {
				return nil, ErrStream
			}
			return body.Events, nil
		},
	}
}

func preciseChunkContract(normalizer *PreciseNormalizer) chunkRecordContract[PreciseRuntimeEvent] {
	return chunkRecordContract[PreciseRuntimeEvent]{
		checkpointVersion: "tetragon-chunk-checkpoint-v2", envelopeVersion: preciseEnvelopeVersion, schema: preciseEnrollmentSchema,
		normalize: normalizer.Normalize, idempotency: preciseEnvelopeIdempotency, eventSize: preciseCheckpointEventsSize,
		prepare: safePreciseChunkPrepare, ingest: safePreciseChunkIngest,
		observation: func(event PreciseRuntimeEvent) runtimelineage.Observation { return event.ObservedLineage.Observation },
		decode: func(raw []byte) ([]PreciseRuntimeEvent, error) {
			var body preciseEnvelopeBody
			if !checkpointJSONBounded(raw, maximumBatchEvents) || json.Unmarshal(raw, &body) != nil || body.Source != "tetragon" || !canonicalChunkBody(raw, body) {
				return nil, ErrStream
			}
			return body.Events, nil
		},
	}
}

func canonicalChunkBody(raw []byte, body any) bool {
	comparison := &checkpointComparisonWriter{expected: append(raw[:len(raw):len(raw)], '\n')}
	return json.NewEncoder(comparison).Encode(body) == nil && comparison.offset == len(comparison.expected)
}

func preciseCheckpointEventsSize(events []PreciseRuntimeEvent) (int, error) {
	if len(events) > maximumBatchEvents {
		return 0, ErrStream
	}
	size := 2
	for _, event := range events {
		when, err := time.Parse(timestampLayout, event.EventTime)
		if err != nil || validatePreciseEnvelopeEvents([]PreciseRuntimeEvent{event}, when) != nil {
			return 0, ErrStream
		}
		body, err := json.Marshal(event)
		if err != nil || len(body)+1 > maximumEnvelopeBodyBytes-size {
			return 0, ErrStream
		}
		size += len(body) + 1
	}
	return size, nil
}

func safePreciseChunkPrepare(client *ProductionClient, events []PreciseRuntimeEvent) (envelope RuntimeEnvelope, err error) {
	defer func() {
		if recover() != nil {
			envelope = RuntimeEnvelope{}
			err = ErrClientRetryable
		}
	}()
	owned := make([]PreciseRuntimeEvent, len(events))
	for i, event := range events {
		owned[i] = event
		owned[i].Content = make(map[string]string, len(event.Content))
		for key, value := range event.Content {
			owned[i].Content[key] = value
		}
	}
	prepared, err := client.PreparePreciseEnvelope(owned)
	return RuntimeEnvelope(prepared), err
}

func safePreciseChunkIngest(client *ProductionClient, ctx context.Context, envelope RuntimeEnvelope) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrClientRetryable
		}
	}()
	return client.IngestPreciseEnvelope(ctx, PreciseRuntimeEnvelope(envelope))
}
