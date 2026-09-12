package sensoradapter

import (
	"strconv"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

// PreciseRuntimeEvent belongs to the next versioned source envelope, not the
// legacy client/checkpoint path. Qualified JSON is rejected by V1 decoders.
type PreciseRuntimeEvent struct {
	RuntimeEvent
	ObservedLineage runtimelineage.PreciseObservation `json:"observed_lineage,omitzero"`
}

// PreciseNormalizer deliberately doesn't expose the legacy Normalizer or
// implement its return type. Old FileProcessors cannot adopt this generation.
type PreciseNormalizer struct {
	normalizer *Normalizer
	source     LineageSource
}

func NewPreciseLineageNormalizer(maximum int, source LineageSource) (*PreciseNormalizer, error) {
	if source.Profile != "tetragon-local-stream-v3" {
		return nil, ErrAdapter
	}
	// V3 retains V2's event-local file/cgroup semantics. Its separate public
	// constructor, record type and original source bind the new precision fence.
	compatible := source
	compatible.Profile = "tetragon-local-stream-v2"
	inner, err := NewLineageNormalizer(maximum, compatible)
	if err != nil {
		return nil, err
	}
	return &PreciseNormalizer{normalizer: inner, source: source}, nil
}

func (normalizer *PreciseNormalizer) Normalize(line []byte) (PreciseRuntimeEvent, error) {
	if normalizer == nil || normalizer.normalizer == nil {
		return PreciseRuntimeEvent{}, ErrAdapter
	}
	var precise runtimelineage.PreciseObservation
	event, err := normalizer.normalizer.normalizeObserved(line, func(root providerRoot, process providerProcess, event *RuntimeEvent) error {
		if event.ObservedLineage == (runtimelineage.Observation{}) {
			return nil
		}
		base := event.ObservedLineage
		base.Profile = "kubernetes-container-v2"
		base.ProcessID, base.ProcessStartTime = "", ""
		precise = runtimelineage.PreciseObservation{Observation: base, SourceEventTime: root.sourceTime.Format(time.RFC3339Nano)}
		if start, ok := parseProviderTimestamp(process.StartTime); ok && process.PID > 0 && !start.After(root.sourceTime) {
			candidate := precise
			candidate.ProcessID = strconv.FormatUint(uint64(process.PID), 10)
			candidate.ProcessStartTime = start.Format(time.RFC3339Nano)
			if candidate.Valid() {
				precise = candidate
			}
		}
		wire, err := time.Parse(timestampLayout, event.EventTime)
		if err != nil || !precise.ValidAt(wire) {
			return ErrAdapter
		}
		// Explicit extraction of the embedded legacy record also fails V1
		// validation instead of silently losing its precision qualification.
		event.ObservedLineage = precise.Observation
		return nil
	})
	if err != nil {
		return PreciseRuntimeEvent{}, err
	}
	return PreciseRuntimeEvent{RuntimeEvent: event, ObservedLineage: precise}, nil
}
