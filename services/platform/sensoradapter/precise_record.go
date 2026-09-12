package sensoradapter

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

// UnmarshalJSON accepts only the frozen precise record serialization. Decode
// into a fresh value so malformed checkpoints cannot partially replace a
// retained event. Transport applies its own current-time freshness check.
func (event *PreciseRuntimeEvent) UnmarshalJSON(payload []byte) error {
	if event == nil || len(payload) == 0 || len(payload) > maximumTetragonLineBytes || !uniqueJSON(payload) {
		return ErrAdapter
	}
	type wire PreciseRuntimeEvent
	var decoded wire
	if decodeClosed(payload, &decoded) != nil {
		return ErrAdapter
	}
	when, err := time.Parse(timestampLayout, decoded.EventTime)
	if err != nil {
		return ErrAdapter
	}
	if decoded.ObservedLineage != (runtimelineage.PreciseObservation{}) && !decoded.ObservedLineage.ValidAt(when) {
		return ErrAdapter
	}
	// Reuse the unchanged event-content contract with observation validated
	// separately. A V2 process start may legitimately follow the rounded time.
	base := decoded.RuntimeEvent
	base.ObservedLineage = runtimelineage.Observation{}
	if !validRuntimeEvent(base, when) {
		return ErrAdapter
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ErrAdapter
	}
	// Preserve the same explicit legacy rejection as freshly normalized output.
	decoded.RuntimeEvent.ObservedLineage = decoded.ObservedLineage.Observation
	*event = PreciseRuntimeEvent(decoded)
	return nil
}
