package runtimelineage

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

// PreciseObservation is an explicit V2 contract. Existing Observation decoders
// still reject it. Source emission and consumers must opt in through versioned
// envelopes and frozen algorithms before this type can be used in production.
type PreciseObservation struct {
	Observation
	SourceEventTime string `json:"source_event_time"`
}

func (value PreciseObservation) Valid() bool {
	if value.Profile != "kubernetes-container-v2" {
		return false
	}
	identity := value.Observation
	identity.Profile = "kubernetes-container-v1"
	if !identity.Valid() {
		return false
	}
	source, ok := processStart(value.SourceEventTime)
	if !ok {
		return false
	}
	if value.ProcessStartTime == "" {
		return true
	}
	start, ok := processStart(value.ProcessStartTime)
	return ok && !start.After(source)
}

func (value PreciseObservation) ValidAt(wire time.Time) bool {
	_, err := value.TimeAt(wire)
	return err == nil
}

// TimeAt returns the source instant only when bound to its exact millisecond
// display timestamp. Matching must use this result, never round a process start.
func (value PreciseObservation) TimeAt(wire time.Time) (time.Time, error) {
	if !value.Valid() || wire.IsZero() || wire.Location() != time.UTC || !wire.Equal(wire.Truncate(time.Millisecond)) {
		return time.Time{}, ErrInput
	}
	source, _ := processStart(value.SourceEventTime)
	if !source.Truncate(time.Millisecond).Equal(wire) {
		return time.Time{}, ErrInput
	}
	return source, nil
}

func (value PreciseObservation) MarshalJSON() ([]byte, error) {
	if !value.Valid() {
		return nil, ErrInput
	}
	// Alias removes Observation's methods while retaining its exact JSON fields.
	type fields Observation
	return json.Marshal(struct {
		fields
		SourceEventTime string `json:"source_event_time"`
	}{fields(value.Observation), value.SourceEventTime})
}

func (value *PreciseObservation) UnmarshalJSON(body []byte) error {
	if value == nil || len(body) == 0 || len(body) > 1280 {
		return ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrInput
	}
	var result PreciseObservation
	fields := map[string]*string{
		"profile": &result.Profile, "cluster_uid": &result.ClusterUID,
		"node_uid": &result.NodeUID, "boot_id": &result.BootID,
		"pod_uid": &result.PodUID, "container_id": &result.ContainerID,
		"process_id": &result.ProcessID, "process_start_time": &result.ProcessStartTime,
		"cgroup_id": &result.CgroupID, "source_event_time": &result.SourceEventTime,
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		before := decoder.InputOffset()
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] == nil || seen[key] || bytes.Contains(body[before:decoder.InputOffset()], []byte{'\\'}) {
			return ErrInput
		}
		seen[key] = true
		token, err = decoder.Token()
		text, ok := token.(string)
		if err != nil || !ok || text == "" {
			return ErrInput
		}
		*fields[key] = text
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || decoder.Decode(&struct{}{}) != io.EOF || !result.Valid() {
		return ErrInput
	}
	*value = result
	return nil
}
