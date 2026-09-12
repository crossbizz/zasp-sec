package runtimelineage

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func preciseFixture() PreciseObservation {
	base := fixtureObservation()
	base.Profile = "kubernetes-container-v2"
	base.ProcessID, base.ProcessStartTime = "42", "2026-09-09T12:00:00.123456789Z"
	return PreciseObservation{Observation: base, SourceEventTime: "2026-09-09T12:00:00.123999999Z"}
}

func TestPreciseObservationRetainsSameMillisecondProcessAndSourceInstant(t *testing.T) {
	value := preciseFixture()
	wire := time.Date(2026, 9, 9, 12, 0, 0, 123000000, time.UTC)
	when, err := value.TimeAt(wire)
	if err != nil || !value.Valid() || !value.ValidAt(wire) || when.Format(time.RFC3339Nano) != "2026-09-09T12:00:00.123999999Z" {
		t.Fatal("lost precise source event", when, err)
	}
	body, err := json.Marshal(value)
	if err != nil || !strings.Contains(string(body), `"source_event_time":"2026-09-09T12:00:00.123999999Z"`) || !strings.Contains(string(body), `"process_start_time":"2026-09-09T12:00:00.123456789Z"`) {
		t.Fatal("lost precise wire times", string(body), err)
	}
	var decoded PreciseObservation
	if err := json.Unmarshal(body, &decoded); err != nil || decoded != value {
		t.Fatal("precise round trip", err)
	}
	var legacy Observation
	if json.Unmarshal(body, &legacy) == nil || value.Observation.ValidAt(wire) {
		t.Fatal("new precision changed V1 acceptance")
	}
	value.ProcessID, value.ProcessStartTime = "", ""
	if !value.ValidAt(wire) {
		t.Fatal("valid container observation requires optional process")
	}
}

func TestPreciseObservationRejectsTemporalAndProfileDrift(t *testing.T) {
	wire := time.Date(2026, 9, 9, 12, 0, 0, 123000000, time.UTC)
	for name, mutate := range map[string]func(*PreciseObservation){
		"missing source":      func(v *PreciseObservation) { v.SourceEventTime = "" },
		"wrong bin":           func(v *PreciseObservation) { v.SourceEventTime = "2026-09-09T12:00:00.124Z" },
		"start after source":  func(v *PreciseObservation) { v.ProcessStartTime = "2026-09-09T12:00:00.124Z" },
		"noncanonical offset": func(v *PreciseObservation) { v.SourceEventTime = "2026-09-09T12:00:00.123999999+00:00" },
		"redundant zero":      func(v *PreciseObservation) { v.SourceEventTime = "2026-09-09T12:00:00.123999990Z" },
		"legacy profile":      func(v *PreciseObservation) { v.Profile = "kubernetes-container-v1" },
		"unknown profile":     func(v *PreciseObservation) { v.Profile = "kubernetes-container-v3" },
		"missing boot":        func(v *PreciseObservation) { v.BootID = "" },
		"bare pid":            func(v *PreciseObservation) { v.ProcessStartTime = "" },
	} {
		t.Run(name, func(t *testing.T) {
			value := preciseFixture()
			mutate(&value)
			if value.ValidAt(wire) {
				t.Fatal("invalid precise observation accepted")
			}
			if _, err := value.TimeAt(wire); err == nil {
				t.Fatal("invalid precise instant returned")
			}
		})
	}
	for _, invalid := range []time.Time{time.Time{}, wire.Add(time.Nanosecond), wire.In(time.FixedZone("offset", 0))} {
		if preciseFixture().ValidAt(invalid) {
			t.Fatal("noncanonical wire time accepted")
		}
	}
}

func TestPreciseObservationDecoderRejectsHostileKeysAndLeavesReceiverUnchanged(t *testing.T) {
	body, err := json.Marshal(preciseFixture())
	if err != nil {
		t.Fatal(err)
	}
	for name, hostile := range map[string]string{
		"null": "null", "empty": "{}", "trailing": string(body) + "{}",
		"duplicate":   strings.Replace(string(body), `"source_event_time":`, `"source_event_time":"2026-09-09T12:00:00Z","source_event_time":`, 1),
		"alias":       strings.Replace(string(body), `"source_event_time":`, `"Source_event_time":`, 1),
		"escaped key": strings.Replace(string(body), `"source_event_time":`, `"source_event_\u0074ime":`, 1),
		"unknown":     strings.Replace(string(body), `"profile":`, `"authority":"Exact","profile":`, 1),
		"null time":   strings.Replace(string(body), `"2026-09-09T12:00:00.123999999Z"`, "null", 1),
	} {
		t.Run(name, func(t *testing.T) {
			value := preciseFixture()
			if json.Unmarshal([]byte(hostile), &value) == nil || value != preciseFixture() {
				t.Fatal("hostile wire accepted or receiver changed")
			}
		})
	}
}
