package sensoradapter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func preciseSourceFixture() LineageSource {
	source := lineageSourceFixture()
	source.Profile = "tetragon-local-stream-v3"
	return source
}

func preciseProviderLine(t *testing.T, kind, eventTime, start string, partial bool) []byte {
	t.Helper()
	line := tetragonExecFixture()
	if kind == "process_kprobe" {
		line = tetragonFileFixture()
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(qualifiedTetragonFixture(line)), &root); err != nil {
		t.Fatal(err)
	}
	root["time"] = eventTime
	process := root[kind].(map[string]any)["process"].(map[string]any)
	process["start_time"] = start
	if partial {
		root[kind].(map[string]any)["process"] = map[string]any{"pid": 42, "flags": "unknown", "start_time": start}
	}
	body, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPreciseSourceRetainsNanosecondsAndRefusesLegacyGeneration(t *testing.T) {
	source := preciseSourceFixture()
	if legacy, err := NewLineageNormalizer(8, source); err == nil || legacy != nil {
		t.Fatal("legacy normalizer adopted V3 generation")
	}
	normalizer, err := NewPreciseLineageNormalizer(8, source)
	if err != nil {
		t.Fatal(err)
	}
	source.BootID = "12345678-1234-1234-1234-123456789099"
	line := preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.123456789Z", false)
	event, err := normalizer.Normalize(line)
	if err != nil || event.EventTime != "2026-08-20T12:00:00.123Z" || event.ObservedLineage.SourceEventTime != "2026-08-20T12:00:00.123999999Z" || event.ObservedLineage.ProcessStartTime != "2026-08-20T12:00:00.123456789Z" || event.ObservedLineage.ProcessID != "42" || event.ObservedLineage.BootID != lineageSourceFixture().BootID {
		t.Fatal("source precision or identity lost", event, err)
	}
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var legacy RuntimeEvent
	if json.Unmarshal(body, &legacy) == nil {
		t.Fatal("legacy decoder accepted precise source")
	}
	if validRuntimeEvent(event.RuntimeEvent, time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)) {
		t.Fatal("extracting base record downgraded qualified precision")
	}
	partial := preciseProviderLine(t, "process_kprobe", "2026-08-20T12:00:01.987654321Z", "2026-08-20T12:00:00.123456789Z", true)
	file, err := normalizer.Normalize(partial)
	if err != nil || file.Class != "file" || file.ObservedLineage.ProcessStartTime != event.ObservedLineage.ProcessStartTime || file.ObservedLineage.SourceEventTime != "2026-08-20T12:00:01.987654321Z" {
		t.Fatal("cached process lost precision", file, err)
	}
}

func TestPreciseSourceKeepsMissingIdentityAbsentAndFutureProcessUnqualified(t *testing.T) {
	for _, profile := range []string{"tetragon-local-stream-v1", "tetragon-local-stream-v2", "future"} {
		source := preciseSourceFixture()
		source.Profile = profile
		if n, err := NewPreciseLineageNormalizer(8, source); err == nil || n != nil {
			t.Fatal("wrong generation accepted")
		}
	}
	for _, future := range []bool{false, true} {
		n, err := NewPreciseLineageNormalizer(8, preciseSourceFixture())
		if err != nil {
			t.Fatal(err)
		}
		line := preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.124Z", false)
		if !future {
			line = []byte(strings.Replace(string(line), adapterLineageFixture().PodUID, "unqualified-pod", 1))
		}
		event, err := n.Normalize(line)
		if err != nil {
			t.Fatal(err)
		}
		if !future && event.ObservedLineage != (runtimelineage.PreciseObservation{}) {
			t.Fatal("missing identity invented")
		}
		if future && (event.ObservedLineage.ProcessID != "" || event.ObservedLineage.ProcessStartTime != "" || event.ObservedLineage.SourceEventTime == "") {
			t.Fatal("future process gained identity")
		}
		if _, err := json.Marshal(event); err != nil {
			t.Fatal("unqualified source cannot serialize", err)
		}
	}
}

func TestPreciseSourceOmitsInvalidProcessStartWithoutDroppingContainer(t *testing.T) {
	for _, start := range []string{"1970-01-01T00:00:00Z", "1969-12-31T23:59:59Z"} {
		t.Run(start, func(t *testing.T) {
			line := preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", start, false)
			legacy, err := NewLineageNormalizer(8, lineageSourceFixture())
			if err != nil {
				t.Fatal(err)
			}
			old, err := legacy.Normalize(line)
			if err != nil || old.ObservedLineage.ContainerID == "" || old.ObservedLineage.ProcessID != "" {
				t.Fatal("legacy omission control", err)
			}
			precise, err := NewPreciseLineageNormalizer(8, preciseSourceFixture())
			if err != nil {
				t.Fatal(err)
			}
			event, err := precise.Normalize(line)
			if err != nil || event.ObservedLineage.ContainerID != old.ObservedLineage.ContainerID || event.ObservedLineage.ProcessID != "" || event.ObservedLineage.ProcessStartTime != "" || event.ObservedLineage.SourceEventTime != "2026-08-20T12:00:00.123999999Z" {
				t.Fatal("invalid process start dropped valid source observation", event, err)
			}
		})
	}
}
