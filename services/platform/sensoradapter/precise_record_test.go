package sensoradapter

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func preciseRecordFixture(t *testing.T) PreciseRuntimeEvent {
	t.Helper()
	normalizer, err := NewPreciseLineageNormalizer(8, preciseSourceFixture())
	if err != nil {
		t.Fatal(err)
	}
	event, err := normalizer.Normalize(preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.123456789Z", false))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

// Removing decoder reconstruction would silently permit a qualified record's
// embedded legacy value to be submitted after JSON checkpoint restoration.
func TestPreciseRecordDecodePreservesLegacyFence(t *testing.T) {
	event := preciseRecordFixture(t)
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PreciseRuntimeEvent
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if validRuntimeEvent(decoded.RuntimeEvent, time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC)) {
		t.Fatal("decoded qualified record silently downgraded through embedded legacy value")
	}
	if !reflect.DeepEqual(decoded, event) {
		t.Fatal("decoded record lost source identity or exact timestamps")
	}
	roundtrip, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(body, roundtrip) {
		t.Fatal("roundtrip changed frozen bytes", err)
	}
	// Missing identity remains missing, including when reusing a populated receiver.
	event.ObservedLineage = runtimelineage.PreciseObservation{}
	event.RuntimeEvent.ObservedLineage = runtimelineage.Observation{}
	body, err = json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &decoded); err != nil || !reflect.DeepEqual(decoded, event) {
		t.Fatal("absent identity failed or retained earlier qualification", err)
	}
}

// Removing complete-record checks would accept mismatched time bins or hostile
// JSON and mutate the caller's retained event on failed decode.
func TestPreciseRecordRejectsInvalidWireWithoutMutation(t *testing.T) {
	event := preciseRecordFixture(t)
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"null":        []byte("null"),
		"empty":       []byte("{}"),
		"wrong bin":   bytes.Replace(body, []byte("12:00:00.123Z"), []byte("12:00:00.124Z"), 1),
		"class":       bytes.Replace(body, []byte(`"class":"process"`), []byte(`"class":"unknown"`), 1),
		"alias":       bytes.Replace(body, []byte(`"event_id":`), []byte(`"Event_id":`), 1),
		"escaped key": bytes.Replace(body, []byte(`"event_id":`), []byte(`"event_\u0069d":`), 1),
		"duplicate":   bytes.Replace(body, []byte(`"class":`), []byte(`"class":"file","class":`), 1),
		"unknown":     bytes.Replace(body, []byte(`"class":`), []byte(`"authority":"Exact","class":`), 1),
		"trailing":    append(bytes.Clone(body), []byte(" {}")...),
	} {
		t.Run(name, func(t *testing.T) {
			decoded := event
			if json.Unmarshal(raw, &decoded) == nil {
				t.Fatal("invalid precise wire accepted")
			}
			if !reflect.DeepEqual(decoded, event) {
				t.Fatal("failed decode mutated retained event")
			}
		})
	}
}
