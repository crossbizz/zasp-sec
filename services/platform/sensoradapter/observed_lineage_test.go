package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
)

func adapterLineageFixture() runtimelineage.Observation {
	return runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: "2026-08-20T11:59:59.123456789Z", CgroupID: "12345"}
}

func TestSensorLineageAbsentPreservesExistingWire(t *testing.T) {
	event, err := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	if err != nil {
		t.Fatal(err)
	}
	// Pin the preceding field order/omission contract independently of the new
	// RuntimeEvent field. Normalization has no source-generation proof yet.
	legacy := struct {
		SearchMetadata runtimemetadata.Fields `json:"search_metadata,omitzero"`
		EventID        string                 `json:"event_id"`
		Class          string                 `json:"class"`
		Action         string                 `json:"action"`
		WorkloadID     string                 `json:"workload_id"`
		EventTime      string                 `json:"event_time"`
		EvidenceID     string                 `json:"evidence_id"`
		Content        map[string]string      `json:"content,omitempty"`
	}{event.SearchMetadata, event.EventID, event.Class, event.Action, event.WorkloadID, event.EventTime, event.EvidenceID, event.Content}
	want, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(event)
	if err != nil || !bytes.Equal(got, want) || bytes.Contains(got, []byte("observed_lineage")) || event.ObservedLineage != (runtimelineage.Observation{}) {
		t.Fatal("absent lineage changed original wire bytes", err)
	}
}

func TestSensorLineageRejectsInvalidObservationBeforeCredentials(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for _, bound := range []bool{false, true} {
		for name, change := range map[string]func(*runtimelineage.Observation){
			"unknown profile":             func(v *runtimelineage.Observation) { v.Profile = "future" },
			"name instead of UID":         func(v *runtimelineage.Observation) { v.NodeUID = "node-a" },
			"missing boot":                func(v *runtimelineage.Observation) { v.BootID = "" },
			"abbreviated container":       func(v *runtimelineage.Observation) { v.ContainerID = "0123456789abcde" },
			"bare process":                func(v *runtimelineage.Observation) { v.ProcessStartTime = "" },
			"reused PID without PID":      func(v *runtimelineage.Observation) { v.ProcessID = "" },
			"process after rounded event": func(v *runtimelineage.Observation) { v.ProcessStartTime = "2026-08-20T12:00:00.000000001Z" },
			"cgroup overflow":             func(v *runtimelineage.Observation) { v.CgroupID = "18446744073709551616" },
		} {
			t.Run(name+map[bool]string{false: "/legacy", true: "/bound"}[bound], func(t *testing.T) {
				config := ProductionClientConfig{BaseURL: "https://runtime.example.test", Now: func() time.Time { return now }, Token: func() ([]byte, error) { t.Error("invalid lineage read a credential"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) {
					t.Error("invalid lineage reached transport")
					return nil, nil
				}}
				if bound {
					config.EnrollmentBinding = strings.Repeat("a", 64)
				}
				client, err := NewProductionClient(config)
				if err != nil {
					t.Fatal(err)
				}
				event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
				event.ObservedLineage = adapterLineageFixture()
				change(&event.ObservedLineage)
				if err := client.Ingest(context.Background(), []RuntimeEvent{event}); err != ErrClient {
					t.Fatal("invalid lineage didn't fail validation", err)
				}
				if _, err := checkpointEventsSize([]RuntimeEvent{event}); err != ErrStream {
					t.Fatal("invalid lineage checkpoint accepted", err)
				}
			})
		}
	}
}

func TestSensorLineageFrozenEnvelopeSurvivesCheckpointRestart(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	token := envelopeCredential(t, 93)
	tokenReads, attempts := 0, 0
	var sent [][]byte
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { tokenReads++; return []byte(token), nil }, Do: func(request *http.Request) (*http.Response, error) {
		attempts++
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, body)
		if attempts == 1 {
			return nil, ErrClientRetryable
		}
		return envelopeAccepted(), nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	event.ObservedLineage = adapterLineageFixture()
	envelope, err := client.PrepareEnvelope([]RuntimeEvent{event})
	if err != nil || tokenReads != 0 {
		t.Fatal("prepare read credentials or rejected valid lineage", err)
	}
	frozen := bytes.Clone(envelope.Body)
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, "")
	processor := newFixtureFileProcessor(t, logPath, cursorPath, client)
	from := cursorState{Version: cursorContractVersion, Device: 1, Inode: 1}
	next := from
	next.Offset = 1
	checkpoint := &streamCheckpoint{Version: streamCheckpointVersion, Source: processor.sourceBinding, Target: streamSinkTarget(client), Committed: &from, Pending: &pendingStream{From: from, State: next, EndOffset: 1, Cache: []cachedProcessIdentity{}, Envelope: &envelope, Result: StreamResult{Read: 1, Submitted: 1}}}
	if err := processor.persistCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	// This fixture injects a qualified envelope, not source emission. Loading
	// and replaying it must never consult newly fetched host identity.
	if _, err := processor.ProcessAvailable(context.Background()); err != ErrClientRetryable {
		t.Fatal("uncertain replay", err)
	}
	if err := processor.Close(); err != nil {
		t.Fatal(err)
	}
	event.ObservedLineage.BootID = "12345678-1234-1234-1234-123456789099"
	token = envelopeCredential(t, 94)
	restarted := newFixtureFileProcessor(t, logPath, cursorPath, client)
	defer restarted.Close()
	if result, err := restarted.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatal("restart replay", result, err)
	}
	if len(sent) != 2 || tokenReads != 2 || !bytes.Equal(sent[0], frozen) || !bytes.Equal(sent[1], frozen) {
		t.Fatal("restart changed frozen lineage")
	}
	var decoded runtimeEnvelopeBody
	if err := json.Unmarshal(sent[1], &decoded); err != nil || len(decoded.Events) != 1 || decoded.Events[0].ObservedLineage != adapterLineageFixture() {
		t.Fatal("lineage bytes or process precision lost", err)
	}
}

func TestSensorLineageRejectsHostileFrozenWire(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { t.Fatal("hostile wire read credentials"); return nil, nil }, Do: func(*http.Request) (*http.Response, error) {
		t.Fatal("hostile wire reached transport")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := NormalizeTetragonLine([]byte(tetragonExecFixture()))
	event.ObservedLineage = adapterLineageFixture()
	envelope, err := client.PrepareEnvelope([]RuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := json.Marshal(event.ObservedLineage)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"null":                      []byte("null"),
		"empty":                     []byte("{}"),
		"duplicate":                 bytes.Replace(observation, []byte(`"process_id":`), []byte(`"process_id":"41","process_id":`), 1),
		"case alias":                bytes.Replace(observation, []byte(`"boot_id":`), []byte(`"Boot_id":`), 1),
		"escaped key":               bytes.Replace(observation, []byte(`"boot_id":`), []byte(`"boot_\u0069d":`), 1),
		"unknown field":             bytes.Replace(observation, []byte(`"profile":`), []byte(`"authority":"Exact","profile":`), 1),
		"noncanonical process time": bytes.Replace(observation, []byte(`2026-08-20T11:59:59.123456789Z`), []byte(`2026-08-20T11:59:59.123456789+00:00`), 1),
		"process after event":       bytes.Replace(observation, []byte(`2026-08-20T11:59:59.123456789Z`), []byte(`2026-08-20T12:00:00.000000001Z`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			changed := envelope
			changed.Body = bytes.Replace(envelope.Body, observation, raw, 1)
			if bytes.Equal(changed.Body, envelope.Body) {
				t.Fatal("mutation didn't change body")
			}
			// Recompute the digest to exercise decoding, not only its checksum.
			changed.IdempotencyKey = envelopeIdempotency(changed.Body)
			if err := client.IngestEnvelope(context.Background(), changed); err != ErrClient {
				t.Fatal("hostile lineage accepted", err)
			}
		})
	}
}
