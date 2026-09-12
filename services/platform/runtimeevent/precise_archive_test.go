package runtimeevent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimemetadata"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func preciseArchiveFixture(t *testing.T, qualified bool) ([]byte, IngestAuthority, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 123000000, time.UTC)
	var base ingestInput
	if err := json.Unmarshal(productionEventBody(now), &base); err != nil {
		t.Fatal(err)
	}
	e := base.Events[0]
	// Serialize the actual precise client record, independently of the server codec.
	event := sensoradapter.PreciseRuntimeEvent{RuntimeEvent: sensoradapter.RuntimeEvent{
		EventID: e.EventID, Class: e.Class, Action: e.Action, WorkloadID: e.WorkloadID, EventTime: e.EventTime, EvidenceID: e.EvidenceID, Content: e.Content,
		SearchMetadata: runtimemetadata.Fields{ProcessDigest: strings.Repeat("c", 64)},
	}}
	if qualified {
		observation := lineageObservationFixture()
		observation.Profile = "kubernetes-container-v2"
		observation.ProcessStartTime = "2026-08-20T12:00:00.123456789Z"
		event.ObservedLineage = runtimelineage.PreciseObservation{Observation: observation, SourceEventTime: "2026-08-20T12:00:00.123999999Z"}
	}
	body, err := json.Marshal(struct {
		Source string                              `json:"source"`
		Events []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}{"tetragon", []sensoradapter.PreciseRuntimeEvent{event}})
	if err != nil {
		t.Fatal(err)
	}
	return body, IngestAuthority{Scope: fixtureScope(t, 70), SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 2, Source: "tetragon", Mode: "full"}, now
}

func TestPreciseArchivePreservesSourceTimeWithoutGrantingAuthority(t *testing.T) {
	for _, qualified := range []bool{true, false} {
		for _, mode := range []string{"full", "metadata_only"} {
			body, authority, now := preciseArchiveFixture(t, qualified)
			authority.Mode = mode
			_, archive, err := decodePreciseProductionInput(body, authority, now)
			if err != nil {
				t.Fatalf("precise preparation failed (%v/%s): %v", qualified, mode, err)
			}
			if !bytes.HasPrefix(archive, []byte(`{"version":"runtime-archive-v2","source":"tetragon","events":[`)) {
				t.Fatal("missing explicit archive version")
			}
			batch, err := DecodePreciseArchivedBatch(authority.Scope, archive)
			if err != nil || batch.Source != "tetragon" || len(batch.Records) != 1 {
				t.Fatalf("replay: %v", err)
			}
			record := batch.Records[0]
			if record.Scope != authority.Scope || record.Event.Scope != authority.Scope || !record.EventTime.Equal(now) {
				t.Fatal("trusted scope or display time changed")
			}
			if record.ContainerID != "" || record.CgroupID != "" || record.ProcessID != "" || !record.AgentID.IsZero() || !record.SessionID.IsZero() {
				t.Fatal("observation promoted into authority")
			}
			if qualified {
				if record.ObservedLineage.SourceEventTime != "2026-08-20T12:00:00.123999999Z" || record.ObservedLineage.ProcessStartTime != "2026-08-20T12:00:00.123456789Z" || record.ObservedLineage.ProcessID != "42" {
					t.Fatal("nanoseconds lost")
				}
				if validRecord(record.Record) {
					t.Fatal("qualified precise record downgraded to legacy")
				}
			} else if record.ObservedLineage != (runtimelineage.PreciseObservation{}) {
				t.Fatal("unqualified identity invented")
			}
			if mode == "metadata_only" && len(record.Content) != 0 || mode == "full" && record.Content["binary"] != "agent" {
				t.Fatal("collection mode ignored")
			}
			if record.SearchMetadata.ProcessDigest != strings.Repeat("c", 64) {
				t.Fatal("content-free search selector lost")
			}
			_, repeated, err := decodePreciseProductionInput(body, authority, now)
			if err != nil || !bytes.Equal(repeated, archive) {
				t.Fatal("same input changed archive bytes")
			}
			if _, err := DecodeArchivedBatch(authority.Scope, archive); err == nil {
				t.Fatal("old worker consumed precise archive")
			}
			if _, err := DecodePreciseArchivedBatch(authority.Scope, body); err == nil {
				t.Fatal("unversioned transport replayed as archive")
			}
			other := fixtureScope(t, 80)
			scoped, err := DecodePreciseArchivedBatch(other, archive)
			if err != nil || scoped.Records[0].Scope != other || scoped.Records[0].ID == record.ID {
				t.Fatal("lease scope not applied to identity")
			}
			if _, _, err := decodePreciseProductionInput(body, authority, now.Add(25*time.Hour)); err == nil {
				t.Fatal("expired upload accepted")
			}
			// Replay has no current-time parameter: old durable jobs retain their source instant.
			replay, err := DecodePreciseArchivedBatch(authority.Scope, archive)
			if err != nil || replay.Records[0].ObservedLineage != record.ObservedLineage {
				t.Fatal("durable replay changed lineage")
			}
		}
	}
}

func TestPreciseArchiveRejectsHostilePayloads(t *testing.T) {
	body, authority, now := preciseArchiveFixture(t, true)
	_, archive, err := decodePreciseProductionInput(body, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"case":      func(s string) string { return strings.Replace(s, `"event_id":`, `"Event_ID":`, 1) },
		"escaped":   func(s string) string { return strings.Replace(s, `"event_id":`, `"event_\u0069d":`, 1) },
		"duplicate": func(s string) string { return strings.Replace(s, `"source":`, `"source":"tetragon","source":`, 1) },
		"scope": func(s string) string {
			return strings.Replace(s, `"source":`, `"organization_id":"forged","source":`, 1)
		},
		"wrong-bin":    func(s string) string { return strings.Replace(s, ".123999999Z", ".124Z", 1) },
		"future-start": func(s string) string { return strings.Replace(s, ".123456789Z", ".124Z", 1) },
		"legacy-profile": func(s string) string {
			return strings.Replace(s, "kubernetes-container-v2", "kubernetes-container-v1", 1)
		},
		"invalid-action": func(s string) string { return strings.Replace(s, `"exec"`, `"invented"`, 1) },
		"null-content":   func(s string) string { return strings.Replace(s, `{"binary":"agent"}`, `null`, 1) },
		"whitespace":     func(s string) string { return " " + s },
		"trailing":       func(s string) string { return s + "{}" },
		"invalid-utf8":   func(s string) string { return strings.Replace(s, "agent", string([]byte{255}), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodePreciseProductionInput([]byte(mutate(string(body))), authority, now); err == nil {
				t.Fatal("hostile ingest accepted")
			}
			if _, err := DecodePreciseArchivedBatch(authority.Scope, []byte(mutate(string(archive)))); err == nil {
				t.Fatal("hostile archive accepted")
			}
		})
	}
	for _, invalid := range [][]byte{nil, []byte(`null`), []byte(`{}`), bytes.Replace(archive, []byte("runtime-archive-v2"), []byte("runtime-archive-v1"), 1), bytes.Replace(archive, []byte("tetragon"), []byte("otlp"), 1)} {
		if _, err := DecodePreciseArchivedBatch(authority.Scope, invalid); err == nil {
			t.Fatal("invalid archive accepted")
		}
	}
	if _, err := DecodePreciseArchivedBatch(domain.Scope{}, archive); err == nil {
		t.Fatal("invalid scope accepted")
	}
	for _, change := range []func(*IngestAuthority){func(a *IngestAuthority) { a.Scope = domain.Scope{} }, func(a *IngestAuthority) { a.SensorID = domain.ProductID{} }, func(a *IngestAuthority) { a.TokenID = domain.ProductID{} }, func(a *IngestAuthority) { a.TokenGeneration = 0 }, func(a *IngestAuthority) { a.Source = "otlp" }, func(a *IngestAuthority) { a.Mode = "unknown" }} {
		invalid := authority
		change(&invalid)
		if _, _, err := decodePreciseProductionInput(body, invalid, now); err == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	for _, clock := range []time.Time{{}, now.In(time.FixedZone("offset", 3600)), now.Add(-6 * time.Minute)} {
		if _, _, err := decodePreciseProductionInput(body, authority, clock); err == nil {
			t.Fatal("invalid clock/window accepted")
		}
	}
}

func TestHistoricalHTTPHandlerRefusesPreciseTransport(t *testing.T) {
	body, authority, now := preciseArchiveFixture(t, true)
	repository := &productionIngestRepositoryStub{authority: authority}
	artifacts := &productionRawArtifactStub{}
	handler, err := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-enrollment-v2")
	request.Header.Set("X-Zasp-Expected-Enrollment", strings.Repeat("a", 64))
	request.Header.Set("Idempotency-Key", "runtime-v2:"+strings.Repeat("b", 64))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || repository.reserveCalls != 0 || repository.finalizeCalls != 0 || artifacts.putCalls != 0 {
		t.Fatalf("premature acceptance: %d", response.Code)
	}
}

func TestPreciseArchiveEventCountAndFreshnessBoundaries(t *testing.T) {
	body, authority, now := preciseArchiveFixture(t, true)
	var original struct {
		Source string            `json:"source"`
		Events []json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{0, 1000, 1001} {
		input := original
		input.Events = make([]json.RawMessage, count)
		for i := range input.Events {
			input.Events[i] = original.Events[0]
		}
		candidate, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		_, archive, err := decodePreciseProductionInput(candidate, authority, now)
		if (err == nil) != (count == 1000) {
			t.Fatalf("ingest count %d: %v", count, err)
		}
		// Build the archive independently, including invalid counts.
		archived := append([]byte(`{"version":"runtime-archive-v2",`), candidate[1:]...)
		batch, err := DecodePreciseArchivedBatch(authority.Scope, archived)
		if (err == nil) != (count == 1000) {
			t.Fatalf("archive count %d: %v", count, err)
		}
		if count == 1000 && (len(batch.Records) != 1000 || !bytes.Equal(archive, archived)) {
			t.Fatal("batch changed")
		}
	}
	for _, delta := range []time.Duration{24 * time.Hour, -5 * time.Minute} {
		if _, _, err := decodePreciseProductionInput(body, authority, now.Add(delta)); err != nil {
			t.Fatalf("boundary %s rejected: %v", delta, err)
		}
	}
}

func TestPreciseArchiveConsumesRealNormalizerEnvelope(t *testing.T) {
	_, authority, now := preciseArchiveFixture(t, true)
	identity := lineageObservationFixture()
	source := sensoradapter.LineageSource{Profile: "tetragon-local-stream-v3", GenerationID: "12345678-1234-1234-1234-123456789005", EnrollmentBinding: strings.Repeat("a", 64), NodeName: "node-a", ClusterUID: identity.ClusterUID, NodeUID: identity.NodeUID, BootID: identity.BootID}
	normalizer, err := sensoradapter.NewPreciseLineageNormalizer(8, source)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(`{"process_exec":{"process":{"exec_id":"exec-1","pid":42,"uid":1000,"cwd":"/tmp","binary":"/usr/bin/agent","arguments":"--password secret","flags":"execve","start_time":"2026-08-20T12:00:00.123456789Z","pod":{"namespace":"agentsec","name":"agent-a","uid":"` + identity.PodUID + `","container":{"id":"` + identity.ContainerID + `","name":"agent"},"workload":"agent-a","workload_kind":"Pod"}}},"node_name":"node-a","cluster_name":"cluster-a","node_labels":{},"time":"2026-08-20T12:00:00.123999999Z"}`)
	event, err := normalizer.Normalize(line)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://ingest.example.test", EnrollmentBinding: source.EnrollmentBinding,
		Now:   func() time.Time { return now },
		Token: func() ([]byte, error) { t.Fatal("preparation read a credential"); return nil, nil },
		Do:    func(*http.Request) (*http.Response, error) { t.Fatal("preparation sent a request"); return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := client.PreparePreciseEnvelope([]sensoradapter.PreciseRuntimeEvent{event})
	if err != nil {
		t.Fatal(err)
	}
	authority.Mode = "metadata_only"
	_, archive, err := decodePreciseProductionInput(envelope.Body, authority, now)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := DecodePreciseArchivedBatch(authority.Scope, archive)
	if err != nil || len(batch.Records) != 1 {
		t.Fatalf("archive: %v", err)
	}
	record := batch.Records[0]
	if record.ObservedLineage.SourceEventTime != "2026-08-20T12:00:00.123999999Z" || record.ObservedLineage.ProcessStartTime != "2026-08-20T12:00:00.123456789Z" || record.ObservedLineage.ProcessID != "42" || record.SourceEventID != event.EventID || len(record.Content) != 0 || record.SearchMetadata.ProcessDigest == "" {
		t.Fatal("source-to-archive precision/filtering changed", record)
	}
}

// Probe decoding at its allocation boundary. The oversized value is valid JSON,
// and would call UnmarshalJSON if the byte-limit check moved after decoding.
type preciseArchiveDecodeProbe struct{ called bool }

func (probe *preciseArchiveDecodeProbe) UnmarshalJSON([]byte) error { probe.called = true; return nil }

func TestPreciseArchiveByteLimitPrecedesDecode(t *testing.T) {
	body := bytes.Repeat([]byte{'x'}, (64<<20)+1)
	body[0], body[len(body)-1] = '"', '"'
	probe := &preciseArchiveDecodeProbe{}
	if err := decodeCanonicalPreciseJSON(body, probe); err == nil || probe.called {
		t.Fatal("oversized input reached decoder")
	}
}
