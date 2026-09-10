package runtimeevent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func lineageObservationFixture() runtimelineage.Observation {
	return runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: "2026-08-18T09:59:59.123456789Z", CgroupID: "12345"}
}

func TestProductionIngestPreservesObservedLineageWithoutGrantingAuthority(t *testing.T) {
	for _, source := range []string{"tetragon", "otlp"} {
		for _, mode := range []string{"metadata_only", "full"} {
			t.Run(source+"/"+mode, func(t *testing.T) {
				record := fixtureRecord(t, "observed-lineage")
				now, scope := record.EventTime, record.Scope
				var body []byte
				if source == "tetragon" {
					body = productionEventBody(now)
				} else {
					event, err := canonicalIngestEvent(record)
					if err != nil {
						t.Fatal(err)
					}
					body, err = json.Marshal(ingestInput{Source: source, Events: []ingestEvent{event}})
					if err != nil {
						t.Fatal(err)
					}
				}
				observation := lineageObservationFixture()
				lineage, err := json.Marshal(observation)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Replace(body, []byte(`"event_time":`), append(append([]byte(`"observed_lineage":`), lineage...), []byte(`,"event_time":`)...), 1)
				repository := &productionIngestRepositoryStub{authority: IngestAuthority{Scope: scope, SensorID: fixtureID(t, 73), TokenID: fixtureID(t, 74), TokenGeneration: 2, Source: source, Mode: mode}}
				artifacts := &productionRawArtifactStub{}
				handler, err := NewProductionIngestHandler(ProductionIngestConfig{Repository: repository, Artifacts: artifacts, MaximumBytes: 1 << 20, Clock: func() time.Time { return now }})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "/internal/v1/runtime/events", bytes.NewReader(body))
				request.Header.Set("Authorization", "Bearer "+productionSensorToken(t))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-Zasp-Runtime-Schema", "runtime-event-v1")
				request.Header.Set("Idempotency-Key", "runtime-lineage-preservation-0001")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusAccepted || repository.finalizeCalls != 1 {
					t.Fatalf("ingest: %d %s", response.Code, response.Body.String())
				}
				decoded, err := DecodeArchivedBatch(scope, artifacts.put.Body)
				if err != nil || len(decoded.Records) != 1 {
					t.Fatalf("archive: %v", err)
				}
				got := decoded.Records[0]
				if got.ObservedLineage != observation || got.ContainerID != "" || got.CgroupID != "" || got.ProcessID != "" {
					t.Fatal("lineage lost or promoted into legacy matching fields")
				}
				if mode == "metadata_only" && len(got.Content) != 0 {
					t.Fatal("raw content retained")
				}
				if repository.reserved.ContentDigest != sha256.Sum256(artifacts.put.Body) || artifacts.put.ContentDigest != repository.reserved.ContentDigest {
					t.Fatal("lineage not bound to committed archive digest")
				}
				event, err := canonicalIngestEvent(got)
				if err != nil {
					t.Fatal(err)
				}
				replayed, err := json.Marshal(ingestInput{Source: source, Events: []ingestEvent{event}})
				if err != nil || !bytes.Equal(replayed, artifacts.put.Body) {
					t.Fatal("lineage archive replay changed bytes")
				}
				batches, err := BuildBatches([]Record{got}, 100, 512*1024)
				if err != nil || len(batches) != 1 || !bytes.Contains(batches[0].Encoded, lineage) {
					t.Fatalf("batch lineage lost: %v", err)
				}
				candidate := Candidate{AgentID: record.AgentID, SessionID: record.SessionID, SandboxID: observation.PodUID, ContainerID: observation.ContainerID, CgroupID: observation.CgroupID, ProcessID: observation.ProcessID}
				result := Correlate(got, []Candidate{candidate})
				if source == "tetragon" {
					if result.Confidence != domain.EvidenceConfidenceUnattributed || !result.AgentID.IsZero() || !result.SessionID.IsZero() {
						t.Fatal("observation incorrectly granted correlation authority")
					}
				} else if result.Confidence != domain.EvidenceConfidenceExact || result.AgentID != record.AgentID || result.SessionID != record.SessionID {
					t.Fatal("explicit semantic identity changed")
				}
			})
		}
	}
}

func TestObservedLineageRejectsHostileIngestAndArchive(t *testing.T) {
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC)
	lineage, err := json.Marshal(lineageObservationFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		`null`, `{}`, `{"profile":"kubernetes-container-v2"}`, `{"process_id":"42"}`,
		strings.Replace(string(lineage), `"profile":`, `"sensor_id":"forged","profile":`, 1),
		strings.Replace(string(lineage), `"profile":`, `"runtime_sensor_id":"forged","profile":`, 1),
		strings.Replace(string(lineage), `"profile":`, `"organization_id":"forged","profile":`, 1),
		strings.Replace(string(lineage), `"profile":`, `"session_id":"forged","profile":`, 1),
		strings.Replace(string(lineage), `"profile":`, `"profile":"kubernetes-container-v1","profile":`, 1),
		strings.Replace(string(lineage), "2026-08-18T09:59:59.123456789Z", "2026-09-09T10:00:00.000000001Z", 1),
	} {
		body := bytes.Replace(productionEventBody(now), []byte(`"content":`), []byte(`"observed_lineage":`+invalid+`,"content":`), 1)
		scope := fixtureScope(t, 70)
		if _, _, err := decodeProductionInput(body, IngestAuthority{Scope: scope, Source: "tetragon", Mode: "full"}, now); err == nil {
			t.Fatalf("invalid lineage ingested: %.120s", invalid)
		}
		if _, err := DecodeArchivedBatch(scope, body); err == nil {
			t.Fatalf("invalid lineage replayed: %.120s", invalid)
		}
	}
}

func TestLegacyArchiveWithoutLineageRetainsExactBytesAndDigest(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	body := productionEventBody(now)
	_, canonical, err := decodeProductionInput(body, IngestAuthority{Scope: fixtureScope(t, 70), Source: "tetragon", Mode: "full"}, now)
	if err != nil || !bytes.Equal(body, canonical) || sha256.Sum256(body) != sha256.Sum256(canonical) || bytes.Contains(canonical, []byte("observed_lineage")) {
		t.Fatal("legacy archive bytes or digest changed")
	}
}
