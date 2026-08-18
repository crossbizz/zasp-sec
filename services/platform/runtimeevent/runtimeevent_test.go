package runtimeevent

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestAdaptersNormalizeTetragonAndOTLP(t *testing.T) {
	scope := fixtureScope(t, 1)
	when := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	for _, kind := range []string{"process", "file", "network"} {
		record, err := AdaptTetragon(TetragonInput{Scope: scope, SourceEventID: "tetragon-" + kind, Kind: kind, Action: map[string]string{"process": "exec", "file": "read", "network": "connect"}[kind], WorkloadID: "workload-a", EventTime: when, EvidenceID: fixtureID(t, 9)})
		if err != nil || record.Source != "tetragon" || record.Class != kind || record.WorkloadID != "workload-a" || record.ID.IsZero() {
			t.Fatalf("%s: %+v %v", kind, record, err)
		}
	}
	otlp, err := AdaptOTLP(OTLPInput{Scope: scope, EventTime: when, EvidenceID: fixtureID(t, 9), Attributes: map[string]string{
		"event.id": "otlp-1", "event.class": "tool", "event.action": "invoke", "agent.id": fixtureID(t, 10).String(), "session.id": fixtureID(t, 11).String(), "task.id": "task-a", "tool.id": "tool-a", "sandbox.id": "sandbox-a", "trace.id": "0123456789abcdef0123456789abcdef", "span.id": "0123456789abcdef",
	}})
	if err != nil || otlp.TraceID != "0123456789abcdef0123456789abcdef" || otlp.SessionID != fixtureID(t, 11) || otlp.ToolID != "tool-a" {
		t.Fatalf("%+v %v", otlp, err)
	}
}

func TestSensorHealthFilterAndBatching(t *testing.T) {
	health, err := EvaluateSensorHealth(SensorHealthInput{Kernel: "6.8.0", BTF: false, CPUMilli: 200, MemoryMiB: 128, EventRate: 50, Drops: 5})
	if err != nil || health.Status != "unsupported" || health.DropRatio != 0.1 {
		t.Fatalf("%+v %v", health, err)
	}
	record := fixtureRecord(t, "event-1")
	record.Content = map[string]string{"arguments": "sensitive", "method": "POST"}
	filtered, err := FilterRecord(record, "metadata_only")
	if err != nil || len(filtered.Content) != 0 || filtered.Action != "invoke" {
		t.Fatalf("%+v %v", filtered, err)
	}
	events := make([]Record, 10_000)
	for index := range events {
		events[index] = fixtureRecord(t, fmt.Sprintf("event-%05d", index))
	}
	batches, err := BuildBatches(events, 100, 512*1024)
	if err != nil || len(batches) != 100 {
		t.Fatalf("batches=%d err=%v", len(batches), err)
	}
	for _, batch := range batches {
		if len(batch.Records) > 100 || batch.ID.IsZero() || len(batch.Encoded) > 512*1024 || len(batch.Compressed) == 0 {
			t.Fatalf("invalid batch: %+v", batch)
		}
		reader, err := gzip.NewReader(bytes.NewReader(batch.Compressed))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(reader)
		if err != nil || reader.Close() != nil || !bytes.Equal(decoded, batch.Encoded) {
			t.Fatalf("compressed archive does not round trip: %v", err)
		}
	}
}

func TestRecordAndBatchBindFullScopeSourceActionAndDate(t *testing.T) {
	when := time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC)
	baseScope := fixtureScope(t, 1)
	otherScope, err := domain.NewScope(baseScope.OrganizationID(), fixtureID(t, 20), fixtureID(t, 21))
	if err != nil {
		t.Fatal(err)
	}
	input := OTLPInput{Scope: baseScope, EventTime: when, EvidenceID: fixtureID(t, 9), Attributes: map[string]string{
		"event.id": "same-provider-event", "event.class": "tool", "event.action": "invoke", "agent.id": fixtureID(t, 10).String(), "session.id": fixtureID(t, 11).String(), "task.id": "task-a", "tool.id": "tool-a", "sandbox.id": "sandbox-a", "trace.id": "0123456789abcdef0123456789abcdef", "span.id": "0123456789abcdef",
	}}
	first, err := AdaptOTLP(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Scope = otherScope
	second, err := AdaptOTLP(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("record identity ignored workspace/environment scope")
	}

	for name, mutate := range map[string]func(*Record){
		"record scope": func(record *Record) { record.Scope = otherScope },
		"event scope":  func(record *Record) { record.Event.Scope = otherScope },
		"event source": func(record *Record) { record.Event.Source = "tetragon" },
		"action":       func(record *Record) { record.Action = "delete" },
	} {
		t.Run(name, func(t *testing.T) {
			forged := cloneRecord(first)
			mutate(&forged)
			if _, err := FilterRecord(forged, "full"); !errors.Is(err, ErrFilter) {
				t.Fatalf("accepted drifted record: %v", err)
			}
		})
	}

	batches, err := BuildBatches([]Record{first}, 100, 512*1024)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Batch){
		"scope": func(batch *Batch) { batch.Scope = otherScope },
		"date":  func(batch *Batch) { batch.Date = batch.Date.Add(time.Millisecond) },
		"gzip":  func(batch *Batch) { batch.Compressed[0] ^= 0xff },
	} {
		t.Run("batch "+name, func(t *testing.T) {
			forged := batches[0]
			forged.Compressed = append([]byte(nil), batches[0].Compressed...)
			mutate(&forged)
			if validBatch(forged) {
				t.Fatal("accepted drifted batch")
			}
		})
	}
}

func TestInternalIngestAuthenticatesBeforeReadingAndAcknowledgesAfterPublish(t *testing.T) {
	scope := fixtureScope(t, 1)
	auth := NewAuthenticator([]Credential{{Scope: scope, Source: "tetragon", Token: "sensor_token_abcdefghijklmnopqrstuvwxyz012345"}})
	publisher := &recordingPublisher{}
	handler, err := NewIngestHandler(auth, publisher, "full")
	if err != nil {
		t.Fatal(err)
	}
	deniedBody := &readProbe{payload: []byte("not-json")}
	denied := httptest.NewRequest(http.MethodPost, "/internal/v1/events", deniedBody)
	denied.Header.Set("Authorization", "Bearer wrong")
	setScopeHeaders(denied, scope)
	deniedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusForbidden || deniedBody.read {
		t.Fatalf("status=%d read=%t", deniedRecorder.Code, deniedBody.read)
	}

	payload := fmt.Sprintf(`{"source":"tetragon","events":[{"event_id":"event-1","class":"process","action":"exec","workload_id":"workload-a","event_time":"2026-08-18T10:00:00.000Z","evidence_id":"%s"}]}`, fixtureID(t, 9).String())
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/events", bytes.NewBufferString(payload))
	request.Header.Set("Authorization", "Bearer sensor_token_abcdefghijklmnopqrstuvwxyz012345")
	request.Header.Set("Content-Type", "application/json")
	setScopeHeaders(request, scope)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || publisher.calls != 1 || len(publisher.batches) != 1 {
		t.Fatalf("status=%d calls=%d body=%s", recorder.Code, publisher.calls, recorder.Body.String())
	}
	publisher.err = errors.New("queue rejected")
	recorder = httptest.NewRecorder()
	rejected := httptest.NewRequest(http.MethodPost, "/internal/v1/events", bytes.NewBufferString(payload))
	rejected.Header.Set("Authorization", "Bearer sensor_token_abcdefghijklmnopqrstuvwxyz012345")
	rejected.Header.Set("Content-Type", "application/json")
	setScopeHeaders(rejected, scope)
	handler.ServeHTTP(recorder, rejected)
	if recorder.Code != http.StatusServiceUnavailable || publisher.calls != 2 {
		t.Fatalf("publisher rejection status=%d calls=%d", recorder.Code, publisher.calls)
	}
}

func TestWorkerDurabilityOrderReplayAndCorrelation(t *testing.T) {
	batch, err := BuildBatches([]Record{fixtureRecord(t, "event-1")}, 100, 512*1024)
	if err != nil {
		t.Fatal(err)
	}
	durable := NewMemoryDurable()
	ack := 0
	worker, err := NewWorker(durable, durable, durable)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := worker.Process(context.Background(), Delivery{Batch: batch[0], Acknowledge: func(context.Context) error { ack++; return nil }}); err != nil {
			t.Fatal(err)
		}
	}
	if ack != 2 || durable.ArchiveCount() != 1 || durable.IndexCount() != 1 || durable.CorrelationCount() != 1 {
		t.Fatalf("ack=%d archive=%d index=%d correlation=%d", ack, durable.ArchiveCount(), durable.IndexCount(), durable.CorrelationCount())
	}
	key := durable.ArchiveKey(batch[0].ID)
	wantPrefix := "organizations/" + batch[0].Scope.OrganizationID().String() + "/runtime-events/2026/08/18/"
	if len(key) <= len(wantPrefix) || key[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("archive key %q", key)
	}
	if !bytes.Equal(durable.ArchivePayload(batch[0].ID), batch[0].Compressed) {
		t.Fatal("archive did not retain the compressed normalized batch")
	}

	record := fixtureRecord(t, "event-correlation")
	record.SessionID, record.AgentID = fixtureID(t, 11), fixtureID(t, 10)
	candidates := []Candidate{{SessionID: record.SessionID, AgentID: record.AgentID, SandboxID: "sandbox-a", ContainerID: "container-a", CgroupID: "cgroup-a", ProcessID: "42"}}
	if result := Correlate(record, candidates); result.Confidence != domain.EvidenceConfidenceExact {
		t.Fatalf("exact: %+v", result)
	}
	record.SessionID, record.AgentID = domain.ProductID{}, domain.ProductID{}
	record.SandboxID, record.ContainerID, record.CgroupID, record.ProcessID = "sandbox-a", "container-a", "cgroup-a", "42"
	if result := Correlate(record, candidates); result.Confidence != domain.EvidenceConfidenceStrong {
		t.Fatalf("strong: %+v", result)
	}
	forged := cloneRecord(record)
	forged.Event.Scope = fixtureScope(t, 20)
	if result := Correlate(forged, candidates); result.Confidence != domain.EvidenceConfidenceUnattributed {
		t.Fatalf("drifted envelope correlated: %+v", result)
	}
	candidates = append(candidates, Candidate{SessionID: fixtureID(t, 12), AgentID: fixtureID(t, 13), SandboxID: "sandbox-a", ContainerID: "container-a", CgroupID: "cgroup-a", ProcessID: "42"})
	if result := Correlate(record, candidates); result.Confidence == domain.EvidenceConfidenceExact {
		t.Fatalf("ambiguous upgraded: %+v", result)
	}
}

type recordingPublisher struct {
	calls   int
	batches []Batch
	err     error
}

func (publisher *recordingPublisher) Publish(_ context.Context, batches []Batch) error {
	publisher.calls++
	publisher.batches = append(publisher.batches, batches...)
	return publisher.err
}

type readProbe struct {
	payload []byte
	read    bool
}

func (probe *readProbe) Read(destination []byte) (int, error) {
	probe.read = true
	if len(probe.payload) == 0 {
		return 0, io.EOF
	}
	count := copy(destination, probe.payload)
	probe.payload = probe.payload[count:]
	return count, nil
}

func (probe *readProbe) Close() error { return nil }

func setScopeHeaders(request *http.Request, scope domain.Scope) {
	request.Header.Set("X-Zasp-Organization", scope.OrganizationID().String())
	request.Header.Set("X-Zasp-Workspace", scope.WorkspaceID().String())
	request.Header.Set("X-Zasp-Environment", scope.EnvironmentID().String())
}

func fixtureRecord(t *testing.T, sourceID string) Record {
	t.Helper()
	record, err := AdaptOTLP(OTLPInput{Scope: fixtureScope(t, 1), EventTime: time.Date(2026, 8, 18, 10, 0, 0, 0, time.UTC), EvidenceID: fixtureID(t, 9), Attributes: map[string]string{
		"event.id": sourceID, "event.class": "tool", "event.action": "invoke", "agent.id": fixtureID(t, 10).String(), "session.id": fixtureID(t, 11).String(), "task.id": "task-a", "tool.id": "tool-a", "sandbox.id": "sandbox-a", "trace.id": "0123456789abcdef0123456789abcdef", "span.id": "0123456789abcdef",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func fixtureScope(t *testing.T, seed int) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(fixtureID(t, seed), fixtureID(t, seed+1), fixtureID(t, seed+2))
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func fixtureID(t *testing.T, value int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(fmt.Sprintf("pid_%08d-0000-4000-8000-%012d", value, value))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
