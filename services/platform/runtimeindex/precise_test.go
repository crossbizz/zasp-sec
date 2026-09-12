package runtimeindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"strings"
	"testing"
)

func preciseIndexInput(t *testing.T) Batch {
	t.Helper()
	lineage := runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64)}, SourceEventTime: "2026-09-10T10:00:00.000000002Z"}
	event := sensoradapter.PreciseRuntimeEvent{RuntimeEvent: sensoradapter.RuntimeEvent{EventID: "event-1", Class: "process", Action: "exec", WorkloadID: "runtime-a", EventTime: "2026-09-10T10:00:00.000Z", EvidenceID: testID(t, 8).String()}, ObservedLineage: lineage}
	body, err := json.Marshal(struct {
		Version string                              `json:"version"`
		Source  string                              `json:"source"`
		Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}{"runtime-archive-v2", "tetragon", []sensoradapter.PreciseRuntimeEvent{event}})
	if err != nil {
		t.Fatal(err)
	}
	return Batch{Scope: testScope(t, 1), BatchID: testID(t, 9), Generation: 3, InputDigest: sha256.Sum256(body), Body: body, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v2"}
}

func TestPreciseIndexPreservesEvidenceWithoutSemanticPromotion(t *testing.T) {
	input := preciseIndexInput(t)
	driver := &driverStub{}
	store, _ := New(driver, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000})
	result, err := store.ApplyPrecise(context.Background(), input)
	if err != nil || len(result.DocumentIDs) != 1 {
		t.Fatal("precise index unavailable", err)
	}
	document := driver.input.Documents[0]
	if document.Source != "tetragon" || document.EventTime != "2026-09-10T10:00:00.000Z" || document.EventClass != "process" || document.AgentID != "" || document.SessionID != "" || document.SandboxID != "" || document.ArchiveVersionID != "raw-v2" || driver.input.InputDigest != input.InputDigest {
		t.Fatal("evidence lost or observed identity promoted")
	}
	again, err := store.ApplyPrecise(context.Background(), input)
	if err != nil || again.ContentDigest != result.ContentDigest || again.DocumentIDs[0] != result.DocumentIDs[0] {
		t.Fatal("unstable index replay", err)
	}
	decoded, err := runtimeevent.DecodePreciseArchivedBatch(input.Scope, input.Body)
	if err != nil {
		t.Fatal(err)
	}
	old, _, ok := makeDriverBatch(input, runtimeevent.ArchivedBatch{Records: []runtimeevent.Record{decoded.Records[0].Record}})
	if !ok || old.ContentDigest == result.ContentDigest {
		t.Fatal("precise effect reused legacy digest domain")
	}
	input.Body = bytes.Replace(input.Body, []byte("10:00:00.000000002Z"), []byte("10:00:00.000000003Z"), 1)
	input.InputDigest = sha256.Sum256(input.Body)
	changed, err := store.ApplyPrecise(context.Background(), input)
	if err != nil || changed.ContentDigest == result.ContentDigest || changed.DocumentIDs[0] == result.DocumentIDs[0] {
		t.Fatal("nanosecond evidence drift lost", err)
	}
}

func TestPreciseIndexRejectsCrossVersionAndDrift(t *testing.T) {
	input := preciseIndexInput(t)
	driver := &driverStub{}
	store, _ := New(driver, Config{MaximumBatchBytes: 1 << 20, MaximumDocuments: 1000})
	if _, err := store.Apply(context.Background(), input); err != ErrInput || driver.calls != 0 {
		t.Fatal("legacy index accepted precise archive")
	}
	legacy := input
	legacy.Body = bytes.Replace(legacy.Body, []byte(`"version":"runtime-archive-v2",`), nil, 1)
	legacy.InputDigest = sha256.Sum256(legacy.Body)
	if _, err := store.ApplyPrecise(context.Background(), legacy); err != ErrInput || driver.calls != 0 {
		t.Fatal("precise index accepted absent version")
	}
	input.InputDigest[0] ^= 1
	if _, err := store.ApplyPrecise(context.Background(), input); err != ErrInput || driver.calls != 0 {
		t.Fatal("index accepted digest drift")
	}
	driver.mutateResult = true
	input = preciseIndexInput(t)
	if _, err := store.ApplyPrecise(context.Background(), input); err != ErrDrift {
		t.Fatal("driver drift accepted", err)
	}
}
