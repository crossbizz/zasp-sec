package runtimeprojection

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimecorrelation"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func preciseProjectionInput(t *testing.T) Batch {
	t.Helper()
	lineage := runtimelineage.PreciseObservation{Observation: runtimelineage.Observation{Profile: "kubernetes-container-v2", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64)}, SourceEventTime: "2026-09-10T10:00:00.000000002Z"}
	event := sensoradapter.PreciseRuntimeEvent{RuntimeEvent: sensoradapter.RuntimeEvent{EventID: "event-1", Class: "process", Action: "exec", WorkloadID: "runtime-a", EventTime: "2026-09-10T10:00:00.000Z", EvidenceID: projectionID(t, 8).String()}, ObservedLineage: lineage}
	body, err := json.Marshal(struct {
		Version string                              `json:"version"`
		Source  string                              `json:"source"`
		Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}{"runtime-archive-v2", "tetragon", []sensoradapter.PreciseRuntimeEvent{event}})
	if err != nil {
		t.Fatal(err)
	}
	input := Batch{Scope: projectionScope(t, 1), BatchID: projectionID(t, 9), Generation: 2, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v2", Body: body, ArchiveDigest: sha256.Sum256(body)}
	archive, err := runtimeevent.DecodePreciseArchivedBatch(input.Scope, body)
	if err != nil {
		t.Fatal(err)
	}
	input.Correlations = []runtimecorrelation.Result{{EventID: archive.Records[0].ID, AgentID: projectionID(t, 6), SessionID: projectionID(t, 7), Confidence: domain.EvidenceConfidenceStrong, SandboxID: "sandbox-a", SandboxSourceSensorID: projectionID(t, 10)}}
	return input
}

func TestPreciseProjectionPreservesBindingAndDisplayTime(t *testing.T) {
	input := preciseProjectionInput(t)
	before := bytes.Clone(input.Body)
	projected, err := ProjectPrecise(input)
	if err != nil || len(projected.Items) != 1 {
		t.Fatal("precise projection rejected", err)
	}
	i := projected.Items[0]
	if i.Source != "tetragon" || i.EventClass != "process" || i.Action != "exec" || i.Severity != "medium" || i.Title != "Runtime process execution" || i.EventTime != "2026-09-10T10:00:00.000Z" || i.EvidenceID != projectionID(t, 8) || i.AgentID != projectionID(t, 6) || i.SessionID != projectionID(t, 7) || i.SandboxID != "sandbox-a" || i.SandboxSourceSensorID != projectionID(t, 10) {
		t.Fatal("projection lost event or identity")
	}
	if !bytes.Equal(input.Body, before) {
		t.Fatal("archive mutated")
	}
	again, err := ProjectPrecise(input)
	if err != nil || again.ContentDigest != projected.ContentDigest || again.Items[0] != i {
		t.Fatal("unstable replay", err)
	}
	oldDigest, err := projectionDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, projected.Items, true)
	if err != nil || oldDigest == projected.ContentDigest || i.ID == sandboxRiskID(input, input.Correlations[0].EventID, input.Correlations[0]) {
		t.Fatal("precision reused old digest or risk domain")
	}
	if _, err := Project(input); err != ErrInput {
		t.Fatal("legacy projector accepted precise archive")
	}
	if _, err := ProjectSandbox(input); err != ErrInput {
		t.Fatal("sandbox projector accepted precise archive")
	}
	if _, err := ProjectPrecise(sandboxProjectionInput(t)); err != ErrInput {
		t.Fatal("precise projector accepted old archive")
	}
}

func TestPreciseProjectionValidatesConfidenceAndBindings(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		change func(*Batch)
		accept bool
	}{
		{"exact", func(b *Batch) { b.Correlations[0].Confidence = domain.EvidenceConfidenceExact }, false},
		{"unknown sandbox", func(b *Batch) {
			b.Correlations[0].SandboxID = ""
			b.Correlations[0].SandboxSourceSensorID = domain.ProductID{}
		}, true},
		{"probable cleared", func(b *Batch) {
			id := b.Correlations[0].EventID
			b.Correlations[0] = runtimecorrelation.Result{EventID: id, Confidence: domain.EvidenceConfidenceProbable}
		}, true},
		{"probable assigned", func(b *Batch) { b.Correlations[0].Confidence = domain.EvidenceConfidenceProbable }, false},
		{"missing source", func(b *Batch) { b.Correlations[0].SandboxSourceSensorID = domain.ProductID{} }, false},
		{"foreign event", func(b *Batch) { b.Correlations[0].EventID = projectionID(t, 99) }, false},
		{"foreign scope", func(b *Batch) { b.Scope = projectionScope(t, 20) }, false},
		{"archive digest", func(b *Batch) { b.ArchiveDigest = sha256.Sum256([]byte("other")) }, false},
		{"duplicate", func(b *Batch) { b.Correlations = append(b.Correlations, b.Correlations[0]) }, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := preciseProjectionInput(t)
			scenario.change(&input)
			result, err := ProjectPrecise(input)
			if (err == nil) != scenario.accept {
				t.Fatal("validation mismatch", err)
			}
			if !scenario.accept && result.Items != nil {
				t.Fatal("partial projection leaked")
			}
		})
	}
}

func TestPreciseProjectionBindsNanosecondArchiveChanges(t *testing.T) {
	input := preciseProjectionInput(t)
	original, err := ProjectPrecise(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Body = bytes.Replace(input.Body, []byte("10:00:00.000000002Z"), []byte("10:00:00.000000003Z"), 1)
	input.ArchiveDigest = sha256.Sum256(input.Body)
	archive, err := runtimeevent.DecodePreciseArchivedBatch(input.Scope, input.Body)
	if err != nil {
		t.Fatal(err)
	}
	input.Correlations[0].EventID = archive.Records[0].ID
	changed, err := ProjectPrecise(input)
	if err != nil || changed.Items[0].EventTime != original.Items[0].EventTime || changed.ContentDigest == original.ContentDigest || changed.Items[0].ID == original.Items[0].ID {
		t.Fatal("nanosecond evidence change lost despite identical display time", err)
	}
}
