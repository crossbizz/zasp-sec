package runtimecorrelation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

func TestFrozenCorrelationMatchesBeforeIdentityDeduplication(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation
		want   domain.EvidenceConfidence
	}{
		{"unique", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation { return values }, domain.EvidenceConfidenceStrong},
		{"same identity occurrences", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			return append(values, values[0])
		}, domain.EvidenceConfidenceStrong},
		{"competing identities", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := values[0]
			other.AgentID = correlationID(t, 40)
			other.SessionID = correlationID(t, 41)
			return append(values, other)
		}, domain.EvidenceConfidenceProbable},
		{"contradictory occurrence before matching occurrence", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := values[0]
			other.Lineage.ProcessStartTime = "2026-09-10T09:00:01Z"
			return []runtimeevent.CandidateObservation{other, values[0]}
		}, domain.EvidenceConfidenceStrong},
		{"process reuse", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			values[0].Lineage.ProcessStartTime = "2026-09-10T09:00:01Z"
			return values
		}, domain.EvidenceConfidenceUnattributed},
		{"cgroup contradiction", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			values[0].Lineage.CgroupID = "9876"
			return values
		}, domain.EvidenceConfidenceUnattributed},
		{"empty", func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation { return nil }, domain.EvidenceConfidenceUnattributed},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input, snapshot := frozenCorrelationFixture(t, "tetragon", scenario.mutate)
			result, err := CorrelateFrozen(input, snapshot)
			if err != nil || len(result.Results) != 1 || result.Results[0].Confidence != scenario.want || result.CandidateSnapshotDigest != snapshot.Digest() {
				t.Fatal("snapshot correlation failed", err)
			}
			got := result.Results[0]
			if scenario.want == domain.EvidenceConfidenceStrong {
				if got.AgentID != correlationID(t, 6) || got.SessionID != correlationID(t, 7) {
					t.Fatal("wrong unique identity")
				}
			} else if !got.AgentID.IsZero() || !got.SessionID.IsZero() {
				t.Fatal("ambiguous runtime identity became authoritative")
			}
		})
	}
}

func TestFrozenCorrelationRequiresBoundSnapshotAndRejectsCallerCandidates(t *testing.T) {
	input, snapshot := frozenCorrelationFixture(t, "tetragon", nil)
	for _, name := range []string{"empty snapshot", "foreign scope", "batch", "generation", "archive", "caller candidates"} {
		t.Run(name, func(t *testing.T) {
			changed, authority := input, snapshot
			switch name {
			case "empty snapshot":
				authority = runtimeevent.FrozenCandidateSnapshot{}
			case "foreign scope":
				changed.Scope = correlationScope(t, 100)
			case "batch":
				changed.BatchID = correlationID(t, 100)
			case "generation":
				changed.Generation++
			case "archive":
				changed.Body = append(bytes.Clone(input.Body), ' ')
				changed.ArchiveDigest = sha256.Sum256(changed.Body)
			case "caller candidates":
				changed.Candidates = []runtimeevent.Candidate{{AgentID: correlationID(t, 6), SessionID: correlationID(t, 7)}}
			}
			if result, err := CorrelateFrozen(changed, authority); err != ErrInput || result.Results != nil {
				t.Fatal("unbound correlation accepted")
			}
		})
	}
	again, _ := CorrelateFrozen(input, snapshot)
	legacy, _ := Correlate(input)
	if again.ContentDigest == legacy.ContentDigest {
		t.Fatal("v2 reused the v1 digest domain")
	}
	changedInput, changedSnapshot := frozenCorrelationFixture(t, "tetragon", func(values []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
		values[0].ArchiveDigest = sha256.Sum256([]byte("another admitted occurrence"))
		return values
	})
	changed, err := CorrelateFrozen(changedInput, changedSnapshot)
	if err != nil || again.Results[0] != changed.Results[0] || again.ContentDigest == changed.ContentDigest {
		t.Fatal("frozen provenance wasn't bound to equal results")
	}
	copyResults := again.Results
	copyResults[0].AgentID = domain.ProductID{}
	replayed, err := CorrelateFrozen(input, snapshot)
	if err != nil || replayed.ContentDigest != again.ContentDigest || replayed.Results[0].AgentID.IsZero() {
		t.Fatal("caller mutation changed replay")
	}
}

func TestFrozenCorrelationPreservesExplicitSemanticIdentity(t *testing.T) {
	input, snapshot := frozenCorrelationFixture(t, "otlp", func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation { return nil })
	result, err := CorrelateFrozen(input, snapshot)
	if err != nil || len(result.Results) != 1 || result.Results[0].Confidence != domain.EvidenceConfidenceExact || result.Results[0].AgentID != correlationID(t, 6) || result.Results[0].SessionID != correlationID(t, 7) {
		t.Fatal("explicit semantic identity changed", err)
	}
}

func TestFrozenQualifiedMatchingRejectsDomainTimeAndProcessContradictions(t *testing.T) {
	lineage := frozenLineage()
	record := runtimeevent.Record{ObservedLineage: lineage, EventTime: time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)}
	valid := runtimeevent.CandidateObservation{Lineage: lineage, EventTime: record.EventTime}
	for _, name := range []string{"profile", "cluster", "node", "boot", "pod", "container", "pid", "start", "cgroup", "too old", "too new", "absent"} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			switch name {
			case "profile":
				candidate.Lineage.Profile = "future-profile"
			case "cluster":
				candidate.Lineage.ClusterUID = "different"
			case "node":
				candidate.Lineage.NodeUID = "different"
			case "boot":
				candidate.Lineage.BootID = "different"
			case "pod":
				candidate.Lineage.PodUID = "different"
			case "container":
				candidate.Lineage.ContainerID = "different"
			case "pid":
				candidate.Lineage.ProcessID = "43"
			case "start":
				candidate.Lineage.ProcessStartTime = "2026-09-10T09:00:01Z"
			case "cgroup":
				candidate.Lineage.CgroupID = "9876"
			case "too old":
				candidate.EventTime = record.EventTime.Add(-5*time.Minute - time.Millisecond)
			case "too new":
				candidate.EventTime = record.EventTime.Add(5*time.Minute + time.Millisecond)
			case "absent":
				candidate.Lineage = runtimelineage.Observation{}
			}
			if qualifiedObservationMatch(record, candidate) {
				t.Fatal("contradictory observation matched")
			}
		})
	}
	for _, offset := range []time.Duration{-5 * time.Minute, 0, 5 * time.Minute} {
		candidate := valid
		candidate.EventTime = record.EventTime.Add(offset)
		if !qualifiedObservationMatch(record, candidate) {
			t.Fatal("inclusive time boundary rejected")
		}
	}
	containerOnly := valid
	containerOnly.Lineage.ProcessID, containerOnly.Lineage.ProcessStartTime, containerOnly.Lineage.CgroupID = "", "", ""
	if !qualifiedObservationMatch(record, containerOnly) {
		t.Fatal("valid fully qualified container identity required optional fields")
	}
}

// This fixture crosses the real closed repository decoder with a declared SQL
// response stub. It doesn't grant callers a snapshot constructor or claim PG proof.
func frozenCorrelationFixture(t *testing.T, source string, mutate func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation) (Batch, runtimeevent.FrozenCandidateSnapshot) {
	t.Helper()
	scope, now := correlationScope(t, 1), time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	lineage := frozenLineage()
	event := map[string]any{"event_id": "event-1", "class": "process", "action": "exec", "workload_id": "runtime-a", "event_time": now.Format("2006-01-02T15:04:05.000Z"), "evidence_id": correlationID(t, 8).String(), "content": map[string]any{}, "observed_lineage": lineage}
	if source == "otlp" {
		event["event_id"], event["class"], event["action"], event["workload_id"] = "", "", "", ""
		event["attributes"] = map[string]string{"event.id": "event-1", "event.class": "tool", "event.action": "invoke", "agent.id": correlationID(t, 6).String(), "session.id": correlationID(t, 7).String(), "task.id": "task-a", "tool.id": "tool-a", "sandbox.id": "sandbox-a", "trace.id": strings.Repeat("a", 32), "span.id": strings.Repeat("b", 16)}
	}
	body, err := json.Marshal(map[string]any{"source": source, "events": []any{event}})
	if err != nil {
		t.Fatal(err)
	}
	input := Batch{Scope: scope, BatchID: correlationID(t, 9), Generation: 2, ArchiveDigest: sha256.Sum256(body), Body: body}
	effectDigest := sha256.Sum256([]byte("index effect"))
	receipt, receiptDigest, _, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v1", Scope: scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/raw.json", InputVersionID: "raw-v1", InputDigest: input.ArchiveDigest, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v1", ArchiveDigest: input.ArchiveDigest, EffectDigest: effectDigest})
	if err != nil {
		t.Fatal(err)
	}
	candidates := []runtimeevent.CandidateObservation{{BatchID: correlationID(t, 10), Generation: 1, EventOrdinal: 1, SourceSensorID: correlationID(t, 11), AgentID: correlationID(t, 6), SessionID: correlationID(t, 7), ArchiveDigest: sha256.Sum256([]byte("admitted archive")), IndexReceiptDigest: sha256.Sum256([]byte("admitted index")), Lineage: lineage, EventTime: now}}
	if mutate != nil {
		candidates = mutate(candidates)
	}
	values := make([]any, len(candidates))
	for index, candidate := range candidates {
		values[index] = map[string]any{"batch_id": candidate.BatchID.String(), "generation": candidate.Generation, "event_ordinal": index + 1, "source_sensor_id": candidate.SourceSensorID.String(), "agent_id": candidate.AgentID.String(), "session_id": candidate.SessionID.String(), "archive_digest": hex.EncodeToString(candidate.ArchiveDigest[:]), "index_receipt_digest": hex.EncodeToString(candidate.IndexReceiptDigest[:]), "observed_lineage": candidate.Lineage, "event_time": candidate.EventTime.Format("2006-01-02T15:04:05.000Z")}
	}
	sourceID, anchor := correlationID(t, 12), correlationID(t, 12)
	if source == "otlp" {
		sourceID = correlationID(t, 11)
	}
	snapshotBody, err := json.Marshal(map[string]any{"schema": "runtime-candidate-snapshot-v1", "organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": input.BatchID.String(), "generation": input.Generation, "source_sensor_id": sourceID.String(), "runtime_sensor_id": anchor.String(), "archive_digest": hex.EncodeToString(input.ArchiveDigest[:]), "index_receipt_digest": hex.EncodeToString(receiptDigest[:]), "window_seconds": 300, "candidates": values})
	if err != nil {
		t.Fatal(err)
	}
	snapshotDigest := sha256.Sum256(snapshotBody)
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(snapshotBody), "sha256": hex.EncodeToString(snapshotDigest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(frozenResponseDatabase{envelope}, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	lease := runtimeevent.StageLease{Scope: scope, BatchID: input.BatchID, Generation: input.Generation, Stage: runtimeevent.RuntimeStageCorrelate, Attempt: 1, ImplementationVersion: "runtime-correlation-v2", InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v1", InputDigest: effectDigest, PredecessorDigest: &effectDigest, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	snapshot, err := repository.FreezeCandidates(context.Background(), lease, "candidate-worker-01", strings.Repeat("a", 32), receipt, body)
	if err != nil {
		t.Fatal("fixture snapshot rejected", err)
	}
	return input, snapshot
}

type frozenResponseDatabase struct{ response json.RawMessage }

func (database frozenResponseDatabase) QueryJSON(context.Context, string, ...any) (json.RawMessage, error) {
	return bytes.Clone(database.response), nil
}

func frozenLineage() runtimelineage.Observation {
	return runtimelineage.Observation{Profile: "kubernetes-container-v1", ClusterUID: "12345678-1234-1234-1234-123456789001", NodeUID: "12345678-1234-1234-1234-123456789002", BootID: "12345678-1234-1234-1234-123456789003", PodUID: "12345678-1234-1234-1234-123456789004", ContainerID: "containerd://" + strings.Repeat("a", 64), ProcessID: "42", ProcessStartTime: "2026-09-10T09:00:00Z", CgroupID: "12345"}
}
