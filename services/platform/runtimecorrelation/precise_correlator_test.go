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
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func preciseCorrelationFixture(t *testing.T, mutate func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation) (Batch, runtimeevent.PreciseFrozenCandidateSnapshot) {
	t.Helper()
	scope := correlationScope(t, 1)
	lineage := frozenLineage()
	lineage.ProcessStartTime = "2026-09-10T10:00:00.000000001Z"
	observation := runtimelineage.PreciseObservation{Observation: lineage, SourceEventTime: "2026-09-10T10:00:00.000000002Z"}
	observation.Profile = "kubernetes-container-v2"
	event := sensoradapter.PreciseRuntimeEvent{RuntimeEvent: sensoradapter.RuntimeEvent{EventID: "event-1", Class: "process", Action: "exec", WorkloadID: "runtime-a", EventTime: "2026-09-10T10:00:00.000Z", EvidenceID: correlationID(t, 8).String()}, ObservedLineage: observation}
	body, err := json.Marshal(struct {
		Version string                              `json:"version"`
		Source  string                              `json:"source"`
		Events  []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}{"runtime-archive-v2", "tetragon", []sensoradapter.PreciseRuntimeEvent{event}})
	if err != nil {
		t.Fatal(err)
	}
	input := Batch{Scope: scope, BatchID: correlationID(t, 9), Generation: 2, ArchiveDigest: sha256.Sum256(body), Body: body}
	effect := sha256.Sum256([]byte("index effect"))
	receipt, receiptDigest, _, err := runtimeevent.EncodeStageReceipt(runtimeevent.StageReceipt{Stage: runtimeevent.RuntimeStageIndex, ImplementationVersion: "runtime-index-v2", Scope: scope, BatchID: input.BatchID, Generation: input.Generation, InputReference: "s3://zasp-evidence/raw.json", InputVersionID: "raw-v2", InputDigest: input.ArchiveDigest, ArchiveReference: "s3://zasp-evidence/raw.json", ArchiveVersionID: "raw-v2", ArchiveDigest: input.ArchiveDigest, EffectDigest: effect})
	if err != nil {
		t.Fatal(err)
	}
	candidates := []runtimeevent.CandidateObservation{{BatchID: correlationID(t, 10), Generation: 1, SourceSensorID: correlationID(t, 11), AgentID: correlationID(t, 6), SessionID: correlationID(t, 7), ArchiveDigest: sha256.Sum256([]byte("semantic archive")), IndexReceiptDigest: sha256.Sum256([]byte("semantic index")), Lineage: lineage, EventTime: time.Date(2026, 9, 10, 10, 0, 1, 0, time.UTC), SandboxID: "sandbox-a", SandboxObserved: true}}
	if mutate != nil {
		candidates = mutate(candidates)
	}
	values := make([]any, len(candidates))
	for i, c := range candidates {
		var sandbox any
		if c.SandboxObserved {
			sandbox = c.SandboxID
		}
		values[i] = map[string]any{"batch_id": c.BatchID.String(), "generation": c.Generation, "event_ordinal": i + 1, "source_sensor_id": c.SourceSensorID.String(), "agent_id": c.AgentID.String(), "session_id": c.SessionID.String(), "sandbox_id": sandbox, "archive_digest": hex.EncodeToString(c.ArchiveDigest[:]), "index_receipt_digest": hex.EncodeToString(c.IndexReceiptDigest[:]), "observed_lineage": c.Lineage, "event_time": c.EventTime.Format("2006-01-02T15:04:05.000Z")}
	}
	snapshotBody, err := json.Marshal(map[string]any{"schema": "runtime-candidate-snapshot-v3", "organization_id": scope.OrganizationID().String(), "workspace_id": scope.WorkspaceID().String(), "environment_id": scope.EnvironmentID().String(), "batch_id": input.BatchID.String(), "generation": input.Generation, "source_sensor_id": correlationID(t, 12).String(), "runtime_sensor_id": correlationID(t, 12).String(), "archive_digest": hex.EncodeToString(input.ArchiveDigest[:]), "index_receipt_digest": hex.EncodeToString(receiptDigest[:]), "window_seconds": 300, "candidates": values})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshotBody)
	envelope, err := json.Marshal(map[string]any{"snapshot": hex.EncodeToString(snapshotBody), "sha256": hex.EncodeToString(digest[:]), "replayed": false})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := runtimeevent.NewPostgresProductionPipelineRepository(frozenResponseDatabase{envelope}, runtimeevent.ProductionPipelineAuthorityCorrelation)
	if err != nil {
		t.Fatal(err)
	}
	lease := runtimeevent.StageLease{Scope: scope, BatchID: input.BatchID, Generation: input.Generation, Stage: runtimeevent.RuntimeStageCorrelate, Attempt: 1, ImplementationVersion: "runtime-correlation-v4", InputReference: "s3://zasp-evidence/index.json", InputVersionID: "index-v2", InputDigest: effect, PredecessorDigest: &effect, LeaseExpiresAt: time.Now().UTC().Add(time.Minute)}
	snapshot, err := repository.FreezePreciseCandidates(context.Background(), lease, "candidate-worker", strings.Repeat("a", 32), receipt, body)
	if err != nil {
		t.Fatal(err)
	}
	return input, snapshot
}

func TestPreciseCorrelationRetainsProcessIdentityAndCompleteBindings(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation
		want   domain.EvidenceConfidence
		known  bool
	}{
		{"same-ms", nil, domain.EvidenceConfidenceStrong, true},
		{"duplicate-binding", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			return append(c, c[0])
		}, domain.EvidenceConfidenceStrong, true},
		{"other-sandbox", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := c[0]
			other.SandboxID = "sandbox-b"
			return append(c, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"other-enrollment", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := c[0]
			other.SourceSensorID = correlationID(t, 42)
			return append(c, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"unknown", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			c[0].SandboxID = ""
			c[0].SandboxObserved = false
			return c
		}, domain.EvidenceConfidenceStrong, false},
		{"unknown-competes", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := c[0]
			other.SandboxID = ""
			other.SandboxObserved = false
			return append(c, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"pid-reuse-1ns", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			c[0].Lineage.ProcessStartTime = "2026-09-10T10:00:00.000000002Z"
			return c
		}, domain.EvidenceConfidenceUnattributed, false},
		{"cgroup", func(c []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			c[0].Lineage.CgroupID = "9876"
			return c
		}, domain.EvidenceConfidenceUnattributed, false},
		{"none", func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation { return nil }, domain.EvidenceConfidenceUnattributed, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, snapshot := preciseCorrelationFixture(t, test.mutate)
			result, err := CorrelatePreciseFrozen(input, snapshot)
			if err != nil || len(result.Results) != 1 || result.Results[0].Confidence != test.want || result.CandidateSnapshotDigest != snapshot.Digest() {
				t.Fatal("precise correlation failed", err, result)
			}
			got := result.Results[0]
			if test.want == domain.EvidenceConfidenceStrong {
				if got.AgentID != correlationID(t, 6) || got.SessionID != correlationID(t, 7) {
					t.Fatal("identity lost")
				}
			} else if !got.AgentID.IsZero() || !got.SessionID.IsZero() {
				t.Fatal("ambiguous identity assigned")
			}
			if test.known {
				if got.SandboxID != "sandbox-a" || got.SandboxSourceSensorID != correlationID(t, 11) {
					t.Fatal("sandbox binding lost")
				}
			} else if got.SandboxID != "" || !got.SandboxSourceSensorID.IsZero() {
				t.Fatal("unknown sandbox assigned")
			}
			again, err := CorrelatePreciseFrozen(input, snapshot)
			if err != nil || again.ContentDigest != result.ContentDigest || again.Results[0] != got {
				t.Fatal("replay changed")
			}
			legacy, err := sandboxCorrelationDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, snapshot.Digest(), result.Results)
			if err != nil || legacy == result.ContentDigest {
				t.Fatal("V4 reused old digest domain")
			}
		})
	}
}

func TestPreciseMatchingUsesSourceTimeNotDisplayTime(t *testing.T) {
	input, snapshot := preciseCorrelationFixture(t, nil)
	batch, err := runtimeevent.DecodePreciseArchivedBatch(input.Scope, input.Body)
	if err != nil {
		t.Fatal(err)
	}
	record, candidate := batch.Records[0], snapshot.Candidates()[0]
	record.ObservedLineage.ProcessID, record.ObservedLineage.ProcessStartTime = "", ""
	candidate.Lineage.ProcessID, candidate.Lineage.ProcessStartTime = "", ""
	candidate.EventTime = time.Date(2026, 9, 10, 9, 55, 0, 0, time.UTC)
	if preciseQualifiedObservationMatch(record, candidate) {
		t.Fatal("candidate2ns outside source window matched")
	}
	candidate.EventTime = time.Date(2026, 9, 10, 10, 5, 0, 0, time.UTC)
	if !preciseQualifiedObservationMatch(record, candidate) {
		t.Fatal("candidate inside precise upper window rejected")
	}
	candidate.Lineage.CgroupID = "different"
	if preciseQualifiedObservationMatch(record, candidate) {
		t.Fatal("invalid identity matched")
	}
}

func TestPreciseCorrelationRejectsUnboundInputs(t *testing.T) {
	input, snapshot := preciseCorrelationFixture(t, nil)
	for _, name := range []string{"scope", "batch", "generation", "body", "candidates", "snapshot"} {
		changed, authority := input, snapshot
		switch name {
		case "scope":
			changed.Scope = correlationScope(t, 100)
		case "batch":
			changed.BatchID = correlationID(t, 100)
		case "generation":
			changed.Generation++
		case "body":
			changed.Body = append(bytes.Clone(input.Body), ' ')
		case "candidates":
			changed.Candidates = []runtimeevent.Candidate{{AgentID: correlationID(t, 6)}}
		case "snapshot":
			authority = runtimeevent.PreciseFrozenCandidateSnapshot{}
		}
		if _, err := CorrelatePreciseFrozen(changed, authority); err != ErrInput {
			t.Fatal("unbound input accepted", name)
		}
	}
}
