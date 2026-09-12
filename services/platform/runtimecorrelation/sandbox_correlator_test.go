package runtimecorrelation

import (
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestSandboxSnapshotCannotUseHistoricalCorrelation(t *testing.T) {
	input, snapshot := versionedFrozenCorrelationFixture(t, "tetragon", true, nil)
	if _, err := CorrelateFrozen(input, snapshot); err != ErrInput {
		t.Fatal("historical correlation consumed a sandbox-versioned snapshot")
	}
}

func TestSandboxCorrelationMatchesCompleteBindingBeforeDeduplication(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		mutate     func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation
		confidence domain.EvidenceConfidence
		known      bool
	}{
		{"known binding", nil, domain.EvidenceConfidenceStrong, true},
		{"repeated binding", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			return append(v, v[0])
		}, domain.EvidenceConfidenceStrong, true},
		{"same agent different sandbox", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := v[0]
			other.SandboxID = "sandbox-b"
			return append(v, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"same text different enrollment", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := v[0]
			other.SourceSensorID = correlationID(t, 42)
			return append(v, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"historical unknown", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			v[0].SandboxID, v[0].SandboxObserved = "", false
			return v
		}, domain.EvidenceConfidenceStrong, false},
		{"unknown cannot be discarded", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := v[0]
			other.SandboxID, other.SandboxObserved = "", false
			return append(v, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"same sandbox different agent", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := v[0]
			other.AgentID, other.SessionID = correlationID(t, 40), correlationID(t, 41)
			return append(v, other)
		}, domain.EvidenceConfidenceProbable, false},
		{"process reuse", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			v[0].Lineage.ProcessStartTime = "2026-09-10T09:00:01Z"
			return v
		}, domain.EvidenceConfidenceUnattributed, false},
		{"cgroup conflict", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			v[0].Lineage.CgroupID = "9876"
			return v
		}, domain.EvidenceConfidenceUnattributed, false},
		{"contradiction before good binding", func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
			other := v[0]
			other.SandboxID = "sandbox-b"
			other.Lineage.CgroupID = "9876"
			return append([]runtimeevent.CandidateObservation{other}, v...)
		}, domain.EvidenceConfidenceStrong, true},
		{"no candidates", func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation { return nil }, domain.EvidenceConfidenceUnattributed, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input, snapshot := versionedFrozenCorrelationFixture(t, "tetragon", true, func(v []runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation {
				v[0].SandboxID, v[0].SandboxObserved = "sandbox-a", true
				if scenario.mutate != nil {
					return scenario.mutate(v)
				}
				return v
			})
			result, err := CorrelateSandboxFrozen(input, snapshot)
			if err != nil || len(result.Results) != 1 || result.Results[0].Confidence != scenario.confidence || result.CandidateSnapshotDigest != snapshot.Digest() {
				t.Fatal("sandbox correlation failed", err)
			}
			got := result.Results[0]
			if scenario.confidence == domain.EvidenceConfidenceStrong {
				if got.AgentID != correlationID(t, 6) || got.SessionID != correlationID(t, 7) {
					t.Fatal("wrong identity")
				}
			} else if !got.AgentID.IsZero() || !got.SessionID.IsZero() {
				t.Fatal("unassigned result retained identity")
			}
			if scenario.known {
				if got.SandboxID != "sandbox-a" || got.SandboxSourceSensorID != correlationID(t, 11) {
					t.Fatal("lost enrolled sandbox binding")
				}
			} else if got.SandboxID != "" || !got.SandboxSourceSensorID.IsZero() {
				t.Fatal("unknown or conflicting sandbox became authoritative")
			}
			again, err := CorrelateSandboxFrozen(input, snapshot)
			if err != nil || again.ContentDigest != result.ContentDigest || again.Results[0] != got {
				t.Fatal("frozen replay changed")
			}
		})
	}
}

func TestSandboxCorrelationExplicitIdentityAndVersionBinding(t *testing.T) {
	input, snapshot := versionedFrozenCorrelationFixture(t, "otlp", true, func([]runtimeevent.CandidateObservation) []runtimeevent.CandidateObservation { return nil })
	result, err := CorrelateSandboxFrozen(input, snapshot)
	if err != nil || len(result.Results) != 1 || result.Results[0].Confidence != domain.EvidenceConfidenceExact || result.Results[0].SandboxID != "sandbox-a" || result.Results[0].SandboxSourceSensorID != snapshot.SourceSensorID() {
		t.Fatal("explicit enrolled semantic identity lost", err)
	}
	oldInput, oldSnapshot := frozenCorrelationFixture(t, "tetragon", nil)
	if _, err := CorrelateSandboxFrozen(oldInput, oldSnapshot); err != ErrInput {
		t.Fatal("v3 consumed historical snapshot")
	}
	for _, name := range []string{"scope", "batch", "generation", "body", "caller candidates", "empty snapshot"} {
		t.Run(name, func(t *testing.T) {
			changed, authority := input, snapshot
			switch name {
			case "scope":
				changed.Scope = correlationScope(t, 100)
			case "batch":
				changed.BatchID = correlationID(t, 100)
			case "generation":
				changed.Generation++
			case "body":
				changed.Body = append(append([]byte(nil), input.Body...), ' ')
			case "caller candidates":
				changed.Candidates = []runtimeevent.Candidate{{AgentID: correlationID(t, 6), SessionID: correlationID(t, 7)}}
			case "empty snapshot":
				authority = runtimeevent.FrozenCandidateSnapshot{}
			}
			if _, err := CorrelateSandboxFrozen(changed, authority); err != ErrInput {
				t.Fatal("unbound sandbox correlation accepted")
			}
		})
	}
}
