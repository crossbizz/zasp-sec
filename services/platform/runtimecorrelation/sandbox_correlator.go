package runtimecorrelation

import (
	"crypto/sha256"
	"sort"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// CorrelateSandboxFrozen is the v3 algorithm. A semantic sandbox is scoped to
// its admitted source enrollment, never a caller-supplied source attribute.
// The five-minute occurrence window isn't a claim of continuous lifetime.
func CorrelateSandboxFrozen(input Batch, snapshot runtimeevent.FrozenCandidateSnapshot) (CorrelatedBatch, error) {
	if input.Scope.Validate() != nil || input.BatchID.IsZero() || input.Generation < 1 || input.ArchiveDigest == ([sha256.Size]byte{}) || len(input.Body) < 1 || len(input.Body) > 64<<20 || sha256.Sum256(input.Body) != input.ArchiveDigest || len(input.Candidates) != 0 || !snapshot.HasSandboxBindings() || !snapshot.ValidFor(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest) {
		return CorrelatedBatch{}, ErrInput
	}
	batch, err := runtimeevent.DecodeArchivedBatch(input.Scope, input.Body)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	candidates := snapshot.Candidates()
	results := make([]Result, len(batch.Records))
	for index, record := range batch.Records {
		result := Result{EventID: record.ID, Confidence: domain.EvidenceConfidenceUnattributed}
		if batch.Source == "otlp" && !record.AgentID.IsZero() && !record.SessionID.IsZero() {
			result.AgentID, result.SessionID, result.Confidence = record.AgentID, record.SessionID, domain.EvidenceConfidenceExact
			result.SandboxID, result.SandboxSourceSensorID = record.SandboxID, snapshot.SourceSensorID()
		} else {
			type binding struct {
				agent, session, source domain.ProductID
				sandbox                string
				observed               bool
			}
			matched := make(map[binding]struct{})
			for _, candidate := range candidates {
				if qualifiedObservationMatch(record, candidate) {
					matched[binding{candidate.AgentID, candidate.SessionID, candidate.SourceSensorID, candidate.SandboxID, candidate.SandboxObserved}] = struct{}{}
				}
			}
			if len(matched) == 1 {
				for value := range matched {
					result.AgentID, result.SessionID = value.agent, value.session
					if value.observed {
						result.SandboxID, result.SandboxSourceSensorID = value.sandbox, value.source
					}
				}
				result.Confidence = domain.EvidenceConfidenceStrong
			} else if len(matched) > 1 {
				result.Confidence = domain.EvidenceConfidenceProbable
			}
		}
		results[index] = result
	}
	sort.Slice(results, func(i, j int) bool { return results[i].EventID.String() < results[j].EventID.String() })
	if !validSandboxResults(results) {
		return CorrelatedBatch{}, ErrInput
	}
	digest, err := sandboxCorrelationDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, snapshot.Digest(), results)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	return CorrelatedBatch{BatchID: input.BatchID, Generation: input.Generation, ArchiveDigest: input.ArchiveDigest, ContentDigest: digest, CandidateSnapshotDigest: snapshot.Digest(), Results: results}, nil
}

func validSandboxResults(results []Result) bool {
	if !validResults(results) {
		return false
	}
	for _, result := range results {
		if !validOptional(result.SandboxID, 256) || (result.SandboxID == "") != result.SandboxSourceSensorID.IsZero() {
			return false
		}
		if result.Confidence == domain.EvidenceConfidenceExact && result.SandboxID == "" {
			return false
		}
		if (result.Confidence == domain.EvidenceConfidenceProbable || result.Confidence == domain.EvidenceConfidenceUnattributed) && result.SandboxID != "" {
			return false
		}
	}
	return true
}

func sandboxCorrelationDigest(scope domain.Scope, batchID domain.ProductID, generation int64, archiveDigest, snapshotDigest [sha256.Size]byte, results []Result) ([sha256.Size]byte, error) {
	return versionedFrozenCorrelationDigest("zasp.runtime-correlation.batch.v3", scope, batchID, generation, archiveDigest, snapshotDigest, results)
}
