package runtimecorrelation

import (
	"crypto/sha256"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

// CorrelatePreciseFrozen is the V4 kernel-observation algorithm. Exact source
// time governs its occurrence window; a match remains Strong, not attestation.
func CorrelatePreciseFrozen(input Batch, snapshot runtimeevent.PreciseFrozenCandidateSnapshot) (CorrelatedBatch, error) {
	if input.Scope.Validate() != nil || input.BatchID.IsZero() || input.Generation < 1 || input.ArchiveDigest == ([sha256.Size]byte{}) || len(input.Body) < 1 || len(input.Body) > 64<<20 || sha256.Sum256(input.Body) != input.ArchiveDigest || len(input.Candidates) != 0 || !snapshot.ValidFor(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest) {
		return CorrelatedBatch{}, ErrInput
	}
	batch, err := runtimeevent.DecodePreciseArchivedBatch(input.Scope, input.Body)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	candidates := snapshot.Candidates()
	results := make([]Result, len(batch.Records))
	for i, record := range batch.Records {
		result := Result{EventID: record.ID, Confidence: domain.EvidenceConfidenceUnattributed}
		type binding struct {
			agent, session, source domain.ProductID
			sandbox                string
			observed               bool
		}
		matched := make(map[binding]struct{})
		for _, candidate := range candidates {
			if preciseQualifiedObservationMatch(record, candidate) {
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
		results[i] = result
	}
	sort.Slice(results, func(i, j int) bool { return results[i].EventID.String() < results[j].EventID.String() })
	if !validSandboxResults(results) {
		return CorrelatedBatch{}, ErrInput
	}
	digest, err := versionedFrozenCorrelationDigest("zasp.runtime-correlation.batch.v4", input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, snapshot.Digest(), results)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	return CorrelatedBatch{BatchID: input.BatchID, Generation: input.Generation, ArchiveDigest: input.ArchiveDigest, ContentDigest: digest, CandidateSnapshotDigest: snapshot.Digest(), Results: results}, nil
}

func preciseQualifiedObservationMatch(record runtimeevent.PreciseRecord, candidate runtimeevent.CandidateObservation) bool {
	left, right := record.ObservedLineage, candidate.Lineage
	source, err := left.TimeAt(record.EventTime)
	if err != nil || right.Profile != "kubernetes-container-v1" || !right.ValidAt(candidate.EventTime) || left.ClusterUID != right.ClusterUID || left.NodeUID != right.NodeUID || left.BootID != right.BootID || left.PodUID != right.PodUID || left.ContainerID != right.ContainerID {
		return false
	}
	delta := candidate.EventTime.Sub(source)
	if delta < -5*time.Minute || delta > 5*time.Minute {
		return false
	}
	if left.ProcessID != "" && right.ProcessID != "" && (left.ProcessID != right.ProcessID || left.ProcessStartTime != right.ProcessStartTime) {
		return false
	}
	if left.CgroupID != "" && right.CgroupID != "" && left.CgroupID != right.CgroupID {
		return false
	}
	return true
}
