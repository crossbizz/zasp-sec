package runtimecorrelation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

// CorrelateFrozen is the v2 algorithm. Only a repository-decoded frozen snapshot
// supplies cross-batch candidates. This pure computation doesn't grant permission
// to write effects; its caller must separately hold a current execution lease.
func CorrelateFrozen(input Batch, snapshot runtimeevent.FrozenCandidateSnapshot) (CorrelatedBatch, error) {
	if input.Scope.Validate() != nil || input.BatchID.IsZero() || input.Generation < 1 || input.ArchiveDigest == ([sha256.Size]byte{}) || len(input.Body) < 1 || len(input.Body) > 64<<20 || sha256.Sum256(input.Body) != input.ArchiveDigest || len(input.Candidates) != 0 || snapshot.HasSandboxBindings() || !snapshot.ValidFor(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest) {
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
			// Semantic IDs were validated in this exact archive. Runtime qualifiers
			// neither grant nor displace explicit semantic identity.
			result.AgentID, result.SessionID, result.Confidence = record.AgentID, record.SessionID, domain.EvidenceConfidenceExact
		} else {
			type identity struct{ agent, session domain.ProductID }
			matched := make(map[identity]struct{})
			for _, candidate := range candidates {
				if qualifiedObservationMatch(record, candidate) {
					matched[identity{candidate.AgentID, candidate.SessionID}] = struct{}{}
				}
			}
			if len(matched) == 1 {
				for value := range matched {
					result.AgentID, result.SessionID = value.agent, value.session
				}
				result.Confidence = domain.EvidenceConfidenceStrong
			} else if len(matched) > 1 {
				result.Confidence = domain.EvidenceConfidenceProbable
			}
		}
		results[index] = result
	}
	sort.Slice(results, func(left, right int) bool { return results[left].EventID.String() < results[right].EventID.String() })
	if !validResults(results) {
		return CorrelatedBatch{}, ErrInput
	}
	digest, err := frozenCorrelationDigest(input.Scope, input.BatchID, input.Generation, input.ArchiveDigest, snapshot.Digest(), results)
	if err != nil {
		return CorrelatedBatch{}, ErrInput
	}
	return CorrelatedBatch{BatchID: input.BatchID, Generation: input.Generation, ArchiveDigest: input.ArchiveDigest, ContentDigest: digest, CandidateSnapshotDigest: snapshot.Digest(), Results: results}, nil
}

func qualifiedObservationMatch(record runtimeevent.Record, candidate runtimeevent.CandidateObservation) bool {
	left, right := record.ObservedLineage, candidate.Lineage
	if left == (runtimelineage.Observation{}) || right == (runtimelineage.Observation{}) || !left.ValidAt(record.EventTime) || !right.ValidAt(candidate.EventTime) || left.Profile != right.Profile || left.ClusterUID != right.ClusterUID || left.NodeUID != right.NodeUID || left.BootID != right.BootID || left.PodUID != right.PodUID || left.ContainerID != right.ContainerID {
		return false
	}
	delta := candidate.EventTime.Sub(record.EventTime)
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

func frozenCorrelationDigest(scope domain.Scope, batchID domain.ProductID, generation int64, archiveDigest, snapshotDigest [sha256.Size]byte, results []Result) ([sha256.Size]byte, error) {
	return versionedFrozenCorrelationDigest("zasp.runtime-correlation.batch.v2", scope, batchID, generation, archiveDigest, snapshotDigest, results)
}

func versionedFrozenCorrelationDigest(digestDomain string, scope domain.Scope, batchID domain.ProductID, generation int64, archiveDigest, snapshotDigest [sha256.Size]byte, results []Result) ([sha256.Size]byte, error) {
	wire := struct {
		Domain                  string       `json:"domain"`
		OrganizationID          string       `json:"organization_id"`
		WorkspaceID             string       `json:"workspace_id"`
		EnvironmentID           string       `json:"environment_id"`
		BatchID                 string       `json:"batch_id"`
		Generation              int64        `json:"generation"`
		ArchiveDigest           string       `json:"archive_digest"`
		CandidateSnapshotDigest string       `json:"candidate_snapshot_digest"`
		Results                 []resultWire `json:"results"`
	}{digestDomain, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String(), generation, hex.EncodeToString(archiveDigest[:]), hex.EncodeToString(snapshotDigest[:]), resultsToWire(results)}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return [sha256.Size]byte{}, ErrInput
	}
	return sha256.Sum256(encoded), nil
}
