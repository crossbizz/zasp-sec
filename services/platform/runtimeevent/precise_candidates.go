package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

// PreciseFrozenCandidateSnapshot is a separate sealed capability for the V4
// algorithm. Historical binding is not permission to execute a current effect.
type PreciseFrozenCandidateSnapshot struct{ value FrozenCandidateSnapshot }

func (v PreciseFrozenCandidateSnapshot) ValidFor(scope domain.Scope, batch domain.ProductID, generation int64, archive [sha256.Size]byte) bool {
	return v.value.ValidFor(scope, batch, generation, archive)
}
func (v PreciseFrozenCandidateSnapshot) Digest() [sha256.Size]byte { return v.value.Digest() }
func (v PreciseFrozenCandidateSnapshot) IndexReceiptDigest() [sha256.Size]byte {
	return v.value.IndexReceiptDigest()
}
func (v PreciseFrozenCandidateSnapshot) SourceSensorID() domain.ProductID {
	return v.value.SourceSensorID()
}
func (v PreciseFrozenCandidateSnapshot) RuntimeSensorID() domain.ProductID {
	return v.value.RuntimeSensorID()
}
func (v PreciseFrozenCandidateSnapshot) Bytes() []byte  { return v.value.Bytes() }
func (v PreciseFrozenCandidateSnapshot) Replayed() bool { return v.value.Replayed() }
func (v PreciseFrozenCandidateSnapshot) Candidates() []CandidateObservation {
	return v.value.Candidates()
}
func (PreciseFrozenCandidateSnapshot) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("runtime-precise-candidate-snapshot[private]"))
}

func (repository *PostgresProductionPipelineRepository) FreezePreciseCandidates(ctx context.Context, lease StageLease, workerID, leaseToken string, indexReceipt, archive []byte) (PreciseFrozenCandidateSnapshot, error) {
	if !validProductionPipelineRepository(repository, ctx) || repository.authority != ProductionPipelineAuthorityCorrelation || !validStageLease(lease, RuntimeStageCorrelate, repository.clock()) || lease.ImplementationVersion != "runtime-correlation-v4" || !candidateWorkerPattern.MatchString(workerID) || !productionLeaseTokenPattern.MatchString(leaseToken) || lease.PredecessorDigest == nil || *lease.PredecessorDigest != lease.InputDigest {
		return PreciseFrozenCandidateSnapshot{}, ErrProductionPipeline
	}
	receipt, err := DecodeStageReceipt(indexReceipt)
	if err != nil || receipt.Stage != RuntimeStageIndex || receipt.ImplementationVersion != "runtime-index-v2" || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.EffectDigest != lease.InputDigest || receipt.InputDigest != receipt.ArchiveDigest || receipt.InputReference != receipt.ArchiveReference || receipt.InputVersionID != receipt.ArchiveVersionID || len(archive) == 0 || len(archive) > maximumProductionIngestBytes || sha256.Sum256(archive) != receipt.ArchiveDigest {
		return PreciseFrozenCandidateSnapshot{}, ErrProductionPipeline
	}
	decoded, err := DecodePreciseArchivedBatch(lease.Scope, archive)
	if err != nil {
		return PreciseFrozenCandidateSnapshot{}, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, `SELECT zasp_runtime_freeze_precise_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.BatchID.String(), lease.Generation, workerID, leaseToken, lease.Attempt, lease.ImplementationVersion, lease.InputDigest[:], indexReceipt, archive)
	if err != nil {
		var provider *pgconn.PgError
		if errors.As(err, &provider) {
			if provider.Code == "54000" {
				return PreciseFrozenCandidateSnapshot{}, ErrCandidateSnapshotOverflow
			}
			if provider.Code == "42501" {
				return PreciseFrozenCandidateSnapshot{}, ErrCandidateSnapshotDenied
			}
		}
		return PreciseFrozenCandidateSnapshot{}, ErrProductionPipelineUnavailable
	}
	value, err := decodePreciseFrozenCandidates(payload, lease, receipt.ArchiveDigest, sha256.Sum256(indexReceipt), decoded)
	if err != nil {
		return PreciseFrozenCandidateSnapshot{}, err
	}
	if ctx.Err() != nil || !validStageLease(lease, RuntimeStageCorrelate, repository.clock()) {
		return PreciseFrozenCandidateSnapshot{}, ErrProductionPipelineUnavailable
	}
	return value, nil
}

func decodePreciseFrozenCandidates(payload []byte, lease StageLease, archiveDigest, receiptDigest [sha256.Size]byte, archive PreciseArchivedBatch) (PreciseFrozenCandidateSnapshot, error) {
	reject := func() (PreciseFrozenCandidateSnapshot, error) {
		return PreciseFrozenCandidateSnapshot{}, ErrProductionPipelineUnavailable
	}
	var envelope candidateEnvelopeWire
	if !closedCandidateJSON(payload, maximumCandidateEnvelopeBytes, &envelope, "snapshot", "sha256", "replayed") || len(envelope.Snapshot) < 2 || len(envelope.Snapshot) > 2*maximumCandidateSnapshotBytes {
		return reject()
	}
	body, err := hex.DecodeString(envelope.Snapshot)
	if err != nil || hex.EncodeToString(body) != envelope.Snapshot {
		return reject()
	}
	digest, ok := candidateDigest(envelope.SHA256)
	if !ok || digest != sha256.Sum256(body) {
		return reject()
	}
	var wire candidateSnapshotWire
	if !closedCandidateJSON(body, maximumCandidateSnapshotBytes, &wire, "schema", "organization_id", "workspace_id", "environment_id", "batch_id", "generation", "source_sensor_id", "runtime_sensor_id", "archive_digest", "index_receipt_digest", "window_seconds", "candidates") || wire.Schema != "runtime-candidate-snapshot-v3" || lease.ImplementationVersion != "runtime-correlation-v4" || archive.Source != "tetragon" || wire.OrganizationID != lease.Scope.OrganizationID().String() || wire.WorkspaceID != lease.Scope.WorkspaceID().String() || wire.EnvironmentID != lease.Scope.EnvironmentID().String() || wire.BatchID != lease.BatchID.String() || wire.Generation != lease.Generation || wire.WindowSeconds != 300 || len(wire.Candidates) > 1000 {
		return reject()
	}
	gotArchive, archiveOK := candidateDigest(wire.ArchiveDigest)
	gotReceipt, receiptOK := candidateDigest(wire.IndexReceiptDigest)
	source, sourceErr := domain.ParseProductID(wire.SourceSensorID)
	if !archiveOK || !receiptOK || gotArchive != archiveDigest || gotReceipt != receiptDigest || sourceErr != nil || wire.RuntimeSensorID == nil || *wire.RuntimeSensorID != wire.SourceSensorID {
		return reject()
	}
	value := FrozenCandidateSnapshot{scope: lease.Scope, batchID: lease.BatchID, generation: lease.Generation, sourceSensorID: source, runtimeSensorID: source, archiveDigest: archiveDigest, indexReceiptDigest: receiptDigest, digest: digest, body: body, replayed: envelope.Replayed, sandboxBindings: true, candidates: make([]CandidateObservation, 0, len(wire.Candidates))}
	var previous CandidateObservation
	for _, raw := range wire.Candidates {
		var candidate candidateObservationWire
		if !closedCandidateJSONWithNullable(raw, maximumCandidateSnapshotBytes, &candidate, "sandbox_id", "batch_id", "generation", "event_ordinal", "source_sensor_id", "agent_id", "session_id", "sandbox_id", "archive_digest", "index_receipt_digest", "observed_lineage", "event_time") {
			return reject()
		}
		observation, ok := decodeCandidateObservation(candidate)
		if !ok || observation.SourceSensorID == source || observation.BatchID == lease.BatchID || !preciseCandidateInSelectionWindow(observation, archive) || !previous.BatchID.IsZero() && (observation.BatchID.String() < previous.BatchID.String() || observation.BatchID == previous.BatchID && observation.EventOrdinal <= previous.EventOrdinal) {
			return reject()
		}
		value.candidates = append(value.candidates, observation)
		previous = observation
	}
	return PreciseFrozenCandidateSnapshot{value: value}, nil
}

func preciseCandidateInSelectionWindow(candidate CandidateObservation, archive PreciseArchivedBatch) bool {
	for _, record := range archive.Records {
		right, left := record.ObservedLineage, candidate.Lineage
		source, err := right.TimeAt(record.EventTime)
		if err != nil {
			continue
		}
		delta := candidate.EventTime.Sub(source)
		if left.Profile == "kubernetes-container-v1" && left.ClusterUID == right.ClusterUID && left.NodeUID == right.NodeUID && left.BootID == right.BootID && left.PodUID == right.PodUID && left.ContainerID == right.ContainerID && delta >= -5*time.Minute && delta <= 5*time.Minute {
			return true
		}
	}
	return false
}
