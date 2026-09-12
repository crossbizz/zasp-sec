package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimelineage"
)

const productionCandidateFreezeSQL = `SELECT zasp_runtime_freeze_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
const productionSandboxCandidateFreezeSQL = `SELECT zasp_runtime_freeze_sandbox_candidates($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
const productionCandidateReadySQL = `SELECT jsonb_build_object('ready',zasp_production_runtime_candidate_authority_readiness($1,$2) AND zasp_runtime_principal_ready($3))`
const productionCandidateReadyV48SQL = `SELECT jsonb_build_object('ready',zasp_production_runtime_acceptance_readiness($1,$2) AND zasp_production_runtime_candidate_authority_readiness($3,$4) AND zasp_runtime_principal_ready($5))`
const maximumCandidateSnapshotBytes = 1 << 20
const maximumCandidateEnvelopeBytes = 2*maximumCandidateSnapshotBytes + 1024

var candidateWorkerPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,127}$`)
var ErrCandidateSnapshotOverflow = errors.New("runtime candidate snapshot overflow")
var ErrCandidateSnapshotDenied = errors.New("runtime candidate snapshot denied")

// ReadyCandidates requires the exact candidate schema and registered correlation
// principal. Only an absent v48 function can try the explicitly pinned v47
// predecessor; false readiness and other provider failures never fall back.
func (repository *PostgresProductionPipelineRepository) ReadyCandidates(ctx context.Context) error {
	if !validProductionPipelineRepository(repository, ctx) || repository.authority != ProductionPipelineAuthorityCorrelation {
		return ErrProductionPipelineUnavailable
	}
	metadata := migrations.ProductionRuntimeCandidateAuthority()
	payload, err := safeProductionQuery(repository.database, ctx, productionCandidateReadyV48SQL, migrations.ProductionRuntimeAcceptance().Checksum(), migrations.ProductionRuntimeAcceptanceSemanticFingerprint(), metadata.Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint(), string(repository.authority))
	var provider *pgconn.PgError
	if ctx.Err() == nil && errors.As(err, &provider) && provider.Code == "42883" {
		payload, err = safeProductionQuery(repository.database, ctx, productionCandidateReadySQL, metadata.Checksum(), migrations.ProductionRuntimeCandidateAuthoritySemanticFingerprint(), string(repository.authority))
	}
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || ctx.Err() != nil || !closedCandidateJSON(payload, 16<<10, &result, "ready") || !result.Ready {
		return ErrProductionPipelineUnavailable
	}
	return nil
}

// CandidateObservation is a copy of one admitted, provenance-bound occurrence.
// Its existence is not host attestation or permission to assign Exact confidence.
type CandidateObservation struct {
	BatchID        domain.ProductID
	Generation     int64
	EventOrdinal   int
	SourceSensorID domain.ProductID
	AgentID        domain.ProductID
	SessionID      domain.ProductID
	// SandboxObserved distinguishes retained semantic evidence from historical
	// rows whose sandbox was not retained. Unknown isn't observed absence.
	SandboxID          string
	SandboxObserved    bool
	ArchiveDigest      [sha256.Size]byte
	IndexReceiptDigest [sha256.Size]byte
	Lineage            runtimelineage.Observation
	EventTime          time.Time
}

// FrozenCandidateSnapshot can only be populated by the repository's closed
// decoder. All slice accessors return copies. Its original bytes, not a Go JSON
// re-encoding, bind the correlation decision to the frozen database record.
type FrozenCandidateSnapshot struct {
	scope              domain.Scope
	batchID            domain.ProductID
	generation         int64
	sourceSensorID     domain.ProductID
	runtimeSensorID    domain.ProductID
	archiveDigest      [sha256.Size]byte
	indexReceiptDigest [sha256.Size]byte
	digest             [sha256.Size]byte
	body               []byte
	candidates         []CandidateObservation
	replayed           bool
	sandboxBindings    bool
}

// ValidFor checks historical snapshot binding, not a current execution lease.
// Effect execution must separately validate its live worker capability.
func (value FrozenCandidateSnapshot) ValidFor(scope domain.Scope, batch domain.ProductID, generation int64, archive [sha256.Size]byte) bool {
	return len(value.body) > 0 && value.scope == scope && value.batchID == batch && value.generation == generation && value.archiveDigest == archive
}
func (value FrozenCandidateSnapshot) Digest() [sha256.Size]byte { return value.digest }
func (value FrozenCandidateSnapshot) IndexReceiptDigest() [sha256.Size]byte {
	return value.indexReceiptDigest
}
func (value FrozenCandidateSnapshot) SourceSensorID() domain.ProductID  { return value.sourceSensorID }
func (value FrozenCandidateSnapshot) RuntimeSensorID() domain.ProductID { return value.runtimeSensorID }
func (value FrozenCandidateSnapshot) Bytes() []byte                     { return bytes.Clone(value.body) }
func (value FrozenCandidateSnapshot) Replayed() bool                    { return value.replayed }
func (value FrozenCandidateSnapshot) HasSandboxBindings() bool          { return value.sandboxBindings }
func (value FrozenCandidateSnapshot) Candidates() []CandidateObservation {
	return append([]CandidateObservation(nil), value.candidates...)
}
func (FrozenCandidateSnapshot) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("runtime-candidate-snapshot[private]"))
}

// FreezeCandidates borrows immutable receipt/archive buffers only for this call.
// Callers retain buffer ownership and must not mutate them concurrently. Worker
// and lease credentials go only to the private SQL call, never into the snapshot.
// An uncertain database outcome is retryable: SQL replays the original freeze.
func (repository *PostgresProductionPipelineRepository) FreezeCandidates(ctx context.Context, lease StageLease, workerID, leaseToken string, indexReceipt, archive []byte) (FrozenCandidateSnapshot, error) {
	if !validProductionPipelineRepository(repository, ctx) || repository.authority != ProductionPipelineAuthorityCorrelation || repository.stage != RuntimeStageCorrelate || !validStageLease(lease, RuntimeStageCorrelate, repository.clock()) || (lease.ImplementationVersion != "runtime-correlation-v2" && lease.ImplementationVersion != "runtime-correlation-v3") || !candidateWorkerPattern.MatchString(workerID) || !productionLeaseTokenPattern.MatchString(leaseToken) || lease.PredecessorDigest == nil || *lease.PredecessorDigest != lease.InputDigest {
		return FrozenCandidateSnapshot{}, ErrProductionPipeline
	}
	receipt, err := DecodeStageReceipt(indexReceipt)
	if err != nil || receipt.Stage != RuntimeStageIndex || receipt.ImplementationVersion != "runtime-index-v1" || receipt.Scope != lease.Scope || receipt.BatchID != lease.BatchID || receipt.Generation != lease.Generation || receipt.EffectDigest != lease.InputDigest || receipt.InputDigest != receipt.ArchiveDigest || receipt.InputReference != receipt.ArchiveReference || receipt.InputVersionID != receipt.ArchiveVersionID || len(archive) == 0 || len(archive) > maximumProductionIngestBytes || sha256.Sum256(archive) != receipt.ArchiveDigest {
		return FrozenCandidateSnapshot{}, ErrProductionPipeline
	}
	decoded, err := DecodeArchivedBatch(lease.Scope, archive)
	if err != nil {
		return FrozenCandidateSnapshot{}, ErrProductionPipeline
	}
	statement := productionCandidateFreezeSQL
	if lease.ImplementationVersion == "runtime-correlation-v3" {
		statement = productionSandboxCandidateFreezeSQL
	}
	payload, err := safeProductionQuery(repository.database, ctx, statement, lease.Scope.OrganizationID().String(), lease.Scope.WorkspaceID().String(), lease.Scope.EnvironmentID().String(), lease.BatchID.String(), lease.Generation, workerID, leaseToken, lease.Attempt, lease.ImplementationVersion, lease.InputDigest[:], indexReceipt, archive)
	if err != nil {
		var provider *pgconn.PgError
		if errors.As(err, &provider) {
			if provider.Code == "54000" {
				return FrozenCandidateSnapshot{}, ErrCandidateSnapshotOverflow
			}
			if provider.Code == "42501" {
				return FrozenCandidateSnapshot{}, ErrCandidateSnapshotDenied
			}
		}
		return FrozenCandidateSnapshot{}, ErrProductionPipelineUnavailable
	}
	value, err := decodeFrozenCandidates(payload, lease, receipt.ArchiveDigest, sha256.Sum256(indexReceipt), decoded)
	if err != nil {
		return FrozenCandidateSnapshot{}, err
	}
	// A successful database response can arrive after local cancellation or the
	// submitted lease expires. Decoding must not extend execution authority.
	if ctx.Err() != nil || !validStageLease(lease, RuntimeStageCorrelate, repository.clock()) {
		return FrozenCandidateSnapshot{}, ErrProductionPipelineUnavailable
	}
	return value, nil
}

type candidateEnvelopeWire struct {
	Snapshot string `json:"snapshot"`
	SHA256   string `json:"sha256"`
	Replayed bool   `json:"replayed"`
}
type candidateSnapshotWire struct {
	Schema             string            `json:"schema"`
	OrganizationID     string            `json:"organization_id"`
	WorkspaceID        string            `json:"workspace_id"`
	EnvironmentID      string            `json:"environment_id"`
	BatchID            string            `json:"batch_id"`
	Generation         int64             `json:"generation"`
	SourceSensorID     string            `json:"source_sensor_id"`
	RuntimeSensorID    *string           `json:"runtime_sensor_id"`
	ArchiveDigest      string            `json:"archive_digest"`
	IndexReceiptDigest string            `json:"index_receipt_digest"`
	WindowSeconds      int               `json:"window_seconds"`
	Candidates         []json.RawMessage `json:"candidates"`
}
type candidateObservationWire struct {
	BatchID            string                     `json:"batch_id"`
	Generation         int64                      `json:"generation"`
	EventOrdinal       int                        `json:"event_ordinal"`
	SourceSensorID     string                     `json:"source_sensor_id"`
	AgentID            string                     `json:"agent_id"`
	SessionID          string                     `json:"session_id"`
	SandboxID          *string                    `json:"sandbox_id"`
	ArchiveDigest      string                     `json:"archive_digest"`
	IndexReceiptDigest string                     `json:"index_receipt_digest"`
	Lineage            runtimelineage.Observation `json:"observed_lineage"`
	EventTime          string                     `json:"event_time"`
}

func decodeFrozenCandidates(payload []byte, lease StageLease, archiveDigest, receiptDigest [sha256.Size]byte, archive ArchivedBatch) (FrozenCandidateSnapshot, error) {
	reject := func() (FrozenCandidateSnapshot, error) {
		return FrozenCandidateSnapshot{}, ErrProductionPipelineUnavailable
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
	sandboxBindings := lease.ImplementationVersion == "runtime-correlation-v3"
	expectedSchema := "runtime-candidate-snapshot-v1"
	if sandboxBindings {
		expectedSchema = "runtime-candidate-snapshot-v2"
	} else if lease.ImplementationVersion != "runtime-correlation-v2" {
		return reject()
	}
	if !closedCandidateJSON(body, maximumCandidateSnapshotBytes, &wire, "schema", "organization_id", "workspace_id", "environment_id", "batch_id", "generation", "source_sensor_id", "runtime_sensor_id", "archive_digest", "index_receipt_digest", "window_seconds", "candidates") || wire.Schema != expectedSchema || wire.OrganizationID != lease.Scope.OrganizationID().String() || wire.WorkspaceID != lease.Scope.WorkspaceID().String() || wire.EnvironmentID != lease.Scope.EnvironmentID().String() || wire.BatchID != lease.BatchID.String() || wire.Generation != lease.Generation || wire.WindowSeconds != 300 || len(wire.Candidates) > 1000 {
		return reject()
	}
	gotArchive, archiveOK := candidateDigest(wire.ArchiveDigest)
	gotReceipt, receiptOK := candidateDigest(wire.IndexReceiptDigest)
	source, sourceErr := domain.ParseProductID(wire.SourceSensorID)
	var runtimeSensor domain.ProductID
	if wire.RuntimeSensorID != nil {
		runtimeSensor, err = domain.ParseProductID(*wire.RuntimeSensorID)
		if err != nil {
			return reject()
		}
	}
	if !archiveOK || !receiptOK || gotArchive != archiveDigest || gotReceipt != receiptDigest || sourceErr != nil || runtimeSensor.IsZero() && len(wire.Candidates) > 0 || archive.Source == "tetragon" && runtimeSensor != source || archive.Source == "otlp" && runtimeSensor == source {
		return reject()
	}
	value := FrozenCandidateSnapshot{scope: lease.Scope, batchID: lease.BatchID, generation: lease.Generation, sourceSensorID: source, runtimeSensorID: runtimeSensor, archiveDigest: archiveDigest, indexReceiptDigest: receiptDigest, digest: digest, body: body, replayed: envelope.Replayed, sandboxBindings: sandboxBindings, candidates: make([]CandidateObservation, 0, len(wire.Candidates))}
	var previous CandidateObservation
	for _, raw := range wire.Candidates {
		var candidate candidateObservationWire
		keys := []string{"batch_id", "generation", "event_ordinal", "source_sensor_id", "agent_id", "session_id", "archive_digest", "index_receipt_digest", "observed_lineage", "event_time"}
		nullable := ""
		if sandboxBindings {
			keys = append(keys, "sandbox_id")
			nullable = "sandbox_id"
		}
		if !closedCandidateJSONWithNullable(raw, maximumCandidateSnapshotBytes, &candidate, nullable, keys...) {
			return reject()
		}
		observation, ok := decodeCandidateObservation(candidate)
		if !ok || observation.SourceSensorID == runtimeSensor || !candidateInSelectionWindow(observation, archive) || !previous.BatchID.IsZero() && (observation.BatchID.String() < previous.BatchID.String() || observation.BatchID == previous.BatchID && observation.EventOrdinal <= previous.EventOrdinal) {
			return reject()
		}
		if observation.BatchID == lease.BatchID {
			if archive.Source != "otlp" || observation.Generation != lease.Generation || observation.SourceSensorID != source || observation.ArchiveDigest != archiveDigest || observation.IndexReceiptDigest != receiptDigest || observation.EventOrdinal > len(archive.Records) {
				return reject()
			}
			record := archive.Records[observation.EventOrdinal-1]
			if observation.AgentID != record.AgentID || observation.SessionID != record.SessionID || observation.Lineage != record.ObservedLineage || !observation.EventTime.Equal(record.EventTime) || sandboxBindings && (!observation.SandboxObserved || observation.SandboxID != record.SandboxID) {
				return reject()
			}
		}
		value.candidates = append(value.candidates, observation)
		previous = observation
	}
	return value, nil
}

func decodeCandidateObservation(wire candidateObservationWire) (CandidateObservation, bool) {
	var value CandidateObservation
	var err error
	for _, field := range []struct {
		text        string
		destination *domain.ProductID
	}{{wire.BatchID, &value.BatchID}, {wire.SourceSensorID, &value.SourceSensorID}, {wire.AgentID, &value.AgentID}, {wire.SessionID, &value.SessionID}} {
		*field.destination, err = domain.ParseProductID(field.text)
		if err != nil {
			return CandidateObservation{}, false
		}
	}
	if value.BatchID.IsZero() || value.SourceSensorID.IsZero() || value.AgentID.IsZero() || value.SessionID.IsZero() || value.AgentID == value.SessionID || wire.Generation < 1 || wire.EventOrdinal < 1 || wire.EventOrdinal > 1000 {
		return CandidateObservation{}, false
	}
	var ok bool
	value.ArchiveDigest, ok = candidateDigest(wire.ArchiveDigest)
	if !ok {
		return CandidateObservation{}, false
	}
	value.IndexReceiptDigest, ok = candidateDigest(wire.IndexReceiptDigest)
	if !ok {
		return CandidateObservation{}, false
	}
	value.EventTime, err = time.Parse(timestampLayout, wire.EventTime)
	if err != nil || value.EventTime.Format(timestampLayout) != wire.EventTime || wire.Lineage == (runtimelineage.Observation{}) || !wire.Lineage.ValidAt(value.EventTime) {
		return CandidateObservation{}, false
	}
	value.Generation, value.EventOrdinal, value.Lineage = wire.Generation, wire.EventOrdinal, wire.Lineage
	if wire.SandboxID != nil {
		if !validProductionText(*wire.SandboxID, 256) {
			return CandidateObservation{}, false
		}
		value.SandboxID, value.SandboxObserved = *wire.SandboxID, true
	}
	return value, true
}

func candidateInSelectionWindow(candidate CandidateObservation, archive ArchivedBatch) bool {
	for _, record := range archive.Records {
		left, right := candidate.Lineage, record.ObservedLineage
		delta := candidate.EventTime.Sub(record.EventTime)
		if right != (runtimelineage.Observation{}) && left.Profile == right.Profile && left.ClusterUID == right.ClusterUID && left.NodeUID == right.NodeUID && left.BootID == right.BootID && left.PodUID == right.PodUID && left.ContainerID == right.ContainerID && delta >= -5*time.Minute && delta <= 5*time.Minute {
			return true
		}
	}
	return false
}

func candidateDigest(text string) ([sha256.Size]byte, bool) {
	var digest [sha256.Size]byte
	if len(text) != 2*sha256.Size {
		return digest, false
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(decoded) != text {
		return digest, false
	}
	copy(digest[:], decoded)
	return digest, digest != [sha256.Size]byte{}
}

// This dedicated limit must not relax strictProductionJSON's shared 16 KiB cap.
func closedCandidateJSON(payload []byte, maximum int, destination any, keys ...string) bool {
	return closedCandidateJSONWithNullable(payload, maximum, destination, "runtime_sensor_id", keys...)
}

// Only the versioned candidate decoder permits nullable sandbox_id. The old
// decoder's keys and null policy remain unchanged.
func closedCandidateJSONWithNullable(payload []byte, maximum int, destination any, nullable string, keys ...string) bool {
	if len(payload) < 2 || len(payload) > maximum || !utf8.Valid(payload) || !uniqueProductionJSON(payload) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, exists := fields[key]
		if !exists || key != nullable && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return json.Unmarshal(payload, destination) == nil
}
