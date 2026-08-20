package runtimeevent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	productionPipelineReadySQL             = `SELECT jsonb_build_object('ready',zasp_runtime_data_plane_readiness($1,$2) AND zasp_runtime_principal_ready($3))`
	productionPipelineClaimDeliverySQL     = `SELECT zasp_runtime_claim_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	productionPipelineHeartbeatDeliverySQL = `SELECT zasp_runtime_heartbeat_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	productionPipelineReleaseDeliverySQL   = `SELECT zasp_runtime_release_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	productionPipelineAckDeliverySQL       = `SELECT zasp_runtime_ack_delivery($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	productionPipelineClaimStageSQL        = `SELECT zasp_runtime_claim_stage($1,$2,$3,$4)`
	productionPipelineHeartbeatStageSQL    = `SELECT zasp_runtime_heartbeat_stage($1,$2,$3,$4,$5,$6,$7,$8)`
	productionPipelineFinishStageSQL       = `SELECT zasp_runtime_finish_stage($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
)

var (
	ErrProductionPipeline            = errors.New("production runtime pipeline rejected")
	ErrProductionPipelineUnavailable = errors.New("production runtime pipeline unavailable")
	ErrProductionPipelineUnknown     = errors.New("production runtime pipeline outcome unknown")
	productionWorkerPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	productionLeaseTokenPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)
	productionMessageKeyPattern      = regexp.MustCompile(`^sha256_[0-9a-f]{64}$`)
)

type ProductionPipelineAuthority string

const (
	ProductionPipelineAuthorityCoordinator ProductionPipelineAuthority = "zasp_runtime_coordinator"
	ProductionPipelineAuthorityArchive     ProductionPipelineAuthority = "zasp_runtime_archive_worker"
	ProductionPipelineAuthorityIndex       ProductionPipelineAuthority = "zasp_runtime_index_worker"
	ProductionPipelineAuthorityCorrelation ProductionPipelineAuthority = "zasp_runtime_correlation_worker"
	ProductionPipelineAuthorityProjection  ProductionPipelineAuthority = "zasp_runtime_projection_worker"
)

type RuntimeStage string

const (
	RuntimeStageArchive   RuntimeStage = "archive"
	RuntimeStageIndex     RuntimeStage = "index"
	RuntimeStageCorrelate RuntimeStage = "correlate"
	RuntimeStageProject   RuntimeStage = "project"
	RuntimeStageComplete  RuntimeStage = "complete"
)

type DeliveryDisposition string

const (
	DeliveryDispositionClaimed     DeliveryDisposition = "claimed"
	DeliveryDispositionAckPending  DeliveryDisposition = "ack_pending"
	DeliveryDispositionAckTerminal DeliveryDisposition = "ack_terminal"
	DeliveryDispositionBusy        DeliveryDisposition = "busy"
	DeliveryDispositionUnknown     DeliveryDisposition = "unknown"
	DeliveryDispositionQuarantined DeliveryDisposition = "quarantined"
	DeliveryDispositionRetryable   DeliveryDisposition = "retryable"
	DeliveryDispositionAcked       DeliveryDisposition = "acked"
)

type DeliveryOutcome string

const (
	DeliveryOutcomeRetryable   DeliveryOutcome = "retryable"
	DeliveryOutcomeUnknown     DeliveryOutcome = "unknown"
	DeliveryOutcomeQuarantined DeliveryOutcome = "quarantined"
)

type DeliveryClaimRequest struct {
	Scope             domain.Scope
	BatchID           domain.ProductID
	Generation        int64
	MessageID         string
	MessageDigest     [sha256.Size]byte
	ReceiveCount      int
	WorkerID          string
	LeaseToken        string
	LeaseSeconds      int
	VisibilitySeconds int
}

type DeliveryClaim struct {
	Scope              domain.Scope
	BatchID            domain.ProductID
	Generation         int64
	Disposition        DeliveryDisposition
	Replayed           bool
	LeaseExpiresAt     time.Time
	VisibilityDeadline time.Time
	Artifact           RawArtifact
	RequestDigest      [sha256.Size]byte
}

type DeliveryLeaseResult struct {
	BatchID            domain.ProductID
	Generation         int64
	LeaseExpiresAt     time.Time
	VisibilityDeadline time.Time
}

type DeliveryTransitionResult struct {
	BatchID     domain.ProductID
	Generation  int64
	Disposition DeliveryDisposition
	ErrorClass  string
	Replayed    bool
}

type StageLease struct {
	Scope                 domain.Scope
	BatchID               domain.ProductID
	Generation            int64
	Stage                 RuntimeStage
	Attempt               int
	ImplementationVersion string
	PredecessorDigest     *[sha256.Size]byte
	InputDigest           [sha256.Size]byte
	LeaseExpiresAt        time.Time
}

type StageOutcome string

const (
	StageOutcomeSucceeded   StageOutcome = "succeeded"
	StageOutcomeRetryable   StageOutcome = "retryable"
	StageOutcomeFailed      StageOutcome = "failed"
	StageOutcomeUnknown     StageOutcome = "unknown"
	StageOutcomeQuarantined StageOutcome = "quarantined"
)

type StageFinishRequest struct {
	Lease           StageLease
	WorkerID        string
	LeaseToken      string
	Outcome         StageOutcome
	EffectDigest    [sha256.Size]byte
	ResultReference string
	ResultVersionID string
	ResultDigest    [sha256.Size]byte
	ErrorClass      string
	RetryAfter      time.Duration
}

type StageFinishResult struct {
	BatchID               domain.ProductID
	Generation            int64
	Stage                 RuntimeStage
	State                 StageOutcome
	Attempt               int
	InputDigest           [sha256.Size]byte
	ImplementationVersion string
	EffectDigest          [sha256.Size]byte
	ResultReference       string
	ResultVersionID       string
	ResultDigest          [sha256.Size]byte
	ErrorClass            string
}

type PostgresProductionPipelineRepository struct {
	database  ProductionIngestDatabase
	authority ProductionPipelineAuthority
	stage     RuntimeStage
	clock     func() time.Time
}

func NewPostgresProductionPipelineRepository(database ProductionIngestDatabase, authority ProductionPipelineAuthority) (*PostgresProductionPipelineRepository, error) {
	stage, ok := stageForProductionAuthority(authority)
	if nilProductionDatabase(database) || !ok {
		return nil, ErrProductionPipeline
	}
	return &PostgresProductionPipelineRepository{database: database, authority: authority, stage: stage, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func (repository *PostgresProductionPipelineRepository) Ready(ctx context.Context) error {
	if !validProductionPipelineRepository(repository, ctx) {
		return ErrProductionPipelineUnavailable
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineReadySQL, migrations.ProductionRuntimeDataPlane().Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint(), string(repository.authority))
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || strictProductionJSON(payload, &result) != nil || !result.Ready {
		return ErrProductionPipelineUnavailable
	}
	return nil
}

func (repository *PostgresProductionPipelineRepository) ClaimDelivery(ctx context.Context, request DeliveryClaimRequest) (DeliveryClaim, error) {
	if repository == nil || repository.authority != ProductionPipelineAuthorityCoordinator || !validDeliveryClaimRequest(request) || ctx == nil || ctx.Err() != nil {
		return DeliveryClaim{}, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineClaimDeliverySQL, scopeArguments(request.Scope, request.BatchID, request.Generation, request.MessageID, request.MessageDigest[:], request.ReceiveCount, request.WorkerID, request.LeaseToken, request.LeaseSeconds, request.VisibilitySeconds)...)
	if err != nil {
		return DeliveryClaim{}, ErrProductionPipelineUnavailable
	}
	result, decodeErr := decodeDeliveryClaim(payload, request, repository.clock())
	if decodeErr != nil {
		return DeliveryClaim{}, ErrProductionPipelineUnavailable
	}
	return result, nil
}

func (repository *PostgresProductionPipelineRepository) HeartbeatDelivery(ctx context.Context, request DeliveryClaimRequest) (DeliveryLeaseResult, error) {
	if repository == nil || repository.authority != ProductionPipelineAuthorityCoordinator || !validDeliveryClaimRequest(request) || ctx == nil || ctx.Err() != nil {
		return DeliveryLeaseResult{}, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineHeartbeatDeliverySQL, scopeArguments(request.Scope, request.BatchID, request.Generation, request.MessageID, request.MessageDigest[:], request.WorkerID, request.LeaseToken, request.LeaseSeconds, request.VisibilitySeconds)...)
	if err != nil {
		return DeliveryLeaseResult{}, ErrProductionPipelineUnknown
	}
	var wire deliveryLeaseWire
	if strictProductionJSON(payload, &wire) != nil {
		return DeliveryLeaseResult{}, ErrProductionPipelineUnknown
	}
	result, ok := wire.result(request.BatchID, request.Generation, repository.clock())
	if !ok {
		return DeliveryLeaseResult{}, ErrProductionPipelineUnknown
	}
	return result, nil
}

func (repository *PostgresProductionPipelineRepository) ReleaseDelivery(ctx context.Context, request DeliveryClaimRequest, outcome DeliveryOutcome, errorClass string) (DeliveryTransitionResult, error) {
	if repository == nil || repository.authority != ProductionPipelineAuthorityCoordinator || !validDeliveryClaimRequest(request) || !validDeliveryOutcome(outcome, errorClass) || ctx == nil || ctx.Err() != nil {
		return DeliveryTransitionResult{}, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineReleaseDeliverySQL, scopeArguments(request.Scope, request.BatchID, request.Generation, request.MessageID, request.MessageDigest[:], request.WorkerID, request.LeaseToken, string(outcome), errorClass)...)
	if err != nil {
		return DeliveryTransitionResult{}, ErrProductionPipelineUnknown
	}
	result, ok := decodeDeliveryTransition(payload, request.BatchID, request.Generation)
	if !ok || result.Disposition != DeliveryDisposition(outcome) {
		return DeliveryTransitionResult{}, ErrProductionPipelineUnknown
	}
	return result, nil
}

func (repository *PostgresProductionPipelineRepository) AcknowledgeDelivery(ctx context.Context, request DeliveryClaimRequest, providerAck [sha256.Size]byte) (DeliveryTransitionResult, error) {
	if repository == nil || repository.authority != ProductionPipelineAuthorityCoordinator || !validDeliveryClaimRequest(request) || providerAck == [sha256.Size]byte{} || ctx == nil || ctx.Err() != nil {
		return DeliveryTransitionResult{}, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineAckDeliverySQL, scopeArguments(request.Scope, request.BatchID, request.Generation, request.MessageID, request.MessageDigest[:], request.WorkerID, request.LeaseToken, providerAck[:])...)
	if err != nil {
		return DeliveryTransitionResult{}, ErrProductionPipelineUnknown
	}
	result, ok := decodeDeliveryTransition(payload, request.BatchID, request.Generation)
	if !ok || result.Disposition != DeliveryDispositionAcked {
		return DeliveryTransitionResult{}, ErrProductionPipelineUnknown
	}
	return result, nil
}

func (repository *PostgresProductionPipelineRepository) ClaimStages(ctx context.Context, workerID, leaseToken string, leaseSeconds, limit int) ([]StageLease, error) {
	if !validProductionPipelineRepository(repository, ctx) || !validWorkerLease(workerID, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 || limit < 1 || limit > 10 {
		return nil, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineClaimStageSQL, workerID, leaseToken, leaseSeconds, limit)
	if err != nil {
		return nil, ErrProductionPipelineUnavailable
	}
	var wires []stageLeaseWire
	if strictProductionJSON(payload, &wires) != nil || len(wires) > limit {
		return nil, ErrProductionPipelineUnavailable
	}
	result := make([]StageLease, len(wires))
	seen := make(map[domain.ProductID]struct{}, len(wires))
	for index, wire := range wires {
		lease, ok := wire.result(repository.stage)
		if !ok || !validStageLease(lease, repository.stage, repository.clock()) {
			return nil, ErrProductionPipelineUnavailable
		}
		if _, duplicate := seen[lease.BatchID]; duplicate {
			return nil, ErrProductionPipelineUnavailable
		}
		seen[lease.BatchID] = struct{}{}
		result[index] = lease
	}
	return result, nil
}

func (repository *PostgresProductionPipelineRepository) HeartbeatStage(ctx context.Context, lease StageLease, workerID, leaseToken string, leaseSeconds int) (time.Time, error) {
	if !validProductionPipelineRepository(repository, ctx) || !validStageLease(lease, repository.stage, repository.clock()) || !validWorkerLease(workerID, leaseToken) || leaseSeconds < 5 || leaseSeconds > 900 {
		return time.Time{}, ErrProductionPipeline
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineHeartbeatStageSQL, scopeArguments(lease.Scope, lease.BatchID, lease.Generation, workerID, leaseToken, leaseSeconds)...)
	if err != nil {
		return time.Time{}, ErrProductionPipelineUnknown
	}
	var wire struct {
		BatchID        string    `json:"batch_id"`
		Generation     int64     `json:"generation"`
		Stage          string    `json:"stage"`
		LeaseExpiresAt time.Time `json:"lease_expires_at"`
	}
	if strictProductionJSON(payload, &wire) != nil || wire.BatchID != lease.BatchID.String() || wire.Generation != lease.Generation || RuntimeStage(wire.Stage) != lease.Stage || !wire.LeaseExpiresAt.After(repository.clock()) {
		return time.Time{}, ErrProductionPipelineUnknown
	}
	return wire.LeaseExpiresAt.UTC(), nil
}

func (repository *PostgresProductionPipelineRepository) FinishStage(ctx context.Context, request StageFinishRequest) (StageFinishResult, error) {
	if !validProductionPipelineRepository(repository, ctx) || !validStageFinishRequest(request, repository.stage, repository.clock()) {
		return StageFinishResult{}, ErrProductionPipeline
	}
	var effect, resultDigest []byte
	if request.Outcome == StageOutcomeSucceeded {
		effect, resultDigest = request.EffectDigest[:], request.ResultDigest[:]
	}
	retrySeconds := 0
	if request.Outcome == StageOutcomeRetryable {
		retrySeconds = int(request.RetryAfter / time.Second)
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionPipelineFinishStageSQL, scopeArguments(request.Lease.Scope, request.Lease.BatchID, request.Lease.Generation, request.WorkerID, request.LeaseToken, request.Lease.Attempt, request.Lease.InputDigest[:], request.Lease.ImplementationVersion, string(request.Outcome), effect, nullableString(request.ResultReference), nullableString(request.ResultVersionID), resultDigest, nullableString(request.ErrorClass), retrySeconds)...)
	if err != nil {
		return StageFinishResult{}, ErrProductionPipelineUnknown
	}
	result, ok := decodeStageFinish(payload)
	if !ok || result.BatchID != request.Lease.BatchID || result.Generation != request.Lease.Generation || result.Stage != request.Lease.Stage || result.State != request.Outcome || result.Attempt != request.Lease.Attempt || result.InputDigest != request.Lease.InputDigest || result.ImplementationVersion != request.Lease.ImplementationVersion || request.Outcome == StageOutcomeSucceeded && (result.EffectDigest != request.EffectDigest || result.ResultReference != request.ResultReference || result.ResultVersionID != request.ResultVersionID || result.ResultDigest != request.ResultDigest) {
		return StageFinishResult{}, ErrProductionPipelineUnknown
	}
	return result, nil
}

func validProductionPipelineRepository(repository *PostgresProductionPipelineRepository, ctx context.Context) bool {
	if repository == nil || nilProductionDatabase(repository.database) || ctx == nil || ctx.Err() != nil || repository.clock == nil {
		return false
	}
	stage, ok := stageForProductionAuthority(repository.authority)
	return ok && stage == repository.stage
}

func stageForProductionAuthority(authority ProductionPipelineAuthority) (RuntimeStage, bool) {
	switch authority {
	case ProductionPipelineAuthorityCoordinator:
		return RuntimeStageComplete, true
	case ProductionPipelineAuthorityArchive:
		return RuntimeStageArchive, true
	case ProductionPipelineAuthorityIndex:
		return RuntimeStageIndex, true
	case ProductionPipelineAuthorityCorrelation:
		return RuntimeStageCorrelate, true
	case ProductionPipelineAuthorityProjection:
		return RuntimeStageProject, true
	default:
		return "", false
	}
}

func validDeliveryClaimRequest(request DeliveryClaimRequest) bool {
	return request.Scope.Validate() == nil && !request.BatchID.IsZero() && request.Generation > 0 && productionMessageKeyPattern.MatchString(request.MessageID) && request.MessageDigest != [sha256.Size]byte{} && request.ReceiveCount >= 1 && request.ReceiveCount <= 100 && validWorkerLease(request.WorkerID, request.LeaseToken) && request.LeaseSeconds >= 5 && request.LeaseSeconds <= 900 && request.VisibilitySeconds >= request.LeaseSeconds && request.VisibilitySeconds <= 43_200
}

func validWorkerLease(worker, token string) bool {
	return productionWorkerPattern.MatchString(worker) && productionLeaseTokenPattern.MatchString(token)
}

func validDeliveryOutcome(outcome DeliveryOutcome, errorClass string) bool {
	return outcome == DeliveryOutcomeRetryable && errorClass == "retryable" || outcome == DeliveryOutcomeUnknown && errorClass == "outcome_unknown" || outcome == DeliveryOutcomeQuarantined && (errorClass == "denied" || errorClass == "malformed")
}

func validStageLease(lease StageLease, expected RuntimeStage, now time.Time) bool {
	if lease.Scope.Validate() != nil || lease.BatchID.IsZero() || lease.Generation < 1 || lease.Stage != expected || lease.Attempt < 1 || lease.Attempt > 100 || !validProductionText(lease.ImplementationVersion, 64) || lease.InputDigest == [sha256.Size]byte{} || !lease.LeaseExpiresAt.After(now) {
		return false
	}
	return lease.PredecessorDigest == nil || *lease.PredecessorDigest != [sha256.Size]byte{}
}

func validStageFinishRequest(request StageFinishRequest, expected RuntimeStage, now time.Time) bool {
	if !validStageLease(request.Lease, expected, now) || !validWorkerLease(request.WorkerID, request.LeaseToken) {
		return false
	}
	switch request.Outcome {
	case StageOutcomeSucceeded:
		return request.EffectDigest != [sha256.Size]byte{} && request.ResultDigest != [sha256.Size]byte{} && validProductionText(request.ResultReference, 1024) && validProductionText(request.ResultVersionID, 1024) && request.ErrorClass == "" && request.RetryAfter == 0
	case StageOutcomeRetryable:
		return request.EffectDigest == [sha256.Size]byte{} && request.ResultDigest == [sha256.Size]byte{} && request.ResultReference == "" && request.ResultVersionID == "" && request.ErrorClass == "retryable" && request.RetryAfter >= time.Second && request.RetryAfter <= time.Hour && request.RetryAfter%time.Second == 0
	case StageOutcomeFailed:
		return noStageResult(request) && (request.ErrorClass == "denied" || request.ErrorClass == "malformed" || request.ErrorClass == "exhausted")
	case StageOutcomeUnknown:
		return noStageResult(request) && request.ErrorClass == "outcome_unknown"
	case StageOutcomeQuarantined:
		return noStageResult(request) && (request.ErrorClass == "denied" || request.ErrorClass == "malformed")
	default:
		return false
	}
}

func noStageResult(request StageFinishRequest) bool {
	return request.EffectDigest == [sha256.Size]byte{} && request.ResultDigest == [sha256.Size]byte{} && request.ResultReference == "" && request.ResultVersionID == "" && request.RetryAfter == 0
}

func validProductionText(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && strings.TrimSpace(value) == value && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func scopeArguments(scope domain.Scope, batchID domain.ProductID, trailing ...any) []any {
	result := []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), batchID.String()}
	return append(result, trailing...)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type deliveryClaimWire struct {
	BatchID            string     `json:"batch_id"`
	Generation         int64      `json:"generation"`
	Disposition        string     `json:"disposition"`
	Replayed           bool       `json:"replayed"`
	LeaseExpiresAt     *time.Time `json:"lease_expires_at,omitempty"`
	VisibilityDeadline *time.Time `json:"visibility_deadline,omitempty"`
	ArtifactReference  *string    `json:"artifact_reference,omitempty"`
	ArtifactKey        *string    `json:"artifact_key,omitempty"`
	ArtifactVersionID  *string    `json:"artifact_version_id,omitempty"`
	ArtifactChecksum   *string    `json:"artifact_checksum,omitempty"`
	ArtifactSize       *int64     `json:"artifact_size_bytes,omitempty"`
	ArtifactKMSKey     *string    `json:"artifact_kms_key,omitempty"`
	RequestDigest      *string    `json:"request_digest,omitempty"`
}

func decodeDeliveryClaim(payload json.RawMessage, request DeliveryClaimRequest, now time.Time) (DeliveryClaim, error) {
	var wire deliveryClaimWire
	if strictProductionJSON(payload, &wire) != nil || wire.BatchID != request.BatchID.String() || wire.Generation != request.Generation {
		return DeliveryClaim{}, ErrProductionPipeline
	}
	result := DeliveryClaim{Scope: request.Scope, BatchID: request.BatchID, Generation: request.Generation, Disposition: DeliveryDisposition(wire.Disposition), Replayed: wire.Replayed}
	switch result.Disposition {
	case DeliveryDispositionClaimed, DeliveryDispositionAckPending:
		if wire.LeaseExpiresAt == nil || wire.VisibilityDeadline == nil || !wire.LeaseExpiresAt.After(now) || !wire.VisibilityDeadline.After(now) || wire.VisibilityDeadline.Before(*wire.LeaseExpiresAt) || wire.ArtifactReference == nil || wire.ArtifactKey == nil || wire.ArtifactVersionID == nil || wire.ArtifactChecksum == nil || wire.ArtifactSize == nil || wire.ArtifactKMSKey == nil || wire.RequestDigest == nil {
			return DeliveryClaim{}, ErrProductionPipeline
		}
		artifactDigest, digestOK := decodeProductionDigest(*wire.ArtifactChecksum)
		requestDigest, requestOK := decodeProductionDigest(*wire.RequestDigest)
		artifact := RawArtifact{Scope: request.Scope, Reference: *wire.ArtifactReference, Key: *wire.ArtifactKey, VersionID: *wire.ArtifactVersionID, ContentDigest: artifactDigest, Size: *wire.ArtifactSize, MediaType: "application/json", KMSKeyARN: *wire.ArtifactKMSKey}
		if !digestOK || !requestOK || !validPipelineArtifact(artifact) {
			return DeliveryClaim{}, ErrProductionPipeline
		}
		result.LeaseExpiresAt, result.VisibilityDeadline, result.Artifact, result.RequestDigest = wire.LeaseExpiresAt.UTC(), wire.VisibilityDeadline.UTC(), artifact, requestDigest
	case DeliveryDispositionBusy:
		if wire.LeaseExpiresAt != nil {
			result.LeaseExpiresAt = wire.LeaseExpiresAt.UTC()
		}
	case DeliveryDispositionAckTerminal, DeliveryDispositionUnknown, DeliveryDispositionQuarantined:
	default:
		return DeliveryClaim{}, ErrProductionPipeline
	}
	return result, nil
}

func validPipelineArtifact(artifact RawArtifact) bool {
	return artifact.Scope.Validate() == nil && validProductionText(artifact.Reference, 2048) && strings.HasPrefix(artifact.Reference, "s3://") && validProductionText(artifact.Key, 1024) && strings.HasSuffix(artifact.Reference, "/"+artifact.Key) && validProductionText(artifact.VersionID, 1024) && artifact.ContentDigest != [sha256.Size]byte{} && artifact.Size >= 1 && artifact.Size <= 64<<20 && productionKMSKeyPattern.MatchString(artifact.KMSKeyARN)
}

type deliveryLeaseWire struct {
	BatchID            string    `json:"batch_id"`
	Generation         int64     `json:"generation"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
	VisibilityDeadline time.Time `json:"visibility_deadline"`
}

func (wire deliveryLeaseWire) result(batchID domain.ProductID, generation int64, now time.Time) (DeliveryLeaseResult, bool) {
	result := DeliveryLeaseResult{BatchID: batchID, Generation: generation, LeaseExpiresAt: wire.LeaseExpiresAt.UTC(), VisibilityDeadline: wire.VisibilityDeadline.UTC()}
	return result, wire.BatchID == batchID.String() && wire.Generation == generation && wire.LeaseExpiresAt.After(now) && wire.VisibilityDeadline.After(now) && !wire.VisibilityDeadline.Before(wire.LeaseExpiresAt)
}

func decodeDeliveryTransition(payload json.RawMessage, batchID domain.ProductID, generation int64) (DeliveryTransitionResult, bool) {
	var wire struct {
		BatchID     string `json:"batch_id"`
		Generation  int64  `json:"generation"`
		Disposition string `json:"disposition"`
		ErrorClass  string `json:"error_class,omitempty"`
		Replayed    bool   `json:"replayed,omitempty"`
	}
	if strictProductionJSON(payload, &wire) != nil || wire.BatchID != batchID.String() || wire.Generation != generation {
		return DeliveryTransitionResult{}, false
	}
	result := DeliveryTransitionResult{BatchID: batchID, Generation: generation, Disposition: DeliveryDisposition(wire.Disposition), ErrorClass: wire.ErrorClass, Replayed: wire.Replayed}
	valid := result.Disposition == DeliveryDispositionRetryable && result.ErrorClass == "retryable" || result.Disposition == DeliveryDispositionUnknown && result.ErrorClass == "outcome_unknown" || result.Disposition == DeliveryDispositionQuarantined && (result.ErrorClass == "denied" || result.ErrorClass == "malformed") || result.Disposition == DeliveryDispositionAcked && result.ErrorClass == ""
	return result, valid
}

type stageLeaseWire struct {
	OrganizationID        string    `json:"organization_id"`
	WorkspaceID           string    `json:"workspace_id"`
	EnvironmentID         string    `json:"environment_id"`
	BatchID               string    `json:"batch_id"`
	Generation            int64     `json:"generation"`
	Stage                 string    `json:"stage"`
	Attempt               int       `json:"attempt"`
	ImplementationVersion string    `json:"implementation_version"`
	PredecessorDigest     *string   `json:"predecessor_digest"`
	InputDigest           string    `json:"input_digest"`
	LeaseExpiresAt        time.Time `json:"lease_expires_at"`
}

func (wire stageLeaseWire) result(expected RuntimeStage) (StageLease, bool) {
	scope, batchID, ok := parsePipelineScope(wire.OrganizationID, wire.WorkspaceID, wire.EnvironmentID, wire.BatchID)
	inputDigest, inputOK := decodeProductionDigest(wire.InputDigest)
	result := StageLease{Scope: scope, BatchID: batchID, Generation: wire.Generation, Stage: RuntimeStage(wire.Stage), Attempt: wire.Attempt, ImplementationVersion: wire.ImplementationVersion, InputDigest: inputDigest, LeaseExpiresAt: wire.LeaseExpiresAt.UTC()}
	if wire.PredecessorDigest != nil {
		predecessor, predecessorOK := decodeProductionDigest(*wire.PredecessorDigest)
		if !predecessorOK {
			return StageLease{}, false
		}
		result.PredecessorDigest = &predecessor
	}
	return result, ok && inputOK && result.Stage == expected
}

func decodeStageFinish(payload json.RawMessage) (StageFinishResult, bool) {
	var wire struct {
		BatchID               string  `json:"batch_id"`
		Generation            int64   `json:"generation"`
		Stage                 string  `json:"stage"`
		State                 string  `json:"state"`
		Attempt               int     `json:"attempt"`
		InputDigest           string  `json:"input_digest"`
		ImplementationVersion string  `json:"implementation_version"`
		EffectDigest          *string `json:"effect_digest"`
		ResultReference       *string `json:"result_reference"`
		ResultVersionID       *string `json:"result_version_id"`
		ResultDigest          *string `json:"result_digest"`
		ErrorClass            *string `json:"error_class"`
	}
	if strictProductionJSON(payload, &wire) != nil {
		return StageFinishResult{}, false
	}
	batchID, batchErr := domain.ParseProductID(wire.BatchID)
	input, inputOK := decodeProductionDigest(wire.InputDigest)
	result := StageFinishResult{BatchID: batchID, Generation: wire.Generation, Stage: RuntimeStage(wire.Stage), State: StageOutcome(wire.State), Attempt: wire.Attempt, InputDigest: input, ImplementationVersion: wire.ImplementationVersion}
	if wire.ErrorClass != nil {
		result.ErrorClass = *wire.ErrorClass
	}
	if result.State == StageOutcomeSucceeded {
		if wire.EffectDigest == nil || wire.ResultReference == nil || wire.ResultVersionID == nil || wire.ResultDigest == nil || wire.ErrorClass != nil {
			return StageFinishResult{}, false
		}
		var effectOK, resultOK bool
		result.EffectDigest, effectOK = decodeProductionDigest(*wire.EffectDigest)
		result.ResultDigest, resultOK = decodeProductionDigest(*wire.ResultDigest)
		result.ResultReference, result.ResultVersionID = *wire.ResultReference, *wire.ResultVersionID
		if !effectOK || !resultOK {
			return StageFinishResult{}, false
		}
	} else if wire.EffectDigest != nil || wire.ResultReference != nil || wire.ResultVersionID != nil || wire.ResultDigest != nil || wire.ErrorClass == nil {
		return StageFinishResult{}, false
	}
	return result, batchErr == nil && !batchID.IsZero() && wire.Generation > 0 && inputOK && validProductionText(wire.ImplementationVersion, 64)
}

func parsePipelineScope(organization, workspace, environment, batch string) (domain.Scope, domain.ProductID, bool) {
	organizationID, organizationErr := domain.ParseProductID(organization)
	workspaceID, workspaceErr := domain.ParseProductID(workspace)
	environmentID, environmentErr := domain.ParseProductID(environment)
	batchID, batchErr := domain.ParseProductID(batch)
	scope, scopeErr := domain.NewScope(organizationID, workspaceID, environmentID)
	return scope, batchID, organizationErr == nil && workspaceErr == nil && environmentErr == nil && batchErr == nil && scopeErr == nil && !batchID.IsZero()
}

func decodeProductionDigest(value string) ([sha256.Size]byte, bool) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		clear(decoded)
		return result, false
	}
	copy(result[:], decoded)
	clear(decoded)
	return result, result != [sha256.Size]byte{}
}
