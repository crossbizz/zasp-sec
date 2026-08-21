package runtimeevent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type IngestReconciliationLease struct {
	Scope          domain.Scope
	BatchID        domain.ProductID
	Generation     int64
	Attempt        int
	LeaseExpiresAt time.Time
	RequestDigest  [sha256.Size]byte
	ArtifactKey    string
	ContentDigest  [sha256.Size]byte
	PayloadSize    int64
	MediaType      string
	SchemaVersion  string
}

type ProductionIngestReconciliationRepository interface {
	Ready(context.Context) error
	ClaimReconciliation(context.Context, string, string, int, int) ([]IngestReconciliationLease, error)
	ReleaseReconciliation(context.Context, IngestReconciliationLease, string, string, time.Duration, string) error
	FinishReconciliation(context.Context, IngestReconciliationLease, string, string, domain.ProductID, domain.ProductID, RawArtifact) error
	QuarantineReconciliation(context.Context, IngestReconciliationLease, string, string) error
}

type ProductionIngestReconcilerConfig struct {
	Repository       ProductionIngestReconciliationRepository
	Artifacts        RawArtifactInspector
	WorkerID         string
	LeaseSeconds     int
	ClaimLimit       int
	OperationTimeout time.Duration
	NewLeaseToken    func() (string, error)
}

type ProductionIngestReconciler struct {
	config ProductionIngestReconcilerConfig
}

func NewProductionIngestReconciler(config ProductionIngestReconcilerConfig) (*ProductionIngestReconciler, error) {
	if nilProductionIngestValue(config.Repository) || nilProductionIngestValue(config.Artifacts) || !productionWorkerPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 60 || config.LeaseSeconds > 300 || config.ClaimLimit < 1 || config.ClaimLimit > 10 || config.OperationTimeout <= 0 || config.OperationTimeout > 30*time.Second || config.NewLeaseToken == nil {
		return nil, ErrProductionIngest
	}
	return &ProductionIngestReconciler{config: config}, nil
}

func (reconciler *ProductionIngestReconciler) RunOnce(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrProductionIngestUnavailable
		}
	}()
	if reconciler == nil || ctx == nil || ctx.Err() != nil {
		return ErrProductionIngestUnavailable
	}
	if err := reconciler.config.Repository.Ready(ctx); err != nil {
		return ErrProductionIngestUnavailable
	}
	token, err := reconciler.config.NewLeaseToken()
	if err != nil || !productionLeaseTokenPattern.MatchString(token) {
		return ErrProductionIngestUnavailable
	}
	leasing, err := reconciler.config.Repository.ClaimReconciliation(ctx, reconciler.config.WorkerID, token, reconciler.config.LeaseSeconds, reconciler.config.ClaimLimit)
	if err != nil {
		return ErrProductionIngestUnavailable
	}
	for _, lease := range leasing {
		if !validIngestReconciliationLease(lease) {
			return ErrProductionIngestUnavailable
		}
		if err := reconciler.process(ctx, lease, token); err != nil {
			return err
		}
	}
	return nil
}

func (reconciler *ProductionIngestReconciler) process(ctx context.Context, lease IngestReconciliationLease, token string) error {
	operation, cancel := context.WithTimeout(ctx, reconciler.config.OperationTimeout)
	defer cancel()
	artifact, err := reconciler.config.Artifacts.Inspect(operation, RawArtifactInspect{Scope: lease.Scope, Key: lease.ArtifactKey, ContentDigest: lease.ContentDigest, Size: lease.PayloadSize, MediaType: lease.MediaType})
	switch {
	case err == nil:
		if !validRawArtifact(artifact, lease.Scope, lease.ArtifactKey, lease.ContentDigest, lease.PayloadSize) {
			return reconciler.quarantine(operation, lease, token)
		}
		jobID, jobErr := reconciliationID(lease, "job")
		outboxID, outboxErr := reconciliationID(lease, "outbox")
		if jobErr != nil || outboxErr != nil || reconciler.config.Repository.FinishReconciliation(operation, lease, reconciler.config.WorkerID, token, jobID, outboxID, artifact) != nil {
			return ErrProductionIngestUnavailable
		}
		return nil
	case errors.Is(err, ErrProductionIngestArtifactDrift):
		return reconciler.quarantine(operation, lease, token)
	case errors.Is(err, ErrProductionIngestArtifactNotFound):
		if reconciler.config.Repository.ReleaseReconciliation(operation, lease, reconciler.config.WorkerID, token, 30*time.Second, "not_found") != nil {
			return ErrProductionIngestUnavailable
		}
		return nil
	default:
		if reconciler.config.Repository.ReleaseReconciliation(operation, lease, reconciler.config.WorkerID, token, 30*time.Second, "dependency_unavailable") != nil {
			return ErrProductionIngestUnavailable
		}
		return nil
	}
}

func (reconciler *ProductionIngestReconciler) quarantine(ctx context.Context, lease IngestReconciliationLease, token string) error {
	if reconciler.config.Repository.QuarantineReconciliation(ctx, lease, reconciler.config.WorkerID, token) != nil {
		return ErrProductionIngestUnavailable
	}
	return nil
}

func reconciliationID(lease IngestReconciliationLease, kind string) (domain.ProductID, error) {
	return deterministicID(scopeIdentity(lease.Scope) + "\x00" + lease.BatchID.String() + "\x00" + fmt.Sprint(lease.Generation) + "\x00reconciliation\x00" + kind)
}

func validIngestReconciliationLease(value IngestReconciliationLease) bool {
	return value.Scope.Validate() == nil && !value.BatchID.IsZero() && value.Generation > 0 && value.Attempt >= 1 && value.Attempt <= 100 && !value.LeaseExpiresAt.IsZero() && value.LeaseExpiresAt.Location() == time.UTC && value.RequestDigest != [sha256.Size]byte{} && len(value.ArtifactKey) >= 32 && len(value.ArtifactKey) <= 1024 && strings.HasPrefix(value.ArtifactKey, "runtime/v15/"+value.Scope.OrganizationID().String()+"/"+value.Scope.WorkspaceID().String()+"/"+value.Scope.EnvironmentID().String()+"/") && !strings.Contains(value.ArtifactKey, "..") && value.ContentDigest != [sha256.Size]byte{} && value.PayloadSize >= 1 && value.PayloadSize <= maximumProductionIngestBytes && value.MediaType == "application/json" && value.SchemaVersion == productionRuntimeSchema
}

var _ interface{ RunOnce(context.Context) error } = (*ProductionIngestReconciler)(nil)
