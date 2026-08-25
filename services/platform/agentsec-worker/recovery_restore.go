package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/recovery"
)

var (
	errRecoverySignatureInvalid      = errors.New("recovery signature invalid")
	errRecoveryManifestInvalid       = errors.New("recovery manifest invalid")
	errRecoveryManifestExpired       = errors.New("recovery manifest expired")
	recoveryEvidenceReferencePattern = regexp.MustCompile(`^s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/([A-Za-z0-9][A-Za-z0-9._/-]*)$`)
	recoveryEvidenceVersionPattern   = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

type recoveryManifestLoader interface {
	Load(context.Context, recoveryOperationClaim) (recoveryLoadedManifest, error)
}

type recoveryLoadedManifest struct {
	Manifest             recovery.Manifest
	EvidenceSampleDigest [sha256.Size]byte
}

type recoveryRestoreProvisionRequest struct {
	Scope                recoveryOperationClaim
	TargetEnvironment    string
	Manifest             recovery.Manifest
	EvidenceSampleDigest [sha256.Size]byte
}

type recoveryRestoreTarget struct {
	BranchID     string
	BranchName   string
	Namespace    string
	NamespaceUID string
	ScopeDigest  string
	plan         recoveryKubernetesPlan
}

type recoveryRestoreInfrastructure interface {
	Ready(context.Context) error
	Provision(context.Context, recoveryRestoreProvisionRequest) (recoveryRestoreTarget, error)
	Validate(context.Context, recoveryRestoreTarget, recovery.Manifest) (apiserver.RecoveryCounts, apiserver.RecoveryArtifactLocator, error)
	Rebuild(context.Context, recoveryRestoreTarget, recovery.Manifest) ([sha256.Size]byte, error)
	Cleanup(context.Context, recoveryRestoreTarget) (apiserver.RecoveryCleanupEvidence, error)
}

type recoveryRestoreProcessorConfig struct {
	Authority         recoveryOperationAuthority
	Loader            recoveryManifestLoader
	Infrastructure    recoveryRestoreInfrastructure
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	NewLeaseToken     func() (string, error)
}

type recoveryRestoreProcessor struct {
	config recoveryRestoreProcessorConfig
}

func newRecoveryRestoreProcessor(config recoveryRestoreProcessorConfig) (*recoveryRestoreProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	if config.Authority == nil || config.Loader == nil || config.Infrastructure == nil || config.NewLeaseToken == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 25 || config.HeartbeatInterval < time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 {
		return nil, errWorkerExecution
	}
	return &recoveryRestoreProcessor{config: config}, nil
}

func (processor *recoveryRestoreProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Authority.Ready(ctx) != nil {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	claims, err := processor.config.Authority.Claim(ctx, "restore", processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(claims) > processor.config.BatchSize {
		return errWorkerExecution
	}
	results := make(chan error, len(claims))
	for _, claim := range claims {
		claim := claim
		go func() { results <- processor.process(ctx, token, claim) }()
	}
	failed := false
	for range claims {
		if <-results != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *recoveryRestoreProcessor) process(ctx context.Context, token string, claim recoveryOperationClaim) error {
	if !validRecoveryOperationClaim(claim) || claim.Kind != "restore" {
		return errWorkerExecution
	}
	lease := recoveryOperationLease{recoveryOperationClaim: claim, WorkerID: processor.config.WorkerID, LeaseToken: token}
	if processor.config.Authority.Heartbeat(ctx, lease, processor.config.LeaseSeconds) != nil {
		return errWorkerExecution
	}
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	var leaseLost atomic.Bool
	heartbeatDone := make(chan struct{})
	go processor.keepLease(workCtx, lease, cancelWork, &leaseLost, heartbeatDone)

	loaded, err := processor.config.Loader.Load(workCtx, claim)
	if err != nil {
		return processor.stopAndRecordFailure(ctx, cancelWork, heartbeatDone, &leaseLost, lease, recoveryManifestFailureCode(err), nil)
	}
	manifest := loaded.Manifest
	if !validLoadedRecoveryManifest(manifest, claim.Scope) || loaded.EvidenceSampleDigest == ([sha256.Size]byte{}) {
		return processor.stopAndRecordFailure(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "manifest_invalid", nil)
	}
	if processor.config.Authority.CheckpointRestore(workCtx, lease, "verifying", "provisioning", map[string]string{"state": "verified"}) != nil {
		return processor.stopAndRecordFailure(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "lease_lost", nil)
	}

	target, err := processor.config.Infrastructure.Provision(workCtx, recoveryRestoreProvisionRequest{Scope: claim, TargetEnvironment: claim.TargetEnvironment, Manifest: manifest, EvidenceSampleDigest: loaded.EvidenceSampleDigest})
	if err != nil || !validRecoveryRestoreTarget(target, claim) {
		if validStartedRecoveryRestoreTarget(target, claim) {
			return processor.cleanupAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, target, "outcome_unknown")
		}
		return processor.stopAndRecordFailure(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "outcome_unknown", nil)
	}
	if processor.config.Authority.CheckpointRestore(workCtx, lease, "provisioning", "validating", map[string]string{"state": "provisioned"}) != nil {
		return processor.cleanupAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, target, "lease_lost")
	}

	observed, evidence, err := processor.config.Infrastructure.Validate(workCtx, target, manifest)
	expected := recoveryManifestCounts(manifest)
	if err != nil || !validRecoveryCounts(observed) || observed != expected || !validRecoveryEvidenceLocator(evidence, claim.Scope, "recovery_validation_v1") {
		return processor.cleanupAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, target, "validation_failed")
	}
	validation := apiserver.RecoveryValidationEvidence{State: "validated", ExpectedCounts: expected, ObservedCounts: observed, Evidence: evidence}
	if processor.config.Authority.CheckpointRestore(workCtx, lease, "validating", "rebuilding", validation) != nil {
		return processor.cleanupAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, target, "lease_lost")
	}

	projectionDigest, err := processor.config.Infrastructure.Rebuild(workCtx, target, manifest)
	if err != nil || projectionDigest == ([sha256.Size]byte{}) || projectionDigest != manifest.Projection.SHA256 {
		return processor.cleanupAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, target, "projection_mismatch")
	}
	if processor.config.Authority.CheckpointRestore(workCtx, lease, "rebuilding", "cleanup_required", map[string]string{"state": "rebuilt"}) != nil || processor.config.Authority.CheckpointRestore(workCtx, lease, "cleanup_required", "cleaning", map[string]string{"state": "cleanup_started"}) != nil {
		return processor.cleanupAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, target, "lease_lost")
	}

	cleanup, cleanupErr := processor.cleanup(ctx, target, claim)
	if cleanupErr != nil || cleanup.State != "deleted" {
		return processor.stopAndRecordFailure(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "cleanup_failed", &cleanup)
	}
	finalizeCtx, cancelFinalize := context.WithTimeout(workCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancelFinalize()
	if leaseLost.Load() || processor.config.Authority.FinishRestore(finalizeCtx, lease, observed, validation, cleanup) != nil {
		cancelWork()
		<-heartbeatDone
		return errWorkerExecution
	}
	cancelWork()
	<-heartbeatDone
	return nil
}

func (processor *recoveryRestoreProcessor) cleanupAndFail(ctx context.Context, cancelWork context.CancelFunc, heartbeatDone <-chan struct{}, leaseLost *atomic.Bool, lease recoveryOperationLease, target recoveryRestoreTarget, code string) error {
	cleanup, err := processor.cleanup(ctx, target, lease.recoveryOperationClaim)
	if err != nil || cleanup.State != "deleted" {
		code = "cleanup_failed"
	}
	return processor.stopAndRecordFailure(ctx, cancelWork, heartbeatDone, leaseLost, lease, code, &cleanup)
}

func (processor *recoveryRestoreProcessor) cleanup(ctx context.Context, target recoveryRestoreTarget, claim recoveryOperationClaim) (apiserver.RecoveryCleanupEvidence, error) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancel()
	cleanup, err := processor.config.Infrastructure.Cleanup(cleanupCtx, target)
	if !validRecoveryEvidenceLocator(cleanup.Evidence, claim.Scope, "recovery_cleanup_v1") || !stringInWorker(cleanup.State, "deleted", "failed") {
		return cleanup, errWorkerExecution
	}
	return cleanup, err
}

func (processor *recoveryRestoreProcessor) stopAndRecordFailure(ctx context.Context, cancelWork context.CancelFunc, heartbeatDone <-chan struct{}, leaseLost *atomic.Bool, lease recoveryOperationLease, code string, cleanup *apiserver.RecoveryCleanupEvidence) error {
	cancelWork()
	<-heartbeatDone
	if leaseLost.Load() {
		return errWorkerExecution
	}
	failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancel()
	if processor.config.Authority.Fail(failureCtx, lease, code, 30*time.Second, cleanup) != nil {
		return errWorkerExecution
	}
	return errWorkerExecution
}

func (processor *recoveryRestoreProcessor) keepLease(ctx context.Context, lease recoveryOperationLease, cancelWork context.CancelFunc, leaseLost *atomic.Bool, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewCtx, cancel := context.WithTimeout(ctx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
			err := processor.config.Authority.Heartbeat(renewCtx, lease, processor.config.LeaseSeconds)
			cancel()
			if err != nil {
				leaseLost.Store(true)
				cancelWork()
				return
			}
		}
	}
}

func recoveryManifestFailureCode(err error) string {
	switch {
	case errors.Is(err, errRecoverySignatureInvalid):
		return "signature_invalid"
	case errors.Is(err, errRecoveryManifestExpired):
		return "manifest_expired"
	default:
		return "manifest_invalid"
	}
}

func validLoadedRecoveryManifest(manifest recovery.Manifest, scope domain.Scope) bool {
	if scope.Validate() != nil || manifest.Scope.Validate() != nil || manifest.Scope != scope {
		return false
	}
	_, _, err := recovery.BuildManifest(recovery.ManifestInput{Scope: manifest.Scope, BackupID: manifest.BackupID, CapturedAt: manifest.CapturedAt, ExpiresAt: manifest.ExpiresAt, NeonProjectID: manifest.NeonProjectID, NeonBranchID: manifest.NeonBranchID, PostgresLSN: manifest.PostgresLSN, Configuration: manifest.Configuration, Projection: manifest.Projection, Evidence: manifest.Evidence, ExpectedCounts: manifest.ExpectedCounts})
	return err == nil
}

func recoveryManifestCounts(manifest recovery.Manifest) apiserver.RecoveryCounts {
	return apiserver.RecoveryCounts{Assets: manifest.ExpectedCounts["assets"], Findings: manifest.ExpectedCounts["findings"], Policies: manifest.ExpectedCounts["policies"]}
}

func validRecoveryCounts(counts apiserver.RecoveryCounts) bool {
	return counts.Assets <= 1_000_000_000 && counts.Findings <= 1_000_000_000 && counts.Policies <= 1_000_000_000
}

func validStartedRecoveryRestoreTarget(target recoveryRestoreTarget, claim recoveryOperationClaim) bool {
	return target.BranchID != "" || target.Namespace != "" || target.NamespaceUID != "" || target.ScopeDigest != ""
}

func validRecoveryRestoreTarget(target recoveryRestoreTarget, claim recoveryOperationClaim) bool {
	suffix := strings.TrimPrefix(claim.OperationID, "pid_")
	suffix = strings.ReplaceAll(suffix, "-", "")
	if len(suffix) != 32 {
		return false
	}
	wantNamespace := "zasp-recovery-" + suffix
	return strings.HasPrefix(target.BranchID, "br-") && target.Namespace == wantNamespace && len(target.NamespaceUID) >= 8 && len(target.NamespaceUID) <= 64 && len(target.ScopeDigest) == 16
}

func validRecoveryEvidenceLocator(value apiserver.RecoveryArtifactLocator, scope domain.Scope, schema string) bool {
	if scope.Validate() != nil || value.Schema != schema || value.MediaType != "application/json" || value.SizeBytes < 1 || value.SizeBytes > 64<<20 || len(value.SHA256) != 64 || len(value.VersionID) < 1 || len(value.VersionID) > 1024 {
		return false
	}
	digest, digestErr := hex.DecodeString(value.SHA256)
	parts := recoveryEvidenceReferencePattern.FindStringSubmatch(value.Reference)
	if digestErr != nil || len(digest) != sha256.Size || bytes.Equal(digest, make([]byte, sha256.Size)) || !recoveryEvidenceVersionPattern.MatchString(value.VersionID) || len(parts) != 3 || strings.Contains(parts[1], "..") || strings.Contains(parts[1], ".-") || strings.Contains(parts[1], "-.") {
		return false
	}
	wantPrefix := "organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/"
	if !strings.HasPrefix(parts[2], wantPrefix) {
		return false
	}
	identifier := strings.TrimPrefix(parts[2], wantPrefix)
	if strings.Contains(identifier, "/") {
		return false
	}
	productID, err := domain.ParseProductID(identifier)
	return err == nil && productID.String() == identifier
}

var _ workerProcessor = (*recoveryRestoreProcessor)(nil)
