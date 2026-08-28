package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const (
	recoveryMaximumCapturedPages = 4096
	recoveryMaximumCapturedBytes = 64 << 20
)

type recoveryOperationClaim struct {
	Kind              string
	Scope             domain.Scope
	OperationID       string
	Attempt           int
	RetentionDays     int
	TargetEnvironment string
	Manifest          *apiserver.RecoveryManifestLocator
	CreatedAt         time.Time
	CleanupOnly       bool
}

type recoveryDeliveryClaim struct {
	Disposition string
	Operation   recoveryOperationClaim
}

type recoveryOperationLease struct {
	recoveryOperationClaim
	WorkerID   string
	LeaseToken string
}

type recoveryCapturePage struct {
	Section    string            `json:"section"`
	Items      []json.RawMessage `json:"items"`
	NextCursor *string           `json:"next_cursor"`
}

type recoveryBackupPublication struct {
	Claim    recoveryOperationClaim
	Sections map[string][]json.RawMessage
}

type recoveryOperationAuthority interface {
	Ready(context.Context) error
	Claim(context.Context, string, string, string, int, int) ([]recoveryOperationClaim, error)
	Heartbeat(context.Context, recoveryOperationLease, int) error
	BeginHold(context.Context, recoveryOperationLease) error
	ReleaseHold(context.Context, recoveryOperationLease) error
	CapturePage(context.Context, recoveryOperationLease, string, *string, int) (recoveryCapturePage, error)
	FinishBackup(context.Context, recoveryOperationLease, apiserver.RecoveryManifestLocator) error
	CheckpointRestore(context.Context, recoveryOperationLease, string, string, any) error
	FinishRestore(context.Context, recoveryOperationLease, apiserver.RecoveryCounts, apiserver.RecoveryValidationEvidence, apiserver.RecoveryCleanupEvidence) error
	Fail(context.Context, recoveryOperationLease, string, time.Duration, *apiserver.RecoveryCleanupEvidence) error
}

type recoveryDeliveryAuthority interface {
	ClaimDelivery(context.Context, string, domain.Scope, string, string, string, int) (recoveryDeliveryClaim, error)
}

type recoveryBackupPublisher interface {
	Publish(context.Context, recoveryBackupPublication) (apiserver.RecoveryManifestLocator, error)
}

type recoveryBackupProcessorConfig struct {
	Authority         recoveryOperationAuthority
	Queue             discoveryQueue
	Publisher         recoveryBackupPublisher
	Metrics           *recoveryMetrics
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	PageSize          int
	NewLeaseToken     func() (string, error)
	Now               func() time.Time
}

type recoveryBackupProcessor struct{ config recoveryBackupProcessorConfig }

func newRecoveryBackupProcessor(config recoveryBackupProcessorConfig) (*recoveryBackupProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	_, extendsVisibility := config.Queue.(jobqueue.VisibilityExtender)
	_, claimsDeliveries := config.Authority.(recoveryDeliveryAuthority)
	if config.Authority == nil || config.Publisher == nil || config.NewLeaseToken == nil || config.Queue != nil && (!extendsVisibility || !claimsDeliveries) || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 25 || config.PageSize < 1 || config.PageSize > 100 || config.HeartbeatInterval < time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 {
		return nil, errWorkerExecution
	}
	return &recoveryBackupProcessor{config: config}, nil
}

func (processor *recoveryBackupProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Authority.Ready(ctx) != nil {
		return errWorkerExecution
	}
	if processor.config.Queue != nil {
		return processor.runDeliveries(ctx)
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	claims, err := processor.config.Authority.Claim(ctx, "backup", processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(claims) > processor.config.BatchSize {
		return errWorkerExecution
	}
	results := make(chan error, len(claims))
	for _, claim := range claims {
		claim := claim
		go func() { results <- processor.process(ctx, token, claim, nil) }()
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

func (processor *recoveryBackupProcessor) runDeliveries(ctx context.Context) error {
	deliveries, err := processor.config.Queue.ConsumeBatch(ctx, processor.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	if len(deliveries) == 0 {
		processor.config.Metrics.observeEmptyClaim()
		return nil
	}
	results := make(chan error, len(deliveries))
	for _, delivery := range deliveries {
		delivery := delivery
		go func() { results <- processor.runDelivery(ctx, delivery) }()
	}
	failed := false
	for range deliveries {
		if <-results != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *recoveryBackupProcessor) runDelivery(ctx context.Context, delivery jobqueue.Delivery) error {
	if !validRecoveryDelivery(delivery, "backup") {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	claim, err := processor.config.Authority.(recoveryDeliveryAuthority).ClaimDelivery(ctx, "backup", delivery.Job.Scope, delivery.Job.JobID.String(), processor.config.WorkerID, token, processor.config.LeaseSeconds)
	if err != nil {
		return errWorkerExecution
	}
	switch claim.Disposition {
	case "retry_later":
		return nil
	case "ack_terminal":
		return processor.acknowledge(ctx, delivery.Receipt)
	case "exhausted":
		processor.config.Metrics.observeExhaustion()
		return processor.acknowledge(ctx, delivery.Receipt)
	case "claimed":
		if claim.Operation.Kind != "backup" || claim.Operation.Scope != delivery.Job.Scope || claim.Operation.OperationID != delivery.Job.JobID.String() {
			return errWorkerExecution
		}
		processor.config.Metrics.observeClaim(claim.Operation, processor.config.Now().UTC())
		if processor.process(ctx, token, claim.Operation, &delivery.Receipt) != nil {
			return errWorkerExecution
		}
		return processor.acknowledge(ctx, delivery.Receipt)
	default:
		return errWorkerExecution
	}
}

func (processor *recoveryBackupProcessor) acknowledge(ctx context.Context, receipt jobqueue.Receipt) error {
	ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancel()
	if processor.config.Queue.AcknowledgeBatch(ackCtx, []jobqueue.Receipt{receipt}) != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *recoveryBackupProcessor) process(ctx context.Context, token string, claim recoveryOperationClaim, receipt *jobqueue.Receipt) error {
	if !validRecoveryOperationClaim(claim) || claim.Kind != "backup" {
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
	go processor.keepLease(workCtx, lease, receipt, cancelWork, &leaseLost, heartbeatDone)
	if processor.config.Authority.BeginHold(workCtx, lease) != nil {
		return processor.stopAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "outcome_unknown")
	}
	processor.config.Metrics.beginHold(processor.config.Now().UTC())
	sections := make(map[string][]json.RawMessage, 4)
	totalBytes := 0
	for _, section := range []string{"configuration", "projection", "evidence", "counts"} {
		items, err := processor.captureSection(workCtx, lease, section)
		if err != nil {
			return processor.stopReleaseAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "outcome_unknown")
		}
		for _, item := range items {
			totalBytes += len(item)
		}
		if totalBytes > recoveryMaximumCapturedBytes {
			return processor.stopReleaseAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "outcome_unknown")
		}
		sections[section] = items
	}
	manifest, err := callRecoveryPublisher(processor.config.Publisher, workCtx, recoveryBackupPublication{Claim: claim, Sections: sections})
	if err != nil || !validPublishedRecoveryManifest(manifest, claim.Scope) {
		return processor.stopReleaseAndFail(ctx, cancelWork, heartbeatDone, &leaseLost, lease, "outcome_unknown")
	}
	finalizeCtx, cancelFinalize := context.WithTimeout(workCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancelFinalize()
	if leaseLost.Load() || processor.config.Authority.FinishBackup(finalizeCtx, lease, manifest) != nil {
		cancelWork()
		<-heartbeatDone
		return errWorkerExecution
	}
	processor.config.Metrics.endHold()
	cancelWork()
	<-heartbeatDone
	return nil
}

func (processor *recoveryBackupProcessor) captureSection(ctx context.Context, lease recoveryOperationLease, section string) ([]json.RawMessage, error) {
	var after *string
	items := make([]json.RawMessage, 0)
	totalBytes := 0
	seen := make(map[string]struct{})
	limit := processor.config.PageSize
	if section == "counts" {
		limit = 1
	}
	for pageIndex := 0; pageIndex < recoveryMaximumCapturedPages; pageIndex++ {
		page, err := processor.config.Authority.CapturePage(ctx, lease, section, after, limit)
		if err != nil || page.Section != section || len(page.Items) > limit || section == "counts" && (pageIndex != 0 || page.NextCursor != nil || len(page.Items) != 1) {
			return nil, errWorkerExecution
		}
		for _, item := range page.Items {
			if len(item) < 2 || !json.Valid(item) {
				return nil, errWorkerExecution
			}
			totalBytes += len(item)
			if totalBytes > recoveryMaximumCapturedBytes {
				return nil, errWorkerExecution
			}
			items = append(items, append(json.RawMessage(nil), item...))
		}
		if page.NextCursor == nil {
			return items, nil
		}
		if len(*page.NextCursor) == 0 || len(*page.NextCursor) > 256 || strings.TrimSpace(*page.NextCursor) != *page.NextCursor {
			return nil, errWorkerExecution
		}
		if _, duplicate := seen[*page.NextCursor]; duplicate {
			return nil, errWorkerExecution
		}
		seen[*page.NextCursor] = struct{}{}
		cursor := *page.NextCursor
		after = &cursor
	}
	return nil, errWorkerExecution
}

func (processor *recoveryBackupProcessor) keepLease(ctx context.Context, lease recoveryOperationLease, receipt *jobqueue.Receipt, cancelWork context.CancelFunc, leaseLost *atomic.Bool, done chan<- struct{}) {
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
			if err == nil && receipt != nil {
				err = processor.config.Queue.(jobqueue.VisibilityExtender).ExtendVisibility(renewCtx, []jobqueue.Receipt{*receipt}, time.Duration(processor.config.LeaseSeconds)*time.Second)
			}
			cancel()
			if err != nil {
				processor.config.Metrics.observeLeaseLoss()
				leaseLost.Store(true)
				cancelWork()
				return
			}
		}
	}
}

func (processor *recoveryBackupProcessor) stopReleaseAndFail(ctx context.Context, cancelWork context.CancelFunc, heartbeatDone <-chan struct{}, leaseLost *atomic.Bool, lease recoveryOperationLease, code string) error {
	cancelWork()
	<-heartbeatDone
	if leaseLost.Load() {
		return errWorkerExecution
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancel()
	if processor.config.Authority.ReleaseHold(cleanupCtx, lease) != nil || processor.config.Authority.Fail(cleanupCtx, lease, code, 30*time.Second, nil) != nil {
		return errWorkerExecution
	}
	processor.config.Metrics.endHold()
	return errWorkerExecution
}

func (processor *recoveryBackupProcessor) stopAndFail(ctx context.Context, cancelWork context.CancelFunc, heartbeatDone <-chan struct{}, leaseLost *atomic.Bool, lease recoveryOperationLease, code string) error {
	cancelWork()
	<-heartbeatDone
	if leaseLost.Load() {
		return errWorkerExecution
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 30*time.Second))
	defer cancel()
	if processor.config.Authority.Fail(cleanupCtx, lease, code, 30*time.Second, nil) != nil {
		return errWorkerExecution
	}
	return errWorkerExecution
}

func callRecoveryPublisher(publisher recoveryBackupPublisher, ctx context.Context, input recoveryBackupPublication) (manifest apiserver.RecoveryManifestLocator, resultErr error) {
	defer func() {
		if recover() != nil {
			manifest, resultErr = apiserver.RecoveryManifestLocator{}, errWorkerExecution
		}
	}()
	return publisher.Publish(ctx, input)
}

func validRecoveryOperationClaim(claim recoveryOperationClaim) bool {
	operationID, err := domain.ParseProductID(claim.OperationID)
	if claim.Scope.Validate() != nil || err != nil || operationID.IsZero() || claim.Attempt < 1 || claim.Attempt > 100 {
		return false
	}
	if claim.Kind == "backup" {
		return claim.RetentionDays >= 7 && claim.RetentionDays <= 90 && claim.TargetEnvironment == "" && claim.Manifest == nil && !claim.CleanupOnly
	}
	return claim.Kind == "restore" && claim.RetentionDays == 0 && validRecoveryTargetEnvironment(claim.TargetEnvironment, claim.Scope) && claim.Manifest != nil && validPublishedRecoveryManifest(*claim.Manifest, claim.Scope) && (!claim.CleanupOnly || claim.Attempt == 100)
}

func validRecoveryDelivery(delivery jobqueue.Delivery, kind string) bool {
	if delivery.Job.Scope.Validate() != nil || delivery.Job.JobID.IsZero() || !stringInWorker(kind, "backup", "restore") || delivery.Job.Kind != "recovery-"+kind || len(delivery.Job.Payload) < 2 || len(delivery.Job.Payload) > 65536 || sha256.Sum256(delivery.Job.Payload) != delivery.Job.AuthorityDigest {
		return false
	}
	if kind == "backup" {
		var payload recoveryBackupOutboxPayload
		return decodeExactRecoveryOutboxPayload(delivery.Job.Payload, &payload) == nil && payload.BackupID == delivery.Job.JobID.String() && payload.OrganizationID == delivery.Job.Scope.OrganizationID().String() && payload.WorkspaceID == delivery.Job.Scope.WorkspaceID().String() && payload.EnvironmentID == delivery.Job.Scope.EnvironmentID().String()
	}
	var payload recoveryRestoreOutboxPayload
	return decodeExactRecoveryOutboxPayload(delivery.Job.Payload, &payload) == nil && payload.RestoreID == delivery.Job.JobID.String() && payload.OrganizationID == delivery.Job.Scope.OrganizationID().String() && payload.WorkspaceID == delivery.Job.Scope.WorkspaceID().String() && payload.EnvironmentID == delivery.Job.Scope.EnvironmentID().String() && validRecoveryTargetEnvironment(payload.TargetEnvironment, delivery.Job.Scope)
}

func validRecoveryTargetEnvironment(value string, scope domain.Scope) bool {
	if len(value) < 1 || len(value) > 63 || value == "production" || value == scope.EnvironmentID().String() {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' && index > 0 && index < len(value)-1 {
			continue
		}
		return false
	}
	return true
}

func validPublishedRecoveryManifest(manifest apiserver.RecoveryManifestLocator, scope domain.Scope) bool {
	prefix := "s3://"
	scopePath := "/organizations/" + scope.OrganizationID().String() + "/workspaces/" + scope.WorkspaceID().String() + "/environments/" + scope.EnvironmentID().String() + "/artifacts/"
	return strings.HasPrefix(manifest.Reference, prefix) && strings.Contains(manifest.Reference, scopePath) && manifest.VersionID != "" && len(manifest.SHA256) == 64 && manifest.SizeBytes > 0 && manifest.SizeBytes <= 64<<20 && manifest.MediaType == "application/vnd.zasp.recovery-manifest+json" && manifest.Schema == "recovery_signed_manifest_v1" && manifest.SigningKeyID != "" && manifest.Signature != ""
}

var _ workerProcessor = (*recoveryBackupProcessor)(nil)
