package main

import (
	"context"
	"errors"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

var errWorkerExecution = errors.New("worker execution unavailable")

type discoveryQueue interface {
	ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error)
	AcknowledgeBatch(context.Context, []jobqueue.Receipt) error
}

type discoveryCollector interface {
	Collect(context.Context, collection.Request) (collection.Outcome, error)
}

type discoveryAuthority interface {
	ClaimDiscoveryDelivery(context.Context, domain.Scope, string, string, string, int) (apiserver.DiscoveryDeliveryClaim, error)
	GetDiscoveryJobInput(context.Context, domain.Scope, string, string, string) (apiserver.ExecutionJobInput, error)
	HeartbeatDiscoveryJob(context.Context, domain.Scope, apiserver.JobHeartbeat) (apiserver.LeaseHeartbeatResult, error)
	CheckpointPartialDiscoveryJob(context.Context, domain.Scope, apiserver.ExecutionPartialCheckpoint) (apiserver.ExecutionPartialCheckpointResult, error)
	ApplyCompleteSnapshot(context.Context, domain.Scope, apiserver.ExecutionCompleteSnapshot) (apiserver.ExecutionSnapshotApplyResult, error)
	FinishDiscoveryJob(context.Context, domain.Scope, apiserver.DiscoveryJobCompletion) (apiserver.WorkCompletionResult, error)
}

type discoveryProcessorConfig struct {
	Authority         discoveryAuthority
	Queue             discoveryQueue
	Collector         discoveryCollector
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	HeartbeatInterval time.Duration
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
}

type discoveryProcessor struct{ config discoveryProcessorConfig }

func newDiscoveryProcessor(config discoveryProcessorConfig) (*discoveryProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	_, extendsVisibility := config.Queue.(jobqueue.VisibilityExtender)
	if config.Authority == nil || config.Queue == nil || !extendsVisibility || config.Collector == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 || config.Now == nil || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &discoveryProcessor{config: config}, nil
}

func (processor *discoveryProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	deliveries, err := processor.config.Queue.ConsumeBatch(ctx, processor.config.BatchSize)
	if err != nil {
		return errWorkerExecution
	}
	results := make(chan error, len(deliveries))
	for _, delivery := range deliveries {
		delivery := delivery
		go func() { results <- processor.process(ctx, delivery) }()
	}
	var failed bool
	for range deliveries {
		if err := <-results; err != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *discoveryProcessor) process(ctx context.Context, delivery jobqueue.Delivery) error {
	if delivery.Job.Scope.Validate() != nil || delivery.Job.JobID.IsZero() || delivery.Job.Kind != "discovery" {
		return errWorkerExecution
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || len(leaseToken) < 16 || len(leaseToken) > 128 {
		return errWorkerExecution
	}
	jobID := delivery.Job.JobID.String()
	claim, err := processor.config.Authority.ClaimDiscoveryDelivery(ctx, delivery.Job.Scope, jobID, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds)
	if err != nil {
		return errWorkerExecution
	}
	switch claim.Disposition {
	case "busy":
		return nil
	case "ack_terminal":
		return processor.acknowledge(ctx, delivery.Receipt)
	case "claimed":
	default:
		return errWorkerExecution
	}
	input, err := processor.config.Authority.GetDiscoveryJobInput(ctx, delivery.Job.Scope, jobID, processor.config.WorkerID, leaseToken)
	if err != nil {
		return errWorkerExecution
	}
	request, ok := collectionRequest(delivery.Job.Scope, input)
	if !ok {
		return errWorkerExecution
	}
	outcome, err, lifecycleErr := processor.collectWithHeartbeat(ctx, delivery, input, leaseToken, request)
	if lifecycleErr != nil {
		return errWorkerExecution
	}
	if err != nil {
		return processor.finishFailure(ctx, delivery, input, leaseToken, err)
	}
	switch value := outcome.(type) {
	case collection.CompleteResult:
		return processor.finishComplete(ctx, delivery, input, leaseToken, value)
	case collection.PartialResult:
		return processor.finishPartial(ctx, delivery, input, leaseToken, value)
	default:
		return errWorkerExecution
	}
}

func (processor *discoveryProcessor) collectWithHeartbeat(ctx context.Context, delivery jobqueue.Delivery, input apiserver.ExecutionJobInput, leaseToken string, request collection.Request) (collection.Outcome, error, error) {
	workCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(processor.config.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(workCtx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
				_, heartbeatErr := processor.config.Authority.HeartbeatDiscoveryJob(renewCtx, delivery.Job.Scope, apiserver.JobHeartbeat{JobID: input.JobID, Worker: processor.config.WorkerID, LeaseToken: leaseToken, LeaseSeconds: processor.config.LeaseSeconds})
				visibilityErr := error(nil)
				if heartbeatErr == nil {
					visibilityErr = processor.config.Queue.(jobqueue.VisibilityExtender).ExtendVisibility(renewCtx, []jobqueue.Receipt{delivery.Receipt}, time.Duration(processor.config.LeaseSeconds)*time.Second)
				}
				renewCancel()
				if heartbeatErr != nil || visibilityErr != nil {
					cancel()
					done <- errWorkerExecution
					return
				}
			}
		}
	}()
	outcome, collectErr := processor.config.Collector.Collect(workCtx, request)
	cancel()
	select {
	case lifecycleErr := <-done:
		return outcome, collectErr, lifecycleErr
	case <-time.After(5 * time.Second):
		return nil, collectErr, errWorkerExecution
	}
}

func (processor *discoveryProcessor) finishComplete(ctx context.Context, delivery jobqueue.Delivery, input apiserver.ExecutionJobInput, leaseToken string, result collection.CompleteResult) error {
	descriptor := result.Manifest().Descriptor()
	candidate := result.Snapshot()
	cursor := result.NextCursor()
	manifestChecksum := descriptor.Checksum()
	collectedAt := processor.config.Now()
	if collectedAt.IsZero() || collectedAt.Location() != time.UTC {
		return errWorkerExecution
	}
	applied, err := processor.config.Authority.ApplyCompleteSnapshot(ctx, delivery.Job.Scope, apiserver.ExecutionCompleteSnapshot{
		CompleteSnapshot: apiserver.CompleteSnapshot{
			IntegrationID: input.IntegrationID, SyncID: input.SyncID, SnapshotID: input.SnapshotID, Generation: input.Generation,
			Source: string(input.Provider), ManifestReference: descriptor.ObjectReference(), ManifestChecksum: manifestChecksum[:], CollectedAt: collectedAt,
			CursorProvider: string(cursor.Provider), CursorValue: cursor.Value, Entities: candidate.Entities(), Relationships: candidate.Relationships(), Evidence: candidate.Evidence(),
		},
		JobID: input.JobID, Worker: processor.config.WorkerID, LeaseToken: leaseToken, ManifestKey: descriptor.Key(), ManifestVersionID: descriptor.VersionID(),
		ManifestSizeBytes: descriptor.Size(), ManifestMediaType: descriptor.MediaType(), ManifestSchemaVersion: descriptor.SchemaVersion(), ParserVersion: candidate.ParserVersion(), ToolVersion: candidate.ToolVersion(),
	})
	if err != nil {
		return errWorkerExecution
	}
	completion, err := processor.config.Authority.FinishDiscoveryJob(ctx, delivery.Job.Scope, apiserver.DiscoveryJobCompletion{ID: input.JobID, Worker: processor.config.WorkerID, LeaseToken: leaseToken, Outcome: "succeeded", ResultDigest: applied.CandidateDigest})
	if err != nil || completion.State != "succeeded" {
		return errWorkerExecution
	}
	return processor.acknowledge(ctx, delivery.Receipt)
}

func (processor *discoveryProcessor) finishPartial(ctx context.Context, delivery jobqueue.Delivery, input apiserver.ExecutionJobInput, leaseToken string, result collection.PartialResult) error {
	if result.Reason() != collection.FailurePartial {
		return errWorkerExecution
	}
	descriptor := result.Manifest().Descriptor()
	cursor := result.NextCursor()
	checksum := descriptor.Checksum()
	checkpoint, err := processor.config.Authority.CheckpointPartialDiscoveryJob(ctx, delivery.Job.Scope, apiserver.ExecutionPartialCheckpoint{
		JobID: input.JobID, Worker: processor.config.WorkerID, LeaseToken: leaseToken, ExpectedVersion: input.CheckpointVersion,
		CursorProvider: cursor.Provider, CursorVersion: cursor.Version, CursorValue: cursor.Value,
		ManifestReference: descriptor.ObjectReference(), ManifestKey: descriptor.Key(), ManifestVersionID: descriptor.VersionID(), ManifestChecksum: checksum[:],
		ManifestSizeBytes: descriptor.Size(), ManifestMediaType: descriptor.MediaType(), ManifestSchemaVersion: descriptor.SchemaVersion(), ParserVersion: input.ParserVersion, ToolVersion: input.ToolVersion,
	})
	if err != nil {
		return errWorkerExecution
	}
	completion, err := processor.config.Authority.FinishDiscoveryJob(ctx, delivery.Job.Scope, apiserver.DiscoveryJobCompletion{ID: input.JobID, Worker: processor.config.WorkerID, LeaseToken: leaseToken, Outcome: "retryable", ResultDigest: checkpoint.CheckpointDigest, LastErrorCode: "partial", LastError: "partial provider result", RetryAfterSeconds: 30})
	if err != nil {
		return errWorkerExecution
	}
	if completion.State == "failed" || completion.State == "cancelled" {
		return processor.acknowledge(ctx, delivery.Receipt)
	}
	if completion.State != "retryable" {
		return errWorkerExecution
	}
	return nil
}

func (processor *discoveryProcessor) finishFailure(ctx context.Context, delivery jobqueue.Delivery, input apiserver.ExecutionJobInput, leaseToken string, cause error) error {
	code, retry, retryAfter := "terminal", false, 0
	var failure *collection.Failure
	if errors.As(cause, &failure) {
		code = string(failure.Code())
		switch failure.Code() {
		case collection.FailureRetryable, collection.FailureRateLimited, collection.FailureOutcomeUnknown:
			retry = true
			if !failure.RetryAt().IsZero() {
				retryAfter = int(time.Until(failure.RetryAt()).Seconds())
				if retryAfter < 1 {
					retryAfter = 1
				}
			}
		case collection.FailureCancelled:
			code = "cancelled"
		}
	}
	outcome := "failed"
	if retry {
		outcome = "retryable"
	}
	if code == "cancelled" {
		outcome = "cancelled"
	}
	completion, err := processor.config.Authority.FinishDiscoveryJob(ctx, delivery.Job.Scope, apiserver.DiscoveryJobCompletion{ID: input.JobID, Worker: processor.config.WorkerID, LeaseToken: leaseToken, Outcome: outcome, LastErrorCode: code, LastError: "provider collection failed", RetryAfterSeconds: retryAfter})
	if err != nil {
		return errWorkerExecution
	}
	if completion.State == "retryable" {
		return nil
	}
	if completion.State != "failed" && completion.State != "cancelled" {
		return errWorkerExecution
	}
	return processor.acknowledge(ctx, delivery.Receipt)
}

func (processor *discoveryProcessor) acknowledge(ctx context.Context, receipt jobqueue.Receipt) error {
	if err := processor.config.Queue.AcknowledgeBatch(ctx, []jobqueue.Receipt{receipt}); err != nil {
		return errWorkerExecution
	}
	return nil
}

func collectionRequest(scope domain.Scope, input apiserver.ExecutionJobInput) (collection.Request, bool) {
	integration, integrationErr := domain.ParseProductID(input.IntegrationID)
	connection, connectionErr := domain.ParseProductID(input.ConnectionID)
	job, jobErr := domain.ParseProductID(input.JobID)
	if integrationErr != nil || connectionErr != nil || jobErr != nil {
		return collection.Request{}, false
	}
	cursor := collection.Cursor{}
	if input.CursorProvider != nil || input.CursorVersion != nil || input.CursorValue != nil {
		if input.CursorProvider == nil || input.CursorVersion == nil || input.CursorValue == nil {
			return collection.Request{}, false
		}
		cursor = collection.Cursor{Provider: *input.CursorProvider, Version: *input.CursorVersion, Value: *input.CursorValue}
	}
	request := collection.Request{Scope: scope, IntegrationID: integration, ConnectionID: connection, JobID: job, Attempt: input.Attempt, Provider: input.Provider, CollectorVersion: input.CollectorVersion, CredentialClass: input.CredentialClass, CredentialReference: input.CredentialReference, ExpectedSubject: collection.SubjectBinding{Kind: input.SubjectKind, ID: input.SubjectID}, Cursor: cursor, ParserVersion: input.ParserVersion, ToolVersion: input.ToolVersion, Bounds: collection.Bounds{MaxPages: 100, MaxItems: 10000, MaxRawBytes: 64 << 20, Timeout: 10 * time.Minute}}
	return request, request.Validate() == nil
}
