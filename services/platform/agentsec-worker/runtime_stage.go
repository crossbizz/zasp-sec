package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

var (
	errRuntimeStageRetryable = errors.New("runtime stage retryable")
	errRuntimeStageDenied    = errors.New("runtime stage denied")
	errRuntimeStageMalformed = errors.New("runtime stage malformed")
)

type runtimeStageAuthority interface {
	Ready(context.Context) error
	ClaimStages(context.Context, string, string, int, int) ([]runtimeevent.StageLease, error)
	HeartbeatStage(context.Context, runtimeevent.StageLease, string, string, int) (time.Time, error)
	FinishStage(context.Context, runtimeevent.StageFinishRequest) (runtimeevent.StageFinishResult, error)
}

type runtimeStageEffect struct {
	EffectDigest    [sha256.Size]byte
	ResultReference string
	ResultVersionID string
	ResultDigest    [sha256.Size]byte
}

type runtimeStageExecutor interface {
	Execute(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error)
}

type runtimeStageProcessorConfig struct {
	Authority             runtimeStageAuthority
	Executor              runtimeStageExecutor
	Stage                 runtimeevent.RuntimeStage
	ImplementationVersion string
	WorkerID              string
	LeaseSeconds          int
	BatchSize             int
	HeartbeatInterval     time.Duration
	RetrySeconds          int
	NewLeaseToken         func() (string, error)
}

type runtimeStageProcessor struct{ config runtimeStageProcessorConfig }

func newRuntimeStageProcessor(config runtimeStageProcessorConfig) (*runtimeStageProcessor, error) {
	leaseDuration := time.Duration(config.LeaseSeconds) * time.Second
	if config.Authority == nil || config.Executor == nil || !validRuntimeStage(config.Stage) || !workerVersionPattern.MatchString(config.ImplementationVersion) || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > leaseDuration/2 || config.RetrySeconds < 1 || config.RetrySeconds > 3600 || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &runtimeStageProcessor{config: config}, nil
}

func (processor *runtimeStageProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	leaseToken, err := processor.config.NewLeaseToken()
	if err != nil || !runtimeLeaseToken(leaseToken) {
		return errWorkerExecution
	}
	leases, err := processor.config.Authority.ClaimStages(ctx, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(leases) > processor.config.BatchSize {
		return errWorkerExecution
	}
	results := make(chan error, len(leases))
	for _, lease := range leases {
		lease := lease
		go func() { results <- processor.callProcess(ctx, lease, leaseToken) }()
	}
	failed := false
	for range leases {
		if <-results != nil {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
}

func (processor *runtimeStageProcessor) callProcess(ctx context.Context, lease runtimeevent.StageLease, leaseToken string) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	return processor.process(ctx, lease, leaseToken)
}

func (processor *runtimeStageProcessor) process(ctx context.Context, lease runtimeevent.StageLease, leaseToken string) error {
	if !exactRuntimeStageLease(lease, processor.config.Stage) || lease.ImplementationVersion != processor.config.ImplementationVersion {
		return errWorkerExecution
	}
	workCtx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go processor.keepStageLease(workCtx, cancel, lease, leaseToken, heartbeatDone)
	effect, executeErr := callRuntimeStageExecutor(processor.config.Executor, workCtx, lease)
	if ctx.Err() != nil || workCtx.Err() != nil {
		cancel()
		_ = processor.joinHeartbeat(heartbeatDone)
		return errWorkerExecution
	}
	finish := processor.finishRequest(lease, leaseToken, effect, executeErr)
	finishCtx, finishCancel := context.WithTimeout(workCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 10*time.Second))
	result, finishErr := processor.config.Authority.FinishStage(finishCtx, finish)
	finishCancel()
	cancel()
	heartbeatErr := processor.joinHeartbeat(heartbeatDone)
	if finishErr != nil || heartbeatErr != nil || !exactRuntimeStageFinish(result, finish) {
		return errWorkerExecution
	}
	return nil
}

func (processor *runtimeStageProcessor) keepStageLease(ctx context.Context, cancel context.CancelFunc, lease runtimeevent.StageLease, leaseToken string, done chan<- error) {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			heartbeatCtx, heartbeatCancel := context.WithTimeout(ctx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
			expiresAt, err := processor.config.Authority.HeartbeatStage(heartbeatCtx, lease, processor.config.WorkerID, leaseToken, processor.config.LeaseSeconds)
			heartbeatCancel()
			if err != nil || !expiresAt.After(time.Now()) {
				cancel()
				done <- errWorkerExecution
				return
			}
		}
	}
}

func (processor *runtimeStageProcessor) joinHeartbeat(done <-chan error) error {
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return errWorkerExecution
	}
}

func (processor *runtimeStageProcessor) finishRequest(lease runtimeevent.StageLease, leaseToken string, effect runtimeStageEffect, executeErr error) runtimeevent.StageFinishRequest {
	request := runtimeevent.StageFinishRequest{Lease: lease, WorkerID: processor.config.WorkerID, LeaseToken: leaseToken}
	switch {
	case executeErr == nil && validRuntimeStageEffect(effect):
		request.Outcome, request.EffectDigest, request.ResultReference, request.ResultVersionID, request.ResultDigest = runtimeevent.StageOutcomeSucceeded, effect.EffectDigest, effect.ResultReference, effect.ResultVersionID, effect.ResultDigest
	case errors.Is(executeErr, errRuntimeStageRetryable):
		request.Outcome, request.ErrorClass, request.RetryAfter = runtimeevent.StageOutcomeRetryable, "retryable", time.Duration(processor.config.RetrySeconds)*time.Second
	case errors.Is(executeErr, errRuntimeStageDenied):
		request.Outcome, request.ErrorClass = runtimeevent.StageOutcomeFailed, "denied"
	case errors.Is(executeErr, errRuntimeStageMalformed):
		request.Outcome, request.ErrorClass = runtimeevent.StageOutcomeQuarantined, "malformed"
	default:
		request.Outcome, request.ErrorClass = runtimeevent.StageOutcomeUnknown, "outcome_unknown"
	}
	return request
}

func callRuntimeStageExecutor(executor runtimeStageExecutor, ctx context.Context, lease runtimeevent.StageLease) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	return executor.Execute(ctx, lease)
}

func validRuntimeStage(stage runtimeevent.RuntimeStage) bool {
	switch stage {
	case runtimeevent.RuntimeStageArchive, runtimeevent.RuntimeStageIndex, runtimeevent.RuntimeStageCorrelate, runtimeevent.RuntimeStageProject, runtimeevent.RuntimeStageComplete:
		return true
	default:
		return false
	}
}

func exactRuntimeStageLease(lease runtimeevent.StageLease, stage runtimeevent.RuntimeStage) bool {
	return lease.Scope.Validate() == nil && !lease.BatchID.IsZero() && lease.Generation > 0 && lease.Stage == stage && lease.Attempt >= 1 && lease.Attempt <= 100 && workerVersionPattern.MatchString(lease.ImplementationVersion) && lease.InputDigest != ([sha256.Size]byte{}) && len(lease.InputReference) >= 1 && len(lease.InputReference) <= 1024 && strings.HasPrefix(lease.InputReference, "s3://") && validRuntimeVersion(lease.InputVersionID) && lease.LeaseExpiresAt.After(time.Now())
}

func validRuntimeStageEffect(effect runtimeStageEffect) bool {
	return effect.EffectDigest != ([sha256.Size]byte{}) && effect.ResultDigest != ([sha256.Size]byte{}) && len(effect.ResultReference) >= 1 && len(effect.ResultReference) <= 1024 && strings.HasPrefix(effect.ResultReference, "s3://") && validRuntimeVersion(effect.ResultVersionID)
}

func exactRuntimeStageFinish(result runtimeevent.StageFinishResult, request runtimeevent.StageFinishRequest) bool {
	return result.BatchID == request.Lease.BatchID && result.Generation == request.Lease.Generation && result.Stage == request.Lease.Stage && result.State == request.Outcome && result.Attempt == request.Lease.Attempt && result.InputDigest == request.Lease.InputDigest && result.ImplementationVersion == request.Lease.ImplementationVersion && result.EffectDigest == request.EffectDigest && result.ResultReference == request.ResultReference && result.ResultVersionID == request.ResultVersionID && result.ResultDigest == request.ResultDigest && result.ErrorClass == request.ErrorClass
}
