package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
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
	EffectDigest      [sha256.Size]byte
	ResultReference   string
	ResultVersionID   string
	ResultDigest      [sha256.Size]byte
	ProjectionReceipt string
}

type runtimeStageExecutor interface {
	Execute(context.Context, runtimeevent.StageLease) (runtimeStageEffect, error)
}

// Private execution capability, never an archive/receipt field. A database
// admission must still revalidate this lease after acquiring its locks.
type runtimeStageExecution struct {
	lease      runtimeevent.StageLease
	workerID   string
	leaseToken string
	renewal    *runtimeStageLeaseRenewal
}

// Only successful, bound database heartbeats update this per-execution window.
// Lease identity, attempt and credentials never change with its expiry.
type runtimeStageLeaseRenewal struct {
	mu        sync.RWMutex
	expiresAt time.Time
}

func (execution runtimeStageExecution) currentLease() runtimeevent.StageLease {
	lease := execution.lease
	if execution.renewal != nil {
		execution.renewal.mu.RLock()
		lease.LeaseExpiresAt = execution.renewal.expiresAt
		execution.renewal.mu.RUnlock()
	}
	return lease
}

// Defense in depth only: callers must not log capabilities or reflect them
// into structured fields. Format suppresses all values, including scope IDs.
func (runtimeStageExecution) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "runtime-stage-execution[redacted]")
}

type authorizedRuntimeStageExecutor interface {
	ExecuteAuthorized(context.Context, runtimeStageExecution) (runtimeStageEffect, error)
}

type versionedRuntimeStageExecutor interface {
	SupportsRuntimeStageVersion(runtimeevent.RuntimeStage, string, string) bool
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
	if !exactRuntimeStageLease(lease, processor.config.Stage) {
		return errWorkerExecution
	}
	if lease.ImplementationVersion != processor.config.ImplementationVersion {
		compatible, ok := processor.config.Executor.(versionedRuntimeStageExecutor)
		if !ok || !compatible.SupportsRuntimeStageVersion(lease.Stage, processor.config.ImplementationVersion, lease.ImplementationVersion) {
			return errWorkerExecution
		}
	}
	workCtx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	execution := runtimeStageExecution{lease: lease, workerID: processor.config.WorkerID, leaseToken: leaseToken, renewal: &runtimeStageLeaseRenewal{expiresAt: lease.LeaseExpiresAt}}
	go processor.keepStageLease(workCtx, cancel, execution, heartbeatDone)
	effect, executeErr := callAuthorizedRuntimeStageExecutor(processor.config.Executor, workCtx, execution)
	if ctx.Err() != nil || workCtx.Err() != nil {
		cancel()
		_ = processor.joinHeartbeat(heartbeatDone)
		return errWorkerExecution
	}
	finish := processor.finishRequest(execution.currentLease(), leaseToken, effect, executeErr)
	finishCtx, finishCancel := context.WithTimeout(workCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 10*time.Second))
	result, finishErr := processor.config.Authority.FinishStage(finishCtx, finish)
	finishCancel()
	cancel()
	heartbeatErr := processor.joinHeartbeat(heartbeatDone)
	if ctx.Err() != nil || finishErr != nil || heartbeatErr != nil || !exactRuntimeStageFinish(result, finish) {
		return errWorkerExecution
	}
	return nil
}

func (processor *runtimeStageProcessor) keepStageLease(ctx context.Context, cancel context.CancelFunc, execution runtimeStageExecution, done chan<- error) {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			heartbeatCtx, heartbeatCancel := context.WithTimeout(ctx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
			expiresAt, err := processor.config.Authority.HeartbeatStage(heartbeatCtx, execution.currentLease(), execution.workerID, execution.leaseToken, processor.config.LeaseSeconds)
			heartbeatContextErr := heartbeatCtx.Err()
			heartbeatCancel()
			// Normal durable completion cancels this loop too. Never publish a
			// renewal after cancellation, but don't turn orderly shutdown into
			// lease loss. The processor separately checks its caller context.
			if ctx.Err() != nil {
				done <- nil
				return
			}
			if err != nil || heartbeatContextErr != nil || !expiresAt.After(time.Now()) {
				cancel()
				done <- errWorkerExecution
				return
			}
			execution.renewal.mu.Lock()
			execution.renewal.expiresAt = expiresAt
			execution.renewal.mu.Unlock()
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
		request.ProjectionReceipt = effect.ProjectionReceipt
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

func callAuthorizedRuntimeStageExecutor(executor runtimeStageExecutor, ctx context.Context, execution runtimeStageExecution) (effect runtimeStageEffect, resultErr error) {
	defer func() {
		if recover() != nil {
			effect = runtimeStageEffect{}
			resultErr = errWorkerExecution
		}
	}()
	lease := execution.currentLease()
	if nilWorkerDependency(executor) || ctx == nil || ctx.Err() != nil || !validRuntimeStage(lease.Stage) || !exactRuntimeStageLease(lease, lease.Stage) || !workerIdentityPattern.MatchString(execution.workerID) || !runtimeLeaseToken(execution.leaseToken) {
		return runtimeStageEffect{}, errWorkerExecution
	}
	if authorized, ok := executor.(authorizedRuntimeStageExecutor); ok {
		return authorized.ExecuteAuthorized(ctx, execution)
	}
	return callRuntimeStageExecutor(executor, ctx, lease)
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
