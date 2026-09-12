package main

import (
	"context"
	"errors"
	"slices"
	"time"
)

type runtimeSessionSearchWork interface {
	Execute(context.Context, runtimeSessionSearchLease) ([]string, error)
}
type runtimeSessionSearchProcessorConfig struct {
	Authority                             runtimeSessionSearchAuthority
	Executor                              runtimeSessionSearchWork
	WorkerID                              string
	LeaseSeconds, BatchSize, RetrySeconds int
	HeartbeatInterval                     time.Duration
	NewLeaseToken                         func() (string, error)
}
type runtimeSessionSearchProcessor struct {
	config runtimeSessionSearchProcessorConfig
}

func newRuntimeSessionSearchProcessor(config runtimeSessionSearchProcessorConfig) (*runtimeSessionSearchProcessor, error) {
	if nilWorkerDependency(config.Authority) || nilWorkerDependency(config.Executor) || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.RetrySeconds < 1 || config.RetrySeconds > 3600 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 || config.NewLeaseToken == nil {
		return nil, errRuntimeUnavailable
	}
	return &runtimeSessionSearchProcessor{config: config}, nil
}
func (processor *runtimeSessionSearchProcessor) RunOnce(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	for range processor.config.BatchSize {
		token, err := processor.config.NewLeaseToken()
		if err != nil || !runtimeLeaseToken(token) {
			return errWorkerExecution
		}
		lease, err := processor.config.Authority.Claim(ctx, processor.config.WorkerID, token, processor.config.LeaseSeconds)
		if err != nil {
			return errWorkerExecution
		}
		if lease == nil {
			return resultErr
		}
		if err := processor.process(ctx, *lease, token); err != nil {
			resultErr = errWorkerExecution
		}
		if ctx.Err() != nil {
			return errWorkerExecution
		}
	}
	return resultErr
}
func (processor *runtimeSessionSearchProcessor) process(ctx context.Context, lease runtimeSessionSearchLease, token string) error {
	if !validRuntimeSessionSearchLease(lease) || !lease.LeaseUntil.After(time.Now()) {
		return errWorkerExecution
	}
	workCtx, cancel := context.WithTimeout(ctx, minDuration(time.Duration(processor.config.LeaseSeconds)*4*time.Second, 2*time.Minute))
	lease.renewal = &runtimeStageLeaseRenewal{expiresAt: lease.LeaseUntil}
	defer cancel()
	heartbeatCtx, stopHeartbeat := context.WithCancel(workCtx)
	defer stopHeartbeat()
	done := make(chan error, 1)
	go processor.keepLease(heartbeatCtx, cancel, lease, token, done)
	ids, executeErr := callRuntimeSessionSearchWork(processor.config.Executor, workCtx, lease)
	stopHeartbeat()
	var heartbeatErr error
	select {
	case heartbeatErr = <-done:
	case <-workCtx.Done():
		return errWorkerExecution
	}
	if heartbeatErr != nil || workCtx.Err() != nil {
		return errWorkerExecution
	}
	if executeErr == nil && !slices.Equal(ids, lease.DocumentIDs) {
		executeErr = errWorkerExecution
	}
	outcome, retrySeconds := "indexed", 0
	if executeErr != nil {
		ids = []string{}
		outcome, retrySeconds = "retryable", processor.config.RetrySeconds
		if errors.Is(executeErr, errRuntimeStageMalformed) {
			outcome, retrySeconds = "quarantined", 0
		}
	}
	// Stop background renewal before the terminal transition, then renew once
	// synchronously. A late heartbeat cannot turn an indexed acknowledgement into
	// a misleading failure, and PostgreSQL still checks expiry after its row lock.
	finishCtx, finishCancel := context.WithTimeout(workCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/3, 10*time.Second))
	defer finishCancel()
	until, err := processor.config.Authority.Heartbeat(finishCtx, lease, processor.config.WorkerID, token, processor.config.LeaseSeconds)
	if err != nil || !until.After(time.Now()) || finishCtx.Err() != nil {
		return errWorkerExecution
	}
	if err := processor.config.Authority.Finish(finishCtx, lease, processor.config.WorkerID, token, outcome, ids, retrySeconds); err != nil {
		return errWorkerExecution
	}
	if executeErr != nil {
		return errWorkerExecution
	}
	return nil
}
func callRuntimeSessionSearchWork(executor runtimeSessionSearchWork, ctx context.Context, lease runtimeSessionSearchLease) (ids []string, resultErr error) {
	defer func() {
		if recover() != nil {
			ids = nil
			resultErr = errWorkerExecution
		}
	}()
	return executor.Execute(ctx, lease)
}
func (processor *runtimeSessionSearchProcessor) keepLease(ctx context.Context, cancel context.CancelFunc, lease runtimeSessionSearchLease, token string, done chan<- error) {
	var resultErr error
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
			cancel()
		}
		done <- resultErr
	}()
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeatCtx, heartbeatCancel := context.WithTimeout(ctx, minDuration(processor.config.HeartbeatInterval, 5*time.Second))
			until, err := processor.config.Authority.Heartbeat(heartbeatCtx, lease, processor.config.WorkerID, token, processor.config.LeaseSeconds)
			heartbeatCancel()
			if ctx.Err() != nil {
				return
			}
			if err != nil || !until.After(time.Now()) {
				resultErr = errWorkerExecution
				cancel()
				return
			}
			if lease.renewal != nil {
				lease.renewal.mu.Lock()
				lease.renewal.expiresAt = until
				lease.renewal.mu.Unlock()
			}
		}
	}
}

// The existing indexing service drains independent receipt-backed search work
// even if a raw-stage attempt fails. Each queue keeps its own fenced checkpoint.
type runtimeIndexAndSessionProcessor struct{ raw, sessions workerProcessor }

func (processor runtimeIndexAndSessionProcessor) RunOnce(ctx context.Context) error {
	first := processor.raw.RunOnce(ctx)
	second := processor.sessions.RunOnce(ctx)
	return errors.Join(first, second)
}
