package main

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

// Linked execution never uses legacy retry or local-cancellation transitions.
// Work without a durable terminal result stays unacknowledged for reconciliation.
// Production composition supplies the database-classified protocol router.
type linkedRedTeamCancellationAuthority interface {
	CancelLinkedRedTeamRun(context.Context, domain.Scope, string, string, string, [sha256.Size]byte) (apiserver.RedTeamRun, error)
}

type linkedLeaseStop struct {
	cancelRequested bool
	expiry          time.Time
}

func (p *redTeamProcessor) runLinkedLeased(ctx context.Context, delivery jobqueue.Delivery, request redTeamExecutionRequest, expires time.Time) error {
	now := time.Now()
	if !expires.After(now) || expires.After(now.Add(time.Duration(p.config.LeaseSeconds)*time.Second)) || request.Run.Status != "leased" || request.Run.CancelRequested {
		return errWorkerExecution
	}
	workCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var stopped linkedLeaseStop
	go func() {
		defer close(done)
		stopped = p.keepLinkedLease(workCtx, cancel, delivery, request, expires)
	}()
	defer func() { cancel(); <-done }()
	result, err := callRedTeamRunner(p.config.Runner, workCtx, request)
	if err != nil || result.InputArtifact == nil || workCtx.Err() != nil {
		cancel()
		<-done
		return p.finalizeLinkedCancellation(ctx, delivery, request, stopped)
	}
	input := *result.InputArtifact
	// Preserve the exact bytes whose checksum/version were acknowledged by the
	// artifact store; the database compares their observations with its journal.
	completion := apiserver.RedTeamRunCompletion{RunID: request.Run.ID, Worker: p.config.WorkerID, LeaseToken: request.LeaseToken, InputDigest: request.InputDigest, InputArtifact: &input, Verdict: result.Verdict, Objective: result.Objective, Behavior: result.Behavior, ErrorCode: result.ErrorCode, Evidence: append([]string(nil), result.Evidence...), EvidenceReference: result.EvidenceReference, EvidenceKey: result.EvidenceKey, EvidenceVersionID: result.EvidenceVersionID, EvidenceChecksum: append([]byte(nil), result.EvidenceChecksum...), EvidenceSizeBytes: result.EvidenceSizeBytes}
	completion.EvidenceArtifact = append([]byte(nil), result.EvidenceArtifact...)
	// Completion is itself lease-fenced. Do not detach it from shutdown, deadline,
	// cancellation or heartbeat loss, even when the runner returned evidence.
	finished, err := p.config.Authority.FinishRedTeamRun(workCtx, delivery.Job.Scope, completion)
	if err != nil || workCtx.Err() != nil || finished.ID != request.Run.ID || finished.Status != "complete" {
		cancel()
		<-done
		return p.finalizeLinkedCancellation(ctx, delivery, request, stopped)
	}
	cancel()
	<-done
	return p.acknowledge(ctx, delivery.Receipt)
}

func (p *redTeamProcessor) finalizeLinkedCancellation(ctx context.Context, delivery jobqueue.Delivery, request redTeamExecutionRequest, stopped linkedLeaseStop) error {
	authority, ok := p.config.Authority.(linkedRedTeamCancellationAuthority)
	if !ok || !stopped.cancelRequested || ctx.Err() != nil || !stopped.expiry.After(time.Now()) {
		return errWorkerExecution
	}
	// The execution context is cancelled by the request. Finalization retains
	// root shutdown and the last confirmed lease deadline, never a new lease.
	finalizeCtx, cancel := context.WithDeadline(ctx, minTime(stopped.expiry, time.Now().Add(5*time.Second)))
	defer cancel()
	result, err := authority.CancelLinkedRedTeamRun(finalizeCtx, delivery.Job.Scope, request.Run.ID, p.config.WorkerID, request.LeaseToken, request.InputDigest)
	if err != nil || finalizeCtx.Err() != nil || result.ID != request.Run.ID || !result.CancelRequested || !(result.Status == "cancelled" && result.ErrorCode == "cancelled" || result.Status == "failed" && result.ErrorCode == "outcome_unknown") {
		return errWorkerExecution
	}
	// Both are durable terminal states. Unknown execution remains failed and
	// its journal is retained for reconciliation; this is only queue acknowledgement.
	return p.acknowledge(ctx, delivery.Receipt)
}

func (p *redTeamProcessor) keepLinkedLease(ctx context.Context, cancel context.CancelFunc, delivery jobqueue.Delivery, request redTeamExecutionRequest, expires time.Time) (stopped linkedLeaseStop) {
	defer cancel()
	timer := time.NewTimer(max(time.Until(expires), 0))
	defer timer.Stop()
	ticker := time.NewTicker(p.config.HeartbeatInterval)
	defer ticker.Stop()
	type renewal struct {
		expiry          time.Time
		valid           bool
		cancelRequested bool
	}
	results := make(chan renewal, 1)
	var outstanding sync.WaitGroup
	// Cancel pending I/O before joining it. The database/queue drivers honor ctx.
	defer func() { cancel(); outstanding.Wait() }()
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		case <-ticker.C:
			if pending {
				continue
			}
			pending = true
			deadline := minTime(expires, time.Now().Add(minDuration(p.config.HeartbeatInterval, 5*time.Second)))
			renewCtx, stop := context.WithDeadline(ctx, deadline)
			outstanding.Add(1)
			go func(oldExpiry time.Time) {
				defer outstanding.Done()
				defer stop()
				heartbeat, err := p.config.Authority.HeartbeatRedTeamRun(renewCtx, delivery.Job.Scope, request.Run.ID, p.config.WorkerID, request.LeaseToken, p.config.LeaseSeconds)
				value := renewal{}
				now := time.Now()
				if err == nil && renewCtx.Err() == nil && !heartbeat.Renewed && heartbeat.CancelRequested && heartbeat.LeaseExpiresAt == nil && oldExpiry.After(now) {
					value.cancelRequested = true
					value.expiry = oldExpiry
				}
				if err == nil && renewCtx.Err() == nil && heartbeat.Renewed && !heartbeat.CancelRequested && heartbeat.LeaseExpiresAt != nil && oldExpiry.After(now) && heartbeat.LeaseExpiresAt.After(now) && !heartbeat.LeaseExpiresAt.After(now.Add(time.Duration(p.config.LeaseSeconds)*time.Second)) {
					value.expiry = *heartbeat.LeaseExpiresAt
					// Queue visibility accepts whole seconds. Never round up past
					// the database deadline; subsecond work needs no extension.
					visibility := time.Until(value.expiry).Truncate(time.Second)
					if visibility < time.Second || p.config.Queue.(jobqueue.VisibilityExtender).ExtendVisibility(renewCtx, []jobqueue.Receipt{delivery.Receipt}, visibility) == nil {
						value.valid = renewCtx.Err() == nil
					}
				}
				results <- value
			}(expires)
		case result := <-results:
			pending = false
			if result.cancelRequested && result.expiry.After(time.Now()) {
				return linkedLeaseStop{cancelRequested: true, expiry: result.expiry}
			}
			if !result.valid || !expires.After(time.Now()) || !result.expiry.After(time.Now()) {
				return
			}
			expires = result.expiry
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(time.Until(expires))
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
