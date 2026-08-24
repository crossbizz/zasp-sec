package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type attackLabOutboxAuthority interface {
	Ready(context.Context) error
	ClaimAttackLabOutbox(context.Context, string, string, int, int) ([]apiserver.AttackLabOutboxEvent, error)
	HeartbeatAttackLabOutbox(context.Context, string, string, int, int) (apiserver.AttackLabOutboxTransition, error)
	AcknowledgeAttackLabOutbox(context.Context, domain.Scope, string, string, string, string) (apiserver.AttackLabOutboxTransition, error)
	RetryAttackLabOutbox(context.Context, domain.Scope, string, string, string, int, string) (apiserver.AttackLabOutboxTransition, error)
}

type attackLabOutboxProcessorConfig struct {
	Authority         attackLabOutboxAuthority
	Publisher         outboxPublisher
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	RetrySeconds      int
	HeartbeatInterval time.Duration
	Now               func() time.Time
	NewLeaseToken     func() (string, error)
	Ready             func(context.Context) error
}

type attackLabOutboxProcessor struct {
	config attackLabOutboxProcessorConfig
}

type attackLabOutboxLeaseSet struct {
	mu     sync.Mutex
	active []bool
}

func newAttackLabOutboxProcessor(config attackLabOutboxProcessorConfig) (*attackLabOutboxProcessor, error) {
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	if config.Authority == nil || config.Publisher == nil || config.Ready == nil || config.Now == nil || config.NewLeaseToken == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.RetrySeconds < 1 || config.RetrySeconds > 3600 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 {
		return nil, errWorkerExecution
	}
	now := config.Now()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errWorkerExecution
	}
	return &attackLabOutboxProcessor{config: config}, nil
}

func (processor *attackLabOutboxProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Ready(ctx) != nil {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	events, err := processor.config.Authority.ClaimAttackLabOutbox(ctx, processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(events) > processor.config.BatchSize {
		return errWorkerExecution
	}
	if len(events) == 0 {
		return nil
	}
	jobs := make([]jobqueue.Job, len(events))
	scopes := make([]domain.Scope, len(events))
	seenEvents := make(map[string]struct{}, len(events))
	seenRuns := make(map[domain.ProductID]struct{}, len(events))
	for index, event := range events {
		job, scope, ok := attackLabJobForOutbox(event)
		if !ok {
			return errWorkerExecution
		}
		if _, duplicate := seenEvents[event.ID]; duplicate {
			return errWorkerExecution
		}
		if _, duplicate := seenRuns[job.JobID]; duplicate {
			return errWorkerExecution
		}
		seenEvents[event.ID], seenRuns[job.JobID] = struct{}{}, struct{}{}
		jobs[index], scopes[index] = job, scope
	}
	leases := &attackLabOutboxLeaseSet{active: make([]bool, len(events))}
	for index := range leases.active {
		leases.active[index] = true
	}
	if processor.heartbeatActive(ctx, token, leases) != nil {
		return errWorkerExecution
	}
	leaseCtx, cancelLease := context.WithCancel(context.WithoutCancel(ctx))
	publishCtx, cancelPublish := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go processor.keepOutboxLease(leaseCtx, token, leases, cancelPublish, heartbeatDone)
	result, publishErr := processor.config.Publisher.PublishBatch(publishCtx, jobs)
	cancelPublish()
	finalizeCtx, cancelFinalize := context.WithTimeout(leaseCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/2, 30*time.Second))
	defer cancelFinalize()
	if publishErr != nil || !exactOutboxPublishResult(result, jobs) {
		for index, event := range events {
			if processor.heartbeatActive(finalizeCtx, token, leases) != nil {
				cancelLease()
				<-heartbeatDone
				return errWorkerExecution
			}
			if processor.retryTransition(finalizeCtx, scopes[index], event.ID, token, leases, index) != nil {
				cancelLease()
				<-heartbeatDone
				return errWorkerExecution
			}
		}
		cancelLease()
		<-heartbeatDone
		return errWorkerExecution
	}
	for index, event := range events {
		if processor.heartbeatActive(finalizeCtx, token, leases) != nil {
			cancelLease()
			<-heartbeatDone
			return errWorkerExecution
		}
		if processor.acknowledgeTransition(finalizeCtx, scopes[index], event.ID, token, result.Acknowledgements[index].ProviderAck, leases, index) != nil {
			cancelLease()
			<-heartbeatDone
			return errWorkerExecution
		}
	}
	cancelLease()
	if heartbeatErr := <-heartbeatDone; heartbeatErr != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *attackLabOutboxProcessor) heartbeatActive(ctx context.Context, token string, leases *attackLabOutboxLeaseSet) error {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	count := leases.countLocked()
	if count == 0 {
		return nil
	}
	transition, err := processor.config.Authority.HeartbeatAttackLabOutbox(ctx, processor.config.WorkerID, token, processor.config.LeaseSeconds, count)
	if err != nil || transition.Topic != apiserver.AttackLabOutboxTopic || transition.RemainingCount != count {
		return errWorkerExecution
	}
	return nil
}

func (processor *attackLabOutboxProcessor) acknowledgeTransition(ctx context.Context, scope domain.Scope, id, token, providerAck string, leases *attackLabOutboxLeaseSet, index int) error {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	wantRemaining := leases.countLocked() - 1
	transition, err := processor.config.Authority.AcknowledgeAttackLabOutbox(ctx, scope, id, processor.config.WorkerID, token, providerAck)
	if err != nil || wantRemaining < 0 || transition.RemainingCount != wantRemaining || transition.State != "published" || index < 0 || index >= len(leases.active) || !leases.active[index] {
		return errWorkerExecution
	}
	leases.active[index] = false
	return nil
}

func (processor *attackLabOutboxProcessor) retryTransition(ctx context.Context, scope domain.Scope, id, token string, leases *attackLabOutboxLeaseSet, index int) error {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	wantRemaining := leases.countLocked() - 1
	transition, err := processor.config.Authority.RetryAttackLabOutbox(ctx, scope, id, processor.config.WorkerID, token, processor.config.RetrySeconds, "queue_publish_unknown")
	if err != nil || wantRemaining < 0 || transition.RemainingCount != wantRemaining || transition.State != "pending" && transition.State != "failed" || index < 0 || index >= len(leases.active) || !leases.active[index] {
		return errWorkerExecution
	}
	leases.active[index] = false
	return nil
}

func (processor *attackLabOutboxProcessor) keepOutboxLease(ctx context.Context, token string, leases *attackLabOutboxLeaseSet, cancelWork context.CancelFunc, done chan<- error) {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			if err := processor.heartbeatActive(ctx, token, leases); err != nil {
				cancelWork()
				done <- err
				return
			}
		}
	}
}

func (leases *attackLabOutboxLeaseSet) countLocked() int {
	count := 0
	for _, active := range leases.active {
		if active {
			count++
		}
	}
	return count
}

func attackLabJobForOutbox(event apiserver.AttackLabOutboxEvent) (jobqueue.Job, domain.Scope, bool) {
	organization, organizationErr := domain.ParseProductID(event.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(event.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(event.EnvironmentID)
	outbox, outboxErr := domain.ParseProductID(event.ID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	payloadDigest := sha256.Sum256(event.Payload)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outbox.IsZero() || event.Topic != apiserver.AttackLabOutboxTopic || len(event.Payload) < 2 || len(event.Payload) > 65_536 || len(event.PayloadDigest) != sha256.Size || subtle.ConstantTimeCompare(event.PayloadDigest, payloadDigest[:]) != 1 || event.Attempt < 1 || event.Attempt > 100 {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var payload attackLabDeliveryPayload
	if decodeStrictWorkerJSON(event.Payload, &payload) != nil {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	runID, runErr := domain.ParseProductID(payload.RunID)
	digest, digestErr := hexDigest(payload.InputDigest)
	if runErr != nil || digestErr != nil {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	job := jobqueue.Job{Scope: scope, JobID: runID, Kind: "attack-lab", Payload: append([]byte(nil), event.Payload...), AuthorityDigest: digest}
	if _, ok := validAttackLabDelivery(jobqueue.Delivery{Job: job}); !ok {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	return job, scope, true
}

func hexDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(value) != sha256.Size*2 {
		return result, errWorkerExecution
	}
	for index := 0; index < sha256.Size; index++ {
		high, highOK := hexNibble(value[index*2])
		low, lowOK := hexNibble(value[index*2+1])
		if !highOK || !lowOK {
			return [sha256.Size]byte{}, errWorkerExecution
		}
		result[index] = high<<4 | low
	}
	if result == [sha256.Size]byte{} {
		return [sha256.Size]byte{}, errWorkerExecution
	}
	return result, nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

var _ workerProcessor = (*attackLabOutboxProcessor)(nil)
