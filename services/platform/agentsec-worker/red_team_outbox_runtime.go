package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type redTeamOutboxAuthority interface {
	Ready(context.Context) error
	ClaimRedTeamOutbox(context.Context, string, string, int, int) ([]apiserver.RedTeamOutboxEvent, error)
	HeartbeatRedTeamOutbox(context.Context, domain.Scope, string, string, string, int) (bool, error)
	AcknowledgeRedTeamOutbox(context.Context, domain.Scope, string, string, string, string) error
	RetryRedTeamOutbox(context.Context, domain.Scope, string, string, string, time.Time) error
}

type redTeamOutboxProcessorConfig struct {
	Authority         redTeamOutboxAuthority
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

type redTeamOutboxProcessor struct{ config redTeamOutboxProcessorConfig }

type redTeamOutboxLeaseSet struct {
	mu     sync.Mutex
	active []bool
}

type redTeamOutboxPayload struct {
	OrganizationID    string `json:"organization_id"`
	WorkspaceID       string `json:"workspace_id"`
	EnvironmentID     string `json:"environment_id"`
	RunID             string `json:"run_id"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
	InputDigest       string `json:"input_digest"`
}

func newRedTeamOutboxProcessor(config redTeamOutboxProcessorConfig) (*redTeamOutboxProcessor, error) {
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
	return &redTeamOutboxProcessor{config: config}, nil
}

func (processor *redTeamOutboxProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil || processor.config.Ready(ctx) != nil {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) != 32 {
		return errWorkerExecution
	}
	events, err := processor.config.Authority.ClaimRedTeamOutbox(ctx, processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
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
		job, scope, ok := redTeamJobForOutbox(event)
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
	leases := &redTeamOutboxLeaseSet{active: make([]bool, len(events))}
	for index := range leases.active {
		leases.active[index] = true
	}
	if processor.heartbeatActive(ctx, events, scopes, token, leases) != nil {
		return errWorkerExecution
	}
	leaseCtx, cancelLease := context.WithCancel(context.WithoutCancel(ctx))
	publishCtx, cancelPublish := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go processor.keepOutboxLeases(leaseCtx, events, scopes, token, leases, cancelPublish, heartbeatDone)
	result, publishErr := processor.config.Publisher.PublishBatch(publishCtx, jobs)
	cancelPublish()
	finalizeCtx, cancelFinalize := context.WithTimeout(leaseCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second/2, 30*time.Second))
	defer cancelFinalize()
	if publishErr != nil || !exactOutboxPublishResult(result, jobs) {
		for index, event := range events {
			if processor.heartbeatActive(finalizeCtx, events, scopes, token, leases) != nil || processor.config.Authority.RetryRedTeamOutbox(finalizeCtx, scopes[index], event.ID, processor.config.WorkerID, token, processor.config.Now().Add(time.Duration(processor.config.RetrySeconds)*time.Second)) != nil {
				cancelLease()
				<-heartbeatDone
				return errWorkerExecution
			}
			leases.remove(index)
		}
		cancelLease()
		<-heartbeatDone
		return errWorkerExecution
	}
	for index, event := range events {
		if processor.heartbeatActive(finalizeCtx, events, scopes, token, leases) != nil || processor.config.Authority.AcknowledgeRedTeamOutbox(finalizeCtx, scopes[index], event.ID, processor.config.WorkerID, token, result.Acknowledgements[index].ProviderAck) != nil {
			cancelLease()
			<-heartbeatDone
			return errWorkerExecution
		}
		leases.remove(index)
	}
	cancelLease()
	if heartbeatErr := <-heartbeatDone; heartbeatErr != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *redTeamOutboxProcessor) heartbeatActive(ctx context.Context, events []apiserver.RedTeamOutboxEvent, scopes []domain.Scope, token string, leases *redTeamOutboxLeaseSet) error {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	for index, active := range leases.active {
		if !active {
			continue
		}
		renewed, err := processor.config.Authority.HeartbeatRedTeamOutbox(ctx, scopes[index], events[index].ID, processor.config.WorkerID, token, processor.config.LeaseSeconds)
		if err != nil || !renewed {
			return errWorkerExecution
		}
	}
	return nil
}

func (processor *redTeamOutboxProcessor) keepOutboxLeases(ctx context.Context, events []apiserver.RedTeamOutboxEvent, scopes []domain.Scope, token string, leases *redTeamOutboxLeaseSet, cancelWork context.CancelFunc, done chan<- error) {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			if err := processor.heartbeatActive(ctx, events, scopes, token, leases); err != nil {
				cancelWork()
				done <- err
				return
			}
		}
	}
}

func (leases *redTeamOutboxLeaseSet) remove(index int) {
	leases.mu.Lock()
	defer leases.mu.Unlock()
	if index >= 0 && index < len(leases.active) {
		leases.active[index] = false
	}
}

func redTeamJobForOutbox(event apiserver.RedTeamOutboxEvent) (jobqueue.Job, domain.Scope, bool) {
	organization, organizationErr := domain.ParseProductID(event.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(event.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(event.EnvironmentID)
	outbox, outboxErr := domain.ParseProductID(event.ID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	payloadDigest := sha256.Sum256(event.Payload)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outbox.IsZero() || event.Topic != apiserver.RedTeamOutboxTopic || len(event.Payload) < 2 || len(event.Payload) > 65_536 || len(event.PayloadDigest) != sha256.Size || subtle.ConstantTimeCompare(event.PayloadDigest, payloadDigest[:]) != 1 || event.Attempt < 1 || event.Attempt > 100 {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var payload redTeamOutboxPayload
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	runID, runErr := domain.ParseProductID(payload.RunID)
	definitionID, definitionErr := domain.ParseProductID(payload.DefinitionID)
	inputDigest, digestErr := hex.DecodeString(payload.InputDigest)
	if runErr != nil || definitionErr != nil || runID.IsZero() || definitionID.IsZero() || payload.OrganizationID != event.OrganizationID || payload.WorkspaceID != event.WorkspaceID || payload.EnvironmentID != event.EnvironmentID || payload.DefinitionVersion < 1 || payload.DefinitionVersion > 1_000_000 || digestErr != nil || len(inputDigest) != sha256.Size || bytes.Equal(inputDigest, make([]byte, sha256.Size)) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var authorityDigest [sha256.Size]byte
	copy(authorityDigest[:], inputDigest)
	return jobqueue.Job{Scope: scope, JobID: runID, Kind: "red-team", Payload: bytes.Clone(event.Payload), AuthorityDigest: authorityDigest}, scope, true
}

var _ workerProcessor = (*redTeamOutboxProcessor)(nil)
