package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const discoveryOutboxTopic = "discovery-jobs"

var (
	discoveryRequestDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	providerAckPattern            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type outboxAuthority interface {
	ClaimOutboxTopic(context.Context, string, string, string, int, int) ([]apiserver.DiscoveryOutboxEvent, error)
	AcknowledgeOutbox(context.Context, domain.Scope, string, string, string, string) error
	RetryOutbox(context.Context, domain.Scope, string, string, string, int, string) error
}

type outboxPublisher interface {
	PublishBatch(context.Context, []jobqueue.Job) (jobqueue.PublishResult, error)
}

type outboxProcessorConfig struct {
	Authority     outboxAuthority
	Publisher     outboxPublisher
	Topic         string
	WorkerID      string
	LeaseSeconds  int
	BatchSize     int
	RetrySeconds  int
	NewLeaseToken func() (string, error)
}

type outboxProcessor struct{ config outboxProcessorConfig }

func newOutboxProcessor(config outboxProcessorConfig) (*outboxProcessor, error) {
	if config.Authority == nil || config.Publisher == nil || config.Topic != discoveryOutboxTopic || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.RetrySeconds < 1 || config.RetrySeconds > 3600 || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &outboxProcessor{config: config}, nil
}

func (processor *outboxProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	token, err := processor.config.NewLeaseToken()
	if err != nil || len(token) < 16 || len(token) > 128 {
		return errWorkerExecution
	}
	events, err := processor.config.Authority.ClaimOutboxTopic(ctx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, processor.config.BatchSize)
	if err != nil || len(events) > processor.config.BatchSize {
		return errWorkerExecution
	}
	if len(events) == 0 {
		return nil
	}
	jobs := make([]jobqueue.Job, len(events))
	scopes := make([]domain.Scope, len(events))
	seenOutbox := make(map[string]struct{}, len(events))
	seenJobs := make(map[domain.ProductID]struct{}, len(events))
	for index, event := range events {
		job, scope, ok := discoveryJobForOutbox(event, processor.config.Topic)
		if !ok {
			return errWorkerExecution
		}
		if _, duplicate := seenOutbox[event.ID]; duplicate {
			return errWorkerExecution
		}
		if _, duplicate := seenJobs[job.JobID]; duplicate {
			return errWorkerExecution
		}
		seenOutbox[event.ID] = struct{}{}
		seenJobs[job.JobID] = struct{}{}
		jobs[index], scopes[index] = job, scope
	}
	result, publishErr := processor.config.Publisher.PublishBatch(ctx, jobs)
	if publishErr != nil || !exactOutboxPublishResult(result, jobs) {
		processor.retryClaims(ctx, events, scopes, token, "queue_publish_unknown")
		return errWorkerExecution
	}
	for index, event := range events {
		if err := processor.config.Authority.AcknowledgeOutbox(ctx, scopes[index], event.ID, processor.config.WorkerID, token, result.Acknowledgements[index].ProviderAck); err != nil {
			// The provider publish has succeeded. Leaving the exact DB lease in place
			// is safer than republishing; the fenced acknowledgement can be replayed.
			return errWorkerExecution
		}
	}
	return nil
}

func (processor *outboxProcessor) retryClaims(ctx context.Context, events []apiserver.DiscoveryOutboxEvent, scopes []domain.Scope, token, code string) {
	for index, event := range events {
		_ = processor.config.Authority.RetryOutbox(ctx, scopes[index], event.ID, processor.config.WorkerID, token, processor.config.RetrySeconds, code)
	}
}

type discoveryOutboxPayload struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
	JobID          string `json:"job_id"`
	SyncID         string `json:"sync_id"`
	IntegrationID  string `json:"integration_id"`
	RequestDigest  string `json:"request_digest"`
}

func discoveryJobForOutbox(event apiserver.DiscoveryOutboxEvent, expectedTopic string) (jobqueue.Job, domain.Scope, bool) {
	organization, organizationErr := domain.ParseProductID(event.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(event.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(event.EnvironmentID)
	outboxID, outboxErr := domain.ParseProductID(event.ID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outboxID.IsZero() || event.Topic != expectedTopic || expectedTopic != discoveryOutboxTopic || event.PayloadVersion != 1 || len(event.Payload) == 0 || len(event.Payload) > 65_536 || len(event.PayloadDigest) != 32 || event.Attempt < 1 || event.Attempt > 100 {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var payload discoveryOutboxPayload
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	jobID, jobErr := domain.ParseProductID(payload.JobID)
	syncID, syncErr := domain.ParseProductID(payload.SyncID)
	integrationID, integrationErr := domain.ParseProductID(payload.IntegrationID)
	if jobErr != nil || syncErr != nil || integrationErr != nil || jobID.IsZero() || syncID.IsZero() || integrationID.IsZero() || payload.OrganizationID != event.OrganizationID || payload.WorkspaceID != event.WorkspaceID || payload.EnvironmentID != event.EnvironmentID || event.DeterministicKey != "sync:"+payload.SyncID || !discoveryRequestDigestPattern.MatchString(payload.RequestDigest) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	return jobqueue.Job{Scope: scope, JobID: jobID, Kind: "discovery", Payload: bytes.Clone(event.Payload)}, scope, true
}

func exactOutboxPublishResult(result jobqueue.PublishResult, jobs []jobqueue.Job) bool {
	if len(result.JobIDs) != len(jobs) || len(result.Acknowledgements) != len(jobs) {
		return false
	}
	seenAcknowledgements := make(map[string]struct{}, len(jobs))
	for index, job := range jobs {
		acknowledgement := result.Acknowledgements[index]
		if result.JobIDs[index] != job.JobID || acknowledgement.JobID != job.JobID || !providerAckPattern.MatchString(acknowledgement.ProviderAck) {
			return false
		}
		if _, duplicate := seenAcknowledgements[acknowledgement.ProviderAck]; duplicate {
			return false
		}
		seenAcknowledgements[acknowledgement.ProviderAck] = struct{}{}
	}
	return true
}
