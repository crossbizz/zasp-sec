package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const (
	discoveryOutboxTopic = "discovery-jobs"
	runtimeOutboxTopic   = "runtime-events"
)

const outboxAcknowledgementAttempts = 3

var (
	discoveryRequestDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	providerAckPattern            = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	runtimeS3ReferencePattern     = regexp.MustCompile(`^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

type outboxAuthority interface {
	ClaimOutboxTopic(context.Context, string, string, string, int, int) ([]apiserver.DiscoveryOutboxEvent, error)
	HeartbeatOutboxTopic(context.Context, string, string, string, int, int) (apiserver.OutboxLeaseHeartbeatResult, error)
	AcknowledgeOutboxTopic(context.Context, string, domain.Scope, string, string, string, string) (apiserver.OutboxLeaseTransitionResult, error)
	RetryOutboxTopic(context.Context, string, domain.Scope, string, string, string, int, string) (apiserver.OutboxLeaseTransitionResult, error)
}

type outboxPublisher interface {
	PublishBatch(context.Context, []jobqueue.Job) (jobqueue.PublishResult, error)
}

type outboxProcessorConfig struct {
	Authority         outboxAuthority
	Publisher         outboxPublisher
	Topic             string
	WorkerID          string
	LeaseSeconds      int
	BatchSize         int
	RetrySeconds      int
	NewLeaseToken     func() (string, error)
	HeartbeatInterval time.Duration
	Ready             func(context.Context) error
}

type outboxProcessor struct{ config outboxProcessorConfig }

func newOutboxProcessor(config outboxProcessorConfig) (*outboxProcessor, error) {
	if config.Authority == nil || config.Publisher == nil || config.Topic != discoveryOutboxTopic && config.Topic != runtimeOutboxTopic || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.BatchSize < 1 || config.BatchSize > 10 || config.RetrySeconds < 1 || config.RetrySeconds > 3600 || config.NewLeaseToken == nil || config.Ready == nil {
		return nil, errWorkerExecution
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = time.Duration(config.LeaseSeconds) * time.Second / 3
	}
	if config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > time.Duration(config.LeaseSeconds)*time.Second/2 {
		return nil, errWorkerExecution
	}
	return &outboxProcessor{config: config}, nil
}

func (processor *outboxProcessor) RunOnce(ctx context.Context) error {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	if err := processor.config.Ready(ctx); err != nil {
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
	if _, err := processor.heartbeat(ctx, token, len(events)); err != nil {
		return errWorkerExecution
	}
	var remaining atomic.Int64
	remaining.Store(int64(len(events)))
	var leaseMu sync.Mutex
	leaseCtx, cancelLease := context.WithCancel(context.WithoutCancel(ctx))
	publishCtx, cancelPublish := context.WithCancel(ctx)
	heartbeatDone := make(chan error, 1)
	go processor.keepLease(leaseCtx, token, &remaining, &leaseMu, cancelPublish, cancelLease, heartbeatDone)
	result, publishErr := processor.config.Publisher.PublishBatch(publishCtx, jobs)
	cancelPublish()
	finalizeCtx, cancelFinalize := context.WithTimeout(leaseCtx, minDuration(time.Duration(processor.config.LeaseSeconds)*time.Second, 30*time.Second))
	defer cancelFinalize()
	if publishErr != nil || !exactOutboxPublishResult(result, jobs) {
		retryErr := processor.retryClaims(finalizeCtx, events, scopes, token, "queue_publish_unknown", &remaining, &leaseMu)
		cancelLease()
		heartbeatErr := <-heartbeatDone
		if retryErr != nil || heartbeatErr != nil {
			return errWorkerExecution
		}
		return errWorkerExecution
	}
	for index, event := range events {
		if err := processor.acknowledge(finalizeCtx, scopes[index], event.ID, token, result.Acknowledgements[index].ProviderAck, &remaining, &leaseMu); err != nil {
			cancelLease()
			<-heartbeatDone
			// Standard queues are at-least-once. A later lease may republish after a
			// process crash, but the stable job envelope and downstream job authority
			// prevent a duplicate collection effect.
			return errWorkerExecution
		}
	}
	cancelLease()
	if heartbeatErr := <-heartbeatDone; heartbeatErr != nil {
		return errWorkerExecution
	}
	return nil
}

func (processor *outboxProcessor) heartbeat(ctx context.Context, token string, count int) (int, error) {
	result, err := processor.config.Authority.HeartbeatOutboxTopic(ctx, processor.config.Topic, processor.config.WorkerID, token, processor.config.LeaseSeconds, count)
	if err != nil || result.ID != processor.config.Topic || !result.LeaseExpiresAt.After(time.Now()) {
		return 0, errWorkerExecution
	}
	return result.RemainingCount, nil
}

func (processor *outboxProcessor) keepLease(ctx context.Context, token string, remaining *atomic.Int64, leaseMu *sync.Mutex, cancelPublish, cancelLease context.CancelFunc, done chan<- error) {
	ticker := time.NewTicker(processor.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case <-ticker.C:
			leaseMu.Lock()
			count := int(remaining.Load())
			if count == 0 {
				leaseMu.Unlock()
				done <- nil
				return
			}
			observed, err := processor.heartbeat(ctx, token, count)
			leaseMu.Unlock()
			if err != nil || observed != count {
				cancelPublish()
				cancelLease()
				done <- err
				return
			}
		}
	}
}

func (processor *outboxProcessor) acknowledge(ctx context.Context, scope domain.Scope, id, token, providerAck string, remaining *atomic.Int64, leaseMu *sync.Mutex) error {
	for attempt := 0; attempt < outboxAcknowledgementAttempts; {
		leaseMu.Lock()
		before := int(remaining.Load())
		observed, heartbeatErr := processor.heartbeat(ctx, token, before)
		if heartbeatErr != nil || observed != before {
			leaseMu.Unlock()
			return errWorkerExecution
		}
		seriesCtx, cancelSeries := context.WithTimeout(ctx, processor.config.HeartbeatInterval)
		for attempt < outboxAcknowledgementAttempts {
			attempt++
			result, err := processor.config.Authority.AcknowledgeOutboxTopic(seriesCtx, processor.config.Topic, scope, id, processor.config.WorkerID, token, providerAck)
			if err == nil && result.RemainingCount == before-1 {
				remaining.Store(int64(result.RemainingCount))
				cancelSeries()
				leaseMu.Unlock()
				return nil
			}
			if seriesCtx.Err() != nil {
				break
			}
		}
		cancelSeries()
		leaseMu.Unlock()
		if ctx.Err() != nil {
			break
		}
	}
	return errWorkerExecution
}

func (processor *outboxProcessor) retryClaims(ctx context.Context, events []apiserver.DiscoveryOutboxEvent, scopes []domain.Scope, token, code string, remaining *atomic.Int64, leaseMu *sync.Mutex) error {
	failed := false
	for index, event := range events {
		completed := false
		for attempt := 0; attempt < outboxAcknowledgementAttempts && !completed; {
			leaseMu.Lock()
			before := int(remaining.Load())
			observed, heartbeatErr := processor.heartbeat(ctx, token, before)
			if heartbeatErr != nil || observed != before {
				leaseMu.Unlock()
				return errWorkerExecution
			}
			seriesCtx, cancelSeries := context.WithTimeout(ctx, processor.config.HeartbeatInterval)
			for attempt < outboxAcknowledgementAttempts {
				attempt++
				result, err := processor.config.Authority.RetryOutboxTopic(seriesCtx, processor.config.Topic, scopes[index], event.ID, processor.config.WorkerID, token, processor.config.RetrySeconds, code)
				if err == nil && result.RemainingCount == before-1 {
					remaining.Store(int64(result.RemainingCount))
					completed = true
					break
				}
				if seriesCtx.Err() != nil {
					break
				}
			}
			cancelSeries()
			leaseMu.Unlock()
		}
		if !completed {
			failed = true
		}
	}
	if failed {
		return errWorkerExecution
	}
	return nil
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
	if expectedTopic == runtimeOutboxTopic {
		return runtimeJobForOutbox(event)
	}
	organization, organizationErr := domain.ParseProductID(event.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(event.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(event.EnvironmentID)
	outboxID, outboxErr := domain.ParseProductID(event.ID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	payloadDigest := sha256.Sum256(event.Payload)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outboxID.IsZero() || event.Topic != expectedTopic || expectedTopic != discoveryOutboxTopic || event.PayloadVersion != 1 || len(event.Payload) == 0 || len(event.Payload) > 65_536 || len(event.PayloadDigest) != sha256.Size || subtle.ConstantTimeCompare(event.PayloadDigest, payloadDigest[:]) != 1 || event.Attempt < 1 || event.Attempt > 100 {
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

type runtimeOutboxPayload struct {
	BatchID           string `json:"batch_id"`
	JobID             string `json:"job_id"`
	Generation        int64  `json:"generation"`
	PipelineVersion   int    `json:"pipeline_version"`
	ArtifactReference string `json:"artifact_reference"`
	ArtifactKey       string `json:"artifact_key"`
	ArtifactVersionID string `json:"artifact_version_id"`
	ArtifactChecksum  string `json:"artifact_checksum"`
	ArtifactSizeBytes int64  `json:"artifact_size_bytes"`
	PayloadMediaType  string `json:"payload_media_type"`
	PayloadSchema     string `json:"payload_schema_version"`
	EventCount        int    `json:"event_count"`
	RequestDigest     string `json:"request_digest"`
}

func runtimeJobForOutbox(event apiserver.DiscoveryOutboxEvent) (jobqueue.Job, domain.Scope, bool) {
	organization, organizationErr := domain.ParseProductID(event.OrganizationID)
	workspace, workspaceErr := domain.ParseProductID(event.WorkspaceID)
	environment, environmentErr := domain.ParseProductID(event.EnvironmentID)
	outboxID, outboxErr := domain.ParseProductID(event.ID)
	scope, scopeErr := domain.NewScope(organization, workspace, environment)
	payloadDigest := sha256.Sum256(event.Payload)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || outboxErr != nil || scopeErr != nil || outboxID.IsZero() || event.Topic != runtimeOutboxTopic || event.PayloadVersion != 15 || len(event.Payload) == 0 || len(event.Payload) > 65_536 || len(event.PayloadDigest) != sha256.Size || subtle.ConstantTimeCompare(event.PayloadDigest, payloadDigest[:]) != 1 || event.Attempt < 1 || event.Attempt > 100 {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var payload runtimeOutboxPayload
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	batchID, batchErr := domain.ParseProductID(payload.BatchID)
	jobID, jobErr := domain.ParseProductID(payload.JobID)
	if batchErr != nil || jobErr != nil || batchID.IsZero() || jobID.IsZero() || payload.Generation < 1 || payload.PipelineVersion != 15 || event.DeterministicKey != "runtime:"+payload.BatchID || !validRuntimeArtifactKey(scope, batchID, payload.Generation, payload.ArtifactKey) || !runtimeS3ReferencePattern.MatchString(payload.ArtifactReference) || !strings.HasSuffix(payload.ArtifactReference, "/"+payload.ArtifactKey) || !validRuntimeVersion(payload.ArtifactVersionID) || !discoveryRequestDigestPattern.MatchString(payload.ArtifactChecksum) || payload.ArtifactChecksum == strings.Repeat("0", 64) || payload.ArtifactSizeBytes < 1 || payload.ArtifactSizeBytes > 64<<20 || payload.PayloadMediaType != "application/json" || payload.PayloadSchema != "runtime-event-v1" || payload.EventCount < 1 || payload.EventCount > 1000 || !discoveryRequestDigestPattern.MatchString(payload.RequestDigest) || payload.RequestDigest == strings.Repeat("0", 64) {
		return jobqueue.Job{}, domain.Scope{}, false
	}
	var authorityDigest [sha256.Size]byte
	copy(authorityDigest[:], event.PayloadDigest)
	return jobqueue.Job{Scope: scope, JobID: jobID, Kind: "runtime", Payload: bytes.Clone(event.Payload), AuthorityDigest: authorityDigest}, scope, true
}

func validRuntimeArtifactKey(scope domain.Scope, batchID domain.ProductID, generation int64, key string) bool {
	parts := strings.Split(key, "/")
	if len(parts) != 8 || parts[0] != "runtime" || parts[1] != "v15" || parts[2] != scope.OrganizationID().String() || parts[3] != scope.WorkspaceID().String() || parts[4] != scope.EnvironmentID().String() || parts[6] != fmt.Sprintf("%020d", generation) || parts[7] != batchID.String()+".json" {
		return false
	}
	sensorID, err := domain.ParseProductID(parts[5])
	return err == nil && !sensorID.IsZero()
}

func validRuntimeVersion(value string) bool {
	return len(value) >= 1 && len(value) <= 1024 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\r\n\x00")
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
