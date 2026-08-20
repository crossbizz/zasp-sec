package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type runtimeDeliveryAuthority interface {
	Ready(context.Context) error
	ClaimDelivery(context.Context, runtimeevent.DeliveryClaimRequest) (runtimeevent.DeliveryClaim, error)
	HeartbeatDelivery(context.Context, runtimeevent.DeliveryClaimRequest) (runtimeevent.DeliveryLeaseResult, error)
	ReleaseDelivery(context.Context, runtimeevent.DeliveryClaimRequest, runtimeevent.DeliveryOutcome, string) (runtimeevent.DeliveryTransitionResult, error)
	AcknowledgeDelivery(context.Context, runtimeevent.DeliveryClaimRequest, [sha256.Size]byte) (runtimeevent.DeliveryTransitionResult, error)
}

type runtimeDeliveryQueue interface {
	ConsumeBatch(context.Context, int) ([]jobqueue.Delivery, error)
	AcknowledgeBatch(context.Context, []jobqueue.Receipt) error
	jobqueue.VisibilityExtender
}

type runtimeCoordinatorConfig struct {
	Authority         runtimeDeliveryAuthority
	Queue             runtimeDeliveryQueue
	WorkerID          string
	LeaseSeconds      int
	VisibilitySeconds int
	BatchSize         int
	HeartbeatInterval time.Duration
	NewLeaseToken     func() (string, error)
}

type runtimeCoordinator struct{ config runtimeCoordinatorConfig }

func newRuntimeCoordinator(config runtimeCoordinatorConfig) (*runtimeCoordinator, error) {
	leaseDuration := time.Duration(config.LeaseSeconds) * time.Second
	if config.Authority == nil || config.Queue == nil || !workerIdentityPattern.MatchString(config.WorkerID) || config.LeaseSeconds < 5 || config.LeaseSeconds > 900 || config.VisibilitySeconds < config.LeaseSeconds || config.VisibilitySeconds > 43_200 || config.BatchSize < 1 || config.BatchSize > 10 || config.HeartbeatInterval < 10*time.Millisecond || config.HeartbeatInterval > leaseDuration/2 || config.NewLeaseToken == nil {
		return nil, errWorkerExecution
	}
	return &runtimeCoordinator{config: config}, nil
}

func (coordinator *runtimeCoordinator) RunOnce(ctx context.Context) error {
	if coordinator == nil || ctx == nil || ctx.Err() != nil {
		return errWorkerExecution
	}
	deliveries, err := coordinator.config.Queue.ConsumeBatch(ctx, coordinator.config.BatchSize)
	if err != nil || len(deliveries) > coordinator.config.BatchSize {
		return errWorkerExecution
	}
	results := make(chan error, len(deliveries))
	for _, delivery := range deliveries {
		delivery := delivery
		go func() { results <- coordinator.callProcess(ctx, delivery) }()
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

func (coordinator *runtimeCoordinator) callProcess(ctx context.Context, delivery jobqueue.Delivery) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = errWorkerExecution
		}
	}()
	return coordinator.process(ctx, delivery)
}

func (coordinator *runtimeCoordinator) process(ctx context.Context, delivery jobqueue.Delivery) error {
	payload, batchID, ok := decodeRuntimeDeliveryJob(delivery.Job)
	messageID := delivery.Receipt.MessageKey()
	if !ok || messageID == "" || delivery.ReceiveCount < 1 || delivery.ReceiveCount > 100 {
		return errWorkerExecution
	}
	leaseToken, err := coordinator.config.NewLeaseToken()
	if err != nil || !runtimeLeaseToken(leaseToken) {
		return errWorkerExecution
	}
	request := runtimeevent.DeliveryClaimRequest{
		Scope: delivery.Job.Scope, BatchID: batchID, Generation: payload.Generation, MessageID: messageID,
		MessageDigest: delivery.Job.AuthorityDigest, ReceiveCount: delivery.ReceiveCount, WorkerID: coordinator.config.WorkerID,
		LeaseToken: leaseToken, LeaseSeconds: coordinator.config.LeaseSeconds, VisibilitySeconds: coordinator.config.VisibilitySeconds,
	}
	claim, err := coordinator.config.Authority.ClaimDelivery(ctx, request)
	if err != nil || !exactRuntimeDeliveryClaim(claim, request) {
		return errWorkerExecution
	}
	return coordinator.handleClaim(ctx, delivery, request, claim)
}

func (coordinator *runtimeCoordinator) handleClaim(ctx context.Context, delivery jobqueue.Delivery, request runtimeevent.DeliveryClaimRequest, claim runtimeevent.DeliveryClaim) error {
	switch claim.Disposition {
	case runtimeevent.DeliveryDispositionBusy:
		return nil
	case runtimeevent.DeliveryDispositionAckTerminal, runtimeevent.DeliveryDispositionQuarantined:
		return coordinator.ackQueue(ctx, delivery.Receipt)
	case runtimeevent.DeliveryDispositionAckPending:
		return coordinator.authorizeAndAck(ctx, delivery.Receipt, request)
	case runtimeevent.DeliveryDispositionUnknown:
		return errWorkerExecution
	case runtimeevent.DeliveryDispositionClaimed:
		return coordinator.waitForTerminal(ctx, delivery.Receipt, request)
	default:
		return errWorkerExecution
	}
}

func (coordinator *runtimeCoordinator) waitForTerminal(ctx context.Context, receipt jobqueue.Receipt, request runtimeevent.DeliveryClaimRequest) error {
	ticker := time.NewTicker(coordinator.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return errWorkerExecution
		case <-ticker.C:
			operationCtx, cancel := context.WithTimeout(ctx, coordinator.operationTimeout())
			lease, heartbeatErr := coordinator.config.Authority.HeartbeatDelivery(operationCtx, request)
			visibilityErr := error(nil)
			if heartbeatErr == nil && exactRuntimeDeliveryLease(lease, request) {
				visibilityErr = coordinator.config.Queue.ExtendVisibility(operationCtx, []jobqueue.Receipt{receipt}, time.Duration(request.VisibilitySeconds)*time.Second)
			} else if heartbeatErr == nil {
				heartbeatErr = errWorkerExecution
			}
			if heartbeatErr != nil || visibilityErr != nil {
				cancel()
				return errWorkerExecution
			}
			claim, claimErr := coordinator.config.Authority.ClaimDelivery(operationCtx, request)
			cancel()
			if claimErr != nil || !exactRuntimeDeliveryClaim(claim, request) {
				return errWorkerExecution
			}
			switch claim.Disposition {
			case runtimeevent.DeliveryDispositionClaimed:
				continue
			case runtimeevent.DeliveryDispositionAckPending:
				return coordinator.authorizeAndAck(ctx, receipt, request)
			case runtimeevent.DeliveryDispositionAckTerminal, runtimeevent.DeliveryDispositionQuarantined:
				return coordinator.ackQueue(ctx, receipt)
			case runtimeevent.DeliveryDispositionUnknown:
				return errWorkerExecution
			default:
				return errWorkerExecution
			}
		}
	}
}

// authorizeAndAck persists the exact, replayable delete authority before the
// provider delete. If the process loses the provider response, redelivery sees
// ack_terminal and repeats only the final SQS delete, never a pipeline effect.
func (coordinator *runtimeCoordinator) authorizeAndAck(ctx context.Context, receipt jobqueue.Receipt, request runtimeevent.DeliveryClaimRequest) error {
	ackDigest := runtimeQueueAcknowledgementDigest(request.MessageID)
	operationCtx, cancel := context.WithTimeout(ctx, coordinator.operationTimeout())
	defer cancel()
	result, err := coordinator.config.Authority.AcknowledgeDelivery(operationCtx, request, ackDigest)
	if err != nil || result.BatchID != request.BatchID || result.Generation != request.Generation || result.Disposition != runtimeevent.DeliveryDispositionAcked {
		return errWorkerExecution
	}
	if err := coordinator.config.Queue.AcknowledgeBatch(operationCtx, []jobqueue.Receipt{receipt}); err != nil {
		return errWorkerExecution
	}
	return nil
}

func (coordinator *runtimeCoordinator) ackQueue(ctx context.Context, receipt jobqueue.Receipt) error {
	operationCtx, cancel := context.WithTimeout(ctx, coordinator.operationTimeout())
	defer cancel()
	if err := coordinator.config.Queue.AcknowledgeBatch(operationCtx, []jobqueue.Receipt{receipt}); err != nil {
		return errWorkerExecution
	}
	return nil
}

func (coordinator *runtimeCoordinator) operationTimeout() time.Duration {
	return minDuration(time.Duration(coordinator.config.LeaseSeconds)*time.Second/3, 10*time.Second)
}

func runtimeQueueAcknowledgementDigest(messageID string) [sha256.Size]byte {
	return sha256.Sum256([]byte("zasp-runtime-sqs-ack-v1\x00" + messageID))
}

func decodeRuntimeDeliveryJob(job jobqueue.Job) (runtimeOutboxPayload, domain.ProductID, bool) {
	if job.Scope.Validate() != nil || job.JobID.IsZero() || job.Kind != "runtime" || len(job.Payload) < 1 || len(job.Payload) > 65_536 || job.AuthorityDigest == ([sha256.Size]byte{}) {
		return runtimeOutboxPayload{}, domain.ProductID{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(job.Payload))
	decoder.DisallowUnknownFields()
	var payload runtimeOutboxPayload
	if err := decoder.Decode(&payload); err != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
		return runtimeOutboxPayload{}, domain.ProductID{}, false
	}
	batchID, batchErr := domain.ParseProductID(payload.BatchID)
	jobID, jobErr := domain.ParseProductID(payload.JobID)
	if batchErr != nil || jobErr != nil || batchID.IsZero() || jobID != job.JobID || payload.Generation < 1 || payload.PipelineVersion != 15 || !validRuntimeArtifactKey(job.Scope, batchID, payload.Generation, payload.ArtifactKey) || !runtimeS3ReferencePattern.MatchString(payload.ArtifactReference) || !strings.HasSuffix(payload.ArtifactReference, "/"+payload.ArtifactKey) || !validRuntimeVersion(payload.ArtifactVersionID) || !discoveryRequestDigestPattern.MatchString(payload.ArtifactChecksum) || payload.ArtifactChecksum == strings.Repeat("0", 64) || payload.ArtifactSizeBytes < 1 || payload.ArtifactSizeBytes > 64<<20 || payload.PayloadMediaType != "application/json" || payload.PayloadSchema != "runtime-event-v1" || payload.EventCount < 1 || payload.EventCount > 1000 || !discoveryRequestDigestPattern.MatchString(payload.RequestDigest) || payload.RequestDigest == strings.Repeat("0", 64) {
		return runtimeOutboxPayload{}, domain.ProductID{}, false
	}
	return payload, batchID, true
}

func runtimeLeaseToken(value string) bool {
	return len(value) >= 16 && len(value) <= 128 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func exactRuntimeDeliveryClaim(claim runtimeevent.DeliveryClaim, request runtimeevent.DeliveryClaimRequest) bool {
	return claim.Scope == request.Scope && claim.BatchID == request.BatchID && claim.Generation == request.Generation
}

func exactRuntimeDeliveryLease(lease runtimeevent.DeliveryLeaseResult, request runtimeevent.DeliveryClaimRequest) bool {
	return lease.BatchID == request.BatchID && lease.Generation == request.Generation && lease.LeaseExpiresAt.After(time.Now()) && lease.VisibilityDeadline.After(time.Now()) && !lease.VisibilityDeadline.Before(lease.LeaseExpiresAt)
}
