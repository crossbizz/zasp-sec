package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

func TestRuntimeCoordinatorHeartbeatsAndAuthorizesBeforeQueueAck(t *testing.T) {
	steps := &runtimeCoordinatorSteps{}
	queue, driver, job := runtimeCoordinatorQueue(t, steps)
	authority := &runtimeCoordinatorAuthority{steps: steps}
	processor, err := newRuntimeCoordinator(runtimeCoordinatorConfig{
		Authority: authority, Queue: queue, WorkerID: "runtime-coordinator-01", LeaseSeconds: 5,
		VisibilitySeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce() error = %v; steps=%v", err, steps.snapshot())
	}
	messageKey := "sha256_" + fmt.Sprintf("%x", sha256.Sum256([]byte(driver.messageID)))
	wantDigest := sha256.Sum256([]byte("zasp-runtime-sqs-ack-v1\x00" + messageKey))
	if authority.claimRequest.BatchID.String() != runtimeCoordinatorPayload(t, job).BatchID || authority.claimRequest.MessageID != "sha256_"+fmt.Sprintf("%x", sha256.Sum256([]byte(driver.messageID))) || authority.claimRequest.MessageDigest != job.AuthorityDigest || authority.providerAck != wantDigest {
		t.Fatalf("claim/provider authority = %#v / %x", authority.claimRequest, authority.providerAck)
	}
	ordered := steps.snapshot()
	for _, required := range []string{"claim", "heartbeat", "visibility", "claim", "db-ack", "queue-ack"} {
		if !containsRuntimeStep(ordered, required) {
			t.Fatalf("steps = %v, missing %q", ordered, required)
		}
	}
	if runtimeStepIndex(ordered, "db-ack") > runtimeStepIndex(ordered, "queue-ack") {
		t.Fatalf("queue ACK was not last: %v", ordered)
	}
}

func TestRuntimeCoordinatorReplaysQueueAckWithoutRepeatingDatabaseMutation(t *testing.T) {
	steps := &runtimeCoordinatorSteps{}
	queue, driver, _ := runtimeCoordinatorQueue(t, steps)
	driver.failAcknowledgements = 1
	authority := &runtimeCoordinatorAuthority{steps: steps}
	processor, err := newRuntimeCoordinator(runtimeCoordinatorConfig{
		Authority: authority, Queue: queue, WorkerID: "runtime-coordinator-01", LeaseSeconds: 5,
		VisibilitySeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond,
		NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := processor.RunOnce(ctx); !errors.Is(err, errWorkerExecution) {
		t.Fatalf("first RunOnce() error = %v", err)
	}
	if authority.acknowledgements != 1 || driver.acknowledgements != 1 {
		t.Fatalf("first acknowledgements db=%d queue=%d", authority.acknowledgements, driver.acknowledgements)
	}
	if err := processor.RunOnce(ctx); err != nil {
		t.Fatalf("replay RunOnce() error = %v", err)
	}
	if authority.acknowledgements != 1 || driver.acknowledgements != 2 {
		t.Fatalf("replay acknowledgements db=%d queue=%d", authority.acknowledgements, driver.acknowledgements)
	}
}

func TestRuntimeCoordinatorRejectsUnboundRuntimeMessagesBeforeClaim(t *testing.T) {
	for name, mutate := range map[string]func(*jobqueue.Job){
		"kind":             func(job *jobqueue.Job) { job.Kind = "discovery" },
		"authority digest": func(job *jobqueue.Job) { job.AuthorityDigest = [sha256.Size]byte{} },
		"job": func(job *jobqueue.Job) {
			var payload runtimeOutboxPayload
			_ = json.Unmarshal(job.Payload, &payload)
			payload.JobID = "pid_70000001-0000-4000-8000-000000000099"
			job.Payload, _ = json.Marshal(payload)
		},
	} {
		t.Run(name, func(t *testing.T) {
			steps := &runtimeCoordinatorSteps{}
			job := runtimeCoordinatorJob(t)
			mutate(&job)
			queue, driver := runtimeCoordinatorQueueForJob(t, steps, job)
			authority := &runtimeCoordinatorAuthority{steps: steps}
			processor, err := newRuntimeCoordinator(runtimeCoordinatorConfig{Authority: authority, Queue: queue, WorkerID: "runtime-coordinator-01", LeaseSeconds: 5, VisibilitySeconds: 5, BatchSize: 1, HeartbeatInterval: 10 * time.Millisecond, NewLeaseToken: func() (string, error) { return "0123456789abcdef", nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err := processor.RunOnce(context.Background()); !errors.Is(err, errWorkerExecution) || authority.claims != 0 || driver.acknowledgements != 0 {
				t.Fatalf("RunOnce=%v claims=%d acks=%d", err, authority.claims, driver.acknowledgements)
			}
		})
	}
}

type runtimeCoordinatorAuthority struct {
	mu               sync.Mutex
	steps            *runtimeCoordinatorSteps
	claims           int
	heartbeats       int
	acknowledgements int
	claimRequest     runtimeevent.DeliveryClaimRequest
	providerAck      [sha256.Size]byte
}

func (authority *runtimeCoordinatorAuthority) Ready(context.Context) error { return nil }

func (authority *runtimeCoordinatorAuthority) ClaimDelivery(_ context.Context, request runtimeevent.DeliveryClaimRequest) (runtimeevent.DeliveryClaim, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.claims++
	authority.claimRequest = request
	authority.steps.add("claim")
	disposition := runtimeevent.DeliveryDispositionClaimed
	if authority.acknowledgements > 0 {
		disposition = runtimeevent.DeliveryDispositionAckTerminal
	} else if authority.claims > 1 {
		disposition = runtimeevent.DeliveryDispositionAckPending
	}
	return runtimeevent.DeliveryClaim{Scope: request.Scope, BatchID: request.BatchID, Generation: request.Generation, Disposition: disposition, LeaseExpiresAt: time.Now().Add(time.Minute), VisibilityDeadline: time.Now().Add(time.Minute)}, nil
}

func (authority *runtimeCoordinatorAuthority) HeartbeatDelivery(_ context.Context, request runtimeevent.DeliveryClaimRequest) (runtimeevent.DeliveryLeaseResult, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.heartbeats++
	authority.steps.add("heartbeat")
	return runtimeevent.DeliveryLeaseResult{BatchID: request.BatchID, Generation: request.Generation, LeaseExpiresAt: time.Now().Add(time.Minute), VisibilityDeadline: time.Now().Add(time.Minute)}, nil
}

func (*runtimeCoordinatorAuthority) ReleaseDelivery(context.Context, runtimeevent.DeliveryClaimRequest, runtimeevent.DeliveryOutcome, string) (runtimeevent.DeliveryTransitionResult, error) {
	return runtimeevent.DeliveryTransitionResult{}, errors.New("unexpected release")
}

func (authority *runtimeCoordinatorAuthority) AcknowledgeDelivery(_ context.Context, request runtimeevent.DeliveryClaimRequest, digest [sha256.Size]byte) (runtimeevent.DeliveryTransitionResult, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.acknowledgements++
	authority.providerAck = digest
	authority.steps.add("db-ack")
	return runtimeevent.DeliveryTransitionResult{BatchID: request.BatchID, Generation: request.Generation, Disposition: runtimeevent.DeliveryDispositionAcked}, nil
}

type runtimeCoordinatorQueueDriver struct {
	mu                   sync.Mutex
	steps                *runtimeCoordinatorSteps
	message              jobqueue.DriverMessage
	messageID            string
	acknowledgements     int
	visibilityExtensions int
	failAcknowledgements int
}

func (driver *runtimeCoordinatorQueueDriver) PublishBatch(_ context.Context, messages []jobqueue.DriverMessage) ([]jobqueue.DriverPublished, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.message = messages[0]
	return []jobqueue.DriverPublished{{EntryID: messages[0].EntryID, JobID: messages[0].JobID, MessageID: driver.messageID}}, nil
}

func (driver *runtimeCoordinatorQueueDriver) ConsumeBatch(context.Context, int) ([]jobqueue.DriverDelivery, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return []jobqueue.DriverDelivery{{Message: driver.message, MessageID: driver.messageID, ReceiptHandle: "runtime-receipt-handle", ReceiveCount: 1}}, nil
}

func (driver *runtimeCoordinatorQueueDriver) AcknowledgeBatch(_ context.Context, receipts []jobqueue.DriverReceipt) ([]domain.ProductID, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.acknowledgements++
	driver.steps.add("queue-ack")
	if driver.failAcknowledgements > 0 {
		driver.failAcknowledgements--
		return nil, errors.New("lost queue acknowledgement")
	}
	return []domain.ProductID{receipts[0].JobID}, nil
}

func (driver *runtimeCoordinatorQueueDriver) ExtendVisibility(_ context.Context, receipts []jobqueue.DriverReceipt, _ int32) ([]domain.ProductID, error) {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	driver.visibilityExtensions++
	driver.steps.add("visibility")
	return []domain.ProductID{receipts[0].JobID}, nil
}

type runtimeCoordinatorSteps struct {
	mu    sync.Mutex
	items []string
}

func (steps *runtimeCoordinatorSteps) add(value string) {
	steps.mu.Lock()
	defer steps.mu.Unlock()
	steps.items = append(steps.items, value)
}

func (steps *runtimeCoordinatorSteps) snapshot() []string {
	steps.mu.Lock()
	defer steps.mu.Unlock()
	return append([]string(nil), steps.items...)
}

func runtimeCoordinatorQueue(t *testing.T, steps *runtimeCoordinatorSteps) (*jobqueue.Queue, *runtimeCoordinatorQueueDriver, jobqueue.Job) {
	t.Helper()
	job := runtimeCoordinatorJob(t)
	queue, driver := runtimeCoordinatorQueueForJob(t, steps, job)
	return queue, driver, job
}

func runtimeCoordinatorQueueForJob(t *testing.T, steps *runtimeCoordinatorSteps, job jobqueue.Job) (*jobqueue.Queue, *runtimeCoordinatorQueueDriver) {
	t.Helper()
	driver := &runtimeCoordinatorQueueDriver{steps: steps, messageID: "runtime-message-0001"}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := queue.PublishBatch(context.Background(), []jobqueue.Job{job}); err != nil {
		t.Fatal(err)
	}
	return queue, driver
}

func runtimeCoordinatorJob(t *testing.T) jobqueue.Job {
	t.Helper()
	scope := workerScope(t)
	batchID := workerID(t, "pid_70000001-0000-4000-8000-000000000001")
	jobID := workerID(t, "pid_70000001-0000-4000-8000-000000000002")
	sensorID := workerID(t, "pid_70000001-0000-4000-8000-000000000003")
	artifactDigest := sha256.Sum256([]byte("runtime-artifact"))
	requestDigest := sha256.Sum256([]byte("runtime-request"))
	key := fmt.Sprintf("runtime/v15/%s/%s/%s/%s/%020d/%s.json", scope.OrganizationID(), scope.WorkspaceID(), scope.EnvironmentID(), sensorID, 1, batchID)
	payload, err := json.Marshal(runtimeOutboxPayload{BatchID: batchID.String(), JobID: jobID.String(), Generation: 1, PipelineVersion: 15, ArtifactReference: "s3://runtime-evidence/" + key, ArtifactKey: key, ArtifactVersionID: "runtime-version-0001", ArtifactChecksum: fmt.Sprintf("%x", artifactDigest), ArtifactSizeBytes: 1024, PayloadMediaType: "application/json", PayloadSchema: "runtime-event-v1", EventCount: 1, RequestDigest: fmt.Sprintf("%x", requestDigest)})
	if err != nil {
		t.Fatal(err)
	}
	return jobqueue.Job{Scope: scope, JobID: jobID, Kind: "runtime", Payload: payload, AuthorityDigest: sha256.Sum256(payload)}
}

func runtimeCoordinatorPayload(t *testing.T, job jobqueue.Job) runtimeOutboxPayload {
	t.Helper()
	var payload runtimeOutboxPayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func runtimeStepIndex(steps []string, value string) int {
	for index, step := range steps {
		if step == value {
			return index
		}
	}
	return -1
}

func containsRuntimeStep(steps []string, value string) bool {
	return runtimeStepIndex(steps, value) >= 0
}
