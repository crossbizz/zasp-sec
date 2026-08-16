package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunJobQueueProofRoundTripsTwoScopedJobsAndCleans(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if err != nil {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if result.Publish != 2 || result.Consume != 2 || result.Acknowledge != 2 ||
		!result.Scoped || !result.Redrive || !result.Empty || !result.Cleanup || !result.Audit {
		t.Fatalf("result = %#v", result)
	}
	if names := fake.queueNames(); len(names) != 0 {
		t.Fatalf("queues remain = %v", names)
	}
	events := fake.eventSnapshot()
	sourceDelete := indexOfEvent(events, "delete-queue:zasp-m1-13-"+testMarker+"-source")
	dlqDelete := indexOfEvent(events, "delete-queue:zasp-m1-13-"+testMarker+"-dlq")
	if sourceDelete < 0 || dlqDelete < 0 || sourceDelete >= dlqDelete {
		t.Fatalf("cleanup order = %v", events)
	}
	if fake.sendCalls != 1 || fake.receiveCalls < 3 || fake.deleteCalls != 1 {
		t.Fatalf("batch calls send=%d receive=%d delete=%d", fake.sendCalls, fake.receiveCalls, fake.deleteCalls)
	}
}

func TestRunJobQueueProofReconcilesOnlyAmbiguousAppliedCreate(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.ambiguousCreate = map[string]bool{"dlq": true, "source": true}
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if err != nil {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
		t.Fatalf("result = %#v, queues = %v", result, fake.queueNames())
	}
}

func TestRunJobQueueProofPollsDelayedAmbiguousVisibility(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.ambiguousCreate = map[string]bool{"dlq": true}
	fake.hideAfterCreate = 2
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if err != nil {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
		t.Fatalf("result = %#v, queues = %v", result, fake.queueNames())
	}
}

func TestRunJobQueueProofCollectsPartialReorderedStandardQueueDeliveries(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.receiveOneAtATime = true
	fake.reverseReceiveOrder = true
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if err != nil || result.Consume != 2 || result.Acknowledge != 2 || !result.Empty || !result.Cleanup || !result.Audit {
		t.Fatalf("RunJobQueueProof() = %#v, %v", result, err)
	}
	if fake.receiveCalls < 4 {
		t.Fatalf("receive calls = %d, want partial reads plus two empty proofs", fake.receiveCalls)
	}
}

func TestRunJobQueueProofCleansMalformedSuccessAndPanicAfterApply(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"malformed", "panic"} {
		t.Run(mode, func(t *testing.T) {
			fake := newJobLifecycleFake()
			fake.createAfterApplyMode = mode
			if mode == "malformed" {
				result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
				if err != nil || !result.Cleanup || !result.Audit {
					t.Fatalf("RunJobQueueProof() = %#v, %v", result, err)
				}
			} else {
				result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
				if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit {
					t.Fatalf("RunJobQueueProof() = %#v, %v", result, err)
				}
			}
			if len(fake.queueNames()) != 0 {
				t.Fatalf("queues remain = %v", fake.queueNames())
			}
		})
	}
}

func TestRunJobQueueProofWaitsForDelayedMalformedSuccessBeforeCleanup(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.createAfterApplyMode = "malformed"
	fake.hideAfterCreate = 3
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if err != nil || !result.Cleanup || !result.Audit {
		t.Fatalf("RunJobQueueProof() = %#v, %v", result, err)
	}
	if names := fake.queueNames(); len(names) != 0 {
		t.Fatalf("delayed malformed-success queue remains = %v", names)
	}
}

func TestRunJobQueueProofRearmsDelayedPanicCandidateBeforeCleanup(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.createAfterApplyMode = "panic"
	fake.hideAfterCreate = 3
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if !errors.Is(err, errProvider) || !result.Cleanup || !result.Audit {
		t.Fatalf("RunJobQueueProof() = %#v, %v", result, err)
	}
	if names := fake.queueNames(); len(names) != 0 {
		t.Fatalf("delayed panic-applied queue remains = %v", names)
	}
}

func TestRunJobQueueProofRearmPanicDoesNotStopLaterCleanup(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.createAfterApplyMode = "panic"
	fake.createAfterApplyRole = "source"
	fake.panicRearmRole = "source"
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if !errors.Is(err, errCleanup) || result.Cleanup || result.Audit {
		t.Fatalf("RunJobQueueProof() = %#v, %v", result, err)
	}
	names := fake.queueNames()
	if len(names) != 1 || !strings.HasSuffix(names[0], "-source") {
		t.Fatalf("later DLQ cleanup did not continue after rearm panic: %v", names)
	}
}

func TestQueueMutationClassificationSeparatesHTTPRejectionFromAmbiguity(t *testing.T) {
	t.Parallel()

	if !mutationIsDefinitive(classifyQueueMutationError(statusCodeError{code: 409})) {
		t.Fatal("HTTP 409 was not definitive")
	}
	if mutationIsDefinitive(classifyQueueMutationError(statusCodeError{code: 201})) {
		t.Fatal("unexpected HTTP 201 error was definitive")
	}
	if mutationIsDefinitive(classifyQueueMutationError(errors.New("transport ended after send"))) {
		t.Fatal("transport ambiguity was definitive")
	}
}

func TestRunJobQueueProofNeverAdoptsDefinitiveCreateRejection(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.definitiveCreateRole = "dlq"
	_, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if !errors.Is(err, errProvider) {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if fake.listAfterDefinitive {
		t.Fatal("definitive create rejection entered reconciliation")
	}
	if len(fake.queueNames()) != 0 {
		t.Fatalf("queues remain = %v", fake.queueNames())
	}
}

func TestRunJobQueueProofRejectsPrefixCollisionWithoutDeletion(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	name := "zasp-m1-13-" + testMarker + "-foreign"
	fake.addQueue(name, nil, map[string]string{"foreign": "true"})
	_, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if !errors.Is(err, errOwnership) {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if names := fake.queueNames(); len(names) != 1 || names[0] != name {
		t.Fatalf("collision was mutated: %v", names)
	}
}

func TestRunJobQueueProofUsesIndependentCleanupAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	fake := newJobLifecycleFake()
	fake.cancelAtJobSend = cancel
	result, err := RunJobQueueProof(ctx, jobProofOptions(fake))
	if err == nil {
		t.Fatal("RunJobQueueProof() error = nil")
	}
	if !result.Cleanup || !result.Audit || len(fake.queueNames()) != 0 {
		t.Fatalf("result = %#v, queues = %v", result, fake.queueNames())
	}
}

func TestRunJobQueueProofCleanupFailureWinsAndLaterCleanupContinues(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.mutateSourceTagsBeforeDelete = true
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if result.Cleanup || result.Audit {
		t.Fatalf("result = %#v", result)
	}
	names := fake.queueNames()
	if len(names) != 1 || !strings.HasSuffix(names[0], "-source") {
		t.Fatalf("later DLQ cleanup did not continue: %v", names)
	}
}

func TestRunJobQueueProofCleanupPanicDoesNotStopLaterTargets(t *testing.T) {
	t.Parallel()

	fake := newJobLifecycleFake()
	fake.panicStep = "delete-queue:source"
	result, err := RunJobQueueProof(context.Background(), jobProofOptions(fake))
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunJobQueueProof() error = %v", err)
	}
	if result.Cleanup || result.Audit {
		t.Fatalf("result = %#v", result)
	}
	names := fake.queueNames()
	if len(names) != 1 || !strings.HasSuffix(names[0], "-source") {
		t.Fatalf("cleanup panic stopped later target: %v", names)
	}
}

func TestDisposableJobQueueEndpointAcceptsOnlyNumericHighLoopbackPort(t *testing.T) {
	t.Parallel()

	endpoint, err := validateDisposableJobEndpoint(context.Background(), "http://127.0.0.1:49152")
	if err != nil || endpoint.baseURL != "http://127.0.0.1:49152" || endpoint.port != "49152" {
		t.Fatalf("validateDisposableJobEndpoint() = %#v, %v", endpoint, err)
	}
	for _, unsafe := range []string{
		"http://127.0.0.1:4566",
		"http://localhost:49152",
		"http://0.0.0.0:49152",
		"http://203.0.113.10:49152",
		"https://127.0.0.1:49152",
		"http://127.0.0.1:49152/path",
	} {
		if _, err := validateDisposableJobEndpoint(context.Background(), unsafe); !errors.Is(err, errConfiguration) {
			t.Fatalf("unsafe endpoint %q error = %v", unsafe, err)
		}
	}
	client, err := newDisposableJobSDKQueueClient(context.Background(), "http://127.0.0.1:49152")
	if err != nil {
		t.Fatalf("newDisposableJobSDKQueueClient() error = %v", err)
	}
	options := client.client.Options()
	if options.BaseEndpoint == nil || *options.BaseEndpoint != "http://127.0.0.1:49152" {
		t.Fatalf("client endpoint = %#v", options.BaseEndpoint)
	}
}

func TestFormatJobQueueChildSuccessIsExactAndFixed(t *testing.T) {
	t.Parallel()

	result := JobQueueProofResult{
		Publish: 2, Consume: 2, Acknowledge: 2, Scoped: true,
		Redrive: true, Empty: true, Cleanup: true, Audit: true,
	}
	if got := formatJobQueueChildSuccess(result); got !=
		"LocalStack job queue passed: publish=2 consume=2 acknowledge=2 scoped=true redrive=true empty=true cleanup=true audit=true." {
		t.Fatalf("success line = %q", got)
	}
}

type jobLifecycleFake struct {
	*fakeSQS
	muJob                sync.Mutex
	definitiveCreateRole string
	definitiveRejected   bool
	listAfterDefinitive  bool
	cancelAtJobSend      context.CancelFunc
	sendCalls            int
	receiveCalls         int
	deleteCalls          int
	receiveOneAtATime    bool
	reverseReceiveOrder  bool
	created              bool
	hideAfterCreate      int
	createAfterApplyMode string
	createAfterApplyRole string
	panicRearmRole       string
}

func newJobLifecycleFake() *jobLifecycleFake {
	return &jobLifecycleFake{fakeSQS: newFakeSQS()}
}

func (fake *jobLifecycleFake) ListQueues(ctx context.Context, prefix string) ([]string, error) {
	fake.muJob.Lock()
	if fake.definitiveRejected {
		fake.listAfterDefinitive = true
	}
	fake.muJob.Unlock()
	fake.muJob.Lock()
	if fake.created && fake.hideAfterCreate > 0 {
		fake.hideAfterCreate--
		fake.muJob.Unlock()
		return nil, nil
	}
	fake.muJob.Unlock()
	if roleFromName(prefix) == fake.panicRearmRole {
		panic("provider detail must not escape")
	}
	return fake.fakeSQS.ListQueues(ctx, prefix)
}

func (fake *jobLifecycleFake) CreateQueue(ctx context.Context, name string, attributes, tags map[string]string) (string, error) {
	if roleFromName(name) == fake.definitiveCreateRole {
		fake.muJob.Lock()
		fake.definitiveRejected = true
		fake.muJob.Unlock()
		return "", definitiveMutationError()
	}
	returnedURL, err := fake.fakeSQS.CreateQueue(ctx, name, attributes, tags)
	fake.muJob.Lock()
	fake.created = true
	mode := fake.createAfterApplyMode
	if fake.createAfterApplyRole == "" || fake.createAfterApplyRole == roleFromName(name) {
		fake.createAfterApplyMode = ""
	} else {
		mode = ""
	}
	fake.muJob.Unlock()
	fake.mu.Lock()
	if queue := fake.queues[name]; queue != nil {
		queue.url = strings.Replace(queue.url, ":4566/", ":49152/", 1)
	}
	fake.mu.Unlock()
	if returnedURL != "" {
		returnedURL = strings.Replace(returnedURL, ":4566/", ":49152/", 1)
	}
	switch mode {
	case "malformed":
		return "", nil
	case "panic":
		panic("provider detail must not escape")
	}
	return returnedURL, err
}

func (fake *jobLifecycleFake) SendJobBatch(ctx context.Context, queueURL string, entries []outgoingMessage) (jobBatchSendResult, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.sendCalls++
	queue := fake.queueByURL(queueURL)
	if queue == nil {
		return jobBatchSendResult{}, errors.New("not found")
	}
	if fake.cancelAtJobSend != nil {
		fake.cancelAtJobSend()
	}
	if err := ctx.Err(); err != nil {
		return jobBatchSendResult{}, err
	}
	result := jobBatchSendResult{}
	for index, entry := range entries {
		messageID := "job-provider-message-" + string(rune('1'+index))
		receipt := "job-provider-receipt-" + string(rune('1'+index))
		queue.messages = append(queue.messages, receivedMessage{
			Body: entry.Body, Attributes: cloneMessageAttributes(entry.Attributes),
			MessageID: messageID, ReceiptHandle: receipt, BodyDigest: md5Hex(entry.Body),
		})
		result.Successful = append(result.Successful, jobBatchSendSuccess{
			ID: entry.ID, MessageID: messageID, BodyDigest: md5Hex(entry.Body),
		})
	}
	return result, nil
}

func (fake *jobLifecycleFake) ReceiveJobMessages(_ context.Context, queueURL string, maximum int) ([]receivedMessage, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.receiveCalls++
	queue := fake.queueByURL(queueURL)
	if queue == nil {
		return nil, errors.New("not found")
	}
	if fake.receiveOneAtATime {
		index := fake.receiveCalls - 1
		if index >= len(queue.messages) {
			return nil, nil
		}
		if fake.reverseReceiveOrder {
			index = len(queue.messages) - 1 - index
		}
		return []receivedMessage{queue.messages[index]}, nil
	}
	count := len(queue.messages)
	if count > maximum {
		count = maximum
	}
	result := make([]receivedMessage, count)
	copy(result, queue.messages[:count])
	return result, nil
}

func (fake *jobLifecycleFake) DeleteJobBatch(_ context.Context, queueURL string, entries []jobDeleteEntry) (jobBatchDeleteResult, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.deleteCalls++
	queue := fake.queueByURL(queueURL)
	if queue == nil {
		return jobBatchDeleteResult{}, errors.New("not found")
	}
	byReceipt := make(map[string]int, len(queue.messages))
	for index, message := range queue.messages {
		byReceipt[message.ReceiptHandle] = index
	}
	result := jobBatchDeleteResult{}
	for _, entry := range entries {
		if _, exists := byReceipt[entry.ReceiptHandle]; !exists {
			result.FailedIDs = append(result.FailedIDs, entry.ID)
			continue
		}
		result.SuccessfulIDs = append(result.SuccessfulIDs, entry.ID)
	}
	if len(result.FailedIDs) == 0 {
		queue.messages = nil
	}
	return result, nil
}

func jobProofOptions(client jobQueueProofClient) JobQueueProofOptions {
	return JobQueueProofOptions{
		Endpoint:       "http://127.0.0.1:49152",
		Marker:         testMarker,
		Client:         client,
		CleanupTimeout: 100 * time.Millisecond,
		PollInterval:   time.Millisecond,
	}
}

func indexOfEvent(events []string, target string) int {
	for index, event := range events {
		if event == target {
			return index
		}
	}
	return -1
}

type statusCodeError struct {
	code int
}

func (err statusCodeError) Error() string {
	return "provider detail"
}

func (err statusCodeError) HTTPStatusCode() int {
	return err.code
}
