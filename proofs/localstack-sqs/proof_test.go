package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const testMarker = "0123456789abcdef"

func TestRunProofRejectsMissingEndpoint(t *testing.T) {
	t.Parallel()

	err := RunProof(context.Background(), ProofOptions{})
	if !errors.Is(err, errConfiguration) {
		t.Fatalf("RunProof() error = %v, want fixed configuration error", err)
	}
}

func TestRunProofRoundTripsOneScopedBatchAndCleansInOrder(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	err := RunProof(context.Background(), testOptions(fake))
	if err != nil {
		t.Fatalf("RunProof() error = %v", err)
	}

	want := []string{
		"list:zasp-m0-06-0123456789abcdef",
		"create:zasp-m0-06-0123456789abcdef-dlq",
		"attributes:zasp-m0-06-0123456789abcdef-dlq",
		"tags:zasp-m0-06-0123456789abcdef-dlq",
		"create:zasp-m0-06-0123456789abcdef-source",
		"attributes:zasp-m0-06-0123456789abcdef-source",
		"tags:zasp-m0-06-0123456789abcdef-source",
		"set-attributes:zasp-m0-06-0123456789abcdef-dlq",
		"attributes:zasp-m0-06-0123456789abcdef-dlq",
		"attributes:zasp-m0-06-0123456789abcdef-source",
		"send-batch:zasp-m0-06-0123456789abcdef-source",
		"receive:zasp-m0-06-0123456789abcdef-source",
		"delete-message-batch:zasp-m0-06-0123456789abcdef-source",
		"receive:zasp-m0-06-0123456789abcdef-source",
		"receive:zasp-m0-06-0123456789abcdef-source",
		"attributes:zasp-m0-06-0123456789abcdef-source",
		"tags:zasp-m0-06-0123456789abcdef-source",
		"delete-queue:zasp-m0-06-0123456789abcdef-source",
		"list:zasp-m0-06-0123456789abcdef-source",
		"attributes:zasp-m0-06-0123456789abcdef-dlq",
		"tags:zasp-m0-06-0123456789abcdef-dlq",
		"delete-queue:zasp-m0-06-0123456789abcdef-dlq",
		"list:zasp-m0-06-0123456789abcdef-dlq",
	}
	if got := fake.eventSnapshot(); !equalStrings(got, want) {
		t.Fatalf("event order = %#v, want %#v", got, want)
	}
	if len(fake.queueNames()) != 0 {
		t.Fatal("proof queues remain after successful cleanup")
	}
}

func TestRunProofReconcilesAmbiguousCreatesAndDeletes(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	fake.ambiguousCreate = map[string]bool{"dlq": true, "source": true}
	fake.ambiguousDelete = map[string]bool{"dlq": true, "source": true}
	if err := RunProof(context.Background(), testOptions(fake)); err != nil {
		t.Fatalf("RunProof() error = %v", err)
	}
	if len(fake.queueNames()) != 0 {
		t.Fatal("ambiguously deleted queues remain")
	}
}

func TestRunProofReconcilesUntrustedSuccessfulCreateResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		behavior func(*fakeSQS)
	}{
		{name: "malformed returned URL", behavior: func(fake *fakeSQS) {
			fake.createReturnedURLOverride = "http://example.test:4566/000000000000/not-owned"
		}},
		{name: "transient wrong ARN", behavior: func(fake *fakeSQS) {
			fake.transientARN = true
		}},
		{name: "transient tag read failure", behavior: func(fake *fakeSQS) {
			fake.transientTagFailure = true
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSQS()
			test.behavior(fake)
			if err := RunProof(context.Background(), testOptions(fake)); err != nil {
				t.Fatalf("RunProof() error = %v", err)
			}
			if len(fake.queueNames()) != 0 {
				t.Fatal("reconciled successful create stranded a proof queue")
			}
			if !containsPrefix(fake.eventSnapshot(), "list:zasp-m0-06-0123456789abcdef-") {
				t.Fatal("untrusted successful create was not reconciled by exact name")
			}
		})
	}
}

func TestRunProofReprovesOwnershipImmediatelyBeforeDelete(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	fake.mutateSourceTagsBeforeDelete = true
	err := RunProof(context.Background(), testOptions(fake))
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunProof() error = %v, want cleanup error", err)
	}
	if contains(fake.eventSnapshot(), "delete-queue:zasp-m0-06-0123456789abcdef-source") {
		t.Fatal("source queue deleted after fresh ownership proof failed")
	}
	if !contains(fake.queueNames(), "zasp-m0-06-0123456789abcdef-source") {
		t.Fatal("source queue unexpectedly absent after deletion was refused")
	}
	if !contains(fake.eventSnapshot(), "delete-queue:zasp-m0-06-0123456789abcdef-dlq") {
		t.Fatal("DLQ cleanup was skipped after source ownership refusal")
	}
}

func TestRunProofRejectsPreexistingExactNameWithoutMutation(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	fake.addQueue("zasp-m0-06-0123456789abcdef-source", nil, proofTags(testMarker, "source"))
	err := RunProof(context.Background(), testOptions(fake))
	if !errors.Is(err, errOwnership) {
		t.Fatalf("RunProof() error = %v, want ownership error", err)
	}
	for _, event := range fake.eventSnapshot() {
		if strings.HasPrefix(event, "create:") || strings.HasPrefix(event, "delete-queue:") {
			t.Fatalf("preexisting queue was mutated: %q", event)
		}
	}
}

func TestRunProofCleansAfterEveryPostCreateFailure(t *testing.T) {
	t.Parallel()

	steps := []string{
		"create:source", "set-attributes:dlq", "attributes:dlq-policy",
		"attributes:source-policy", "send-batch", "receive", "delete-message-batch",
		"empty-receive",
	}
	for _, step := range steps {
		step := step
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSQS()
			fake.failStep = step
			err := RunProof(context.Background(), testOptions(fake))
			if err == nil {
				t.Fatal("RunProof() error = nil, want categorized failure")
			}
			if len(fake.queueNames()) != 0 {
				t.Fatalf("proof queues remain after %s failure", step)
			}
		})
	}
}

func TestRunProofCleanupFailureWinsAndStillAttemptsDLQ(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	fake.failStep = "send-batch"
	fake.retainOnDelete = map[string]bool{"source": true}
	err := RunProof(context.Background(), testOptions(fake))
	if !errors.Is(err, errCleanup) {
		t.Fatalf("RunProof() error = %v, want cleanup failure", err)
	}
	if !contains(fake.eventSnapshot(), "delete-queue:zasp-m0-06-0123456789abcdef-dlq") {
		t.Fatal("DLQ cleanup was skipped after source cleanup failure")
	}
}

func TestRunProofConvertsPanicToFixedErrorAndCleans(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	fake.panicStep = "send-batch"
	err := RunProof(context.Background(), testOptions(fake))
	if !errors.Is(err, errProvider) {
		t.Fatalf("RunProof() error = %v, want fixed provider error", err)
	}
	if len(fake.queueNames()) != 0 {
		t.Fatal("proof queues remain after panic")
	}
	if strings.Contains(err.Error(), "panic") || strings.Contains(err.Error(), testMarker) {
		t.Fatal("failure exposes internal details")
	}
}

func TestRunProofRejectsMalformedQueueIdentityBeforeOwnership(t *testing.T) {
	t.Parallel()

	tests := []string{
		"https://127.0.0.1:4566/000000000000/zasp-m0-06-0123456789abcdef-dlq",
		"http://example.test:4566/000000000000/zasp-m0-06-0123456789abcdef-dlq",
		"http://127.0.0.1:4566/other/zasp-m0-06-0123456789abcdef-dlq",
		"http://127.0.0.1:4566/000000000000/not-proof-owned",
		"http://user@127.0.0.1:4566/000000000000/zasp-m0-06-0123456789abcdef-dlq",
	}
	for _, queueURL := range tests {
		queueURL := queueURL
		t.Run(queueURL, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSQS()
			fake.createURLOverride = queueURL
			err := RunProof(context.Background(), testOptions(fake))
			if !errors.Is(err, errOwnership) {
				t.Fatalf("RunProof() error = %v, want ownership error", err)
			}
			for _, event := range fake.eventSnapshot() {
				if strings.HasPrefix(event, "delete-queue:") {
					t.Fatal("unproven queue identity was deleted")
				}
			}
		})
	}
}

func TestValidateQueueURLAcceptsExactLocalStackPathStrategy(t *testing.T) {
	t.Parallel()

	name := "zasp-m0-06-0123456789abcdef-dlq"
	queueURL := "http://127.0.0.1:4566/queue/us-east-1/000000000000/" + name
	account, err := validateQueueURL(context.Background(), "http://127.0.0.1:4566", queueURL, name, nil)
	if err != nil || account != "000000000000" {
		t.Fatalf("validateQueueURL() account shape rejected: error=%v", err)
	}
	if got := queueNameFromURL(queueURL); got != name {
		t.Fatalf("queueNameFromURL() returned unexpected shape")
	}
}

func TestRunProofRejectsPolicyAndMessageMismatchesWithCleanup(t *testing.T) {
	t.Parallel()

	tests := []string{
		"foreign-redrive", "extra-redrive-member", "foreign-redrive-allow",
		"partial-send", "foreign-message", "foreign-organization", "bad-digest",
	}
	for _, mutation := range tests {
		mutation := mutation
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSQS()
			fake.mutation = mutation
			err := RunProof(context.Background(), testOptions(fake))
			if err == nil {
				t.Fatal("RunProof() error = nil, want policy/message rejection")
			}
			if len(fake.queueNames()) != 0 {
				t.Fatal("queues remain after policy/message rejection")
			}
		})
	}
}

func TestDecodeExactJSONRejectsDuplicatePolicyMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		target any
	}{
		{name: "dead letter expected then foreign", raw: `{"deadLetterTargetArn":"expected","deadLetterTargetArn":"foreign","maxReceiveCount":"3"}`, target: &redrivePolicy{}},
		{name: "dead letter foreign then expected", raw: `{"deadLetterTargetArn":"foreign","deadLetterTargetArn":"expected","maxReceiveCount":"3"}`, target: &redrivePolicy{}},
		{name: "receive count expected then foreign", raw: `{"deadLetterTargetArn":"expected","maxReceiveCount":"3","maxReceiveCount":"99"}`, target: &redrivePolicy{}},
		{name: "receive count foreign then expected", raw: `{"deadLetterTargetArn":"expected","maxReceiveCount":"99","maxReceiveCount":"3"}`, target: &redrivePolicy{}},
		{name: "permission expected then foreign", raw: `{"redrivePermission":"byQueue","redrivePermission":"allowAll","sourceQueueArns":["expected"]}`, target: &redriveAllowPolicy{}},
		{name: "permission foreign then expected", raw: `{"redrivePermission":"allowAll","redrivePermission":"byQueue","sourceQueueArns":["expected"]}`, target: &redriveAllowPolicy{}},
		{name: "source arns expected then foreign", raw: `{"redrivePermission":"byQueue","sourceQueueArns":["expected"],"sourceQueueArns":["foreign"]}`, target: &redriveAllowPolicy{}},
		{name: "source arns foreign then expected", raw: `{"redrivePermission":"byQueue","sourceQueueArns":["foreign"],"sourceQueueArns":["expected"]}`, target: &redriveAllowPolicy{}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := decodeExactJSON(test.raw, test.target); err == nil {
				t.Fatal("decodeExactJSON() accepted a duplicate known policy member")
			}
		})
	}
}

func TestDecodeExactJSONRejectsNestedDuplicateEnvelopeMembers(t *testing.T) {
	t.Parallel()

	raw := `{"version":"1","batch_id":"batch","organization_id":"org","workspace_id":"workspace","environment_id":"environment","events":[{"event_id":"first","organization_id":"org","organization_id":"foreign","kind":"event","sequence":1}]}`
	if err := decodeExactJSON(raw, &eventEnvelope{}); err == nil {
		t.Fatal("decodeExactJSON() accepted a nested duplicate envelope member")
	}
}

func TestRunProofHonorsCancellationAndUsesIndependentCleanupContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	fake := newFakeSQS()
	fake.cancelAtSend = cancel
	err := RunProof(ctx, testOptions(fake))
	if err == nil {
		t.Fatal("RunProof() error = nil after cancellation")
	}
	if len(fake.queueNames()) != 0 {
		t.Fatal("queues remain after caller cancellation")
	}
}

func TestValidateEndpointRejectsUnsafeDestinations(t *testing.T) {
	t.Parallel()

	unsafe := []string{
		"", "https://127.0.0.1:4566", "http://example.com:4566",
		"http://0.0.0.0:4566", "http://127.0.0.1:4567",
		"http://user@127.0.0.1:4566", "http://127.0.0.1:4566/path",
		"http://127.0.0.1:4566?x=1", "http://127.0.0.1:4566/#fragment",
	}
	for _, raw := range unsafe {
		if _, err := validateEndpoint(context.Background(), raw, nil); !errors.Is(err, errConfiguration) {
			t.Errorf("validateEndpoint(%q) error = %v, want configuration error", raw, err)
		}
	}
	if _, err := validateEndpoint(context.Background(), "http://localhost:4566", staticResolver{"203.0.113.10"}); !errors.Is(err, errConfiguration) {
		t.Fatalf("non-loopback DNS error = %v, want configuration error", err)
	}
	if _, err := validateEndpoint(context.Background(), "http://127.0.0.1:4566", nil); err != nil {
		t.Fatalf("loopback endpoint rejected: %v", err)
	}
}

func TestBuildEnvelopeRequiresSharedOrganizationScope(t *testing.T) {
	t.Parallel()

	body, envelope, err := buildEnvelope(testMarker)
	if err != nil {
		t.Fatalf("buildEnvelope() error = %v", err)
	}
	if len(envelope.Events) != 2 {
		t.Fatalf("event count = %d, want 2", len(envelope.Events))
	}
	if err := validateEnvelope(body, envelope); err != nil {
		t.Fatalf("validateEnvelope() error = %v", err)
	}
	foreign := envelope
	foreign.Events[1].OrganizationID = "org-foreign"
	if err := validateEnvelope(body, foreign); !errors.Is(err, errMessage) {
		t.Fatalf("foreign Organization error = %v, want message error", err)
	}
}

func TestAuditNoQueuesChecksOnlyExactProofPrefix(t *testing.T) {
	t.Parallel()

	fake := newFakeSQS()
	fake.addQueue("unrelated", nil, nil)
	if err := AuditNoQueues(context.Background(), fake, testMarker); err != nil {
		t.Fatalf("AuditNoQueues() error = %v", err)
	}
	fake.addQueue("zasp-m0-06-0123456789abcdef-source", nil, proofTags(testMarker, "source"))
	if err := AuditNoQueues(context.Background(), fake, testMarker); !errors.Is(err, errCleanup) {
		t.Fatalf("AuditNoQueues() error = %v, want cleanup error", err)
	}
}

type staticResolver []string

func (r staticResolver) LookupHost(context.Context, string) ([]string, error) {
	return append([]string(nil), r...), nil
}

type fakeQueue struct {
	name       string
	url        string
	arn        string
	attributes map[string]string
	tags       map[string]string
	messages   []receivedMessage
}

type fakeSQS struct {
	mu                           sync.Mutex
	queues                       map[string]*fakeQueue
	events                       []string
	ambiguousCreate              map[string]bool
	ambiguousDelete              map[string]bool
	retainOnDelete               map[string]bool
	createURLOverride            string
	createReturnedURLOverride    string
	failStep                     string
	failedStep                   bool
	panicStep                    string
	mutation                     string
	cancelAtSend                 context.CancelFunc
	attributeReads               map[string]int
	tagReads                     map[string]int
	transientARN                 bool
	transientTagFailure          bool
	mutateSourceTagsBeforeDelete bool
}

func newFakeSQS() *fakeSQS {
	return &fakeSQS{queues: make(map[string]*fakeQueue), attributeReads: make(map[string]int), tagReads: make(map[string]int)}
}

func testOptions(client queueAPI) ProofOptions {
	return ProofOptions{
		Endpoint:       "http://127.0.0.1:4566",
		Marker:         testMarker,
		Client:         client,
		CleanupTimeout: 50 * time.Millisecond,
		PollInterval:   time.Millisecond,
	}
}

func (f *fakeSQS) step(event, failKey string) error {
	f.events = append(f.events, event)
	if f.panicStep == failKey {
		panic("provider detail must be discarded")
	}
	if f.failStep == failKey && !f.failedStep {
		f.failedStep = true
		return errors.New("provider detail must be discarded")
	}
	return nil
}

func (f *fakeSQS) ListQueues(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.step("list:"+prefix, "list:"+roleFromName(prefix)); err != nil {
		return nil, err
	}
	var urls []string
	for name, queue := range f.queues {
		if strings.HasPrefix(name, prefix) {
			urls = append(urls, queue.url)
		}
	}
	sort.Strings(urls)
	return urls, nil
}

func (f *fakeSQS) CreateQueue(_ context.Context, name string, attributes, tags map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	role := roleFromName(name)
	if err := f.step("create:"+name, "create:"+role); err != nil {
		return "", err
	}
	queue := f.addQueueLocked(name, attributes, tags)
	if f.createURLOverride != "" {
		queue.url = f.createURLOverride
	}
	if f.ambiguousCreate[role] {
		return "", errors.New("ambiguous create")
	}
	if f.createReturnedURLOverride != "" {
		return f.createReturnedURLOverride, nil
	}
	return queue.url, nil
}

func (f *fakeSQS) GetQueueAttributes(_ context.Context, queueURL string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return nil, errors.New("not found")
	}
	role := roleFromName(queue.name)
	f.attributeReads[role]++
	failKey := "attributes:" + role + "-policy"
	if f.attributeReads[role] == 1 {
		failKey = "attributes:" + role
	}
	if err := f.step("attributes:"+queue.name, failKey); err != nil {
		return nil, err
	}
	got := cloneMap(queue.attributes)
	got[queueARNAttribute] = queue.arn
	if f.transientARN && f.attributeReads[role] == 1 {
		got[queueARNAttribute] = "arn:aws:sqs:us-east-1:000000000000:foreign"
	}
	got[fifoQueueAttribute] = "false"
	if f.mutation == "foreign-redrive" && role == "source" && f.attributeReads[role] > 1 {
		got[redrivePolicyAttribute] = `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:000000000000:foreign","maxReceiveCount":"3"}`
	}
	if f.mutation == "extra-redrive-member" && role == "source" && f.attributeReads[role] > 1 {
		got[redrivePolicyAttribute] = strings.TrimSuffix(got[redrivePolicyAttribute], "}") + `,"extra":true}`
	}
	if f.mutation == "foreign-redrive-allow" && role == "dlq" && f.attributeReads[role] > 1 && got[redriveAllowPolicyAttribute] != "" {
		got[redriveAllowPolicyAttribute] = `{"redrivePermission":"byQueue","sourceQueueArns":["arn:aws:sqs:us-east-1:000000000000:foreign"]}`
	}
	return got, nil
}

func (f *fakeSQS) ListQueueTags(_ context.Context, queueURL string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return nil, errors.New("not found")
	}
	role := roleFromName(queue.name)
	f.tagReads[role]++
	if f.transientTagFailure && f.tagReads[role] == 1 {
		f.events = append(f.events, "tags:"+queue.name)
		return nil, errors.New("transient tag failure")
	}
	if f.mutateSourceTagsBeforeDelete && role == "source" && f.tagReads[role] >= 2 {
		queue.tags["zasp-proof-marker"] = "fedcba9876543210"
	}
	if err := f.step("tags:"+queue.name, "tags:"+role); err != nil {
		return nil, err
	}
	return cloneMap(queue.tags), nil
}

func (f *fakeSQS) SetQueueAttributes(_ context.Context, queueURL string, attributes map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return errors.New("not found")
	}
	if err := f.step("set-attributes:"+queue.name, "set-attributes:"+roleFromName(queue.name)); err != nil {
		return err
	}
	for key, value := range attributes {
		queue.attributes[key] = value
	}
	return nil
}

func (f *fakeSQS) SendMessageBatch(ctx context.Context, queueURL string, entry outgoingMessage) (batchSendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return batchSendResult{}, errors.New("not found")
	}
	if f.cancelAtSend != nil {
		f.cancelAtSend()
	}
	if err := f.step("send-batch:"+queue.name, "send-batch"); err != nil {
		return batchSendResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return batchSendResult{}, err
	}
	messageID := "provider-message-id"
	body := entry.Body
	attributes := cloneMessageAttributes(entry.Attributes)
	if f.mutation == "foreign-message" {
		body = `{"foreign":true}`
	}
	if f.mutation == "foreign-organization" {
		attributes[organizationAttribute] = messageAttribute{DataType: "String", Value: "org-foreign"}
	}
	if f.mutation == "bad-digest" {
		attributes[digestAttribute] = messageAttribute{DataType: "String", Value: strings.Repeat("0", 64)}
	}
	queue.messages = append(queue.messages, receivedMessage{
		Body: body, Attributes: attributes, MessageID: messageID, ReceiptHandle: "receipt-handle",
	})
	if f.mutation == "partial-send" {
		return batchSendResult{SuccessfulIDs: []string{entry.ID}, FailedIDs: []string{"failed-entry"}}, nil
	}
	return batchSendResult{SuccessfulIDs: []string{entry.ID}, MessageID: messageID}, nil
}

func (f *fakeSQS) ReceiveMessages(_ context.Context, queueURL string) ([]receivedMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return nil, errors.New("not found")
	}
	failKey := "receive"
	if len(queue.messages) == 0 {
		failKey = "empty-receive"
	}
	if err := f.step("receive:"+queue.name, failKey); err != nil {
		return nil, err
	}
	return append([]receivedMessage(nil), queue.messages...), nil
}

func (f *fakeSQS) DeleteMessageBatch(_ context.Context, queueURL, receiptHandle string) (batchDeleteResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return batchDeleteResult{}, errors.New("not found")
	}
	if err := f.step("delete-message-batch:"+queue.name, "delete-message-batch"); err != nil {
		return batchDeleteResult{}, err
	}
	if receiptHandle == "" {
		return batchDeleteResult{}, errors.New("empty receipt")
	}
	queue.messages = nil
	return batchDeleteResult{SuccessfulIDs: []string{deleteBatchEntryID}}, nil
}

func (f *fakeSQS) DeleteQueue(_ context.Context, queueURL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.queueByURL(queueURL)
	if queue == nil {
		return errors.New("not found")
	}
	role := roleFromName(queue.name)
	if err := f.step("delete-queue:"+queue.name, "delete-queue:"+role); err != nil {
		return err
	}
	if !f.retainOnDelete[role] {
		delete(f.queues, queue.name)
	}
	if f.ambiguousDelete[role] {
		return errors.New("ambiguous delete")
	}
	return nil
}

func (f *fakeSQS) addQueue(name string, attributes, tags map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addQueueLocked(name, attributes, tags)
}

func (f *fakeSQS) addQueueLocked(name string, attributes, tags map[string]string) *fakeQueue {
	queue := &fakeQueue{
		name:       name,
		url:        "http://127.0.0.1:4566/000000000000/" + name,
		arn:        "arn:aws:sqs:us-east-1:000000000000:" + name,
		attributes: cloneMap(attributes),
		tags:       cloneMap(tags),
	}
	f.queues[name] = queue
	return queue
}

func (f *fakeSQS) queueByURL(queueURL string) *fakeQueue {
	for _, queue := range f.queues {
		if queue.url == queueURL {
			return queue
		}
	}
	return nil
}

func (f *fakeSQS) queueNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for name := range f.queues {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (f *fakeSQS) eventSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func roleFromName(name string) string {
	switch {
	case strings.HasSuffix(name, "-source"):
		return "source"
	case strings.HasSuffix(name, "-dlq"):
		return "dlq"
	default:
		return name
	}
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneMessageAttributes(source map[string]messageAttribute) map[string]messageAttribute {
	result := make(map[string]messageAttribute, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeSQS) String() string {
	return fmt.Sprintf("fakeSQS(%d queues)", len(f.queues))
}
