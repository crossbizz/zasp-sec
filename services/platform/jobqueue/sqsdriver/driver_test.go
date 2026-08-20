package sqsdriver

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type stubClient struct {
	send       func(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error)
	receive    func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	delete     func(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error)
	visibility func(context.Context, *sqs.ChangeMessageVisibilityBatchInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error)
}

func (client *stubClient) SendMessageBatch(ctx context.Context, input *sqs.SendMessageBatchInput, options ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	if client.send == nil {
		return nil, errors.New("unexpected SendMessageBatch")
	}
	return client.send(ctx, input, options...)
}

func (client *stubClient) ReceiveMessage(ctx context.Context, input *sqs.ReceiveMessageInput, options ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	if client.receive == nil {
		return nil, errors.New("unexpected ReceiveMessage")
	}
	return client.receive(ctx, input, options...)
}

func (client *stubClient) DeleteMessageBatch(ctx context.Context, input *sqs.DeleteMessageBatchInput, options ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	if client.delete == nil {
		return nil, errors.New("unexpected DeleteMessageBatch")
	}
	return client.delete(ctx, input, options...)
}

func (client *stubClient) ChangeMessageVisibilityBatch(ctx context.Context, input *sqs.ChangeMessageVisibilityBatchInput, options ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
	if client.visibility == nil {
		return nil, errors.New("unexpected ChangeMessageVisibilityBatch")
	}
	return client.visibility(ctx, input, options...)
}

func TestNewRequiresInjectedClientAndProductionQueueURL(t *testing.T) {
	t.Parallel()

	valid := Config{
		QueueURL:                 "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-background",
		ReceiveWaitSeconds:       20,
		VisibilityTimeoutSeconds: 300,
		MaximumReceiveCount:      5,
	}

	if _, err := New(nil, valid); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New(nil) error = %v", err)
	}
	for _, queueURL := range []string{
		"http://127.0.0.1:4566/000000000000/agentsec-background",
		"https://example.com/123456789012/agentsec-background",
		"https://" + "user:secret@" + "sqs.us-west-2.amazonaws.com/123456789012/agentsec-background",
		"https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-background?token=secret",
	} {
		config := valid
		config.QueueURL = queueURL
		if _, err := New(&stubClient{}, config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("New(%q) error = %v", queueURL, err)
		}
	}

	driver, err := New(&stubClient{}, valid)
	if err != nil {
		t.Fatalf("New(valid) error = %v", err)
	}
	var _ jobqueue.Driver = driver
}

func TestNewRejectsOutOfRangeQueueBehavior(t *testing.T) {
	t.Parallel()

	valid := Config{
		QueueURL:                 "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-background",
		ReceiveWaitSeconds:       20,
		VisibilityTimeoutSeconds: 300,
		MaximumReceiveCount:      5,
	}
	mutations := []func(*Config){
		func(value *Config) { value.ReceiveWaitSeconds = -1 },
		func(value *Config) { value.ReceiveWaitSeconds = 21 },
		func(value *Config) { value.VisibilityTimeoutSeconds = 0 },
		func(value *Config) { value.VisibilityTimeoutSeconds = 43201 },
		func(value *Config) { value.MaximumReceiveCount = 0 },
		func(value *Config) { value.MaximumReceiveCount = 1001 },
	}
	for index, mutate := range mutations {
		config := valid
		mutate(&config)
		if _, err := New(&stubClient{}, config); !errors.Is(err, ErrConfiguration) {
			t.Fatalf("mutation %d error = %v", index, err)
		}
	}
}

func TestPublishBatchSendsExactCanonicalEnvelopesOnceWithoutSDKRetries(t *testing.T) {
	t.Parallel()

	messages := []jobqueue.DriverMessage{
		fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`),
		fixtureMessage(t, "pid_50000000-0000-4000-8000-000000000005", `{"action":"inventory"}`),
	}
	calls := 0
	client := &stubClient{send: func(ctx context.Context, input *sqs.SendMessageBatchInput, optionFunctions ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		calls++
		if ctx == nil || input == nil || aws.ToString(input.QueueUrl) != validConfig().QueueURL || len(input.Entries) != 2 {
			t.Fatalf("SendMessageBatch input = %#v", input)
		}
		requireOneAttempt(t, optionFunctions)
		for index, entry := range input.Entries {
			if aws.ToString(entry.Id) != messages[index].EntryID || aws.ToString(entry.MessageBody) != string(messages[index].Body) || aws.ToString(entry.MessageGroupId) != messages[index].Scope.OrganizationID().String() || entry.MessageDeduplicationId != nil || len(entry.MessageAttributes) != 0 || len(entry.MessageSystemAttributes) != 0 {
				t.Fatalf("entry %d = %#v", index, entry)
			}
		}
		return &sqs.SendMessageBatchOutput{Successful: []types.SendMessageBatchResultEntry{
			{Id: input.Entries[1].Id, MessageId: aws.String("provider-message-2"), MD5OfMessageBody: aws.String(md5Hex(messages[1].Body))},
			{Id: input.Entries[0].Id, MessageId: aws.String("provider-message-1"), MD5OfMessageBody: aws.String(md5Hex(messages[0].Body))},
		}}, nil
	}}
	driver := mustDriver(t, client)

	published, err := driver.PublishBatch(context.Background(), messages)
	if err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("SendMessageBatch calls = %d", calls)
	}
	want := []jobqueue.DriverPublished{
		{EntryID: messages[0].EntryID, JobID: messages[0].JobID, MessageID: "provider-message-1"},
		{EntryID: messages[1].EntryID, JobID: messages[1].JobID, MessageID: "provider-message-2"},
	}
	if !reflect.DeepEqual(published, want) {
		t.Fatalf("published = %#v, want %#v", published, want)
	}
}

func TestPublishBatchEnforcesCanonicalEnvelopeAndExact262144ByteTotal(t *testing.T) {
	t.Parallel()

	clientCalls := 0
	client := &stubClient{send: func(_ context.Context, input *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		clientCalls++
		return successfulSend(input), nil
	}}
	driver := mustDriver(t, client)

	exact := fixtureMessageOfSize(t, 262_144)
	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{exact}); err != nil {
		t.Fatalf("PublishBatch(exact bound) error = %v", err)
	}
	tooLarge := fixtureMessageOfSize(t, 262_145)
	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{tooLarge}); !errors.Is(err, ErrInput) {
		t.Fatalf("PublishBatch(over bound) error = %v", err)
	}
	noncanonical := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	noncanonical.Body = append([]byte(" "), noncanonical.Body...)
	noncanonical.SHA256 = sha256.Sum256(noncanonical.Body)
	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{noncanonical}); !errors.Is(err, ErrInput) {
		t.Fatalf("PublishBatch(noncanonical) error = %v", err)
	}
	if clientCalls != 1 {
		t.Fatalf("SendMessageBatch calls = %d, want 1", clientCalls)
	}
}

func TestPublishBatchLostAcknowledgementReplaysIdenticalDeterministicEntries(t *testing.T) {
	t.Parallel()

	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	var calls [][]types.SendMessageBatchRequestEntry
	client := &stubClient{send: func(_ context.Context, input *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		calls = append(calls, cloneSendEntries(input.Entries))
		if len(calls) == 1 {
			return nil, errors.New("AccessKey=must-not-escape: transport reset after write")
		}
		return successfulSend(input), nil
	}}
	driver := mustDriver(t, client)

	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{message}); !errors.Is(err, ErrUnknownOutcome) || ErrorClassOf(err) != ErrorClassUnknownOutcome || strings.Contains(err.Error(), "AccessKey") {
		t.Fatalf("first PublishBatch() error = %q, class = %q", err, ErrorClassOf(err))
	}
	published, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{message})
	if err != nil || len(published) != 1 || published[0].JobID != message.JobID {
		t.Fatalf("replay PublishBatch() = %#v, %v", published, err)
	}
	if len(calls) != 2 || !reflect.DeepEqual(calls[0], calls[1]) {
		t.Fatalf("replayed entries differ: %#v / %#v", calls[0], calls[1])
	}
}

func TestPublishBatchClassifiesExactProviderBatchFailuresWithoutLeakingMessages(t *testing.T) {
	t.Parallel()

	messages := []jobqueue.DriverMessage{
		fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`),
		fixtureMessage(t, "pid_50000000-0000-4000-8000-000000000005", `{"action":"inventory"}`),
	}
	client := &stubClient{send: func(_ context.Context, input *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		return &sqs.SendMessageBatchOutput{
			Successful: []types.SendMessageBatchResultEntry{{Id: input.Entries[0].Id, MessageId: aws.String("provider-message-1"), MD5OfMessageBody: aws.String(md5Hex(messages[0].Body))}},
			Failed:     []types.BatchResultErrorEntry{{Id: input.Entries[1].Id, Code: aws.String("AccessDenied"), Message: aws.String("secret provider detail"), SenderFault: true}},
		}, nil
	}}
	driver := mustDriver(t, client)

	published, err := driver.PublishBatch(context.Background(), messages)
	if !errors.Is(err, ErrRejected) || ErrorClassOf(err) != ErrorClassRejected || strings.Contains(err.Error(), "secret") || len(published) != 1 || published[0].JobID != messages[0].JobID {
		t.Fatalf("PublishBatch() = %#v, %q, class = %q", published, err, ErrorClassOf(err))
	}
	failures := EntryFailures(err)
	want := []EntryFailure{{EntryID: messages[1].EntryID, Disposition: DispositionDeadLetter}}
	if !reflect.DeepEqual(failures, want) {
		t.Fatalf("EntryFailures() = %#v, want %#v", failures, want)
	}
}

func TestPublishBatchTreatsMalformedOrForeignResponseAsUnknownOutcome(t *testing.T) {
	t.Parallel()

	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	client := &stubClient{send: func(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		return &sqs.SendMessageBatchOutput{Successful: []types.SendMessageBatchResultEntry{{Id: aws.String("foreign-entry"), MessageId: aws.String("provider-message")}}}, nil
	}}
	driver := mustDriver(t, client)

	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{message}); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("PublishBatch() error = %v", err)
	}
}

func TestPublishBatchRejectsUnsafeProviderMessageIDsWithoutEcho(t *testing.T) {
	t.Parallel()

	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	for _, hostile := range []string{strings.Repeat("a", 257), "provider\nsecret", " AKIAIOSFODNN7EXAMPLE "} {
		hostile := hostile
		t.Run(fmt.Sprintf("length-%d", len(hostile)), func(t *testing.T) {
			client := &stubClient{send: func(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
				return &sqs.SendMessageBatchOutput{Successful: []types.SendMessageBatchResultEntry{{Id: aws.String(message.EntryID), MessageId: aws.String(hostile), MD5OfMessageBody: aws.String(md5Body(message.Body))}}}, nil
			}}
			driver := mustDriver(t, client)
			published, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{message})
			if len(published) != 0 || !errors.Is(err, ErrUnknownOutcome) || strings.Contains(fmt.Sprint(err), hostile) {
				t.Fatalf("hostile message ID result=%#v err=%q", published, err)
			}
		})
	}
}

func TestConsumeBatchValidatesCanonicalEnvelopeAndClassifiesFinalDLQAttempt(t *testing.T) {
	t.Parallel()

	messages := []jobqueue.DriverMessage{
		fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`),
		fixtureMessage(t, "pid_50000000-0000-4000-8000-000000000005", `{"action":"inventory"}`),
	}
	client := &stubClient{receive: func(ctx context.Context, input *sqs.ReceiveMessageInput, optionFunctions ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
		if ctx == nil || aws.ToString(input.QueueUrl) != validConfig().QueueURL || input.MaxNumberOfMessages != 2 || input.WaitTimeSeconds != 20 || input.VisibilityTimeout != 300 || !reflect.DeepEqual(input.MessageSystemAttributeNames, []types.MessageSystemAttributeName{types.MessageSystemAttributeNameApproximateReceiveCount}) || len(input.MessageAttributeNames) != 0 {
			t.Fatalf("ReceiveMessage input = %#v", input)
		}
		requireOneAttempt(t, optionFunctions)
		return &sqs.ReceiveMessageOutput{Messages: []types.Message{
			providerMessage(messages[0], "provider-message-1", "opaque-receipt-1", 1),
			providerMessage(messages[1], "provider-message-2", "opaque-receipt-2", 5),
		}}, nil
	}}
	driver := mustDriver(t, client)

	classified, err := driver.ConsumeBatchDetailed(context.Background(), 2)
	if err != nil {
		t.Fatalf("ConsumeBatchDetailed() error = %v", err)
	}
	if len(classified) != 2 || classified[0].ReceiveCount != 1 || classified[0].FailureDisposition != DispositionRetry || classified[1].ReceiveCount != 5 || classified[1].FailureDisposition != DispositionDeadLetter {
		t.Fatalf("classified = %#v", classified)
	}
	for index, delivery := range classified {
		if !reflect.DeepEqual(delivery.Delivery.Message, messages[index]) || delivery.Delivery.MessageID != fmt.Sprintf("provider-message-%d", index+1) || delivery.Delivery.ReceiptHandle != fmt.Sprintf("opaque-receipt-%d", index+1) {
			t.Fatalf("delivery %d = %#v", index, delivery)
		}
	}

	plain, err := driver.ConsumeBatch(context.Background(), 2)
	if err != nil || len(plain) != 2 || !reflect.DeepEqual(plain[0], classified[0].Delivery) || !reflect.DeepEqual(plain[1], classified[1].Delivery) {
		t.Fatalf("ConsumeBatch() = %#v, %v", plain, err)
	}
}

func TestConsumeBatchRejectsMalformedProviderOutputAndRedactsProviderError(t *testing.T) {
	t.Parallel()

	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	responses := []func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error){
		func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
			return &sqs.ReceiveMessageOutput{Messages: []types.Message{providerMessage(message, "provider-message", "opaque-receipt", 0)}}, nil
		},
		func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
			value := providerMessage(message, "provider-message", "opaque-receipt", 1)
			value.MD5OfBody = aws.String("00000000000000000000000000000000")
			return &sqs.ReceiveMessageOutput{Messages: []types.Message{value}}, nil
		},
		func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
			return nil, errors.New("credential=must-not-escape")
		},
	}
	for index, response := range responses {
		driver := mustDriver(t, &stubClient{receive: response})
		if _, err := driver.ConsumeBatch(context.Background(), 1); !errors.Is(err, ErrRetryable) || ErrorClassOf(err) != ErrorClassRetryable || strings.Contains(err.Error(), "credential") {
			t.Fatalf("case %d error = %q, class = %q", index, err, ErrorClassOf(err))
		}
	}
}

func TestConsumeBatchRejectsInvalidBoundsBeforeCallingSDK(t *testing.T) {
	t.Parallel()

	calls := 0
	driver := mustDriver(t, &stubClient{receive: func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
		calls++
		return &sqs.ReceiveMessageOutput{}, nil
	}})
	for _, maximum := range []int{0, 11} {
		if _, err := driver.ConsumeBatch(context.Background(), maximum); !errors.Is(err, ErrInput) {
			t.Fatalf("ConsumeBatch(%d) error = %v", maximum, err)
		}
	}
	if calls != 0 {
		t.Fatalf("ReceiveMessage calls = %d", calls)
	}
}

func TestAcknowledgeBatchReturnsExactPartialDeleteAndRetryClassification(t *testing.T) {
	t.Parallel()

	receipts := fixtureReceipts(t)
	client := &stubClient{delete: func(ctx context.Context, input *sqs.DeleteMessageBatchInput, optionFunctions ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
		if ctx == nil || aws.ToString(input.QueueUrl) != validConfig().QueueURL || len(input.Entries) != 2 {
			t.Fatalf("DeleteMessageBatch input = %#v", input)
		}
		requireOneAttempt(t, optionFunctions)
		for index, entry := range input.Entries {
			if aws.ToString(entry.Id) != receipts[index].EntryID || aws.ToString(entry.ReceiptHandle) != receipts[index].ReceiptHandle {
				t.Fatalf("delete entry %d = %#v", index, entry)
			}
		}
		return &sqs.DeleteMessageBatchOutput{
			Successful: []types.DeleteMessageBatchResultEntry{{Id: input.Entries[0].Id}},
			Failed:     []types.BatchResultErrorEntry{{Id: input.Entries[1].Id, Code: aws.String("ServiceUnavailable"), Message: aws.String("provider detail"), SenderFault: false}},
		}, nil
	}}
	driver := mustDriver(t, client)

	acknowledged, err := driver.AcknowledgeBatch(context.Background(), receipts)
	if !errors.Is(err, ErrRetryable) || ErrorClassOf(err) != ErrorClassRetryable || len(acknowledged) != 1 || acknowledged[0] != receipts[0].JobID {
		t.Fatalf("AcknowledgeBatch() = %#v, %v, class %q", acknowledged, err, ErrorClassOf(err))
	}
	want := []EntryFailure{{EntryID: receipts[1].EntryID, Disposition: DispositionRetry}}
	if got := EntryFailures(err); !reflect.DeepEqual(got, want) {
		t.Fatalf("EntryFailures() = %#v, want %#v", got, want)
	}
}

func TestAcknowledgeBatchTreatsLostOrMalformedDeleteAcknowledgementAsUnknown(t *testing.T) {
	t.Parallel()

	receipts := fixtureReceipts(t)[:1]
	responses := []func(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error){
		func(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
			return nil, errors.New("receipt=must-not-escape")
		},
		func(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
			return &sqs.DeleteMessageBatchOutput{Successful: []types.DeleteMessageBatchResultEntry{{Id: aws.String("foreign")}}}, nil
		},
	}
	for index, response := range responses {
		driver := mustDriver(t, &stubClient{delete: response})
		acknowledged, err := driver.AcknowledgeBatch(context.Background(), receipts)
		if !errors.Is(err, ErrUnknownOutcome) || len(acknowledged) != 0 || strings.Contains(err.Error(), "receipt") {
			t.Fatalf("case %d = %#v, %q", index, acknowledged, err)
		}
		want := []EntryFailure{{EntryID: receipts[0].EntryID, Disposition: DispositionReconcile}}
		if got := EntryFailures(err); !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d failures = %#v, want %#v", index, got, want)
		}
	}
}

func TestExtendVisibilityUsesExactReceiptsAndReturnsPartialResults(t *testing.T) {
	t.Parallel()

	receipts := fixtureReceipts(t)
	client := &stubClient{visibility: func(ctx context.Context, input *sqs.ChangeMessageVisibilityBatchInput, optionFunctions ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
		if ctx == nil || aws.ToString(input.QueueUrl) != validConfig().QueueURL || len(input.Entries) != 2 {
			t.Fatalf("ChangeMessageVisibilityBatch input = %#v", input)
		}
		requireOneAttempt(t, optionFunctions)
		for index, entry := range input.Entries {
			if aws.ToString(entry.Id) != receipts[index].EntryID || aws.ToString(entry.ReceiptHandle) != receipts[index].ReceiptHandle || entry.VisibilityTimeout != 600 {
				t.Fatalf("visibility entry %d = %#v", index, entry)
			}
		}
		return &sqs.ChangeMessageVisibilityBatchOutput{
			Successful: []types.ChangeMessageVisibilityBatchResultEntry{{Id: input.Entries[1].Id}},
			Failed:     []types.BatchResultErrorEntry{{Id: input.Entries[0].Id, Code: aws.String("ServiceUnavailable"), SenderFault: false}},
		}, nil
	}}
	driver := mustDriver(t, client)

	extended, err := driver.ExtendVisibility(context.Background(), receipts, 600)
	if !errors.Is(err, ErrRetryable) || len(extended) != 1 || extended[0] != receipts[1].JobID {
		t.Fatalf("ExtendVisibility() = %#v, %v", extended, err)
	}
	want := []EntryFailure{{EntryID: receipts[0].EntryID, Disposition: DispositionRetry}}
	if got := EntryFailures(err); !reflect.DeepEqual(got, want) {
		t.Fatalf("EntryFailures() = %#v, want %#v", got, want)
	}
}

func TestAcknowledgementAndVisibilityRejectInvalidReceiptsBeforeSDK(t *testing.T) {
	t.Parallel()

	deleteCalls, visibilityCalls := 0, 0
	client := &stubClient{
		delete: func(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
			deleteCalls++
			return &sqs.DeleteMessageBatchOutput{}, nil
		},
		visibility: func(context.Context, *sqs.ChangeMessageVisibilityBatchInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
			visibilityCalls++
			return &sqs.ChangeMessageVisibilityBatchOutput{}, nil
		},
	}
	driver := mustDriver(t, client)
	invalid := fixtureReceipts(t)[:1]
	invalid[0].EntryID = "foreign"
	if _, err := driver.AcknowledgeBatch(context.Background(), invalid); !errors.Is(err, ErrInput) {
		t.Fatalf("AcknowledgeBatch(invalid) error = %v", err)
	}
	if _, err := driver.ExtendVisibility(context.Background(), invalid, 600); !errors.Is(err, ErrInput) {
		t.Fatalf("ExtendVisibility(invalid) error = %v", err)
	}
	valid := fixtureReceipts(t)[:1]
	for _, seconds := range []int32{0, 43_201} {
		if _, err := driver.ExtendVisibility(context.Background(), valid, seconds); !errors.Is(err, ErrInput) {
			t.Fatalf("ExtendVisibility(%d) error = %v", seconds, err)
		}
	}
	if deleteCalls != 0 || visibilityCalls != 0 {
		t.Fatalf("SDK calls = delete %d visibility %d", deleteCalls, visibilityCalls)
	}
}

func TestCanceledContextBeforeOperationNeverCallsSDK(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := &stubClient{
		send: func(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
			calls.Add(1)
			return nil, errors.New("unexpected")
		},
		receive: func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
			calls.Add(1)
			return nil, errors.New("unexpected")
		},
		delete: func(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
			calls.Add(1)
			return nil, errors.New("unexpected")
		},
		visibility: func(context.Context, *sqs.ChangeMessageVisibilityBatchInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
			calls.Add(1)
			return nil, errors.New("unexpected")
		},
	}
	driver := mustDriver(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	receipts := fixtureReceipts(t)[:1]
	operations := []func() error{
		func() error { _, err := driver.PublishBatch(ctx, []jobqueue.DriverMessage{message}); return err },
		func() error { _, err := driver.ConsumeBatch(ctx, 1); return err },
		func() error { _, err := driver.AcknowledgeBatch(ctx, receipts); return err },
		func() error { _, err := driver.ExtendVisibility(ctx, receipts, 600); return err },
	}
	for index, operation := range operations {
		if err := operation(); !errors.Is(err, ErrCanceled) || ErrorClassOf(err) != ErrorClassCanceled {
			t.Fatalf("operation %d error = %v, class %q", index, err, ErrorClassOf(err))
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("SDK calls = %d", calls.Load())
	}
}

func TestDrainRejectsNewWorkAndWaitsForInflightCall(t *testing.T) {
	t.Parallel()

	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce sync.Once
	client := &stubClient{send: func(ctx context.Context, input *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		startOnce.Do(func() { close(started) })
		select {
		case <-release:
			return successfulSend(input), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	driver := mustDriver(t, client)
	publishDone := make(chan error, 1)
	go func() {
		_, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{message})
		publishDone <- err
	}()
	waitClosed(t, started, "publish start")

	drainDone := make(chan error, 1)
	go func() { drainDone <- driver.Drain(context.Background()) }()
	eventuallyDraining(t, driver)
	select {
	case err := <-drainDone:
		t.Fatalf("Drain returned before inflight operation: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := waitError(t, publishDone, "publish completion"); err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}
	if err := waitError(t, drainDone, "drain completion"); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{message}); !errors.Is(err, ErrDraining) || ErrorClassOf(err) != ErrorClassDraining {
		t.Fatalf("PublishBatch(after drain) error = %v, class %q", err, ErrorClassOf(err))
	}
}

func TestCanceledInflightSendIsUnknownOutcomeAndDrainCanTimeOut(t *testing.T) {
	t.Parallel()

	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	started := make(chan struct{})
	release := make(chan struct{})
	client := &stubClient{send: func(ctx context.Context, _ *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		close(started)
		select {
		case <-release:
			return nil, errors.New("provider write may have completed")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	driver := mustDriver(t, client)
	callCtx, cancelCall := context.WithCancel(context.Background())
	publishDone := make(chan error, 1)
	go func() {
		_, err := driver.PublishBatch(callCtx, []jobqueue.DriverMessage{message})
		publishDone <- err
	}()
	waitClosed(t, started, "publish start")
	drainCtx, cancelDrain := context.WithCancel(context.Background())
	cancelDrain()
	if err := driver.Drain(drainCtx); !errors.Is(err, ErrCanceled) {
		t.Fatalf("Drain(canceled) error = %v", err)
	}
	cancelCall()
	if err := waitError(t, publishDone, "publish cancellation"); !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("PublishBatch(canceled inflight) error = %v", err)
	}
	close(release)
}

func validConfig() Config {
	return Config{
		QueueURL:                 "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-background",
		ReceiveWaitSeconds:       20,
		VisibilityTimeoutSeconds: 300,
		MaximumReceiveCount:      5,
	}
}

func mustDriver(t *testing.T, client Client) *Driver {
	t.Helper()
	driver, err := New(client, validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return driver
}

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	organizationID := mustProductID(t, "pid_10000000-0000-4000-8000-000000000001")
	workspaceID := mustProductID(t, "pid_20000000-0000-4000-8000-000000000002")
	environmentID := mustProductID(t, "pid_30000000-0000-4000-8000-000000000003")
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	return scope
}

func mustProductID(t *testing.T, value string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(value)
	if err != nil {
		t.Fatalf("ParseProductID(%q) error = %v", value, err)
	}
	return id
}

func fixtureMessage(t *testing.T, jobIDText, payload string) jobqueue.DriverMessage {
	t.Helper()
	scope := fixtureScope(t)
	jobID := mustProductID(t, jobIDText)
	body := []byte(fmt.Sprintf(`{"version":1,"job_id":%q,"organization_id":%q,"workspace_id":%q,"environment_id":%q,"kind":"evidence.collect","payload":%s}`,
		jobID.String(), scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), payload))
	return jobqueue.DriverMessage{EntryID: jobID.String(), Scope: scope, JobID: jobID, Kind: "evidence.collect", Body: body, SHA256: sha256.Sum256(body)}
}

func fixtureMessageOfSize(t *testing.T, size int) jobqueue.DriverMessage {
	t.Helper()
	message := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `""`)
	additional := size - len(message.Body)
	if additional < 0 {
		t.Fatalf("requested body size %d is below envelope size %d", size, len(message.Body))
	}
	closing := bytes.LastIndexByte(message.Body, '"')
	message.Body = append(append(append([]byte(nil), message.Body[:closing]...), bytes.Repeat([]byte{'x'}, additional)...), message.Body[closing:]...)
	message.SHA256 = sha256.Sum256(message.Body)
	if len(message.Body) != size {
		t.Fatalf("fixture size = %d, want %d", len(message.Body), size)
	}
	return message
}

func md5Hex(body []byte) string {
	digest := md5.Sum(body)
	return fmt.Sprintf("%x", digest[:])
}

func successfulSend(input *sqs.SendMessageBatchInput) *sqs.SendMessageBatchOutput {
	output := &sqs.SendMessageBatchOutput{Successful: make([]types.SendMessageBatchResultEntry, len(input.Entries))}
	for index, entry := range input.Entries {
		output.Successful[index] = types.SendMessageBatchResultEntry{Id: entry.Id, MessageId: aws.String(fmt.Sprintf("provider-message-%d", index+1)), MD5OfMessageBody: aws.String(md5Hex([]byte(aws.ToString(entry.MessageBody))))}
	}
	return output
}

func providerMessage(message jobqueue.DriverMessage, messageID, receiptHandle string, receiveCount int) types.Message {
	return types.Message{
		Body:          aws.String(string(message.Body)),
		MD5OfBody:     aws.String(md5Hex(message.Body)),
		MessageId:     aws.String(messageID),
		ReceiptHandle: aws.String(receiptHandle),
		Attributes: map[string]string{
			string(types.MessageSystemAttributeNameApproximateReceiveCount): strconv.Itoa(receiveCount),
		},
	}
}

func fixtureReceipts(t *testing.T) []jobqueue.DriverReceipt {
	t.Helper()
	first := mustProductID(t, "pid_40000000-0000-4000-8000-000000000004")
	second := mustProductID(t, "pid_50000000-0000-4000-8000-000000000005")
	return []jobqueue.DriverReceipt{
		{EntryID: first.String(), JobID: first, MessageID: "provider-message-1", ReceiptHandle: "opaque-receipt-1"},
		{EntryID: second.String(), JobID: second, MessageID: "provider-message-2", ReceiptHandle: "opaque-receipt-2"},
	}
}

func waitClosed(t *testing.T, channel <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitError(t *testing.T, channel <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-channel:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}

func eventuallyDraining(t *testing.T, driver *Driver) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := driver.ConsumeBatch(context.Background(), 1); errors.Is(err, ErrDraining) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("driver did not enter draining state")
}

func cloneSendEntries(entries []types.SendMessageBatchRequestEntry) []types.SendMessageBatchRequestEntry {
	cloned := make([]types.SendMessageBatchRequestEntry, len(entries))
	copy(cloned, entries)
	return cloned
}

func requireOneAttempt(t *testing.T, optionFunctions []func(*sqs.Options)) {
	t.Helper()
	options := sqs.Options{RetryMaxAttempts: 99}
	for _, option := range optionFunctions {
		option(&options)
	}
	if options.RetryMaxAttempts != 1 || options.Retryer == nil || options.Retryer.MaxAttempts() != 1 {
		t.Fatalf("retry options = attempts %d, retryer %#v", options.RetryMaxAttempts, options.Retryer)
	}
}
