package jobqueue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type recordingDriver struct {
	publish     func(context.Context, []DriverMessage) ([]DriverPublished, error)
	consume     func(context.Context, int) ([]DriverDelivery, error)
	acknowledge func(context.Context, []DriverReceipt) ([]domain.ProductID, error)
}

func (driver *recordingDriver) PublishBatch(ctx context.Context, messages []DriverMessage) ([]DriverPublished, error) {
	return driver.publish(ctx, messages)
}

func (driver *recordingDriver) ConsumeBatch(ctx context.Context, maximum int) ([]DriverDelivery, error) {
	return driver.consume(ctx, maximum)
}

func (driver *recordingDriver) AcknowledgeBatch(ctx context.Context, receipts []DriverReceipt) ([]domain.ProductID, error) {
	return driver.acknowledge(ctx, receipts)
}

func TestQueuePublishesConsumesAndAcknowledgesScopedBatch(t *testing.T) {
	t.Parallel()

	scope := fixtureScope(t)
	jobs := []Job{
		{
			Scope:   scope,
			JobID:   mustProductID(t, "pid_40000000-0000-4000-8000-000000000004"),
			Kind:    "evidence.collect",
			Payload: []byte(`{"action":"scan"}`),
		},
		{
			Scope:   scope,
			JobID:   mustProductID(t, "pid_50000000-0000-4000-8000-000000000005"),
			Kind:    "event.correlate",
			Payload: []byte(`{"attempt":1}`),
		},
	}

	var retained []DriverMessage
	driver := &recordingDriver{}
	driver.publish = func(ctx context.Context, messages []DriverMessage) ([]DriverPublished, error) {
		requireOperationDeadline(t, ctx)
		if len(messages) != len(jobs) {
			t.Fatalf("PublishBatch message count = %d", len(messages))
		}
		retained = cloneMessages(messages)
		results := make([]DriverPublished, len(messages))
		for index, message := range messages {
			wantBody := expectedBody(jobs[index])
			if message.EntryID != jobs[index].JobID.String() || message.Scope != scope ||
				message.JobID != jobs[index].JobID || message.Kind != jobs[index].Kind ||
				!bytes.Equal(message.Body, wantBody) || message.SHA256 != sha256.Sum256(wantBody) {
				t.Fatalf("message %d = %#v, body = %q", index, message, message.Body)
			}
			results[index] = DriverPublished{
				EntryID:   message.EntryID,
				JobID:     message.JobID,
				MessageID: fmt.Sprintf("provider-message-%d", index+1),
			}
		}
		return results, nil
	}
	driver.consume = func(ctx context.Context, maximum int) ([]DriverDelivery, error) {
		requireOperationDeadline(t, ctx)
		if maximum != 2 {
			t.Fatalf("ConsumeBatch maximum = %d", maximum)
		}
		results := make([]DriverDelivery, len(retained))
		for index, message := range retained {
			results[index] = DriverDelivery{
				Message:       cloneMessage(message),
				MessageID:     fmt.Sprintf("provider-message-%d", index+1),
				ReceiptHandle: fmt.Sprintf("opaque-receipt-%d", index+1),
				ReceiveCount:  index + 1,
			}
		}
		return results, nil
	}
	driver.acknowledge = func(ctx context.Context, receipts []DriverReceipt) ([]domain.ProductID, error) {
		requireOperationDeadline(t, ctx)
		if len(receipts) != len(jobs) {
			t.Fatalf("AcknowledgeBatch receipt count = %d", len(receipts))
		}
		acknowledged := make([]domain.ProductID, len(receipts))
		for index, receipt := range receipts {
			if receipt.EntryID != jobs[index].JobID.String() || receipt.JobID != jobs[index].JobID ||
				receipt.MessageID != fmt.Sprintf("provider-message-%d", index+1) ||
				receipt.ReceiptHandle != fmt.Sprintf("opaque-receipt-%d", index+1) {
				t.Fatalf("receipt %d = %#v", index, receipt)
			}
			acknowledged[index] = receipt.JobID
		}
		return acknowledged, nil
	}

	queue, err := New(driver, validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	var contract JobQueue = queue

	published, err := contract.PublishBatch(context.Background(), jobs)
	if err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}
	if len(published.JobIDs) != len(jobs) || published.JobIDs[0] != jobs[0].JobID || published.JobIDs[1] != jobs[1].JobID {
		t.Fatalf("published = %#v", published)
	}
	jobs[0].Payload[0] = 'X'
	published.JobIDs[0] = domain.ProductID{}
	if retained[0].Body[0] != '{' {
		t.Fatal("PublishBatch retained caller-owned bytes")
	}

	deliveries, err := contract.ConsumeBatch(context.Background(), 2)
	if err != nil {
		t.Fatalf("ConsumeBatch() error = %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("delivery count = %d", len(deliveries))
	}
	for index, delivery := range deliveries {
		messageDigest := sha256.Sum256([]byte(fmt.Sprintf("provider-message-%d", index+1)))
		wantMessageKey := "sha256_" + hex.EncodeToString(messageDigest[:])
		if delivery.Job.Scope != scope || delivery.Job.JobID != jobs[index].JobID ||
			delivery.Job.Kind != jobs[index].Kind || delivery.Receipt.JobID() != jobs[index].JobID || delivery.ReceiveCount != index+1 || delivery.Receipt.MessageKey() != wantMessageKey {
			t.Fatalf("delivery %d = %#v", index, delivery)
		}
	}
	deliveries[0].Job.Payload[0] = 'X'
	if retained[0].Body[0] != '{' {
		t.Fatal("ConsumeBatch returned driver-owned bytes")
	}

	receipts := []Receipt{deliveries[0].Receipt, deliveries[1].Receipt}
	if err := contract.AcknowledgeBatch(context.Background(), receipts); err != nil {
		t.Fatalf("AcknowledgeBatch() error = %v", err)
	}
}

func TestNewRejectsInvalidConfigurationAndDriver(t *testing.T) {
	t.Parallel()

	driver := noCallDriver()
	configs := []Config{
		{},
		{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1, MaximumBatchBytes: 0},
		{OperationTimeout: 0, MaximumBatchMessages: 10, MaximumMessageBytes: 1, MaximumBatchBytes: 1},
		{OperationTimeout: -time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1, MaximumBatchBytes: 1},
		{OperationTimeout: 30*time.Second + time.Nanosecond, MaximumBatchMessages: 10, MaximumMessageBytes: 1, MaximumBatchBytes: 1},
		{OperationTimeout: time.Second, MaximumBatchMessages: 0, MaximumMessageBytes: 1, MaximumBatchBytes: 1},
		{OperationTimeout: time.Second, MaximumBatchMessages: 11, MaximumMessageBytes: 1, MaximumBatchBytes: 1},
		{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 0, MaximumBatchBytes: 1},
		{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1_048_577, MaximumBatchBytes: 1_048_576},
		{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 1, MaximumBatchBytes: 1_048_577},
		{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 2, MaximumBatchBytes: 1},
	}
	for index, config := range configs {
		if queue, err := New(driver, config); !errors.Is(err, ErrConfiguration) || queue != nil {
			t.Fatalf("config %d = %#v, %v", index, queue, err)
		}
	}
	if queue, err := New(nil, validConfig()); !errors.Is(err, ErrConfiguration) || queue != nil {
		t.Fatalf("nil driver = %#v, %v", queue, err)
	}
	var typedNil *recordingDriver
	if queue, err := New(typedNil, validConfig()); !errors.Is(err, ErrConfiguration) || queue != nil {
		t.Fatalf("typed nil driver = %#v, %v", queue, err)
	}
}

func TestPublishRejectsInvalidJobsBeforeDriver(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	driver := noCallDriver()
	driver.publish = func(context.Context, []DriverMessage) ([]DriverPublished, error) {
		calls.Add(1)
		return nil, nil
	}
	queue := mustQueue(t, driver, validConfig())
	valid := fixtureJobs(t)
	tooMany := make([]Job, 11)
	for index := range tooMany {
		tooMany[index] = valid[index%len(valid)]
	}
	longKind := strings.Repeat("a", 64)
	cases := []struct {
		name string
		jobs []Job
	}{
		{name: "empty", jobs: nil},
		{name: "too many", jobs: tooMany},
		{name: "scope", jobs: []Job{{Scope: domain.Scope{}, JobID: valid[0].JobID, Kind: valid[0].Kind, Payload: valid[0].Payload}}},
		{name: "job id", jobs: []Job{{Scope: valid[0].Scope, Kind: valid[0].Kind, Payload: valid[0].Payload}}},
		{name: "uppercase kind", jobs: []Job{{Scope: valid[0].Scope, JobID: valid[0].JobID, Kind: "Scan", Payload: valid[0].Payload}}},
		{name: "leading digit kind", jobs: []Job{{Scope: valid[0].Scope, JobID: valid[0].JobID, Kind: "1scan", Payload: valid[0].Payload}}},
		{name: "long kind", jobs: []Job{{Scope: valid[0].Scope, JobID: valid[0].JobID, Kind: longKind, Payload: valid[0].Payload}}},
		{name: "empty payload", jobs: []Job{{Scope: valid[0].Scope, JobID: valid[0].JobID, Kind: valid[0].Kind}}},
		{name: "invalid payload", jobs: []Job{{Scope: valid[0].Scope, JobID: valid[0].JobID, Kind: valid[0].Kind, Payload: []byte(`{"open":`)}}},
		{name: "duplicate id", jobs: []Job{valid[0], valid[0]}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if result, err := queue.PublishBatch(context.Background(), test.jobs); !errors.Is(err, ErrJob) || result.JobIDs != nil {
				t.Fatalf("PublishBatch() = %#v, %v", result, err)
			}
		})
	}

	body, ok := canonicalBody(valid[0])
	if !ok {
		t.Fatal("canonicalBody failed")
	}
	messageLimited := mustQueue(t, driver, Config{
		OperationTimeout:     time.Second,
		MaximumBatchMessages: 10,
		MaximumMessageBytes:  int64(len(body) - 1),
		MaximumBatchBytes:    int64(len(body) * 2),
	})
	if _, err := messageLimited.PublishBatch(context.Background(), valid[:1]); !errors.Is(err, ErrJob) {
		t.Fatalf("message limit error = %v", err)
	}
	bodies := make([][]byte, len(valid))
	var total int
	var largest int
	for index, job := range valid {
		bodies[index], _ = canonicalBody(job)
		total += len(bodies[index])
		if len(bodies[index]) > largest {
			largest = len(bodies[index])
		}
	}
	batchLimited := mustQueue(t, driver, Config{
		OperationTimeout:     time.Second,
		MaximumBatchMessages: 10,
		MaximumMessageBytes:  int64(largest),
		MaximumBatchBytes:    int64(total - 1),
	})
	if _, err := batchLimited.PublishBatch(context.Background(), valid); !errors.Is(err, ErrJob) {
		t.Fatalf("batch limit error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("driver calls = %d", calls.Load())
	}
}

func TestPublishRequiresExactFullDriverSuccess(t *testing.T) {
	t.Parallel()

	jobs := fixtureJobs(t)
	base := func(messages []DriverMessage) []DriverPublished {
		results := make([]DriverPublished, len(messages))
		for index, message := range messages {
			results[index] = DriverPublished{EntryID: message.EntryID, JobID: message.JobID, MessageID: fmt.Sprintf("message-%d", index)}
		}
		return results
	}
	tests := []struct {
		name   string
		mutate func([]DriverPublished) []DriverPublished
	}{
		{name: "partial", mutate: func(results []DriverPublished) []DriverPublished { return results[:1] }},
		{name: "extra", mutate: func(results []DriverPublished) []DriverPublished { return append(results, results[0]) }},
		{name: "foreign entry", mutate: func(results []DriverPublished) []DriverPublished { results[0].EntryID = "foreign"; return results }},
		{name: "foreign job", mutate: func(results []DriverPublished) []DriverPublished { results[0].JobID = jobs[1].JobID; return results }},
		{name: "missing message id", mutate: func(results []DriverPublished) []DriverPublished { results[0].MessageID = ""; return results }},
		{name: "oversized message id", mutate: func(results []DriverPublished) []DriverPublished {
			results[0].MessageID = strings.Repeat("a", 257)
			return results
		}},
		{name: "control message id", mutate: func(results []DriverPublished) []DriverPublished {
			results[0].MessageID = "provider\nsecret"
			return results
		}},
		{name: "duplicate message id", mutate: func(results []DriverPublished) []DriverPublished {
			results[1].MessageID = results[0].MessageID
			return results
		}},
		{name: "duplicate", mutate: func(results []DriverPublished) []DriverPublished { results[1] = results[0]; return results }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			queue := mustQueue(t, &recordingDriver{
				publish: func(_ context.Context, messages []DriverMessage) ([]DriverPublished, error) {
					return test.mutate(base(messages)), nil
				},
			}, validConfig())
			if result, err := queue.PublishBatch(context.Background(), jobs); !errors.Is(err, ErrPublish) || result.JobIDs != nil {
				t.Fatalf("PublishBatch() = %#v, %v", result, err)
			}
		})
	}
	queue := mustQueue(t, &recordingDriver{
		publish: func(_ context.Context, messages []DriverMessage) ([]DriverPublished, error) {
			results := base(messages)
			return []DriverPublished{results[1], results[0]}, nil
		},
	}, validConfig())
	result, err := queue.PublishBatch(context.Background(), jobs)
	if err != nil {
		t.Fatalf("unordered exact success error = %v", err)
	}
	firstAck, _ := CanonicalProviderAcknowledgement("message-0")
	secondAck, _ := CanonicalProviderAcknowledgement("message-1")
	if len(result.Acknowledgements) != len(jobs) || result.Acknowledgements[0].JobID != jobs[0].JobID || result.Acknowledgements[0].ProviderAck != firstAck || result.Acknowledgements[1].JobID != jobs[1].JobID || result.Acknowledgements[1].ProviderAck != secondAck {
		t.Fatalf("publish acknowledgements drifted: %#v", result.Acknowledgements)
	}
}

func TestCanonicalProviderAcknowledgementNeverExposesProviderText(t *testing.T) {
	t.Parallel()
	providerValue := "AKIAIOSFODNN7EXAMPLE"
	acknowledgement, ok := CanonicalProviderAcknowledgement(providerValue)
	if !ok || acknowledgement != "sha256:1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3" {
		t.Fatalf("acknowledgement = %q, %v", acknowledgement, ok)
	}
	if strings.Contains(acknowledgement, providerValue) {
		t.Fatalf("provider value exposed in acknowledgement: %q", acknowledgement)
	}
	for _, invalid := range []string{"", " leading", "trailing ", "line\nbreak", strings.Repeat("a", 257), string([]byte{0xff})} {
		if value, ok := CanonicalProviderAcknowledgement(invalid); ok || value != "" {
			t.Fatalf("invalid provider message ID accepted: %q => %q", invalid, value)
		}
	}
}

func TestConsumeRejectsMalformedForeignAndNoncanonicalDeliveries(t *testing.T) {
	t.Parallel()

	jobs := fixtureJobs(t)
	queue := mustQueue(t, noCallDriver(), validConfig())
	messages, err := queue.messagesForJobs(jobs)
	if err != nil {
		t.Fatal(err)
	}
	base := func() []DriverDelivery {
		return []DriverDelivery{
			{Message: cloneDriverMessage(messages[0]), MessageID: "message-1", ReceiptHandle: "receipt-1", ReceiveCount: 1},
			{Message: cloneDriverMessage(messages[1]), MessageID: "message-2", ReceiptHandle: "receipt-2", ReceiveCount: 2},
		}
	}
	otherScope, err := domain.NewScope(
		mustProductID(t, "pid_60000000-0000-4000-8000-000000000006"),
		mustProductID(t, "pid_70000000-0000-4000-8000-000000000007"),
		mustProductID(t, "pid_80000000-0000-4000-8000-000000000008"),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]DriverDelivery) []DriverDelivery
	}{
		{name: "too many", mutate: func(values []DriverDelivery) []DriverDelivery { return append(values, values[0]) }},
		{name: "entry", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].Message.EntryID = "foreign"; return values }},
		{name: "scope", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].Message.Scope = otherScope; return values }},
		{name: "job id", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].Message.JobID = jobs[1].JobID; return values }},
		{name: "kind", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].Message.Kind = "foreign"; return values }},
		{name: "checksum", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].Message.SHA256[0] ^= 1; return values }},
		{name: "message id", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].MessageID = ""; return values }},
		{name: "receipt", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].ReceiptHandle = ""; return values }},
		{name: "receive count", mutate: func(values []DriverDelivery) []DriverDelivery { values[0].ReceiveCount = 0; return values }},
		{name: "duplicate job", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[1].Message = cloneDriverMessage(values[0].Message)
			return values
		}},
		{name: "duplicate message", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[1].MessageID = values[0].MessageID
			return values
		}},
		{name: "duplicate receipt", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[1].ReceiptHandle = values[0].ReceiptHandle
			return values
		}},
		{name: "unknown key", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[0].Message.Body = append(bytes.TrimSuffix(values[0].Message.Body, []byte("}")), []byte(`,"unknown":true}`)...)
			values[0].Message.SHA256 = sha256.Sum256(values[0].Message.Body)
			return values
		}},
		{name: "duplicate key", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[0].Message.Body = bytes.Replace(values[0].Message.Body, []byte(`"job_id":`), []byte(`"job_id":"pid_40000000-0000-4000-8000-000000000004","job_id":`), 1)
			values[0].Message.SHA256 = sha256.Sum256(values[0].Message.Body)
			return values
		}},
		{name: "whitespace", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[0].Message.Body = append([]byte(" "), values[0].Message.Body...)
			values[0].Message.SHA256 = sha256.Sum256(values[0].Message.Body)
			return values
		}},
		{name: "trailing", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[0].Message.Body = append(values[0].Message.Body, []byte("{}")...)
			values[0].Message.SHA256 = sha256.Sum256(values[0].Message.Body)
			return values
		}},
		{name: "version", mutate: func(values []DriverDelivery) []DriverDelivery {
			values[0].Message.Body = bytes.Replace(values[0].Message.Body, []byte(`"version":1`), []byte(`"version":2`), 1)
			values[0].Message.SHA256 = sha256.Sum256(values[0].Message.Body)
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := noCallDriver()
			driver.consume = func(context.Context, int) ([]DriverDelivery, error) { return test.mutate(base()), nil }
			testQueue := mustQueue(t, driver, validConfig())
			if deliveries, err := testQueue.ConsumeBatch(context.Background(), 2); !errors.Is(err, ErrConsume) || deliveries != nil {
				t.Fatalf("ConsumeBatch() = %#v, %v", deliveries, err)
			}
		})
	}
}

func TestAcknowledgeRejectsForgedDuplicateAndPartialState(t *testing.T) {
	t.Parallel()

	queue, deliveries := queueWithDeliveries(t)
	otherQueue, otherDeliveries := queueWithDeliveries(t)
	_ = otherQueue
	invalid := []struct {
		name     string
		receipts []Receipt
	}{
		{name: "empty"},
		{name: "forged", receipts: []Receipt{{}}},
		{name: "foreign queue", receipts: []Receipt{otherDeliveries[0].Receipt}},
		{name: "duplicate", receipts: []Receipt{deliveries[0].Receipt, deliveries[0].Receipt}},
		{name: "too many", receipts: func() []Receipt {
			values := make([]Receipt, 11)
			for index := range values {
				values[index] = deliveries[index%len(deliveries)].Receipt
			}
			return values
		}()},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if err := queue.AcknowledgeBatch(context.Background(), test.receipts); !errors.Is(err, ErrAcknowledge) {
				t.Fatalf("AcknowledgeBatch() error = %v", err)
			}
		})
	}
	for name, mutate := range map[string]func(*Receipt){
		"job id":         func(receipt *Receipt) { receipt.jobID = domain.ProductID{} },
		"driver job":     func(receipt *Receipt) { receipt.driver.JobID = domain.ProductID{} },
		"entry":          func(receipt *Receipt) { receipt.driver.EntryID = "foreign" },
		"message id":     func(receipt *Receipt) { receipt.driver.MessageID = "" },
		"receipt handle": func(receipt *Receipt) { receipt.driver.ReceiptHandle = "" },
	} {
		t.Run(name, func(t *testing.T) {
			receipt := deliveries[0].Receipt
			mutate(&receipt)
			if err := queue.AcknowledgeBatch(context.Background(), []Receipt{receipt}); !errors.Is(err, ErrAcknowledge) {
				t.Fatalf("AcknowledgeBatch() error = %v", err)
			}
		})
	}

	tests := []struct {
		name   string
		result func([]DriverReceipt) []domain.ProductID
	}{
		{name: "partial", result: func(receipts []DriverReceipt) []domain.ProductID { return []domain.ProductID{receipts[0].JobID} }},
		{name: "extra", result: func(receipts []DriverReceipt) []domain.ProductID {
			return []domain.ProductID{receipts[0].JobID, receipts[1].JobID, receipts[0].JobID}
		}},
		{name: "duplicate", result: func(receipts []DriverReceipt) []domain.ProductID {
			return []domain.ProductID{receipts[0].JobID, receipts[0].JobID}
		}},
		{name: "foreign", result: func(receipts []DriverReceipt) []domain.ProductID {
			return []domain.ProductID{receipts[0].JobID, mustProductID(t, "pid_90000000-0000-4000-8000-000000000009")}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := noCallDriver()
			driver.acknowledge = func(_ context.Context, receipts []DriverReceipt) ([]domain.ProductID, error) {
				return test.result(receipts), nil
			}
			testQueue := mustQueue(t, driver, validConfig())
			testReceipts := make([]Receipt, len(deliveries))
			for index, delivery := range deliveries {
				testReceipts[index] = delivery.Receipt
				testReceipts[index].owner = testQueue
			}
			if err := testQueue.AcknowledgeBatch(context.Background(), testReceipts); !errors.Is(err, ErrAcknowledge) {
				t.Fatalf("AcknowledgeBatch() error = %v", err)
			}
		})
	}
}

func TestReceiptExposesOnlyProductJobIdentity(t *testing.T) {
	t.Parallel()

	queue, deliveries := queueWithDeliveries(t)
	_ = queue
	receiptType := reflect.TypeOf(Receipt{})
	for index := 0; index < receiptType.NumField(); index++ {
		if receiptType.Field(index).IsExported() {
			t.Fatalf("Receipt field %q is exported", receiptType.Field(index).Name)
		}
	}
	if deliveries[0].Receipt.JobID() != deliveries[0].Job.JobID {
		t.Fatalf("receipt JobID = %s", deliveries[0].Receipt.JobID())
	}
	if !(Receipt{}).JobID().IsZero() {
		t.Fatal("zero receipt exposed nonzero job ID")
	}
}

func TestOperationsContainDriverFailuresCancellationAndPanics(t *testing.T) {
	t.Parallel()

	const secret = "provider-secret-must-not-escape"
	jobs := fixtureJobs(t)
	tests := []struct {
		name string
		run  func(*Queue, context.Context) error
		set  func(*recordingDriver)
		want error
	}{
		{
			name: "publish error",
			set: func(driver *recordingDriver) {
				driver.publish = func(context.Context, []DriverMessage) ([]DriverPublished, error) { return nil, errors.New(secret) }
			},
			run:  func(queue *Queue, ctx context.Context) error { _, err := queue.PublishBatch(ctx, jobs); return err },
			want: ErrPublish,
		},
		{
			name: "publish panic",
			set: func(driver *recordingDriver) {
				driver.publish = func(context.Context, []DriverMessage) ([]DriverPublished, error) { panic(secret) }
			},
			run:  func(queue *Queue, ctx context.Context) error { _, err := queue.PublishBatch(ctx, jobs); return err },
			want: ErrPublish,
		},
		{
			name: "consume error",
			set: func(driver *recordingDriver) {
				driver.consume = func(context.Context, int) ([]DriverDelivery, error) { return nil, errors.New(secret) }
			},
			run:  func(queue *Queue, ctx context.Context) error { _, err := queue.ConsumeBatch(ctx, 2); return err },
			want: ErrConsume,
		},
		{
			name: "consume panic",
			set: func(driver *recordingDriver) {
				driver.consume = func(context.Context, int) ([]DriverDelivery, error) { panic(secret) }
			},
			run:  func(queue *Queue, ctx context.Context) error { _, err := queue.ConsumeBatch(ctx, 2); return err },
			want: ErrConsume,
		},
		{
			name: "ack error",
			set: func(driver *recordingDriver) {
				driver.acknowledge = func(context.Context, []DriverReceipt) ([]domain.ProductID, error) { return nil, errors.New(secret) }
			},
			run: func(queue *Queue, ctx context.Context) error {
				return queue.AcknowledgeBatch(ctx, []Receipt{fixtureReceipt(queue, jobs[0].JobID, "1")})
			},
			want: ErrAcknowledge,
		},
		{
			name: "ack panic",
			set: func(driver *recordingDriver) {
				driver.acknowledge = func(context.Context, []DriverReceipt) ([]domain.ProductID, error) { panic(secret) }
			},
			run: func(queue *Queue, ctx context.Context) error {
				return queue.AcknowledgeBatch(ctx, []Receipt{fixtureReceipt(queue, jobs[0].JobID, "1")})
			},
			want: ErrAcknowledge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := noCallDriver()
			test.set(driver)
			queue := mustQueue(t, driver, validConfig())
			err := test.run(queue, context.Background())
			if !errors.Is(err, test.want) || strings.Contains(err.Error(), secret) {
				t.Fatalf("operation error = %q, want %v", err, test.want)
			}
		})
	}

	driver := noCallDriver()
	driver.publish = func(ctx context.Context, _ []DriverMessage) ([]DriverPublished, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	timeoutQueue := mustQueue(t, driver, Config{
		OperationTimeout:     5 * time.Millisecond,
		MaximumBatchMessages: 10,
		MaximumMessageBytes:  1024,
		MaximumBatchBytes:    4096,
	})
	if _, err := timeoutQueue.PublishBatch(context.Background(), jobs); !errors.Is(err, ErrPublish) {
		t.Fatalf("timeout error = %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	driver.publish = func(context.Context, []DriverMessage) ([]DriverPublished, error) {
		calls.Add(1)
		return nil, nil
	}
	if _, err := timeoutQueue.PublishBatch(cancelled, jobs); !errors.Is(err, ErrPublish) {
		t.Fatalf("canceled error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("canceled operation driver calls = %d", calls.Load())
	}
}

func TestOperationsRejectNilInvalidAndCanceledInputsWithoutDriverIO(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	driver := noCallDriver()
	driver.publish = func(context.Context, []DriverMessage) ([]DriverPublished, error) {
		calls.Add(1)
		return nil, nil
	}
	driver.consume = func(context.Context, int) ([]DriverDelivery, error) {
		calls.Add(1)
		return nil, nil
	}
	driver.acknowledge = func(context.Context, []DriverReceipt) ([]domain.ProductID, error) {
		calls.Add(1)
		return nil, nil
	}
	queue := mustQueue(t, driver, validConfig())
	jobs := fixtureJobs(t)
	receipt := fixtureReceipt(queue, jobs[0].JobID, "1")

	var nilQueue *Queue
	if _, err := nilQueue.PublishBatch(context.Background(), jobs); !errors.Is(err, ErrPublish) {
		t.Fatalf("nil queue publish error = %v", err)
	}
	if _, err := nilQueue.ConsumeBatch(context.Background(), 1); !errors.Is(err, ErrConsume) {
		t.Fatalf("nil queue consume error = %v", err)
	}
	if err := nilQueue.AcknowledgeBatch(context.Background(), []Receipt{receipt}); !errors.Is(err, ErrAcknowledge) {
		t.Fatalf("nil queue acknowledge error = %v", err)
	}
	if _, err := queue.PublishBatch(nil, jobs); !errors.Is(err, ErrPublish) {
		t.Fatalf("nil context publish error = %v", err)
	}
	if _, err := queue.ConsumeBatch(nil, 1); !errors.Is(err, ErrConsume) {
		t.Fatalf("nil context consume error = %v", err)
	}
	if err := queue.AcknowledgeBatch(nil, []Receipt{receipt}); !errors.Is(err, ErrAcknowledge) {
		t.Fatalf("nil context acknowledge error = %v", err)
	}
	for _, maximum := range []int{-1, 0, 11} {
		if _, err := queue.ConsumeBatch(context.Background(), maximum); !errors.Is(err, ErrConsume) {
			t.Fatalf("ConsumeBatch(%d) error = %v", maximum, err)
		}
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := queue.PublishBatch(cancelled, jobs); !errors.Is(err, ErrPublish) {
		t.Fatalf("canceled publish error = %v", err)
	}
	if _, err := queue.ConsumeBatch(cancelled, 1); !errors.Is(err, ErrConsume) {
		t.Fatalf("canceled consume error = %v", err)
	}
	if err := queue.AcknowledgeBatch(cancelled, []Receipt{receipt}); !errors.Is(err, ErrAcknowledge) {
		t.Fatalf("canceled acknowledge error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("driver calls = %d", calls.Load())
	}
}

func TestConsumeAndAcknowledgeHonorConfiguredDeadline(t *testing.T) {
	t.Parallel()

	driver := noCallDriver()
	driver.consume = func(ctx context.Context, _ int) ([]DriverDelivery, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	driver.acknowledge = func(ctx context.Context, _ []DriverReceipt) ([]domain.ProductID, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	queue := mustQueue(t, driver, Config{
		OperationTimeout:     5 * time.Millisecond,
		MaximumBatchMessages: 10,
		MaximumMessageBytes:  1024,
		MaximumBatchBytes:    4096,
	})
	if _, err := queue.ConsumeBatch(context.Background(), 1); !errors.Is(err, ErrConsume) {
		t.Fatalf("ConsumeBatch timeout error = %v", err)
	}
	jobID := fixtureJobs(t)[0].JobID
	if err := queue.AcknowledgeBatch(context.Background(), []Receipt{fixtureReceipt(queue, jobID, "1")}); !errors.Is(err, ErrAcknowledge) {
		t.Fatalf("AcknowledgeBatch timeout error = %v", err)
	}
}

func TestConsumeDefensivelyCopiesDriverBytesAndAcceptsEmptyQueue(t *testing.T) {
	t.Parallel()

	jobs := fixtureJobs(t)
	driver := noCallDriver()
	queue := mustQueue(t, driver, validConfig())
	messages, err := queue.messagesForJobs(jobs[:1])
	if err != nil {
		t.Fatal(err)
	}
	returned := []DriverDelivery{{
		Message:       cloneDriverMessage(messages[0]),
		MessageID:     "message",
		ReceiptHandle: "receipt",
		ReceiveCount:  1,
	}}
	driver.consume = func(context.Context, int) ([]DriverDelivery, error) { return returned, nil }
	deliveries, err := queue.ConsumeBatch(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	returned[0].Message.Body[0] = 'X'
	if deliveries[0].Job.Payload[0] != '{' {
		t.Fatal("delivery retained driver-owned bytes")
	}
	driver.consume = func(context.Context, int) ([]DriverDelivery, error) { return []DriverDelivery{}, nil }
	empty, err := queue.ConsumeBatch(context.Background(), 1)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty ConsumeBatch() = %#v, %v", empty, err)
	}
}

func TestQueueSupportsConcurrentIndependentOperations(t *testing.T) {
	t.Parallel()

	jobs := fixtureJobs(t)
	driver := noCallDriver()
	driver.publish = func(_ context.Context, messages []DriverMessage) ([]DriverPublished, error) {
		return []DriverPublished{{EntryID: messages[0].EntryID, JobID: messages[0].JobID, MessageID: "message"}}, nil
	}
	queue := mustQueue(t, driver, validConfig())
	var group sync.WaitGroup
	failures := make(chan error, 32)
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := queue.PublishBatch(context.Background(), jobs[:1])
			if err != nil {
				failures <- err
				return
			}
			if len(result.JobIDs) != 1 || result.JobIDs[0] != jobs[0].JobID {
				failures <- fmt.Errorf("unexpected result %#v", result)
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func validConfig() Config {
	return Config{
		OperationTimeout:     time.Second,
		MaximumBatchMessages: 10,
		MaximumMessageBytes:  1024,
		MaximumBatchBytes:    4096,
	}
}

func fixtureJobs(t *testing.T) []Job {
	t.Helper()
	scope := fixtureScope(t)
	return []Job{
		{
			Scope:   scope,
			JobID:   mustProductID(t, "pid_40000000-0000-4000-8000-000000000004"),
			Kind:    "evidence.collect",
			Payload: []byte(`{"action":"scan"}`),
		},
		{
			Scope:   scope,
			JobID:   mustProductID(t, "pid_50000000-0000-4000-8000-000000000005"),
			Kind:    "event.correlate",
			Payload: []byte(`{"attempt":1}`),
		},
	}
}

func mustQueue(t *testing.T, driver Driver, config Config) *Queue {
	t.Helper()
	queue, err := New(driver, config)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return queue
}

func noCallDriver() *recordingDriver {
	return &recordingDriver{
		publish: func(context.Context, []DriverMessage) ([]DriverPublished, error) {
			panic("unexpected PublishBatch call")
		},
		consume: func(context.Context, int) ([]DriverDelivery, error) {
			panic("unexpected ConsumeBatch call")
		},
		acknowledge: func(context.Context, []DriverReceipt) ([]domain.ProductID, error) {
			panic("unexpected AcknowledgeBatch call")
		},
	}
}

func queueWithDeliveries(t *testing.T) (*Queue, []Delivery) {
	t.Helper()
	driver := noCallDriver()
	queue := mustQueue(t, driver, validConfig())
	messages, err := queue.messagesForJobs(fixtureJobs(t))
	if err != nil {
		t.Fatal(err)
	}
	driver.consume = func(context.Context, int) ([]DriverDelivery, error) {
		return []DriverDelivery{
			{Message: cloneDriverMessage(messages[0]), MessageID: "message-1", ReceiptHandle: "receipt-1", ReceiveCount: 1},
			{Message: cloneDriverMessage(messages[1]), MessageID: "message-2", ReceiptHandle: "receipt-2", ReceiveCount: 2},
		}, nil
	}
	deliveries, err := queue.ConsumeBatch(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	return queue, deliveries
}

func fixtureReceipt(queue *Queue, jobID domain.ProductID, suffix string) Receipt {
	return Receipt{
		jobID: jobID,
		owner: queue,
		driver: DriverReceipt{
			EntryID:       jobID.String(),
			JobID:         jobID,
			MessageID:     "message-" + suffix,
			ReceiptHandle: "receipt-" + suffix,
		},
	}
}

func fixtureScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		mustProductID(t, "pid_10000000-0000-4000-8000-000000000001"),
		mustProductID(t, "pid_20000000-0000-4000-8000-000000000002"),
		mustProductID(t, "pid_30000000-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	return scope
}

func mustProductID(t *testing.T, text string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q) error = %v", text, err)
	}
	return id
}

func expectedBody(job Job) []byte {
	return []byte(fmt.Sprintf(
		`{"version":1,"job_id":"%s","organization_id":"%s","workspace_id":"%s","environment_id":"%s","kind":"%s","payload":%s}`,
		job.JobID.String(),
		job.Scope.OrganizationID().String(),
		job.Scope.WorkspaceID().String(),
		job.Scope.EnvironmentID().String(),
		job.Kind,
		job.Payload,
	))
}

func cloneMessages(messages []DriverMessage) []DriverMessage {
	cloned := make([]DriverMessage, len(messages))
	for index, message := range messages {
		cloned[index] = cloneMessage(message)
	}
	return cloned
}

func cloneMessage(message DriverMessage) DriverMessage {
	message.Body = bytes.Clone(message.Body)
	return message
}

func requireOperationDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("driver context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > time.Second {
		t.Fatalf("driver deadline remaining = %s", remaining)
	}
}
