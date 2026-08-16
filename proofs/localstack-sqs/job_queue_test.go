package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const jobQueueURL = "http://127.0.0.1:4566/000000000000/zasp-m1-13-test-source"

type fakeJobBatchAPI struct {
	send    func(context.Context, string, []outgoingMessage) (jobBatchSendResult, error)
	receive func(context.Context, string, int) ([]receivedMessage, error)
	delete  func(context.Context, string, []jobDeleteEntry) (jobBatchDeleteResult, error)
}

func (api *fakeJobBatchAPI) SendJobBatch(ctx context.Context, queueURL string, entries []outgoingMessage) (jobBatchSendResult, error) {
	return api.send(ctx, queueURL, entries)
}

func (api *fakeJobBatchAPI) ReceiveJobMessages(ctx context.Context, queueURL string, maximum int) ([]receivedMessage, error) {
	return api.receive(ctx, queueURL, maximum)
}

func (api *fakeJobBatchAPI) DeleteJobBatch(ctx context.Context, queueURL string, entries []jobDeleteEntry) (jobBatchDeleteResult, error) {
	return api.delete(ctx, queueURL, entries)
}

func TestJobQueueDriverMapsTwoExactScopedMessages(t *testing.T) {
	t.Parallel()

	messages := jobDriverMessages(t)
	api := noCallJobBatchAPI()
	api.send = func(_ context.Context, queueURL string, entries []outgoingMessage) (jobBatchSendResult, error) {
		if queueURL != jobQueueURL || len(entries) != len(messages) {
			t.Fatalf("SendJobBatch(%q) entries = %#v", queueURL, entries)
		}
		successes := make([]jobBatchSendSuccess, len(entries))
		for index, entry := range entries {
			wantAttributes := expectedJobAttributes(messages[index])
			if entry.ID != messages[index].EntryID || entry.Body != string(messages[index].Body) ||
				!reflect.DeepEqual(entry.Attributes, wantAttributes) {
				t.Fatalf("entry %d = %#v", index, entry)
			}
			successes[index] = jobBatchSendSuccess{
				ID:         entry.ID,
				MessageID:  "provider-message-" + string(rune('1'+index)),
				BodyDigest: md5Hex(entry.Body),
			}
		}
		return jobBatchSendResult{Successful: successes}, nil
	}
	driver := mustJobDriver(t, api)
	published, err := driver.PublishBatch(context.Background(), messages)
	if err != nil {
		t.Fatalf("PublishBatch() error = %v", err)
	}
	if len(published) != 2 {
		t.Fatalf("published = %#v", published)
	}
	for index, result := range published {
		if result.EntryID != messages[index].EntryID || result.JobID != messages[index].JobID ||
			result.MessageID != "provider-message-"+string(rune('1'+index)) {
			t.Fatalf("published %d = %#v", index, result)
		}
	}
}

func TestJobQueueDriverEnforcesSQSBodyAndAttributeByteLimit(t *testing.T) {
	t.Parallel()

	messages := jobDriverMessages(t)
	const firstAttributeBytes = 338
	accepted := messages[0]
	accepted.Body = []byte(strings.Repeat("x", jobMessageLimit-firstAttributeBytes))
	accepted.SHA256 = sha256.Sum256(accepted.Body)

	api := noCallJobBatchAPI()
	api.send = func(_ context.Context, _ string, entries []outgoingMessage) (jobBatchSendResult, error) {
		return jobBatchSendResult{Successful: []jobBatchSendSuccess{{
			ID: entries[0].ID, MessageID: "provider-message", BodyDigest: md5Hex(entries[0].Body),
		}}}, nil
	}
	driver := mustJobDriver(t, api)
	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{accepted}); err != nil {
		t.Fatalf("exact-limit PublishBatch() error = %v", err)
	}

	over := accepted
	over.Body = append(append([]byte(nil), accepted.Body...), 'x')
	over.SHA256 = sha256.Sum256(over.Body)
	if _, err := driver.PublishBatch(context.Background(), []jobqueue.DriverMessage{over}); !errors.Is(err, errMessage) {
		t.Fatalf("over-limit PublishBatch() error = %v", err)
	}
}

func TestJobQueueDriverEnforcesSQSBatchBodyAndAttributeByteLimit(t *testing.T) {
	t.Parallel()

	messages := jobDriverMessages(t)
	const (
		firstAttributeBytes  = 338
		secondAttributeBytes = 337
	)
	messages[0].Body = []byte(strings.Repeat("a", jobMessageLimit/2+1-firstAttributeBytes))
	messages[0].SHA256 = sha256.Sum256(messages[0].Body)
	messages[1].Body = []byte(strings.Repeat("b", jobMessageLimit/2+1-secondAttributeBytes))
	messages[1].SHA256 = sha256.Sum256(messages[1].Body)

	driver := mustJobDriver(t, noCallJobBatchAPI())
	if _, err := driver.PublishBatch(context.Background(), messages); !errors.Is(err, errMessage) {
		t.Fatalf("over-limit batch PublishBatch() error = %v", err)
	}
}

func TestJobQueueDriverStrictlyReconstructsConsumedMessages(t *testing.T) {
	t.Parallel()

	messages := jobDriverMessages(t)
	api := noCallJobBatchAPI()
	api.receive = func(_ context.Context, queueURL string, maximum int) ([]receivedMessage, error) {
		if queueURL != jobQueueURL || maximum != 2 {
			t.Fatalf("ReceiveJobMessages(%q, %d)", queueURL, maximum)
		}
		results := make([]receivedMessage, len(messages))
		for index, message := range messages {
			results[index] = receivedMessage{
				Body:          string(message.Body),
				Attributes:    expectedJobAttributes(message),
				MessageID:     "provider-message-" + string(rune('1'+index)),
				ReceiptHandle: "provider-receipt-" + string(rune('1'+index)),
				BodyDigest:    md5Hex(string(message.Body)),
			}
		}
		return results, nil
	}
	driver := mustJobDriver(t, api)
	deliveries, err := driver.ConsumeBatch(context.Background(), 2)
	if err != nil {
		t.Fatalf("ConsumeBatch() error = %v", err)
	}
	if len(deliveries) != len(messages) {
		t.Fatalf("deliveries = %#v", deliveries)
	}
	for index, delivery := range deliveries {
		if delivery.Message.EntryID != messages[index].EntryID || delivery.Message.Scope != messages[index].Scope ||
			delivery.Message.JobID != messages[index].JobID || delivery.Message.Kind != messages[index].Kind ||
			string(delivery.Message.Body) != string(messages[index].Body) || delivery.Message.SHA256 != messages[index].SHA256 ||
			delivery.MessageID != "provider-message-"+string(rune('1'+index)) ||
			delivery.ReceiptHandle != "provider-receipt-"+string(rune('1'+index)) {
			t.Fatalf("delivery %d = %#v", index, delivery)
		}
	}
}

func TestJobQueueDriverAcknowledgesOneExactBatch(t *testing.T) {
	t.Parallel()

	messages := jobDriverMessages(t)
	receipts := make([]jobqueue.DriverReceipt, len(messages))
	for index, message := range messages {
		receipts[index] = jobqueue.DriverReceipt{
			EntryID:       message.EntryID,
			JobID:         message.JobID,
			MessageID:     "provider-message-" + string(rune('1'+index)),
			ReceiptHandle: "provider-receipt-" + string(rune('1'+index)),
		}
	}
	api := noCallJobBatchAPI()
	api.delete = func(_ context.Context, queueURL string, entries []jobDeleteEntry) (jobBatchDeleteResult, error) {
		if queueURL != jobQueueURL || len(entries) != len(receipts) {
			t.Fatalf("DeleteJobBatch(%q) entries = %#v", queueURL, entries)
		}
		for index, entry := range entries {
			if entry.ID != receipts[index].EntryID || entry.ReceiptHandle != receipts[index].ReceiptHandle {
				t.Fatalf("delete entry %d = %#v", index, entry)
			}
		}
		return jobBatchDeleteResult{SuccessfulIDs: []string{entries[1].ID, entries[0].ID}}, nil
	}
	driver := mustJobDriver(t, api)
	acknowledged, err := driver.AcknowledgeBatch(context.Background(), receipts)
	if err != nil {
		t.Fatalf("AcknowledgeBatch() error = %v", err)
	}
	if !reflect.DeepEqual(acknowledged, []domain.ProductID{messages[0].JobID, messages[1].JobID}) {
		t.Fatalf("acknowledged = %#v", acknowledged)
	}
}

func TestJobQueueDriverRejectsPartialForeignAndMalformedProviderState(t *testing.T) {
	t.Parallel()

	messages := jobDriverMessages(t)
	tests := []struct {
		name string
		run  func(*sqsJobDriver) error
		api  func() *fakeJobBatchAPI
		want error
	}{
		{
			name: "partial publish",
			api: func() *fakeJobBatchAPI {
				api := noCallJobBatchAPI()
				api.send = func(context.Context, string, []outgoingMessage) (jobBatchSendResult, error) {
					return jobBatchSendResult{
						Successful: []jobBatchSendSuccess{{ID: messages[0].EntryID, MessageID: "message", BodyDigest: md5Hex(string(messages[0].Body))}},
						FailedIDs:  []string{messages[1].EntryID},
					}, nil
				}
				return api
			},
			run: func(driver *sqsJobDriver) error {
				_, err := driver.PublishBatch(context.Background(), messages)
				return err
			},
			want: errMessage,
		},
		{
			name: "foreign receive attribute",
			api: func() *fakeJobBatchAPI {
				api := noCallJobBatchAPI()
				api.receive = func(context.Context, string, int) ([]receivedMessage, error) {
					attributes := expectedJobAttributes(messages[0])
					attributes[organizationAttribute] = messageAttribute{
						DataType: "String",
						Value:    "pid_90000000-0000-4000-8000-000000000009",
					}
					return []receivedMessage{{
						Body: string(messages[0].Body), Attributes: attributes, MessageID: "message",
						ReceiptHandle: "receipt", BodyDigest: md5Hex(string(messages[0].Body)),
					}}, nil
				}
				return api
			},
			run: func(driver *sqsJobDriver) error {
				queue, err := jobqueue.New(driver, jobqueue.Config{
					OperationTimeout: time.Second, MaximumBatchMessages: 10,
					MaximumMessageBytes: 1024, MaximumBatchBytes: 4096,
				})
				if err != nil {
					return err
				}
				_, err = queue.ConsumeBatch(context.Background(), 1)
				return err
			},
			want: jobqueue.ErrConsume,
		},
		{
			name: "partial delete",
			api: func() *fakeJobBatchAPI {
				api := noCallJobBatchAPI()
				api.delete = func(context.Context, string, []jobDeleteEntry) (jobBatchDeleteResult, error) {
					return jobBatchDeleteResult{SuccessfulIDs: []string{messages[0].EntryID}, FailedIDs: []string{messages[1].EntryID}}, nil
				}
				return api
			},
			run: func(driver *sqsJobDriver) error {
				receipts := []jobqueue.DriverReceipt{
					{EntryID: messages[0].EntryID, JobID: messages[0].JobID, MessageID: "message-1", ReceiptHandle: "receipt-1"},
					{EntryID: messages[1].EntryID, JobID: messages[1].JobID, MessageID: "message-2", ReceiptHandle: "receipt-2"},
				}
				_, err := driver.AcknowledgeBatch(context.Background(), receipts)
				return err
			},
			want: errMessage,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			driver := mustJobDriver(t, test.api())
			if err := test.run(driver); !errors.Is(err, test.want) {
				t.Fatalf("operation error = %v", err)
			}
		})
	}
}

func TestJobQueueDriverContainsProviderErrorsAndPanics(t *testing.T) {
	t.Parallel()

	const secret = "provider-secret-must-not-escape"
	messages := jobDriverMessages(t)
	for _, panics := range []bool{false, true} {
		api := noCallJobBatchAPI()
		api.send = func(context.Context, string, []outgoingMessage) (jobBatchSendResult, error) {
			if panics {
				panic(secret)
			}
			return jobBatchSendResult{}, errors.New(secret)
		}
		driver := mustJobDriver(t, api)
		_, err := driver.PublishBatch(context.Background(), messages)
		if !errors.Is(err, errProvider) || strings.Contains(err.Error(), secret) {
			t.Fatalf("PublishBatch() error = %q", err)
		}
	}
}

func TestJobQueueBoundaryExists(t *testing.T) {
	t.Parallel()

	_ = newSQSJobDriver
	_ = RunJobQueueProof
	var _ JobQueueProofOptions
}

func TestJobQueueDriverAcceptsOnlyLoopbackLocalStackQueueURLs(t *testing.T) {
	t.Parallel()

	api := noCallJobBatchAPI()
	for _, accepted := range []string{
		"http://127.0.0.1:49152/000000000000/source",
		"http://localhost:49152/000000000000/source",
		"http://sqs.us-east-1.localhost.localstack.cloud:49152/000000000000/source",
	} {
		if _, err := newSQSJobDriver(api, accepted); err != nil {
			t.Fatalf("newSQSJobDriver(%q) error = %v", accepted, err)
		}
	}
	for _, rejected := range []string{
		"", "https://127.0.0.1:49152/000000000000/source",
		"http://example.com:49152/000000000000/source",
		"http://127.0.0.1:49152/source",
	} {
		if _, err := newSQSJobDriver(api, rejected); !errors.Is(err, errConfiguration) {
			t.Fatalf("newSQSJobDriver(%q) error = %v", rejected, err)
		}
	}
}

func mustJobDriver(t *testing.T, api jobBatchAPI) *sqsJobDriver {
	t.Helper()
	driver, err := newSQSJobDriver(api, jobQueueURL)
	if err != nil {
		t.Fatalf("newSQSJobDriver() error = %v", err)
	}
	return driver
}

func noCallJobBatchAPI() *fakeJobBatchAPI {
	return &fakeJobBatchAPI{
		send: func(context.Context, string, []outgoingMessage) (jobBatchSendResult, error) {
			panic("unexpected SendJobBatch call")
		},
		receive: func(context.Context, string, int) ([]receivedMessage, error) {
			panic("unexpected ReceiveJobMessages call")
		},
		delete: func(context.Context, string, []jobDeleteEntry) (jobBatchDeleteResult, error) {
			panic("unexpected DeleteJobBatch call")
		},
	}
}

func jobDriverMessages(t *testing.T) []jobqueue.DriverMessage {
	t.Helper()
	scope, err := domain.NewScope(
		mustJobProductID(t, "pid_10000000-0000-4000-8000-000000000001"),
		mustJobProductID(t, "pid_20000000-0000-4000-8000-000000000002"),
		mustJobProductID(t, "pid_30000000-0000-4000-8000-000000000003"),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		id      string
		kind    string
		payload string
	}{
		{id: "pid_40000000-0000-4000-8000-000000000004", kind: "evidence.collect", payload: `{"action":"scan"}`},
		{id: "pid_50000000-0000-4000-8000-000000000005", kind: "event.correlate", payload: `{"attempt":1}`},
	}
	messages := make([]jobqueue.DriverMessage, len(fixtures))
	for index, fixture := range fixtures {
		jobID := mustJobProductID(t, fixture.id)
		body := []byte(`{"version":1,"job_id":"` + jobID.String() +
			`","organization_id":"` + scope.OrganizationID().String() +
			`","workspace_id":"` + scope.WorkspaceID().String() +
			`","environment_id":"` + scope.EnvironmentID().String() +
			`","kind":"` + fixture.kind + `","payload":` + fixture.payload + `}`)
		messages[index] = jobqueue.DriverMessage{
			EntryID: jobID.String(), Scope: scope, JobID: jobID, Kind: fixture.kind,
			Body: body, SHA256: sha256.Sum256(body),
		}
	}
	return messages
}

func mustJobProductID(t *testing.T, text string) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func expectedJobAttributes(message jobqueue.DriverMessage) map[string]messageAttribute {
	return map[string]messageAttribute{
		organizationAttribute: {DataType: "String", Value: message.Scope.OrganizationID().String()},
		workspaceAttribute:    {DataType: "String", Value: message.Scope.WorkspaceID().String()},
		environmentAttribute:  {DataType: "String", Value: message.Scope.EnvironmentID().String()},
		jobIDAttribute:        {DataType: "String", Value: message.JobID.String()},
		jobKindAttribute:      {DataType: "String", Value: message.Kind},
		digestAttribute:       {DataType: "String", Value: hex.EncodeToString(message.SHA256[:])},
	}
}
