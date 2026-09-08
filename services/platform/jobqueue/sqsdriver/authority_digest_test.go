package sqsdriver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func TestProductionQueuePreservesAuthorityDigestThroughSQS(t *testing.T) {
	fixture := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"runtime"}`)
	digest := sha256.Sum256([]byte("durable-runtime-outbox-authority"))
	var body string
	client := &stubClient{send: func(_ context.Context, input *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
		body = aws.ToString(input.Entries[0].MessageBody)
		if !strings.Contains(body, `"authority_digest":"`+hex.EncodeToString(digest[:])+`"`) {
			t.Fatal("authority digest omitted")
		}
		return &sqs.SendMessageBatchOutput{Successful: []types.SendMessageBatchResultEntry{{Id: input.Entries[0].Id, MessageId: aws.String("runtime-message-1"), MD5OfMessageBody: aws.String(md5Hex([]byte(body)))}}}, nil
	}, receive: func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
		return &sqs.ReceiveMessageOutput{Messages: []types.Message{{Body: &body, MessageId: aws.String("runtime-message-1"), ReceiptHandle: aws.String("runtime-receipt-1"), MD5OfBody: aws.String(md5Hex([]byte(body))), Attributes: map[string]string{"ApproximateReceiveCount": "1"}}}}, nil
	}}
	queue, err := jobqueue.New(mustDriver(t, client), jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
	if err != nil {
		t.Fatal(err)
	}
	job := jobqueue.Job{Scope: fixture.Scope, JobID: fixture.JobID, Kind: "runtime", Payload: []byte(`{"action":"runtime"}`), AuthorityDigest: digest}
	if _, err := queue.PublishBatch(context.Background(), []jobqueue.Job{job}); err != nil {
		t.Fatalf("production runtime publish: %v; provider called=%t", err, body != "")
	}
	deliveries, err := queue.ConsumeBatch(context.Background(), 1)
	if err != nil || len(deliveries) != 1 || deliveries[0].Job.AuthorityDigest != digest {
		t.Fatalf("runtime authority round trip: deliveries=%#v err=%v", deliveries, err)
	}
}

func TestCanonicalEnvelopeRejectsMalformedAuthorityDigests(t *testing.T) {
	fixture := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"scan"}`)
	for _, digest := range []string{"short", strings.Repeat("A", 64), strings.Repeat("0", 64), strings.Repeat("g", 64)} {
		body := append(append([]byte(nil), fixture.Body[:len(fixture.Body)-1]...), []byte(`,"authority_digest":"`+digest+`"}`)...)
		if _, ok := parseCanonicalEnvelope(body); ok {
			t.Fatalf("accepted malformed digest %q", digest)
		}
	}
}

func TestProductionQueueConsumesExactPhysicalDuplicatesIndividually(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(fmt.Sprintf("drift=%t", drift), func(t *testing.T) {
			fixture := fixtureMessage(t, "pid_40000000-0000-4000-8000-000000000004", `{"action":"runtime"}`)
			second := string(fixture.Body)
			if drift {
				second = strings.Replace(second, "runtime", "changed", 1)
			}
			deleted := 0
			client := &stubClient{receive: func(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
				messages := []types.Message{}
				for i, body := range []string{string(fixture.Body), second} {
					messages = append(messages, types.Message{Body: aws.String(body), MessageId: aws.String(fmt.Sprintf("physical-%d", i)), ReceiptHandle: aws.String(fmt.Sprintf("receipt-%d", i)), MD5OfBody: aws.String(md5Hex([]byte(body))), Attributes: map[string]string{"ApproximateReceiveCount": "1"}})
				}
				return &sqs.ReceiveMessageOutput{Messages: messages}, nil
			}, delete: func(_ context.Context, input *sqs.DeleteMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
				if len(input.Entries) != 1 {
					t.Fatal("duplicate physical receipts must be acknowledged separately")
				}
				deleted++
				return &sqs.DeleteMessageBatchOutput{Successful: []types.DeleteMessageBatchResultEntry{{Id: input.Entries[0].Id}}}, nil
			}}
			queue, err := jobqueue.New(mustDriver(t, client), jobqueue.Config{OperationTimeout: time.Second, MaximumBatchMessages: 10, MaximumMessageBytes: 262144, MaximumBatchBytes: 1048576})
			if err != nil {
				t.Fatal(err)
			}
			deliveries, err := queue.ConsumeBatch(context.Background(), 2)
			if drift {
				if err == nil {
					t.Fatal("drifted same-job envelopes accepted")
				}
				return
			}
			if err != nil || len(deliveries) != 2 {
				t.Fatalf("physical duplicate consume=%d err=%v", len(deliveries), err)
			}
			for _, delivery := range deliveries {
				if err := queue.AcknowledgeBatch(context.Background(), []jobqueue.Receipt{delivery.Receipt}); err != nil {
					t.Fatal(err)
				}
			}
			if deleted != 2 {
				t.Fatalf("physical deletions=%d", deleted)
			}
		})
	}
}
