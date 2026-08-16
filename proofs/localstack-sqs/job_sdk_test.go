package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestSDKJobBatchMethodsUseOneExactMultiEntryRequestEach(t *testing.T) {
	t.Parallel()

	entries := []outgoingMessage{
		{ID: "entry-1", Body: `{"one":1}`, Attributes: map[string]messageAttribute{"job_id": {DataType: "String", Value: "job-1"}}},
		{ID: "entry-2", Body: `{"two":2}`, Attributes: map[string]messageAttribute{"job_id": {DataType: "String", Value: "job-2"}}},
	}
	call := 0
	client := sdkJobClientWithTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		call++
		target := request.Header.Get("X-Amz-Target")
		var document map[string]any
		if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		switch call {
		case 1:
			if target != "AmazonSQS.SendMessageBatch" || document["QueueUrl"] != jobQueueURL {
				t.Fatalf("send request target=%q document=%#v", target, document)
			}
			sent, ok := document["Entries"].([]any)
			if !ok || len(sent) != 2 {
				t.Fatalf("send entries = %#v", document["Entries"])
			}
			for index, raw := range sent {
				entry := raw.(map[string]any)
				if entry["Id"] != entries[index].ID || entry["MessageBody"] != entries[index].Body {
					t.Fatalf("send entry %d = %#v", index, entry)
				}
				attributes := entry["MessageAttributes"].(map[string]any)
				jobID := attributes["job_id"].(map[string]any)
				if jobID["DataType"] != "String" || jobID["StringValue"] != "job-"+string(rune('1'+index)) {
					t.Fatalf("send attributes %d = %#v", index, attributes)
				}
			}
			return sdkJSONResponse(request, `{"Successful":[{"Id":"entry-1","MessageId":"message-1","MD5OfMessageBody":"`+
				md5Hex(entries[0].Body)+`"},{"Id":"entry-2","MessageId":"message-2","MD5OfMessageBody":"`+
				md5Hex(entries[1].Body)+`"}],"Failed":[]}`), nil
		case 2:
			if target != "AmazonSQS.ReceiveMessage" || document["QueueUrl"] != jobQueueURL ||
				document["MaxNumberOfMessages"] != float64(2) ||
				!reflect.DeepEqual(document["MessageAttributeNames"], []any{"All"}) {
				t.Fatalf("receive request target=%q document=%#v", target, document)
			}
			return sdkJSONResponse(request, `{"Messages":[{"Body":"{\"one\":1}","MessageId":"message-1","ReceiptHandle":"receipt-1","MD5OfBody":"`+
				md5Hex(entries[0].Body)+`","MessageAttributes":{"job_id":{"DataType":"String","StringValue":"job-1"}}},{"Body":"{\"two\":2}","MessageId":"message-2","ReceiptHandle":"receipt-2","MD5OfBody":"`+
				md5Hex(entries[1].Body)+`","MessageAttributes":{"job_id":{"DataType":"String","StringValue":"job-2"}}}]}`), nil
		case 3:
			if target != "AmazonSQS.DeleteMessageBatch" || document["QueueUrl"] != jobQueueURL {
				t.Fatalf("delete request target=%q document=%#v", target, document)
			}
			deleted, ok := document["Entries"].([]any)
			if !ok || len(deleted) != 2 {
				t.Fatalf("delete entries = %#v", document["Entries"])
			}
			for index, raw := range deleted {
				entry := raw.(map[string]any)
				if entry["Id"] != entries[index].ID || entry["ReceiptHandle"] != "receipt-"+string(rune('1'+index)) {
					t.Fatalf("delete entry %d = %#v", index, entry)
				}
			}
			return sdkJSONResponse(request, `{"Successful":[{"Id":"entry-1"},{"Id":"entry-2"}],"Failed":[]}`), nil
		default:
			t.Fatalf("unexpected SDK request %d target=%q", call, target)
			return nil, nil
		}
	}))

	sent, err := client.SendJobBatch(context.Background(), jobQueueURL, entries)
	if err != nil || len(sent.Successful) != 2 || len(sent.FailedIDs) != 0 {
		t.Fatalf("SendJobBatch() = %#v, %v", sent, err)
	}
	received, err := client.ReceiveJobMessages(context.Background(), jobQueueURL, 2)
	if err != nil || len(received) != 2 || received[0].ReceiptHandle != "receipt-1" || received[1].MessageID != "message-2" {
		t.Fatalf("ReceiveJobMessages() = %#v, %v", received, err)
	}
	deleted, err := client.DeleteJobBatch(context.Background(), jobQueueURL, []jobDeleteEntry{
		{ID: "entry-1", ReceiptHandle: "receipt-1"},
		{ID: "entry-2", ReceiptHandle: "receipt-2"},
	})
	if err != nil || !reflect.DeepEqual(deleted.SuccessfulIDs, []string{"entry-1", "entry-2"}) || len(deleted.FailedIDs) != 0 {
		t.Fatalf("DeleteJobBatch() = %#v, %v", deleted, err)
	}
	if call != 3 {
		t.Fatalf("SDK call count = %d", call)
	}
}

func TestSDKJobBatchRejectsMalformedSuccess(t *testing.T) {
	t.Parallel()

	client := sdkJobClientWithTransport(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return sdkJSONResponse(request, `{"Successful":[{"Id":"entry-1","MD5OfMessageBody":"`+
			md5Hex(`{"one":1}`)+`"}],"Failed":[]}`), nil
	}))
	_, err := client.SendJobBatch(context.Background(), jobQueueURL, []outgoingMessage{
		{ID: "entry-1", Body: `{"one":1}`, Attributes: map[string]messageAttribute{}},
	})
	if !errors.Is(err, errProvider) {
		t.Fatalf("SendJobBatch() error = %v", err)
	}
}

func TestSDKListQueuesAcceptsDisposableHighPortQueueURL(t *testing.T) {
	t.Parallel()

	const (
		endpoint  = "http://127.0.0.1:49152"
		queueName = "zasp-m1-13-0123456789abcdef-dlq"
		queueURL  = endpoint + "/000000000000/" + queueName
	)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if target := request.Header.Get("X-Amz-Target"); target != "AmazonSQS.ListQueues" {
			t.Fatalf("target = %q", target)
		}
		return sdkJSONResponse(request, `{"QueueUrls":["`+queueURL+`"]}`), nil
	})
	client := sqs.New(sqs.Options{
		Region: fixedRegion, BaseEndpoint: aws.String(endpoint),
		HTTPClient:  &http.Client{Transport: transport},
		Credentials: aws.CredentialsProviderFunc(staticLocalCredentials),
		Retryer:     aws.NopRetryer{},
	})
	sdkClient := &sdkQueueClient{
		client: client,
		endpoint: validatedEndpoint{
			baseURL:  endpoint,
			hostname: "127.0.0.1",
			port:     "49152",
		},
	}

	urls, err := sdkClient.ListQueues(context.Background(), queueName)
	if err != nil || !reflect.DeepEqual(urls, []string{queueURL}) {
		t.Fatalf("ListQueues() = %#v, %v", urls, err)
	}
}

func sdkJobClientWithTransport(transport http.RoundTripper) *sdkQueueClient {
	client := sqs.New(sqs.Options{
		Region: fixedRegion, BaseEndpoint: aws.String("http://127.0.0.1:4566"),
		HTTPClient:  &http.Client{Transport: transport},
		Credentials: aws.CredentialsProviderFunc(staticLocalCredentials),
		Retryer:     aws.NopRetryer{},
	})
	return &sdkQueueClient{client: client}
}

func sdkJSONResponse(request *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    request,
	}
}
