package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func TestSDKClientUsesOnlyExplicitLocalIdentity(t *testing.T) {
	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_PROFILE", "production")
	t.Setenv("AWS_ENDPOINT_URL_SQS", "https://sqs.us-west-2.amazonaws.com")
	t.Setenv("HTTPS_PROXY", "http://example.invalid:9999")

	client, err := newSDKQueueClient(context.Background(), "http://127.0.0.1:4566")
	if err != nil {
		t.Fatalf("newSDKQueueClient() error = %v", err)
	}
	options := client.client.Options()
	if options.Region != fixedRegion || options.BaseEndpoint == nil || *options.BaseEndpoint != "http://127.0.0.1:4566" {
		t.Fatal("SDK identity was changed by ambient AWS configuration")
	}
	credentials, err := options.Credentials.Retrieve(context.Background())
	if err != nil || credentials.Source != "zasp-localstack-proof" || credentials.AccessKeyID != "test" {
		t.Fatal("SDK did not use the fixed non-secret local credential provider")
	}
	if client.transport.Proxy != nil {
		t.Fatal("SDK transport permits proxy routing")
	}
}

func TestSDKDialerRejectsNonLoopbackResolution(t *testing.T) {
	endpoint, err := validateEndpoint(context.Background(), "http://127.0.0.1:4566", nil)
	if err != nil {
		t.Fatalf("validateEndpoint() error = %v", err)
	}
	dial := loopbackDialerWithResolver(endpoint, staticResolver{"203.0.113.5"})
	if _, err := dial(context.Background(), "tcp", "malicious.invalid:4566"); !errors.Is(err, errConfiguration) {
		t.Fatalf("dial error = %v, want configuration rejection", err)
	}
}

func TestSDKDialerFallsBackAcrossValidatedLoopbackAddresses(t *testing.T) {
	t.Parallel()

	endpoint, err := validateEndpoint(context.Background(), "http://127.0.0.1:4566", nil)
	if err != nil {
		t.Fatalf("validateEndpoint() error = %v", err)
	}
	attempts := 0
	peer, server := net.Pipe()
	defer server.Close()
	dial := loopbackDialerWithResolverAndDialer(endpoint, staticResolver{"::1", "127.0.0.1"}, func(context.Context, string, string) (net.Conn, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("first loopback family unavailable")
		}
		return peer, nil
	})
	connection, err := dial(context.Background(), "tcp", "localhost:4566")
	if err != nil {
		t.Fatalf("dial() error = %v", err)
	}
	connection.Close()
	if attempts != 2 {
		t.Fatalf("dial attempts = %d, want 2 loopback addresses", attempts)
	}
}

func TestSDKQueueMutationsUseOneAttemptAndKeepServerFailureAmbiguous(t *testing.T) {
	t.Parallel()

	calls := make(map[string]int)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		target := request.Header.Get("X-Amz-Target")
		calls[target]++
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "500 Internal Server Error",
			Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
			Body:       io.NopCloser(bytes.NewBufferString(`{"__type":"InternalError","message":"retryable"}`)),
			Request:    request,
		}, nil
	})
	retryer := awsretry.NewStandard(func(options *awsretry.StandardOptions) {
		options.MaxAttempts = 3
		options.MaxBackoff = time.Millisecond
	})
	client := sqs.New(sqs.Options{
		Region: fixedRegion, BaseEndpoint: aws.String("http://127.0.0.1:49152"),
		HTTPClient:  &http.Client{Transport: transport},
		Credentials: aws.CredentialsProviderFunc(staticLocalCredentials),
		Retryer:     retryer,
	})
	sdkClient := &sdkQueueClient{client: client}

	_, createErr := sdkClient.CreateQueue(context.Background(), "agentsec-background", nil, nil)
	setErr := sdkClient.SetQueueAttributes(context.Background(), "http://127.0.0.1:49152/000000000000/agentsec-background", map[string]string{"VisibilityTimeout": "300"})
	deleteErr := sdkClient.DeleteQueue(context.Background(), "http://127.0.0.1:49152/000000000000/agentsec-background")
	for name, err := range map[string]error{"create": createErr, "set": setErr, "delete": deleteErr} {
		if err == nil || mutationIsDefinitive(err) {
			t.Fatalf("%s error = %v, want ambiguous", name, err)
		}
	}
	for _, target := range []string{"AmazonSQS.CreateQueue", "AmazonSQS.SetQueueAttributes", "AmazonSQS.DeleteQueue"} {
		if calls[target] != 1 {
			t.Fatalf("%s attempts = %d, want 1", target, calls[target])
		}
	}
}
