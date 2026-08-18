package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsretry "github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type sdkQueueClient struct {
	client    *sqs.Client
	endpoint  validatedEndpoint
	transport *http.Transport
}

func newSDKQueueClient(ctx context.Context, rawEndpoint string) (*sdkQueueClient, error) {
	endpoint, err := validateEndpoint(ctx, rawEndpoint, nil)
	if err != nil {
		return nil, errConfiguration
	}
	return newSDKQueueClientFromEndpoint(endpoint), nil
}

func newSDKQueueClientFromEndpoint(endpoint validatedEndpoint) *sdkQueueClient {
	transport := &http.Transport{
		Proxy: nil, DialContext: loopbackDialerWithResolver(endpoint, net.DefaultResolver),
		DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second,
	}
	httpClient := &http.Client{
		Timeout: 25 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	retryer := awsretry.NewStandard(func(options *awsretry.StandardOptions) {
		options.MaxAttempts = 2
		options.MaxBackoff = 500 * time.Millisecond
	})
	client := sqs.New(sqs.Options{
		Region: fixedRegion, BaseEndpoint: aws.String(endpoint.baseURL), HTTPClient: httpClient,
		Credentials: aws.CredentialsProviderFunc(staticLocalCredentials), Retryer: retryer, RetryMaxAttempts: 2,
	})
	return &sdkQueueClient{client: client, endpoint: endpoint, transport: transport}
}

func staticLocalCredentials(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test", Source: "zasp-localstack-proof"}, nil
}

func loopbackDialerWithResolver(endpoint validatedEndpoint, resolver hostResolver) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
	return loopbackDialerWithResolverAndDialer(endpoint, resolver, dialer.DialContext)
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func loopbackDialerWithResolverAndDialer(endpoint validatedEndpoint, resolver hostResolver, dial dialContextFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != endpoint.port {
			return nil, errConfiguration
		}
		addresses, err := resolver.LookupHost(ctx, strings.Trim(host, "[]"))
		if err != nil || len(addresses) == 0 {
			return nil, errConfiguration
		}
		for _, candidate := range addresses {
			ip := net.ParseIP(candidate)
			if ip == nil || !ip.IsLoopback() {
				return nil, errConfiguration
			}
		}
		var lastErr error
		for _, candidate := range addresses {
			connection, err := dial(ctx, network, net.JoinHostPort(candidate, port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func (s *sdkQueueClient) ListQueues(ctx context.Context, prefix string) ([]string, error) {
	var urls []string
	var token *string
	for {
		maximum := int32(1000)
		output, err := s.client.ListQueues(ctx, &sqs.ListQueuesInput{MaxResults: &maximum, NextToken: token, QueueNamePrefix: aws.String(prefix)})
		if err != nil || output == nil {
			return nil, errProvider
		}
		for _, queueURL := range output.QueueUrls {
			name := queueNameFromURL(queueURL)
			if _, err := s.validateListedQueueURL(ctx, queueURL, name); err != nil {
				return nil, errOwnership
			}
			urls = append(urls, queueURL)
		}
		if output.NextToken == nil || *output.NextToken == "" {
			return urls, nil
		}
		token = output.NextToken
	}
}

func (s *sdkQueueClient) validateListedQueueURL(ctx context.Context, queueURL, name string) (string, error) {
	if s.endpoint.port == "4566" {
		return validateQueueURL(ctx, s.endpoint.baseURL, queueURL, name, nil)
	}
	return validateDisposableJobQueueURL(ctx, s.endpoint.baseURL, queueURL, name, nil)
}

func queueNameFromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 2 && len(parts) != 4 {
		return ""
	}
	return parts[len(parts)-1]
}

func (s *sdkQueueClient) CreateQueue(ctx context.Context, name string, attributes, tags map[string]string) (string, error) {
	output, err := s.client.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String(name), Attributes: attributes, Tags: tags}, oneAttemptSQS)
	if err != nil {
		return "", classifyQueueMutationError(err)
	}
	if output == nil || output.QueueUrl == nil || *output.QueueUrl == "" {
		return "", ambiguousMutationError()
	}
	return *output.QueueUrl, nil
}

func (s *sdkQueueClient) GetQueueAttributes(ctx context.Context, queueURL string) (map[string]string, error) {
	output, err := s.client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: aws.String(queueURL), AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameAll},
	})
	if err != nil || output == nil {
		return nil, errProvider
	}
	return cloneStringMap(output.Attributes), nil
}

func (s *sdkQueueClient) ListQueueTags(ctx context.Context, queueURL string) (map[string]string, error) {
	output, err := s.client.ListQueueTags(ctx, &sqs.ListQueueTagsInput{QueueUrl: aws.String(queueURL)})
	if err != nil || output == nil {
		return nil, errProvider
	}
	return cloneStringMap(output.Tags), nil
}

func (s *sdkQueueClient) SetQueueAttributes(ctx context.Context, queueURL string, attributes map[string]string) error {
	if _, err := s.client.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{QueueUrl: aws.String(queueURL), Attributes: attributes}, oneAttemptSQS); err != nil {
		return classifyQueueMutationError(err)
	}
	return nil
}

func (s *sdkQueueClient) SendMessageBatch(ctx context.Context, queueURL string, entry outgoingMessage) (batchSendResult, error) {
	output, err := s.client.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{QueueUrl: aws.String(queueURL), Entries: []types.SendMessageBatchRequestEntry{{
		Id: aws.String(entry.ID), MessageBody: aws.String(entry.Body), MessageAttributes: toSDKMessageAttributes(entry.Attributes),
	}}})
	if err != nil || output == nil {
		return batchSendResult{}, errProvider
	}
	result := batchSendResult{}
	for _, success := range output.Successful {
		if success.Id == nil || success.MessageId == nil || success.MD5OfMessageBody == nil {
			return batchSendResult{}, errProvider
		}
		result.SuccessfulIDs = append(result.SuccessfulIDs, *success.Id)
		result.MessageID, result.BodyDigest = *success.MessageId, *success.MD5OfMessageBody
	}
	for _, failure := range output.Failed {
		if failure.Id == nil {
			return batchSendResult{}, errProvider
		}
		result.FailedIDs = append(result.FailedIDs, *failure.Id)
	}
	return result, nil
}

func (s *sdkQueueClient) SendJobBatch(ctx context.Context, queueURL string, entries []outgoingMessage) (jobBatchSendResult, error) {
	if s == nil || s.client == nil || ctx == nil || len(entries) == 0 || len(entries) > jobBatchLimit {
		return jobBatchSendResult{}, errProvider
	}
	sdkEntries := make([]types.SendMessageBatchRequestEntry, len(entries))
	for index, entry := range entries {
		if entry.ID == "" || entry.Body == "" {
			return jobBatchSendResult{}, errProvider
		}
		sdkEntries[index] = types.SendMessageBatchRequestEntry{
			Id:                aws.String(entry.ID),
			MessageBody:       aws.String(entry.Body),
			MessageAttributes: toSDKMessageAttributes(entry.Attributes),
		}
	}
	output, err := s.client.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{
		QueueUrl: aws.String(queueURL),
		Entries:  sdkEntries,
	})
	if err != nil || output == nil {
		return jobBatchSendResult{}, errProvider
	}
	result := jobBatchSendResult{}
	for _, success := range output.Successful {
		if success.Id == nil || success.MessageId == nil || success.MD5OfMessageBody == nil {
			return jobBatchSendResult{}, errProvider
		}
		result.Successful = append(result.Successful, jobBatchSendSuccess{
			ID: *success.Id, MessageID: *success.MessageId, BodyDigest: *success.MD5OfMessageBody,
		})
	}
	for _, failure := range output.Failed {
		if failure.Id == nil {
			return jobBatchSendResult{}, errProvider
		}
		result.FailedIDs = append(result.FailedIDs, *failure.Id)
	}
	return result, nil
}

func toSDKMessageAttributes(attributes map[string]messageAttribute) map[string]types.MessageAttributeValue {
	result := make(map[string]types.MessageAttributeValue, len(attributes))
	for key, value := range attributes {
		result[key] = types.MessageAttributeValue{DataType: aws.String(value.DataType), StringValue: aws.String(value.Value)}
	}
	return result
}

func (s *sdkQueueClient) ReceiveMessages(ctx context.Context, queueURL string) ([]receivedMessage, error) {
	output, err := s.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl: aws.String(queueURL), MaxNumberOfMessages: 10, MessageAttributeNames: []string{"All"}, VisibilityTimeout: 5, WaitTimeSeconds: 1,
	})
	if err != nil || output == nil {
		return nil, errProvider
	}
	result := make([]receivedMessage, 0, len(output.Messages))
	for _, message := range output.Messages {
		if message.Body == nil || message.MessageId == nil || message.ReceiptHandle == nil {
			return nil, errProvider
		}
		attributes, err := fromSDKMessageAttributes(message.MessageAttributes)
		if err != nil {
			return nil, errProvider
		}
		received := receivedMessage{Body: *message.Body, MessageID: *message.MessageId, ReceiptHandle: *message.ReceiptHandle, Attributes: attributes}
		if message.MD5OfBody != nil {
			received.BodyDigest = *message.MD5OfBody
		}
		result = append(result, received)
	}
	return result, nil
}

func (s *sdkQueueClient) ReceiveJobMessages(ctx context.Context, queueURL string, maximum int) ([]receivedMessage, error) {
	if s == nil || s.client == nil || ctx == nil || maximum <= 0 || maximum > jobBatchLimit {
		return nil, errProvider
	}
	output, err := s.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:              aws.String(queueURL),
		MaxNumberOfMessages:   int32(maximum),
		MessageAttributeNames: []string{"All"},
		VisibilityTimeout:     5,
		WaitTimeSeconds:       1,
	})
	if err != nil || output == nil {
		return nil, errProvider
	}
	result := make([]receivedMessage, 0, len(output.Messages))
	for _, message := range output.Messages {
		if message.Body == nil || message.MessageId == nil || message.ReceiptHandle == nil {
			return nil, errProvider
		}
		attributes, err := fromSDKMessageAttributes(message.MessageAttributes)
		if err != nil {
			return nil, errProvider
		}
		received := receivedMessage{
			Body: *message.Body, MessageID: *message.MessageId,
			ReceiptHandle: *message.ReceiptHandle, Attributes: attributes,
		}
		if message.MD5OfBody != nil {
			received.BodyDigest = *message.MD5OfBody
		}
		result = append(result, received)
	}
	return result, nil
}

func fromSDKMessageAttributes(attributes map[string]types.MessageAttributeValue) (map[string]messageAttribute, error) {
	result := make(map[string]messageAttribute, len(attributes))
	for key, value := range attributes {
		if value.DataType == nil || value.StringValue == nil || len(value.BinaryValue) != 0 || len(value.BinaryListValues) != 0 || len(value.StringListValues) != 0 {
			return nil, errMessage
		}
		result[key] = messageAttribute{DataType: *value.DataType, Value: *value.StringValue}
	}
	return result, nil
}

func (s *sdkQueueClient) DeleteMessageBatch(ctx context.Context, queueURL, receiptHandle string) (batchDeleteResult, error) {
	output, err := s.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{QueueUrl: aws.String(queueURL), Entries: []types.DeleteMessageBatchRequestEntry{{
		Id: aws.String(deleteBatchEntryID), ReceiptHandle: aws.String(receiptHandle),
	}}})
	if err != nil || output == nil {
		return batchDeleteResult{}, errProvider
	}
	result := batchDeleteResult{}
	for _, success := range output.Successful {
		if success.Id == nil {
			return batchDeleteResult{}, errProvider
		}
		result.SuccessfulIDs = append(result.SuccessfulIDs, *success.Id)
	}
	for _, failure := range output.Failed {
		if failure.Id == nil {
			return batchDeleteResult{}, errProvider
		}
		result.FailedIDs = append(result.FailedIDs, *failure.Id)
	}
	return result, nil
}

func (s *sdkQueueClient) DeleteJobBatch(ctx context.Context, queueURL string, entries []jobDeleteEntry) (jobBatchDeleteResult, error) {
	if s == nil || s.client == nil || ctx == nil || len(entries) == 0 || len(entries) > jobBatchLimit {
		return jobBatchDeleteResult{}, errProvider
	}
	sdkEntries := make([]types.DeleteMessageBatchRequestEntry, len(entries))
	for index, entry := range entries {
		if entry.ID == "" || entry.ReceiptHandle == "" {
			return jobBatchDeleteResult{}, errProvider
		}
		sdkEntries[index] = types.DeleteMessageBatchRequestEntry{
			Id: aws.String(entry.ID), ReceiptHandle: aws.String(entry.ReceiptHandle),
		}
	}
	output, err := s.client.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{
		QueueUrl: aws.String(queueURL),
		Entries:  sdkEntries,
	})
	if err != nil || output == nil {
		return jobBatchDeleteResult{}, errProvider
	}
	result := jobBatchDeleteResult{}
	for _, success := range output.Successful {
		if success.Id == nil {
			return jobBatchDeleteResult{}, errProvider
		}
		result.SuccessfulIDs = append(result.SuccessfulIDs, *success.Id)
	}
	for _, failure := range output.Failed {
		if failure.Id == nil {
			return jobBatchDeleteResult{}, errProvider
		}
		result.FailedIDs = append(result.FailedIDs, *failure.Id)
	}
	return result, nil
}

func (s *sdkQueueClient) DeleteQueue(ctx context.Context, queueURL string) error {
	if _, err := s.client.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: aws.String(queueURL)}, oneAttemptSQS); err != nil {
		return classifyQueueMutationError(err)
	}
	return nil
}

func oneAttemptSQS(options *sqs.Options) {
	options.Retryer = aws.NopRetryer{}
	options.RetryMaxAttempts = 1
}
