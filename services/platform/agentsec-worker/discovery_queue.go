package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue/sqsdriver"
)

type discoveryQueueAPI interface {
	sqsdriver.Client
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

type productionDiscoveryQueueConfig struct {
	Region           string
	QueueURL         string
	OperationTimeout time.Duration
	Visibility       time.Duration
	ShutdownTimeout  time.Duration
}

type productionDiscoveryQueue struct {
	Queue jobqueue.JobQueue
	ready func(context.Context) error
	close func() error
}

func newProductionDiscoveryQueue(api discoveryQueueAPI, config productionDiscoveryQueueConfig) (productionDiscoveryQueue, error) {
	parsed, parseErr := url.Parse(config.QueueURL)
	if nilWorkerDependency(api) || parseErr != nil || parsed == nil || !validSQSURL(config.QueueURL) || parsed.Hostname() != "sqs."+config.Region+".amazonaws.com" ||
		config.OperationTimeout < time.Second || config.OperationTimeout > 30*time.Second || config.Visibility < 5*time.Second || config.Visibility > 15*time.Minute || config.Visibility%time.Second != 0 ||
		config.ShutdownTimeout < time.Second || config.ShutdownTimeout > time.Minute || config.ShutdownTimeout >= config.Visibility {
		return productionDiscoveryQueue{}, errRuntimeUnavailable
	}
	receiveWait := int32(config.OperationTimeout/time.Second) - 1
	if receiveWait < 0 {
		receiveWait = 0
	}
	if receiveWait > 20 {
		receiveWait = 20
	}
	driver, err := sqsdriver.New(api, sqsdriver.Config{QueueURL: config.QueueURL, ReceiveWaitSeconds: receiveWait, VisibilityTimeoutSeconds: int32(config.Visibility / time.Second), MaximumReceiveCount: 5})
	if err != nil {
		return productionDiscoveryQueue{}, errRuntimeUnavailable
	}
	queue, err := jobqueue.New(driver, jobqueue.Config{OperationTimeout: config.OperationTimeout, MaximumBatchMessages: 10, MaximumMessageBytes: 262_144, MaximumBatchBytes: 1_048_576})
	if err != nil {
		return productionDiscoveryQueue{}, errRuntimeUnavailable
	}
	ready := func(ctx context.Context) error { return readyProductionDiscoveryQueue(ctx, api, config) }
	var closeOnce sync.Once
	var closeErr error
	closeQueue := func() error {
		closeOnce.Do(func() {
			drainCtx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
			defer cancel()
			if err := driver.Drain(drainCtx); err != nil {
				closeErr = errRuntimeUnavailable
			}
		})
		return closeErr
	}
	return productionDiscoveryQueue{Queue: queue, ready: ready, close: closeQueue}, nil
}

func (queue productionDiscoveryQueue) Ready(ctx context.Context) error {
	if queue.ready == nil {
		return errRuntimeUnavailable
	}
	return queue.ready(ctx)
}

func (queue productionDiscoveryQueue) Close() error {
	if queue.close == nil {
		return nil
	}
	return queue.close()
}

func readyProductionDiscoveryQueue(ctx context.Context, api discoveryQueueAPI, config productionDiscoveryQueueConfig) error {
	if ctx == nil || ctx.Err() != nil || nilWorkerDependency(api) {
		return errRuntimeUnavailable
	}
	output, err := getDiscoveryQueueAttributes(api, ctx, &sqs.GetQueueAttributesInput{QueueUrl: aws.String(config.QueueURL), AttributeNames: []types.QueueAttributeName{types.QueueAttributeNameQueueArn, types.QueueAttributeNameRedrivePolicy}})
	if err != nil || ctx.Err() != nil || output == nil || len(output.Attributes) != 2 {
		return errRuntimeUnavailable
	}
	parsed, parseErr := url.Parse(config.QueueURL)
	if parseErr != nil || parsed == nil {
		return errRuntimeUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) != 2 {
		return errRuntimeUnavailable
	}
	queueARN := "arn:aws:sqs:" + config.Region + ":" + parts[0] + ":agentsec-discovery-jobs"
	if output.Attributes[string(types.QueueAttributeNameQueueArn)] != queueARN {
		return errRuntimeUnavailable
	}
	var redrive struct {
		DeadLetterTargetARN string `json:"deadLetterTargetArn"`
		MaximumReceiveCount string `json:"maxReceiveCount"`
	}
	raw := []byte(output.Attributes[string(types.QueueAttributeNameRedrivePolicy)])
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&redrive) != nil || decoder.Decode(&struct{}{}) != io.EOF || redrive.DeadLetterTargetARN != queueARN+"-dlq" || redrive.MaximumReceiveCount != "5" {
		return errRuntimeUnavailable
	}
	return nil
}

func getDiscoveryQueueAttributes(api discoveryQueueAPI, ctx context.Context, input *sqs.GetQueueAttributesInput) (output *sqs.GetQueueAttributesOutput, resultErr error) {
	defer func() {
		if recover() != nil {
			output = nil
			resultErr = errRuntimeUnavailable
		}
	}()
	return api.GetQueueAttributes(ctx, input, func(options *sqs.Options) { options.Retryer = aws.NopRetryer{} })
}
