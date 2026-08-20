package main

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type discoveryQueueAPIStub struct {
	attributes *sqs.GetQueueAttributesInput
	output     *sqs.GetQueueAttributesOutput
}

func (stub *discoveryQueueAPIStub) GetQueueAttributes(_ context.Context, input *sqs.GetQueueAttributesInput, options ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	stub.attributes = input
	for _, option := range options {
		option(&sqs.Options{})
	}
	return stub.output, nil
}

func (*discoveryQueueAPIStub) SendMessageBatch(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	return &sqs.SendMessageBatchOutput{}, nil
}
func (*discoveryQueueAPIStub) ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	return &sqs.ReceiveMessageOutput{}, nil
}
func (*discoveryQueueAPIStub) DeleteMessageBatch(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	return &sqs.DeleteMessageBatchOutput{}, nil
}
func (*discoveryQueueAPIStub) ChangeMessageVisibilityBatch(context.Context, *sqs.ChangeMessageVisibilityBatchInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
	return &sqs.ChangeMessageVisibilityBatchOutput{}, nil
}

func TestProductionDiscoveryQueueBindsReceiveVisibilityAndReadiness(t *testing.T) {
	queueARN := "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs"
	stub := &discoveryQueueAPIStub{output: &sqs.GetQueueAttributesOutput{Attributes: map[string]string{
		string(types.QueueAttributeNameQueueArn):      queueARN,
		string(types.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"` + queueARN + `-dlq","maxReceiveCount":"5"}`,
	}}}
	queue, err := newProductionDiscoveryQueue(stub, productionDiscoveryQueueConfig{Region: "us-west-2", QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", OperationTimeout: 10 * time.Second, Visibility: 30 * time.Second, ShutdownTimeout: 15 * time.Second})
	if err != nil || queue.Queue == nil || queue.ready == nil || queue.close == nil {
		t.Fatalf("queue=%#v err=%v", queue, err)
	}
	if err := queue.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(stub.attributes.QueueUrl) != "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs" || len(stub.attributes.AttributeNames) != 2 {
		t.Fatalf("attributes=%#v", stub.attributes)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionDiscoveryQueueRejectsDriftAndMalformedReadiness(t *testing.T) {
	queueARN := "arn:aws:sqs:us-west-2:123456789012:agentsec-discovery-jobs"
	valid := productionDiscoveryQueueConfig{Region: "us-west-2", QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/agentsec-discovery-jobs", OperationTimeout: 10 * time.Second, Visibility: 30 * time.Second, ShutdownTimeout: 15 * time.Second}
	for _, mutate := range []func(*productionDiscoveryQueueConfig){
		func(config *productionDiscoveryQueueConfig) { config.Region = "us-east-1" },
		func(config *productionDiscoveryQueueConfig) { config.OperationTimeout = 31 * time.Second },
		func(config *productionDiscoveryQueueConfig) { config.Visibility = 500 * time.Millisecond },
		func(config *productionDiscoveryQueueConfig) { config.ShutdownTimeout = 31 * time.Second },
	} {
		config := valid
		mutate(&config)
		if queue, err := newProductionDiscoveryQueue(&discoveryQueueAPIStub{}, config); err == nil || queue.Queue != nil {
			t.Fatal("hostile queue config accepted")
		}
	}
	stub := &discoveryQueueAPIStub{output: &sqs.GetQueueAttributesOutput{Attributes: map[string]string{
		string(types.QueueAttributeNameQueueArn):      queueARN,
		string(types.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"arn:aws:sqs:us-west-2:999999999999:foreign","maxReceiveCount":"5"}`,
	}}}
	queue, err := newProductionDiscoveryQueue(stub, valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Ready(context.Background()); err == nil {
		t.Fatal("foreign DLQ readiness accepted")
	}
}

var _ discoveryQueueAPI = (*discoveryQueueAPIStub)(nil)
