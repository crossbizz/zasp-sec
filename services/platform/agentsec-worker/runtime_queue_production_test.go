package main

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestRuntimeQueueReadinessBindsExactQueueRedriveAndRoleIdentity(t *testing.T) {
	config := validRuntimeCoordinatorConfig()
	queueARN := "arn:aws:sqs:us-west-2:123456789012:agentsec-runtime-events"
	queue := &runtimeQueueReadinessStub{attributes: map[string]string{
		string(types.QueueAttributeNameQueueArn):      queueARN,
		string(types.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"` + queueARN + `-dlq","maxReceiveCount":"5"}`,
	}}
	identity := &runtimeIdentityStub{account: "123456789012", arn: "arn:aws:sts::123456789012:assumed-role/zasp-production-runtime-coordinator/session"}
	if err := readyProductionRuntimeQueue(context.Background(), queue, identity, config); err != nil {
		t.Fatalf("readyProductionRuntimeQueue() error = %v", err)
	}
	if queue.attributeCalls != 1 || identity.calls != 1 {
		t.Fatalf("readiness calls queue=%d identity=%d", queue.attributeCalls, identity.calls)
	}
	for name, mutate := range map[string]func(*runtimeQueueReadinessStub, *runtimeIdentityStub){
		"foreign queue": func(queue *runtimeQueueReadinessStub, _ *runtimeIdentityStub) {
			queue.attributes[string(types.QueueAttributeNameQueueArn)] = "arn:aws:sqs:us-west-2:123456789012:other"
		},
		"missing dlq": func(queue *runtimeQueueReadinessStub, _ *runtimeIdentityStub) {
			queue.attributes[string(types.QueueAttributeNameRedrivePolicy)] = `{"deadLetterTargetArn":"` + queueARN + `-other","maxReceiveCount":"5"}`
		},
		"wrong redrive count": func(queue *runtimeQueueReadinessStub, _ *runtimeIdentityStub) {
			queue.attributes[string(types.QueueAttributeNameRedrivePolicy)] = `{"deadLetterTargetArn":"` + queueARN + `-dlq","maxReceiveCount":"4"}`
		},
		"foreign role": func(_ *runtimeQueueReadinessStub, identity *runtimeIdentityStub) {
			identity.arn = "arn:aws:sts::123456789012:assumed-role/zasp-production-runtime-outbox/session"
		},
		"foreign account": func(_ *runtimeQueueReadinessStub, identity *runtimeIdentityStub) { identity.account = "210987654321" },
	} {
		t.Run(name, func(t *testing.T) {
			candidateQueue := &runtimeQueueReadinessStub{attributes: map[string]string{
				string(types.QueueAttributeNameQueueArn):      queueARN,
				string(types.QueueAttributeNameRedrivePolicy): `{"deadLetterTargetArn":"` + queueARN + `-dlq","maxReceiveCount":"5"}`,
			}}
			candidateIdentity := &runtimeIdentityStub{account: identity.account, arn: identity.arn}
			mutate(candidateQueue, candidateIdentity)
			if err := readyProductionRuntimeQueue(context.Background(), candidateQueue, candidateIdentity, config); !errors.Is(err, errRuntimeUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type runtimeQueueReadinessStub struct {
	attributes     map[string]string
	attributeCalls int
}

func (*runtimeQueueReadinessStub) SendMessageBatch(context.Context, *sqs.SendMessageBatchInput, ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	return nil, errors.New("unexpected send")
}
func (*runtimeQueueReadinessStub) ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	return nil, errors.New("unexpected receive")
}
func (*runtimeQueueReadinessStub) DeleteMessageBatch(context.Context, *sqs.DeleteMessageBatchInput, ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error) {
	return nil, errors.New("unexpected delete")
}
func (*runtimeQueueReadinessStub) ChangeMessageVisibilityBatch(context.Context, *sqs.ChangeMessageVisibilityBatchInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityBatchOutput, error) {
	return nil, errors.New("unexpected visibility")
}
func (stub *runtimeQueueReadinessStub) GetQueueAttributes(_ context.Context, input *sqs.GetQueueAttributesInput, options ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	stub.attributeCalls++
	if aws.ToString(input.QueueUrl) == "" || len(input.AttributeNames) != 2 || len(options) != 1 {
		return nil, errors.New("invalid readiness request")
	}
	return &sqs.GetQueueAttributesOutput{Attributes: stub.attributes}, nil
}

type runtimeIdentityStub struct {
	account string
	arn     string
	calls   int
}

func (stub *runtimeIdentityStub) GetCallerIdentity(_ context.Context, input *sts.GetCallerIdentityInput, options ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	stub.calls++
	if input == nil || len(options) != 1 {
		return nil, errors.New("invalid identity request")
	}
	return &sts.GetCallerIdentityOutput{Account: aws.String(stub.account), Arn: aws.String(stub.arn), UserId: aws.String("runtime-coordinator")}, nil
}
