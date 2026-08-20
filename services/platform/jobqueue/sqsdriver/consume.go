package sqsdriver

import (
	"context"
	"crypto/sha256"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

type ClassifiedDelivery struct {
	Delivery           jobqueue.DriverDelivery
	ReceiveCount       int
	FailureDisposition Disposition
}

func (driver *Driver) ConsumeBatch(ctx context.Context, maximum int) ([]jobqueue.DriverDelivery, error) {
	classified, err := driver.ConsumeBatchDetailed(ctx, maximum)
	if err != nil {
		return nil, err
	}
	deliveries := make([]jobqueue.DriverDelivery, len(classified))
	for index, delivery := range classified {
		deliveries[index] = delivery.Delivery
	}
	return deliveries, nil
}

func (driver *Driver) ConsumeBatchDetailed(ctx context.Context, maximum int) ([]ClassifiedDelivery, error) {
	end, err := driver.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	if maximum < 1 || maximum > maximumBatchEntries {
		return nil, ErrInput
	}
	output, err := receiveBatch(driver.client, ctx, &sqs.ReceiveMessageInput{
		QueueUrl:                    aws.String(driver.config.QueueURL),
		MaxNumberOfMessages:         int32(maximum),
		WaitTimeSeconds:             driver.config.ReceiveWaitSeconds,
		VisibilityTimeout:           driver.config.VisibilityTimeoutSeconds,
		MessageSystemAttributeNames: []types.MessageSystemAttributeName{types.MessageSystemAttributeNameApproximateReceiveCount},
	})
	if err != nil || output == nil || ctx.Err() != nil || len(output.Messages) > maximum {
		if ctx.Err() != nil {
			return nil, ErrCanceled
		}
		return nil, ErrRetryable
	}

	result := make([]ClassifiedDelivery, len(output.Messages))
	seenJobs := make(map[domain.ProductID]struct{}, len(output.Messages))
	seenMessages := make(map[string]struct{}, len(output.Messages))
	seenHandles := make(map[string]struct{}, len(output.Messages))
	totalBytes := 0
	for index, message := range output.Messages {
		delivery, receiveCount, ok := driver.classifiedDelivery(message)
		if !ok || totalBytes > maximumEnvelopeBytes-len(delivery.Delivery.Message.Body) {
			return nil, ErrRetryable
		}
		totalBytes += len(delivery.Delivery.Message.Body)
		if _, duplicate := seenJobs[delivery.Delivery.Message.JobID]; duplicate {
			return nil, ErrRetryable
		}
		if _, duplicate := seenMessages[delivery.Delivery.MessageID]; duplicate {
			return nil, ErrRetryable
		}
		if _, duplicate := seenHandles[delivery.Delivery.ReceiptHandle]; duplicate {
			return nil, ErrRetryable
		}
		seenJobs[delivery.Delivery.Message.JobID] = struct{}{}
		seenMessages[delivery.Delivery.MessageID] = struct{}{}
		seenHandles[delivery.Delivery.ReceiptHandle] = struct{}{}
		delivery.ReceiveCount = receiveCount
		result[index] = delivery
	}
	return result, nil
}

func (driver *Driver) classifiedDelivery(message types.Message) (ClassifiedDelivery, int, bool) {
	body := []byte(aws.ToString(message.Body))
	messageID := aws.ToString(message.MessageId)
	receiptHandle := aws.ToString(message.ReceiptHandle)
	if len(body) < 1 || len(body) > maximumEnvelopeBytes || aws.ToString(message.MD5OfBody) != md5Body(body) || len(message.MessageAttributes) != 0 || len(message.Attributes) != 1 || len(messageID) < 1 || len(messageID) > 256 || strings.TrimSpace(messageID) != messageID || len(receiptHandle) < 1 || len(receiptHandle) > 8192 || strings.TrimSpace(receiptHandle) != receiptHandle {
		return ClassifiedDelivery{}, 0, false
	}
	receiveCount, err := strconv.Atoi(message.Attributes[string(types.MessageSystemAttributeNameApproximateReceiveCount)])
	if err != nil || receiveCount < 1 || receiveCount > 1_000_000_000 {
		return ClassifiedDelivery{}, 0, false
	}
	envelope, ok := parseCanonicalEnvelope(body)
	if !ok {
		return ClassifiedDelivery{}, 0, false
	}
	organizationID, organizationErr := domain.ParseProductID(envelope.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(envelope.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(envelope.EnvironmentID)
	jobID, jobErr := domain.ParseProductID(envelope.JobID)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || jobErr != nil {
		return ClassifiedDelivery{}, 0, false
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return ClassifiedDelivery{}, 0, false
	}
	disposition := DispositionRetry
	if receiveCount >= driver.config.MaximumReceiveCount {
		disposition = DispositionDeadLetter
	}
	return ClassifiedDelivery{
		Delivery: jobqueue.DriverDelivery{
			Message: jobqueue.DriverMessage{
				EntryID: envelope.JobID,
				Scope:   scope,
				JobID:   jobID,
				Kind:    envelope.Kind,
				Body:    append([]byte(nil), body...),
				SHA256:  sha256.Sum256(body),
			},
			MessageID:     messageID,
			ReceiptHandle: receiptHandle,
			ReceiveCount:  receiveCount,
		},
		FailureDisposition: disposition,
	}, receiveCount, true
}

func receiveBatch(client Client, ctx context.Context, input *sqs.ReceiveMessageInput) (output *sqs.ReceiveMessageOutput, resultErr error) {
	defer func() {
		if recover() != nil {
			output = nil
			resultErr = ErrRetryable
		}
	}()
	return client.ReceiveMessage(ctx, input, oneAttempt)
}
