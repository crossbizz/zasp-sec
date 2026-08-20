package sqsdriver

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

func (driver *Driver) AcknowledgeBatch(ctx context.Context, receipts []jobqueue.DriverReceipt) ([]domain.ProductID, error) {
	end, err := driver.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	validated, ok := validateReceipts(receipts)
	if !ok {
		return nil, ErrInput
	}
	entries := make([]types.DeleteMessageBatchRequestEntry, len(receipts))
	for index, receipt := range receipts {
		entries[index] = types.DeleteMessageBatchRequestEntry{Id: aws.String(receipt.EntryID), ReceiptHandle: aws.String(receipt.ReceiptHandle)}
	}
	output, err := deleteBatch(driver.client, ctx, &sqs.DeleteMessageBatchInput{QueueUrl: aws.String(driver.config.QueueURL), Entries: entries})
	if err != nil || output == nil || ctx.Err() != nil {
		return nil, unknownReceiptFailures(receipts)
	}
	return validateEffectOutput(receipts, validated, successIDsFromDelete(output.Successful), output.Failed)
}

func (driver *Driver) ExtendVisibility(ctx context.Context, receipts []jobqueue.DriverReceipt, seconds int32) ([]domain.ProductID, error) {
	end, err := driver.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	if seconds < 1 || seconds > maximumVisibilitySeconds {
		return nil, ErrInput
	}
	validated, ok := validateReceipts(receipts)
	if !ok {
		return nil, ErrInput
	}
	entries := make([]types.ChangeMessageVisibilityBatchRequestEntry, len(receipts))
	for index, receipt := range receipts {
		entries[index] = types.ChangeMessageVisibilityBatchRequestEntry{Id: aws.String(receipt.EntryID), ReceiptHandle: aws.String(receipt.ReceiptHandle), VisibilityTimeout: seconds}
	}
	output, err := changeVisibilityBatch(driver.client, ctx, &sqs.ChangeMessageVisibilityBatchInput{QueueUrl: aws.String(driver.config.QueueURL), Entries: entries})
	if err != nil || output == nil || ctx.Err() != nil {
		return nil, unknownReceiptFailures(receipts)
	}
	return validateEffectOutput(receipts, validated, successIDsFromVisibility(output.Successful), output.Failed)
}

func validateReceipts(receipts []jobqueue.DriverReceipt) (map[string]domain.ProductID, bool) {
	if len(receipts) < 1 || len(receipts) > maximumBatchEntries {
		return nil, false
	}
	validated := make(map[string]domain.ProductID, len(receipts))
	messageIDs := make(map[string]struct{}, len(receipts))
	handles := make(map[string]struct{}, len(receipts))
	for _, receipt := range receipts {
		parsed, err := domain.ParseProductID(receipt.EntryID)
		if err != nil || parsed != receipt.JobID || receipt.EntryID != receipt.JobID.String() || len(receipt.MessageID) < 1 || len(receipt.MessageID) > 256 || strings.TrimSpace(receipt.MessageID) != receipt.MessageID || len(receipt.ReceiptHandle) < 1 || len(receipt.ReceiptHandle) > 8192 || strings.TrimSpace(receipt.ReceiptHandle) != receipt.ReceiptHandle {
			return nil, false
		}
		if _, duplicate := validated[receipt.EntryID]; duplicate {
			return nil, false
		}
		if _, duplicate := messageIDs[receipt.MessageID]; duplicate {
			return nil, false
		}
		if _, duplicate := handles[receipt.ReceiptHandle]; duplicate {
			return nil, false
		}
		validated[receipt.EntryID] = receipt.JobID
		messageIDs[receipt.MessageID] = struct{}{}
		handles[receipt.ReceiptHandle] = struct{}{}
	}
	return validated, true
}

func validateEffectOutput(receipts []jobqueue.DriverReceipt, expected map[string]domain.ProductID, successIDs []string, failed []types.BatchResultErrorEntry) ([]domain.ProductID, error) {
	succeeded := make(map[string]struct{}, len(successIDs))
	failures := make(map[string]EntryFailure, len(failed))
	malformed := false
	for _, id := range successIDs {
		if _, exists := expected[id]; !exists || id == "" {
			malformed = true
			continue
		}
		if _, duplicate := succeeded[id]; duplicate {
			malformed = true
			continue
		}
		succeeded[id] = struct{}{}
	}
	for _, failedEntry := range failed {
		id := aws.ToString(failedEntry.Id)
		if _, exists := expected[id]; !exists || id == "" || aws.ToString(failedEntry.Code) == "" {
			malformed = true
			continue
		}
		if _, exists := succeeded[id]; exists {
			malformed = true
			continue
		}
		if _, duplicate := failures[id]; duplicate {
			malformed = true
			continue
		}
		disposition := DispositionRetry
		if failedEntry.SenderFault {
			disposition = DispositionDeadLetter
		}
		failures[id] = EntryFailure{EntryID: id, Disposition: disposition}
	}
	if len(succeeded)+len(failures) != len(receipts) {
		malformed = true
	}
	if malformed {
		return nil, unknownReceiptFailures(receipts)
	}

	acknowledged := make([]domain.ProductID, 0, len(succeeded))
	orderedFailures := make([]EntryFailure, 0, len(failures))
	hasDeadLetter := false
	for _, receipt := range receipts {
		if _, exists := succeeded[receipt.EntryID]; exists {
			acknowledged = append(acknowledged, receipt.JobID)
			continue
		}
		failure := failures[receipt.EntryID]
		orderedFailures = append(orderedFailures, failure)
		hasDeadLetter = hasDeadLetter || failure.Disposition == DispositionDeadLetter
	}
	if len(orderedFailures) == 0 {
		return acknowledged, nil
	}
	cause := ErrRetryable
	if hasDeadLetter {
		cause = ErrRejected
	}
	return acknowledged, newBatchError(cause, orderedFailures)
}

func successIDsFromDelete(entries []types.DeleteMessageBatchResultEntry) []string {
	values := make([]string, len(entries))
	for index, entry := range entries {
		values[index] = aws.ToString(entry.Id)
	}
	return values
}

func successIDsFromVisibility(entries []types.ChangeMessageVisibilityBatchResultEntry) []string {
	values := make([]string, len(entries))
	for index, entry := range entries {
		values[index] = aws.ToString(entry.Id)
	}
	return values
}

func unknownReceiptFailures(receipts []jobqueue.DriverReceipt) error {
	failures := make([]EntryFailure, len(receipts))
	for index, receipt := range receipts {
		failures[index] = EntryFailure{EntryID: receipt.EntryID, Disposition: DispositionReconcile}
	}
	return newBatchError(ErrUnknownOutcome, failures)
}

func deleteBatch(client Client, ctx context.Context, input *sqs.DeleteMessageBatchInput) (output *sqs.DeleteMessageBatchOutput, resultErr error) {
	defer func() {
		if recover() != nil {
			output = nil
			resultErr = ErrUnknownOutcome
		}
	}()
	return client.DeleteMessageBatch(ctx, input, oneAttempt)
}

func changeVisibilityBatch(client Client, ctx context.Context, input *sqs.ChangeMessageVisibilityBatchInput) (output *sqs.ChangeMessageVisibilityBatchOutput, resultErr error) {
	defer func() {
		if recover() != nil {
			output = nil
			resultErr = ErrUnknownOutcome
		}
	}()
	return client.ChangeMessageVisibilityBatch(ctx, input, oneAttempt)
}
