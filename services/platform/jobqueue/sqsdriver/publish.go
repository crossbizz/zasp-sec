package sqsdriver

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const (
	maximumBatchEntries  = 10
	maximumEnvelopeBytes = 262_144
)

var (
	entryIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	kindPattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
)

type canonicalEnvelope struct {
	Version        int             `json:"version"`
	JobID          string          `json:"job_id"`
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
}

func (driver *Driver) PublishBatch(ctx context.Context, messages []jobqueue.DriverMessage) ([]jobqueue.DriverPublished, error) {
	end, err := driver.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer end()
	if len(messages) < 1 || len(messages) > maximumBatchEntries {
		return nil, ErrInput
	}

	entries := make([]types.SendMessageBatchRequestEntry, len(messages))
	byID := make(map[string]jobqueue.DriverMessage, len(messages))
	totalBytes := 0
	for index, message := range messages {
		if !validMessage(message) || totalBytes > maximumEnvelopeBytes-len(message.Body) {
			return nil, ErrInput
		}
		if _, exists := byID[message.EntryID]; exists {
			return nil, ErrInput
		}
		totalBytes += len(message.Body)
		byID[message.EntryID] = cloneMessage(message)
		entries[index] = types.SendMessageBatchRequestEntry{
			Id:             aws.String(message.EntryID),
			MessageBody:    aws.String(string(message.Body)),
			MessageGroupId: aws.String(message.Scope.OrganizationID().String()),
		}
	}

	output, err := sendBatch(driver.client, ctx, &sqs.SendMessageBatchInput{QueueUrl: aws.String(driver.config.QueueURL), Entries: entries})
	if err != nil || output == nil || ctx.Err() != nil {
		return nil, unknownFailures(messages)
	}
	return validateSendOutput(messages, byID, output)
}

func (driver *Driver) usable() bool {
	return driver != nil && !nilInterface(driver.client) && validQueueURL(driver.config.QueueURL)
}

func validMessage(message jobqueue.DriverMessage) bool {
	if !entryIDPattern.MatchString(message.EntryID) || message.EntryID != message.JobID.String() || message.JobID.IsZero() || message.Scope.Validate() != nil || !kindPattern.MatchString(message.Kind) || len(message.Body) < 1 || len(message.Body) > maximumEnvelopeBytes || message.SHA256 != sha256.Sum256(message.Body) {
		return false
	}
	envelope, ok := parseCanonicalEnvelope(message.Body)
	return ok && envelope.JobID == message.EntryID && envelope.OrganizationID == message.Scope.OrganizationID().String() && envelope.WorkspaceID == message.Scope.WorkspaceID().String() && envelope.EnvironmentID == message.Scope.EnvironmentID().String() && envelope.Kind == message.Kind
}

func parseCanonicalEnvelope(body []byte) (canonicalEnvelope, bool) {
	var envelope canonicalEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.Version != 1 || !kindPattern.MatchString(envelope.Kind) || len(envelope.Payload) == 0 || !json.Valid(envelope.Payload) {
		return canonicalEnvelope{}, false
	}
	if decoder.Decode(&struct{}{}) == nil {
		return canonicalEnvelope{}, false
	}
	organizationID, organizationErr := domain.ParseProductID(envelope.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(envelope.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(envelope.EnvironmentID)
	jobID, jobErr := domain.ParseProductID(envelope.JobID)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || jobErr != nil || organizationID.IsZero() || workspaceID.IsZero() || environmentID.IsZero() || jobID.IsZero() {
		return canonicalEnvelope{}, false
	}
	canonical, err := json.Marshal(envelope)
	return envelope, err == nil && bytes.Equal(canonical, body)
}

func validateSendOutput(messages []jobqueue.DriverMessage, byID map[string]jobqueue.DriverMessage, output *sqs.SendMessageBatchOutput) ([]jobqueue.DriverPublished, error) {
	publishedByID := make(map[string]jobqueue.DriverPublished, len(output.Successful))
	failedByID := make(map[string]EntryFailure, len(output.Failed))
	messageIDs := make(map[string]struct{}, len(output.Successful))
	malformed := false
	for _, success := range output.Successful {
		id := aws.ToString(success.Id)
		message, exists := byID[id]
		messageID := aws.ToString(success.MessageId)
		if !exists || id == "" || messageID == "" || aws.ToString(success.MD5OfMessageBody) != md5Body(message.Body) {
			malformed = true
			continue
		}
		if _, duplicate := publishedByID[id]; duplicate {
			malformed = true
			continue
		}
		if _, duplicate := messageIDs[messageID]; duplicate {
			malformed = true
			continue
		}
		publishedByID[id] = jobqueue.DriverPublished{EntryID: id, JobID: message.JobID, MessageID: messageID}
		messageIDs[messageID] = struct{}{}
	}
	for _, failed := range output.Failed {
		id := aws.ToString(failed.Id)
		if _, exists := byID[id]; !exists || id == "" || aws.ToString(failed.Code) == "" {
			malformed = true
			continue
		}
		if _, succeeded := publishedByID[id]; succeeded {
			malformed = true
			continue
		}
		if _, duplicate := failedByID[id]; duplicate {
			malformed = true
			continue
		}
		disposition := DispositionRetry
		if failed.SenderFault {
			disposition = DispositionDeadLetter
		}
		failedByID[id] = EntryFailure{EntryID: id, Disposition: disposition}
	}
	if len(publishedByID)+len(failedByID) != len(messages) {
		malformed = true
	}
	if malformed {
		return nil, unknownFailures(messages)
	}

	published := make([]jobqueue.DriverPublished, 0, len(publishedByID))
	failures := make([]EntryFailure, 0, len(failedByID))
	hasDeadLetter := false
	for _, message := range messages {
		if value, exists := publishedByID[message.EntryID]; exists {
			published = append(published, value)
			continue
		}
		failure := failedByID[message.EntryID]
		failures = append(failures, failure)
		hasDeadLetter = hasDeadLetter || failure.Disposition == DispositionDeadLetter
	}
	if len(failures) == 0 {
		return published, nil
	}
	cause := ErrRetryable
	if hasDeadLetter {
		cause = ErrRejected
	}
	return published, newBatchError(cause, failures)
}

func unknownFailures(messages []jobqueue.DriverMessage) error {
	failures := make([]EntryFailure, len(messages))
	for index, message := range messages {
		failures[index] = EntryFailure{EntryID: message.EntryID, Disposition: DispositionReconcile}
	}
	return newBatchError(ErrUnknownOutcome, failures)
}

func sendBatch(client Client, ctx context.Context, input *sqs.SendMessageBatchInput) (output *sqs.SendMessageBatchOutput, resultErr error) {
	defer func() {
		if recover() != nil {
			output = nil
			resultErr = ErrUnknownOutcome
		}
	}()
	return client.SendMessageBatch(ctx, input, oneAttempt)
}

func oneAttempt(options *sqs.Options) {
	options.Retryer = aws.NopRetryer{}
	options.RetryMaxAttempts = 1
}

func cloneMessage(message jobqueue.DriverMessage) jobqueue.DriverMessage {
	message.Body = bytes.Clone(message.Body)
	return message
}

func md5Body(body []byte) string {
	digest := md5.Sum(body)
	return hex.EncodeToString(digest[:])
}
