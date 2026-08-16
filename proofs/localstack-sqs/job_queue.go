package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
)

const (
	jobIDAttribute   = "job_id"
	jobKindAttribute = "kind"
	jobBatchLimit    = 10
	jobMessageLimit  = 1_048_576
)

var jobKindPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)

type jobBatchSendSuccess struct {
	ID         string
	MessageID  string
	BodyDigest string
}

type jobBatchSendResult struct {
	Successful []jobBatchSendSuccess
	FailedIDs  []string
}

type jobDeleteEntry struct {
	ID            string
	ReceiptHandle string
}

type jobBatchDeleteResult struct {
	SuccessfulIDs []string
	FailedIDs     []string
}

type jobBatchAPI interface {
	SendJobBatch(context.Context, string, []outgoingMessage) (jobBatchSendResult, error)
	ReceiveJobMessages(context.Context, string, int) ([]receivedMessage, error)
	DeleteJobBatch(context.Context, string, []jobDeleteEntry) (jobBatchDeleteResult, error)
}

type sqsJobDriver struct {
	client   jobBatchAPI
	queueURL string
}

func newSQSJobDriver(client jobBatchAPI, queueURL string) (*sqsJobDriver, error) {
	if jobNilInterface(client) || !validJobQueueURL(queueURL) {
		return nil, errConfiguration
	}
	return &sqsJobDriver{client: client, queueURL: queueURL}, nil
}

func (driver *sqsJobDriver) PublishBatch(ctx context.Context, messages []jobqueue.DriverMessage) ([]jobqueue.DriverPublished, error) {
	if driver == nil || jobNilInterface(driver.client) || ctx == nil || len(messages) == 0 || len(messages) > jobBatchLimit {
		return nil, errMessage
	}
	entries := make([]outgoingMessage, len(messages))
	byID := make(map[string]jobqueue.DriverMessage, len(messages))
	batchBytes := 0
	for index, message := range messages {
		if !validJobDriverMessage(message) {
			return nil, errMessage
		}
		messageBytes, ok := sqsJobMessageBytes(message)
		if !ok || batchBytes > jobMessageLimit-messageBytes {
			return nil, errMessage
		}
		batchBytes += messageBytes
		if _, duplicate := byID[message.EntryID]; duplicate {
			return nil, errMessage
		}
		byID[message.EntryID] = cloneJobDriverMessage(message)
		entries[index] = outgoingMessage{
			ID:         message.EntryID,
			Body:       string(message.Body),
			Attributes: expectedJobDriverAttributes(message),
		}
	}
	result, err := sendJobBatch(driver.client, ctx, driver.queueURL, entries)
	if err != nil {
		return nil, errProvider
	}
	if len(result.FailedIDs) != 0 || len(result.Successful) != len(messages) {
		return nil, errMessage
	}
	publishedByID := make(map[string]jobqueue.DriverPublished, len(result.Successful))
	seenMessageIDs := make(map[string]struct{}, len(result.Successful))
	for _, success := range result.Successful {
		message, exists := byID[success.ID]
		if !exists || success.MessageID == "" {
			return nil, errMessage
		}
		if _, duplicate := publishedByID[success.ID]; duplicate {
			return nil, errMessage
		}
		if _, duplicate := seenMessageIDs[success.MessageID]; duplicate {
			return nil, errMessage
		}
		if success.BodyDigest != "" && !strings.EqualFold(success.BodyDigest, md5Hex(string(message.Body))) {
			return nil, errMessage
		}
		publishedByID[success.ID] = jobqueue.DriverPublished{
			EntryID: success.ID, JobID: message.JobID, MessageID: success.MessageID,
		}
		seenMessageIDs[success.MessageID] = struct{}{}
	}
	published := make([]jobqueue.DriverPublished, len(messages))
	for index, message := range messages {
		value, exists := publishedByID[message.EntryID]
		if !exists {
			return nil, errMessage
		}
		published[index] = value
	}
	return published, nil
}

func (driver *sqsJobDriver) ConsumeBatch(ctx context.Context, maximum int) ([]jobqueue.DriverDelivery, error) {
	if driver == nil || jobNilInterface(driver.client) || ctx == nil || maximum <= 0 || maximum > jobBatchLimit {
		return nil, errMessage
	}
	messages, err := receiveJobMessages(driver.client, ctx, driver.queueURL, maximum)
	if err != nil {
		return nil, errProvider
	}
	if len(messages) > maximum {
		return nil, errMessage
	}
	deliveries := make([]jobqueue.DriverDelivery, len(messages))
	seenJobs := make(map[domain.ProductID]struct{}, len(messages))
	seenMessageIDs := make(map[string]struct{}, len(messages))
	seenHandles := make(map[string]struct{}, len(messages))
	for index, message := range messages {
		driverMessage, ok := driverMessageFromReceived(message)
		if !ok || message.MessageID == "" || message.ReceiptHandle == "" {
			return nil, errMessage
		}
		if _, duplicate := seenJobs[driverMessage.JobID]; duplicate {
			return nil, errMessage
		}
		if _, duplicate := seenMessageIDs[message.MessageID]; duplicate {
			return nil, errMessage
		}
		if _, duplicate := seenHandles[message.ReceiptHandle]; duplicate {
			return nil, errMessage
		}
		seenJobs[driverMessage.JobID] = struct{}{}
		seenMessageIDs[message.MessageID] = struct{}{}
		seenHandles[message.ReceiptHandle] = struct{}{}
		deliveries[index] = jobqueue.DriverDelivery{
			Message:       driverMessage,
			MessageID:     message.MessageID,
			ReceiptHandle: message.ReceiptHandle,
		}
	}
	return deliveries, nil
}

func (driver *sqsJobDriver) AcknowledgeBatch(ctx context.Context, receipts []jobqueue.DriverReceipt) ([]domain.ProductID, error) {
	if driver == nil || jobNilInterface(driver.client) || ctx == nil || len(receipts) == 0 || len(receipts) > jobBatchLimit {
		return nil, errMessage
	}
	entries := make([]jobDeleteEntry, len(receipts))
	expected := make(map[string]domain.ProductID, len(receipts))
	seenMessages := make(map[string]struct{}, len(receipts))
	seenHandles := make(map[string]struct{}, len(receipts))
	for index, receipt := range receipts {
		if !validJobProductID(receipt.JobID) || receipt.EntryID != receipt.JobID.String() ||
			receipt.MessageID == "" || receipt.ReceiptHandle == "" {
			return nil, errMessage
		}
		if _, duplicate := expected[receipt.EntryID]; duplicate {
			return nil, errMessage
		}
		if _, duplicate := seenMessages[receipt.MessageID]; duplicate {
			return nil, errMessage
		}
		if _, duplicate := seenHandles[receipt.ReceiptHandle]; duplicate {
			return nil, errMessage
		}
		expected[receipt.EntryID] = receipt.JobID
		seenMessages[receipt.MessageID] = struct{}{}
		seenHandles[receipt.ReceiptHandle] = struct{}{}
		entries[index] = jobDeleteEntry{ID: receipt.EntryID, ReceiptHandle: receipt.ReceiptHandle}
	}
	result, err := deleteJobBatch(driver.client, ctx, driver.queueURL, entries)
	if err != nil {
		return nil, errProvider
	}
	if len(result.FailedIDs) != 0 || len(result.SuccessfulIDs) != len(entries) {
		return nil, errMessage
	}
	seen := make(map[string]struct{}, len(result.SuccessfulIDs))
	for _, id := range result.SuccessfulIDs {
		if _, exists := expected[id]; !exists {
			return nil, errMessage
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, errMessage
		}
		seen[id] = struct{}{}
	}
	acknowledged := make([]domain.ProductID, len(receipts))
	for index, receipt := range receipts {
		if _, exists := seen[receipt.EntryID]; !exists {
			return nil, errMessage
		}
		acknowledged[index] = receipt.JobID
	}
	return acknowledged, nil
}

func validJobDriverMessage(message jobqueue.DriverMessage) bool {
	return message.EntryID == message.JobID.String() && validJobProductID(message.JobID) &&
		message.Scope.Validate() == nil && jobKindPattern.MatchString(message.Kind) &&
		len(message.Body) > 0 && len(message.Body) <= jobMessageLimit &&
		message.SHA256 == sha256.Sum256(message.Body)
}

func sqsJobMessageBytes(message jobqueue.DriverMessage) (int, bool) {
	total := len(message.Body)
	for name, attribute := range expectedJobDriverAttributes(message) {
		attributeBytes := len(name) + len(attribute.DataType) + len(attribute.Value)
		if attributeBytes > jobMessageLimit-total {
			return 0, false
		}
		total += attributeBytes
	}
	return total, true
}

func expectedJobDriverAttributes(message jobqueue.DriverMessage) map[string]messageAttribute {
	return map[string]messageAttribute{
		organizationAttribute: {DataType: "String", Value: message.Scope.OrganizationID().String()},
		workspaceAttribute:    {DataType: "String", Value: message.Scope.WorkspaceID().String()},
		environmentAttribute:  {DataType: "String", Value: message.Scope.EnvironmentID().String()},
		jobIDAttribute:        {DataType: "String", Value: message.JobID.String()},
		jobKindAttribute:      {DataType: "String", Value: message.Kind},
		digestAttribute:       {DataType: "String", Value: hex.EncodeToString(message.SHA256[:])},
	}
}

func driverMessageFromReceived(message receivedMessage) (jobqueue.DriverMessage, bool) {
	if len(message.Body) == 0 || len(message.Body) > jobMessageLimit || len(message.Attributes) != 6 ||
		(message.BodyDigest != "" && !strings.EqualFold(message.BodyDigest, md5Hex(message.Body))) {
		return jobqueue.DriverMessage{}, false
	}
	values := make(map[string]string, len(message.Attributes))
	for key, attribute := range message.Attributes {
		if attribute.DataType != "String" || attribute.Value == "" {
			return jobqueue.DriverMessage{}, false
		}
		switch key {
		case organizationAttribute, workspaceAttribute, environmentAttribute, jobIDAttribute, jobKindAttribute, digestAttribute:
			values[key] = attribute.Value
		default:
			return jobqueue.DriverMessage{}, false
		}
	}
	organizationID, err := domain.ParseProductID(values[organizationAttribute])
	if err != nil {
		return jobqueue.DriverMessage{}, false
	}
	workspaceID, err := domain.ParseProductID(values[workspaceAttribute])
	if err != nil {
		return jobqueue.DriverMessage{}, false
	}
	environmentID, err := domain.ParseProductID(values[environmentAttribute])
	if err != nil {
		return jobqueue.DriverMessage{}, false
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return jobqueue.DriverMessage{}, false
	}
	jobID, err := domain.ParseProductID(values[jobIDAttribute])
	if err != nil || !jobKindPattern.MatchString(values[jobKindAttribute]) {
		return jobqueue.DriverMessage{}, false
	}
	body := []byte(message.Body)
	digest := sha256.Sum256(body)
	if values[digestAttribute] != hex.EncodeToString(digest[:]) {
		return jobqueue.DriverMessage{}, false
	}
	return jobqueue.DriverMessage{
		EntryID: jobID.String(), Scope: scope, JobID: jobID, Kind: values[jobKindAttribute],
		Body: bytes.Clone(body), SHA256: digest,
	}, true
}

func cloneJobDriverMessage(message jobqueue.DriverMessage) jobqueue.DriverMessage {
	message.Body = bytes.Clone(message.Body)
	return message
}

func validJobProductID(id domain.ProductID) bool {
	if id.IsZero() {
		return false
	}
	parsed, err := domain.ParseProductID(id.String())
	return err == nil && parsed == id
}

func validJobQueueURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Hostname() == "" || parsed.Port() == "" || queueNameFromURL(raw) == "" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost.localstack.cloud")
}

func sendJobBatch(client jobBatchAPI, ctx context.Context, queueURL string, entries []outgoingMessage) (result jobBatchSendResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result = jobBatchSendResult{}
			resultErr = errProvider
		}
	}()
	return client.SendJobBatch(ctx, queueURL, entries)
}

func receiveJobMessages(client jobBatchAPI, ctx context.Context, queueURL string, maximum int) (result []receivedMessage, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = errProvider
		}
	}()
	return client.ReceiveJobMessages(ctx, queueURL, maximum)
}

func deleteJobBatch(client jobBatchAPI, ctx context.Context, queueURL string, entries []jobDeleteEntry) (result jobBatchDeleteResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result = jobBatchDeleteResult{}
			resultErr = errProvider
		}
	}()
	return client.DeleteJobBatch(ctx, queueURL, entries)
}

func jobNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
