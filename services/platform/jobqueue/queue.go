package jobqueue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumBatchMessages    = 10
	maximumSQSBytes         = 1_048_576
	maximumVisibility       = 12 * time.Hour
	envelopeVersion         = 1
)

var (
	ErrConfiguration = errors.New("job queue configuration rejected")
	ErrJob           = errors.New("job rejected")
	ErrPublish       = errors.New("job publish failed")
	ErrConsume       = errors.New("job consume failed")
	ErrAcknowledge   = errors.New("job acknowledge failed")
	ErrVisibility    = errors.New("job visibility renewal failed")
	kindPattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,62}$`)
)

type Config struct {
	OperationTimeout     time.Duration
	MaximumBatchMessages int
	MaximumMessageBytes  int64
	MaximumBatchBytes    int64
}

type Job struct {
	Scope   domain.Scope
	JobID   domain.ProductID
	Kind    string
	Payload []byte
}

type PublishResult struct {
	JobIDs           []domain.ProductID
	Acknowledgements []PublishAcknowledgement
}

type PublishAcknowledgement struct {
	JobID       domain.ProductID
	ProviderAck string
}

type Delivery struct {
	Job     Job
	Receipt Receipt
}

type Receipt struct {
	jobID  domain.ProductID
	driver DriverReceipt
	owner  *Queue
}

func (receipt Receipt) JobID() domain.ProductID {
	return receipt.jobID
}

type DriverMessage struct {
	EntryID string
	Scope   domain.Scope
	JobID   domain.ProductID
	Kind    string
	Body    []byte
	SHA256  [sha256.Size]byte
}

type DriverPublished struct {
	EntryID   string
	JobID     domain.ProductID
	MessageID string
}

type DriverDelivery struct {
	Message       DriverMessage
	MessageID     string
	ReceiptHandle string
}

type DriverReceipt struct {
	EntryID       string
	JobID         domain.ProductID
	MessageID     string
	ReceiptHandle string
}

type JobQueue interface {
	PublishBatch(context.Context, []Job) (PublishResult, error)
	ConsumeBatch(context.Context, int) ([]Delivery, error)
	AcknowledgeBatch(context.Context, []Receipt) error
}

type VisibilityExtender interface {
	ExtendVisibility(context.Context, []Receipt, time.Duration) error
}

type Driver interface {
	PublishBatch(context.Context, []DriverMessage) ([]DriverPublished, error)
	ConsumeBatch(context.Context, int) ([]DriverDelivery, error)
	AcknowledgeBatch(context.Context, []DriverReceipt) ([]domain.ProductID, error)
}

type VisibilityDriver interface {
	ExtendVisibility(context.Context, []DriverReceipt, int32) ([]domain.ProductID, error)
}

type Queue struct {
	driver Driver
	config Config
}

type envelope struct {
	Version        int             `json:"version"`
	JobID          string          `json:"job_id"`
	OrganizationID string          `json:"organization_id"`
	WorkspaceID    string          `json:"workspace_id"`
	EnvironmentID  string          `json:"environment_id"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
}

func New(driver Driver, config Config) (*Queue, error) {
	if nilInterface(driver) || config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout ||
		config.MaximumBatchMessages <= 0 || config.MaximumBatchMessages > maximumBatchMessages ||
		config.MaximumMessageBytes <= 0 || config.MaximumMessageBytes > maximumSQSBytes ||
		config.MaximumBatchBytes <= 0 || config.MaximumBatchBytes > maximumSQSBytes ||
		config.MaximumMessageBytes > config.MaximumBatchBytes {
		return nil, ErrConfiguration
	}
	return &Queue{driver: driver, config: config}, nil
}

func (queue *Queue) PublishBatch(ctx context.Context, jobs []Job) (result PublishResult, resultErr error) {
	if !queue.usable() || ctx == nil {
		return PublishResult{}, ErrPublish
	}
	messages, err := queue.messagesForJobs(jobs)
	if err != nil {
		return PublishResult{}, ErrJob
	}

	operationCtx, cancel := context.WithTimeout(ctx, queue.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return PublishResult{}, ErrPublish
	}
	published, err := publishDriver(queue.driver, operationCtx, cloneDriverMessages(messages))
	if err != nil || operationCtx.Err() != nil || !exactPublished(published, messages) {
		return PublishResult{}, ErrPublish
	}
	byJob := make(map[domain.ProductID]string, len(published))
	for _, acknowledgement := range published {
		byJob[acknowledgement.JobID] = acknowledgement.MessageID
	}
	jobIDs := make([]domain.ProductID, len(messages))
	acknowledgements := make([]PublishAcknowledgement, len(messages))
	for index, message := range messages {
		jobIDs[index] = message.JobID
		acknowledgements[index] = PublishAcknowledgement{JobID: message.JobID, ProviderAck: byJob[message.JobID]}
	}
	return PublishResult{JobIDs: jobIDs, Acknowledgements: acknowledgements}, nil
}

func (queue *Queue) ConsumeBatch(ctx context.Context, maximum int) (deliveries []Delivery, resultErr error) {
	if !queue.usable() || ctx == nil || maximum <= 0 || maximum > queue.config.MaximumBatchMessages {
		return nil, ErrConsume
	}
	operationCtx, cancel := context.WithTimeout(ctx, queue.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return nil, ErrConsume
	}
	returned, err := consumeDriver(queue.driver, operationCtx, maximum)
	if err != nil || operationCtx.Err() != nil || len(returned) > maximum {
		return nil, ErrConsume
	}

	deliveries = make([]Delivery, len(returned))
	seenJobs := make(map[domain.ProductID]struct{}, len(returned))
	seenMessageIDs := make(map[string]struct{}, len(returned))
	seenHandles := make(map[string]struct{}, len(returned))
	var aggregate int64
	for index, returnedDelivery := range returned {
		job, ok := queue.decodeMessage(returnedDelivery.Message)
		if !ok || returnedDelivery.MessageID == "" || returnedDelivery.ReceiptHandle == "" {
			return nil, ErrConsume
		}
		if _, exists := seenJobs[job.JobID]; exists {
			return nil, ErrConsume
		}
		if _, exists := seenMessageIDs[returnedDelivery.MessageID]; exists {
			return nil, ErrConsume
		}
		if _, exists := seenHandles[returnedDelivery.ReceiptHandle]; exists {
			return nil, ErrConsume
		}
		seenJobs[job.JobID] = struct{}{}
		seenMessageIDs[returnedDelivery.MessageID] = struct{}{}
		seenHandles[returnedDelivery.ReceiptHandle] = struct{}{}
		aggregate += int64(len(returnedDelivery.Message.Body))
		if aggregate > queue.config.MaximumBatchBytes {
			return nil, ErrConsume
		}
		driverReceipt := DriverReceipt{
			EntryID:       returnedDelivery.Message.EntryID,
			JobID:         job.JobID,
			MessageID:     returnedDelivery.MessageID,
			ReceiptHandle: returnedDelivery.ReceiptHandle,
		}
		deliveries[index] = Delivery{
			Job: job,
			Receipt: Receipt{
				jobID:  job.JobID,
				driver: driverReceipt,
				owner:  queue,
			},
		}
	}
	return deliveries, nil
}

func (queue *Queue) AcknowledgeBatch(ctx context.Context, receipts []Receipt) (resultErr error) {
	if !queue.usable() || ctx == nil || len(receipts) == 0 || len(receipts) > queue.config.MaximumBatchMessages {
		return ErrAcknowledge
	}
	driverReceipts, seenJobs, ok := queue.prepareReceipts(receipts)
	if !ok {
		return ErrAcknowledge
	}

	operationCtx, cancel := context.WithTimeout(ctx, queue.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrAcknowledge
	}
	acknowledged, err := acknowledgeDriver(queue.driver, operationCtx, driverReceipts)
	if err != nil || operationCtx.Err() != nil || !exactAcknowledged(acknowledged, seenJobs) {
		return ErrAcknowledge
	}
	return nil
}

func (queue *Queue) ExtendVisibility(ctx context.Context, receipts []Receipt, visibility time.Duration) error {
	if !queue.usable() || ctx == nil || len(receipts) == 0 || len(receipts) > queue.config.MaximumBatchMessages || visibility < time.Second || visibility > maximumVisibility || visibility%time.Second != 0 {
		return ErrVisibility
	}
	driver, ok := queue.driver.(VisibilityDriver)
	if !ok || nilInterface(driver) {
		return ErrVisibility
	}
	driverReceipts, seenJobs, ok := queue.prepareReceipts(receipts)
	if !ok {
		return ErrVisibility
	}
	operationCtx, cancel := context.WithTimeout(ctx, queue.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return ErrVisibility
	}
	extended, err := visibilityDriver(driver, operationCtx, driverReceipts, int32(visibility/time.Second))
	if err != nil || operationCtx.Err() != nil || !exactAcknowledged(extended, seenJobs) {
		return ErrVisibility
	}
	return nil
}

func (queue *Queue) prepareReceipts(receipts []Receipt) ([]DriverReceipt, map[domain.ProductID]struct{}, bool) {
	driverReceipts := make([]DriverReceipt, len(receipts))
	seenJobs := make(map[domain.ProductID]struct{}, len(receipts))
	seenMessages := make(map[string]struct{}, len(receipts))
	seenHandles := make(map[string]struct{}, len(receipts))
	for index, receipt := range receipts {
		if receipt.owner != queue || !validProductID(receipt.jobID) || receipt.driver.JobID != receipt.jobID || receipt.driver.EntryID != receipt.jobID.String() || receipt.driver.MessageID == "" || receipt.driver.ReceiptHandle == "" {
			return nil, nil, false
		}
		if _, exists := seenJobs[receipt.jobID]; exists {
			return nil, nil, false
		}
		if _, exists := seenMessages[receipt.driver.MessageID]; exists {
			return nil, nil, false
		}
		if _, exists := seenHandles[receipt.driver.ReceiptHandle]; exists {
			return nil, nil, false
		}
		seenJobs[receipt.jobID] = struct{}{}
		seenMessages[receipt.driver.MessageID] = struct{}{}
		seenHandles[receipt.driver.ReceiptHandle] = struct{}{}
		driverReceipts[index] = receipt.driver
	}
	return driverReceipts, seenJobs, true
}

func (queue *Queue) usable() bool {
	return queue != nil && !nilInterface(queue.driver)
}

func (queue *Queue) messagesForJobs(jobs []Job) ([]DriverMessage, error) {
	if len(jobs) == 0 || len(jobs) > queue.config.MaximumBatchMessages {
		return nil, ErrJob
	}
	messages := make([]DriverMessage, len(jobs))
	seen := make(map[domain.ProductID]struct{}, len(jobs))
	var aggregate int64
	for index, job := range jobs {
		if job.Scope.Validate() != nil || !validProductID(job.JobID) || !kindPattern.MatchString(job.Kind) ||
			len(job.Payload) == 0 || !json.Valid(job.Payload) {
			return nil, ErrJob
		}
		if _, exists := seen[job.JobID]; exists {
			return nil, ErrJob
		}
		seen[job.JobID] = struct{}{}
		body, ok := canonicalBody(job)
		if !ok || int64(len(body)) > queue.config.MaximumMessageBytes {
			return nil, ErrJob
		}
		aggregate += int64(len(body))
		if aggregate > queue.config.MaximumBatchBytes {
			return nil, ErrJob
		}
		messages[index] = DriverMessage{
			EntryID: job.JobID.String(),
			Scope:   job.Scope,
			JobID:   job.JobID,
			Kind:    job.Kind,
			Body:    body,
			SHA256:  sha256.Sum256(body),
		}
	}
	return messages, nil
}

func canonicalBody(job Job) ([]byte, bool) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, job.Payload); err != nil || compact.Len() == 0 {
		return nil, false
	}
	body, err := json.Marshal(envelope{
		Version:        envelopeVersion,
		JobID:          job.JobID.String(),
		OrganizationID: job.Scope.OrganizationID().String(),
		WorkspaceID:    job.Scope.WorkspaceID().String(),
		EnvironmentID:  job.Scope.EnvironmentID().String(),
		Kind:           job.Kind,
		Payload:        json.RawMessage(bytes.Clone(compact.Bytes())),
	})
	return body, err == nil
}

func (queue *Queue) decodeMessage(message DriverMessage) (Job, bool) {
	if message.EntryID == "" || message.Scope.Validate() != nil || !validProductID(message.JobID) ||
		message.EntryID != message.JobID.String() || !kindPattern.MatchString(message.Kind) ||
		len(message.Body) == 0 || int64(len(message.Body)) > queue.config.MaximumMessageBytes ||
		message.SHA256 != sha256.Sum256(message.Body) {
		return Job{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Body))
	decoder.DisallowUnknownFields()
	var decoded envelope
	if err := decoder.Decode(&decoded); err != nil {
		return Job{}, false
	}
	if err := requireJSONEnd(decoder); err != nil {
		return Job{}, false
	}
	jobID, err := domain.ParseProductID(decoded.JobID)
	if err != nil {
		return Job{}, false
	}
	organizationID, err := domain.ParseProductID(decoded.OrganizationID)
	if err != nil {
		return Job{}, false
	}
	workspaceID, err := domain.ParseProductID(decoded.WorkspaceID)
	if err != nil {
		return Job{}, false
	}
	environmentID, err := domain.ParseProductID(decoded.EnvironmentID)
	if err != nil {
		return Job{}, false
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return Job{}, false
	}
	job := Job{Scope: scope, JobID: jobID, Kind: decoded.Kind, Payload: bytes.Clone(decoded.Payload)}
	canonical, ok := canonicalBody(job)
	if !ok || decoded.Version != envelopeVersion || scope != message.Scope || jobID != message.JobID ||
		decoded.Kind != message.Kind || !bytes.Equal(canonical, message.Body) {
		return Job{}, false
	}
	return job, true
}

func requireJSONEnd(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrConsume
		}
		return err
	}
	return nil
}

func exactPublished(published []DriverPublished, messages []DriverMessage) bool {
	if len(published) != len(messages) {
		return false
	}
	expected := make(map[string]domain.ProductID, len(messages))
	for _, message := range messages {
		expected[message.EntryID] = message.JobID
	}
	seen := make(map[string]struct{}, len(published))
	seenMessageIDs := make(map[string]struct{}, len(published))
	for _, result := range published {
		jobID, exists := expected[result.EntryID]
		if !exists || result.JobID != jobID || result.MessageID == "" {
			return false
		}
		if _, duplicate := seen[result.EntryID]; duplicate {
			return false
		}
		if _, duplicate := seenMessageIDs[result.MessageID]; duplicate {
			return false
		}
		seen[result.EntryID] = struct{}{}
		seenMessageIDs[result.MessageID] = struct{}{}
	}
	return len(seen) == len(expected)
}

func exactAcknowledged(acknowledged []domain.ProductID, expected map[domain.ProductID]struct{}) bool {
	if len(acknowledged) != len(expected) {
		return false
	}
	seen := make(map[domain.ProductID]struct{}, len(acknowledged))
	for _, jobID := range acknowledged {
		if _, exists := expected[jobID]; !exists {
			return false
		}
		if _, duplicate := seen[jobID]; duplicate {
			return false
		}
		seen[jobID] = struct{}{}
	}
	return len(seen) == len(expected)
}

func validProductID(id domain.ProductID) bool {
	if id.IsZero() {
		return false
	}
	parsed, err := domain.ParseProductID(id.String())
	return err == nil && parsed == id
}

func cloneDriverMessages(messages []DriverMessage) []DriverMessage {
	cloned := make([]DriverMessage, len(messages))
	for index, message := range messages {
		cloned[index] = cloneDriverMessage(message)
	}
	return cloned
}

func cloneDriverMessage(message DriverMessage) DriverMessage {
	message.Body = bytes.Clone(message.Body)
	return message
}

func publishDriver(driver Driver, ctx context.Context, messages []DriverMessage) (result []DriverPublished, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = ErrPublish
		}
	}()
	return driver.PublishBatch(ctx, messages)
}

func consumeDriver(driver Driver, ctx context.Context, maximum int) (result []DriverDelivery, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = ErrConsume
		}
	}()
	return driver.ConsumeBatch(ctx, maximum)
}

func acknowledgeDriver(driver Driver, ctx context.Context, receipts []DriverReceipt) (result []domain.ProductID, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = ErrAcknowledge
		}
	}()
	return driver.AcknowledgeBatch(ctx, receipts)
}

func visibilityDriver(driver VisibilityDriver, ctx context.Context, receipts []DriverReceipt, seconds int32) (result []domain.ProductID, resultErr error) {
	defer func() {
		if recover() != nil {
			result = nil
			resultErr = ErrVisibility
		}
	}()
	return driver.ExtendVisibility(ctx, receipts, seconds)
}

func nilInterface(value any) bool {
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
