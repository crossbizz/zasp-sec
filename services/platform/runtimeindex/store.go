package runtimeindex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

const contentDigestDomain = "zasp.runtime-index.batch.v1"

var (
	ErrConfiguration  = errors.New("runtime index configuration rejected")
	ErrInput          = errors.New("runtime index input rejected")
	ErrCanceled       = errors.New("runtime index operation canceled")
	ErrRetryable      = errors.New("runtime index operation retryable")
	ErrUnknownOutcome = errors.New("runtime index operation outcome unknown")
	ErrDenied         = errors.New("runtime index authority denied")
	ErrRejected       = errors.New("runtime index operation rejected")
	ErrDrift          = errors.New("runtime index immutable document drift")
)

type Config struct {
	MaximumBatchBytes int
	MaximumDocuments  int
}

type Batch struct {
	Scope            domain.Scope
	BatchID          domain.ProductID
	Generation       int64
	InputDigest      [sha256.Size]byte
	ArchiveReference string
	ArchiveVersionID string
	Body             []byte
}

type DriverDocument struct {
	RecordType       string `json:"record_type"`
	DocumentID       string `json:"document_id"`
	EventID          string `json:"event_id"`
	Source           string `json:"source"`
	SourceEventID    string `json:"source_event_id"`
	EventClass       string `json:"event_class"`
	Action           string `json:"action"`
	WorkloadID       string `json:"workload_id,omitempty"`
	AgentID          string `json:"agent_id,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	TaskID           string `json:"task_id,omitempty"`
	ToolID           string `json:"tool_id,omitempty"`
	SandboxID        string `json:"sandbox_id,omitempty"`
	TraceID          string `json:"trace_id"`
	SpanID           string `json:"span_id"`
	EventTime        string `json:"event_time"`
	EvidenceID       string `json:"evidence_id"`
	ArchiveReference string `json:"archive_reference"`
	ArchiveVersionID string `json:"archive_version_id"`
}

type DriverBatch struct {
	Scope            domain.Scope
	BatchID          string
	Generation       int64
	InputDigest      [sha256.Size]byte
	ContentDigest    [sha256.Size]byte
	ArchiveReference string
	ArchiveVersionID string
	Documents        []DriverDocument
}

type DriverResult struct {
	BatchID       string
	Generation    int64
	InputDigest   [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	DocumentIDs   []string
	Replayed      bool
}

type ApplyResult struct {
	BatchID       domain.ProductID
	Generation    int64
	InputDigest   [sha256.Size]byte
	ContentDigest [sha256.Size]byte
	DocumentIDs   []string
	Replayed      bool
}

type Driver interface {
	Apply(context.Context, DriverBatch) (DriverResult, error)
}

type Store struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Store, error) {
	if nilInterface(driver) || config.MaximumBatchBytes < 1 || config.MaximumBatchBytes > 64<<20 || config.MaximumDocuments < 1 || config.MaximumDocuments > 1000 {
		return nil, ErrConfiguration
	}
	return &Store{driver: driver, config: config}, nil
}

func (store *Store) Apply(ctx context.Context, input Batch) (ApplyResult, error) {
	if store == nil || nilInterface(store.driver) || ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return ApplyResult{}, ErrCanceled
		}
		return ApplyResult{}, ErrInput
	}
	if !validBatch(input, store.config) {
		return ApplyResult{}, ErrInput
	}
	decoded, err := runtimeevent.DecodeArchivedBatch(input.Scope, input.Body)
	if err != nil || len(decoded.Records) > store.config.MaximumDocuments {
		return ApplyResult{}, ErrInput
	}
	driverInput, ids, ok := makeDriverBatch(input, decoded)
	if !ok {
		return ApplyResult{}, ErrInput
	}
	returned, err := callDriver(store.driver, ctx, cloneDriverBatch(driverInput))
	if err != nil {
		return ApplyResult{}, sanitizeDriverError(err)
	}
	if returned.BatchID != driverInput.BatchID || returned.Generation != driverInput.Generation || returned.InputDigest != driverInput.InputDigest || returned.ContentDigest != driverInput.ContentDigest || !equalStrings(returned.DocumentIDs, ids) {
		return ApplyResult{}, ErrDrift
	}
	return ApplyResult{BatchID: input.BatchID, Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: driverInput.ContentDigest, DocumentIDs: append([]string(nil), ids...), Replayed: returned.Replayed}, nil
}

func validBatch(input Batch, config Config) bool {
	return input.Scope.Validate() == nil && !input.BatchID.IsZero() && input.Generation >= 1 && input.InputDigest != ([sha256.Size]byte{}) && len(input.Body) >= 1 && len(input.Body) <= config.MaximumBatchBytes && sha256.Sum256(input.Body) == input.InputDigest && validS3Reference(input.ArchiveReference) && validVersion(input.ArchiveVersionID)
}

func validS3Reference(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.String() == value && parsed.Scheme == "s3" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.RawPath == "" && strings.HasPrefix(parsed.Path, "/") && !strings.Contains(parsed.Path, "..")
}

func validVersion(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func makeDriverBatch(input Batch, decoded runtimeevent.ArchivedBatch) (DriverBatch, []string, bool) {
	records := append([]runtimeevent.Record(nil), decoded.Records...)
	sort.Slice(records, func(i, j int) bool { return records[i].ID.String() < records[j].ID.String() })
	documents := make([]DriverDocument, len(records))
	previous := ""
	for index, record := range records {
		if record.ID.String() <= previous || record.Scope != input.Scope {
			return DriverBatch{}, nil, false
		}
		previous = record.ID.String()
		documents[index] = DriverDocument{
			RecordType: "runtime_event", EventID: record.ID.String(), Source: record.Source, SourceEventID: record.SourceEventID,
			EventClass: record.Class, Action: record.Action, WorkloadID: record.WorkloadID, AgentID: record.AgentID.String(), SessionID: record.SessionID.String(),
			TaskID: record.TaskID, ToolID: record.ToolID, SandboxID: record.SandboxID, TraceID: record.TraceID, SpanID: record.SpanID,
			EventTime: record.EventTime.Format("2006-01-02T15:04:05.000Z"), EvidenceID: record.Event.Evidence.String(),
			ArchiveReference: input.ArchiveReference, ArchiveVersionID: input.ArchiveVersionID,
		}
		documents[index].DocumentID = documentID(input, record.ID)
	}
	authority := struct {
		Domain           string           `json:"domain"`
		OrganizationID   string           `json:"organization_id"`
		WorkspaceID      string           `json:"workspace_id"`
		EnvironmentID    string           `json:"environment_id"`
		BatchID          string           `json:"batch_id"`
		Generation       int64            `json:"generation"`
		InputDigest      string           `json:"input_digest"`
		ArchiveReference string           `json:"archive_reference"`
		ArchiveVersionID string           `json:"archive_version_id"`
		Documents        []DriverDocument `json:"documents"`
	}{contentDigestDomain, input.Scope.OrganizationID().String(), input.Scope.WorkspaceID().String(), input.Scope.EnvironmentID().String(), input.BatchID.String(), input.Generation, hex.EncodeToString(input.InputDigest[:]), input.ArchiveReference, input.ArchiveVersionID, documents}
	encoded, err := json.Marshal(authority)
	if err != nil {
		return DriverBatch{}, nil, false
	}
	contentDigest := sha256.Sum256(encoded)
	ids := make([]string, len(documents))
	for index := range documents {
		ids[index] = documents[index].DocumentID
	}
	return DriverBatch{Scope: input.Scope, BatchID: input.BatchID.String(), Generation: input.Generation, InputDigest: input.InputDigest, ContentDigest: contentDigest, ArchiveReference: input.ArchiveReference, ArchiveVersionID: input.ArchiveVersionID, Documents: documents}, ids, true
}

func documentID(input Batch, eventID domain.ProductID) string {
	value := input.Scope.OrganizationID().String() + "\x00" + input.Scope.WorkspaceID().String() + "\x00" + input.Scope.EnvironmentID().String() + "\x00" + input.BatchID.String() + "\x00" + eventID.String() + "\x00" + hex.EncodeToString(input.InputDigest[:])
	digest := sha256.Sum256([]byte(value))
	return "evt_" + hex.EncodeToString(digest[:])
}

func callDriver(driver Driver, ctx context.Context, input DriverBatch) (result DriverResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result = DriverResult{}
			resultErr = ErrUnknownOutcome
		}
	}()
	return driver.Apply(ctx, input)
}

func sanitizeDriverError(err error) error {
	switch {
	case errors.Is(err, ErrUnknownOutcome):
		return ErrUnknownOutcome
	case errors.Is(err, ErrCanceled):
		return ErrCanceled
	case errors.Is(err, ErrRetryable):
		return ErrRetryable
	case errors.Is(err, ErrDenied):
		return ErrDenied
	case errors.Is(err, ErrRejected):
		return ErrRejected
	case errors.Is(err, ErrDrift):
		return ErrDrift
	default:
		return ErrUnknownOutcome
	}
}

func cloneDriverBatch(input DriverBatch) DriverBatch {
	input.Documents = append([]DriverDocument(nil), input.Documents...)
	return input
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
