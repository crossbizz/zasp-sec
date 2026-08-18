package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const maximumIngestBytes = 1024 * 1024

var (
	ErrAuthentication = errors.New("runtime event authentication rejected")
	ErrIngest         = errors.New("runtime event ingest rejected")
)

type Credential struct {
	Scope  domain.Scope
	Source string
	Token  string
}

type retainedCredential struct {
	scope  domain.Scope
	source string
	hash   string
}

type Authenticator struct{ values []retainedCredential }

func NewAuthenticator(values []Credential) *Authenticator {
	result := &Authenticator{}
	for _, value := range values {
		if value.Scope.Validate() == nil && (value.Source == "tetragon" || value.Source == "otlp") && bounded(value.Token, 256) {
			result.values = append(result.values, retainedCredential{scope: value.Scope, source: value.Source, hash: hashSecret(value.Token)})
		}
	}
	return result
}

func (auth *Authenticator) Authenticate(scope domain.Scope, token string) (string, error) {
	if auth == nil || scope.Validate() != nil || !bounded(token, 256) {
		return "", ErrAuthentication
	}
	hash := hashSecret(token)
	for _, value := range auth.values {
		if value.scope == scope && subtle.ConstantTimeCompare([]byte(value.hash), []byte(hash)) == 1 {
			return value.source, nil
		}
	}
	return "", ErrAuthentication
}

type BatchPublisher interface {
	Publish(context.Context, []Batch) error
}

type IngestHandler struct {
	auth      *Authenticator
	publisher BatchPublisher
	mode      string
}

func NewIngestHandler(auth *Authenticator, publisher BatchPublisher, mode string) (*IngestHandler, error) {
	if auth == nil || len(auth.values) == 0 || publisher == nil || mode != "full" && mode != "metadata_only" {
		return nil, ErrIngest
	}
	return &IngestHandler{auth: auth, publisher: publisher, mode: mode}, nil
}

func (handler *IngestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.auth == nil || handler.publisher == nil || request == nil || request.URL == nil || request.Method != http.MethodPost || request.URL.Path != "/internal/v1/events" || request.URL.RawQuery != "" {
		writeIngestError(writer, http.StatusNotFound)
		return
	}
	scope, err := scopeFromHeaders(request)
	if err != nil {
		writeIngestError(writer, http.StatusForbidden)
		return
	}
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 {
		writeIngestError(writer, http.StatusForbidden)
		return
	}
	source, err := handler.auth.Authenticate(scope, strings.TrimPrefix(authorization, "Bearer "))
	if err != nil {
		writeIngestError(writer, http.StatusForbidden)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" {
		writeIngestError(writer, http.StatusBadRequest)
		return
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumIngestBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumIngestBytes {
		writeIngestError(writer, http.StatusBadRequest)
		return
	}
	var input ingestInput
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.Source != source || len(input.Events) == 0 || len(input.Events) > 10_000 {
		writeIngestError(writer, http.StatusBadRequest)
		return
	}
	records := make([]Record, len(input.Events))
	for index, event := range input.Events {
		record, conversionErr := event.toRecord(scope, source)
		if conversionErr != nil {
			writeIngestError(writer, http.StatusBadRequest)
			return
		}
		filtered, filterErr := FilterRecord(record, handler.mode)
		if filterErr != nil {
			writeIngestError(writer, http.StatusBadRequest)
			return
		}
		records[index] = filtered
	}
	batches, err := BuildBatches(records, 100, 512*1024)
	if err != nil || safePublish(handler.publisher, request.Context(), batches) != nil {
		writeIngestError(writer, http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(writer).Encode(map[string]any{"accepted": len(records), "batches": len(batches)})
}

type ingestInput struct {
	Source string        `json:"source"`
	Events []ingestEvent `json:"events"`
}

type ingestEvent struct {
	EventID    string            `json:"event_id"`
	Class      string            `json:"class"`
	Action     string            `json:"action"`
	WorkloadID string            `json:"workload_id"`
	EventTime  string            `json:"event_time"`
	EvidenceID string            `json:"evidence_id"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Content    map[string]string `json:"content,omitempty"`
}

func (event ingestEvent) toRecord(scope domain.Scope, source string) (Record, error) {
	when, timeErr := time.Parse(timestampLayout, event.EventTime)
	evidenceID, evidenceErr := domain.ParseProductID(event.EvidenceID)
	if timeErr != nil || evidenceErr != nil {
		return Record{}, ErrIngest
	}
	if source == "tetragon" {
		if len(event.Attributes) != 0 {
			return Record{}, ErrIngest
		}
		return AdaptTetragon(TetragonInput{Scope: scope, SourceEventID: event.EventID, Kind: event.Class, Action: event.Action, WorkloadID: event.WorkloadID, EventTime: when, EvidenceID: evidenceID, Content: event.Content})
	}
	if event.EventID != "" || event.Class != "" || event.Action != "" || event.WorkloadID != "" {
		return Record{}, ErrIngest
	}
	return AdaptOTLP(OTLPInput{Scope: scope, EventTime: when, EvidenceID: evidenceID, Attributes: event.Attributes, Content: event.Content})
}

func scopeFromHeaders(request *http.Request) (domain.Scope, error) {
	organizationID, organizationErr := domain.ParseProductID(request.Header.Get("X-Zasp-Organization"))
	workspaceID, workspaceErr := domain.ParseProductID(request.Header.Get("X-Zasp-Workspace"))
	environmentID, environmentErr := domain.ParseProductID(request.Header.Get("X-Zasp-Environment"))
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil {
		return domain.Scope{}, ErrAuthentication
	}
	scope, err := domain.NewScope(organizationID, workspaceID, environmentID)
	if err != nil {
		return domain.Scope{}, ErrAuthentication
	}
	return scope, nil
}

func hashSecret(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func safePublish(publisher BatchPublisher, ctx context.Context, batches []Batch) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrIngest
		}
	}()
	return publisher.Publish(ctx, batches)
}

func writeIngestError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": "runtime_event_rejected", "message": "Request rejected", "retryable": status == http.StatusServiceUnavailable})
}
