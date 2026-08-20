package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

const (
	productionRuntimeSchema      = "runtime-event-v1"
	maximumProductionIngestBytes = 64 << 20
	maximumProductionEvents      = 1000
)

var (
	ErrProductionIngest            = errors.New("production runtime ingest rejected")
	ErrProductionIngestDenied      = errors.New("production runtime ingest authentication rejected")
	ErrProductionIngestUnknown     = errors.New("production runtime ingest outcome unknown")
	ErrProductionIngestUnavailable = errors.New("production runtime ingest unavailable")
	productionIdempotencyPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$`)
)

type IngestAuthority struct {
	Scope           domain.Scope
	SensorID        domain.ProductID
	TokenID         domain.ProductID
	TokenGeneration int64
	Source          string
	Mode            string
}

type IngestReserveRequest struct {
	Scope          domain.Scope
	BatchID        domain.ProductID
	IdempotencyKey string
	ContentDigest  [sha256.Size]byte
	Source         string
	MediaType      string
	SchemaVersion  string
	PayloadSize    int64
	EventCount     int
}

type IngestReservation struct {
	BatchID       domain.ProductID
	Generation    int64
	ArtifactKey   string
	RequestDigest [sha256.Size]byte
	State         string
	Replayed      bool
}

type RawArtifactPut struct {
	Scope         domain.Scope
	Key           string
	MediaType     string
	Body          []byte
	ContentDigest [sha256.Size]byte
}

type RawArtifact struct {
	Scope         domain.Scope
	Key           string
	Reference     string
	VersionID     string
	ContentDigest [sha256.Size]byte
	Size          int64
	MediaType     string
	KMSKeyARN     string
}

type IngestFinalizeRequest struct {
	BatchID  domain.ProductID
	JobID    domain.ProductID
	OutboxID domain.ProductID
	Artifact RawArtifact
}

type IngestResult struct {
	BatchID    domain.ProductID
	Generation int64
	State      string
	Replayed   bool
}

type ProductionIngestRepository interface {
	Ready(context.Context) error
	Authenticate(context.Context, *sensor.TokenCredential) (IngestAuthority, error)
	Reserve(context.Context, *sensor.TokenCredential, IngestReserveRequest) (IngestReservation, error)
	Finalize(context.Context, *sensor.TokenCredential, IngestFinalizeRequest) (IngestResult, error)
}

type RawArtifactAuthority interface {
	Put(context.Context, RawArtifactPut) (RawArtifact, error)
}

type ProductionIngestConfig struct {
	Repository   ProductionIngestRepository
	Artifacts    RawArtifactAuthority
	MaximumBytes int64
	Clock        func() time.Time
}

type ProductionIngestHandler struct{ config ProductionIngestConfig }

func NewProductionIngestHandler(config ProductionIngestConfig) (*ProductionIngestHandler, error) {
	if nilProductionIngestValue(config.Repository) || nilProductionIngestValue(config.Artifacts) || config.MaximumBytes <= 0 || config.MaximumBytes > maximumProductionIngestBytes || config.Clock == nil {
		return nil, ErrProductionIngest
	}
	now := config.Clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, ErrProductionIngest
	}
	return &ProductionIngestHandler{config: config}, nil
}

func (handler *ProductionIngestHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if writer == nil {
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	if handler == nil || request == nil || request.URL == nil || request.Method != http.MethodPost || request.URL.Path != "/internal/v1/runtime/events" || request.URL.RawQuery != "" || !validProductionIngestHeaders(request.Header) {
		writeProductionIngestError(writer, http.StatusBadRequest, false)
		return
	}
	credential, err := productionIngestCredential(request.Header)
	if err != nil {
		writeProductionIngestError(writer, http.StatusForbidden, false)
		return
	}
	defer credential.Destroy()
	ctx := request.Context()
	if ctx == nil || ctx.Err() != nil || safeProductionReady(ctx, handler.config.Repository) != nil {
		writeProductionIngestError(writer, http.StatusServiceUnavailable, true)
		return
	}
	authority, err := safeProductionAuthenticate(ctx, handler.config.Repository, credential)
	if err != nil || !validIngestAuthority(authority) {
		writeProductionIngestError(writer, http.StatusForbidden, false)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, handler.config.MaximumBytes+1))
	if err != nil || len(body) == 0 || int64(len(body)) > handler.config.MaximumBytes {
		writeProductionIngestError(writer, http.StatusBadRequest, false)
		return
	}
	defer clear(body)
	input, err := decodeProductionInput(body, authority, handler.config.Clock())
	if err != nil {
		writeProductionIngestError(writer, http.StatusBadRequest, false)
		return
	}
	digest := sha256.Sum256(body)
	idempotencyKey := request.Header.Get("Idempotency-Key")
	batchID, err := deterministicID(authority.SensorID.String() + "\x00runtime-batch\x00" + idempotencyKey + "\x00" + hex.EncodeToString(digest[:]))
	if err != nil {
		writeProductionIngestError(writer, http.StatusServiceUnavailable, true)
		return
	}
	reservation, err := safeProductionReserve(ctx, handler.config.Repository, credential, IngestReserveRequest{Scope: authority.Scope, BatchID: batchID, IdempotencyKey: idempotencyKey, ContentDigest: digest, Source: input.Source, MediaType: "application/json", SchemaVersion: productionRuntimeSchema, PayloadSize: int64(len(body)), EventCount: len(input.Events)})
	if err != nil || !validReservation(reservation, batchID) {
		writeProductionIngestError(writer, http.StatusServiceUnavailable, true)
		return
	}
	artifact, err := safeProductionArtifactPut(ctx, handler.config.Artifacts, RawArtifactPut{Scope: authority.Scope, Key: reservation.ArtifactKey, MediaType: "application/json", Body: bytes.Clone(body), ContentDigest: digest})
	if err != nil || !validRawArtifact(artifact, authority.Scope, reservation.ArtifactKey, digest, int64(len(body))) {
		writeProductionIngestError(writer, http.StatusServiceUnavailable, true)
		return
	}
	jobID, jobErr := deterministicID(batchID.String() + "\x00runtime-job")
	outboxID, outboxErr := deterministicID(batchID.String() + "\x00runtime-outbox")
	if jobErr != nil || outboxErr != nil {
		writeProductionIngestError(writer, http.StatusServiceUnavailable, true)
		return
	}
	result, err := safeProductionFinalize(ctx, handler.config.Repository, credential, IngestFinalizeRequest{BatchID: batchID, JobID: jobID, OutboxID: outboxID, Artifact: artifact})
	if err != nil || result.BatchID != batchID || result.Generation != reservation.Generation || result.State != "queued" {
		writeProductionIngestError(writer, http.StatusServiceUnavailable, true)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(writer).Encode(map[string]string{"batch_id": batchID.String()})
}

func validProductionIngestHeaders(header http.Header) bool {
	if len(header.Values("Authorization")) != 1 || len(header.Values("Content-Type")) != 1 || header.Get("Content-Type") != "application/json" || len(header.Values("X-Zasp-Runtime-Schema")) != 1 || header.Get("X-Zasp-Runtime-Schema") != productionRuntimeSchema || len(header.Values("Idempotency-Key")) != 1 || !productionIdempotencyPattern.MatchString(header.Get("Idempotency-Key")) {
		return false
	}
	for _, name := range []string{"X-Zasp-Organization", "X-Zasp-Workspace", "X-Zasp-Environment", "X-Zasp-Sensor", "X-Zasp-Organization-ID", "X-Zasp-Workspace-ID", "X-Zasp-Environment-ID", "X-Zasp-Scope", "X-Organization-ID", "X-Workspace-ID", "X-Environment-ID", "X-Scope", "X-Tenant", "X-Tenant-ID", "X-Forwarded-Authorization", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if len(header.Values(name)) != 0 {
			return false
		}
	}
	return header.Get("Content-Encoding") == ""
}

func productionIngestCredential(header http.Header) (*sensor.TokenCredential, error) {
	values := header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.Count(values[0], " ") != 1 {
		return nil, ErrProductionIngestDenied
	}
	return sensor.ParseTokenCredential(strings.TrimPrefix(values[0], "Bearer "))
}

func decodeProductionInput(body []byte, authority IngestAuthority, now time.Time) (ingestInput, error) {
	var input ingestInput
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if !utf8.Valid(body) || !uniqueProductionJSON(body) || decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.Source != authority.Source || len(input.Events) == 0 || len(input.Events) > maximumProductionEvents || now.IsZero() || now.Location() != time.UTC {
		return ingestInput{}, ErrProductionIngest
	}
	for _, event := range input.Events {
		record, err := event.toRecord(authority.Scope, authority.Source)
		if err != nil || record.EventTime.Before(now.Add(-24*time.Hour)) || record.EventTime.After(now.Add(5*time.Minute)) {
			return ingestInput{}, ErrProductionIngest
		}
		if _, err := FilterRecord(record, authority.Mode); err != nil {
			return ingestInput{}, ErrProductionIngest
		}
	}
	return input, nil
}

func validIngestAuthority(value IngestAuthority) bool {
	return value.Scope.Validate() == nil && !value.SensorID.IsZero() && !value.TokenID.IsZero() && value.TokenGeneration > 0 && (value.Source == "tetragon" || value.Source == "otlp") && (value.Mode == "full" || value.Mode == "metadata_only")
}

func validReservation(value IngestReservation, batchID domain.ProductID) bool {
	return value.BatchID == batchID && value.Generation > 0 && len(value.ArtifactKey) >= 32 && len(value.ArtifactKey) <= 1024 && strings.HasPrefix(value.ArtifactKey, "runtime/v15/") && !strings.Contains(value.ArtifactKey, "..") && value.RequestDigest != [sha256.Size]byte{} && (value.State == "uploading" || value.State == "queued")
}

func validRawArtifact(value RawArtifact, scope domain.Scope, key string, digest [sha256.Size]byte, size int64) bool {
	return value.Scope == scope && value.Key == key && value.ContentDigest == digest && value.Size == size && value.MediaType == "application/json" && len(value.Reference) >= len(key)+6 && strings.HasPrefix(value.Reference, "s3://") && strings.HasSuffix(value.Reference, "/"+key) && len(value.VersionID) >= 1 && len(value.VersionID) <= 1024 && value.KMSKeyARN != ""
}

func safeProductionReady(ctx context.Context, repository ProductionIngestRepository) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrProductionIngestUnavailable
		}
	}()
	return repository.Ready(ctx)
}
func safeProductionAuthenticate(ctx context.Context, repository ProductionIngestRepository, credential *sensor.TokenCredential) (value IngestAuthority, err error) {
	defer func() {
		if recover() != nil {
			value = IngestAuthority{}
			err = ErrProductionIngestUnavailable
		}
	}()
	return repository.Authenticate(ctx, credential)
}
func safeProductionReserve(ctx context.Context, repository ProductionIngestRepository, credential *sensor.TokenCredential, request IngestReserveRequest) (value IngestReservation, err error) {
	defer func() {
		if recover() != nil {
			value = IngestReservation{}
			err = ErrProductionIngestUnknown
		}
	}()
	return repository.Reserve(ctx, credential, request)
}
func safeProductionArtifactPut(ctx context.Context, artifacts RawArtifactAuthority, request RawArtifactPut) (value RawArtifact, err error) {
	defer func() {
		if recover() != nil {
			value = RawArtifact{}
			err = ErrProductionIngestUnknown
		}
	}()
	return artifacts.Put(ctx, request)
}
func safeProductionFinalize(ctx context.Context, repository ProductionIngestRepository, credential *sensor.TokenCredential, request IngestFinalizeRequest) (value IngestResult, err error) {
	defer func() {
		if recover() != nil {
			value = IngestResult{}
			err = ErrProductionIngestUnknown
		}
	}()
	return repository.Finalize(ctx, credential, request)
}

func writeProductionIngestError(writer http.ResponseWriter, status int, retryable bool) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"code": "runtime_event_rejected", "message": "Request rejected", "retryable": retryable})
}

func uniqueProductionJSON(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !consumeUniqueProductionJSON(decoder) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func consumeUniqueProductionJSON(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK {
				return false
			}
			if _, exists := seen[key]; exists {
				return false
			}
			seen[key] = struct{}{}
			if !consumeUniqueProductionJSON(decoder) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueProductionJSON(decoder) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim(']')
	default:
		return false
	}
}

func nilProductionIngestValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
