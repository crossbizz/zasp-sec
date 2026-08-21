package runtimeevent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

const (
	productionIngestReadySQL        = `SELECT jsonb_build_object('ready',zasp_runtime_gateway_reconciliation_readiness($1,$2) AND zasp_runtime_principal_ready('zasp_runtime_ingest'))`
	productionIngestAuthenticateSQL = `SELECT zasp_runtime_authenticate_sensor($1,$2,'event-ingest')`
	productionIngestReserveSQL      = `SELECT zasp_runtime_reserve_batch($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9,$10)`
	productionIngestFinalizeSQL     = `SELECT zasp_runtime_finalize_batch($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	productionIngestHeartbeatSQL    = `SELECT zasp_runtime_sensor_heartbeat($1,$2,'event-ingest',$3,$4,$5,$6,$7,$8,$9)`
)

var (
	productionKMSKeyPattern     = regexp.MustCompile(`^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]{8,128}$`)
	productionCapabilityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,95}$`)
)

type ProductionIngestDatabase interface {
	QueryJSON(context.Context, string, ...any) (json.RawMessage, error)
}

type PostgresProductionIngestRepository struct{ database ProductionIngestDatabase }

func NewPostgresProductionIngestRepository(database ProductionIngestDatabase) (*PostgresProductionIngestRepository, error) {
	if nilProductionDatabase(database) {
		return nil, ErrProductionIngest
	}
	return &PostgresProductionIngestRepository{database: database}, nil
}

func (repository *PostgresProductionIngestRepository) Ready(ctx context.Context) error {
	if !validProductionRepository(repository, ctx) {
		return ErrProductionIngestUnavailable
	}
	payload, err := safeProductionQuery(repository.database, ctx, productionIngestReadySQL, migrations.ProductionRuntimeGatewayReconciliation().Checksum(), migrations.ProductionRuntimeGatewayReconciliationSemanticFingerprint())
	var result struct {
		Ready bool `json:"ready"`
	}
	if err != nil || strictProductionJSON(payload, &result) != nil || !result.Ready {
		return ErrProductionIngestUnavailable
	}
	return nil
}

func (repository *PostgresProductionIngestRepository) Authenticate(ctx context.Context, credential *sensor.TokenCredential) (IngestAuthority, error) {
	if !validProductionRepository(repository, ctx) || credential == nil {
		return IngestAuthority{}, ErrProductionIngestDenied
	}
	locator, secret, err := credential.Parts()
	if err != nil {
		return IngestAuthority{}, ErrProductionIngestDenied
	}
	defer clear(locator)
	defer clear(secret)
	payload, queryErr := safeProductionQuery(repository.database, ctx, productionIngestAuthenticateSQL, locator, secret)
	var wire struct {
		OrganizationID  string `json:"organization_id"`
		WorkspaceID     string `json:"workspace_id"`
		EnvironmentID   string `json:"environment_id"`
		SensorID        string `json:"sensor_id"`
		SensorKind      string `json:"sensor_kind"`
		SensorMode      string `json:"sensor_mode"`
		SensorVersion   int64  `json:"sensor_version"`
		TokenID         string `json:"token_id"`
		TokenGeneration int64  `json:"token_generation"`
		Audience        string `json:"audience"`
	}
	if queryErr != nil || strictProductionJSON(payload, &wire) != nil || wire.SensorVersion < 1 || wire.TokenGeneration < 1 || wire.Audience != sensor.SensorTokenAudienceEventIngest {
		return IngestAuthority{}, ErrProductionIngestDenied
	}
	organizationID, organizationErr := domain.ParseProductID(wire.OrganizationID)
	workspaceID, workspaceErr := domain.ParseProductID(wire.WorkspaceID)
	environmentID, environmentErr := domain.ParseProductID(wire.EnvironmentID)
	sensorID, sensorErr := domain.ParseProductID(wire.SensorID)
	tokenID, tokenErr := domain.ParseProductID(wire.TokenID)
	scope, scopeErr := domain.NewScope(organizationID, workspaceID, environmentID)
	result := IngestAuthority{Scope: scope, SensorID: sensorID, TokenID: tokenID, TokenGeneration: wire.TokenGeneration, Source: wire.SensorKind, Mode: wire.SensorMode}
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil || sensorErr != nil || tokenErr != nil || scopeErr != nil || !validIngestAuthority(result) {
		return IngestAuthority{}, ErrProductionIngestDenied
	}
	return result, nil
}

func (repository *PostgresProductionIngestRepository) Reserve(ctx context.Context, credential *sensor.TokenCredential, request IngestReserveRequest) (IngestReservation, error) {
	if !validProductionRepository(repository, ctx) || credential == nil || !validReserveRequest(request) {
		return IngestReservation{}, ErrProductionIngest
	}
	locator, secret, err := credential.Parts()
	if err != nil {
		return IngestReservation{}, ErrProductionIngestDenied
	}
	defer clear(locator)
	defer clear(secret)
	payload, queryErr := safeProductionQuery(repository.database, ctx, productionIngestReserveSQL, locator, secret, request.BatchID.String(), request.IdempotencyKey, request.ContentDigest[:], request.Source, request.MediaType, request.SchemaVersion, request.PayloadSize, request.EventCount)
	var wire struct {
		BatchID       string `json:"batch_id"`
		Generation    int64  `json:"generation"`
		ArtifactKey   string `json:"artifact_key"`
		RequestDigest string `json:"request_digest"`
		State         string `json:"state"`
		Replayed      bool   `json:"replayed"`
	}
	if queryErr != nil || strictProductionJSON(payload, &wire) != nil {
		var postgresError *pgconn.PgError
		if errors.As(queryErr, &postgresError) && postgresError.Code == "53300" && postgresError.Message == "runtime batch rate limited" {
			return IngestReservation{}, ErrProductionIngestRateLimited
		}
		return IngestReservation{}, ErrProductionIngestUnavailable
	}
	batchID, parseErr := domain.ParseProductID(wire.BatchID)
	digest, digestErr := hex.DecodeString(wire.RequestDigest)
	result := IngestReservation{BatchID: batchID, Generation: wire.Generation, ArtifactKey: wire.ArtifactKey, State: wire.State, Replayed: wire.Replayed}
	if digestErr == nil && len(digest) == sha256.Size {
		copy(result.RequestDigest[:], digest)
	}
	clear(digest)
	if parseErr != nil || batchID != request.BatchID || digestErr != nil || !validReservation(result, request.BatchID) {
		return IngestReservation{}, ErrProductionIngestUnavailable
	}
	return result, nil
}

func (repository *PostgresProductionIngestRepository) Finalize(ctx context.Context, credential *sensor.TokenCredential, request IngestFinalizeRequest) (IngestResult, error) {
	if !validProductionRepository(repository, ctx) || credential == nil || !validFinalizeRequest(request) {
		return IngestResult{}, ErrProductionIngest
	}
	locator, secret, err := credential.Parts()
	if err != nil {
		return IngestResult{}, ErrProductionIngestDenied
	}
	defer clear(locator)
	defer clear(secret)
	payload, queryErr := safeProductionQuery(repository.database, ctx, productionIngestFinalizeSQL, locator, secret, request.BatchID.String(), request.JobID.String(), request.OutboxID.String(), request.Artifact.Reference, request.Artifact.Key, request.Artifact.VersionID, request.Artifact.ContentDigest[:], request.Artifact.Size, request.Artifact.KMSKeyARN)
	var wire struct {
		BatchID    string `json:"batch_id"`
		Generation int64  `json:"generation"`
		State      string `json:"state"`
		Replayed   bool   `json:"replayed"`
	}
	if queryErr != nil || strictProductionJSON(payload, &wire) != nil {
		return IngestResult{}, ErrProductionIngestUnknown
	}
	batchID, parseErr := domain.ParseProductID(wire.BatchID)
	result := IngestResult{BatchID: batchID, Generation: wire.Generation, State: wire.State, Replayed: wire.Replayed}
	if parseErr != nil || batchID != request.BatchID || result.Generation < 1 || result.State != "queued" {
		return IngestResult{}, ErrProductionIngestUnknown
	}
	return result, nil
}

func (repository *PostgresProductionIngestRepository) RecordAuthenticatedHeartbeat(ctx context.Context, credential *sensor.TokenCredential, report sensor.PrivateHeartbeat) error {
	if !validProductionRepository(repository, ctx) || credential == nil || !validRepositoryHeartbeat(report) {
		return sensor.ErrInvalid
	}
	locator, secret, err := credential.Parts()
	if err != nil {
		return sensor.ErrForbidden
	}
	defer clear(locator)
	defer clear(secret)
	capabilities, marshalErr := json.Marshal(report.Capabilities)
	if marshalErr != nil {
		return sensor.ErrInvalid
	}
	payload, queryErr := safeProductionQuery(repository.database, ctx, productionIngestHeartbeatSQL, locator, secret, report.Sequence, report.Status, json.RawMessage(capabilities), report.Kernel, report.BTF, report.EventRate, report.Drops)
	clear(capabilities)
	var wire struct {
		SensorID   string    `json:"sensor_id"`
		Sequence   int64     `json:"sequence"`
		ObservedAt time.Time `json:"observed_at"`
	}
	if queryErr != nil {
		return sensor.ErrForbidden
	}
	if strictProductionJSON(payload, &wire) != nil || wire.Sequence != report.Sequence || wire.ObservedAt.IsZero() || wire.ObservedAt.Location() != time.UTC {
		return sensor.ErrUnavailable
	}
	if sensorID, parseErr := domain.ParseProductID(wire.SensorID); parseErr != nil || sensorID.IsZero() {
		return sensor.ErrUnavailable
	}
	return nil
}

func validReserveRequest(request IngestReserveRequest) bool {
	return request.Scope.Validate() == nil && !request.BatchID.IsZero() && productionIdempotencyPattern.MatchString(request.IdempotencyKey) && request.ContentDigest != [sha256.Size]byte{} && (request.Source == "tetragon" || request.Source == "otlp") && request.MediaType == "application/json" && request.SchemaVersion == productionRuntimeSchema && request.PayloadSize >= 1 && request.PayloadSize <= maximumProductionIngestBytes && request.EventCount >= 1 && request.EventCount <= maximumProductionEvents
}

func validFinalizeRequest(request IngestFinalizeRequest) bool {
	return !request.BatchID.IsZero() && !request.JobID.IsZero() && !request.OutboxID.IsZero() && validRawArtifact(request.Artifact, request.Artifact.Scope, request.Artifact.Key, request.Artifact.ContentDigest, request.Artifact.Size) && productionKMSKeyPattern.MatchString(request.Artifact.KMSKeyARN)
}

func validRepositoryHeartbeat(report sensor.PrivateHeartbeat) bool {
	if report.Sequence < 0 || report.Status != "healthy" && report.Status != "degraded" || len(report.Capabilities) < 1 || len(report.Capabilities) > 32 || len(report.Kernel) < 1 || len(report.Kernel) > 128 || strings.TrimSpace(report.Kernel) != report.Kernel || report.EventRate > 1_000_000_000 || report.Drops > 1_000_000_000 {
		return false
	}
	copyCapabilities := append([]string(nil), report.Capabilities...)
	sort.Strings(copyCapabilities)
	for index, capability := range copyCapabilities {
		if !productionCapabilityPattern.MatchString(capability) || capability != report.Capabilities[index] || index > 0 && capability == copyCapabilities[index-1] {
			return false
		}
	}
	return true
}

func strictProductionJSON(payload json.RawMessage, destination any) error {
	if len(payload) < 2 || len(payload) > 16<<10 || destination == nil {
		return ErrProductionIngestUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrProductionIngestUnavailable
	}
	return nil
}

func safeProductionQuery(database ProductionIngestDatabase, ctx context.Context, statement string, arguments ...any) (payload json.RawMessage, err error) {
	defer func() {
		if recover() != nil {
			payload = nil
			err = ErrProductionIngestUnavailable
		}
	}()
	return database.QueryJSON(ctx, statement, arguments...)
}

func validProductionRepository(repository *PostgresProductionIngestRepository, ctx context.Context) bool {
	return repository != nil && !nilProductionDatabase(repository.database) && ctx != nil && ctx.Err() == nil
}

func nilProductionDatabase(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

var _ ProductionIngestRepository = (*PostgresProductionIngestRepository)(nil)
var _ sensor.PrivateHeartbeatAuthority = (*PostgresProductionIngestRepository)(nil)
