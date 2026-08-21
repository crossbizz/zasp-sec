package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const (
	postgresRuntimePublicSensorPageSQL           = `SELECT zasp_runtime_public_sensor_page($1,$2,$3,NULLIF($4,''),$5)`
	postgresRuntimePublicSensorDetailSQL         = `SELECT zasp_runtime_public_sensor_detail($1,$2,$3,$4)`
	postgresRuntimePublicSensorCoverageSQL       = `SELECT zasp_runtime_public_sensor_coverage($1,$2,$3,$4)`
	postgresRuntimePublicSensorTokenAuthoritySQL = `SELECT zasp_runtime_public_sensor_token_authority($1,$2,$3,$4)`
	postgresRuntimePublicCreateSensorSQL         = `SELECT zasp_runtime_public_create_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`
	postgresRuntimePublicUpdateSensorSQL         = `SELECT zasp_runtime_public_update_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
	postgresRuntimePublicDeleteSensorSQL         = `SELECT zasp_runtime_public_delete_sensor($1,$2,$3,$4,$5,$6,$7,$8)`
	postgresRuntimePublicRotateSensorSQL         = `SELECT zasp_runtime_public_rotate_sensor($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
)

var publicSensorFields = []string{"created_at", "id", "kind", "last_heartbeat_at", "mode", "name", "state", "token_expires_at", "updated_at", "version"}

type SensorPublicRepository struct {
	database JSONDatabase
}

type ProductSensor struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Kind            string     `json:"kind"`
	Mode            string     `json:"mode"`
	State           string     `json:"state"`
	Version         int64      `json:"version"`
	TokenExpiresAt  *time.Time `json:"token_expires_at"`
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type SensorPage struct {
	Items  []ProductSensor
	NextID string
}

type sensorPageEnvelope struct {
	Items  []json.RawMessage `json:"items"`
	NextID *string           `json:"next_id"`
}

type SensorCoverage struct {
	SensorID      string     `json:"sensor_id"`
	Supported     bool       `json:"supported"`
	Status        string     `json:"status"`
	LastHeartbeat *time.Time `json:"last_heartbeat"`
	Kernel        string     `json:"kernel"`
	BTF           bool       `json:"btf"`
	Capabilities  []string   `json:"capabilities"`
	EventRate     uint64     `json:"event_rate"`
	Drops         int64      `json:"drops"`
}

type SensorTokenAuthority struct {
	Generation    int64 `json:"generation"`
	SensorVersion int64 `json:"sensor_version"`
}

type SensorCreateMutation struct {
	SensorID, Name, Kind, Mode, IdempotencyKey string
	RequestDigest                              []byte
	TokenID                                    string
	TokenGeneration                            int64
	LocatorDigest, Salt, TokenHash             []byte
	TokenExpiresAt                             time.Time
}

type SensorUpdateMutation struct {
	SensorID, Name, Mode, IdempotencyKey string
	ExpectedVersion                      int64
	RequestDigest                        []byte
}

type SensorDeleteMutation struct {
	SensorID, IdempotencyKey string
	ExpectedVersion          int64
	RequestDigest            []byte
}

type SensorRotateMutation struct {
	SensorID, IdempotencyKey       string
	ExpectedVersion                int64
	RequestDigest                  []byte
	TokenID                        string
	TokenGeneration                int64
	LocatorDigest, Salt, TokenHash []byte
	TokenExpiresAt                 time.Time
}

type SensorMutationResult struct {
	Sensor          ProductSensor
	TokenID         string
	TokenGeneration int64
	TokenExpiresAt  *time.Time
	Replayed        bool
}

type sensorMutationEnvelope struct {
	Body            json.RawMessage `json:"body"`
	TokenID         *string         `json:"token_id"`
	TokenGeneration *int64          `json:"token_generation"`
	TokenExpiresAt  *time.Time      `json:"token_expires_at"`
	Replayed        bool            `json:"replayed"`
}

func NewSensorPublicRepository(database JSONDatabase) (*SensorPublicRepository, error) {
	if nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := database.SchemaVersion(ctx)
	if err != nil || version != RuntimeDataPlaneSchemaVersion {
		return nil, ErrRepositoryConfiguration
	}
	payload, err := database.QueryJSON(ctx, postgresRuntimeDataPlaneReadinessSQL, migrations.ProductionRuntimeIngestReconciliation().Checksum(), migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return nil, ErrRepositoryConfiguration
	}
	return &SensorPublicRepository{database: database}, nil
}

func (repository *SensorPublicRepository) Ready(ctx context.Context) error {
	if repository == nil || nilInterface(repository.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimeDataPlaneReadinessSQL, migrations.ProductionRuntimeIngestReconciliation().Checksum(), migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint())
	var ready bool
	if err != nil || decodeStrictDiscovery(payload, &ready) != nil || !ready {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (repository *SensorPublicRepository) ListSensors(ctx context.Context, scope domain.Scope, after string, limit int) (SensorPage, error) {
	if !validSensorRepository(repository, ctx) || scope.Validate() != nil || after != "" && !validProductID(after) || limit < 1 || limit > 100 {
		return SensorPage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicSensorPageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), after, limit)
	if err != nil {
		return SensorPage{}, discoveryProviderError(err)
	}
	var envelope sensorPageEnvelope
	if !exactJSONFields(payload, "items", "next_id") || decodeStrictDiscovery(payload, &envelope) != nil || envelope.Items == nil || len(envelope.Items) > limit {
		return SensorPage{}, ErrRepositoryUnavailable
	}
	page := SensorPage{Items: make([]ProductSensor, 0, len(envelope.Items))}
	prior := after
	for _, raw := range envelope.Items {
		item, valid := decodeSensorRecord(raw)
		if !valid || item.ID <= prior {
			return SensorPage{}, ErrRepositoryUnavailable
		}
		prior = item.ID
		page.Items = append(page.Items, item)
	}
	if envelope.NextID != nil {
		if len(page.Items) != limit || *envelope.NextID != prior {
			return SensorPage{}, ErrRepositoryUnavailable
		}
		page.NextID = *envelope.NextID
	}
	return page, nil
}

func (repository *SensorPublicRepository) GetSensor(ctx context.Context, scope domain.Scope, id string) (ProductSensor, error) {
	if !validSensorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(id) {
		return ProductSensor{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicSensorDetailSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id)
	if err != nil {
		return ProductSensor{}, discoveryProviderError(err)
	}
	result, valid := decodeSensorRecord(payload)
	if !valid || result.ID != id {
		return ProductSensor{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *SensorPublicRepository) GetSensorCoverage(ctx context.Context, scope domain.Scope, id string) (SensorCoverage, error) {
	if !validSensorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(id) {
		return SensorCoverage{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicSensorCoverageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id)
	if err != nil {
		return SensorCoverage{}, discoveryProviderError(err)
	}
	var result SensorCoverage
	if !exactJSONFields(payload, "btf", "capabilities", "drops", "event_rate", "kernel", "last_heartbeat", "sensor_id", "status", "supported") || decodeStrictDiscovery(payload, &result) != nil || !validSensorCoverage(result, id) {
		return SensorCoverage{}, ErrRepositoryUnavailable
	}
	if result.LastHeartbeat != nil {
		value := result.LastHeartbeat.UTC()
		result.LastHeartbeat = &value
	}
	return result, nil
}

func (repository *SensorPublicRepository) GetSensorTokenAuthority(ctx context.Context, scope domain.Scope, id string) (SensorTokenAuthority, error) {
	if !validSensorRepository(repository, ctx) || scope.Validate() != nil || !validProductID(id) {
		return SensorTokenAuthority{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicSensorTokenAuthoritySQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id)
	if err != nil {
		return SensorTokenAuthority{}, discoveryProviderError(err)
	}
	var result SensorTokenAuthority
	if !exactJSONFields(payload, "generation", "sensor_version") || decodeStrictDiscovery(payload, &result) != nil || result.Generation < 1 || result.SensorVersion < 1 {
		return SensorTokenAuthority{}, ErrRepositoryUnavailable
	}
	return result, nil
}

func (repository *SensorPublicRepository) CreateSensor(ctx context.Context, identity RequestIdentity, input SensorCreateMutation) (SensorMutationResult, error) {
	if !validSensorMutationAuthority(repository, ctx, identity) || !validCreateSensorMutation(input) {
		return SensorMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicCreateSensorSQL,
		identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(),
		input.SensorID, input.Name, input.Kind, input.Mode, input.IdempotencyKey, input.RequestDigest, input.TokenID, input.TokenGeneration, input.LocatorDigest, input.Salt, input.TokenHash, input.TokenExpiresAt)
	return decodeSensorMutation(payload, err, input.SensorID, input.TokenID, input.TokenGeneration, true)
}

func (repository *SensorPublicRepository) UpdateSensor(ctx context.Context, identity RequestIdentity, input SensorUpdateMutation) (SensorMutationResult, error) {
	if !validSensorMutationAuthority(repository, ctx, identity) || !validProductID(input.SensorID) || !validSensorName(input.Name) || !validSensorMode(input.Mode) || input.ExpectedVersion < 1 || !validIdempotentDigest(input.IdempotencyKey, input.RequestDigest) {
		return SensorMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicUpdateSensorSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.SensorID, input.ExpectedVersion, input.Name, input.Mode, input.IdempotencyKey, input.RequestDigest)
	return decodeSensorMutation(payload, err, input.SensorID, "", 0, false)
}

func (repository *SensorPublicRepository) DeleteSensor(ctx context.Context, identity RequestIdentity, input SensorDeleteMutation) (SensorMutationResult, error) {
	if !validSensorMutationAuthority(repository, ctx, identity) || !validProductID(input.SensorID) || input.ExpectedVersion < 1 || !validIdempotentDigest(input.IdempotencyKey, input.RequestDigest) {
		return SensorMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicDeleteSensorSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.SensorID, input.ExpectedVersion, input.IdempotencyKey, input.RequestDigest)
	return decodeSensorMutation(payload, err, input.SensorID, "", 0, false)
}

func (repository *SensorPublicRepository) RotateSensorToken(ctx context.Context, identity RequestIdentity, input SensorRotateMutation) (SensorMutationResult, error) {
	if !validSensorMutationAuthority(repository, ctx, identity) || !validProductID(input.SensorID) || input.ExpectedVersion < 1 || !validTokenMutation(input.TokenID, input.TokenGeneration, input.LocatorDigest, input.Salt, input.TokenHash, input.TokenExpiresAt) || !validIdempotentDigest(input.IdempotencyKey, input.RequestDigest) {
		return SensorMutationResult{}, ErrRepositoryOperation
	}
	payload, err := repository.database.QueryJSON(ctx, postgresRuntimePublicRotateSensorSQL, identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), input.SensorID, input.ExpectedVersion, input.IdempotencyKey, input.RequestDigest, input.TokenID, input.TokenGeneration, input.LocatorDigest, input.Salt, input.TokenHash, input.TokenExpiresAt)
	return decodeSensorMutation(payload, err, input.SensorID, input.TokenID, input.TokenGeneration, true)
}

func decodeSensorMutation(payload json.RawMessage, err error, sensorID, tokenID string, tokenGeneration int64, tokenExpected bool) (SensorMutationResult, error) {
	if err != nil {
		return SensorMutationResult{}, discoveryProviderError(err)
	}
	var envelope sensorMutationEnvelope
	if !exactJSONFields(payload, "body", "replayed", "token_expires_at", "token_generation", "token_id") || decodeStrictDiscovery(payload, &envelope) != nil {
		return SensorMutationResult{}, ErrRepositoryUnavailable
	}
	sensorValue, valid := decodeSensorRecord(envelope.Body)
	if !valid || !envelope.Replayed && sensorValue.ID != sensorID {
		return SensorMutationResult{}, ErrRepositoryUnavailable
	}
	if tokenExpected {
		if envelope.TokenID == nil || envelope.TokenGeneration == nil || envelope.TokenExpiresAt == nil || !validProductID(*envelope.TokenID) || *envelope.TokenGeneration < 1 || !validSensorTime(*envelope.TokenExpiresAt) || sensorValue.TokenExpiresAt == nil || !sensorValue.TokenExpiresAt.Equal(*envelope.TokenExpiresAt) || !envelope.Replayed && (*envelope.TokenID != tokenID || *envelope.TokenGeneration != tokenGeneration) {
			return SensorMutationResult{}, ErrRepositoryUnavailable
		}
		value := envelope.TokenExpiresAt.UTC()
		return SensorMutationResult{Sensor: sensorValue, TokenID: *envelope.TokenID, TokenGeneration: *envelope.TokenGeneration, TokenExpiresAt: &value, Replayed: envelope.Replayed}, nil
	}
	if envelope.TokenID != nil || envelope.TokenGeneration != nil || envelope.TokenExpiresAt != nil {
		return SensorMutationResult{}, ErrRepositoryUnavailable
	}
	return SensorMutationResult{Sensor: sensorValue, Replayed: envelope.Replayed}, nil
}

func decodeSensorRecord(payload json.RawMessage) (ProductSensor, bool) {
	var result ProductSensor
	if !exactJSONFields(payload, publicSensorFields...) || decodeStrictDiscovery(payload, &result) != nil || !validProductID(result.ID) || !validSensorName(result.Name) || !stringIn(result.Kind, "tetragon", "otlp") || !validSensorMode(result.Mode) || !stringIn(result.State, "pending", "active", "degraded", "revoked", "deleted") || result.Version < 1 || !validSensorTime(result.CreatedAt) || !validSensorTime(result.UpdatedAt) || result.UpdatedAt.Before(result.CreatedAt) {
		return ProductSensor{}, false
	}
	if result.TokenExpiresAt != nil {
		if !validSensorTime(*result.TokenExpiresAt) {
			return ProductSensor{}, false
		}
		value := result.TokenExpiresAt.UTC()
		result.TokenExpiresAt = &value
	}
	if result.LastHeartbeatAt != nil {
		if !validSensorTime(*result.LastHeartbeatAt) || result.LastHeartbeatAt.Before(result.CreatedAt) {
			return ProductSensor{}, false
		}
		value := result.LastHeartbeatAt.UTC()
		result.LastHeartbeatAt = &value
	}
	if stringIn(result.State, "pending", "active", "degraded") != (result.TokenExpiresAt != nil) {
		return ProductSensor{}, false
	}
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, true
}

func validSensorCoverage(result SensorCoverage, sensorID string) bool {
	if result.SensorID != sensorID || result.Capabilities == nil || len(result.Capabilities) > 32 || result.Drops < 0 || result.EventRate > 1e9 || !stringIn(result.Status, "pending", "healthy", "degraded", "offline", "revoked") || len(result.Kernel) > 128 || result.Kernel != "" && !printableInventoryString(result.Kernel, 1, 128, false) {
		return false
	}
	prior := ""
	for _, capability := range result.Capabilities {
		if !stringIn(capability, "file", "network", "process", "runtime", "syscall") || capability <= prior {
			return false
		}
		prior = capability
	}
	return result.LastHeartbeat == nil || validSensorTime(*result.LastHeartbeat)
}

func validSensorRepository(repository *SensorPublicRepository, ctx context.Context) bool {
	return repository != nil && !nilInterface(repository.database) && ctx != nil && ctx.Err() == nil
}

func validSensorMutationAuthority(repository *SensorPublicRepository, ctx context.Context, identity RequestIdentity) bool {
	return validSensorRepository(repository, ctx) && validRequestIdentity(identity, false)
}

func validCreateSensorMutation(input SensorCreateMutation) bool {
	return validProductID(input.SensorID) && validSensorName(input.Name) && stringIn(input.Kind, "tetragon", "otlp") && validSensorMode(input.Mode) && validIdempotentDigest(input.IdempotencyKey, input.RequestDigest) && validTokenMutation(input.TokenID, input.TokenGeneration, input.LocatorDigest, input.Salt, input.TokenHash, input.TokenExpiresAt)
}

func validIdempotentDigest(key string, digest []byte) bool {
	return len(key) >= 16 && len(key) <= 128 && workflowKeyPattern.MatchString(key) && len(digest) == sha256.Size
}

func validTokenMutation(id string, generation int64, locator, salt, hash []byte, expires time.Time) bool {
	return validProductID(id) && generation > 0 && len(locator) == sha256.Size && len(salt) == sha256.Size && len(hash) == sha256.Size && validSensorTime(expires)
}

func validSensorName(value string) bool { return printableInventoryString(value, 1, 128, false) }
func validSensorMode(value string) bool { return stringIn(value, "metadata_only", "full") }
func validSensorTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Format(time.RFC3339Nano) == value.UTC().Format(time.RFC3339Nano)
}
