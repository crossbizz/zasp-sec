package gatewaycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

var errPostgresRepository = errors.New("gateway control repository unavailable")

const (
	postgresReadySQL     = `SELECT zasp_runtime_data_plane_readiness($1,$2) AND zasp_runtime_principal_ready('zasp_gateway_control')`
	postgresAuthoritySQL = `SELECT zasp_runtime_gateway_credential_authority($1,'runtime-gateway')`
	postgresPolicySQL    = `SELECT zasp_runtime_gateway_policy_bundle($1,$2)`
	postgresRecordSQL    = `SELECT zasp_runtime_gateway_record_event(
 $1,$2,$3,$4,
 digest(convert_to(jsonb_build_object(
  'credential_id',$1::text,'device_id',$5::text,'event_id',$2::text,
  'expected_floor',$3::bigint,'next_floor',$4::bigint,'policy_version',$6::bigint,
  'decision',$7::text,'action_kind',$8::text,'classification',$9::jsonb,
  'occurred_at',to_char($10::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
 )::text,'UTF8'),'sha256'),
 $6,$7,$8,$9::jsonb,$10
)`
)

type PostgresDatabase interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresRepository struct {
	database PostgresDatabase
	timeout  time.Duration
}

func NewPostgresRepository(database PostgresDatabase, timeout time.Duration) (*PostgresRepository, error) {
	if database == nil || timeout < 50*time.Millisecond || timeout > 10*time.Second {
		return nil, errPostgresRepository
	}
	return &PostgresRepository{database: database, timeout: timeout}, nil
}

func (repository *PostgresRepository) Ready(ctx context.Context) error {
	if repository == nil || repository.database == nil || ctx == nil || ctx.Err() != nil {
		return errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	metadata := migrations.ProductionRuntimeDataPlane()
	var ready bool
	if err := repository.database.QueryRow(operation, postgresReadySQL, metadata.Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()).Scan(&ready); err != nil || !ready || operation.Err() != nil {
		return errPostgresRepository
	}
	return nil
}

func (repository *PostgresRepository) Authority(ctx context.Context, credentialID string) (Authority, error) {
	if repository == nil || repository.database == nil || ctx == nil || ctx.Err() != nil || !validProductID(credentialID) {
		return Authority{}, errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	var raw json.RawMessage
	if err := repository.database.QueryRow(operation, postgresAuthoritySQL, credentialID).Scan(&raw); err != nil || operation.Err() != nil {
		return Authority{}, errPostgresRepository
	}
	return decodePostgresAuthority(raw, credentialID)
}

func (repository *PostgresRepository) Policy(ctx context.Context, credentialID string, after uint64) (*policy.GatewayPolicyEnvelope, error) {
	if repository == nil || repository.database == nil || ctx == nil || ctx.Err() != nil || !validProductID(credentialID) || after > uint64(^uint64(0)>>1) {
		return nil, errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	var raw json.RawMessage
	if err := repository.database.QueryRow(operation, postgresPolicySQL, credentialID, after).Scan(&raw); err != nil || operation.Err() != nil {
		return nil, errPostgresRepository
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	envelope, err := decodePostgresPolicy(raw, credentialID)
	if err != nil {
		return nil, err
	}
	return &envelope, nil
}

func (repository *PostgresRepository) Record(ctx context.Context, event DecisionEvent) error {
	if repository == nil || repository.database == nil || ctx == nil || ctx.Err() != nil || !validDecisionEvent(event) {
		return errPostgresRepository
	}
	classification, err := json.Marshal(event.Classification)
	if err != nil {
		return errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	var raw json.RawMessage
	if err := repository.database.QueryRow(operation, postgresRecordSQL,
		event.CredentialID, event.EventID, event.ExpectedFloor, event.NextFloor, event.DeviceID,
		event.PolicyVersion, event.Decision, event.ActionKind, json.RawMessage(classification), event.OccurredAt,
	).Scan(&raw); err != nil || operation.Err() != nil {
		return errPostgresRepository
	}
	var receipt struct {
		EventID    string    `json:"event_id"`
		DeviceID   string    `json:"device_id"`
		Sequence   uint64    `json:"sequence"`
		RecordedAt time.Time `json:"recorded_at"`
		Replayed   bool      `json:"replayed"`
	}
	if strictJSON(raw, &receipt) != nil || receipt.EventID != event.EventID || receipt.DeviceID != event.DeviceID || receipt.Sequence != event.NextFloor || receipt.RecordedAt.IsZero() {
		return errPostgresRepository
	}
	return nil
}

type postgresPolicyPayload struct {
	ContractVersion int                     `json:"contract_version"`
	KeyID           string                  `json:"key_id"`
	Algorithm       string                  `json:"algorithm"`
	Audience        string                  `json:"audience"`
	OrganizationID  string                  `json:"organization_id"`
	WorkspaceID     string                  `json:"workspace_id"`
	EnvironmentID   string                  `json:"environment_id"`
	DeviceID        string                  `json:"device_id"`
	CredentialID    string                  `json:"credential_id"`
	Sequence        uint64                  `json:"sequence"`
	PolicyVersion   uint64                  `json:"policy_version"`
	IssuedAt        time.Time               `json:"issued_at"`
	ExpiresAt       time.Time               `json:"expires_at"`
	FailureMode     string                  `json:"failure_mode"`
	PayloadDigest   string                  `json:"payload_digest"`
	Policies        []policy.CompiledPolicy `json:"policies"`
	Signature       string                  `json:"signature"`
}

func decodePostgresAuthority(raw json.RawMessage, credentialID string) (Authority, error) {
	var payload authorityPayload
	if strictJSON(raw, &payload) != nil {
		return Authority{}, errPostgresRepository
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != payload.PublicKey {
		return Authority{}, errPostgresRepository
	}
	authority := Authority{
		OrganizationID: payload.OrganizationID, WorkspaceID: payload.WorkspaceID, EnvironmentID: payload.EnvironmentID,
		DeviceID: payload.DeviceID, DeviceVersion: payload.DeviceVersion, ReplayFloor: payload.ReplayFloor,
		CredentialID: payload.CredentialID, CredentialGeneration: payload.CredentialGeneration, KeyID: payload.KeyID,
		Algorithm: payload.Algorithm, PublicKey: ed25519.PublicKey(publicKey), Audience: payload.Audience, ExpiresAt: payload.ExpiresAt,
	}
	if !validAuthority(authority, credentialID, time.Time{}) {
		return Authority{}, errPostgresRepository
	}
	return cloneAuthority(authority), nil
}

func decodePostgresPolicy(raw json.RawMessage, credentialID string) (policy.GatewayPolicyEnvelope, error) {
	var payload postgresPolicyPayload
	if strictJSON(raw, &payload) != nil || payload.CredentialID != credentialID {
		return policy.GatewayPolicyEnvelope{}, errPostgresRepository
	}
	return policy.GatewayPolicyEnvelope{
		ContractVersion: payload.ContractVersion, KeyID: payload.KeyID, Algorithm: payload.Algorithm, Audience: payload.Audience,
		OrganizationID: payload.OrganizationID, WorkspaceID: payload.WorkspaceID, EnvironmentID: payload.EnvironmentID, DeviceID: payload.DeviceID,
		Sequence: payload.Sequence, PolicyVersion: payload.PolicyVersion, IssuedAt: payload.IssuedAt, ExpiresAt: payload.ExpiresAt,
		FailureMode: payload.FailureMode, PayloadDigest: payload.PayloadDigest, Policies: payload.Policies, Signature: payload.Signature,
	}, nil
}

var _ Repository = (*PostgresRepository)(nil)
