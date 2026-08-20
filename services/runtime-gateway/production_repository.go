package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

var errGatewayRepository = errors.New("gateway repository unavailable")

var gatewayRepositoryKeyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{7,63}$`)

const (
	gatewayRepositoryReadySQL     = `SELECT zasp_runtime_data_plane_readiness($1,$2) AND zasp_runtime_principal_ready('zasp_gateway_control')`
	gatewayRepositoryAuthoritySQL = `SELECT zasp_runtime_gateway_credential_authority($1,'runtime-gateway')`
	gatewayRepositoryPolicySQL    = `SELECT zasp_runtime_gateway_policy_bundle($1,$2)`
	gatewayRepositoryRecordSQL    = `SELECT zasp_runtime_gateway_record_event(
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

type gatewayDatabaseRow interface {
	Scan(...any) error
}

type gatewayDatabase interface {
	QueryRow(context.Context, string, ...any) gatewayDatabaseRow
}

type gatewayPostgresControl struct {
	database gatewayDatabase
	timeout  time.Duration
}

func newGatewayPostgresControl(database gatewayDatabase, timeout time.Duration) (*gatewayPostgresControl, error) {
	if database == nil || timeout < 50*time.Millisecond || timeout > 10*time.Second {
		return nil, errGatewayRepository
	}
	return &gatewayPostgresControl{database: database, timeout: timeout}, nil
}

func (control *gatewayPostgresControl) Ready(ctx context.Context) error {
	if control == nil || control.database == nil || ctx == nil || ctx.Err() != nil {
		return errGatewayRepository
	}
	operation, cancel := context.WithTimeout(ctx, control.timeout)
	defer cancel()
	metadata := migrations.ProductionRuntimeDataPlane()
	var ready bool
	if err := control.database.QueryRow(operation, gatewayRepositoryReadySQL, metadata.Checksum(), migrations.ProductionRuntimeDataPlaneSemanticFingerprint()).Scan(&ready); err != nil || !ready || operation.Err() != nil {
		return errGatewayRepository
	}
	return nil
}

func (control *gatewayPostgresControl) Authority(ctx context.Context, credentialID string) (gatewayAuthority, error) {
	if control == nil || control.database == nil || ctx == nil || ctx.Err() != nil || !validGatewayProductID(credentialID) {
		return gatewayAuthority{}, errGatewayRepository
	}
	operation, cancel := context.WithTimeout(ctx, control.timeout)
	defer cancel()
	var raw json.RawMessage
	if err := control.database.QueryRow(operation, gatewayRepositoryAuthoritySQL, credentialID).Scan(&raw); err != nil || operation.Err() != nil {
		return gatewayAuthority{}, errGatewayRepository
	}
	decoded, err := decodeGatewayAuthority(raw, credentialID)
	if err != nil {
		return gatewayAuthority{}, err
	}
	return decoded, nil
}

func (control *gatewayPostgresControl) Policy(ctx context.Context, credentialID string, afterSequence uint64) (*policy.GatewayPolicyEnvelope, error) {
	if control == nil || control.database == nil || ctx == nil || ctx.Err() != nil || !validGatewayProductID(credentialID) || afterSequence > uint64(^uint64(0)>>1) {
		return nil, errGatewayRepository
	}
	operation, cancel := context.WithTimeout(ctx, control.timeout)
	defer cancel()
	var raw json.RawMessage
	if err := control.database.QueryRow(operation, gatewayRepositoryPolicySQL, credentialID, afterSequence).Scan(&raw); err != nil || operation.Err() != nil {
		return nil, errGatewayRepository
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	envelope, err := decodeGatewayPolicy(raw, credentialID)
	if err != nil {
		return nil, err
	}
	return &envelope, nil
}

func (control *gatewayPostgresControl) Record(ctx context.Context, event gatewayDecisionEvent) error {
	if control == nil || control.database == nil || ctx == nil || ctx.Err() != nil || !validGatewayDecisionEvent(event) {
		return errGatewayRepository
	}
	classification, err := json.Marshal(event.Classification)
	if err != nil {
		return errGatewayRepository
	}
	operation, cancel := context.WithTimeout(ctx, control.timeout)
	defer cancel()
	var raw json.RawMessage
	if err := control.database.QueryRow(operation, gatewayRepositoryRecordSQL,
		event.CredentialID, event.EventID, event.ExpectedFloor, event.NextFloor, event.DeviceID,
		event.PolicyVersion, event.Decision, event.ActionKind, json.RawMessage(classification), event.OccurredAt,
	).Scan(&raw); err != nil || operation.Err() != nil {
		return errGatewayRepository
	}
	var receipt struct {
		EventID    string    `json:"event_id"`
		DeviceID   string    `json:"device_id"`
		Sequence   uint64    `json:"sequence"`
		RecordedAt time.Time `json:"recorded_at"`
		Replayed   bool      `json:"replayed"`
	}
	if strictGatewayJSON(raw, &receipt) != nil || receipt.EventID != event.EventID || receipt.DeviceID != event.DeviceID || receipt.Sequence != event.NextFloor || receipt.RecordedAt.IsZero() {
		return errGatewayRepository
	}
	return nil
}

type gatewayAuthorityPayload struct {
	OrganizationID       string    `json:"organization_id"`
	WorkspaceID          string    `json:"workspace_id"`
	EnvironmentID        string    `json:"environment_id"`
	DeviceID             string    `json:"device_id"`
	DeviceVersion        uint64    `json:"device_version"`
	ReplayFloor          uint64    `json:"replay_floor"`
	CredentialID         string    `json:"credential_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	PublicKey            string    `json:"public_key"`
	Audience             string    `json:"audience"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func decodeGatewayAuthority(raw json.RawMessage, credentialID string) (gatewayAuthority, error) {
	var payload gatewayAuthorityPayload
	if strictGatewayJSON(raw, &payload) != nil || payload.DeviceVersion < 1 || payload.CredentialGeneration < 1 ||
		payload.Algorithm != "Ed25519" || payload.Audience != "runtime-gateway" || !gatewayRepositoryKeyIDPattern.MatchString(payload.KeyID) ||
		payload.CredentialID != credentialID || payload.ExpiresAt.IsZero() {
		return gatewayAuthority{}, errGatewayRepository
	}
	key, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != payload.PublicKey {
		return gatewayAuthority{}, errGatewayRepository
	}
	authority := gatewayAuthority{OrganizationID: payload.OrganizationID, WorkspaceID: payload.WorkspaceID, EnvironmentID: payload.EnvironmentID, DeviceID: payload.DeviceID, CredentialID: payload.CredentialID, ReplayFloor: payload.ReplayFloor}
	if !validGatewayAuthority(authority, credentialID) {
		return gatewayAuthority{}, errGatewayRepository
	}
	return authority, nil
}

type gatewayPolicyPayload struct {
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

func decodeGatewayPolicy(raw json.RawMessage, credentialID string) (policy.GatewayPolicyEnvelope, error) {
	var payload gatewayPolicyPayload
	if strictGatewayJSON(raw, &payload) != nil || payload.CredentialID != credentialID {
		return policy.GatewayPolicyEnvelope{}, errGatewayRepository
	}
	return policy.GatewayPolicyEnvelope{
		ContractVersion: payload.ContractVersion,
		KeyID:           payload.KeyID,
		Algorithm:       payload.Algorithm,
		Audience:        payload.Audience,
		OrganizationID:  payload.OrganizationID,
		WorkspaceID:     payload.WorkspaceID,
		EnvironmentID:   payload.EnvironmentID,
		DeviceID:        payload.DeviceID,
		Sequence:        payload.Sequence,
		PolicyVersion:   payload.PolicyVersion,
		IssuedAt:        payload.IssuedAt,
		ExpiresAt:       payload.ExpiresAt,
		FailureMode:     payload.FailureMode,
		PayloadDigest:   payload.PayloadDigest,
		Policies:        payload.Policies,
		Signature:       payload.Signature,
	}, nil
}

func validGatewayDecisionEvent(event gatewayDecisionEvent) bool {
	return validGatewayProductID(event.CredentialID) && validGatewayProductID(event.DeviceID) && validGatewayProductID(event.EventID) &&
		event.NextFloor == event.ExpectedFloor+1 && event.PolicyVersion > 0 &&
		(event.Decision == "allow" || event.Decision == "monitor" || event.Decision == "block") &&
		(event.ActionKind == "http" || event.ActionKind == "mcp") && validGatewayClassification(event.Classification) && validGatewayTime(event.OccurredAt)
}

func strictGatewayJSON(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > 1024*1024 || destination == nil {
		return errGatewayRepository
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errGatewayRepository
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errGatewayRepository
	}
	return nil
}
