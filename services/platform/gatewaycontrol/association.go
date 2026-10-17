package gatewaycontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayassociationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const AssociationAcceptPath = "/internal/v1/runtime-gateway/agent-device-associations/accept"
const associationReadySQL = `SELECT zasp_agent_device_association_v1.caller_ready('gateway-control',$1)`
const associationAcceptSQL = `SELECT zasp_agent_device_association_v1.accept_intent($1,$2,$3)`
const associationConfirmSQL = `SELECT zasp_agent_device_association_v1.confirm_device($1,$2,$3::jsonb,$4)`

// AssociationRepository is optional and authorizes only the Device acceptance
// phase. It does not activate an association or change legacy readiness.
type AssociationRepository interface {
	AssociationReady(context.Context) error
	AcceptAgentDevice(context.Context, []byte, wire.DeviceBinding) (wire.AcceptResponse, error)
}
type postgresAssociationRepository struct {
	database InstallationDatabase
	timeout  time.Duration
	pin      string
}

func NewPostgresAssociationRepository(database InstallationDatabase, timeout time.Duration, pin string) (AssociationRepository, error) {
	if nilInstallationValue(database) || timeout < 50*time.Millisecond || timeout > 10*time.Second || !migrations.IsAgentDeviceAssociationProfileChecksum(pin) {
		return nil, errPostgresRepository
	}
	return &postgresAssociationRepository{database: database, timeout: timeout, pin: pin}, nil
}

// AssociationRepositoryForProfile borrows the same registered gateway-control
// pool without granting a role or creating an identity or connection.
func (repository *PostgresRepository) AssociationRepositoryForProfile(pin string) (AssociationRepository, error) {
	if repository == nil {
		return nil, errPostgresRepository
	}
	database, ok := repository.database.(InstallationDatabase)
	if !ok {
		return nil, errPostgresRepository
	}
	return NewPostgresAssociationRepository(database, repository.timeout, pin)
}
func (repository *postgresAssociationRepository) AssociationReady(ctx context.Context) error {
	if repository == nil || nilInstallationValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	var ready bool
	if repository.database.QueryRow(operation, associationReadySQL, repository.pin).Scan(&ready) != nil || !ready || operation.Err() != nil {
		return errPostgresRepository
	}
	return nil
}
func (repository *postgresAssociationRepository) AcceptAgentDevice(ctx context.Context, raw []byte, binding wire.DeviceBinding) (wire.AcceptResponse, error) {
	if repository == nil || nilInstallationValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	return CommitProductionAgentDeviceAcceptance(operation, repository.database, raw, binding, repository.pin, time.Now().UTC().Truncate(time.Microsecond))
}

// The outer body is parsed without changing the original bytes passed to SQL.
// All allowed string alphabets are canonical ASCII. Invalid UTF16 replacement
// characters therefore fail the shared envelope/inner challenge validation.
func parseAssociationAcceptBody(raw []byte) (wire.Challenge, error) {
	if len(raw) == 0 || len(raw) > wire.MaximumBytes || !utf8.Valid(raw) {
		return wire.Challenge{}, errHTTPControl
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, e := decoder.Token()
	if e != nil || token != json.Delim('{') {
		return wire.Challenge{}, errHTTPControl
	}
	fields := make(map[string]string, 3)
	for decoder.More() {
		name, e := decoder.Token()
		key, ok := name.(string)
		if e != nil || !ok || key != "schema" && key != "challenge_wire" && key != "challenge_sha256" {
			return wire.Challenge{}, errHTTPControl
		}
		if _, exists := fields[key]; exists {
			return wire.Challenge{}, errHTTPControl
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return wire.Challenge{}, errHTTPControl
		}
		var text string
		if json.Unmarshal(value, &text) != nil {
			return wire.Challenge{}, errHTTPControl
		}
		fields[key] = text
	}
	if token, e = decoder.Token(); e != nil || token != json.Delim('}') || len(fields) != 3 || fields["schema"] != wire.AcceptSchema {
		return wire.Challenge{}, errHTTPControl
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return wire.Challenge{}, errHTTPControl
	}
	envelope := wire.ChallengeEnvelope{Schema: wire.EnvelopeSchema, ChallengeWire: fields["challenge_wire"], ChallengeSHA256: fields["challenge_sha256"]}
	return wire.ChallengeFromEnvelope(envelope)
}

// parseAssociationInternal validates this own profile wrapper without changing
// the permissive legacy decoder shared by existing routes. Confirm still gets
// the exact original JSONB bytes returned by SQL.
func parseAssociationInternal(raw []byte) (json.RawMessage, bool, error) {
	if len(raw) == 0 || len(raw) > wire.MaximumBytes+256 || !utf8.Valid(raw) {
		return nil, false, errPostgresRepository
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, e := decoder.Token()
	if e != nil || token != json.Delim('{') {
		return nil, false, errPostgresRepository
	}
	fields := make(map[string]json.RawMessage, 2)
	for decoder.More() {
		name, e := decoder.Token()
		key, ok := name.(string)
		if e != nil || !ok || key != "receipt" && key != "new_mutation" {
			return nil, false, errPostgresRepository
		}
		if _, exists := fields[key]; exists {
			return nil, false, errPostgresRepository
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, false, errPostgresRepository
		}
		fields[key] = value
	}
	if token, e = decoder.Token(); e != nil || token != json.Delim('}') || len(fields) != 2 {
		return nil, false, errPostgresRepository
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, false, errPostgresRepository
	}
	marker := bytes.TrimSpace(fields["new_mutation"])
	if !bytes.Equal(marker, []byte("true")) && !bytes.Equal(marker, []byte("false")) {
		return nil, false, errPostgresRepository
	}
	return fields["receipt"], bytes.Equal(marker, []byte("true")), nil
}

func associationChallengeMatchesBinding(challenge wire.Challenge, binding wire.DeviceBinding) bool {
	return challenge.OrganizationID == binding.OrganizationID && challenge.WorkspaceID == binding.WorkspaceID && challenge.EnvironmentID == binding.EnvironmentID && challenge.DeviceID == binding.DeviceID
}

// CommitProductionAgentDeviceAcceptance is shared by the live repository and
// application native fixtures. The own SQL functions enforce Agent-before-Device
// locking and independently reauthenticate the original current Device authority.
func CommitProductionAgentDeviceAcceptance(ctx context.Context, pool InstallationTransactionPool, raw []byte, binding wire.DeviceBinding, pin string, now time.Time) (wire.AcceptResponse, error) {
	if ctx == nil || ctx.Err() != nil || nilInstallationValue(pool) || !migrations.IsAgentDeviceAssociationProfileChecksum(pin) || now.IsZero() || now.Location() != time.UTC || !validProductID(binding.CredentialID) {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	challenge, e := parseAssociationAcceptBody(raw)
	if e != nil || !associationChallengeMatchesBinding(challenge, binding) {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	tx, e := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil || nilInstallationValue(tx) {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	defer func() {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollback)
	}()
	var internal []byte
	if tx.QueryRow(ctx, associationAcceptSQL, binding.CredentialID, raw, pin).Scan(&internal) != nil || len(internal) == 0 || len(internal) > wire.MaximumBytes+256 {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	receipt, newMutation, e := parseAssociationInternal(internal)
	if e != nil {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	response, e := wire.ParseAcceptResponse(receipt)
	if e != nil || !wire.AcceptResponseMatches(response, raw, binding, now) || !newMutation && !response.Replayed {
		return wire.AcceptResponse{}, errPostgresRepository
	}

	// Confirm the EXACT original internal wrapper and original body, not a JSON
	// reserialization or public receipt. Final native clock/gen/source/nonce fences
	// belong to confirm_device. No application query follows it before COMMIT.
	var confirmed bool
	if tx.QueryRow(ctx, associationConfirmSQL, binding.CredentialID, raw, json.RawMessage(internal), pin).Scan(&confirmed) != nil || !confirmed || ctx.Err() != nil {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return wire.AcceptResponse{}, errPostgresRepository
	}
	return response, nil
}

func (handler *httpHandler) serveAssociationAccept(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Pragma", "no-cache")
	if handler.associationRepository == nil || request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.ForceQuery || len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != JSONMediaType {
		writeError(writer, http.StatusNotFound, "not_found")
		return
	}
	operation, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	if handler.associationRepository.AssociationReady(operation) != nil || operation.Err() != nil {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if request.Body == nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(writer, request.Body, wire.MaximumBytes))
	if e != nil || len(body) == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	challenge, e := parseAssociationAcceptBody(body)
	if e != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	authority, ok := handler.authenticate(request, body)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	binding := wire.DeviceBinding{OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, CredentialID: authority.CredentialID, CredentialGeneration: authority.CredentialGeneration, PublicKey: base64.RawURLEncoding.EncodeToString(authority.PublicKey), ExpiresAt: authority.ExpiresAt}
	if !associationChallengeMatchesBinding(challenge, binding) {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	response, e := handler.associationRepository.AcceptAgentDevice(operation, body, binding)
	if e != nil || operation.Err() != nil || !wire.AcceptResponseMatches(response, body, binding, handler.clock()) {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	raw, e := wire.MarshalAcceptResponse(response)
	if e != nil || len(raw) > wire.MaximumBytes {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writer.Header().Set("Content-Type", JSONMediaType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(raw)
}
