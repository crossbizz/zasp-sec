package gatewaycontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayenrollmentwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

var ErrEnrollmentAuthentication = errors.New("gateway enrollment authentication rejected")

func enrollmentQueryError(err error) error {
	var server *pgconn.PgError
	if errors.As(err, &server) && server.Code == "28000" {
		return ErrEnrollmentAuthentication
	}
	return errPostgresRepository
}

const EnrollmentPath = "/internal/v1/runtime-gateway/enrollments"
const enrollmentAuthenticateSQL = `SELECT public.zasp_runtime_authenticate_gateway_enrollment($1,$2,'runtime-gateway-enroll')`
const enrollmentEnrollSQL = `SELECT public.zasp_runtime_gateway_enroll($1,$2,'runtime-gateway-enroll',$3,$4,$5,'Ed25519',$6,$7)`
const enrollmentCredentialSQL = `SELECT public.zasp_runtime_gateway_credential_authority($1,'runtime-gateway')`
const enrollmentClockSQL = `SELECT clock_timestamp()`
const enrollmentFinalFenceSQL = `SELECT zasp_gateway_bootstrap_v1.enrollment_final_fence($1,$2,$3,$4::jsonb,$5)`
const enrollmentReadySQL = `SELECT zasp_gateway_bootstrap_v1.caller_ready('gateway-control',$1)`

// EnrollmentRepository is an isolated optional bootstrap capability. It is not
// embedded in the original repository interface or its global readiness check.
type EnrollmentRepository interface {
	EnrollmentReady(context.Context) error
	EnrollGateway(context.Context, []byte, []byte, []byte) (wire.Receipt, error)
}
type postgresEnrollmentRepository struct {
	database InstallationDatabase
	timeout  time.Duration
	pin      string
}

func NewPostgresEnrollmentRepository(database InstallationDatabase, timeout time.Duration, pin string) (EnrollmentRepository, error) {
	if nilInstallationValue(database) || timeout < 50*time.Millisecond || timeout > 10*time.Second || !migrations.IsGatewayBootstrapProfileChecksum(pin) {
		return nil, errPostgresRepository
	}
	return &postgresEnrollmentRepository{database: database, timeout: timeout, pin: pin}, nil
}

// EnrollmentRepositoryForProfile borrows the same original registered pool;
// it does not select roles, create identities, or change legacy readiness.
func (repository *PostgresRepository) EnrollmentRepositoryForProfile(pin string) (EnrollmentRepository, error) {
	if repository == nil {
		return nil, errPostgresRepository
	}
	database, ok := repository.database.(InstallationDatabase)
	if !ok {
		return nil, errPostgresRepository
	}
	return NewPostgresEnrollmentRepository(database, repository.timeout, pin)
}
func (repository *postgresEnrollmentRepository) EnrollmentReady(ctx context.Context) error {
	if repository == nil || nilInstallationValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	var ready bool
	if repository.database.QueryRow(operation, enrollmentReadySQL, repository.pin).Scan(&ready) != nil || !ready || operation.Err() != nil {
		return errPostgresRepository
	}
	return nil
}
func (repository *postgresEnrollmentRepository) EnrollGateway(ctx context.Context, locator, secret, raw []byte) (wire.Receipt, error) {
	if repository == nil || nilInstallationValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	return CommitProductionGatewayEnrollment(operation, repository.database, locator, secret, raw, repository.pin)
}

type enrollmentAuthority struct {
	OrganizationID  string `json:"organization_id"`
	WorkspaceID     string `json:"workspace_id"`
	EnvironmentID   string `json:"environment_id"`
	DeviceID        string `json:"device_id"`
	DeviceVersion   uint64 `json:"device_version"`
	EnrollmentID    string `json:"enrollment_id"`
	TokenGeneration uint64 `json:"token_generation"`
	Consumed        bool   `json:"consumed"`
	Audience        string `json:"audience"`
}
type enrollmentNativeReceipt struct {
	ID                   string    `json:"id"`
	DeviceID             string    `json:"device_id"`
	CredentialGeneration uint64    `json:"credential_generation"`
	KeyID                string    `json:"key_id"`
	Algorithm            string    `json:"algorithm"`
	Audience             string    `json:"audience"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	Replayed             bool      `json:"replayed"`
}

// Native responses originate as JSONB, which has unique object keys. Require
// every expected non-null field as well as the typed closed shape.
func decodeEnrollmentNative(raw []byte, destination any, keys ...string) bool {
	var object map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &object) != nil || len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		value, ok := object[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return strictJSON(raw, destination) == nil
}
func enrollmentAuthorityMatches(raw []byte, request wire.Request, consumed bool) (enrollmentAuthority, bool) {
	var authority enrollmentAuthority
	if !decodeEnrollmentNative(raw, &authority, "organization_id", "workspace_id", "environment_id", "device_id", "device_version", "enrollment_id", "token_generation", "consumed", "audience") {
		return authority, false
	}
	return authority, authority.OrganizationID == request.OrganizationID && authority.WorkspaceID == request.WorkspaceID && authority.EnvironmentID == request.EnvironmentID && authority.DeviceID == request.DeviceID && authority.EnrollmentID == request.EnrollmentID && authority.TokenGeneration == request.TokenGeneration && authority.DeviceVersion > 0 && authority.DeviceVersion <= uint64(^uint64(0)>>1) && authority.Audience == "runtime-gateway-enroll" && (!consumed || authority.Consumed)
}

// CommitProductionGatewayEnrollment is the shared live/native-application
// transaction boundary. Original15/current80 authenticate/enroll and role
// helpers remain authoritative; an unknown commit never yields a receipt.
func CommitProductionGatewayEnrollment(ctx context.Context, pool InstallationTransactionPool, locator, secret, raw []byte, pin string) (wire.Receipt, error) {
	if ctx == nil || ctx.Err() != nil || nilInstallationValue(pool) || len(locator) != 16 || len(secret) != 32 || !migrations.IsGatewayBootstrapProfileChecksum(pin) {
		return wire.Receipt{}, errPostgresRepository
	}
	request, e := wire.ParseRequest(raw)
	if e != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	publicKey, e := base64.RawURLEncoding.DecodeString(request.PublicKey)
	if e != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	tx, e := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil || nilInstallationValue(tx) {
		return wire.Receipt{}, errPostgresRepository
	}
	defer func() {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(rollback)
	}()
	var authenticated []byte
	if e := tx.QueryRow(ctx, enrollmentAuthenticateSQL, locator, secret).Scan(&authenticated); e != nil {
		return wire.Receipt{}, enrollmentQueryError(e)
	}
	initial, ok := enrollmentAuthorityMatches(authenticated, request, false)
	if !ok {
		return wire.Receipt{}, ErrEnrollmentAuthentication
	}
	var enrolled []byte
	if tx.QueryRow(ctx, enrollmentEnrollSQL, locator, secret, request.CredentialID, request.CredentialGeneration, request.KeyID, publicKey, request.ExpiresAt).Scan(&enrolled) != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	var native enrollmentNativeReceipt
	if !decodeEnrollmentNative(enrolled, &native, "id", "device_id", "credential_generation", "key_id", "algorithm", "audience", "issued_at", "expires_at", "replayed") || native.ID != request.CredentialID || native.DeviceID != request.DeviceID || native.CredentialGeneration != request.CredentialGeneration || native.KeyID != request.KeyID || native.Algorithm != "Ed25519" || native.Audience != GatewayAudience || !native.ExpiresAt.Equal(request.ExpiresAt) || native.IssuedAt.IsZero() || native.IssuedAt.Nanosecond()%1000 != 0 {
		return wire.Receipt{}, errPostgresRepository
	}
	// The current80 enrollment authenticator rechecks current token generation,
	// revocation and wall-clock expiry after original organization/device waits.
	var reauthenticated []byte
	if e := tx.QueryRow(ctx, enrollmentAuthenticateSQL, locator, secret).Scan(&reauthenticated); e != nil {
		return wire.Receipt{}, enrollmentQueryError(e)
	}
	final, ok := enrollmentAuthorityMatches(reauthenticated, request, true)
	if !ok || final.DeviceVersion < initial.DeviceVersion {
		return wire.Receipt{}, ErrEnrollmentAuthentication
	}
	var currentRaw []byte
	if tx.QueryRow(ctx, enrollmentCredentialSQL, request.CredentialID).Scan(&currentRaw) != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	authority, e := decodePostgresAuthority(currentRaw, request.CredentialID)
	if e != nil || authority.OrganizationID != request.OrganizationID || authority.WorkspaceID != request.WorkspaceID || authority.EnvironmentID != request.EnvironmentID || authority.DeviceID != request.DeviceID || authority.DeviceVersion != final.DeviceVersion || authority.CredentialGeneration != request.CredentialGeneration || authority.KeyID != request.KeyID || !bytes.Equal(authority.PublicKey, publicKey) || !authority.ExpiresAt.Equal(request.ExpiresAt) {
		return wire.Receipt{}, errPostgresRepository
	}
	// Original15 requested credential expiry uses transaction_timestamp. This
	// early credential check is followed by the own profile final fence below,
	// which checks BOTH native token and credential expiry after all queries.
	var now time.Time
	if tx.QueryRow(ctx, enrollmentClockSQL).Scan(&now) != nil || now.IsZero() || !authority.ExpiresAt.After(now) || native.IssuedAt.After(now) || !native.ExpiresAt.After(native.IssuedAt) || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	receipt := wire.Receipt{Schema: wire.ReceiptSchema, RequestSHA256: wire.Digest(raw), OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID, EnvironmentID: request.EnvironmentID, DeviceID: request.DeviceID, EnrollmentID: request.EnrollmentID, TokenGeneration: request.TokenGeneration, CredentialID: request.CredentialID, CredentialGeneration: request.CredentialGeneration, KeyID: request.KeyID, Algorithm: request.Algorithm, PublicKey: request.PublicKey, Audience: GatewayAudience, IssuedAt: native.IssuedAt.UTC(), ExpiresAt: native.ExpiresAt.UTC(), Replayed: native.Replayed}
	if !wire.ReceiptMatches(receipt, request, wire.Digest(raw)) {
		return wire.Receipt{}, errPostgresRepository
	}
	// Strict wire binds the exact original request digest in Go; SQL independently
	// authenticates native authority and checks actual native token expiry, which
	// the original enrollment authority DTO does not expose. No query follows it.
	expected, e := wire.MarshalReceipt(receipt)
	if e != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	var fenced bool
	if tx.QueryRow(ctx, enrollmentFinalFenceSQL, locator, secret, request.CredentialID, json.RawMessage(expected), pin).Scan(&fenced) != nil || !fenced || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	return receipt, nil
}

func (handler *httpHandler) serveEnrollment(writer http.ResponseWriter, request *http.Request) {
	if handler.enrollmentRepository == nil || request.Method != http.MethodPost || request.URL.RawQuery != "" || len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != JSONMediaType {
		writeError(writer, http.StatusNotFound, "not_found")
		return
	}
	operation, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	if handler.enrollmentRepository.EnrollmentReady(operation) != nil || operation.Err() != nil {
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
	intent, e := wire.ParseRequest(body)
	if e != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if hasForbiddenScopeHeader(request.Header) || wire.VerifyRequest(request, body, handler.clock()) != nil || len(request.Header.Values(AuthorizationHeader)) != 1 {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	header := request.Header.Get(AuthorizationHeader)
	prefix := wire.AuthorizationScheme + " "
	if !strings.HasPrefix(header, prefix) {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	parts := strings.Split(strings.TrimPrefix(header, prefix), ".")
	if len(parts) != 2 {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	locator, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || len(locator) != 16 || base64.RawURLEncoding.EncodeToString(locator) != parts[0] {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	defer clear(locator)
	secret, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[1] {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	defer clear(secret)
	receipt, e := handler.enrollmentRepository.EnrollGateway(operation, locator, secret, body)
	if errors.Is(e, ErrEnrollmentAuthentication) && operation.Err() == nil {
		writeError(writer, http.StatusUnauthorized, "authentication_rejected")
		return
	}
	if e != nil || operation.Err() != nil || !wire.ReceiptMatches(receipt, intent, wire.Digest(body)) {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	response, e := wire.MarshalReceipt(receipt)
	if e != nil || len(response) > wire.MaximumBytes {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writer.Header().Set("Content-Type", JSONMediaType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response)
}
