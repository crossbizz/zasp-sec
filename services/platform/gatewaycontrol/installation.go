package gatewaycontrol

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	wire "github.com/zasp-ai/zasp-sec/services/platform/gatewayinstallationwire"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const InstallationPath = "/internal/v1/runtime-gateway/installations"
const installationRecordSQL = `SELECT zasp_gateway_installation_v1.record_installation($1,$2)`
const installationConfirmSQL = `SELECT zasp_gateway_installation_v1.confirm_receipt($1,$2,$3::jsonb)`
const installationReadySQL = `SELECT zasp_gateway_installation_v1.caller_ready('gateway-control',$1)`

// InstallationRepository is optional and does not change the original control repository.
type InstallationRepository interface {
	InstallationReady(context.Context) error
	RecordInstallation(context.Context, string, []byte) (wire.Receipt, error)
}

// InstallationTransactionPool borrows transactions from the original registered
// gateway-control pool. It cannot select roles or create or close a pool.
type InstallationTransactionPool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}
type InstallationDatabase interface {
	PostgresDatabase
	InstallationTransactionPool
}
type postgresInstallationRepository struct {
	database InstallationDatabase
	timeout  time.Duration
	pin      string
}

func nilInstallationValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func NewPostgresInstallationRepository(database InstallationDatabase, timeout time.Duration, pin string) (InstallationRepository, error) {
	if nilInstallationValue(database) || timeout < 50*time.Millisecond || timeout > 10*time.Second || !migrations.IsGatewayInstallationProfileChecksum(pin) {
		return nil, errPostgresRepository
	}
	return &postgresInstallationRepository{database: database, timeout: timeout, pin: pin}, nil
}

// InstallationRepositoryForProfile creates an isolated optional capability from
// the existing pool. Original readiness and original repository state are unchanged.
func (repository *PostgresRepository) InstallationRepositoryForProfile(pin string) (InstallationRepository, error) {
	if repository == nil {
		return nil, errPostgresRepository
	}
	database, ok := repository.database.(InstallationDatabase)
	if !ok {
		return nil, errPostgresRepository
	}
	return NewPostgresInstallationRepository(database, repository.timeout, pin)
}
func (repository *postgresInstallationRepository) InstallationReady(ctx context.Context) error {
	if repository == nil || nilInstallationValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	var ready bool
	if repository.database.QueryRow(operation, installationReadySQL, repository.pin).Scan(&ready) != nil || !ready || operation.Err() != nil {
		return errPostgresRepository
	}
	return nil
}
func (repository *postgresInstallationRepository) RecordInstallation(ctx context.Context, credentialID string, raw []byte) (wire.Receipt, error) {
	if repository == nil || nilInstallationValue(repository.database) || ctx == nil || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	operation, cancel := context.WithTimeout(ctx, repository.timeout)
	defer cancel()
	return CommitProductionGatewayInstallation(operation, repository.database, credentialID, raw)
}

func (client *HTTPClient) RecordInstallation(ctx context.Context, credentialID string, raw []byte) (wire.Receipt, error) {
	if !validClientCall(client, ctx, credentialID) {
		return wire.Receipt{}, errHTTPControl
	}
	observation, e := wire.ParseObservation(raw)
	if e != nil {
		return wire.Receipt{}, errHTTPControl
	}
	response, e := client.do(ctx, http.MethodPost, InstallationPath, raw, JSONMediaType)
	if e != nil {
		return wire.Receipt{}, errHTTPControl
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != JSONMediaType || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return wire.Receipt{}, errHTTPControl
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, wire.MaximumBytes+1))
	if e != nil || len(body) > wire.MaximumBytes {
		return wire.Receipt{}, errHTTPControl
	}
	receipt, e := wire.ParseReceipt(body)
	binding := wire.Binding{OrganizationID: client.organizationID, WorkspaceID: client.workspaceID, EnvironmentID: client.environmentID, DeviceID: client.deviceID, CredentialID: credentialID}
	if e != nil || !wire.ReceiptMatches(receipt, observation, wire.Digest(raw), binding) {
		return wire.Receipt{}, errHTTPControl
	}
	return receipt, nil
}

// CommitProductionGatewayInstallation is the sole production record-confirm-
// commit boundary, shared by the live repository and application native fixtures.
// A receipt is never returned for an unknown commit outcome.
func CommitProductionGatewayInstallation(ctx context.Context, pool InstallationTransactionPool, credentialID string, raw []byte) (wire.Receipt, error) {
	if ctx == nil || ctx.Err() != nil || nilInstallationValue(pool) || !validProductID(credentialID) {
		return wire.Receipt{}, errPostgresRepository
	}
	observation, e := wire.ParseObservation(raw)
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
	var recorded []byte
	if tx.QueryRow(ctx, installationRecordSQL, credentialID, raw).Scan(&recorded) != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	receipt, e := wire.ParseReceipt(recorded)
	// Scope originates in the current SQL credential authority. The HTTP boundary
	// additionally checks it against the authenticated request authority.
	binding := wire.Binding{OrganizationID: receipt.OrganizationID, WorkspaceID: receipt.WorkspaceID, EnvironmentID: receipt.EnvironmentID, DeviceID: receipt.DeviceID, CredentialID: credentialID}
	if e != nil || !wire.ReceiptMatches(receipt, observation, wire.Digest(raw), binding) {
		return wire.Receipt{}, errPostgresRepository
	}
	var confirmed bool
	if tx.QueryRow(ctx, installationConfirmSQL, credentialID, raw, json.RawMessage(recorded)).Scan(&confirmed) != nil || !confirmed || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return wire.Receipt{}, errPostgresRepository
	}
	return receipt, nil
}

func (handler *httpHandler) writeInstallation(ctx context.Context, writer http.ResponseWriter, body []byte, authority Authority) {
	observation, e := wire.ParseObservation(body)
	if e != nil || observation.CredentialGeneration != authority.CredentialGeneration {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	receipt, e := handler.installationRepository.RecordInstallation(ctx, authority.CredentialID, body)
	binding := wire.Binding{OrganizationID: authority.OrganizationID, WorkspaceID: authority.WorkspaceID, EnvironmentID: authority.EnvironmentID, DeviceID: authority.DeviceID, CredentialID: authority.CredentialID}
	if e != nil || ctx.Err() != nil || !wire.ReceiptMatches(receipt, observation, wire.Digest(body), binding) {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	raw, e := wire.MarshalReceipt(receipt)
	if e != nil || len(raw) > wire.MaximumBytes {
		writeError(writer, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	writer.Header().Set("Content-Type", JSONMediaType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(raw)
}
