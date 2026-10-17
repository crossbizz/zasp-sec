package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const gatewayBootstrapCreateSQL = `SELECT zasp_gateway_bootstrap_v1.create_device($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const gatewayBootstrapIssueSQL = `SELECT zasp_gateway_bootstrap_v1.issue_enrollment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
const gatewayBootstrapRevokeSQL = `SELECT zasp_gateway_bootstrap_v1.revoke_enrollment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
const gatewayBootstrapGetSQL = `SELECT zasp_gateway_bootstrap_v1.get_device($1,$2,$3,$4,$5)`
const gatewayBootstrapPrepareSQL = `SELECT zasp_gateway_bootstrap_v1.prepare_issue($1,$2,$3,$4,$5,$6,$7,$8,$9)`
const gatewayBootstrapConfirmSQL = `SELECT zasp_gateway_bootstrap_v1.confirm_public($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`

type GatewayBootstrapRepository struct {
	database JSONDatabase
	pin      string
}
type gatewayBootstrapSecretKey struct{}
type gatewayBootstrapSecretMaterial struct {
	secret       []byte
	enrollmentID string
}

func (r *PostgresRepository) RequireGatewayBootstrapProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsGatewayBootstrapProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.gatewayBootstrapProfileChecksum = pin
	return nil
}
func NewGatewayBootstrapRepository(db JSONDatabase, pin string) (*GatewayBootstrapRepository, error) {
	if nilInterface(db) || !migrations.IsGatewayBootstrapProfileChecksum(pin) {
		return nil, ErrRepositoryConfiguration
	}
	if _, ok := db.(*PostgresJSONDatabase); !ok {
		return nil, ErrRepositoryConfiguration
	}
	return &GatewayBootstrapRepository{db, pin}, nil
}
func (r *GatewayBootstrapRepository) GetGateway(ctx context.Context, s domain.Scope, id string) (GatewayBootstrapStatus, error) {
	var result GatewayBootstrapStatus
	if r == nil || s.Validate() != nil || !validProductID(id) {
		return result, ErrRepositoryOperation
	}
	args := []any{s.OrganizationID().String(), s.WorkspaceID().String(), s.EnvironmentID().String(), id, r.pin}
	g, ok := requestAuthorizationFromContext(ctx)
	if !ok || !gatewayBootstrapStatementAllowed(g, gatewayBootstrapGetSQL, args) {
		return result, ErrAuthorizationDenied
	}
	raw, e := r.database.QueryJSON(ctx, gatewayBootstrapGetSQL, args...)
	if e != nil {
		return result, discoveryProviderError(e)
	}
	if decodeGatewayBootstrapJSON(raw, &result) != nil || result.Device.ID != id || !validGatewayBootstrapDevice(result.Device) || result.NextCredentialGeneration < 1 || !stringIn(result.IssuanceState, "available", "existing_enrollment", "existing_credential", "device_unavailable") || result.LatestEnrollment != nil && !validGatewayBootstrapEnrollment(*result.LatestEnrollment, id) {
		return result, ErrRepositoryUnavailable
	}
	return result, nil
}
func (r *GatewayBootstrapRepository) MutateGateway(ctx context.Context, identity RequestIdentity, op string, in GatewayBootstrapMutation) (GatewayBootstrapMutationResult, error) {
	var result GatewayBootstrapMutationResult
	if r == nil || !validRequestIdentity(identity, false) {
		return result, ErrRepositoryOperation
	}
	args := []any{identity.Scope.OrganizationID().String(), identity.Scope.WorkspaceID().String(), identity.Scope.EnvironmentID().String(), identity.PrincipalID.String(), in.IdempotencyKey, in.RequestDigest, in.DeviceID}
	query := ""
	switch op {
	case "createGatewayDevice":
		query = gatewayBootstrapCreateSQL
		args = append(args, in.DeviceName, r.pin)
	case "issueGatewayEnrollment":
		query = gatewayBootstrapIssueSQL
		args = append(args, in.ExpectedVersion, in.EnrollmentID, in.LocatorDigest, in.Salt, []byte(nil), in.ExpiresAt, r.pin)
		if len(in.EnrollmentSecret) != 32 {
			return result, ErrRepositoryOperation
		}
		ctx = context.WithValue(ctx, gatewayBootstrapSecretKey{}, gatewayBootstrapSecretMaterial{in.EnrollmentSecret, in.EnrollmentID})
	case "revokeGatewayEnrollment":
		query = gatewayBootstrapRevokeSQL
		args = append(args, in.ExpectedVersion, in.EnrollmentID, r.pin)
	default:
		return result, ErrRepositoryOperation
	}
	g, ok := requestAuthorizationFromContext(ctx)
	if !ok || !gatewayBootstrapStatementAllowed(g, query, args) {
		return result, ErrAuthorizationDenied
	}
	raw, e := r.database.QueryJSON(ctx, query, args...)
	if e != nil {
		return result, discoveryProviderError(e)
	}
	if decodeGatewayBootstrapMutation(raw, &result) != nil || result.Operation != op {
		return result, ErrRepositoryUnavailable
	}
	return result, nil
}
func validGatewayBootstrapDevice(d GatewayDeviceRecord) bool {
	return validProductID(d.ID) && len(d.Name) > 0 && len(d.Name) <= 128 && stringIn(d.State, "pending", "active", "revoked", "deleted") && d.Version > 0 && d.ReplayFloor >= 0 && !d.CreatedAt.IsZero()
}
func validGatewayBootstrapEnrollment(e GatewayBootstrapEnrollment, id string) bool {
	return validProductID(e.ID) && e.DeviceID == id && e.TokenGeneration > 0 && e.DeviceVersion > 0 && e.Audience == "runtime-gateway-enroll" && !e.IssuedAt.IsZero() && e.ExpiresAt.After(e.IssuedAt)
}
func decodeGatewayBootstrapMutation(raw []byte, v *GatewayBootstrapMutationResult) error {
	if decodeGatewayBootstrapJSON(raw, v) != nil || !validGatewayBootstrapDevice(v.Device) || v.NewMutation == v.Replayed || !stringIn(v.Operation, "createGatewayDevice", "issueGatewayEnrollment", "revokeGatewayEnrollment") {
		return ErrRepositoryUnavailable
	}
	if v.Operation == "createGatewayDevice" {
		if v.Enrollment != nil || v.CredentialGeneration != 0 {
			return ErrRepositoryUnavailable
		}
	} else if v.Enrollment == nil || !validGatewayBootstrapEnrollment(*v.Enrollment, v.Device.ID) || v.Operation == "issueGatewayEnrollment" && v.CredentialGeneration < 1 {
		return ErrRepositoryUnavailable
	}
	return nil
}
func gatewayBootstrapStatementAllowed(g RequestAuthorization, q string, args []any) bool {
	op := ""
	n := 0
	switch q {
	case gatewayBootstrapCreateSQL:
		op = "createGatewayDevice"
		n = 9
	case gatewayBootstrapIssueSQL:
		op = "issueGatewayEnrollment"
		n = 14
	case gatewayBootstrapRevokeSQL:
		op = "revokeGatewayEnrollment"
		n = 10
	case gatewayBootstrapGetSQL:
		op = "getGatewayDevice"
		n = 5
	default:
		return false
	}
	if len(args) != n || g.OperationID != op || g.Collection || !authorizationNativeTargetAllowed(g, "environment", g.Identity.Scope.EnvironmentID().String()) || args[0] != g.Identity.Scope.OrganizationID().String() || args[1] != g.Identity.Scope.WorkspaceID().String() || args[2] != g.Identity.Scope.EnvironmentID().String() {
		return false
	}
	pin, ok := args[n-1].(string)
	if !ok || !migrations.IsGatewayBootstrapProfileChecksum(pin) {
		return false
	}
	if op == "getGatewayDevice" {
		return args[3] == g.PathParameters["id"] && validProductID(g.PathParameters["id"])
	}
	if args[3] != g.Identity.PrincipalID.String() || g.Identity.CredentialKind == CredentialBrowserSession && !g.Identity.FreshAuthenticated {
		return false
	}
	if op != "createGatewayDevice" && args[6] != g.PathParameters["id"] {
		return false
	}
	if op == "revokeGatewayEnrollment" && args[8] != g.PathParameters["enrollmentId"] {
		return false
	}
	return true
}
func (d *PostgresJSONDatabase) GatewayBootstrapProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsGatewayBootstrapProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if e := d.driver.QueryRow(ctx, `SELECT zasp_gateway_bootstrap_v1.caller_ready('public-api',$1)`, pin).Scan(&ready); e != nil {
		return false, classifyPostgresError(e)
	}
	return ready, nil
}

// Called only inside the already fenced original authorization transaction.
// Raw secret is read from private Go context and never supplied to PostgreSQL.
func prepareGatewayBootstrapIssue(ctx context.Context, tx pgx.Tx, g RequestAuthorization, q string, args []any) ([]any, error) {
	if q != gatewayBootstrapIssueSQL {
		return args, nil
	}
	material, ok := ctx.Value(gatewayBootstrapSecretKey{}).(gatewayBootstrapSecretMaterial)
	if !ok || len(material.secret) != 32 || len(args) != 14 || args[8] != material.enrollmentID {
		return nil, ErrRepositoryUnavailable
	}
	var raw []byte
	if e := tx.QueryRow(ctx, gatewayBootstrapPrepareSQL, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[13]).Scan(&raw); e != nil {
		return nil, classifyPostgresError(e)
	}
	var prepared struct {
		DeviceVersion        int64 `json:"device_version"`
		TokenGeneration      int64 `json:"token_generation"`
		CredentialGeneration int64 `json:"credential_generation"`
		Replayed             bool  `json:"replayed"`
	}
	if decodeGatewayBootstrapJSON(raw, &prepared) != nil || prepared.DeviceVersion < 1 || prepared.TokenGeneration < 1 || prepared.CredentialGeneration < 1 || !prepared.Replayed && args[7] != prepared.DeviceVersion {
		return nil, ErrRepositoryUnavailable
	}
	salt, ok := args[10].([]byte)
	if !ok || len(salt) != 32 {
		return nil, ErrRepositoryUnavailable
	}
	hash := sha256.New()
	for _, part := range [][]byte{[]byte("zasp-gateway-enrollment-token-hash-v1"), {0}, []byte("runtime-gateway-enroll"), {0}, []byte(material.enrollmentID), {0}} {
		_, _ = hash.Write(part)
	}
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], uint64(prepared.TokenGeneration))
	_, _ = hash.Write(generation[:])
	_, _ = hash.Write(salt)
	_, _ = hash.Write(material.secret)
	copyArgs := append([]any(nil), args...)
	copyArgs[11] = hash.Sum(nil)
	if !gatewayBootstrapStatementAllowed(g, q, copyArgs) {
		return nil, ErrAuthorizationDenied
	}
	return copyArgs, nil
}
func confirmGatewayBootstrapMutation(ctx context.Context, tx pgx.Tx, g RequestAuthorization, q string, args []any, raw []byte) error {
	if q != gatewayBootstrapCreateSQL && q != gatewayBootstrapIssueSQL && q != gatewayBootstrapRevokeSQL {
		return nil
	}
	var value GatewayBootstrapMutationResult
	if decodeGatewayBootstrapMutation(raw, &value) != nil || value.Operation != g.OperationID {
		return ErrRepositoryUnavailable
	}
	if value.NewMutation && q == gatewayBootstrapIssueSQL {
		enrollmentID, _ := args[8].(string)
		expiry, _ := args[12].(time.Time)
		if value.Enrollment == nil || value.Enrollment.ID != enrollmentID || !value.Enrollment.ExpiresAt.Equal(expiry) || value.Device.ID != args[6] {
			return ErrRepositoryUnavailable
		}
	}
	var confirmed bool
	if e := tx.QueryRow(ctx, gatewayBootstrapConfirmSQL, args[0], args[1], args[2], args[3], g.OperationID, args[4], args[5], string(raw), args[len(args)-1]).Scan(&confirmed); e != nil {
		return classifyPostgresError(e)
	}
	if !confirmed || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}
