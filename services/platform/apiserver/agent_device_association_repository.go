package apiserver

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const associationCreateSQL = `SELECT zasp_agent_device_association_v1.create_intent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`
const associationActivateSQL = `SELECT zasp_agent_device_association_v1.activate($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
const associationRevokeSQL = `SELECT zasp_agent_device_association_v1.revoke($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`
const associationPageSQL = `SELECT zasp_agent_device_association_v1.page($1,$2,$3,$4,$5,$6,$7)`
const associationConfirmSQL = `SELECT zasp_agent_device_association_v1.confirm_human($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`

type AgentDeviceAssociationRepository struct {
	database JSONDatabase
	pin      string
}

func (r *PostgresRepository) RequireAgentDeviceAssociationProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsAgentDeviceAssociationProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.agentDeviceAssociationProfileChecksum = pin
	return nil
}
func NewAgentDeviceAssociationRepository(db JSONDatabase, pin string) (*AgentDeviceAssociationRepository, error) {
	if nilInterface(db) || !migrations.IsAgentDeviceAssociationProfileChecksum(pin) {
		return nil, ErrRepositoryConfiguration
	}
	if _, ok := db.(*PostgresJSONDatabase); !ok {
		return nil, ErrRepositoryConfiguration
	}
	return &AgentDeviceAssociationRepository{db, pin}, nil
}
func (r *AgentDeviceAssociationRepository) AgentDeviceAssociationProfileChecksum() string {
	if r == nil {
		return ""
	}
	return r.pin
}
func (r *AgentDeviceAssociationRepository) MutateAssociation(ctx context.Context, i RequestIdentity, op string, in AgentDeviceAssociationMutation) (json.RawMessage, error) {
	if r == nil || !validRequestIdentity(i, false) || i.CredentialKind != CredentialBrowserSession || !i.FreshAuthenticated {
		return nil, ErrAuthorizationDenied
	}
	q, args := associationMutationStatement(i, op, in, r.pin)
	g, ok := requestAuthorizationFromContext(ctx)
	if !ok || !associationIdentityMatches(g.Identity, i) || !agentDeviceAssociationStatementAllowed(g, q, args) {
		return nil, ErrAuthorizationDenied
	}
	raw, e := r.database.QueryJSON(ctx, q, args...)
	if e != nil {
		return nil, discoveryProviderError(e)
	}
	if _, _, e = validateAgentDeviceAssociationMutationResult(raw, op, i, in); e != nil {
		return nil, ErrRepositoryUnavailable
	}
	return raw, nil
}
func associationMutationStatement(i RequestIdentity, op string, in AgentDeviceAssociationMutation, pin string) (string, []any) {
	args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), i.PrincipalID.String(), in.AgentID}
	switch op {
	case "createAgentDeviceIntent":
		return associationCreateSQL, append(args, in.DeviceID, in.IdempotencyKey, in.RequestDigest, in.ExpectedVersion, in.ChallengeID, in.Nonce, in.TTLSeconds, pin)
	case "activateAgentDeviceAssociation":
		return associationActivateSQL, append(args, in.AssociationID, in.ChallengeID, in.ChallengeSHA256, in.ExpectedVersion, in.IdempotencyKey, in.RequestDigest, pin)
	case "revokeAgentDeviceAssociation":
		return associationRevokeSQL, append(args, in.AssociationID, in.ExpectedVersion, in.IdempotencyKey, in.RequestDigest, pin)
	default:
		return "", nil
	}
}
func (r *AgentDeviceAssociationRepository) ListAssociations(ctx context.Context, i RequestIdentity, agent, after string, limit int) (json.RawMessage, error) {
	if r == nil || !validRequestIdentity(i, false) || !validProductID(agent) || after != "" && !validProductID(after) || limit < 1 || limit > 100 {
		return nil, ErrRepositoryOperation
	}
	var cursor any
	if after != "" {
		cursor = after
	}
	args := []any{i.Scope.OrganizationID().String(), i.Scope.WorkspaceID().String(), i.Scope.EnvironmentID().String(), agent, cursor, limit, r.pin}
	g, ok := requestAuthorizationFromContext(ctx)
	if !ok || !associationIdentityMatches(g.Identity, i) || !agentDeviceAssociationStatementAllowed(g, associationPageSQL, args) {
		return nil, ErrAuthorizationDenied
	}
	raw, e := r.database.QueryJSON(ctx, associationPageSQL, args...)
	if e != nil {
		return nil, discoveryProviderError(e)
	}
	if _, _, e = validateAgentDeviceAssociationList(raw, agent, limit); e != nil {
		return nil, ErrRepositoryUnavailable
	}
	return raw, nil
}
func agentDeviceAssociationStatementAllowed(g RequestAuthorization, q string, args []any) bool {
	op, n, agentIndex := "", 0, 4
	switch q {
	case associationCreateSQL:
		op, n = "createAgentDeviceIntent", 13
	case associationActivateSQL:
		op, n = "activateAgentDeviceAssociation", 12
	case associationRevokeSQL:
		op, n = "revokeAgentDeviceAssociation", 10
	case associationPageSQL:
		op, n, agentIndex = "listAgentDeviceAssociations", 7, 3
	default:
		return false
	}
	if len(args) != n || g.OperationID != op || g.Collection || len(g.Targets) != 1 || len(g.Allowed) != 1 || g.Targets[0] != g.Allowed[0] || !validProductID(g.PathParameters["id"]) || !authorizationNativeTargetAllowed(g, "agent", g.PathParameters["id"]) || args[agentIndex] != g.PathParameters["id"] || args[0] != g.Identity.Scope.OrganizationID().String() || args[1] != g.Identity.Scope.WorkspaceID().String() || args[2] != g.Identity.Scope.EnvironmentID().String() {
		return false
	}
	pin, ok := args[n-1].(string)
	if !ok || !migrations.IsAgentDeviceAssociationProfileChecksum(pin) {
		return false
	}
	if q == associationPageSQL {
		limit, ok := args[5].(int)
		if !ok || limit < 1 || limit > 100 {
			return false
		}
		return args[4] == nil || func() bool { s, ok := args[4].(string); return ok && validProductID(s) }()
	}
	if args[3] != g.Identity.PrincipalID.String() || g.Identity.CredentialKind != CredentialBrowserSession || !g.Identity.FreshAuthenticated {
		return false
	}
	versionIndex, keyIndex, digestIndex := 8, 6, 7
	switch q {
	case associationActivateSQL:
		versionIndex, keyIndex, digestIndex = 8, 9, 10
	case associationRevokeSQL:
		versionIndex, keyIndex, digestIndex = 6, 7, 8
	}
	version, ok := args[versionIndex].(int64)
	if !ok || version < 0 {
		return false
	}
	key, ok := args[keyIndex].(string)
	if !ok || !validAdministrationIdempotencyKey(key) {
		return false
	}
	digest, ok := args[digestIndex].([]byte)
	if !ok || len(digest) != 32 {
		return false
	}
	if q != associationCreateSQL {
		return args[5] == g.PathParameters["associationId"] && validProductID(g.PathParameters["associationId"]) && (q != associationActivateSQL || func() bool {
			id, ok := args[6].(string)
			hash, yes := args[7].([]byte)
			return ok && yes && validProductID(id) && len(hash) == 32
		}())
	}
	device, ok := args[5].(string)
	challenge, yes := args[9].(string)
	nonce, valid := args[10].([]byte)
	ttl, typed := args[11].(int32)
	return ok && yes && valid && typed && validProductID(device) && validProductID(challenge) && len(nonce) == 32 && ttl >= 60 && ttl <= 300
}
func (d *PostgresJSONDatabase) AgentDeviceAssociationProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsAgentDeviceAssociationProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if e := d.driver.QueryRow(ctx, `SELECT zasp_agent_device_association_v1.caller_ready('public-api',$1)`, pin).Scan(&ready); e != nil {
		return false, classifyPostgresError(e)
	}
	return ready, nil
}
func confirmAgentDeviceAssociationMutation(ctx context.Context, tx pgx.Tx, g RequestAuthorization, q string, args []any, raw []byte) error {
	if q != associationCreateSQL && q != associationActivateSQL && q != associationRevokeSQL {
		return nil
	}
	if !agentDeviceAssociationStatementAllowed(g, q, args) {
		return ErrAuthorizationDenied
	}
	in := AgentDeviceAssociationMutation{AgentID: g.PathParameters["id"]}
	keyIndex, digestIndex := 6, 7
	switch q {
	case associationCreateSQL:
		in.DeviceID, _ = args[5].(string)
		in.ExpectedVersion, _ = args[8].(int64)
		in.ChallengeID, _ = args[9].(string)
		in.Nonce, _ = args[10].([]byte)
		in.TTLSeconds, _ = args[11].(int32)
	case associationActivateSQL:
		keyIndex, digestIndex = 9, 10
		in.AssociationID, _ = args[5].(string)
		in.ChallengeID, _ = args[6].(string)
		in.ChallengeSHA256, _ = args[7].([]byte)
		in.ExpectedVersion, _ = args[8].(int64)
	case associationRevokeSQL:
		keyIndex, digestIndex = 7, 8
		in.AssociationID, _ = args[5].(string)
		in.ExpectedVersion, _ = args[6].(int64)
	}
	in.IdempotencyKey, _ = args[keyIndex].(string)
	in.RequestDigest, _ = args[digestIndex].([]byte)
	if _, _, e := validateAgentDeviceAssociationMutationResult(raw, g.OperationID, g.Identity, in); e != nil {
		return ErrRepositoryUnavailable
	}
	var confirmed bool
	if e := tx.QueryRow(ctx, associationConfirmSQL, args[0], args[1], args[2], args[3], in.AgentID, g.OperationID, in.IdempotencyKey, in.RequestDigest, string(raw), args[len(args)-1]).Scan(&confirmed); e != nil {
		return classifyPostgresError(e)
	}
	if !confirmed || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func associationIdentityMatches(a, b RequestIdentity) bool {
	return a.PrincipalID == b.PrincipalID && a.Scope == b.Scope && a.CredentialKind == b.CredentialKind && a.CSRFToken == b.CSRFToken && a.FreshAuthenticated == b.FreshAuthenticated && a.FreshAuthExpiresAt.Equal(b.FreshAuthExpiresAt)
}
