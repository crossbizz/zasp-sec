package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type connectorCallbackPermit struct {
	Token       string
	Attempt     string
	Effect      string
	Cleanup     string
	Integration string
	Reference   string
	Expires     time.Time
}

func connectorCallbackKey(grant RequestAuthorization) ([32]byte, []byte, error) {
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return sha256.Sum256(proof), proof, nil
}
func (d *ConnectorMaintenanceEnqueueDatabase) callbackPermit(key [32]byte) (connectorCallbackPermit, bool) {
	d.callbackMu.Lock()
	defer d.callbackMu.Unlock()
	now := time.Now()
	for k, p := range d.callbacks {
		if !p.Expires.After(now) {
			delete(d.callbacks, k)
		}
	}
	p, ok := d.callbacks[key]
	return p, ok
}

// Reserve local capacity before consuming the durable attempt. Pending SQL
// transactions count against the same bound as issued permits, so concurrent
// callbacks cannot commit consumption and then lose their private permit to a
// capacity race. Pending entries live only until this request returns.
func (d *ConnectorMaintenanceEnqueueDatabase) reserveCallback(key [32]byte) bool {
	d.callbackMu.Lock()
	defer d.callbackMu.Unlock()
	now := time.Now()
	for k, p := range d.callbacks {
		if !p.Expires.After(now) {
			delete(d.callbacks, k)
		}
	}
	if _, exists := d.callbackPending[key]; exists {
		return false
	}
	if _, exists := d.callbacks[key]; exists {
		return false
	}
	if len(d.callbacks)+len(d.callbackPending) >= 512 {
		return false
	}
	if d.callbackPending == nil {
		d.callbackPending = make(map[[32]byte]struct{})
	}
	d.callbackPending[key] = struct{}{}
	return true
}
func (d *ConnectorMaintenanceEnqueueDatabase) releaseCallbackReservation(key [32]byte) {
	d.callbackMu.Lock()
	delete(d.callbackPending, key)
	d.callbackMu.Unlock()
}
func (d *ConnectorMaintenanceEnqueueDatabase) queryConnectorCallback(ctx context.Context, statement string, args []any, grant RequestAuthorization) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || grant.Credential.Kind != CredentialBrowserSession || grant.OperationID != "completeIntegrationOAuthCallback" || len(args) < 3 {
		return nil, ErrAuthorizationDenied
	}
	scope := grant.Identity.Scope
	if args[0] != scope.OrganizationID().String() || args[1] != scope.WorkspaceID().String() || args[2] != scope.EnvironmentID().String() {
		return nil, ErrAuthorizationDenied
	}
	key, proof, err := connectorCallbackKey(grant)
	if err != nil {
		return nil, err
	}
	if statement == postgresConnectorConsumeOAuthSQL {
		if len(args) != 6 || args[4] != grant.Identity.PrincipalID.String() {
			return nil, ErrAuthorizationDenied
		}
		session, ok := args[5].([]byte)
		if !ok || len(session) != 32 || string(session) != string(grant.Credential.Digest[:]) {
			return nil, ErrAuthorizationDenied
		}
		if !d.reserveCallback(key) {
			return nil, ErrRepositoryUnavailable
		}
		defer d.releaseCallbackReservation(key)
		raw, err := d.connectorCallbackTransaction(ctx, `SELECT zasp_connector_maintenance.consume_callback($1,$2,$3,$4,$5,$6,$7)`, append([]any{string(proof)}, args...)...)
		if err != nil {
			return nil, err
		}
		var wire struct {
			Consumption json.RawMessage `json:"consumption"`
			Permit      string          `json:"permit"`
			Expires     time.Time       `json:"expires_at"`
		}
		var consumed OAuthConsumption
		if decodeStrictDiscovery(raw, &wire) != nil || decodeStrictDiscovery(wire.Consumption, &consumed) != nil || !validProductID(consumed.ID) || !validProductID(consumed.EffectID) || consumed.PrincipalID != grant.Identity.PrincipalID.String() || !wire.Expires.After(time.Now()) || wire.Expires.After(time.Now().Add(time.Minute)) {
			return nil, ErrRepositoryUnavailable
		}
		token, err := hex.DecodeString(wire.Permit)
		if err != nil || len(token) != 32 || len(wire.Permit) != 64 {
			return nil, ErrRepositoryUnavailable
		}
		d.callbackMu.Lock()
		defer d.callbackMu.Unlock()
		if ctx.Err() != nil {
			return nil, ErrRepositoryUnavailable
		}
		delete(d.callbackPending, key)
		d.callbacks[key] = connectorCallbackPermit{Token: wire.Permit, Attempt: consumed.ID, Effect: consumed.EffectID, Cleanup: connectorDeterministicID(scope, consumed.ID, "pkce-cleanup"), Integration: consumed.IntegrationID, Reference: consumed.PKCEVerifierReference, Expires: wire.Expires.UTC()}
		return append(json.RawMessage(nil), wire.Consumption...), nil
	}
	operations := map[string]string{postgresConnectorActivatePKCECleanupSQL: "activate_pkce", postgresConnectorCompletePKCECleanupSQL: "complete_pkce", postgresConnectorResolveEffectSQL: "resolve", postgresConnectorCompleteOAuthSQL: "complete_oauth", postgresConnectorCompleteCleanupSQL: "complete_cleanup"}
	operation, ok := operations[statement]
	if !ok {
		return nil, ErrAuthorizationDenied
	}
	permit, ok := d.callbackPermit(key)
	if !ok {
		return nil, ErrAuthorizationDenied
	}
	body, err := json.Marshal(args)
	if err != nil || len(body) > 131072 {
		return nil, ErrRepositoryOperation
	}
	raw, err := d.connectorCallbackTransaction(ctx, `SELECT zasp_connector_maintenance.callback_step($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, string(proof), scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), permit.Attempt, permit.Token, operation, body)
	if err == nil && (operation == "resolve" || operation == "complete_cleanup") {
		d.callbackMu.Lock()
		delete(d.callbacks, key)
		d.callbackMu.Unlock()
	}
	return raw, err
}
func (d *ConnectorMaintenanceEnqueueDatabase) PrepareConnectorOAuthCallback(ctx context.Context, phase string, consumed OAuthConsumption) error {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	grant, ok := requestAuthorizationFromContext(ctx)
	if !ok || grant.OperationID != "completeIntegrationOAuthCallback" || !stringIn(phase, "secret", "provider", "cleanup", "reject_secret") {
		return ErrAuthorizationDenied
	}
	key, proof, err := connectorCallbackKey(grant)
	if err != nil {
		return err
	}
	permit, ok := d.callbackPermit(key)
	if !ok || permit.Attempt != consumed.ID || permit.Effect != consumed.EffectID || permit.Integration != consumed.IntegrationID || permit.Reference != consumed.PKCEVerifierReference || consumed.PrincipalID != grant.Identity.PrincipalID.String() {
		return ErrAuthorizationDenied
	}
	scope := grant.Identity.Scope
	raw, err := d.connectorCallbackTransaction(ctx, `SELECT zasp_connector_maintenance.callback_step($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`, string(proof), scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), permit.Attempt, permit.Token, phase, []byte(`[]`))
	var wire struct {
		Ready *bool `json:"ready"`
	}
	if err != nil {
		return err
	}
	if decodeStrictDiscovery(raw, &wire) != nil || wire.Ready == nil || !*wire.Ready || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

// Captured rejection cleanup is selected only by the constructed native
// database capability; an arbitrary repository does not gain it by implementing
// the forward preparation hook.
func (r *ConnectorRepository) ConnectorOAuthCallbackAuthorityRequired() bool {
	if r == nil || nilInterface(r.database) {
		return false
	}
	native, ok := r.database.(interface{ ConnectorOAuthCallbackAuthorityRequired() bool })
	return ok && native.ConnectorOAuthCallbackAuthorityRequired()
}
func (r *ConnectorRepository) PrepareConnectorOAuthCallback(ctx context.Context, phase string, consumed OAuthConsumption) error {
	if r == nil || nilInterface(r.database) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	if native, ok := r.database.(interface {
		PrepareConnectorOAuthCallback(context.Context, string, OAuthConsumption) error
	}); ok {
		return native.PrepareConnectorOAuthCallback(ctx, phase, consumed)
	}
	if required, ok := r.database.(interface{ ConnectorOAuthCallbackAuthorityRequired() bool }); ok && required.ConnectorOAuthCallbackAuthorityRequired() {
		return ErrRepositoryUnavailable
	}
	return nil // Original legacy database path retains its original behavior.
}
func (d *ConnectorMaintenanceEnqueueDatabase) connectorCallbackTransaction(ctx context.Context, query string, args ...any) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return nil, ErrRepositoryUnavailable
	}
	driver, ok := d.driver.(AuthorizationTransactionDriver)
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	tx, err := driver.Begin(ctx)
	if err != nil {
		return nil, classifyPostgresError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var raw []byte
	if err := tx.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
		return nil, classifyPostgresError(err)
	}
	if len(raw) == 0 || len(raw) > 131072 || !json.Valid(raw) || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, classifyPostgresError(err)
	}
	if ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	return append(json.RawMessage(nil), raw...), nil
}

// This capability marker is derived from the constructed native adapter, never
// from a caller Boolean or environment flag. Known wrappers forward it.
func (d *ConnectorMaintenanceEnqueueDatabase) ConnectorOAuthCallbackAuthorityRequired() bool {
	return d != nil
}
func (d *ConnectorMaintenanceEnqueueDatabase) NativeIdentityDatabase() *PostgresJSONDatabase {
	if d == nil || d.PostgresJSONDatabase == nil || !d.CurrentAuthorizationRequired() {
		return nil
	}
	return d.PostgresJSONDatabase
}
