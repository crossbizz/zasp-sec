package apiserver

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/connectormaintenance"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// ConnectorMaintenanceEnqueueDatabase changes only the three exact authentic
// enqueue paths. It preserves every other original database capability and
// authorization rule; bare runtime contexts never acquire an API grant.
type ConnectorMaintenanceEnqueueDatabase struct {
	*PostgresJSONDatabase
	profile    string
	callbackMu sync.Mutex
	callbacks  map[[32]byte]connectorCallbackPermit
}

func NewConnectorMaintenanceEnqueueDatabase(ctx context.Context, base *PostgresJSONDatabase, pin string) (*ConnectorMaintenanceEnqueueDatabase, error) {
	if ctx == nil || ctx.Err() != nil || base == nil {
		return nil, ErrRepositoryConfiguration
	}
	compiled, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil || pin != compiled {
		return nil, ErrRepositoryConfiguration
	}
	base.mu.RLock()
	defer base.mu.RUnlock()
	if base.closed || !base.currentAuthorization || nilInterface(base.driver) {
		return nil, ErrRepositoryConfiguration
	}
	if _, ok := base.driver.(AuthorizationTransactionDriver); !ok {
		return nil, ErrRepositoryConfiguration
	}
	var raw []byte
	if err := base.driver.QueryRow(ctx, `SELECT zasp_connector_maintenance.projection_profile_state()`).Scan(&raw); err != nil || connectormaintenance.VerifyActiveProfile(raw, pin) != nil || ctx.Err() != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &ConnectorMaintenanceEnqueueDatabase{PostgresJSONDatabase: base, profile: pin, callbacks: make(map[[32]byte]connectorCallbackPermit)}, nil
}

func (d *ConnectorMaintenanceEnqueueDatabase) QueryJSON(ctx context.Context, statement string, args ...any) (json.RawMessage, error) {
	if d == nil || d.PostgresJSONDatabase == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	grant, checked := requestAuthorizationFromContext(ctx)
	var query string
	var nativeArgs []any
	switch statement {
	case postgresConnectorConsumeOAuthSQL, postgresConnectorActivatePKCECleanupSQL, postgresConnectorCompletePKCECleanupSQL, postgresConnectorResolveEffectSQL, postgresConnectorCompleteOAuthSQL, postgresConnectorCompleteCleanupSQL:
		if statement == postgresConnectorActivatePKCECleanupSQL && checked && grant.OperationID == "authorizeIntegration" {
			if len(args) != 4 {
				return nil, ErrAuthorizationDenied
			}
			scope := grant.Identity.Scope
			if args[0] != scope.OrganizationID().String() || args[1] != scope.WorkspaceID().String() || args[2] != scope.EnvironmentID().String() {
				return nil, ErrAuthorizationDenied
			}
			proof, err := authorizationProofJSON(grant)
			if err != nil {
				return nil, err
			}
			return d.connectorCallbackTransaction(ctx, `SELECT zasp_connector_maintenance.handoff_pkce($1,$2,$3,$4,$5)`, append([]any{string(proof)}, args...)...)
		}
		if !checked || grant.OperationID != "completeIntegrationOAuthCallback" {
			return d.PostgresJSONDatabase.QueryJSON(ctx, statement, args...)
		}
		return d.queryConnectorCallback(ctx, statement, args, grant)
	case postgresConnectorStagePKCECleanupSQL:
		if !checked || len(args) != 11 || grant.OperationID != "authorizeIntegration" || !connectorEnqueueScope(grant, args, 0, 4) {
			return nil, ErrAuthorizationDenied
		}
		query = `SELECT zasp_connector_maintenance.capture_pkce_cleanup($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
		nativeArgs = args
	case postgresConnectorStartOAuthSQL:
		if !checked || len(args) != 17 || grant.OperationID != "authorizeIntegration" || !connectorEnqueueScope(grant, args, 0, 4) || args[6] != grant.Identity.PrincipalID.String() {
			return nil, ErrAuthorizationDenied
		}
		query = `SELECT zasp_connector_maintenance.start_oauth($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17,$18)`
		nativeArgs = args
	case postgresConnectorWorkflowMutateSQL:
		if len(args) < 1 || args[0] != "delete" {
			return d.PostgresJSONDatabase.QueryJSON(ctx, statement, args...)
		}
		if !checked || len(args) != 15 || args[1] != "integration" || args[7] != "deleteIntegration" || grant.OperationID != "deleteIntegration" || !connectorEnqueueScope(grant, args, 3, 2) || args[6] != grant.Identity.PrincipalID.String() {
			return nil, ErrAuthorizationDenied
		}
		query = `SELECT zasp_connector_maintenance.delete_integration($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11,$12,$13)`
		nativeArgs = []any{args[2], args[3], args[4], args[5], args[6], args[8], args[9], args[10], args[11], args[12], args[13], args[14]}
	default:
		return d.PostgresJSONDatabase.QueryJSON(ctx, statement, args...)
	}
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		return nil, err
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
	var state []byte
	if err := tx.QueryRow(ctx, `SELECT zasp_connector_maintenance.projection_profile_state()`).Scan(&state); err != nil || connectormaintenance.VerifyActiveProfile(state, d.profile) != nil {
		return nil, ErrRepositoryUnavailable
	}
	var raw []byte
	if err := tx.QueryRow(ctx, query, append([]any{string(proof)}, nativeArgs...)...).Scan(&raw); err != nil {
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
func connectorEnqueueScope(grant RequestAuthorization, args []any, scopeAt, integrationAt int) bool {
	if scopeAt+2 >= len(args) || integrationAt >= len(args) {
		return false
	}
	scope := grant.Identity.Scope
	return args[scopeAt] == scope.OrganizationID().String() && args[scopeAt+1] == scope.WorkspaceID().String() && args[scopeAt+2] == scope.EnvironmentID().String() && args[integrationAt] == grant.PathParameters["id"]
}
