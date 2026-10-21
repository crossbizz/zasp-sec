package apiserver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// RetentionEventVisibility owns only closed retention reads on the original
// core API connection. The request's existing current authorization proof is
// fenced in the same transaction; a scope/event pair never grants read access.
type RetentionEventVisibility struct {
	database *PostgresJSONDatabase
	checksum string
}

const postgresRetainedProductSessionEventPageSQL = `SELECT zasp_retention_v1.product_session_event_page($1,$2,$3,$4,$5,$6,$7)`

// RequireRetentionProfile selects origin-aware event reads only after current
// authorization and the exact compiled supplementary profile are configured.
func (r *PostgresRepository) RequireRetentionProfile(checksum string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsRetentionProfileChecksum(checksum) {
		return ErrRepositoryConfiguration
	}
	r.retentionProfileChecksum = checksum
	return nil
}

func NewRetentionEventVisibility(database *PostgresJSONDatabase, checksum string) (*RetentionEventVisibility, error) {
	if database == nil || checksum != migrations.RetentionAuditProfileChecksum() {
		return nil, ErrRepositoryConfiguration
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if _, ok := database.driver.(AuthorizationTransactionDriver); !ok || database.closed || !database.currentAuthorization {
		return nil, ErrRepositoryConfiguration
	}
	return &RetentionEventVisibility{database: database, checksum: checksum}, nil
}

func (r *RetentionEventVisibility) Ready(ctx context.Context) error {
	if r == nil || r.database == nil || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	d := r.database
	d.mu.RLock()
	defer d.mu.RUnlock()
	driver, ok := d.driver.(AuthorizationTransactionDriver)
	if d.closed || !d.currentAuthorization || !ok {
		return ErrRepositoryUnavailable
	}
	tx, err := driver.Begin(ctx)
	if err != nil {
		return ErrRepositoryUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var ready bool
	if tx.QueryRow(ctx, `SELECT zasp_retention_v1.caller_ready('human-read',$1)`, r.checksum).Scan(&ready) != nil || !ready || tx.Commit(ctx) != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}

func (r *RetentionEventVisibility) VisibleEvents(ctx context.Context, scope domain.Scope, ids []string) (map[string]bool, error) {
	if r == nil || r.database == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil || len(ids) == 0 || len(ids) > 1000 {
		return nil, ErrRepositoryOperation
	}
	grant, ok := requestAuthorizationFromContext(ctx)
	if !ok || grant.Identity.Scope != scope || !stringIn(grant.OperationID, "listSessions", "simulatePolicy") || grant.OperationID == "listSessions" && grant.Credential.Kind != CredentialBrowserSession {
		return nil, ErrAuthorizationDenied
	}
	proof, err := authorizationProofJSON(grant)
	if err != nil {
		return nil, ErrAuthorizationDenied
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, err := domain.ParseProductID(id); err != nil || seen[id] {
			return nil, ErrRepositoryOperation
		}
		seen[id] = true
	}
	q, err := json.Marshal(struct {
		Organization string   `json:"organization_id"`
		Workspace    string   `json:"workspace_id"`
		Environment  string   `json:"environment_id"`
		Class        string   `json:"class"`
		EventIDs     []string `json:"event_ids"`
	}{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), "runtime_event", ids})
	if err != nil {
		return nil, ErrRepositoryOperation
	}
	d := r.database
	d.mu.RLock()
	defer d.mu.RUnlock()
	driver, ok := d.driver.(AuthorizationTransactionDriver)
	if d.closed || !d.currentAuthorization || !ok {
		return nil, ErrRepositoryUnavailable
	}
	tx, err := driver.Begin(ctx)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
		return nil, ErrRepositoryUnavailable
	}
	if _, err = tx.Exec(ctx, `SELECT zasp_authorization80.fence($1::text)`, string(proof)); err != nil {
		return nil, classifyPostgresError(err)
	}
	var ready bool
	if tx.QueryRow(ctx, `SELECT zasp_retention_v1.caller_ready('human-read',$1)`, r.checksum).Scan(&ready) != nil || !ready {
		return nil, ErrRepositoryUnavailable
	}
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT zasp_retention_v1.visibility($1::jsonb)`, q).Scan(&raw); err != nil {
		return nil, classifyPostgresError(err)
	}
	var response struct {
		Items []struct {
			EventID string `json:"event_id"`
			Visible *bool  `json:"visible"`
		} `json:"items"`
	}
	if len(raw) > 256<<10 || !exactJSONFields(raw, "items") || decodeStrictDiscovery(raw, &response) != nil || response.Items == nil || len(response.Items) != len(ids) {
		return nil, ErrRepositoryUnavailable
	}
	result := make(map[string]bool, len(ids))
	for i, item := range response.Items {
		if item.EventID != ids[i] || item.Visible == nil {
			return nil, ErrRepositoryUnavailable
		}
		result[item.EventID] = *item.Visible
	}
	if tx.Commit(ctx) != nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	return result, nil
}
