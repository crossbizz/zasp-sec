package apiserver

import (
	"context"
	"encoding/json"
	"time"
)

type identityNativeOperation uint8

const (
	identityMetadata identityNativeOperation = iota
	identityBegin
	identityConsume
	identityResolve
	identityIssue
	identityDeprovision
	identityLogout
	identitySwitch
	identityPAT
	identityPostLoginSnapshot
	identityPostLoginRead
)

// This private adapter dispatches only these fixed native entries. It accepts no
// SQL from a caller, and checks decoded consumer output before committing.
func (d *PostgresJSONDatabase) identityTransaction(ctx context.Context, op identityNativeOperation, args []any, validate func(json.RawMessage) error) (json.RawMessage, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || validate == nil {
		return nil, ErrRepositoryUnavailable
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization {
		return nil, ErrRepositoryUnavailable
	}
	queries := [...]string{
		`SELECT zasp_authorization80_identity.metadata()`,
		`SELECT to_jsonb(zasp_authorization80_identity.begin_login($1,$2))`,
		`SELECT zasp_authorization80_identity.consume_login($1)`,
		`SELECT zasp_authorization80_identity.resolve_login($1)`,
		`SELECT zasp_authorization80_identity.issue_login($1,$2,$3)`,
		`SELECT zasp_authorization80_identity.apply_verified_deprovision($1)`,
		`SELECT zasp_authorization80_identity.logout($1,$2,$3,$4)`,
		`SELECT zasp_authorization80_identity.switch_scope($1,$2,$3,$4,$5,$6)`,
		`SELECT zasp_authorization80_identity.authenticate_pat($1)`,
		`SELECT zasp_authorization80_identity.post_login_snapshot($1::jsonb)`,
		`SELECT zasp_authorization80_identity.post_login_read($1::jsonb,$2::jsonb,$3,$4)`,
	}
	if int(op) >= len(queries) {
		return nil, ErrRepositoryOperation
	}
	driver, ok := d.driver.(AuthorizationTransactionDriver)
	if !ok {
		return nil, ErrRepositoryUnavailable
	}
	tx, err := driver.Begin(ctx)
	if err != nil {
		return nil, ErrRepositoryUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var payload []byte
	if err := tx.QueryRow(ctx, queries[op], args...).Scan(&payload); err != nil {
		return nil, classifyPostgresError(err)
	}
	if !json.Valid(payload) || validate(payload) != nil {
		return nil, ErrRepositoryUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrRepositoryUnavailable
	}
	return append(json.RawMessage(nil), payload...), nil
}

func (r *PostgresRepository) nativeIdentityDatabase() (*PostgresJSONDatabase, error) {
	if r == nil || !r.currentAuthorization {
		return nil, ErrRepositoryUnavailable
	}
	d, ok := r.database.(*PostgresJSONDatabase)
	if !ok {
		// A runtime decorator can expose only its exact concrete native
		// database. The closed dispatcher below never accepts generic SQL.
		wrapper, supported := r.database.(interface{ NativeIdentityDatabase() *PostgresJSONDatabase })
		if !supported {
			return nil, ErrRepositoryUnavailable
		}
		d = wrapper.NativeIdentityDatabase()
	}
	if d == nil || !d.CurrentAuthorizationRequired() {
		return nil, ErrRepositoryUnavailable
	}
	return d, nil
}
