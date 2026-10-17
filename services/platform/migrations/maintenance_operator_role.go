package migrations

import "context"

// requireMaintenanceAuthorizationReady reads only the fixed parent readiness
// gate under its existing authority membership. Restore the exact server role
// state before the caller performs source-owner namespace or REFERENCES DDL.
func requireMaintenanceAuthorizationReady(ctx context.Context, tx Transaction) error {
	var incomingUser, incomingRole string
	if err := scanRow(ctx, tx, `SELECT current_user::text,current_setting('role')`, nil, &incomingUser, &incomingRole); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if incomingUser == "" || incomingRole == "" {
		return ErrInvalidState
	}
	if err := tx.Exec(ctx, `SET LOCAL ROLE zasp_discovery_authority`); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	var ready bool
	if err := scanRow(ctx, tx, `SELECT zasp_authorization80.ready($1)`, []any{ProductionAuthorizationEnforcement().Checksum()}, &ready); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if !ready {
		return ErrInvalidState
	}
	var restoredRole string
	if err := scanRow(ctx, tx, `SELECT set_config('role',$1,true)`, []any{incomingRole}, &restoredRole); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	var restoredUser, actualRole string
	if err := scanRow(ctx, tx, `SELECT current_user::text,current_setting('role')`, nil, &restoredUser, &actualRole); err != nil {
		return fixedDatabaseError(ctx, err)
	}
	if restoredRole != incomingRole || actualRole != incomingRole || restoredUser != incomingUser {
		return ErrInvalidState
	}
	return nil
}
