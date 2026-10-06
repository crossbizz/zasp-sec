package apiserver

import (
	"context"
	"encoding/json"

	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresAuthorizationReadySQL = `SELECT zasp_authorization80.ready($1)`
const postgresAuthorizationSourceReadySQL = `SELECT zasp_authorization80.source_ready($1,$2,$3)`

// Readiness is a separate, fixed metadata query: it never grants product access
// and cannot be used to execute an arbitrary statement without a checked proof.
func (database *PostgresJSONDatabase) CurrentAuthorizationSourceReady(ctx context.Context, version int, checksum, fingerprint string) (bool, error) {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return false, ErrRepositoryOperation
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if !database.currentAuthorization {
		return false, nil
	}
	if database.closed || nilInterface(database.driver) || (version != 52 && version != 56) {
		return true, ErrRepositoryUnavailable
	}
	var ready bool
	if err := database.driver.QueryRow(ctx, postgresAuthorizationSourceReadySQL, version, checksum, fingerprint).Scan(&ready); err != nil || !ready {
		return true, ErrRepositoryUnavailable
	}
	if version == 52 {
		// The old export constructor also validates the newest installed test/
		// run-context authority. Its bare61 public55 guard is intentionally shut;
		// registered80 covers that ancestor, but never an invalid present74.
		var installed bool
		if err := database.driver.QueryRow(ctx, `SELECT to_regnamespace('zasp_temporal74') IS NOT NULL`).Scan(&installed); err != nil {
			return true, ErrRepositoryUnavailable
		}
		if installed {
			if err := database.driver.QueryRow(ctx, `SELECT zasp_temporal74.api_ready($1,$2)`, migrations.TemporalTestExecutorChecksum(), migrations.TemporalTestExecutorFingerprint()).Scan(&ready); err != nil || !ready {
				return true, ErrRepositoryUnavailable
			}
		}
	}
	return true, nil
}

func currentAuthorizationSourceReady(ctx context.Context, database JSONDatabase, version int, checksum, fingerprint string) (bool, error) {
	if current, ok := database.(interface {
		CurrentAuthorizationSourceReady(context.Context, int, string, string) (bool, error)
	}); ok {
		return current.CurrentAuthorizationSourceReady(ctx, version, checksum, fingerprint)
	}
	return false, nil
}

func (database *PostgresJSONDatabase) CurrentAuthorizationRequired() bool {
	if database == nil {
		return false
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	return database.currentAuthorization
}

func currentAuthorizationRequired(database JSONDatabase) bool {
	current, ok := database.(interface{ CurrentAuthorizationRequired() bool })
	return ok && current.CurrentAuthorizationRequired()
}

// Called with database.mu held. Registered 80 readiness includes the exact
// canonical 61 private predecessor chain and current 79 projection catalog.
func (database *PostgresJSONDatabase) currentAuthorizationSchemaVersion(ctx context.Context) (string, error) {
	var ready bool
	if err := database.driver.QueryRow(ctx, postgresAuthorizationReadySQL, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&ready); err != nil || !ready {
		return "", ErrRepositoryUnavailable
	}
	// This is the existing API shape marker, not the installed migration number.
	return ProductionRecoverySchemaVersion, nil
}

// Only these complete metadata statements have a registered80 compatibility
// meaning. Their original compiled pins remain mandatory. No text matching,
// generic SELECT exception or product-query fallback is permitted here.
// The caller holds database.mu.
func (database *PostgresJSONDatabase) authorizationMetadataQuery(ctx context.Context, statement string, arguments []any) (json.RawMessage, bool, error) {
	if !database.currentAuthorization {
		return nil, false, nil
	}
	checksum, fingerprint, authority := "", "", DiscoveryDatabaseAuthorityAPI
	object := false
	switch statement {
	case postgresProductionRecoveryReadinessSQL:
		checksum, fingerprint = migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()
	case postgresRecoverySecurityAgentReadySQL:
		checksum, fingerprint = migrations.ProductionRecovery().Checksum(), migrations.ProductionRecoverySemanticFingerprint()
		authority, object = "zasp_security_agent_api", true
	case postgresApprovalNotificationAuthorityReadySQL:
		checksum, fingerprint = migrations.ProductionApprovalNotification().Checksum(), migrations.ProductionApprovalNotificationSemanticFingerprint()
		authority, object = "zasp_security_agent_api", true
	case postgresDiscoveryPrincipalReadySQL:
		if len(arguments) != 1 || arguments[0] != DiscoveryDatabaseAuthorityAPI {
			return nil, true, ErrAuthorizationDenied
		}
	default:
		return nil, false, nil
	}
	if checksum != "" && (len(arguments) != 2 || arguments[0] != checksum || arguments[1] != fingerprint) {
		return nil, true, ErrRepositoryUnavailable
	}
	var release, principal bool
	query := `SELECT zasp_authorization80.ready($1), public.zasp_discovery_principal_ready('zasp_discovery_api')`
	if authority == "zasp_security_agent_api" {
		query = `SELECT zasp_authorization80.ready($1), public.zasp_security_agent_principal_ready('zasp_security_agent_api')`
	}
	// Separate statements matter: a PostgreSQL generic CASE plan checks both
	// function ACLs even when the selected branch belongs to only one API role.
	if err := database.driver.QueryRow(ctx, query, migrations.ProductionAuthorizationEnforcement().Checksum()).Scan(&release, &principal); err != nil || !release || !principal {
		return nil, true, ErrRepositoryUnavailable
	}
	if object {
		return json.RawMessage(`{"release":true,"principal":true}`), true, nil
	}
	return json.RawMessage(`true`), true, nil
}
