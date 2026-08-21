package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

const postgresSchemaVersionSQL = `WITH semantic_objects AS (
    SELECT 'table'::text AS object_kind, class.relname::text AS object_identity,
           jsonb_build_object('row_security', class.relrowsecurity, 'force_row_security', class.relforcerowsecurity, 'persistence', class.relpersistence) AS definition
      FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'public' AND left(class.relname, 5) = 'zasp_' AND class.relkind IN ('r', 'p')
    UNION ALL
    SELECT 'column', class.relname || '.' || attribute.attnum || '.' || attribute.attname,
           jsonb_build_object(
             'type', format_type(attribute.atttypid, attribute.atttypmod),
             'not_null', attribute.attnotnull,
             'default', COALESCE(regexp_replace(pg_get_expr(default_value.adbin, default_value.adrelid, true), E'\\s+', ' ', 'g'), ''),
             'identity', attribute.attidentity,
             'generated', attribute.attgenerated,
             'collation', CASE WHEN attribute.attcollation = 0 THEN '' ELSE attribute.attcollation::regcollation::text END)
      FROM pg_attribute AS attribute
      JOIN pg_class AS class ON class.oid = attribute.attrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      LEFT JOIN pg_attrdef AS default_value ON default_value.adrelid = attribute.attrelid AND default_value.adnum = attribute.attnum
     WHERE namespace.nspname = 'public' AND left(class.relname, 5) = 'zasp_' AND class.relkind IN ('r', 'p')
       AND attribute.attnum > 0 AND NOT attribute.attisdropped
    UNION ALL
    SELECT 'constraint', class.relname || '.' || constraint_value.conname,
           jsonb_build_object(
             'type', constraint_value.contype,
             'definition', regexp_replace(pg_get_constraintdef(constraint_value.oid, true), E'\\s+', ' ', 'g'),
             'deferrable', constraint_value.condeferrable,
             'deferred', constraint_value.condeferred,
             'validated', constraint_value.convalidated)
      FROM pg_constraint AS constraint_value
      JOIN pg_class AS class ON class.oid = constraint_value.conrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
     WHERE namespace.nspname = 'public' AND left(class.relname, 5) = 'zasp_'
    UNION ALL
    SELECT 'index', table_class.relname || '.' || index_class.relname,
           jsonb_build_object(
             'definition', regexp_replace(pg_get_indexdef(index_value.indexrelid, 0, true), E'\\s+', ' ', 'g'),
             'unique', index_value.indisunique,
             'primary', index_value.indisprimary,
             'exclusion', index_value.indisexclusion,
             'valid', index_value.indisvalid,
             'ready', index_value.indisready)
      FROM pg_index AS index_value
      JOIN pg_class AS table_class ON table_class.oid = index_value.indrelid
      JOIN pg_class AS index_class ON index_class.oid = index_value.indexrelid
      JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
     WHERE namespace.nspname = 'public' AND left(table_class.relname, 5) = 'zasp_'
    UNION ALL
    SELECT 'function', procedure.proname || '(' || pg_get_function_identity_arguments(procedure.oid) || ')',
           jsonb_build_object(
             'result', pg_get_function_result(procedure.oid),
             'language', language.lanname,
             'kind', procedure.prokind,
             'volatility', procedure.provolatile,
             'strict', procedure.proisstrict,
             'security_definer', procedure.prosecdef,
             'leakproof', procedure.proleakproof,
             'parallel', procedure.proparallel,
             'config', COALESCE(to_jsonb(procedure.proconfig), '[]'::jsonb),
             'body', regexp_replace(btrim(procedure.prosrc), E'\\s+', ' ', 'g'))
      FROM pg_proc AS procedure
      JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
     JOIN pg_language AS language ON language.oid = procedure.prolang
     WHERE namespace.nspname = 'public' AND left(procedure.proname, 5) = 'zasp_'
    UNION ALL
    SELECT 'trigger', table_class.relname || '.' || trigger_value.tgname,
           jsonb_build_object(
             'definition', regexp_replace(pg_get_triggerdef(trigger_value.oid, true), E'\\s+', ' ', 'g'),
             'enabled', trigger_value.tgenabled,
             'function', trigger_value.tgfoid::regprocedure::text)
      FROM pg_trigger AS trigger_value
      JOIN pg_class AS table_class ON table_class.oid = trigger_value.tgrelid
      JOIN pg_namespace AS namespace ON namespace.oid = table_class.relnamespace
     WHERE namespace.nspname = 'public' AND table_class.relname = 'zasp_connector_effects' AND NOT trigger_value.tgisinternal
), semantic_fingerprint AS (
    SELECT encode(digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(object_kind, object_identity, definition) ORDER BY object_kind, object_identity)::text, '[]'), 'UTF8'), 'sha256'), 'hex') AS value
      FROM semantic_objects
)
SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON (release.version = 9 AND release.name = 'production_risk_projection') OR (release.version = 10 AND release.name = 'production_discovery') OR (release.version = 11 AND release.name = 'connector_authorization') OR (release.version = 12 AND release.name = 'reference_authorization')
JOIN zasp_schema_metadata AS expected_fingerprint ON expected_fingerprint.key = CASE release.version WHEN 9 THEN 'production_risk_projection_fingerprint' WHEN 10 THEN 'production_discovery_fingerprint' WHEN 11 THEN 'connector_authorization_fingerprint' ELSE 'reference_authorization_fingerprint' END
LEFT JOIN zasp_schema_metadata AS release_fingerprint ON release.version = 10 AND release_fingerprint.key = 'production_discovery_release_fingerprint'
CROSS JOIN semantic_fingerprint
WHERE metadata.key = 'production_core_schema' AND metadata.value = CASE release.version WHEN 9 THEN 'production-risk-projection-v1' WHEN 10 THEN 'production-discovery-v1' WHEN 11 THEN 'connector-authorization-v1' ELSE 'reference-authorization-v1' END
  AND release.checksum = CASE release.version WHEN 9 THEN $1 WHEN 10 THEN $3 WHEN 11 THEN $5 ELSE $7 END
  AND COALESCE(release_fingerprint.value, expected_fingerprint.value) = CASE release.version WHEN 9 THEN $2 WHEN 10 THEN $4 WHEN 11 THEN $6 ELSE $8 END
  AND semantic_fingerprint.value = expected_fingerprint.value
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version>release.version)`

const postgresSchemaMarkerSQL = `SELECT value FROM zasp_schema_metadata WHERE key = 'production_core_schema'`

const postgresDiscoveryExecutionSchemaVersionSQL = `SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 13 AND release.name = 'production_discovery_execution'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'production-discovery-execution-v1'
  AND zasp_execution_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 13)`

const postgresTypedInventorySchemaVersionSQL = `SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 14 AND release.name = 'typed_inventory_cutover'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'typed-inventory-cutover-v1'
  AND zasp_inventory_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 14)`

const postgresRuntimeDataPlaneReleaseSQL = `SELECT release.version::text
FROM zasp_schema_versions AS release
WHERE release.version BETWEEN 15 AND 17
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > release.version)
ORDER BY release.version DESC
LIMIT 1`

const postgresRuntimeDataPlaneSchemaVersionSQL = `SELECT 'runtime-data-plane-v1'
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 15 AND release.name = 'runtime_data_plane'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'runtime-data-plane-v1'
  AND zasp_runtime_data_plane_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 15)`

const postgresRuntimeGatewayReconciliationSchemaVersionSQL = `SELECT 'runtime-gateway-reconciliation-v1'
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 16 AND release.name = 'runtime_gateway_reconciliation'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'runtime-data-plane-v1'
  AND zasp_runtime_gateway_reconciliation_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 16)`

const postgresRuntimeIngestReconciliationSchemaVersionSQL = `SELECT 'runtime-ingest-reconciliation-v1'
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 17 AND release.name = 'runtime_ingest_reconciliation'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'runtime-data-plane-v1'
  AND zasp_runtime_ingest_reconciliation_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 17)`

const postgresSecurityAgentExecutionSchemaVersionSQL = `SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 18 AND release.name = 'security_agent_execution'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'security-agent-execution-v1'
  AND zasp_security_agent_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 18)`

const postgresIdentityAdministrationSchemaVersionSQL = `SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 19 AND release.name = 'identity_administration'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'identity-administration-v1'
  AND zasp_identity_administration_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 19)`

const postgresSecurityAgentControlsSchemaVersionSQL = `SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 20 AND release.name = 'security_agent_controls'
WHERE metadata.key = 'production_core_schema' AND metadata.value = 'security-agent-controls-v1'
  AND zasp_security_agent_controls_readiness($1, $2)
  AND NOT EXISTS (SELECT 1 FROM zasp_schema_versions newer WHERE newer.version > 20)`

func expectedCoreSchemaChecksum() string { return migrations.ProductionRiskProjection().Checksum() }
func expectedCoreSchemaFingerprint() string {
	return migrations.ProductionRiskProjectionSemanticFingerprint()
}
func expectedDiscoverySchemaChecksum() string { return migrations.ProductionDiscovery().Checksum() }
func expectedDiscoverySchemaFingerprint() string {
	return migrations.ProductionDiscoverySemanticFingerprint()
}
func expectedConnectorSchemaChecksum() string { return migrations.ConnectorAuthorization().Checksum() }
func expectedConnectorSchemaFingerprint() string {
	return migrations.ConnectorAuthorizationSemanticFingerprint()
}
func expectedReferenceSchemaChecksum() string { return migrations.ReferenceAuthorization().Checksum() }
func expectedReferenceSchemaFingerprint() string {
	return migrations.ReferenceAuthorizationSemanticFingerprint()
}
func expectedDiscoveryExecutionSchemaChecksum() string {
	return migrations.ProductionDiscoveryExecution().Checksum()
}
func expectedDiscoveryExecutionSchemaFingerprint() string {
	return migrations.ProductionDiscoveryExecutionSemanticFingerprint()
}
func expectedTypedInventorySchemaChecksum() string {
	return migrations.ProductionTypedInventoryCutover().Checksum()
}
func expectedTypedInventorySchemaFingerprint() string {
	return migrations.ProductionTypedInventoryCutoverSemanticFingerprint()
}
func expectedRuntimeDataPlaneSchemaChecksum() string {
	return migrations.ProductionRuntimeDataPlane().Checksum()
}
func expectedRuntimeDataPlaneSchemaFingerprint() string {
	return migrations.ProductionRuntimeDataPlaneSemanticFingerprint()
}
func expectedRuntimeGatewayReconciliationSchemaChecksum() string {
	return migrations.ProductionRuntimeGatewayReconciliation().Checksum()
}
func expectedRuntimeGatewayReconciliationSchemaFingerprint() string {
	return migrations.ProductionRuntimeGatewayReconciliationSemanticFingerprint()
}
func expectedRuntimeIngestReconciliationSchemaChecksum() string {
	return migrations.ProductionRuntimeIngestReconciliation().Checksum()
}
func expectedRuntimeIngestReconciliationSchemaFingerprint() string {
	return migrations.ProductionRuntimeIngestReconciliationSemanticFingerprint()
}
func expectedSecurityAgentExecutionSchemaChecksum() string {
	return migrations.ProductionSecurityAgentExecution().Checksum()
}
func expectedSecurityAgentExecutionSchemaFingerprint() string {
	return migrations.ProductionSecurityAgentExecutionSemanticFingerprint()
}
func expectedIdentityAdministrationSchemaChecksum() string {
	return migrations.ProductionIdentityAdministration().Checksum()
}
func expectedIdentityAdministrationSchemaFingerprint() string {
	return migrations.ProductionIdentityAdministrationSemanticFingerprint()
}
func expectedSecurityAgentControlsSchemaChecksum() string {
	return migrations.ProductionSecurityAgentControls().Checksum()
}
func expectedSecurityAgentControlsSchemaFingerprint() string {
	return migrations.ProductionSecurityAgentControlsSemanticFingerprint()
}

type PostgresRow interface{ Scan(...any) error }

type PostgresDriver interface {
	QueryRow(context.Context, string, ...any) PostgresRow
	Exec(context.Context, string, ...any) error
	Close() error
}

type PostgresJSONDatabase struct {
	mu     sync.RWMutex
	driver PostgresDriver
	closed bool
}

func NewPostgresJSONDatabase(driver PostgresDriver) (*PostgresJSONDatabase, error) {
	if nilInterface(driver) {
		return nil, ErrRepositoryConfiguration
	}
	return &PostgresJSONDatabase{driver: driver}, nil
}

func (database *PostgresJSONDatabase) SchemaVersion(ctx context.Context) (string, error) {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return "", ErrRepositoryOperation
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return "", ErrRepositoryUnavailable
	}
	var marker string
	if err := database.driver.QueryRow(ctx, postgresSchemaMarkerSQL).Scan(&marker); err != nil {
		return "", classifyPostgresError(err)
	}
	var version string
	if marker == SecurityAgentControlsSchemaVersion {
		if err := database.driver.QueryRow(ctx, postgresSecurityAgentControlsSchemaVersionSQL, expectedSecurityAgentControlsSchemaChecksum(), expectedSecurityAgentControlsSchemaFingerprint()).Scan(&version); err != nil {
			return "", classifyPostgresError(err)
		}
	} else if marker == IdentityAdministrationSchemaVersion {
		if err := database.driver.QueryRow(ctx, postgresIdentityAdministrationSchemaVersionSQL, expectedIdentityAdministrationSchemaChecksum(), expectedIdentityAdministrationSchemaFingerprint()).Scan(&version); err != nil {
			return "", classifyPostgresError(err)
		}
	} else if marker == SecurityAgentExecutionSchemaVersion {
		if err := database.driver.QueryRow(ctx, postgresSecurityAgentExecutionSchemaVersionSQL, expectedSecurityAgentExecutionSchemaChecksum(), expectedSecurityAgentExecutionSchemaFingerprint()).Scan(&version); err != nil {
			return "", classifyPostgresError(err)
		}
	} else if marker == RuntimeDataPlaneSchemaVersion {
		var release string
		if err := database.driver.QueryRow(ctx, postgresRuntimeDataPlaneReleaseSQL).Scan(&release); err != nil {
			return "", classifyPostgresError(err)
		}
		var readinessErr error
		switch release {
		case "15":
			readinessErr = database.driver.QueryRow(ctx, postgresRuntimeDataPlaneSchemaVersionSQL, expectedRuntimeDataPlaneSchemaChecksum(), expectedRuntimeDataPlaneSchemaFingerprint()).Scan(&version)
		case "16":
			readinessErr = database.driver.QueryRow(ctx, postgresRuntimeGatewayReconciliationSchemaVersionSQL, expectedRuntimeGatewayReconciliationSchemaChecksum(), expectedRuntimeGatewayReconciliationSchemaFingerprint()).Scan(&version)
		case "17":
			readinessErr = database.driver.QueryRow(ctx, postgresRuntimeIngestReconciliationSchemaVersionSQL, expectedRuntimeIngestReconciliationSchemaChecksum(), expectedRuntimeIngestReconciliationSchemaFingerprint()).Scan(&version)
		default:
			return "", ErrRepositoryNotFound
		}
		if readinessErr != nil {
			return "", classifyPostgresError(readinessErr)
		}
	} else if marker == TypedInventorySchemaVersion {
		if err := database.driver.QueryRow(ctx, postgresTypedInventorySchemaVersionSQL, expectedTypedInventorySchemaChecksum(), expectedTypedInventorySchemaFingerprint()).Scan(&version); err != nil {
			return "", classifyPostgresError(err)
		}
	} else if marker == DiscoveryExecutionSchemaVersion {
		if err := database.driver.QueryRow(ctx, postgresDiscoveryExecutionSchemaVersionSQL, expectedDiscoveryExecutionSchemaChecksum(), expectedDiscoveryExecutionSchemaFingerprint()).Scan(&version); err != nil {
			return "", classifyPostgresError(err)
		}
	} else if err := database.driver.QueryRow(ctx, postgresSchemaVersionSQL, expectedCoreSchemaChecksum(), expectedCoreSchemaFingerprint(), expectedDiscoverySchemaChecksum(), expectedDiscoverySchemaFingerprint(), expectedConnectorSchemaChecksum(), expectedConnectorSchemaFingerprint(), expectedReferenceSchemaChecksum(), expectedReferenceSchemaFingerprint()).Scan(&version); err != nil {
		return "", classifyPostgresError(err)
	}
	if version == "" {
		return "", ErrRepositoryNotFound
	}
	return version, nil
}

func (database *PostgresJSONDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	if database == nil || ctx == nil || ctx.Err() != nil || statement == "" {
		return nil, ErrRepositoryOperation
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return nil, ErrRepositoryUnavailable
	}
	var payload []byte
	if err := database.driver.QueryRow(ctx, statement, arguments...).Scan(&payload); err != nil {
		return nil, classifyPostgresError(err)
	}
	if len(payload) == 0 {
		return nil, ErrRepositoryNotFound
	}
	if !json.Valid(payload) {
		return nil, ErrRepositoryUnavailable
	}
	return append(json.RawMessage(nil), payload...), nil
}

func (database *PostgresJSONDatabase) Exec(ctx context.Context, statement string, arguments ...any) error {
	if database == nil || ctx == nil || ctx.Err() != nil || statement == "" {
		return ErrRepositoryOperation
	}
	database.mu.RLock()
	defer database.mu.RUnlock()
	if database.closed || nilInterface(database.driver) {
		return ErrRepositoryUnavailable
	}
	if err := database.driver.Exec(ctx, statement, arguments...); err != nil {
		return classifyPostgresError(err)
	}
	return nil
}

func classifyPostgresError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRepositoryNotFound
	}
	var provider *pgconn.PgError
	if errors.As(err, &provider) {
		switch provider.Code {
		case "22023", "22P02", "23514":
			return ErrRepositoryOperation
		case "23505", "40001", "40P01":
			return ErrRepositoryConflict
		case "P0002":
			return ErrRepositoryNotFound
		}
	}
	return errors.Join(ErrRepositoryUnavailable, err)
}

func (database *PostgresJSONDatabase) Close() error {
	if database == nil {
		return ErrRepositoryOperation
	}
	database.mu.Lock()
	defer database.mu.Unlock()
	if database.closed {
		return nil
	}
	database.closed = true
	if nilInterface(database.driver) || database.driver.Close() != nil {
		return ErrRepositoryOperation
	}
	return nil
}
