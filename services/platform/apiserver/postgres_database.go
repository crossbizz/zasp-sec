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

const postgresSchemaVersionSQL = `SELECT metadata.value
FROM zasp_schema_metadata AS metadata
JOIN zasp_schema_versions AS release ON release.version = 3 AND release.name = 'production_workflows'
WHERE metadata.key = 'production_core_schema' AND release.checksum = $1
  AND to_regclass('public.zasp_workflow_records') IS NOT NULL
  AND to_regclass('public.zasp_workflow_idempotency') IS NOT NULL
  AND to_regclass('public.zasp_workflow_audit') IS NOT NULL
  AND to_regclass('public.zasp_workflow_records_list_idx') IS NOT NULL
  AND to_regprocedure('public.zasp_workflow_list(text,text,text,text,text,text)') IS NOT NULL
  AND to_regprocedure('public.zasp_workflow_get(text,text,text,text,text)') IS NOT NULL
  AND to_regprocedure('public.zasp_workflow_replay(text,text,text,text,text,text,jsonb)') IS NOT NULL
  AND to_regprocedure('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text)') IS NOT NULL
  AND to_regprocedure('public.zasp_effective_scope_permissions(jsonb,text)') IS NOT NULL
  AND (SELECT array_agg(attribute.attname ORDER BY attribute.attnum)
         FROM pg_attribute AS attribute
        WHERE attribute.attrelid = 'public.zasp_workflow_records'::regclass AND attribute.attnum > 0 AND NOT attribute.attisdropped)
      = ARRAY['organization_id','workspace_id','environment_id','kind','id','version','body','secret_generation','deleted_at','created_at','updated_at']::name[]
  AND (SELECT array_agg(attribute.attname ORDER BY attribute.attnum)
         FROM pg_attribute AS attribute
        WHERE attribute.attrelid = 'public.zasp_workflow_idempotency'::regclass AND attribute.attnum > 0 AND NOT attribute.attisdropped)
      = ARRAY['organization_id','workspace_id','environment_id','principal_id','operation','idempotency_key','request_digest','response','created_at']::name[]
  AND (SELECT array_agg(attribute.attname ORDER BY attribute.attnum)
         FROM pg_attribute AS attribute
        WHERE attribute.attrelid = 'public.zasp_workflow_audit'::regclass AND attribute.attnum > 0 AND NOT attribute.attisdropped)
      = ARRAY['organization_id','workspace_id','environment_id','audit_id','correlation_id','principal_id','operation','resource_kind','resource_id','resource_version','created_at']::name[]
  AND (SELECT count(*) FROM pg_constraint WHERE conrelid = 'public.zasp_workflow_records'::regclass AND contype = 'c') = 4
  AND (SELECT count(*) FROM pg_constraint WHERE conrelid = 'public.zasp_workflow_idempotency'::regclass AND contype = 'c') = 1
  AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'public.zasp_product_sessions'::regclass AND attname = 'authenticated_at' AND attnotnull AND NOT attisdropped)`

func expectedCoreSchemaChecksum() string { return migrations.ProductionWorkflows().Checksum() }

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
	var version string
	if err := database.driver.QueryRow(ctx, postgresSchemaVersionSQL, expectedCoreSchemaChecksum()).Scan(&version); err != nil {
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
	return ErrRepositoryUnavailable
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
