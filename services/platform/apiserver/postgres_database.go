package apiserver

import (
	"context"
	"encoding/json"
	"sync"
)

const postgresSchemaVersionSQL = `SELECT value FROM zasp_schema_metadata WHERE key = 'production_core_schema'`

type PostgresRow interface{ Scan(...any) error }

type PostgresDriver interface {
	QueryRow(context.Context, string, ...any) PostgresRow
	Exec(context.Context, string, ...any) error
	Close() error
}

type PostgresJSONDatabase struct {
	mu     sync.Mutex
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
	if !database.usable(ctx) {
		return "", ErrRepositoryOperation
	}
	var version string
	if database.driver.QueryRow(ctx, postgresSchemaVersionSQL).Scan(&version) != nil || version == "" {
		return "", ErrRepositoryOperation
	}
	return version, nil
}

func (database *PostgresJSONDatabase) QueryJSON(ctx context.Context, statement string, arguments ...any) (json.RawMessage, error) {
	if !database.usable(ctx) || statement == "" {
		return nil, ErrRepositoryOperation
	}
	var payload []byte
	if database.driver.QueryRow(ctx, statement, arguments...).Scan(&payload) != nil || !json.Valid(payload) {
		return nil, ErrRepositoryOperation
	}
	return append(json.RawMessage(nil), payload...), nil
}

func (database *PostgresJSONDatabase) Exec(ctx context.Context, statement string, arguments ...any) error {
	if !database.usable(ctx) || statement == "" || database.driver.Exec(ctx, statement, arguments...) != nil {
		return ErrRepositoryOperation
	}
	return nil
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

func (database *PostgresJSONDatabase) usable(ctx context.Context) bool {
	if database == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	database.mu.Lock()
	defer database.mu.Unlock()
	return !database.closed && !nilInterface(database.driver)
}
