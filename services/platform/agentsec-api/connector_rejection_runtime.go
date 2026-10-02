package main

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
)

func (driver *pgxProductionDriver) BeginReadCommitted(ctx context.Context) (pgx.Tx, error) {
	if driver == nil || driver.pool == nil {
		return nil, apiserver.ErrRepositoryUnavailable
	}
	return driver.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

func (database *tracedJSONDatabase) AuditIntegrationRejection(ctx context.Context, identity apiserver.RequestIdentity, command apiserver.IntegrationRejection) (err error) {
	if database == nil || invalidRuntimeValue(database.next) || ctx == nil {
		return apiserver.ErrRepositoryUnavailable
	}
	auditor, ok := database.next.(interface {
		AuditIntegrationRejection(context.Context, apiserver.RequestIdentity, apiserver.IntegrationRejection) error
	})
	if !ok {
		return apiserver.ErrRepositoryUnavailable
	}
	ctx, end := startOperationalSpan(ctx, database.exporter, "repository.integration_rejection", "client", map[string]string{"db.system": "postgresql", "db.operation.name": "integration_rejection"})
	defer func() { database.metrics.observeDependency("repository", err); end(err) }()
	return auditor.AuditIntegrationRejection(ctx, identity, command)
}
