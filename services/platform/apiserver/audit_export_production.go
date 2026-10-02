package apiserver

import (
	"context"
	"net/http"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// AuditExportStorageConfiguration supplies trusted operator pins and a client
// owned by the caller. A database response never creates a client configuration.
type AuditExportStorageConfiguration struct {
	Policy migrations.AuditExportConfiguration
	Client s3driver.API
}

type AuditExportHandlerConfiguration struct {
	Storage          []AuditExportStorageConfiguration
	CursorSigningKey []byte
	ProviderTimeout  time.Duration
}

type AuditExportProductionHandler interface {
	http.Handler
	Ready(context.Context) error
}

type auditExportProductionSurface struct {
	http.Handler
	repository *AuditExportRepository
}

func (surface *auditExportProductionSurface) Ready(ctx context.Context) error {
	if surface == nil || surface.repository == nil {
		return ErrRepositoryUnavailable
	}
	return surface.repository.Ready(ctx)
}

// NewAuditExportProductionHandler composes the durable repository and immutable
// storage reader. The caller retains ownership of the database and SDK clients.
// Authentication, origin checks and route registration belong to the outer API.
func NewAuditExportProductionHandler(ctx context.Context, database JSONDatabase, config AuditExportHandlerConfiguration) (AuditExportProductionHandler, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(database) {
		return nil, ErrRepositoryConfiguration
	}
	cursor, err := newAuditExportCursorCodec(config.CursorSigningKey)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	entries := make([]auditExportStorageEntry, len(config.Storage))
	for index, entry := range config.Storage {
		entries[index] = auditExportStorageEntry{Configuration: entry.Policy, Client: entry.Client}
	}
	registry, err := newAuditExportStorageRegistry(entries, config.ProviderTimeout)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	repository, err := newAuditExportRepository(ctx, database)
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &auditExportProductionSurface{Handler: &auditExportHTTPHandler{repository: repository, storage: registry, cursor: cursor, newID: newWorkflowProductID}, repository: repository}, nil
}
