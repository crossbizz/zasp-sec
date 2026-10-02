package apiserver

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"net/http"
)

type SecurityAgentExportProductionHandler interface {
	http.Handler
	Ready(context.Context) error
}

func NewSecurityAgentExportProductionHandler(ctx context.Context, db JSONDatabase, c ComplianceHandlerConfiguration) (SecurityAgentExportProductionHandler, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(db) {
		return nil, ErrRepositoryConfiguration
	}
	probe, ok := db.(interface {
		SecurityAgentExportsAvailable(context.Context) (bool, error)
	})
	if !ok {
		return nil, nil
	}
	available, err := probe.SecurityAgentExportsAvailable(ctx)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRepositoryUnavailable
	}
	if !available {
		return nil, nil
	}
	if nilInterface(c.Client) {
		return nil, ErrRepositoryConfiguration
	}
	driver, err := s3driver.NewExport(complianceReadOnlyAPI{c.Client}, s3driver.Config{Bucket: c.Bucket, ExpectedBucketOwner: c.ExpectedBucketOwner, KMSKeyARN: c.KMSKeyARN, MaximumBytes: compliancePackageMaximum})
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	store, err := artifactstore.NewExport(driver, artifactstore.Config{OperationTimeout: c.ProviderTimeout, MaximumBytes: compliancePackageMaximum})
	if err != nil {
		return nil, ErrRepositoryConfiguration
	}
	repository, err := NewSecurityAgentExportsRepository(db)
	if err != nil {
		return nil, err
	}
	return &securityAgentExportProductionSurface{securityAgentExportHTTPHandler: &securityAgentExportHTTPHandler{exports: repository, reader: store}, probe: probe}, nil
}

type securityAgentExportProductionSurface struct {
	*securityAgentExportHTTPHandler
	probe interface {
		SecurityAgentExportsAvailable(context.Context) (bool, error)
	}
}

func (s *securityAgentExportProductionSurface) Ready(ctx context.Context) error {
	if s == nil || s.securityAgentExportHTTPHandler == nil || nilInterface(s.probe) || ctx == nil || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	available, err := s.probe.SecurityAgentExportsAvailable(ctx)
	if err != nil || !available || ctx.Err() != nil {
		return ErrRepositoryUnavailable
	}
	return nil
}
