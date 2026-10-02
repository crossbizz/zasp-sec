package apiserver

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"net/http"
	"time"
)

var complianceOperations = []OperationDefinition{
	{Method: "GET", Pattern: "/api/v1/compliance/evidence/{sourceKind}/{id}", OperationID: "getComplianceEvidence"},
	{Method: "POST", Pattern: "/api/v1/compliance/exports", OperationID: "createComplianceExport"},
	{Method: "GET", Pattern: "/api/v1/compliance/exports/{id}", OperationID: "getComplianceExport"},
	{Method: "POST", Pattern: "/api/v1/compliance/exports/{id}/download-grants", OperationID: "createComplianceDownloadGrant"},
	{Method: "POST", Pattern: "/api/v1/compliance/exports/{id}/download", OperationID: "downloadComplianceExport"},
}

func NewCompositionWithCompliance(dependencies Dependencies, auditExports, compliance http.Handler) (http.Handler, error) {
	if _, valid := handlerIdentity(compliance); !valid {
		return nil, ErrInvalidComposition
	}
	return newComposition(dependencies, auditExports, compliance)
}

type ComplianceHandlerConfiguration struct {
	CursorSigningKey    []byte
	Bucket              string
	ExpectedBucketOwner string
	KMSKeyARN           string
	Client              s3driver.ExportReadAPI
	ProviderTimeout     time.Duration
}
type ComplianceProductionHandler interface {
	http.Handler
	Ready(context.Context) error
}
type complianceProductionSurface struct{ *complianceHTTPHandler }

func (s *complianceProductionSurface) Ready(ctx context.Context) error {
	if s == nil || s.complianceHTTPHandler == nil {
		return ErrRepositoryUnavailable
	}
	return s.source.Ready(ctx)
}

// This adapter cannot upload or delete. Its credentials are the API's distinct
// read identity, and every storage coordinate comes from trusted operator pins.
type complianceReadOnlyAPI struct{ s3driver.ExportReadAPI }

func (complianceReadOnlyAPI) PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, s3driver.ErrImmutable
}
func NewComplianceProductionHandler(ctx context.Context, db JSONDatabase, c ComplianceHandlerConfiguration) (ComplianceProductionHandler, error) {
	if ctx == nil || ctx.Err() != nil || nilInterface(db) || nilInterface(c.Client) {
		return nil, ErrRepositoryConfiguration
	}
	if currentAuthorizationRequired(db) && !validAuditExportCursorKey(c.CursorSigningKey) {
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
	source, err := NewComplianceRepository(db)
	if err != nil || ctx.Err() != nil {
		return nil, ErrRepositoryConfiguration
	}
	return &complianceProductionSurface{&complianceHTTPHandler{source: source, exports: &ComplianceExportsRepository{source: source}, reader: store, signingKey: append([]byte(nil), c.CursorSigningKey...)}}, nil
}
