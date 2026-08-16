package observability

import (
	"context"
	"errors"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

var (
	ErrResource    = errors.New("observability resource rejected")
	ErrCorrelation = errors.New("observability correlation rejected")
)

type Service string

const (
	ServiceAPI    Service = "agentsec-api"
	ServiceWorker Service = "agentsec-worker"
)

type Deployment string

const (
	DeploymentDevelopment Deployment = "development"
	DeploymentTest        Deployment = "test"
	DeploymentStaging     Deployment = "staging"
	DeploymentProduction  Deployment = "production"
)

type StringAttribute struct {
	Key   string
	Value string
}

type ResourceAttributes struct {
	values [7]StringAttribute
}

func NewResourceAttributes(scope domain.Scope, service Service, version string, deployment Deployment) (ResourceAttributes, error) {
	if scope.Validate() != nil || !validService(service) || !validVersion(version) || !validDeployment(deployment) {
		return ResourceAttributes{}, ErrResource
	}
	return ResourceAttributes{values: [7]StringAttribute{
		{Key: "service.namespace", Value: "agentsec"},
		{Key: "service.name", Value: string(service)},
		{Key: "service.version", Value: version},
		{Key: "deployment.environment.name", Value: string(deployment)},
		{Key: "organization.id", Value: scope.OrganizationID().String()},
		{Key: "workspace.id", Value: scope.WorkspaceID().String()},
		{Key: "environment.id", Value: scope.EnvironmentID().String()},
	}}, nil
}

func (resource ResourceAttributes) OTLP() []StringAttribute {
	attributes := make([]StringAttribute, len(resource.values))
	copy(attributes, resource.values[:])
	if ValidateResourceAttributes(attributes) != nil {
		return nil
	}
	return attributes
}

func ValidateResourceAttributes(attributes []StringAttribute) error {
	if len(attributes) != 7 {
		return ErrResource
	}
	expectedKeys := [...]string{
		"service.namespace",
		"service.name",
		"service.version",
		"deployment.environment.name",
		"organization.id",
		"workspace.id",
		"environment.id",
	}
	for index, expected := range expectedKeys {
		if attributes[index].Key != expected {
			return ErrResource
		}
	}
	if attributes[0].Value != "agentsec" ||
		!validService(Service(attributes[1].Value)) ||
		!validVersion(attributes[2].Value) ||
		!validDeployment(Deployment(attributes[3].Value)) {
		return ErrResource
	}
	organizationID, organizationErr := domain.ParseProductID(attributes[4].Value)
	workspaceID, workspaceErr := domain.ParseProductID(attributes[5].Value)
	environmentID, environmentErr := domain.ParseProductID(attributes[6].Value)
	if organizationErr != nil || workspaceErr != nil || environmentErr != nil {
		return ErrResource
	}
	if _, err := domain.NewScope(organizationID, workspaceID, environmentID); err != nil {
		return ErrResource
	}
	return nil
}

func validService(service Service) bool {
	switch service {
	case ServiceAPI, ServiceWorker:
		return true
	default:
		return false
	}
}

func validDeployment(deployment Deployment) bool {
	switch deployment {
	case DeploymentDevelopment, DeploymentTest, DeploymentStaging, DeploymentProduction:
		return true
	default:
		return false
	}
}

func validVersion(version string) bool {
	if len(version) == 0 || len(version) > 63 {
		return false
	}
	previousSeparator := false
	for index := 0; index < len(version); index++ {
		character := version[index]
		switch {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
			previousSeparator = false
		case character == '.', character == '+', character == '_', character == '-':
			if index == 0 || index == len(version)-1 || previousSeparator {
				return false
			}
			previousSeparator = true
		default:
			return false
		}
	}
	return true
}

type Correlation struct {
	correlationID domain.CorrelationID
	traceID       string
	spanID        string
}

func NewCorrelation(correlationID domain.CorrelationID, traceID, spanID string) (Correlation, error) {
	correlation := Correlation{correlationID: correlationID, traceID: traceID, spanID: spanID}
	if correlation.Validate() != nil {
		return Correlation{}, ErrCorrelation
	}
	return correlation, nil
}

func (correlation Correlation) Validate() error {
	if !validCorrelationID(correlation.correlationID) ||
		!validHexIdentifier(correlation.traceID, 32) ||
		!validHexIdentifier(correlation.spanID, 16) {
		return ErrCorrelation
	}
	return nil
}

func (correlation Correlation) CorrelationID() domain.CorrelationID {
	if correlation.Validate() != nil {
		return domain.CorrelationID{}
	}
	return correlation.correlationID
}

func (correlation Correlation) TraceID() string {
	if correlation.Validate() != nil {
		return ""
	}
	return correlation.traceID
}

func (correlation Correlation) SpanID() string {
	if correlation.Validate() != nil {
		return ""
	}
	return correlation.spanID
}

func validCorrelationID(correlationID domain.CorrelationID) bool {
	return !correlationID.IsZero() && correlationID.String() != ""
}

func validHexIdentifier(value string, length int) bool {
	if len(value) != length {
		return false
	}
	nonzero := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
		if character != '0' {
			nonzero = true
		}
	}
	return nonzero
}

type correlationContextKey struct{}

func WithCorrelation(ctx context.Context, correlation Correlation) (context.Context, error) {
	if ctx == nil || correlation.Validate() != nil {
		return nil, ErrCorrelation
	}
	if stored := ctx.Value(correlationContextKey{}); stored != nil {
		existing, ok := stored.(Correlation)
		if !ok || existing.Validate() != nil || existing != correlation {
			return ctx, ErrCorrelation
		}
		return ctx, nil
	}
	return context.WithValue(ctx, correlationContextKey{}, correlation), nil
}

func CorrelationFromContext(ctx context.Context) (Correlation, bool) {
	if ctx == nil {
		return Correlation{}, false
	}
	correlation, ok := ctx.Value(correlationContextKey{}).(Correlation)
	if !ok || correlation.Validate() != nil {
		return Correlation{}, false
	}
	return correlation, true
}
