package aigateway

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumTextBytes        = 2_048
	maximumTokenBytes       = 63
	resultSchemaVersion     = "1"
)

var (
	ErrInvalidConfiguration = errors.New("invalid AI gateway configuration")
	ErrInvalidRequest       = errors.New("invalid AI gateway request")
	ErrGeneration           = errors.New("AI generation failed")
)

type Purpose string

const PurposeFindingExplanation Purpose = "finding_explanation"

type ContentMode string

const ContentModeRedactedSummary ContentMode = "redacted_summary"

type RetentionMode string

const RetentionModeNoProviderStorage RetentionMode = "no_provider_storage"

type DataPolicyMetadata struct {
	Version             string
	ApprovedPurpose     Purpose
	ContentMode         ContentMode
	EgressApproved      bool
	SecretsExcluded     bool
	PIIExcluded         bool
	PHIExcluded         bool
	RawEvidenceExcluded bool
	RetentionMode       RetentionMode
}

type Request struct {
	Purpose         Purpose
	SubjectID       domain.ProductID
	RedactedSummary string
	DataPolicy      DataPolicyMetadata
}

type Result struct {
	Purpose           Purpose
	SubjectID         domain.ProductID
	SchemaVersion     string
	Explanation       string
	Recommendation    string
	DataPolicyVersion string
}

type DriverRequest struct {
	OrganizationID  domain.ProductID
	WorkspaceID     domain.ProductID
	EnvironmentID   domain.ProductID
	Purpose         Purpose
	SubjectID       domain.ProductID
	RedactedSummary string
	DataPolicy      DataPolicyMetadata
}

type DriverResult struct {
	Purpose           Purpose
	SubjectID         domain.ProductID
	SchemaVersion     string
	Explanation       string
	Recommendation    string
	DataPolicyVersion string
}

type Driver interface {
	Generate(context.Context, DriverRequest) (DriverResult, error)
}

type AIGateway interface {
	Generate(context.Context, domain.Scope, Request) (Result, error)
}

type Config struct {
	Driver           Driver
	OperationTimeout time.Duration
}

type Gateway struct {
	driver           Driver
	operationTimeout time.Duration
}

func New(config Config) (*Gateway, error) {
	if nilDriver(config.Driver) || config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout {
		return nil, ErrInvalidConfiguration
	}
	return &Gateway{driver: config.Driver, operationTimeout: config.OperationTimeout}, nil
}

func (gateway *Gateway) Generate(ctx context.Context, scope domain.Scope, request Request) (result Result, err error) {
	defer func() {
		if recover() != nil {
			result = Result{}
			err = ErrGeneration
		}
	}()

	if gateway == nil || nilDriver(gateway.driver) || gateway.operationTimeout <= 0 || gateway.operationTimeout > maximumOperationTimeout {
		return Result{}, ErrInvalidConfiguration
	}
	if ctx == nil || scope.Validate() != nil || !validRequest(request) {
		return Result{}, ErrInvalidRequest
	}
	if ctx.Err() != nil {
		return Result{}, ErrGeneration
	}

	operationContext, cancel := context.WithTimeout(ctx, gateway.operationTimeout)
	defer cancel()
	driverRequest := DriverRequest{
		OrganizationID:  scope.OrganizationID(),
		WorkspaceID:     scope.WorkspaceID(),
		EnvironmentID:   scope.EnvironmentID(),
		Purpose:         request.Purpose,
		SubjectID:       request.SubjectID,
		RedactedSummary: request.RedactedSummary,
		DataPolicy:      request.DataPolicy,
	}
	driverResult, driverErr := gateway.driver.Generate(operationContext, driverRequest)
	if driverErr != nil || operationContext.Err() != nil || !validDriverResult(request, driverResult) {
		return Result{}, ErrGeneration
	}
	return Result{
		Purpose:           driverResult.Purpose,
		SubjectID:         driverResult.SubjectID,
		SchemaVersion:     driverResult.SchemaVersion,
		Explanation:       driverResult.Explanation,
		Recommendation:    driverResult.Recommendation,
		DataPolicyVersion: driverResult.DataPolicyVersion,
	}, nil
}

func validRequest(request Request) bool {
	return request.Purpose == PurposeFindingExplanation &&
		validProductID(request.SubjectID) &&
		validText(request.RedactedSummary) &&
		validDataPolicy(request.Purpose, request.DataPolicy)
}

func validDataPolicy(purpose Purpose, policy DataPolicyMetadata) bool {
	return validToken(policy.Version) &&
		policy.ApprovedPurpose == purpose &&
		policy.ContentMode == ContentModeRedactedSummary &&
		policy.EgressApproved &&
		policy.SecretsExcluded &&
		policy.PIIExcluded &&
		policy.PHIExcluded &&
		policy.RawEvidenceExcluded &&
		policy.RetentionMode == RetentionModeNoProviderStorage
}

func validDriverResult(request Request, result DriverResult) bool {
	return result.Purpose == request.Purpose &&
		result.SubjectID == request.SubjectID &&
		result.SchemaVersion == resultSchemaVersion &&
		validText(result.Explanation) &&
		validText(result.Recommendation) &&
		result.DataPolicyVersion == request.DataPolicy.Version
}

func validProductID(value domain.ProductID) bool {
	text := value.String()
	parsed, err := domain.ParseProductID(text)
	return err == nil && parsed == value
}

func validText(value string) bool {
	if len(value) == 0 || len(value) > maximumTextBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if len(value) == 0 || len(value) > maximumTokenBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	separator := false
	for _, character := range []byte(value) {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			separator = false
		case character == '.', character == '_', character == '-':
			if separator {
				return false
			}
			separator = true
		default:
			return false
		}
	}
	return !separator
}

func nilDriver(driver Driver) bool {
	if driver == nil {
		return true
	}
	value := reflect.ValueOf(driver)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
