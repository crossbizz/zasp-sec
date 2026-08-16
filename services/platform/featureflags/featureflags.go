package featureflags

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumAllowedCacheAge  = 24 * time.Hour
	maximumKeyBytes         = 127
)

var (
	ErrConfiguration = errors.New("feature flag configuration rejected")
	ErrRequest       = errors.New("feature flag request rejected")
)

type Config struct {
	OperationTimeout time.Duration
	MaximumCacheAge  time.Duration
}

type Request struct {
	Key     string
	Default bool
}

type CacheMetadata struct {
	Hit bool
	Age time.Duration
}

type Decision struct {
	Value       bool
	UsedDefault bool
	Cache       CacheMetadata
}

type DriverRequest struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	Key            string
}

type DriverDecision struct {
	OrganizationID string
	WorkspaceID    string
	EnvironmentID  string
	Key            string
	Value          bool
	CacheHit       bool
	CacheAge       time.Duration
}

type Driver interface {
	Evaluate(context.Context, DriverRequest) (DriverDecision, error)
}

type FeatureFlags interface {
	Evaluate(context.Context, domain.Scope, Request) (Decision, error)
}

type Evaluator struct {
	driver Driver
	config Config
}

func New(driver Driver, config Config) (*Evaluator, error) {
	if nilInterface(driver) || !validConfig(config) {
		return nil, ErrConfiguration
	}
	return &Evaluator{driver: driver, config: config}, nil
}

func (evaluator *Evaluator) Evaluate(ctx context.Context, scope domain.Scope, request Request) (Decision, error) {
	if evaluator == nil || nilInterface(evaluator.driver) || !validConfig(evaluator.config) {
		return Decision{}, ErrConfiguration
	}
	if ctx == nil || scope.Validate() != nil || !validKey(request.Key) {
		return Decision{}, ErrRequest
	}
	fallback := Decision{Value: request.Default, UsedDefault: true}
	operationCtx, cancel := context.WithTimeout(ctx, evaluator.config.OperationTimeout)
	defer cancel()
	if operationCtx.Err() != nil {
		return fallback, nil
	}
	driverRequest := DriverRequest{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		Key:            request.Key,
	}
	driverDecision, err := evaluateDriver(evaluator.driver, operationCtx, driverRequest)
	if err != nil || operationCtx.Err() != nil || !validDriverDecision(driverRequest, driverDecision, evaluator.config.MaximumCacheAge) {
		return fallback, nil
	}
	return Decision{
		Value: driverDecision.Value,
		Cache: CacheMetadata{Hit: driverDecision.CacheHit, Age: driverDecision.CacheAge},
	}, nil
}

func validConfig(config Config) bool {
	return config.OperationTimeout > 0 && config.OperationTimeout <= maximumOperationTimeout &&
		config.MaximumCacheAge > 0 && config.MaximumCacheAge <= maximumAllowedCacheAge
}

func validKey(key string) bool {
	if len(key) == 0 || len(key) > maximumKeyBytes || key[0] < 'a' || key[0] > 'z' {
		return false
	}
	separator := false
	for index := 1; index < len(key); index++ {
		character := key[index]
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			separator = false
		case character == '.', character == '_', character == '-':
			if separator || index == len(key)-1 {
				return false
			}
			separator = true
		default:
			return false
		}
	}
	return true
}

func evaluateDriver(driver Driver, ctx context.Context, request DriverRequest) (decision DriverDecision, err error) {
	defer func() {
		if recover() != nil {
			decision = DriverDecision{}
			err = ErrConfiguration
		}
	}()
	return driver.Evaluate(ctx, request)
}

func validDriverDecision(request DriverRequest, decision DriverDecision, maximumCacheAge time.Duration) bool {
	if decision.OrganizationID != request.OrganizationID ||
		decision.WorkspaceID != request.WorkspaceID ||
		decision.EnvironmentID != request.EnvironmentID ||
		decision.Key != request.Key || decision.CacheAge < 0 {
		return false
	}
	if !decision.CacheHit {
		return decision.CacheAge == 0
	}
	return decision.CacheAge <= maximumCacheAge
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
