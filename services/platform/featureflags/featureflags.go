package featureflags

import (
	"container/list"
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

const (
	maximumOperationTimeout = 30 * time.Second
	maximumAllowedCacheAge  = 24 * time.Hour
	maximumKeyBytes         = 127
	maximumCacheEntries     = 1024
)

var (
	ErrConfiguration = errors.New("feature flag configuration rejected")
	ErrRequest       = errors.New("feature flag request rejected")
)

type Config struct {
	OperationTimeout time.Duration
	MaximumCacheAge  time.Duration
}

type CodeDefault string

const (
	DefaultDisabled CodeDefault = "disabled"
	DefaultEnabled  CodeDefault = "enabled"
)

type Request struct {
	Key     string
	Default CodeDefault
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
	cache  *decisionCache
}

func New(driver Driver, config Config) (*Evaluator, error) {
	return newWithClock(driver, config, time.Now)
}

func newWithClock(driver Driver, config Config, now func() time.Time) (*Evaluator, error) {
	if nilInterface(driver) || !validConfig(config) || now == nil {
		return nil, ErrConfiguration
	}
	return &Evaluator{driver: driver, config: config, cache: &decisionCache{
		now: now, entries: make(map[DriverRequest]*list.Element), order: list.New(),
	}}, nil
}

func (evaluator *Evaluator) Evaluate(ctx context.Context, scope domain.Scope, request Request) (Decision, error) {
	if evaluator == nil || nilInterface(evaluator.driver) || !validConfig(evaluator.config) {
		return Decision{}, ErrConfiguration
	}
	defaultValue, validDefault := codeDefaultValue(request.Default)
	if ctx == nil || scope.Validate() != nil || !validKey(request.Key) || !validDefault {
		return Decision{}, ErrRequest
	}
	fallback := Decision{Value: defaultValue, UsedDefault: true}
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
	if evaluator.cache != nil {
		if decision, ok := evaluator.cache.get(operationCtx, driverRequest, evaluator.config.MaximumCacheAge); ok {
			if operationCtx.Err() != nil {
				return fallback, nil
			}
			return decision, nil
		}
	}

	if operationCtx.Err() != nil {
		return fallback, nil
	}
	driverDecision, err := evaluateDriver(evaluator.driver, operationCtx, driverRequest)
	if err != nil || operationCtx.Err() != nil || !validDriverDecision(driverRequest, driverDecision, evaluator.config.MaximumCacheAge) {
		return fallback, nil
	}
	if evaluator.cache != nil {
		evaluator.cache.put(operationCtx, driverRequest, driverDecision)
	}
	if operationCtx.Err() != nil {
		return fallback, nil
	}
	return Decision{
		Value: driverDecision.Value,
		Cache: CacheMetadata{Hit: driverDecision.CacheHit, Age: driverDecision.CacheAge},
	}, nil
}

func codeDefaultValue(codeDefault CodeDefault) (bool, bool) {
	switch codeDefault {
	case DefaultDisabled:
		return false, true
	case DefaultEnabled:
		return true, true
	default:
		return false, false
	}
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

// decisionCache keeps only validated flag values and their tenant identity. Its
// clock is fixed at construction; the lock never spans a provider operation.
type decisionCache struct {
	mu           sync.Mutex
	now          func() time.Time
	lastObserved time.Time
	observed     bool
	entries      map[DriverRequest]*list.Element
	order        *list.List
}

type cachedDecision struct {
	key         DriverRequest
	value       bool
	providerAge time.Duration
	insertedAt  time.Time
}

func (cache *decisionCache) observe() time.Time {
	now := cache.now()
	if cache.observed && now.Before(cache.lastObserved) {
		clear(cache.entries)
		cache.order.Init()
	}
	cache.lastObserved, cache.observed = now, true
	return now
}

func (cache *decisionCache) get(ctx context.Context, key DriverRequest, maximumAge time.Duration) (Decision, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.observe()
	element, found := cache.entries[key]
	if !found {
		return Decision{}, false
	}
	entry := element.Value.(cachedDecision)
	elapsed := now.Sub(entry.insertedAt)
	// Compare before adding so even a saturating time difference cannot overflow.
	if elapsed < 0 || entry.providerAge > maximumAge || elapsed > maximumAge-entry.providerAge {
		delete(cache.entries, key)
		cache.order.Remove(element)
		return Decision{}, false
	}
	if ctx.Err() != nil {
		return Decision{}, false
	}
	cache.order.MoveToFront(element)
	return Decision{Value: entry.value, Cache: CacheMetadata{Hit: true, Age: entry.providerAge + elapsed}}, true
}

func (cache *decisionCache) put(ctx context.Context, key DriverRequest, decision DriverDecision) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.observe()
	if ctx.Err() != nil {
		return
	}
	entry := cachedDecision{key: key, value: decision.Value, providerAge: decision.CacheAge, insertedAt: now}
	if element, found := cache.entries[key]; found {
		element.Value = entry
		cache.order.MoveToFront(element)
		return
	}
	if len(cache.entries) == maximumCacheEntries {
		oldest := cache.order.Back()
		delete(cache.entries, oldest.Value.(cachedDecision).key)
		cache.order.Remove(oldest)
	}
	cache.entries[key] = cache.order.PushFront(entry)
}
