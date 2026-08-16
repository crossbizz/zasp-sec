package featureflags

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

type fakeDriver struct {
	mu         sync.Mutex
	calls      []DriverRequest
	evaluateFn func(context.Context, DriverRequest) (DriverDecision, error)
}

func (driver *fakeDriver) Evaluate(ctx context.Context, request DriverRequest) (DriverDecision, error) {
	driver.mu.Lock()
	driver.calls = append(driver.calls, request)
	evaluateFn := driver.evaluateFn
	driver.mu.Unlock()
	if evaluateFn == nil {
		return decisionFromRequest(request, true, false, 0), nil
	}
	return evaluateFn(ctx, request)
}

func (driver *fakeDriver) callCount() int {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return len(driver.calls)
}

func (driver *fakeDriver) call(index int) DriverRequest {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return driver.calls[index]
}

func TestEvaluatorReturnsExactScopedProviderDecision(t *testing.T) {
	scope := featureFlagTestScope(t)
	request := Request{Key: "ui.attack-paths", Default: false}
	driver := &fakeDriver{evaluateFn: func(_ context.Context, got DriverRequest) (DriverDecision, error) {
		return decisionFromRequest(got, true, true, 5*time.Second), nil
	}}
	evaluator, err := New(driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	var contract FeatureFlags = evaluator
	decision, err := contract.Evaluate(context.Background(), scope, request)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	want := Decision{Value: true, Cache: CacheMetadata{Hit: true, Age: 5 * time.Second}}
	if decision != want {
		t.Fatalf("decision = %#v, want %#v", decision, want)
	}
	if driver.callCount() != 1 {
		t.Fatalf("calls = %d, want 1", driver.callCount())
	}
	wantRequest := driverRequest(scope, request.Key)
	if got := driver.call(0); got != wantRequest {
		t.Fatalf("driver request = %#v, want %#v", got, wantRequest)
	}
}

func TestEvaluatorDoesNotMislabelProviderValueEqualToDefault(t *testing.T) {
	scope := featureFlagTestScope(t)
	driver := &fakeDriver{evaluateFn: func(_ context.Context, got DriverRequest) (DriverDecision, error) {
		return decisionFromRequest(got, true, false, 0), nil
	}}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	decision, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.inventory", Default: true})
	if err != nil {
		t.Fatal(err)
	}
	if decision != (Decision{Value: true, UsedDefault: false, Cache: CacheMetadata{Hit: false, Age: 0}}) {
		t.Fatalf("decision = %#v, want provider decision equal to default", decision)
	}
}

func TestEvaluatorRejectsInvalidConstruction(t *testing.T) {
	validDriver := &fakeDriver{}
	validConfig := Config{OperationTimeout: time.Second, MaximumCacheAge: time.Hour}
	var typedNil *fakeDriver
	tests := map[string]struct {
		driver Driver
		config Config
	}{
		"nil driver":             {config: validConfig},
		"typed nil driver":       {driver: typedNil, config: validConfig},
		"zero timeout":           {driver: validDriver, config: Config{MaximumCacheAge: time.Hour}},
		"negative timeout":       {driver: validDriver, config: Config{OperationTimeout: -time.Nanosecond, MaximumCacheAge: time.Hour}},
		"timeout over limit":     {driver: validDriver, config: Config{OperationTimeout: 30*time.Second + time.Nanosecond, MaximumCacheAge: time.Hour}},
		"zero maximum cache age": {driver: validDriver, config: Config{OperationTimeout: time.Second}},
		"negative cache age":     {driver: validDriver, config: Config{OperationTimeout: time.Second, MaximumCacheAge: -time.Nanosecond}},
		"cache age over limit":   {driver: validDriver, config: Config{OperationTimeout: time.Second, MaximumCacheAge: 24*time.Hour + time.Nanosecond}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			evaluator, err := New(test.driver, test.config)
			if !errors.Is(err, ErrConfiguration) || evaluator != nil {
				t.Fatalf("New = %#v, %v; want nil, ErrConfiguration", evaluator, err)
			}
		})
	}
}

func TestEvaluatorRejectsInvalidRequestBeforeIO(t *testing.T) {
	validScope := featureFlagTestScope(t)
	invalidKeys := []string{
		"", "A", ".ui", "ui.", "ui..flag", "ui__flag", "ui--flag",
		"ui/+flag", "ui flag", "ui\nflag", "fëature", strings.Repeat("a", 128),
	}
	tests := map[string]struct {
		scope domain.Scope
		key   string
	}{
		"zero scope": {key: "ui.flag"},
	}
	for index, key := range invalidKeys {
		tests[fmt.Sprintf("invalid key %d", index)] = struct {
			scope domain.Scope
			key   string
		}{scope: validScope, key: key}
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			driver := &fakeDriver{}
			evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Hour})
			decision, err := evaluator.Evaluate(context.Background(), test.scope, Request{Key: test.key, Default: true})
			if !errors.Is(err, ErrRequest) || decision != (Decision{}) {
				t.Fatalf("Evaluate = %#v, %v; want zero, ErrRequest", decision, err)
			}
			if driver.callCount() != 0 {
				t.Fatalf("driver calls = %d, want 0", driver.callCount())
			}
		})
	}
}

func TestEvaluatorAcceptsExactKeyGrammar(t *testing.T) {
	for _, key := range []string{"a", "ui.flag", "experiment_2", "launch-darkly", strings.Repeat("a", 127)} {
		t.Run(key[:min(len(key), 24)], func(t *testing.T) {
			evaluator := mustEvaluator(t, &fakeDriver{}, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Hour})
			if _, err := evaluator.Evaluate(context.Background(), featureFlagTestScope(t), Request{Key: key}); err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
		})
	}
}

func TestEvaluatorFallsBackOnUnavailableOrMalformedDriverState(t *testing.T) {
	scope := featureFlagTestScope(t)
	providerError := errors.New("provider endpoint credential-shaped-value")
	base := decisionFromRequest(driverRequest(scope, "ui.flag"), true, true, time.Second)
	tests := map[string]func(context.Context, DriverRequest) (DriverDecision, error){
		"driver error": func(context.Context, DriverRequest) (DriverDecision, error) {
			return DriverDecision{}, providerError
		},
		"driver panic": func(context.Context, DriverRequest) (DriverDecision, error) {
			panic("provider panic credential-shaped-value")
		},
		"empty success": func(context.Context, DriverRequest) (DriverDecision, error) {
			return DriverDecision{}, nil
		},
		"organization drift": mutateDecision(base, func(value *DriverDecision) { value.OrganizationID = featureFlagTestID(t, 9).String() }),
		"workspace drift":    mutateDecision(base, func(value *DriverDecision) { value.WorkspaceID = featureFlagTestID(t, 9).String() }),
		"environment drift":  mutateDecision(base, func(value *DriverDecision) { value.EnvironmentID = featureFlagTestID(t, 9).String() }),
		"key drift":          mutateDecision(base, func(value *DriverDecision) { value.Key = "ui.other" }),
		"miss with age":      mutateDecision(base, func(value *DriverDecision) { value.CacheHit = false }),
		"negative hit age":   mutateDecision(base, func(value *DriverDecision) { value.CacheAge = -time.Nanosecond }),
		"over-age hit":       mutateDecision(base, func(value *DriverDecision) { value.CacheAge = time.Minute + time.Nanosecond }),
	}
	for name, evaluateFn := range tests {
		for _, defaultValue := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s default=%t", name, defaultValue), func(t *testing.T) {
				driver := &fakeDriver{evaluateFn: evaluateFn}
				evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
				decision, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.flag", Default: defaultValue})
				if err != nil {
					t.Fatalf("Evaluate returned error: %v", err)
				}
				want := Decision{Value: defaultValue, UsedDefault: true}
				if decision != want {
					t.Fatalf("decision = %#v, want %#v", decision, want)
				}
				if driver.callCount() != 1 {
					t.Fatalf("driver calls = %d, want 1", driver.callCount())
				}
			})
		}
	}
}

func TestEvaluatorFallsBackOnCancellationAndDeadline(t *testing.T) {
	scope := featureFlagTestScope(t)
	driver := &fakeDriver{}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := evaluator.Evaluate(cancelled, scope, Request{Key: "ui.flag", Default: true})
	if err != nil || decision != (Decision{Value: true, UsedDefault: true}) {
		t.Fatalf("cancelled Evaluate = %#v, %v; want true fallback", decision, err)
	}
	if driver.callCount() != 0 {
		t.Fatalf("cancelled driver calls = %d, want 0", driver.callCount())
	}

	deadlineDriver := &fakeDriver{evaluateFn: func(ctx context.Context, _ DriverRequest) (DriverDecision, error) {
		<-ctx.Done()
		return DriverDecision{}, ctx.Err()
	}}
	deadlineEvaluator := mustEvaluator(t, deadlineDriver, Config{OperationTimeout: time.Millisecond, MaximumCacheAge: time.Minute})
	decision, err = deadlineEvaluator.Evaluate(context.Background(), scope, Request{Key: "ui.flag", Default: false})
	if err != nil || decision != (Decision{Value: false, UsedDefault: true}) {
		t.Fatalf("deadline Evaluate = %#v, %v; want false fallback", decision, err)
	}
}

func TestEvaluatorRejectsNilContextAndUnusableReceiver(t *testing.T) {
	scope := featureFlagTestScope(t)
	evaluator := mustEvaluator(t, &fakeDriver{}, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	if decision, err := evaluator.Evaluate(nil, scope, Request{Key: "ui.flag"}); !errors.Is(err, ErrRequest) || decision != (Decision{}) {
		t.Fatalf("nil-context Evaluate = %#v, %v; want zero, ErrRequest", decision, err)
	}
	var nilEvaluator *Evaluator
	if decision, err := nilEvaluator.Evaluate(context.Background(), scope, Request{Key: "ui.flag"}); !errors.Is(err, ErrConfiguration) || decision != (Decision{}) {
		t.Fatalf("nil-receiver Evaluate = %#v, %v; want zero, ErrConfiguration", decision, err)
	}
}

func TestEvaluatorKeepsConcurrentDefaultsIsolated(t *testing.T) {
	scope := featureFlagTestScope(t)
	driver := &fakeDriver{evaluateFn: func(context.Context, DriverRequest) (DriverDecision, error) {
		return DriverDecision{}, errors.New("outage")
	}}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	const count = 64
	errorsByCall := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		defaultValue := index%2 == 0
		wait.Add(1)
		go func() {
			defer wait.Done()
			decision, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.concurrent", Default: defaultValue})
			if err == nil && decision != (Decision{Value: defaultValue, UsedDefault: true}) {
				err = fmt.Errorf("decision = %#v, want default %t", decision, defaultValue)
			}
			errorsByCall <- err
		}()
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		if err != nil {
			t.Fatal(err)
		}
	}
	if driver.callCount() != count {
		t.Fatalf("driver calls = %d, want %d", driver.callCount(), count)
	}
}

func mustEvaluator(t *testing.T, driver Driver, config Config) *Evaluator {
	t.Helper()
	evaluator, err := New(driver, config)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return evaluator
}

func featureFlagTestScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(featureFlagTestID(t, 1), featureFlagTestID(t, 2), featureFlagTestID(t, 3))
	if err != nil {
		t.Fatalf("NewScope returned error: %v", err)
	}
	return scope
}

func featureFlagTestID(t *testing.T, suffix byte) domain.ProductID {
	t.Helper()
	text := fmt.Sprintf("pid_00000000-0000-4000-8000-%012x", suffix)
	id, err := domain.ParseProductID(text)
	if err != nil {
		t.Fatalf("ParseProductID(%q) returned error: %v", text, err)
	}
	return id
}

func driverRequest(scope domain.Scope, key string) DriverRequest {
	return DriverRequest{
		OrganizationID: scope.OrganizationID().String(),
		WorkspaceID:    scope.WorkspaceID().String(),
		EnvironmentID:  scope.EnvironmentID().String(),
		Key:            key,
	}
}

func decisionFromRequest(request DriverRequest, value, cacheHit bool, cacheAge time.Duration) DriverDecision {
	return DriverDecision{
		OrganizationID: request.OrganizationID,
		WorkspaceID:    request.WorkspaceID,
		EnvironmentID:  request.EnvironmentID,
		Key:            request.Key,
		Value:          value,
		CacheHit:       cacheHit,
		CacheAge:       cacheAge,
	}
}

func mutateDecision(base DriverDecision, mutate func(*DriverDecision)) func(context.Context, DriverRequest) (DriverDecision, error) {
	return func(context.Context, DriverRequest) (DriverDecision, error) {
		decision := base
		mutate(&decision)
		return decision, nil
	}
}
