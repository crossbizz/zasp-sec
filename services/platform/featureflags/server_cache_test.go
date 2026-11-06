package featureflags

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestServerFlagCacheReusesAuthoritativeDecisionAcrossCodeDefaults(t *testing.T) {
	driver := &fakeDriver{}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	scope := featureFlagTestScope(t)
	first, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.cache", Default: DefaultEnabled})
	if err != nil || !first.Value || first.UsedDefault {
		t.Fatal("authentic provider value equal to default was lost")
	}
	second, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.cache", Default: DefaultDisabled})
	if err != nil || !second.Value || second.UsedDefault || !second.Cache.Hit || driver.callCount() != 1 {
		t.Fatal("validated server decision was not cached independently of request default")
	}
}
func TestServerFlagCacheSeparatesEveryTenantDimensionAndKey(t *testing.T) {
	base := featureFlagTestScope(t)
	makeScope := func(o, w, e byte) domain.Scope {
		scope, err := domain.NewScope(featureFlagTestID(t, o), featureFlagTestID(t, w), featureFlagTestID(t, e))
		if err != nil {
			t.Fatal(err)
		}
		return scope
	}
	cases := []struct {
		scope domain.Scope
		key   string
	}{{base, "ui.scope"}, {makeScope(4, 2, 3), "ui.scope"}, {makeScope(1, 5, 3), "ui.scope"}, {makeScope(1, 2, 6), "ui.scope"}, {base, "ui.other"}}
	driver := &fakeDriver{evaluateFn: func(_ context.Context, r DriverRequest) (DriverDecision, error) {
		return decisionFromRequest(r, r.Key == "ui.other" || r.OrganizationID != base.OrganizationID().String(), false, 0), nil
	}}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	for index, item := range cases {
		request := Request{Key: item.key, Default: DefaultDisabled}
		first, err := evaluator.Evaluate(context.Background(), item.scope, request)
		want := item.key == "ui.other" || item.scope.OrganizationID() != base.OrganizationID()
		if err != nil || first.Value != want || first.UsedDefault || driver.callCount() != index+1 {
			t.Fatal("cache aliased organization, workspace, environment, or key")
		}
		second, err := evaluator.Evaluate(context.Background(), item.scope, request)
		if err != nil || second.Value != want || second.UsedDefault || !second.Cache.Hit || driver.callCount() != index+1 {
			t.Fatal("exact scoped cached decision was not reused")
		}
	}
}
func TestServerFlagCacheRetainsProviderAge(t *testing.T) {
	const age = 45 * time.Second
	driver := &fakeDriver{evaluateFn: func(_ context.Context, r DriverRequest) (DriverDecision, error) {
		return decisionFromRequest(r, false, true, age), nil
	}}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	scope := featureFlagTestScope(t)
	request := Request{Key: "ui.provider-age", Default: DefaultEnabled}
	if _, err := evaluator.Evaluate(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	decision, err := evaluator.Evaluate(context.Background(), scope, request)
	if err != nil || decision.Value || decision.UsedDefault || !decision.Cache.Hit || decision.Cache.Age < age || decision.Cache.Age > time.Minute || driver.callCount() != 1 {
		t.Fatal("server cache reset provider age or reissued a fresh hit")
	}
}
func TestServerFlagCacheNeverCachesUnavailableDefaults(t *testing.T) {
	unavailable := true
	driver := &fakeDriver{evaluateFn: func(_ context.Context, r DriverRequest) (DriverDecision, error) {
		if unavailable {
			return DriverDecision{}, errors.New("provider outage")
		}
		return decisionFromRequest(r, false, false, 0), nil
	}}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	scope := featureFlagTestScope(t)
	for _, fallback := range []CodeDefault{DefaultEnabled, DefaultDisabled} {
		decision, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.outage", Default: fallback})
		if err != nil || !decision.UsedDefault || decision.Value != (fallback == DefaultEnabled) || decision.Cache.Hit {
			t.Fatal("outage fallback was cached or lost current request default")
		}
	}
	unavailable = false
	request := Request{Key: "ui.outage", Default: DefaultEnabled}
	if decision, err := evaluator.Evaluate(context.Background(), scope, request); err != nil || decision.Value || decision.UsedDefault {
		t.Fatal("prior default prevented authentic provider recovery")
	}
	decision, err := evaluator.Evaluate(context.Background(), scope, request)
	if err != nil || decision.Value || decision.UsedDefault || !decision.Cache.Hit || driver.callCount() != 3 {
		t.Fatal("provider recovery did not populate actual server cache")
	}
}
func TestServerFlagCacheValidatesCancellationAndDefaultsBeforeWarmHit(t *testing.T) {
	driver := &fakeDriver{}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	scope := featureFlagTestScope(t)
	request := Request{Key: "ui.validation", Default: DefaultDisabled}
	if _, err := evaluator.Evaluate(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err := evaluator.Evaluate(canceled, scope, request)
	if err != nil || decision != (Decision{Value: false, UsedDefault: true}) || driver.callCount() != 1 {
		t.Fatal("warm cache bypassed cancellation fallback")
	}
	if _, err = evaluator.Evaluate(context.Background(), scope, Request{Key: request.Key}); !errors.Is(err, ErrRequest) || driver.callCount() != 1 {
		t.Fatal("warm cache bypassed explicit code default validation")
	}
}
func TestServerFlagCacheConcurrentWarmHitsRemainScoped(t *testing.T) {
	driver := &fakeDriver{evaluateFn: func(_ context.Context, r DriverRequest) (DriverDecision, error) {
		return decisionFromRequest(r, false, false, 0), nil
	}}
	evaluator := mustEvaluator(t, driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute})
	scope := featureFlagTestScope(t)
	if _, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.warm", Default: DefaultEnabled}); err != nil {
		t.Fatal(err)
	}
	const count = 64
	start := make(chan struct{})
	results := make(chan bool, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		fallback := DefaultDisabled
		if index%2 == 0 {
			fallback = DefaultEnabled
		}
		wait.Add(1)
		go func(defaultValue CodeDefault) {
			defer wait.Done()
			<-start
			decision, err := evaluator.Evaluate(context.Background(), scope, Request{Key: "ui.warm", Default: defaultValue})
			results <- err == nil && !decision.Value && !decision.UsedDefault && decision.Cache.Hit
		}(fallback)
	}
	close(start)
	wait.Wait()
	close(results)
	for valid := range results {
		if !valid {
			t.Fatal("concurrent warm hit lost authentic scoped cache decision")
		}
	}
	if driver.callCount() != 1 {
		t.Fatal("concurrent warm server cache reissued provider requests")
	}
}
