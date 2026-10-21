package featureflags

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestServerFlagCacheExpiryRetainsProviderAgeAndRefusesStaleOutage(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	start := now
	outage := false
	driver := &fakeDriver{evaluateFn: func(_ context.Context, r DriverRequest) (DriverDecision, error) {
		if outage {
			return DriverDecision{}, errors.New("unavailable")
		}
		return decisionFromRequest(r, true, true, 45*time.Second), nil
	}}
	evaluator, err := newWithClock(driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := featureFlagTestScope(t)
	request := Request{Key: "ui.expiry", Default: DefaultDisabled}
	if _, err := evaluator.Evaluate(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	now = start.Add(15 * time.Second)
	outage = true
	hit, err := evaluator.Evaluate(context.Background(), scope, request)
	if err != nil || !hit.Value || hit.UsedDefault || !hit.Cache.Hit || hit.Cache.Age != time.Minute || driver.callCount() != 1 {
		t.Fatal("exact max age must retain valid provider decision without inventing an unseen outage")
	}
	now = now.Add(time.Nanosecond)
	expired, err := evaluator.Evaluate(context.Background(), scope, request)
	if err != nil || expired.Value || !expired.UsedDefault || expired.Cache.Hit || driver.callCount() != 2 {
		t.Fatal("expired provider decision survived observed outage")
	}
	request.Default = DefaultEnabled
	again, err := evaluator.Evaluate(context.Background(), scope, request)
	if err != nil || !again.Value || !again.UsedDefault || driver.callCount() != 3 {
		t.Fatal("failed refresh cached a default")
	}
}

func TestServerFlagCacheBackwardObservationInvalidatesPreviouslyAgedDecision(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	start := now
	outage := false
	driver := &fakeDriver{evaluateFn: func(_ context.Context, r DriverRequest) (DriverDecision, error) {
		if outage {
			return DriverDecision{}, errors.New("unavailable")
		}
		return decisionFromRequest(r, true, false, 0), nil
	}}
	evaluator, err := newWithClock(driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := featureFlagTestScope(t)
	request := Request{Key: "ui.clock", Default: DefaultDisabled}
	if _, err := evaluator.Evaluate(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	now = start.Add(10 * time.Second)
	if d, err := evaluator.Evaluate(context.Background(), scope, request); err != nil || d.Cache.Age != 10*time.Second || !d.Cache.Hit {
		t.Fatal("forward clock did not age hit")
	}
	now = start.Add(5 * time.Second)
	outage = true
	if d, err := evaluator.Evaluate(context.Background(), scope, request); err != nil || !d.UsedDefault || d.Value || driver.callCount() != 2 {
		t.Fatal("backward observation shrank cached age instead of invalidating it")
	}
}

func TestServerFlagCacheBoundedLRUEvictsOldestUntouchedDecision(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	driver := &fakeDriver{}
	evaluator, err := newWithClock(driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := featureFlagTestScope(t)
	evaluate := func(index int) Decision {
		t.Helper()
		d, err := evaluator.Evaluate(context.Background(), scope, Request{Key: fmt.Sprintf("ui.bound%d", index), Default: DefaultDisabled})
		if err != nil || d.UsedDefault {
			t.Fatal("authentic bounded cache request failed")
		}
		return d
	}
	for i := 0; i < 1024; i++ {
		evaluate(i)
	}
	if !evaluate(0).Cache.Hit || driver.callCount() != 1024 {
		t.Fatal("recently touched oldest value was not reused")
	}
	evaluate(1024)
	if !evaluate(0).Cache.Hit || driver.callCount() != 1025 {
		t.Fatal("LRU discarded touched value")
	}
	evaluate(1)
	if driver.callCount() != 1026 {
		t.Fatal("bounded cache retained the least recently used overflow entry")
	}
}

func TestServerFlagCacheRechecksCancellationDuringLookupAndStore(t *testing.T) {
	for _, stage := range []string{"lookup", "store"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
			armed := false
			clockCalls := 0
			clock := func() time.Time {
				clockCalls++
				if armed && (stage == "lookup" || clockCalls == 2) {
					cancel()
				}
				return now
			}
			driver := &fakeDriver{}
			evaluator, err := newWithClock(driver, Config{OperationTimeout: time.Second, MaximumCacheAge: time.Minute}, clock)
			if err != nil {
				t.Fatal(err)
			}
			scope := featureFlagTestScope(t)
			request := Request{Key: "ui.cancel-clock", Default: DefaultDisabled}
			if stage == "lookup" {
				if _, err := evaluator.Evaluate(context.Background(), scope, request); err != nil {
					t.Fatal(err)
				}
			}
			armed = true
			d, err := evaluator.Evaluate(ctx, scope, request)
			if err != nil || !d.UsedDefault || d.Value {
				t.Fatal("cancellation during cache operation returned authentic value")
			}
			if driver.callCount() != 1 {
				t.Fatal("lookup cancellation called provider or store fixture missed provider")
			}
			armed = false
			fresh, err := evaluator.Evaluate(context.Background(), scope, request)
			if err != nil || fresh.UsedDefault || !fresh.Value {
				t.Fatal("uncanceled request did not recover")
			}
			if stage == "store" && driver.callCount() != 2 {
				t.Fatal("canceled refresh was stored")
			}
		})
	}
}
