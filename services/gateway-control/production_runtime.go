package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/gatewaycontrol"
)

type productionControlDependencies struct {
	Handler http.Handler
	Ready   func(context.Context) error
	Close   func() error
}

type productionRepositoryFactory func(context.Context, string, time.Duration) (gatewaycontrol.Repository, func() error, error)

type cachedControlRepository struct {
	gatewaycontrol.Repository
	ready func(context.Context) error
}

func (repository cachedControlRepository) Ready(ctx context.Context) error {
	if repository.ready == nil {
		return errControlUnavailable
	}
	return repository.ready(ctx)
}

type productionReadinessCache struct {
	mu      sync.Mutex
	check   func(context.Context) error
	timeout time.Duration
	ttl     time.Duration
	clock   func() time.Time
	last    time.Time
}

func newProductionReadinessCache(check func(context.Context) error, timeout, ttl time.Duration, clock func() time.Time) (*productionReadinessCache, error) {
	if check == nil || timeout < 50*time.Millisecond || timeout > 10*time.Second || ttl < time.Second || ttl > 5*time.Minute || clock == nil {
		return nil, errControlUnavailable
	}
	return &productionReadinessCache{check: check, timeout: timeout, ttl: ttl, clock: clock}, nil
}

func (cache *productionReadinessCache) Ready(ctx context.Context) error {
	if cache == nil || cache.check == nil || cache.clock == nil || ctx == nil || ctx.Err() != nil {
		return errControlUnavailable
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.clock()
	if now.IsZero() || now.Location() != time.UTC || now.Nanosecond() != 0 {
		return errControlUnavailable
	}
	if !cache.last.IsZero() && !now.Before(cache.last) && now.Sub(cache.last) < cache.ttl {
		return nil
	}
	operation, cancel := context.WithTimeout(ctx, cache.timeout)
	err := cache.check(operation)
	operationErr := operation.Err()
	cancel()
	if err != nil || operationErr != nil {
		return errControlUnavailable
	}
	cache.last = now
	return nil
}

func buildProductionControlDependencies(ctx context.Context, config productionControlConfig) (productionControlDependencies, error) {
	return buildProductionControlDependenciesWithFactory(ctx, config, newProductionPostgresRepository, controlUTCNow)
}

func buildProductionControlDependenciesWithFactory(ctx context.Context, config productionControlConfig, factory productionRepositoryFactory, clock func() time.Time) (productionControlDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validProductionControlConfig(config) || factory == nil || clock == nil {
		return productionControlDependencies{}, errControlUnavailable
	}
	repository, closeRepository, err := factory(ctx, config.DatabaseURL, config.OperationTimeout)
	if err != nil || invalidProductionValue(repository) || closeRepository == nil {
		if closeRepository != nil {
			_ = closeRepository()
		}
		return productionControlDependencies{}, errControlUnavailable
	}
	failRepository := func() (productionControlDependencies, error) {
		_ = closeRepository()
		return productionControlDependencies{}, errControlUnavailable
	}
	readiness, err := newProductionReadinessCache(repository.Ready, config.OperationTimeout, config.ReadinessTTL, clock)
	if err != nil || readiness.Ready(ctx) != nil {
		return failRepository()
	}
	cached := cachedControlRepository{Repository: repository, ready: readiness.Ready}
	handler, err := gatewaycontrol.NewHTTPHandler(gatewaycontrol.HTTPHandlerConfig{
		Repository: cached, Clock: clock, OperationTimeout: config.OperationTimeout, MaximumBodyBytes: config.MaximumBodyBytes,
	})
	if err != nil {
		return failRepository()
	}
	var closeOnce sync.Once
	var closeErr error
	closeDependencies := func() error {
		closeOnce.Do(func() {
			if err := closeRepository(); err != nil {
				closeErr = errControlUnavailable
			}
		})
		return closeErr
	}
	return productionControlDependencies{Handler: handler, Ready: readiness.Ready, Close: closeDependencies}, nil
}

func newProductionPostgresRepository(ctx context.Context, databaseURL string, timeout time.Duration) (gatewaycontrol.Repository, func() error, error) {
	operation, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, nil, errControlUnavailable
	}
	poolConfig.MaxConns, poolConfig.MinConns = 20, 2
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(operation, poolConfig)
	if err != nil {
		return nil, nil, errControlUnavailable
	}
	closePool := func() error { pool.Close(); return nil }
	if pool.Ping(operation) != nil || operation.Err() != nil {
		_ = closePool()
		return nil, nil, errControlUnavailable
	}
	repository, err := gatewaycontrol.NewPostgresRepository(pool, timeout)
	if err != nil {
		_ = closePool()
		return nil, nil, errControlUnavailable
	}
	return repository, closePool, nil
}

func controlUTCNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

var _ gatewaycontrol.Repository = cachedControlRepository{}
