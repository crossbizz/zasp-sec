package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	platformdatabase "github.com/zasp-ai/zasp-sec/services/platform/database"
)

const productPoolSuccessSummary = "Neon pool wrapper passed: reads=10 waited=true in_use=true acquired=0 closed=true."

var (
	errPoolStats = errors.New("pool statistics failed")
	errPoolClose = errors.New("pool close failed")
)

type productPoolOpener func(context.Context, validatedConnection) (*platformdatabase.Pool, error)

type pgxProductDriver struct {
	pool *pgxpool.Pool
}

func prepareProductPGXPoolConfig(target validatedConnection) (*pgxpool.Config, error) {
	config, err := preparePGXPoolConfig(target)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 2
	config.MinConns = 0
	config.MinIdleConns = 0
	return config, nil
}

func openProductPool(ctx context.Context, target validatedConnection) (*platformdatabase.Pool, error) {
	config, err := prepareProductPGXPoolConfig(target)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	wrapper, err := platformdatabase.New(&pgxProductDriver{pool: pool}, platformdatabase.Config{
		QueryTimeout:  5 * time.Second,
		HealthTimeout: 5 * time.Second,
	})
	if err != nil {
		pool.Close()
		return nil, err
	}
	return wrapper, nil
}

func (driver *pgxProductDriver) QueryRow(ctx context.Context, statement string, arguments ...any) platformdatabase.Row {
	return driver.pool.QueryRow(ctx, statement, arguments...)
}

func (driver *pgxProductDriver) Ping(ctx context.Context) error {
	return driver.pool.Ping(ctx)
}

func (driver *pgxProductDriver) Stats() platformdatabase.DriverStats {
	stats := driver.pool.Stat()
	return platformdatabase.DriverStats{
		InUse:             stats.AcquiredConns(),
		Idle:              stats.IdleConns(),
		Constructing:      stats.ConstructingConns(),
		Total:             stats.TotalConns(),
		Maximum:           stats.MaxConns(),
		WaitCount:         stats.EmptyAcquireCount(),
		CanceledWaitCount: stats.CanceledAcquireCount(),
		WaitDuration:      stats.EmptyAcquireWaitTime(),
	}
}

func (driver *pgxProductDriver) Close() {
	driver.pool.Close()
}

func executeProductPoolProof(ctx context.Context, rawURL string, open productPoolOpener, pollInterval time.Duration) (summary string, resultErr error) {
	if ctx == nil || open == nil || pollInterval <= 0 {
		return "", errConfiguration
	}
	target, err := validatedPGXConnection(rawURL)
	if err != nil {
		return "", errConfiguration
	}
	pool, err := open(ctx, target)
	if err != nil {
		if pool != nil {
			if closeErr := pool.Close(); closeErr != nil {
				return "", errPoolClose
			}
		}
		return "", errPoolSetup
	}
	if pool == nil {
		return "", errPoolSetup
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		if err := pool.Close(); err != nil {
			summary = ""
			resultErr = errPoolClose
		}
	}()

	baseline, err := pool.Health(ctx)
	if err != nil {
		return "", errPoolStats
	}
	results := make(chan readRunResult, 1)
	go func() {
		results <- runConcurrentReads(ctx, func(readCtx context.Context) error {
			var value int
			if err := pool.QueryRow(readCtx, readQuery, nil, &value); err != nil || value != 1 {
				return errConcurrentReads
			}
			return nil
		})
	}()

	observedContention := false
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	var result readRunResult
waitForResult:
	for {
		select {
		case result = <-results:
			break waitForResult
		case <-ticker.C:
			stats, err := pool.Stats()
			if err != nil {
				return "", errPoolStats
			}
			if stats.WaitCount > baseline.WaitCount && stats.InUse > 0 {
				observedContention = true
			}
		case <-ctx.Done():
			result = <-results
			break waitForResult
		}
	}
	if len(result.failures) != 0 {
		return "", errConcurrentReads
	}
	if result.completed != concurrentReadCount {
		return "", errReadCount
	}
	stats, err := pool.Stats()
	if err != nil || !observedContention || stats.WaitCount <= baseline.WaitCount || stats.InUse != 0 {
		return "", errPoolStats
	}
	if err := pool.Close(); err != nil {
		closed = true
		return "", errPoolClose
	}
	closed = true
	stats, err = pool.Stats()
	if err != nil || !stats.Closed || stats.Total != 0 || stats.InUse != 0 {
		return "", errPoolClose
	}
	return productPoolSuccessSummary, nil
}

var _ platformdatabase.Driver = (*pgxProductDriver)(nil)

var _ platformdatabase.Row = (pgx.Row)(nil)
