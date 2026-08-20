package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/healthserver"
)

type workerProcessor interface{ RunOnce(context.Context) error }

type workerRuntimeDependencies struct {
	Processor workerProcessor
	Ready     func(context.Context) error
	Close     func() error
}

func buildWorkerRuntime(ctx context.Context, config workerRuntimeConfig) (workerRuntimeDependencies, error) {
	connectCtx, cancel := context.WithTimeout(ctx, minDuration(config.LeaseDuration/2, 5*time.Second))
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(config.PostgresDSN)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	poolConfig.MaxConns, poolConfig.MinConns = int32(config.BatchSize+2), 1
	poolConfig.HealthCheckPeriod = config.PollInterval
	pool, err := pgxpool.NewWithConfig(connectCtx, poolConfig)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	database, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		pool.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	dependencies, err := composeWorkerRuntime(config, database)
	if err != nil {
		_ = database.Close()
		return workerRuntimeDependencies{}, err
	}
	dependencies.Close = database.Close
	return dependencies, nil
}

func composeWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || database == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	switch config.Mode {
	case workerModeScheduler:
		repository, err := apiserver.NewDiscoveryExecutionRepository(database, apiserver.DiscoveryExecutionAuthorityScheduler)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		processor, err := newSchedulerProcessor(schedulerProcessorConfig{Authority: repository, WorkerID: config.WorkerID, LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken})
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return workerRuntimeDependencies{Processor: processor, Ready: repository.Ready, Close: func() error { return nil }}, nil
	default:
		// Modes with an external provider or projection side effect are composed
		// only when their exact production driver is supplied. Returning unavailable
		// keeps the workload and public capability honest.
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
}

func serveWorkerRuntime(ctx context.Context, output interface{ Write([]byte) (int, error) }, version string, config workerRuntimeConfig, dependencies workerRuntimeDependencies, listen func(string, string) (net.Listener, error)) error {
	if ctx == nil || output == nil || !validBuildVersion(version) || !validWorkerRuntimeConfig(config) || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil || listen == nil {
		return errRuntimeUnavailable
	}
	defer dependencies.Close()
	if err := run(output, version); err != nil {
		return err
	}
	listener, err := listen("tcp", healthListenAddress)
	if err != nil || listener == nil {
		return errRuntimeUnavailable
	}
	var executingReady atomic.Bool
	server, err := healthserver.New(healthserver.Config{Service: "agentsec-worker", Version: version, ReadyInterval: maxDuration(config.PollInterval, 100*time.Millisecond), ReadyMaxInterval: minDuration(maxDuration(config.PollInterval*8, time.Second), time.Minute), ReadyCheck: func(checkCtx context.Context) bool {
		return executingReady.Load() && dependencies.Ready(checkCtx) == nil
	}})
	if err != nil {
		_ = listener.Close()
		return errRuntimeUnavailable
	}
	loopDone := make(chan struct{})
	go func() {
		runWorkerPollingLoop(ctx, dependencies.Processor, config.PollInterval, &executingReady)
		close(loopDone)
	}()
	serveErr := server.Serve(ctx, listener)
	shutdownTimer := time.NewTimer(config.ShutdownTimeout)
	select {
	case <-loopDone:
		if !shutdownTimer.Stop() {
			<-shutdownTimer.C
		}
	case <-shutdownTimer.C:
		executingReady.Store(false)
	}
	if serveErr != nil {
		return errRuntimeUnavailable
	}
	return nil
}

func runWorkerPollingLoop(ctx context.Context, processor workerProcessor, interval time.Duration, ready *atomic.Bool) {
	if ctx == nil || processor == nil || ready == nil || interval <= 0 {
		return
	}
	for {
		ready.Store(processor.RunOnce(ctx) == nil)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			ready.Store(false)
			return
		case <-timer.C:
		}
	}
}

func newWorkerLeaseToken() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", errWorkerExecution
	}
	return hex.EncodeToString(value), nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}
func maxDuration(left, right time.Duration) time.Duration {
	if left > right {
		return left
	}
	return right
}

type workerPostgresDriver struct{ pool *pgxpool.Pool }

func (driver *workerPostgresDriver) QueryRow(ctx context.Context, statement string, arguments ...any) apiserver.PostgresRow {
	if driver == nil || driver.pool == nil {
		return workerUnavailableRow{}
	}
	return driver.pool.QueryRow(ctx, statement, arguments...)
}
func (driver *workerPostgresDriver) Exec(ctx context.Context, statement string, arguments ...any) error {
	if driver == nil || driver.pool == nil {
		return errors.New("database unavailable")
	}
	_, err := driver.pool.Exec(ctx, statement, arguments...)
	return err
}
func (driver *workerPostgresDriver) Close() error {
	if driver != nil && driver.pool != nil {
		driver.pool.Close()
	}
	return nil
}

type workerUnavailableRow struct{}

func (workerUnavailableRow) Scan(...any) error { return errors.New("database unavailable") }
