package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
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
	dependencies, err := composeWorkerRuntime(connectCtx, config, database)
	if err != nil {
		_ = database.Close()
		return workerRuntimeDependencies{}, err
	}
	closeDependencies := dependencies.Close
	dependencies.Close = func() error {
		dependencyErr := closeDependencies()
		databaseErr := database.Close()
		if dependencyErr != nil {
			return dependencyErr
		}
		return databaseErr
	}
	return dependencies, nil
}

func composeWorkerRuntime(ctx context.Context, config workerRuntimeConfig, database apiserver.JSONDatabase) (workerRuntimeDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validWorkerRuntimeConfig(config) || database == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	switch config.Mode {
	case workerModeOutbox:
		publisher, err := newProductionOutboxPublisher(ctx, config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeOutboxWorkerRuntime(config, database, publisher.publisher, publisher.ready)
		if err != nil {
			_ = publisher.close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies.Close = publisher.close
		return dependencies, nil
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
	case workerModeDiscovery:
		discovery, err := newProductionDiscoveryDependencies(productionDiscoveryDependenciesConfig(config))
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		dependencies, err := composeDiscoveryWorkerRuntime(config, database, discovery)
		if err != nil {
			_ = discovery.Close()
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return dependencies, nil
	case workerModeProjectionSearch:
		projector, err := newProductionSearchProjection(ctx, config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composeProjectionWorkerRuntime(config, database, projector)
	case workerModeProjectionGraph:
		projector, err := newProductionGraphProjection(ctx, config)
		if err != nil {
			return workerRuntimeDependencies{}, errRuntimeUnavailable
		}
		return composeProjectionWorkerRuntime(config, database, projector)
	default:
		// Modes with an external provider or projection side effect are composed
		// only when their exact production driver is supplied. Returning unavailable
		// keeps the workload and public capability honest.
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
}

func productionDiscoveryDependenciesConfig(config workerRuntimeConfig) productionDiscoveryDependencyConfig {
	return productionDiscoveryDependencyConfig{
		Cloud:       productionDiscoveryCloudConfig{Region: config.AWSRegion, RoleARN: config.DiscoveryRoleARN, TokenFile: config.DiscoveryTokenFile, SecretRoot: config.DiscoverySecretPrefix, Timeout: config.ProviderTimeout, Clock: func() time.Time { return time.Now().UTC() }},
		Artifacts:   productionDiscoveryArtifactConfig{Bucket: config.EvidenceBucket, ExpectedBucketOwner: config.EvidenceOwner, KMSKeyARN: config.EvidenceKMSKeyARN, OperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), MaximumBytes: 64 << 20},
		GitHubAppID: config.GitHubAppID, GitHubPrivateKeyReference: config.GitHubPrivateKeyReference, OktaClientID: config.OktaClientID, OktaClientSecretReference: config.OktaClientSecretReference,
		AWSCollectorVersion: config.AWSCollectorVersion, KubernetesCollectorVersion: config.KubernetesCollectorVersion, GitHubCollectorVersion: config.GitHubCollectorVersion, OktaCollectorVersion: config.OktaCollectorVersion,
		ParserVersion: config.ParserVersion, ToolVersion: config.ToolVersion, KubernetesAllowedCIDRs: config.KubernetesEgressCIDRs, ProviderTimeout: config.ProviderTimeout, ReadinessTimeout: config.DiscoveryReadinessTimeout,
		QueueURL: config.DiscoveryQueueURL, QueueOperationTimeout: minDuration(config.LeaseDuration/3, 30*time.Second), LeaseDuration: config.LeaseDuration, ShutdownTimeout: config.ShutdownTimeout,
	}
}

func composeDiscoveryWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, discovery *productionDiscoveryDependencies) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || config.Mode != workerModeDiscovery || database == nil || discovery == nil || discovery.Factory == nil || discovery.Queue == nil || discovery.ready == nil || discovery.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewDiscoveryExecutionRepository(database, apiserver.DiscoveryExecutionAuthorityWorker)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newDiscoveryProcessor(discoveryProcessorConfig{
		Authority: repository, Queue: discovery.Queue, CollectorFactory: discovery.Factory, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || discovery.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: readinessGatedWorkerProcessor{delegate: processor, ready: ready}, Ready: ready, Close: discovery.Close}, nil
}

func composeOutboxWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, publisher outboxPublisher, publisherReady func(context.Context) error) (workerRuntimeDependencies, error) {
	if !validWorkerRuntimeConfig(config) || database == nil || publisher == nil || publisherReady == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	repository, err := apiserver.NewDiscoveryRepositoryForAuthority(database, apiserver.DiscoveryDatabaseAuthorityOutbox)
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || publisherReady(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	ready, err := newBoundedCachedWorkerReadiness(check, minDuration(config.LeaseDuration/3, 5*time.Second), workerReadinessCacheTTL(config.PollInterval))
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newOutboxProcessor(outboxProcessorConfig{
		Authority: repository, Publisher: publisher, Topic: discoveryOutboxTopic, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: min(config.BatchSize, 10), RetrySeconds: int(config.LeaseDuration / time.Second), NewLeaseToken: newWorkerLeaseToken, Ready: ready,
	})
	if err != nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	return workerRuntimeDependencies{Processor: processor, Ready: ready, Close: func() error { return nil }}, nil
}

type readinessGatedWorkerProcessor struct {
	delegate workerProcessor
	ready    func(context.Context) error
}

func (processor readinessGatedWorkerProcessor) RunOnce(ctx context.Context) error {
	if processor.delegate == nil || processor.ready == nil || ctx == nil || ctx.Err() != nil || processor.ready(ctx) != nil {
		return errWorkerExecution
	}
	return processor.delegate.RunOnce(ctx)
}

type boundedCachedWorkerReadiness struct {
	mu        sync.Mutex
	check     func(context.Context) error
	timeout   time.Duration
	ttl       time.Duration
	checkedAt time.Time
	now       func() time.Time
	ready     bool
}

func newBoundedCachedWorkerReadiness(check func(context.Context) error, timeout, ttl time.Duration) (func(context.Context) error, error) {
	if check == nil || timeout < 100*time.Millisecond || timeout > 30*time.Second || ttl < 10*time.Millisecond || ttl > time.Minute {
		return nil, errRuntimeUnavailable
	}
	readiness := &boundedCachedWorkerReadiness{check: check, timeout: timeout, ttl: ttl, now: time.Now}
	return readiness.Ready, nil
}

func (readiness *boundedCachedWorkerReadiness) Ready(ctx context.Context) error {
	if readiness == nil || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	readiness.mu.Lock()
	defer readiness.mu.Unlock()
	if ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	now := readiness.now()
	elapsed := now.Sub(readiness.checkedAt)
	if readiness.ready && elapsed >= 0 && elapsed < readiness.ttl {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, readiness.timeout)
	defer cancel()
	if readiness.check(bounded) != nil || bounded.Err() != nil {
		readiness.ready = false
		return errRuntimeUnavailable
	}
	readiness.checkedAt = now
	readiness.ready = true
	return nil
}

func workerReadinessCacheTTL(time.Duration) time.Duration {
	return 30 * time.Second
}

func composeProjectionWorkerRuntime(config workerRuntimeConfig, database apiserver.JSONDatabase, projector productionProjectionProjector) (workerRuntimeDependencies, error) {
	if !stringInWorker(config.ProjectionKind, "graph", "search") || projector.projectionProjector == nil || projector.ready == nil || projector.close == nil {
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	authority := apiserver.DiscoveryExecutionAuthorityProjectionGraph
	if config.ProjectionKind == "search" {
		authority = apiserver.DiscoveryExecutionAuthorityProjectionSearch
	}
	repository, err := apiserver.NewDiscoveryExecutionRepository(database, authority)
	if err != nil {
		_ = projector.close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	processor, err := newProjectionProcessor(projectionProcessorConfig{
		Authority: repository, Projector: projector.projectionProjector, Kind: config.ProjectionKind, WorkerID: config.WorkerID,
		LeaseSeconds: int(config.LeaseDuration / time.Second), BatchSize: config.BatchSize, HeartbeatInterval: config.LeaseDuration / 3, NewLeaseToken: newWorkerLeaseToken,
	})
	if err != nil {
		_ = projector.close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	ready := func(ctx context.Context) error {
		if err := repository.Ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		if err := projector.ready(ctx); err != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	return workerRuntimeDependencies{Processor: processor, Ready: ready, Close: projector.close}, nil
}

func serveWorkerRuntime(ctx context.Context, output interface{ Write([]byte) (int, error) }, version string, config workerRuntimeConfig, dependencies workerRuntimeDependencies, listen func(string, string) (net.Listener, error)) (resultErr error) {
	if ctx == nil || output == nil || !validBuildVersion(version) || !validWorkerRuntimeConfig(config) || dependencies.Processor == nil || dependencies.Ready == nil || dependencies.Close == nil || listen == nil {
		return errRuntimeUnavailable
	}
	defer func() {
		if closeErr := dependencies.Close(); closeErr != nil && resultErr == nil {
			resultErr = errRuntimeUnavailable
		}
	}()
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
