package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"github.com/zasp-ai/zasp-sec/services/platform/runtimeservices"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/worker"
)

// Both Activity dispatch and SQS/configuration RPCs borrow the same owned
// clients. Close rejects new borrows and joins existing borrowers before any
// client or database closes. A timed-out Close retains them for a later join.
type discoveryRuntimeBorrowers struct {
	mu      sync.Mutex
	closing bool
	active  int
	drained chan struct{}
}

func (b *discoveryRuntimeBorrowers) run(ctx context.Context, work func() error) error {
	if b == nil || ctx == nil || ctx.Err() != nil || work == nil {
		return errWorkerExecution
	}
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return errWorkerExecution
	}
	b.active++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.active--
		if b.closing && b.active == 0 {
			close(b.drained)
		}
	}()
	return work()
}
func (b *discoveryRuntimeBorrowers) close(ctx context.Context) error {
	b.mu.Lock()
	if !b.closing {
		b.closing = true
		b.drained = make(chan struct{})
		if b.active == 0 {
			close(b.drained)
		}
	}
	done := b.drained
	b.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errWorkerExecution
	}
}

type borrowedDiscoveryProcessor struct {
	borrowers *discoveryRuntimeBorrowers
	processor workerProcessor
}

func (p borrowedDiscoveryProcessor) RunOnce(ctx context.Context) error {
	return p.borrowers.run(ctx, func() error { return p.processor.RunOnce(ctx) })
}

type discoveryTemporalActivities struct {
	product   *temporalDiscoveryProduct
	borrowers *discoveryRuntimeBorrowers
}

func (a *discoveryTemporalActivities) AdmitDiscoveryScheduled(ctx context.Context, q orchestration.DiscoveryOccurrence) (out orchestration.DiscoveryAdmission, err error) {
	err = a.borrowers.run(ctx, func() error { var err error; out, err = a.product.AdmitDiscoveryScheduled(ctx, q); return err })
	return
}
func (a *discoveryTemporalActivities) CollectDiscoveryPage(ctx context.Context, q orchestration.DiscoveryPageCommand) (out orchestration.DiscoveryPage, err error) {
	defer func() { err = temporalProductError(ctx, err) }()
	err = a.borrowers.run(ctx, func() error { var err error; out, err = a.product.CollectDiscoveryPage(ctx, q); return err })
	return
}
func (a *discoveryTemporalActivities) ApplyDiscoverySnapshot(ctx context.Context, q orchestration.DiscoveryApplyCommand) (out string, err error) {
	defer func() { err = temporalProductError(ctx, err) }()
	err = a.borrowers.run(ctx, func() error { var err error; out, err = a.product.ApplyDiscoverySnapshot(ctx, q); return err })
	return
}
func (a *discoveryTemporalActivities) FinishDiscovery(ctx context.Context, q orchestration.DiscoveryFinish) error {
	return a.borrowers.run(ctx, func() error { return a.product.FinishDiscovery(ctx, q) })
}
func (a *discoveryTemporalActivities) ReconcileDiscoveryOutcome(ctx context.Context, q orchestration.DiscoveryReconcile) (out orchestration.DiscoveryResult, err error) {
	err = a.borrowers.run(ctx, func() error { var err error; out, err = a.product.ReconcileDiscoveryOutcome(ctx, q); return err })
	return
}

// This is the installed72 branch of the shipped runtime constructor. It owns
// the supplied database even on failure; no old due-work scheduler runs here.
func buildTemporalDiscoveryRuntime(ctx context.Context, cfg workerRuntimeConfig, db *apiserver.PostgresJSONDatabase, external workerExternalIO) (workerRuntimeDependencies, error) {
	fail := func() (workerRuntimeDependencies, error) {
		db.Close()
		return workerRuntimeDependencies{}, errRuntimeUnavailable
	}
	if !validWorkerRuntimeConfig(cfg) || !cfg.RuntimeServices.Enabled {
		return fail()
	}
	// Full-family refusal precedes FGA/Temporal credentials or provider setup.
	if temporalWorkerProductionProfileReady(ctx, cfg.PostgresDSN) != nil {
		return fail()
	}
	services, err := runtimeservices.Connect(ctx, cfg.RuntimeServices)
	if err != nil || services == nil {
		return fail()
	}
	var closeProviders func() error = func() error { return nil }
	closeAuthorization := func() {}
	failed := func() (workerRuntimeDependencies, error) {
		closeAuthorization()
		closeProviders()
		services.Close()
		return fail()
	}
	borrowers := &discoveryRuntimeBorrowers{}
	var processor workerProcessor
	var readyProduct func(context.Context) error
	var sdkWorker worker.Worker
	if cfg.Mode == workerModeScheduler {
		source, err := newTemporalDiscoveryScheduleSource(ctx, cfg.PostgresDSN, cfg.RuntimeServices.Timeout)
		if err != nil {
			return failed()
		}
		reconciler, err := orchestration.NewDiscoveryScheduleReconciler(services.Temporal.ScheduleClient(), source, cfg.RuntimeServices.DiscoveryTaskQueue, cfg.RuntimeServices.Timeout)
		if err != nil {
			return failed()
		}
		processor = &temporalDiscoveryScheduleProcessor{source: source, reconciler: reconciler, limit: min(cfg.BatchSize, 100), startup: true}
		readyProduct = source.Ready
	} else if cfg.Mode == workerModeDiscovery {
		dependencies, err := newProductionDiscoveryDependenciesWithIO(productionDiscoveryDependenciesConfig(cfg), external.discovery)
		if err != nil {
			return failed()
		}
		closeProviders = dependencies.Close
		factory, ok := dependencies.Factory.(productDiscoveryCollectorFactory)
		if !ok {
			return failed()
		}
		product, err := newTemporalDiscoveryProduct(db, factory)
		if err != nil {
			return failed()
		}
		checker, err := authorization.NewOpenFGA(services.FGA, cfg.RuntimeServices)
		if err != nil {
			return failed()
		}
		closeAuthorization, err = bindDiscoveryWorkerAuthorization(ctx, cfg, checker, product)
		if err != nil {
			return failed()
		}
		readyProduct = func(ctx context.Context) error {
			if product.Ready(ctx) != nil || dependencies.Ready(ctx) != nil {
				return errRuntimeUnavailable
			}
			return nil
		}
		if readyProduct(ctx) != nil {
			return failed()
		}
		starter, err := orchestration.NewDiscoveryStarter(services.Temporal, cfg.RuntimeServices.DiscoveryTaskQueue, cfg.RuntimeServices.Timeout)
		if err != nil {
			return failed()
		}
		consumer, err := newTemporalDiscoveryStartProcessor(db, dependencies.Queue, starter, cfg.BatchSize)
		if err != nil {
			return failed()
		}
		retained, err := apiserver.NewDiscoveryExecutionRepository(db, apiserver.DiscoveryExecutionAuthorityWorker)
		if err != nil {
			return failed()
		}
		consumer.legacy, err = newDiscoveryProcessor(discoveryProcessorConfig{Authority: retained, Queue: dependencies.Queue, CollectorFactory: dependencies.Factory, WorkerID: cfg.WorkerID, LeaseSeconds: int(cfg.LeaseDuration / time.Second), BatchSize: cfg.BatchSize, HeartbeatInterval: cfg.LeaseDuration / 3, Now: func() time.Time { return time.Now().UTC() }, NewLeaseToken: newWorkerLeaseToken})
		if err != nil {
			return failed()
		}
		processor = consumer
		activities := &discoveryTemporalActivities{product: product, borrowers: borrowers}
		sdkWorker = worker.New(services.Temporal, cfg.RuntimeServices.DiscoveryTaskQueue, worker.Options{WorkerStopTimeout: cfg.ShutdownTimeout, MaxConcurrentActivityExecutionSize: cfg.BatchSize, MaxConcurrentWorkflowTaskExecutionSize: cfg.BatchSize})
		sdkWorker.RegisterWorkflow(orchestration.DiscoveryWorkflow)
		sdkWorker.RegisterWorkflow(orchestration.DiscoveryScheduledWorkflow)
		for name, handler := range map[string]any{"AdmitDiscoveryScheduled": activities.AdmitDiscoveryScheduled, "CollectDiscoveryPage": activities.CollectDiscoveryPage, "ApplyDiscoverySnapshot": activities.ApplyDiscoverySnapshot, "FinishDiscovery": activities.FinishDiscovery, "ReconcileDiscoveryOutcome": activities.ReconcileDiscoveryOutcome} {
			sdkWorker.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
		}
		if sdkWorker.Start() != nil {
			return failed()
		}
	} else {
		return failed()
	}
	var closing atomic.Bool
	var stopOnce, closeOnce sync.Once
	stopped := make(chan struct{})
	var closeErr error
	ready := func(ctx context.Context) error {
		if closing.Load() || services.Ready(ctx) != nil {
			return errRuntimeUnavailable
		}
		return readyProduct(ctx)
	}
	closeRuntime := func() error {
		closing.Store(true)
		bounded, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		stopOnce.Do(func() {
			go func() {
				if sdkWorker != nil {
					sdkWorker.Stop()
				}
				close(stopped)
			}()
		})
		if borrowers.close(bounded) != nil {
			return errRuntimeUnavailable
		}
		select {
		case <-stopped:
		case <-bounded.Done():
			return errRuntimeUnavailable
		}
		closeOnce.Do(func() { closeAuthorization(); closeErr = errors.Join(closeProviders(), services.Close(), db.Close()) })
		return closeErr
	}
	return workerRuntimeDependencies{Processor: borrowedDiscoveryProcessor{borrowers: borrowers, processor: processor}, Ready: borrowedDiscoveryReadiness(borrowers, ready), Close: closeRuntime}, nil
}
