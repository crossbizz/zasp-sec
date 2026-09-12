package main

import (
	"context"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
)

type productionIngestArtifactStore interface {
	runtimeevent.RawArtifactAuthority
	runtimeevent.RawArtifactInspector
}

// The production resource factory and composed tests use this same wiring.
// Database connections, cloud clients and their cleanup stay with the caller.
func composeProductionIngestDependencies(ctx context.Context, config productionIngestConfig, database runtimeevent.ProductionIngestDatabase, artifacts productionIngestArtifactStore, cloudReady func(context.Context) error, clock func() time.Time, closeResources func() error) (productionIngestDependencies, error) {
	if ctx == nil || ctx.Err() != nil || !validProductionIngestConfig(config) || invalidRuntimeValue(database) || invalidRuntimeValue(artifacts) || cloudReady == nil || clock == nil || closeResources == nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	repository, err := newConfiguredProductionIngestRepository(database, config.RuntimeSchema)
	if err != nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	check := func(ctx context.Context) error {
		if repository.Ready(ctx) != nil || cloudReady(ctx) != nil {
			return errRuntimeUnavailable
		}
		return nil
	}
	readiness, err := newProductionReadinessCache(check, config.OperationTimeout, productionIngestReadinessTTL, clock)
	if err != nil || readiness.Ready(ctx) != nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	cachedRepository := cachedProductionIngestRepository{productionIngestRepository: repository, ready: readiness.Ready}
	router, err := newVersionedProductionIngestRouter(cachedRepository, artifacts, config.MaximumBytes, clock, config.RuntimeSchema)
	if err != nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	constructor := runtimeevent.NewProductionIngestReconciler
	if config.RuntimeSchema == "runtime-event-v2" {
		constructor = runtimeevent.NewPreciseProductionIngestReconciler
	}
	reconciler, err := constructor(runtimeevent.ProductionIngestReconcilerConfig{Repository: cachedProductionIngestReconciliationRepository{ProductionIngestReconciliationRepository: repository, ready: readiness.Ready}, Artifacts: artifacts, WorkerID: config.ReconcilerID, LeaseSeconds: 60, ClaimLimit: 10, OperationTimeout: config.OperationTimeout, NewLeaseToken: newProductionReconciliationLeaseToken})
	if err != nil {
		return productionIngestDependencies{}, errRuntimeUnavailable
	}
	return productionIngestDependencies{Handler: readinessGatedIngestHandler{ready: readiness.Ready, next: router}, Ready: readiness.Ready, Reconcile: reconciler.RunOnce, ReconcileInterval: config.ReconciliationInterval, Close: closeResources}, nil
}
