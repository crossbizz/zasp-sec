package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/runtimeevent"
	"github.com/zasp-ai/zasp-sec/services/platform/sensor"
)

func newConfiguredProductionIngestRepository(database runtimeevent.ProductionIngestDatabase, schema string) (*runtimeevent.PostgresProductionIngestRepository, error) {
	if schema == "runtime-event-v2" {
		return runtimeevent.NewPostgresPreciseProductionIngestRepository(database)
	}
	if schema != "" && schema != "runtime-event-v1" {
		return nil, errRuntimeUnavailable
	}
	return runtimeevent.NewPostgresProductionIngestRepository(database)
}

// Precision authority must be fresh even while combined cloud readiness is cached.
func (repository cachedProductionIngestRepository) ReadyPrecision(ctx context.Context) error {
	authority, ok := repository.productionIngestRepository.(interface{ ReadyPrecision(context.Context) error })
	if !ok || invalidRuntimeValue(authority) || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return authority.ReadyPrecision(ctx)
}

func (repository cachedProductionIngestReconciliationRepository) ReadyPrecision(ctx context.Context) error {
	authority, ok := repository.ProductionIngestReconciliationRepository.(interface{ ReadyPrecision(context.Context) error })
	if !ok || invalidRuntimeValue(authority) || ctx == nil || ctx.Err() != nil {
		return errRuntimeUnavailable
	}
	return authority.ReadyPrecision(ctx)
}

// Keep immutable acceptance lookup visible through the readiness wrapper.
func (repository cachedProductionIngestRepository) LookupAcceptance(ctx context.Context, credential *sensor.TokenCredential, request runtimeevent.IngestAcceptanceRequest) (runtimeevent.IngestAcceptance, error) {
	authority, ok := repository.productionIngestRepository.(runtimeevent.ProductionAcceptanceRepository)
	if !ok || invalidRuntimeValue(authority) || ctx == nil || ctx.Err() != nil {
		return runtimeevent.IngestAcceptance{}, errRuntimeUnavailable
	}
	return authority.LookupAcceptance(ctx, credential, request)
}
