package runtimeevent

import "context"

type productionPrecisionReadiness interface{ ReadyPrecision(context.Context) error }

func NewPreciseProductionIngestHandler(config ProductionIngestConfig) (*ProductionIngestHandler, error) {
	handler, err := NewProductionIngestHandler(config)
	if err != nil {
		return nil, err
	}
	ready, ok := config.Repository.(productionPrecisionReadiness)
	acceptance, accepted := config.Repository.(ProductionAcceptanceRepository)
	if !ok || !accepted || nilProductionIngestValue(ready) || nilProductionIngestValue(acceptance) {
		return nil, ErrProductionIngest
	}
	handler.precision = true
	return handler, nil
}

func safeProductionPrecisionReady(ctx context.Context, repository ProductionIngestRepository) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrProductionIngestUnavailable
		}
	}()
	ready, ok := repository.(productionPrecisionReadiness)
	if !ok || nilProductionIngestValue(ready) || ctx == nil || ctx.Err() != nil {
		return ErrProductionIngestUnavailable
	}
	if err := ready.ReadyPrecision(ctx); err != nil || ctx.Err() != nil {
		return ErrProductionIngestUnavailable
	}
	return nil
}
