package main

import (
	"context"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/riskprojection"
)

type riskProjectionProjector struct{ projector *riskprojection.Projector }

type riskProjectionAuthority interface {
	ApplyRiskProjectionInput(context.Context, riskprojection.CompleteInput) (riskprojection.ApplyResult, error)
	Ready(context.Context) error
}

type executionRiskProjectionStore struct{ authority riskProjectionAuthority }

func (store executionRiskProjectionStore) ApplyComplete(ctx context.Context, input riskprojection.CompleteInput) (riskprojection.ApplyResult, error) {
	if store.authority == nil {
		return riskprojection.ApplyResult{}, riskprojection.ErrUnavailable
	}
	return store.authority.ApplyRiskProjectionInput(ctx, input)
}

func newRiskProjectionProjector(store riskprojection.Store) (*riskProjectionProjector, error) {
	projector, err := riskprojection.NewProjector(store)
	if err != nil {
		return nil, errWorkerExecution
	}
	return &riskProjectionProjector{projector: projector}, nil
}

func newProductionRiskProjection(authority riskProjectionAuthority) (productionProjectionProjector, error) {
	if authority == nil {
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	projector, err := newRiskProjectionProjector(executionRiskProjectionStore{authority: authority})
	if err != nil {
		return productionProjectionProjector{}, errRuntimeUnavailable
	}
	return productionProjectionProjector{
		projectionProjector: projector,
		ready: func(ctx context.Context) error {
			if err := authority.Ready(ctx); err != nil {
				return errRuntimeUnavailable
			}
			return nil
		},
		close: func() error { return nil },
	}, nil
}

func (projector *riskProjectionProjector) Apply(ctx context.Context, candidate projectionCandidate) (projectionDriverResult, error) {
	if projector == nil || projector.projector == nil || candidate.Kind != "risk" {
		return projectionDriverResult{}, errWorkerExecution
	}
	if _, _, ok := decodeProjectionCandidate(candidate, "risk"); !ok {
		return projectionDriverResult{}, errWorkerExecution
	}
	integrationID, integrationErr := domain.ParseProductID(candidate.IntegrationID)
	snapshotID, snapshotErr := domain.ParseProductID(candidate.SnapshotID)
	if integrationErr != nil || snapshotErr != nil {
		return projectionDriverResult{}, errWorkerExecution
	}
	result, err := projector.projector.Project(ctx, riskprojection.Candidate{
		Scope: candidate.Scope, IntegrationID: integrationID, SnapshotID: snapshotID, Source: candidate.Source, Generation: candidate.Generation,
		Version: candidate.Version, Worker: candidate.Worker, LeaseToken: candidate.LeaseToken, InputDigest: candidate.InputDigest,
		Entities: cloneRawMessages(candidate.Entities), Relationships: cloneRawMessages(candidate.Relationships), Evidence: cloneRawMessages(candidate.Evidence),
	})
	if err != nil {
		return projectionDriverResult{}, err
	}
	return projectionDriverResult{Receipt: result.Receipt, Digest: result.Digest}, nil
}

var _ projectionProjector = (*riskProjectionProjector)(nil)
var _ riskProjectionAuthority = (*apiserver.DiscoveryExecutionRepository)(nil)
