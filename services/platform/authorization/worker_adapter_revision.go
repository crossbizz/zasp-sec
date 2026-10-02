package authorization

import "context"

// The adapter check set is fixed by native metadata and workerCheckShape.
func checkAdapterRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if len(requests) != 8 {
		return Revision{}, ErrInvalid
	}
	return checkWorkerRevisionSet(ctx, reader, checker, requests, storeID, modelID)
}

// Existing workerCheckShape pins four manual targets or five finding/attack-path
// targets. Both subjects still receive every Check; only revision reads share
// one request-local interval. No other planning or worker family selects this.
func checkTestPlanningRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if len(requests) != 8 && len(requests) != 10 {
		return Revision{}, ErrInvalid
	}
	return checkWorkerRevisionSet(ctx, reader, checker, requests, storeID, modelID)
}

func checkWorkerRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if ctx == nil || reader == nil || checker == nil || len(requests) == 0 {
		return Revision{}, ErrInvalid
	}
	for _, request := range requests {
		if _, err := Map(request); err != nil || request.OrganizationID != requests[0].OrganizationID || request.WorkspaceID != requests[0].WorkspaceID || request.EnvironmentID != requests[0].EnvironmentID {
			return Revision{}, ErrInvalid
		}
	}
	revision, err := reader.Revision(ctx, requests[0].OrganizationID)
	if err != nil || ctx.Err() != nil {
		return Revision{}, ErrUnavailable
	}
	if revision.validate() != nil || revision.OrganizationID != requests[0].OrganizationID || revision.StoreID != storeID || revision.ModelID != modelID || revision.Desired != revision.Applied {
		return Revision{}, ErrPending
	}
	// All decisions belong to one monotonic revision interval. No value is
	// cached beyond this call; native execution still locks/rechecks the proof.
	for _, request := range requests {
		if ctx.Err() != nil {
			return Revision{}, ErrUnavailable
		}
		decision, err := checker.Check(ctx, request)
		if err != nil {
			return Revision{}, err
		}
		if decision.ModelID != revision.ModelID {
			return Revision{}, ErrConflict
		}
		if !decision.Allowed {
			return Revision{}, ErrDenied
		}
	}
	current, err := reader.Revision(ctx, requests[0].OrganizationID)
	if err != nil || ctx.Err() != nil {
		return Revision{}, ErrUnavailable
	}
	if current != revision {
		return Revision{}, ErrConflict
	}
	return revision, nil
}
