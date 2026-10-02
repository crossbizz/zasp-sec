package authorization

import "context"

func checkOrderedExecutionRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, spec workerOperationSpec, facts workerFacts, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if !spec.current || !(spec.orderedExecution || spec.orderedSigning || spec.orderedDomain) || !workerCheckShape(spec, facts) || len(facts.Checks) < 3 || len(facts.Checks) > 203 || len(requests) != 2*len(facts.Checks) {
		return Revision{}, ErrInvalid
	}
	for i, target := range facts.Checks {
		for j, actor := range []struct{ kind, id, task string }{{"user", facts.GrantorID, ""}, {"service", facts.PrincipalID, facts.RunID}} {
			want := CheckRequest{OrganizationID: facts.OrganizationID, WorkspaceID: facts.WorkspaceID, EnvironmentID: facts.EnvironmentID, PrincipalKind: actor.kind, PrincipalID: actor.id, TaskID: actor.task, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}
			if requests[2*i+j] != want {
				return Revision{}, ErrInvalid
			}
		}
	}
	// Every native target still gets both grantor and task-service decisions.
	// Only the monotonic revision interval is shared within this call. Native
	// execution and the caller's final source/revision reread remain unchanged.
	return checkWorkerRevisionSet(ctx, reader, checker, requests, storeID, modelID)
}
