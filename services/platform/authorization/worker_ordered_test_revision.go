package authorization

import "context"

// Only these four current, non-adapter Test phases share this request-local
// revision interval. Progress, adapter, captured recovery and other families
// retain their existing check routes.
func orderedTestRevisionPhase(spec workerOperationSpec) bool {
	if !spec.orderedTest || !spec.current || spec.purpose != WorkerForward || spec.adapter || spec.discovery {
		return false
	}
	switch spec.phase {
	case "linked.read", "linked.input", "linked.dispatch", "test.settle":
		return true
	default:
		return false
	}
}

func checkOrderedTestRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, spec workerOperationSpec, facts workerFacts, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if ctx == nil || reader == nil || checker == nil || !orderedTestRevisionPhase(spec) || !orderedTestWorkerCheckShape(spec, facts) || len(requests) != 8 {
		return Revision{}, ErrInvalid
	}
	for i, target := range facts.Checks {
		for j, actor := range []struct{ kind, id, task string }{{"user", facts.GrantorID, ""}, {"service", facts.PrincipalID, facts.RunID}} {
			want := CheckRequest{OrganizationID: facts.OrganizationID, WorkspaceID: facts.WorkspaceID, EnvironmentID: facts.EnvironmentID, PrincipalKind: actor.kind, PrincipalID: actor.id, TaskID: actor.task, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}
			if requests[2*i+j] != want {
				return Revision{}, ErrInvalid
			}
			if _, err := Map(want); err != nil {
				return Revision{}, ErrInvalid
			}
		}
	}
	revision, err := reader.Revision(ctx, facts.OrganizationID)
	if err != nil || ctx.Err() != nil {
		return Revision{}, ErrUnavailable
	}
	if revision.validate() != nil || revision.OrganizationID != facts.OrganizationID || revision.StoreID != storeID || revision.ModelID != modelID || revision.Desired != revision.Applied {
		return Revision{}, ErrPending
	}
	denied := false
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
			denied = true
			break
		}
	}
	// Match CheckRevision's drift-before-denial precedence. A denied Check
	// never bypasses this closing read. Drift during the set is retryable
	// Conflict, including a newly pending projection between checks.
	current, err := reader.Revision(ctx, facts.OrganizationID)
	if err != nil || ctx.Err() != nil {
		return Revision{}, ErrUnavailable
	}
	if current != revision {
		return Revision{}, ErrConflict
	}
	if denied {
		return Revision{}, ErrDenied
	}
	return revision, nil
}
