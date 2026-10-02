package authorization

import "context"

func orderedTestWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: WorkerForward, source: `SELECT zasp_authorization80_worker.ordered68_test_source($1,$2::jsonb)`, current: true, orderedTest: true, limit: 4096}
	switch operation {
	case "ordered68.progress":
		s.statement = `SELECT zasp_temporal68.progress($1::jsonb)`
	case "ordered68.test.state":
		s.purpose, s.current = CapturedCompensation, false
		s.statement = `SELECT zasp_authorization80_worker.ordered68_test_state($1::jsonb)`
	case "ordered68.linked.read", "ordered68.linked.input", "ordered68.linked.dispatch":
		s.limit, s.statement = 131072, `SELECT zasp_temporal68.linked($1::jsonb)`
	case "ordered68.adapter.resolve", "ordered68.adapter.start":
		s.adapter, s.limit, s.statement = true, 8192, `SELECT zasp_temporal68.invocation($1::jsonb)`
	case "ordered68.adapter.complete":
		s.purpose, s.current, s.limit = CapturedCompensation, false, 8192
		s.statement = `SELECT zasp_authorization80_worker.ordered68_test_complete($1::jsonb)`
	case "ordered68.test.settle":
		s.limit, s.statement = 1500000, `SELECT zasp_temporal68.test_settle($1::jsonb)`
	case "ordered68.test.replay":
		s.purpose, s.current, s.limit = CapturedCompensation, false, 1500000
		s.statement = `SELECT zasp_authorization80_worker.ordered68_test_replay($1::jsonb)`
	case "ordered68.test.stop":
		s.purpose, s.current = CapturedCompensation, false
		s.statement = `SELECT zasp_temporal68.test_stop($1::jsonb)`
	default:
		return workerOperationSpec{}, false
	}
	s.phase = string(operation)[len("ordered68."):]
	return s, true
}

func orderedTestWorkerCheckShape(spec workerOperationSpec, f workerFacts) bool {
	if !spec.orderedTest || !spec.current || f.TaskID != "" || f.TriggerKind != "finding" && f.TriggerKind != "attack_path" || f.TargetKind != "agent" && f.TargetKind != "tool" || len(f.OrderedDeviceIDs) != 0 {
		return false
	}
	want := [][3]string{{"security_agent", f.DefinitionID, "manage_workflows"}, {"security_agent_run", f.RunID, "manage_workflows"}}
	if spec.phase != "progress" {
		if f.OrderedActionKey != "run_test" {
			return false
		}
		want = append(want, [3]string{"test", f.TestID, "run_tests"}, [3]string{f.TargetKind, f.TargetID, "run_tests"})
	}
	if len(f.Checks) != len(want) {
		return false
	}
	for i, target := range f.Checks {
		if target.ID == "" || [3]string{target.Kind, target.ID, target.Permission} != want[i] {
			return false
		}
	}
	return true
}

// Progress is exactly two workflow-management resources, each for grantor and
// task. It cannot borrow the variable execution bracket or a Test-send grant.
func checkOrderedProgressRevisionSet(ctx context.Context, reader RevisionReader, checker Checker, spec workerOperationSpec, facts workerFacts, requests []CheckRequest, storeID, modelID string) (Revision, error) {
	if spec.phase != "progress" || !orderedTestWorkerCheckShape(spec, facts) || len(requests) != 4 {
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
	return checkWorkerRevisionSet(ctx, reader, checker, requests, storeID, modelID)
}
