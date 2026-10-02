package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestOrderedProgressRevisionKeepsAllFourChecks(t *testing.T) {
	for _, mutation := range []string{"none", "missing", "extra", "reordered", "wrong-task", "wrong-permission", "early-revision", "last-revision", "generation", "store", "model", "pending", "deny", "wrong-result-model"} {
		t.Run(mutation, func(t *testing.T) {
			r, c, seed := planningSetFixture("finding")
			f := orderedEffectShapeFixture(t, "run_test", 0)
			f.Checks = f.Checks[:2]
			f.OrganizationID, f.WorkspaceID, f.EnvironmentID = r.value.OrganizationID, seed[0].WorkspaceID, seed[0].EnvironmentID
			f.GrantorID, f.PrincipalID = seed[0].PrincipalID, seed[1].PrincipalID
			var requests []CheckRequest
			for _, target := range f.Checks {
				requests = append(requests, CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: "user", PrincipalID: f.GrantorID, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}, CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: "service", PrincipalID: f.PrincipalID, TaskID: f.RunID, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission})
			}
			want := ErrInvalid
			switch mutation {
			case "none":
				want = nil
			case "missing":
				requests = requests[:3]
			case "extra":
				requests = append(requests, requests[0])
			case "reordered":
				requests[0], requests[1] = requests[1], requests[0]
			case "wrong-task":
				requests[3].TaskID = ""
			case "wrong-permission":
				requests[3].Permission = "run_tests"
			case "early-revision":
				c.changeAt = 1
				want = ErrConflict
			case "last-revision":
				c.changeAt = 4
				want = ErrConflict
			case "generation", "store", "model":
				c.changeAt = 4
				c.mutation = mutation
				want = ErrConflict
			case "deny":
				c.denyAt = 4
				want = ErrDenied
			case "pending":
				r.value.Desired++
				want = ErrPending
			case "wrong-result-model":
				c.wrongModelAt = 4
				want = ErrConflict
			}
			spec, _ := workerOperation("ordered68.progress")
			r.budget = 2
			got, err := checkOrderedProgressRevisionSet(context.Background(), r, c, spec, f, requests, r.value.StoreID, r.value.ModelID)
			if !errors.Is(err, want) {
				t.Fatal("progress revision result", err, want)
			}
			if want == nil {
				if got != r.value || r.reads != 2 || len(c.seen) != 4 {
					t.Fatal("progress skipped current authority")
				}
				for i, q := range requests {
					if c.seen[i] != q {
						t.Fatal("progress changed a grantor/task check")
					}
				}
			} else if got != (Revision{}) {
				t.Fatal("failed progress returned usable revision")
			}
		})
	}
}

// The consuming dispatcher must not let compensation create an approval,
// input, dispatch, invocation or first settlement.
func TestOrderedTestExecutionClosedOperations(t *testing.T) {
	for _, tc := range []struct {
		name      string
		purpose   WorkerPurpose
		adapter   bool
		limit     int
		statement string
	}{
		{"progress", WorkerForward, false, 4096, `SELECT zasp_temporal68.progress($1::jsonb)`},
		{"test.state", CapturedCompensation, false, 4096, `SELECT zasp_authorization80_worker.ordered68_test_state($1::jsonb)`},
		{"linked.read", WorkerForward, false, 131072, `SELECT zasp_temporal68.linked($1::jsonb)`},
		{"linked.input", WorkerForward, false, 131072, `SELECT zasp_temporal68.linked($1::jsonb)`},
		{"linked.dispatch", WorkerForward, false, 131072, `SELECT zasp_temporal68.linked($1::jsonb)`},
		{"adapter.resolve", WorkerForward, true, 8192, `SELECT zasp_temporal68.invocation($1::jsonb)`},
		{"adapter.start", WorkerForward, true, 8192, `SELECT zasp_temporal68.invocation($1::jsonb)`},
		{"adapter.complete", CapturedCompensation, false, 8192, `SELECT zasp_authorization80_worker.ordered68_test_complete($1::jsonb)`},
		{"test.settle", WorkerForward, false, 1500000, `SELECT zasp_temporal68.test_settle($1::jsonb)`},
		{"test.replay", CapturedCompensation, false, 1500000, `SELECT zasp_authorization80_worker.ordered68_test_replay($1::jsonb)`},
		{"test.stop", CapturedCompensation, false, 4096, `SELECT zasp_temporal68.test_stop($1::jsonb)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, ok := workerOperation(WorkerOperation("ordered68." + tc.name))
			if !ok || s.purpose != tc.purpose || s.current != (tc.purpose == WorkerForward) || s.adapter != tc.adapter || s.limit != tc.limit || s.statement != tc.statement || s.phase != tc.name || s.bindRequest || s.discovery || s.testExecution || s.orderedPlanning || s.orderedSigning || s.source != `SELECT zasp_authorization80_worker.ordered68_test_source($1,$2::jsonb)` {
				t.Fatal("downstream operation missing or crossed authority/family boundary")
			}
		})
	}
	for _, op := range []WorkerOperation{"ordered68.progress.stop", "ordered68.test.complete", "ordered68.test.recover", "ordered68.adapter.receipt", "ordered68.linked.start", "ordered68.adapter.complete.extra"} {
		if _, ok := workerOperation(op); ok {
			t.Fatal("unreleased downstream operation accepted", op)
		}
	}
}

func TestOrderedProgressDoesNotRequireOrGrantTestSend(t *testing.T) {
	s, ok := workerOperation("ordered68.progress")
	if !ok {
		t.Fatal("current progress operation absent")
	}
	f := orderedEffectShapeFixture(t, "run_test", 0)
	f.Checks = f.Checks[:2]
	if !workerCheckShape(s, f) {
		t.Fatal("workflow management cannot bootstrap successor approval")
	}
	raw, _ := json.Marshal(f)
	for _, mutate := range []func(*workerFacts){
		func(v *workerFacts) { v.Checks = v.Checks[:1] },
		func(v *workerFacts) { v.Checks = append(v.Checks, v.Checks[0]) },
		func(v *workerFacts) { v.Checks[1].Permission = "run_tests" },
		func(v *workerFacts) { v.Checks[1].ID = v.TestID },
		func(v *workerFacts) { v.Checks[0], v.Checks[1] = v.Checks[1], v.Checks[0] },
		func(v *workerFacts) { v.TaskID = v.RunID },
		func(v *workerFacts) { v.TriggerKind = "runtime_decision" },
		func(v *workerFacts) { v.OrderedDeviceIDs = []string{v.TargetID} },
	} {
		var v workerFacts
		if json.Unmarshal(raw, &v) != nil {
			t.Fatal("fixture")
		}
		mutate(&v)
		if workerCheckShape(s, v) {
			t.Fatal("progress accepted a foreign or changed management set")
		}
	}
	for _, op := range []WorkerOperation{"ordered68.linked.read", "ordered68.linked.input", "ordered68.linked.dispatch", "ordered68.adapter.resolve", "ordered68.adapter.start", "ordered68.test.settle"} {
		other, ok := workerOperation(op)
		if !ok {
			t.Fatal("test operation absent", op)
		}
		if workerCheckShape(other, f) {
			t.Fatal("progress authority could send or first-settle Test", op)
		}
		if !workerCheckShape(other, orderedEffectShapeFixture(t, "run_test", 0)) {
			t.Fatal("complete Test authority refused", op)
		}
	}
}
