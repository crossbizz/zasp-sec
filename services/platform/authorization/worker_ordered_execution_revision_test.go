package authorization

import (
	"context"
	"errors"
	"testing"
)

func TestOrderedExecutionCompleteSetRevisionBudget(t *testing.T) {
	for _, op := range []WorkerOperation{"ordered68.effect.reserve", "ordered68.application.complete", "ordered68.delivery.apply.prepare", "ordered68.delivery.apply.store"} {
		for _, count := range []int{1, 100} {
			r, c, seed := planningSetFixture("finding")
			f := orderedEffectShapeFixture(t, "create_temporary_policy", count)
			if op == "ordered68.delivery.apply.prepare" || op == "ordered68.delivery.apply.store" {
				f = orderedPolicyShapeFixture(count)
			}
			f.OrganizationID, f.WorkspaceID, f.EnvironmentID = r.value.OrganizationID, seed[0].WorkspaceID, seed[0].EnvironmentID
			f.GrantorID, f.PrincipalID = seed[0].PrincipalID, seed[1].PrincipalID
			var requests []CheckRequest
			for _, target := range f.Checks {
				for _, actor := range []struct{ kind, id, task string }{{"user", f.GrantorID, ""}, {"service", f.PrincipalID, f.RunID}} {
					requests = append(requests, CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: actor.kind, PrincipalID: actor.id, TaskID: actor.task, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission})
				}
			}
			spec, _ := workerOperation(op)
			r.budget = 2
			got, err := checkOrderedExecutionRevisionSet(context.Background(), r, c, spec, f, requests, r.value.StoreID, r.value.ModelID)
			if err != nil || got != r.value || r.reads != 2 || len(c.seen) != len(requests) {
				t.Fatalf("complete native authority set exceeded revision budget: %s/%d reads=%d checks=%d err=%v", op, count, r.reads, len(c.seen), err)
			}
			for i, q := range requests {
				if c.seen[i] != q {
					t.Fatal("permission check changed or skipped", i)
				}
			}
			for _, mutation := range []string{"missing-check", "reordered", "wrong-permission", "wrong-task", "denied-last", "revision-changed", "model-changed"} {
				reader, checker, _ := planningSetFixture("finding")
				reader.budget = 2
				changed := append([]CheckRequest(nil), requests...)
				want := ErrInvalid
				switch mutation {
				case "missing-check":
					changed = changed[:len(changed)-1]
				case "reordered":
					changed[0], changed[1] = changed[1], changed[0]
				case "wrong-permission":
					changed[len(changed)-1].Permission = "manage_workflows"
					if requests[len(requests)-1].Permission == "manage_workflows" {
						changed[len(changed)-1].Permission = "view"
					}
				case "wrong-task":
					changed[len(changed)-1].TaskID = ""
				case "denied-last":
					checker.denyAt = len(changed)
					want = ErrDenied
				case "revision-changed":
					checker.changeAt = len(changed)
					want = ErrConflict
				case "model-changed":
					checker.wrongModelAt = len(changed)
					want = ErrConflict
				}
				got, err := checkOrderedExecutionRevisionSet(context.Background(), reader, checker, spec, f, changed, reader.value.StoreID, reader.value.ModelID)
				if !errors.Is(err, want) || got != (Revision{}) {
					t.Fatal("changed authority set accepted", op, count, mutation, err)
				}
			}
		}
	}
}
