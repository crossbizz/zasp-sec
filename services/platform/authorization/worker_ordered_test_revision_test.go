package authorization

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func orderedTestRevisionFixture(t *testing.T) (*adapterSetReader, *adapterSetChecker, workerFacts, []CheckRequest) {
	t.Helper()
	r, c, seed := adapterSetFixture()
	f := orderedEffectShapeFixture(t, "run_test", 0)
	f.OrganizationID, f.WorkspaceID, f.EnvironmentID = r.value.OrganizationID, seed[0].WorkspaceID, seed[0].EnvironmentID
	f.GrantorID, f.PrincipalID = seed[0].PrincipalID, seed[1].PrincipalID
	var requests []CheckRequest
	for _, target := range f.Checks {
		requests = append(requests, CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: "user", PrincipalID: f.GrantorID, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}, CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: "service", PrincipalID: f.PrincipalID, TaskID: f.RunID, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission})
	}
	return r, c, f, requests
}

// Reproduces the measured sixteen-read failure using a finite reader budget;
// all eight original permission requests remain mandatory, in order.
func TestOrderedTestRevisionCompleteSet(t *testing.T) {
	for _, phase := range []WorkerOperation{"ordered68.linked.read", "ordered68.linked.input", "ordered68.linked.dispatch", "ordered68.test.settle"} {
		t.Run(string(phase), func(t *testing.T) {
			r, c, f, requests := orderedTestRevisionFixture(t)
			spec, ok := workerOperation(phase)
			if !ok || !orderedTestRevisionPhase(spec) {
				t.Fatal("operation selector did not select fixed Test revision route")
			}
			r.budget = 2
			want := r.value
			got, err := checkOrderedTestRevisionSet(context.Background(), r, c, spec, f, requests, want.StoreID, want.ModelID)
			if err != nil || got != want || r.reads != 2 || len(c.seen) != 8 {
				t.Fatal("complete check set", err, r.reads, len(c.seen))
			}
			for i, q := range requests {
				if c.seen[i] != q {
					t.Fatal("permission request changed", i)
				}
			}
			r.value.Desired++
			r.value.Applied++
			r.budget = 4
			c.seen = nil
			got, err = checkOrderedTestRevisionSet(context.Background(), r, c, spec, f, requests, want.StoreID, want.ModelID)
			if err != nil || got == want || got != r.value || r.reads != 4 || len(c.seen) != 8 {
				t.Fatal("cross-call positive revision reused", err)
			}
		})
	}
	for _, op := range []WorkerOperation{"ordered68.progress", "ordered68.test.state", "ordered68.test.replay", "ordered68.test.stop", "ordered68.adapter.resolve", "ordered68.adapter.start", "ordered68.adapter.complete", "ordered68.effect.reserve", "ordered68.application.read", "test74.linked.read"} {
		spec, _ := workerOperation(op)
		if orderedTestRevisionPhase(spec) {
			t.Fatal("unrelated phase selected new Test bracket", op)
		}
	}
}

func TestOrderedTestRevisionDenialClosesEveryPosition(t *testing.T) {
	for position := 1; position <= 8; position++ {
		for _, drift := range []bool{false, true} {
			t.Run(fmt.Sprintf("position-%d/drift-%t", position, drift), func(t *testing.T) {
				r, c, facts, requests := orderedTestRevisionFixture(t)
				spec, _ := workerOperation("ordered68.linked.read")
				c.denyAt = position
				want := ErrDenied
				if drift {
					c.changeAt = position
					want = ErrConflict
				}
				got, err := checkOrderedTestRevisionSet(context.Background(), r, c, spec, facts, requests, r.value.StoreID, r.value.ModelID)
				if !errors.Is(err, want) || got != (Revision{}) || r.reads != 2 || len(c.seen) != position {
					t.Fatal("denial bypassed closing revision or short circuit", err, r.reads, len(c.seen))
				}
			})
		}
	}
}

func TestOrderedTestRevisionRefusals(t *testing.T) {
	for _, name := range []string{"missing", "extra", "reorder", "foreign-scope", "wrong-subject", "wrong-task", "wrong-resource", "wrong-permission", "short-shape", "pending", "wrong-store", "wrong-model", "invalid-generation", "deny-first", "deny-last", "deny-and-drift", "drift-first", "drift-last", "generation", "store", "model", "checker-error", "model-error", "closing-error", "cancel", "between-check-pending"} {
		t.Run(name, func(t *testing.T) {
			r, c, f, requests := orderedTestRevisionFixture(t)
			spec, _ := workerOperation("ordered68.linked.read")
			store, model := r.value.StoreID, r.value.ModelID
			want := ErrInvalid
			switch name {
			case "missing":
				requests = requests[:7]
			case "extra":
				requests = append(requests, requests[0])
			case "reorder":
				requests[0], requests[1] = requests[1], requests[0]
			case "foreign-scope":
				requests[7].WorkspaceID = principal
			case "wrong-subject":
				requests[7].PrincipalID = f.GrantorID + "x"
			case "wrong-task":
				requests[7].TaskID = ""
			case "wrong-resource":
				requests[7].ResourceID = f.RunID
			case "wrong-permission":
				requests[7].Permission = "view"
			case "short-shape":
				f.Checks = f.Checks[:2]
			case "pending":
				r.value.Desired++
				want = ErrPending
			case "wrong-store":
				store = "01K00000000000000000000009"
				want = ErrPending
			case "wrong-model":
				model = "01K00000000000000000000009"
				want = ErrPending
			case "invalid-generation":
				r.value.Generation = 0
				want = ErrPending
			case "deny-first":
				c.denyAt = 1
				want = ErrDenied
			case "deny-last":
				c.denyAt = 8
				want = ErrDenied
			case "deny-and-drift":
				c.denyAt = 1
				c.changeAt = 1
				want = ErrConflict
			case "drift-first":
				c.changeAt = 1
				want = ErrConflict
			case "drift-last":
				c.changeAt = 8
				want = ErrConflict
			case "generation", "store", "model":
				c.changeAt = 8
				c.mutation = name
				want = ErrConflict
			case "checker-error":
				c.failAt = 8
				want = ErrUnavailable
			case "model-error":
				c.wrongModelAt = 8
				want = ErrConflict
			case "closing-error", "cancel":
				want = ErrUnavailable
			case "between-check-pending":
				want = ErrConflict
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checker := planningRevisionCheckFunc(func(ctx context.Context, q CheckRequest) (Decision, error) {
				d, err := c.Check(ctx, q)
				if name == "between-check-pending" && len(c.seen) == 1 {
					r.value.Desired++
				}
				if name == "cancel" && len(c.seen) == 8 {
					cancel()
				}
				return d, err
			})
			reader := planningRevisionReadFunc(func(ctx context.Context, o string) (Revision, error) {
				if name == "closing-error" && r.reads == 1 {
					return Revision{}, ErrUnavailable
				}
				return r.Revision(ctx, o)
			})
			got, err := checkOrderedTestRevisionSet(ctx, reader, checker, spec, f, requests, store, model)
			if !errors.Is(err, want) || got != (Revision{}) {
				t.Fatal("refusal result", err, want)
			}
			if want == ErrInvalid && (r.reads != 0 || len(c.seen) != 0) {
				t.Fatal("malformed set performed IO")
			}
			if name == "deny-first" || name == "deny-last" || name == "deny-and-drift" {
				if r.reads != 2 || len(c.seen) != c.denyAt {
					t.Fatal("denial did not close revision or continued checks", r.reads, len(c.seen))
				}
			}
		})
	}
}
