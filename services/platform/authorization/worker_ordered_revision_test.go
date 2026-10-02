package authorization

import (
	"context"
	"errors"
	"testing"
)

// The consuming deadline failed on the twentieth revision read after all ten
// Checks. This finite budget catches recurrence without wall-clock sleeps.
func TestOrderedPlanningRevisionCompleteSet(t *testing.T) {
	for _, trigger := range []string{"finding", "attack_path"} {
		t.Run(trigger, func(t *testing.T) {
			r, c, requests := planningSetFixture(trigger)
			r.budget = 2
			want := r.value
			got, err := checkOrderedPlanningRevisionSet(context.Background(), r, c, requests, want.StoreID, want.ModelID)
			if err != nil || got != want || len(c.seen) != 10 || r.reads != 2 {
				t.Fatal("incomplete ordered authority set", err, len(c.seen), r.reads)
			}
			for i, request := range requests {
				if c.seen[i] != request {
					t.Fatal("ordered target or subject skipped", i)
				}
			}
			r.value.Desired++
			r.value.Applied++
			r.budget = 4
			c.seen = nil
			got, err = checkOrderedPlanningRevisionSet(context.Background(), r, c, requests, want.StoreID, want.ModelID)
			if err != nil || got == want || got != r.value || r.reads != 4 || len(c.seen) != 10 {
				t.Fatal("cross-call revision reused", err)
			}
		})
	}
}

func TestOrderedPlanningRevisionRefusesChangedAuthority(t *testing.T) {
	for _, name := range []string{"early revision", "last revision", "generation", "store mutation", "model mutation", "mixed organization", "mixed workspace", "mixed environment", "missing task", "invalid resource", "pending", "foreign tenant", "wrong store", "wrong model", "invalid generation", "deny", "result model", "checker failure", "reader failure", "truncated", "extra", "manual-sized"} {
		t.Run(name, func(t *testing.T) {
			r, c, requests := planningSetFixture("finding")
			store, model := r.value.StoreID, r.value.ModelID
			want := ErrConflict
			switch name {
			case "early revision":
				c.changeAt = 1
			case "last revision":
				c.changeAt = 10
			case "generation", "store mutation", "model mutation":
				c.changeAt = 10
				c.mutation = map[string]string{"generation": "generation", "store mutation": "store", "model mutation": "model"}[name]
			case "mixed organization":
				requests[9].OrganizationID, want = principal, ErrInvalid
			case "mixed workspace":
				requests[9].WorkspaceID, want = principal, ErrInvalid
			case "mixed environment":
				requests[9].EnvironmentID, want = principal, ErrInvalid
			case "missing task":
				requests[9].TaskID, want = "", ErrInvalid
			case "invalid resource":
				requests[9].ResourceID, want = "invalid", ErrInvalid
			case "pending":
				r.value.Desired++
				want = ErrPending
			case "foreign tenant":
				r.value.OrganizationID, want = principal, ErrPending
			case "wrong store":
				store, want = "01K00000000000000000000009", ErrPending
			case "wrong model":
				model, want = "01K00000000000000000000009", ErrPending
			case "invalid generation":
				r.value.Generation, want = 0, ErrPending
			case "deny":
				c.denyAt, want = 10, ErrDenied
			case "result model":
				c.wrongModelAt = 10
			case "checker failure":
				c.failAt, want = 10, ErrUnavailable
			case "reader failure":
				r.fail, want = true, ErrUnavailable
			case "truncated":
				requests, want = requests[:9], ErrInvalid
			case "extra":
				requests, want = append(requests, requests[0]), ErrInvalid
			case "manual-sized":
				requests, want = requests[:8], ErrInvalid
			}
			got, err := checkOrderedPlanningRevisionSet(context.Background(), r, c, requests, store, model)
			if !errors.Is(err, want) || got != (Revision{}) {
				t.Fatal("invalid ordered authority accepted", err)
			}
		})
	}
}

func TestOrderedPlanningRevisionCancellationAndFinalRead(t *testing.T) {
	for _, name := range []string{"before", "last check", "final read"} {
		t.Run(name, func(t *testing.T) {
			r, c, requests := planningSetFixture("finding")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "before" {
				cancel()
			}
			checker := planningRevisionCheckFunc(func(ctx context.Context, q CheckRequest) (Decision, error) {
				d, err := c.Check(ctx, q)
				if name == "last check" && len(c.seen) == 10 {
					cancel()
				}
				return d, err
			})
			reader := planningRevisionReadFunc(func(ctx context.Context, o string) (Revision, error) {
				if name == "final read" && r.reads == 1 {
					return Revision{}, ErrUnavailable
				}
				return r.Revision(ctx, o)
			})
			got, err := checkOrderedPlanningRevisionSet(ctx, reader, checker, requests, r.value.StoreID, r.value.ModelID)
			if !errors.Is(err, ErrUnavailable) || got != (Revision{}) {
				t.Fatal("incomplete ordered revision interval accepted", err)
			}
		})
	}
}

func TestOrderedPlanningRevisionDispatchScope(t *testing.T) {
	for _, phase := range []string{"state", "load", "prepare", "start", "result", "settle", "artifacts", "admit"} {
		spec, ok := workerOperation(WorkerOperation("ordered68.planning." + phase))
		if !ok || !spec.current || !spec.orderedPlanning || spec.testPlanning || spec.adapter || spec.discovery {
			t.Fatal("ordered current route not isolated", phase)
		}
		for _, trigger := range []string{"finding", "attack_path"} {
			if !workerCheckShape(spec, planningShapeFixture(t, trigger)) || workerCheckShape(spec, planningShapeFixture(t, "manual")) {
				t.Fatal("ordered native shape broadened", phase, trigger)
			}
		}
	}
	for _, op := range []WorkerOperation{"ordered68.planning.recovery", "ordered68.planning.reconcile", "ordered68.planning.late_usage", "test74.planning.state", "finding.planning.state", "test74.effect.start", "test74.adapter.start", FindingApply} {
		spec, ok := workerOperation(op)
		if !ok || spec.current && spec.orderedPlanning {
			t.Fatal("unrelated operation selected ordered current bracket", op)
		}
	}
}
