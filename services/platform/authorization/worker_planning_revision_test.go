package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func planningSetFixture(trigger string) (*adapterSetReader, *adapterSetChecker, []CheckRequest) {
	r, c, requests := adapterSetFixture()
	for i := 4; i < 8; i++ {
		requests[i].Permission = "view"
	}
	if trigger != "manual" {
		q := exampleRequest()
		q.ResourceType = trigger
		requests = append(requests, q)
		q.PrincipalKind, q.TaskID = "service", task
		requests = append(requests, q)
	}
	return r, c, requests
}

// A finite reader budget models the measured consuming10s failure without a
// sleep. Every original target/subject Check must still execute in order.
func TestTestPlanningRevisionCompleteSets(t *testing.T) {
	for _, trigger := range []string{"manual", "finding", "attack_path"} {
		t.Run(trigger, func(t *testing.T) {
			r, c, requests := planningSetFixture(trigger)
			r.budget = 2
			want := r.value
			got, err := checkTestPlanningRevisionSet(context.Background(), r, c, requests, want.StoreID, want.ModelID)
			count := 8
			if trigger != "manual" {
				count = 10
			}
			if err != nil || got != want || len(c.seen) != count || r.reads != 2 {
				t.Fatal("incomplete or excessive planning authority read", err, len(c.seen), r.reads)
			}
			for i, q := range requests {
				if c.seen[i] != q {
					t.Fatal("planning target/subject changed", i)
				}
			}
			// A second request must read a new revision, not reuse the first.
			r.budget = 4
			r.value.Desired++
			r.value.Applied++
			c.seen = nil
			got, err = checkTestPlanningRevisionSet(context.Background(), r, c, requests, want.StoreID, want.ModelID)
			if err != nil || got != r.value || got == want || r.reads != 4 {
				t.Fatal("cross-request revision reused", err)
			}
		})
	}
}

func TestTestPlanningRevisionRejectsMutations(t *testing.T) {
	for _, trigger := range []string{"manual", "finding", "attack_path"} {
		for _, name := range []string{"early revision", "last revision", "generation", "store mutation", "model mutation", "mixed organization", "mixed workspace", "mixed environment", "missing task", "invalid resource", "pending", "foreign tenant", "wrong store", "wrong model", "invalid generation", "denied", "result model", "checker failure", "reader failure", "truncated", "extra"} {
			t.Run(trigger+"/"+name, func(t *testing.T) {
				r, c, requests := planningSetFixture(trigger)
				last := len(requests)
				store, model := r.value.StoreID, r.value.ModelID
				want := ErrConflict
				switch name {
				case "early revision":
					c.changeAt = 1
				case "last revision":
					c.changeAt = last
				case "generation":
					c.changeAt = last
					c.mutation = "generation"
				case "store mutation":
					c.changeAt = last
					c.mutation = "store"
				case "model mutation":
					c.changeAt = last
					c.mutation = "model"
				case "mixed organization":
					requests[last-1].OrganizationID = principal
					want = ErrInvalid
				case "mixed workspace":
					requests[last-1].WorkspaceID = principal
					want = ErrInvalid
				case "mixed environment":
					requests[last-1].EnvironmentID = principal
					want = ErrInvalid
				case "missing task":
					requests[last-1].TaskID = ""
					want = ErrInvalid
				case "invalid resource":
					requests[last-1].ResourceID = "invalid"
					want = ErrInvalid
				case "pending":
					r.value.Desired++
					want = ErrPending
				case "foreign tenant":
					r.value.OrganizationID = principal
					want = ErrPending
				case "wrong store":
					store = "01K00000000000000000000009"
					want = ErrPending
				case "wrong model":
					model = "01K00000000000000000000009"
					want = ErrPending
				case "invalid generation":
					r.value.Generation = 0
					want = ErrPending
				case "denied":
					c.denyAt = last
					want = ErrDenied
				case "result model":
					c.wrongModelAt = last
				case "checker failure":
					c.failAt = last
					want = ErrUnavailable
				case "reader failure":
					r.fail = true
					want = ErrUnavailable
				case "truncated":
					requests = requests[:last-1]
					want = ErrInvalid
				case "extra":
					requests = append(requests, requests[0])
					want = ErrInvalid
				}
				got, err := checkTestPlanningRevisionSet(context.Background(), r, c, requests, store, model)
				if !errors.Is(err, want) || got != (Revision{}) {
					t.Fatal("invalid planning set admitted", err)
				}
			})
		}
	}
}

type planningRevisionCheckFunc func(context.Context, CheckRequest) (Decision, error)

func (f planningRevisionCheckFunc) Check(ctx context.Context, q CheckRequest) (Decision, error) {
	return f(ctx, q)
}

type planningRevisionReadFunc func(context.Context, string) (Revision, error)

func (f planningRevisionReadFunc) Revision(ctx context.Context, o string) (Revision, error) {
	return f(ctx, o)
}

func TestTestPlanningRevisionCancellationAndFinalRead(t *testing.T) {
	for _, name := range []string{"cancel before", "cancel last check", "final reader failure"} {
		t.Run(name, func(t *testing.T) {
			r, c, requests := planningSetFixture("finding")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "cancel before" {
				cancel()
			}
			checker := planningRevisionCheckFunc(func(ctx context.Context, q CheckRequest) (Decision, error) {
				d, err := c.Check(ctx, q)
				if name == "cancel last check" && len(c.seen) == 10 {
					cancel()
				}
				return d, err
			})
			reader := planningRevisionReadFunc(func(ctx context.Context, o string) (Revision, error) {
				if name == "final reader failure" && r.reads == 1 {
					return Revision{}, ErrUnavailable
				}
				return r.Revision(ctx, o)
			})
			got, err := checkTestPlanningRevisionSet(ctx, reader, checker, requests, r.value.StoreID, r.value.ModelID)
			if !errors.Is(err, ErrUnavailable) || got != (Revision{}) {
				t.Fatal("cancelled/incomplete revision bracket admitted", err)
			}
		})
	}
}

func planningShapeFixture(t *testing.T, trigger string) workerFacts {
	t.Helper()
	f := workerFacts{DefinitionID: resource, RunID: task, TestID: resource, TargetID: resource, TargetKind: "agent", TriggerKind: trigger, TriggerID: resource}
	raw := fmt.Sprintf(`[{"kind":"security_agent","id":%q,"permission":"manage_workflows"},{"kind":"security_agent_run","id":%q,"permission":"manage_workflows"},{"kind":"test","id":%q,"permission":"view"},{"kind":"agent","id":%q,"permission":"view"}`, resource, task, resource, resource)
	if trigger != "manual" {
		raw += fmt.Sprintf(`,{"kind":%q,"id":%q,"permission":"view"}`, trigger, resource)
	}
	if err := json.Unmarshal([]byte(raw+`]`), &f.Checks); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTestPlanningRevisionScopeAndShape(t *testing.T) {
	for _, phase := range []string{"state", "load", "prepare", "start", "result", "settle", "artifacts", "admit"} {
		spec, ok := workerOperation(WorkerOperation("test74.planning." + phase))
		if !ok || !spec.current || !spec.testPlanning {
			t.Fatal("current test planning phase excluded", phase)
		}
		for _, trigger := range []string{"manual", "finding", "attack_path"} {
			f := planningShapeFixture(t, trigger)
			if !workerCheckShape(spec, f) {
				t.Fatal("valid planning shape rejected", phase, trigger)
			}
			for _, mutate := range []func(*workerFacts){func(f *workerFacts) { f.Checks = f.Checks[:len(f.Checks)-1] }, func(f *workerFacts) { f.Checks[2].Permission = "run_tests" }, func(f *workerFacts) { f.Checks[0].ID = principal }, func(f *workerFacts) { f.TriggerKind = "runtime_decision" }, func(f *workerFacts) { f.Checks[0], f.Checks[1] = f.Checks[1], f.Checks[0] }} {
				bad := planningShapeFixture(t, trigger)
				mutate(&bad)
				if workerCheckShape(spec, bad) {
					t.Fatal("changed native planning shape admitted", phase, trigger)
				}
			}
		}
	}
	for _, op := range []WorkerOperation{"test74.planning.reconcile", "test74.planning.late_usage", "test74.planning.recovery", "finding.planning.prepare", "test74.effect.start", "test74.adapter.start", FindingApply} {
		spec, ok := workerOperation(op)
		if !ok || spec.current && spec.testPlanning {
			t.Fatal("unrelated operation entered planning bracket scope", op)
		}
	}
}
