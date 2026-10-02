package authorization

import (
	"encoding/json"
	"testing"
)

// Wrong routing could permit recovery to create a send or expose a planner
// body without a current grantor/task decision.
func TestOrdered68PlanningOperationPurpose(t *testing.T) {
	for _, phase := range []string{"state", "load", "prepare", "start", "result", "settle", "artifacts", "admit", "recovery", "reconcile", "late_usage"} {
		t.Run(phase, func(t *testing.T) {
			spec, ok := workerOperation(WorkerOperation("ordered68.planning." + phase))
			captured := phase == "recovery" || phase == "reconcile" || phase == "late_usage"
			purpose := WorkerForward
			if captured {
				purpose = CapturedCompensation
			}
			if !ok || !spec.orderedPlanning || spec.orderedSigning || spec.purpose != purpose || spec.current == captured || spec.bindRequest || spec.adapter || spec.discovery {
				t.Fatal("ordered planner routed outside its authority boundary")
			}
		})
	}
	for _, operation := range []WorkerOperation{"ordered68.planning.sql", "ordered68.planning.cleanup", "ordered68.application.sql", "ordered68.adapter.receipt"} {
		if _, ok := workerOperation(operation); ok {
			t.Fatal("unreleased operation accepted", operation)
		}
	}
}

func TestOrdered68PlanningExactCheckShape(t *testing.T) {
	spec, ok := workerOperation("ordered68.planning.load")
	if !ok {
		t.Fatal("ordered planning route missing")
	}
	for _, trigger := range []string{"finding", "attack_path"} {
		for _, target := range []string{"agent", "tool"} {
			t.Run(trigger+"/"+target, func(t *testing.T) {
				var facts workerFacts
				if err := json.Unmarshal([]byte(`{"definition_id":"definition","run_id":"run","test_id":"test","target_id":"target","trigger_id":"trigger","checks":[{"kind":"security_agent","id":"definition","permission":"manage_workflows"},{"kind":"security_agent_run","id":"run","permission":"manage_workflows"},{"kind":"test","id":"test","permission":"view"},{"kind":"agent","id":"target","permission":"view"},{"kind":"finding","id":"trigger","permission":"view"}]}`), &facts); err != nil {
					t.Fatal(err)
				}
				facts.TriggerKind, facts.TargetKind = trigger, target
				facts.Checks[3].Kind, facts.Checks[4].Kind = target, trigger
				if !workerCheckShape(spec, facts) {
					t.Fatal("complete native-derived planning shape refused")
				}
				encoded, _ := json.Marshal(facts)
				for _, mutate := range []func(*workerFacts){
					func(f *workerFacts) { f.Checks = f.Checks[:4] },
					func(f *workerFacts) { f.Checks = append(f.Checks, f.Checks[4]) },
					func(f *workerFacts) { f.Checks[0], f.Checks[1] = f.Checks[1], f.Checks[0] },
					func(f *workerFacts) { f.Checks[2].Permission = "run_tests" },
					func(f *workerFacts) { f.Checks[4].ID = "another-trigger" },
					func(f *workerFacts) { f.TargetKind = "integration" },
					func(f *workerFacts) { f.TriggerKind = "runtime_decision" },
					func(f *workerFacts) { f.TriggerKind = "manual" },
					func(f *workerFacts) { f.TaskID = "discovery-task" },
				} {
					var changed workerFacts
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					if workerCheckShape(spec, changed) {
						t.Fatal("incomplete, broader, or wrong-family shape accepted")
					}
				}
			})
		}
	}
}
