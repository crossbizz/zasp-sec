package authorization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// A wrong purpose or nested phase could authorize a new reserve from captured
// compensation. These are independent literal expectations, not derived SQL.
func TestOrderedEffectOperationPurpose(t *testing.T) {
	for _, phase := range []string{"reserve", "start", "read", "unknown"} {
		spec, ok := orderedEffectWorkerOperation(WorkerOperation("ordered68.effect." + phase))
		compensation := phase == "read" || phase == "unknown"
		purpose := WorkerForward
		if compensation {
			purpose = CapturedCompensation
		}
		if !ok || spec.purpose != purpose || spec.current == compensation || !spec.orderedExecution || spec.orderedPlanning || spec.testExecution || spec.adapter || spec.discovery || spec.bindRequest || spec.limit != 4096 || spec.phase != "effect."+phase || spec.source != `SELECT zasp_authorization80_worker.ordered68_effect_source($1,$2::jsonb)` || spec.statement != `SELECT zasp_temporal68.effect($1::jsonb)` {
			t.Fatalf("wrong ordered effect boundary for %s", phase)
		}
	}
	for _, operation := range []WorkerOperation{"ordered68.effect.sql", "ordered68.effect.complete", "ordered68.effect.start.extra", "ordered68.application.source", "ordered68.delivery.apply.store", "ordered68.planning.start", "test74.effect.reserve"} {
		if _, ok := orderedEffectWorkerOperation(operation); ok {
			t.Fatal("unreleased nested operation accepted", operation)
		}
	}
}

func orderedEffectShapeFixture(t *testing.T, action string, count int) workerFacts {
	t.Helper()
	f := workerFacts{DefinitionID: "pid_00000001-0000-4000-8000-000000000001", RunID: "pid_00000001-0000-4000-8000-000000000002", TestID: "pid_00000001-0000-4000-8000-000000000003", TargetID: "pid_00000001-0000-4000-8000-000000000004", TargetKind: "agent", TriggerKind: "finding", TriggerID: "pid_00000001-0000-4000-8000-000000000005", OrderedActionKey: action}
	checks := [][3]string{{"security_agent", f.DefinitionID, "manage_workflows"}, {"security_agent_run", f.RunID, "manage_workflows"}}
	if action == "create_temporary_policy" {
		for i := 0; i < count; i++ {
			id := fmt.Sprintf("pid_00000001-0000-4000-8000-%012d", i+100)
			f.OrderedDeviceIDs = append(f.OrderedDeviceIDs, id)
			checks = append(checks, [3]string{"gateway_device", id, "manage_workflows"})
		}
	} else {
		checks = append(checks, [3]string{"test", f.TestID, "run_tests"}, [3]string{f.TargetKind, f.TargetID, "run_tests"})
	}
	for _, c := range checks {
		f.Checks = append(f.Checks, struct {
			Kind       string `json:"kind"`
			ID         string `json:"id"`
			Permission string `json:"permission"`
		}{c[0], c[1], c[2]})
	}
	return f
}

func TestOrderedEffectCompleteNativeTargets(t *testing.T) {
	for _, action := range []string{"create_temporary_policy", "run_test"} {
		for _, trigger := range []string{"finding", "attack_path"} {
			for _, n := range []int{1, 100} {
				f := orderedEffectShapeFixture(t, action, n)
				f.TriggerKind = trigger
				if !orderedEffectWorkerCheckShape(f) {
					t.Fatalf("complete target set refused %s/%s/%d", action, trigger, n)
				}
			}
		}
	}
}

func TestOrderedEffectRefusesIncompleteOrForeignShape(t *testing.T) {
	for _, action := range []string{"create_temporary_policy", "run_test"} {
		base := orderedEffectShapeFixture(t, action, 2)
		raw, _ := json.Marshal(base)
		names := []string{"truncated", "extra", "reordered", "permission", "target", "definition", "task", "trigger", "action"}
		if action == "create_temporary_policy" {
			names = append(names, "empty-device", "duplicate-device", "reordered-device", "extra-device", "oversized-device")
		} else {
			names = append(names, "test-with-device")
		}
		for _, name := range names {
			t.Run(action+"/"+name, func(t *testing.T) {
				var f workerFacts
				if err := json.Unmarshal(raw, &f); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "truncated":
					f.Checks = f.Checks[:len(f.Checks)-1]
				case "extra":
					f.Checks = append(f.Checks, f.Checks[0])
				case "reordered":
					f.Checks[0], f.Checks[1] = f.Checks[1], f.Checks[0]
				case "permission":
					f.Checks[2].Permission = "view"
				case "target":
					f.Checks[2].ID = f.DefinitionID
				case "definition":
					f.DefinitionID = ""
				case "task":
					f.TaskID = f.RunID
				case "trigger":
					f.TriggerKind = "runtime_decision"
				case "action":
					f.OrderedActionKey = "monitor"
				case "empty-device":
					f.OrderedDeviceIDs = nil
				case "duplicate-device":
					f.OrderedDeviceIDs[1] = f.OrderedDeviceIDs[0]
					f.Checks[3].ID = f.OrderedDeviceIDs[0]
				case "reordered-device":
					f.OrderedDeviceIDs[0], f.OrderedDeviceIDs[1] = f.OrderedDeviceIDs[1], f.OrderedDeviceIDs[0]
					f.Checks[2], f.Checks[3] = f.Checks[3], f.Checks[2]
				case "extra-device":
					f.OrderedDeviceIDs = append(f.OrderedDeviceIDs, f.TargetID)
				case "oversized-device":
					f = orderedEffectShapeFixture(t, action, 101)
				case "test-with-device":
					f.OrderedDeviceIDs = []string{f.TargetID}
				}
				if orderedEffectWorkerCheckShape(f) {
					t.Fatal("unsafe effect target set accepted")
				}
			})
		}
	}
}

func TestOrderedEffectDispatchAndMaximumProof(t *testing.T) {
	for _, phase := range []string{"reserve", "start", "read", "unknown"} {
		spec, ok := workerOperation(WorkerOperation("ordered68.effect." + phase))
		if !ok || !spec.orderedExecution || spec.orderedPlanning || spec.testExecution || spec.adapter || spec.discovery {
			t.Fatal("effect dispatch crossed family", phase)
		}
		if spec.current && !workerCheckShape(spec, orderedEffectShapeFixture(t, "create_temporary_policy", 100)) {
			t.Fatal("maximum dispatched Block shape refused")
		}
	}
	f := orderedEffectShapeFixture(t, "create_temporary_policy", 100)
	f.OrganizationID = "pid_00000002-0000-4000-8000-000000000001"
	f.WorkspaceID = "pid_00000002-0000-4000-8000-000000000002"
	f.EnvironmentID = "pid_00000002-0000-4000-8000-000000000003"
	f.PrincipalID = "pid_00000002-0000-4000-8000-000000000004"
	f.GrantorID = "pid_00000002-0000-4000-8000-000000000005"
	f.SessionUser = "ordered_executor_login"
	for _, target := range f.Checks {
		for _, actor := range []struct{ kind, id, task string }{{"user", f.GrantorID, ""}, {"service", f.PrincipalID, f.RunID}} {
			if _, err := Map(CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: actor.kind, PrincipalID: actor.id, TaskID: actor.task, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}); err != nil {
				t.Fatal("maximum actual resource mapping", err)
			}
		}
	}
	raw, _ := json.Marshal(f)
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"definition_digest", "source_digest", "target_digest", "destination_digest", "ordered_targets_digest", "request_digest"} {
		metadata[field] = string(bytes.Repeat([]byte{'a'}, 64))
	}
	for _, field := range []string{"credential_binding_id", "snapshot_id", "evidence_id", "integration_id"} {
		metadata[field] = "pid_00000003-0000-4000-8000-000000000001"
	}
	metadata["definition_version"], metadata["test_version"], metadata["run_version"] = 1000000, 1000000, 1000000
	metadata["source"], metadata["run_state"], metadata["execution_phase"], metadata["fresh_until_ms"] = "observed-native-source", "running", "effect.start", int64(1893456000000)
	metadata["step"] = map[string]any{"step_id": f.RunID, "action_key": "create_temporary_policy", "state": "executing", "version": 1000000, "input_digest": string(bytes.Repeat([]byte{'b'}, 64)), "plan_hash": string(bytes.Repeat([]byte{'c'}, 64))}
	metadata["effect"] = map[string]any{"effect_key": f.RunID, "generation": 1, "state": "reserved", "snapshot_digest": string(bytes.Repeat([]byte{'d'}, 64))}
	raw, _ = json.Marshal(metadata)
	key, err := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &WorkerExecutor{key: key}
	decision, err := e.signWorkerDecision("ordered68.effect.start", json.RawMessage(`{}`), nil, raw, Revision{OrganizationID: f.OrganizationID, Desired: 123456789, Applied: 123456789, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, f.SessionUser, time.Unix(1893455900, 0))
	if err != nil {
		t.Fatal("maximum native destination proof refused", err)
	}
	var envelope struct {
		Body []byte `json:"body"`
	}
	if json.Unmarshal(decision.envelope, &envelope) != nil || len(envelope.Body) > 32768 {
		t.Fatal("maximum destination proof exceeds native cap")
	}
	var proof struct {
		Facts workerFacts `json:"facts"`
	}
	if json.Unmarshal(envelope.Body, &proof) != nil || len(proof.Facts.OrderedDeviceIDs) != 100 || len(proof.Facts.Checks) != 102 || proof.Facts.OrderedDeviceIDs[99] != f.OrderedDeviceIDs[99] {
		t.Fatal("maximum proof dropped a target")
	}
	t.Logf("ordered_effect_devices=100 checks=102 grantor_task_requests=204 body_bytes=%d envelope_bytes=%d", len(envelope.Body), len(decision.envelope))
}
