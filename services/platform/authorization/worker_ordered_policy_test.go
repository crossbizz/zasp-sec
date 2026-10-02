package authorization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Catches a supported native composition becoming unencodable or silently
// dropping a grantor/task target. Persistent sources can be non-runtime
// policies, so their 100-source bound is independent of compiled policy count.
func TestOrderedPolicyMaximumProof(t *testing.T) {
	f := orderedPolicyShapeFixture(100)
	f.OrganizationID = "pid_00000004-0000-4000-8000-000000000001"
	f.WorkspaceID = "pid_00000004-0000-4000-8000-000000000002"
	f.EnvironmentID = "pid_00000004-0000-4000-8000-000000000003"
	f.PrincipalID = "pid_00000004-0000-4000-8000-000000000004"
	f.GrantorID = "pid_00000004-0000-4000-8000-000000000005"
	f.SessionUser = "ordered_executor_login"
	for _, target := range f.Checks {
		for _, actor := range []struct{ kind, id, task string }{{"user", f.GrantorID, ""}, {"service", f.PrincipalID, f.RunID}} {
			if _, err := Map(CheckRequest{OrganizationID: f.OrganizationID, WorkspaceID: f.WorkspaceID, EnvironmentID: f.EnvironmentID, PrincipalKind: actor.kind, PrincipalID: actor.id, TaskID: actor.task, ResourceType: target.Kind, ResourceID: target.ID, Permission: target.Permission}); err != nil {
				t.Fatal("maximum composition mapping", err)
			}
		}
	}
	raw, _ := json.Marshal(f)
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"definition_digest", "source_digest", "target_digest", "destination_digest", "ordered_targets_digest", "request_digest", "signing_target_digest", "signing_delivery_digest", "signing_composition_digest"} {
		metadata[field] = string(bytes.Repeat([]byte{'a'}, 64))
	}
	for _, field := range []string{"credential_binding_id", "snapshot_id", "evidence_id", "integration_id"} {
		metadata[field] = "pid_00000005-0000-4000-8000-000000000001"
	}
	metadata["definition_version"], metadata["test_version"], metadata["run_version"] = 1000000, 1000000, 1000000
	metadata["source"], metadata["run_state"], metadata["execution_phase"], metadata["fresh_until_ms"] = "observed-native-source", "running", "ordered68.delivery.apply.store", int64(1893456000000)
	metadata["step"] = map[string]any{"step_id": f.RunID, "action_key": "create_temporary_policy", "state": "executing", "version": 1000000, "input_digest": string(bytes.Repeat([]byte{'b'}, 64)), "plan_hash": string(bytes.Repeat([]byte{'c'}, 64))}
	metadata["effect"] = map[string]any{"effect_key": f.RunID, "generation": 1, "state": "reserved", "snapshot_digest": string(bytes.Repeat([]byte{'d'}, 64))}
	raw, _ = json.Marshal(metadata)
	key, err := NewWorkerKey(WorkerForward, bytes.Repeat([]byte{71}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &WorkerExecutor{key: key}
	decision, err := e.signWorkerDecision("ordered68.delivery.apply.store", json.RawMessage(`{}`), nil, raw, Revision{OrganizationID: f.OrganizationID, Desired: 123456789, Applied: 123456789, Generation: 1, StoreID: "01K00000000000000000000001", ModelID: "01K00000000000000000000002"}, f.SessionUser, time.Unix(1893455900, 0))
	if err != nil {
		t.Fatalf("complete native composition proof refused: facts_bytes=%d: %v", len(raw), err)
	}
	var envelope struct {
		Body []byte `json:"body"`
	}
	var proof struct {
		Facts workerFacts `json:"facts"`
	}
	if json.Unmarshal(decision.envelope, &envelope) != nil || json.Unmarshal(envelope.Body, &proof) != nil || len(envelope.Body) > 32768 || len(proof.Facts.OrderedPolicyIDs) != 100 || len(proof.Facts.OrderedSourceRunIDs) != 100 || len(proof.Facts.Checks) != 203 {
		t.Fatal("maximum composition proof truncated or exceeded native bound")
	}
	t.Logf("ordered_policy_persistent=100 temporary=100 checks=203 grantor_task_requests=406 body_bytes=%d envelope_bytes=%d", len(envelope.Body), len(decision.envelope))
}

func orderedPolicyShapeFixture(count int) workerFacts {
	f := workerFacts{DefinitionID: "pid_00000001-0000-4000-8000-000000000001", RunID: "pid_00000001-0000-4000-8000-000000000002", TriggerKind: "finding", TargetKind: "agent", OrderedActionKey: "create_temporary_policy", OrderedPolicyDeviceID: "pid_00000001-0000-4000-8000-000000000003"}
	values := [][3]string{{"security_agent", f.DefinitionID, "manage_workflows"}, {"security_agent_run", f.RunID, "manage_workflows"}, {"gateway_device", f.OrderedPolicyDeviceID, "manage_workflows"}}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("pid_00000002-0000-4000-8000-%012d", i+1)
		f.OrderedPolicyIDs = append(f.OrderedPolicyIDs, id)
		values = append(values, [3]string{"policy", id, "view"})
	}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("pid_00000003-0000-4000-8000-%012d", i+1)
		f.OrderedSourceRunIDs = append(f.OrderedSourceRunIDs, id)
		values = append(values, [3]string{"security_agent_run", id, "view"})
	}
	for _, v := range values {
		f.Checks = append(f.Checks, struct {
			Kind       string `json:"kind"`
			ID         string `json:"id"`
			Permission string `json:"permission"`
		}{v[0], v[1], v[2]})
	}
	return f
}

func TestOrderedPolicyCompleteCompositionShape(t *testing.T) {
	for _, n := range []int{0, 1, 100} {
		for _, trigger := range []string{"finding", "attack_path"} {
			f := orderedPolicyShapeFixture(n)
			f.TriggerKind = trigger
			operation := WorkerOperation("ordered68.delivery.apply.store")
			if n == 0 {
				operation = "ordered68.application.source"
			}
			if !orderedPolicyWorkerCheckShape(operation, f) {
				t.Fatalf("full native per-device source set refused: %d/%s", n, trigger)
			}
		}
	}
}

func TestOrderedPolicyRejectsCompositionDrift(t *testing.T) {
	for _, name := range []string{"missing", "extra", "reordered", "permission", "foreign-policy", "foreign-source", "wrong-device", "duplicate-policy", "duplicate-source", "reverse-policy", "reverse-source", "too-many", "full-destination-array", "task", "runtime", "test-action"} {
		t.Run(name, func(t *testing.T) {
			original, _ := json.Marshal(orderedPolicyShapeFixture(2))
			var f workerFacts
			_ = json.Unmarshal(original, &f)
			switch name {
			case "missing":
				f.Checks = f.Checks[:len(f.Checks)-1]
			case "extra":
				f.Checks = append(f.Checks, f.Checks[0])
			case "reordered":
				f.Checks[3], f.Checks[4] = f.Checks[4], f.Checks[3]
			case "permission":
				f.Checks[3].Permission = "manage"
			case "foreign-policy":
				f.Checks[3].ID = f.RunID
			case "foreign-source":
				f.Checks[5].ID = f.DefinitionID
			case "wrong-device":
				f.OrderedPolicyDeviceID = f.DefinitionID
			case "duplicate-policy":
				f.OrderedPolicyIDs[1] = f.OrderedPolicyIDs[0]
				f.Checks[4].ID = f.OrderedPolicyIDs[0]
			case "duplicate-source":
				f.OrderedSourceRunIDs[1] = f.OrderedSourceRunIDs[0]
				f.Checks[6].ID = f.OrderedSourceRunIDs[0]
			case "reverse-policy":
				f.OrderedPolicyIDs[0], f.OrderedPolicyIDs[1] = f.OrderedPolicyIDs[1], f.OrderedPolicyIDs[0]
				f.Checks[3], f.Checks[4] = f.Checks[4], f.Checks[3]
			case "reverse-source":
				f.OrderedSourceRunIDs[0], f.OrderedSourceRunIDs[1] = f.OrderedSourceRunIDs[1], f.OrderedSourceRunIDs[0]
				f.Checks[5], f.Checks[6] = f.Checks[6], f.Checks[5]
			case "too-many":
				f = orderedPolicyShapeFixture(101)
			case "full-destination-array":
				f.OrderedDeviceIDs = []string{f.OrderedPolicyDeviceID}
			case "task":
				f.TaskID = f.RunID
			case "runtime":
				f.TriggerKind = "runtime_decision"
			case "test-action":
				f.OrderedActionKey = "run_test"
			}
			if orderedPolicyWorkerCheckShape("ordered68.delivery.apply.store", f) {
				t.Fatal("incomplete or wrong native composition accepted")
			}
		})
	}
}

func TestOrderedPolicyShapeCannotCrossSigningPhase(t *testing.T) {
	if orderedPolicyWorkerCheckShape("ordered68.delivery.apply.store", orderedPolicyShapeFixture(0)) {
		t.Fatal("delivery accepted no actual temporary source")
	}
	if orderedPolicyWorkerCheckShape("ordered68.application.source", orderedPolicyShapeFixture(1)) {
		t.Fatal("source accepted unrelated composed targets")
	}
	for _, op := range []WorkerOperation{"ordered68.cleanup.source", "ordered68.delivery.cleanup.store", "ordered68.sql"} {
		if orderedPolicyWorkerCheckShape(op, orderedPolicyShapeFixture(1)) {
			t.Fatal("non-forward phase accepted forward source shape")
		}
	}
}

func TestOrderedPolicySigningOnlyOperationSet(t *testing.T) {
	for _, op := range []WorkerOperation{"ordered68.application.source", "ordered68.delivery.apply.store", "ordered68.cleanup.source", "ordered68.cleanup.renew", "ordered68.delivery.cleanup.store"} {
		s, ok := orderedPolicyWorkerOperation(op)
		comp := op == "ordered68.cleanup.source" || op == "ordered68.cleanup.renew" || op == "ordered68.delivery.cleanup.store"
		purpose := WorkerForward
		if comp {
			purpose = CapturedCompensation
		}
		if !ok || s.purpose != purpose || s.current == comp || !s.orderedSigning || s.orderedExecution || s.bindRequest || s.phase != string(op) || s.statement != "" || s.source != `SELECT zasp_authorization80_worker.ordered68_policy_source($1,$2::jsonb)` || s.limit != 32768 {
			t.Fatal("wrong signing-only dispatch", op)
		}
	}
	for _, op := range []WorkerOperation{"ordered68.effect.start", "ordered68.application.complete", "ordered68.delivery.store", "ordered68.cleanup.unknown", "ordered68.sql"} {
		if _, ok := orderedPolicyWorkerOperation(op); ok {
			t.Fatal("unexpected signing route", op)
		}
	}
}
