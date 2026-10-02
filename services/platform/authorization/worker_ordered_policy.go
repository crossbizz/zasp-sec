package authorization

func orderedPolicyWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	purpose, ok := orderedSigningPurpose(operation)
	if !ok {
		return workerOperationSpec{}, false
	}
	return workerOperationSpec{purpose: purpose, source: `SELECT zasp_authorization80_worker.ordered68_policy_source($1,$2::jsonb)`, phase: string(operation), current: purpose == WorkerForward, limit: 32768, orderedSigning: true}, true
}

// Signing authorizes one actual destination and every native composition
// source. Initial reserve's complete destination-set shape remains separate.
func orderedPolicyWorkerCheckShape(operation WorkerOperation, f workerFacts) bool {
	if operation == "ordered68.application.source" {
		if len(f.OrderedPolicyIDs) != 0 || len(f.OrderedSourceRunIDs) != 0 {
			return false
		}
	} else if operation == "ordered68.delivery.apply.store" {
		if len(f.OrderedSourceRunIDs) < 1 {
			return false
		}
	} else {
		return false
	}
	if f.TaskID != "" || f.TriggerKind != "finding" && f.TriggerKind != "attack_path" || f.OrderedActionKey != "create_temporary_policy" || f.OrderedPolicyDeviceID == "" || len(f.OrderedDeviceIDs) != 0 || f.DefinitionID == "" || f.RunID == "" || len(f.OrderedPolicyIDs) > 100 || len(f.OrderedSourceRunIDs) > 100 {
		return false
	}
	for _, ids := range [][]string{f.OrderedPolicyIDs, f.OrderedSourceRunIDs} {
		for i, id := range ids {
			if id == "" || i > 0 && ids[i-1] >= id {
				return false
			}
		}
	}
	expected := [][3]string{{"security_agent", f.DefinitionID, "manage_workflows"}, {"security_agent_run", f.RunID, "manage_workflows"}, {"gateway_device", f.OrderedPolicyDeviceID, "manage_workflows"}}
	for _, id := range f.OrderedPolicyIDs {
		expected = append(expected, [3]string{"policy", id, "view"})
	}
	for _, id := range f.OrderedSourceRunIDs {
		expected = append(expected, [3]string{"security_agent_run", id, "view"})
	}
	if len(f.Checks) != len(expected) {
		return false
	}
	for i, want := range expected {
		got := f.Checks[i]
		if [3]string{got.Kind, got.ID, got.Permission} != want {
			return false
		}
	}
	return true
}
