package authorization

func orderedEffectWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: WorkerForward, source: `SELECT zasp_authorization80_worker.ordered68_effect_source($1,$2::jsonb)`, statement: `SELECT zasp_temporal68.effect($1::jsonb)`, current: true, orderedExecution: true, limit: 4096}
	switch operation {
	case "ordered68.effect.reserve", "ordered68.effect.start":
	case "ordered68.effect.read", "ordered68.effect.unknown":
		s.purpose, s.current = CapturedCompensation, false
	default:
		return workerOperationSpec{}, false
	}
	s.phase = string(operation)[len("ordered68."):]
	return s, true
}

// This shape cannot substitute a runtime source-device subset for the complete
// native Block destination set. Runtime ancestry has a separate release gate.
func orderedEffectWorkerCheckShape(f workerFacts) bool {
	if f.TaskID != "" || f.TriggerKind != "finding" && f.TriggerKind != "attack_path" || f.TargetKind != "agent" && f.TargetKind != "tool" {
		return false
	}
	want := [][3]string{{"security_agent", f.DefinitionID, "manage_workflows"}, {"security_agent_run", f.RunID, "manage_workflows"}}
	switch f.OrderedActionKey {
	case "create_temporary_policy":
		if len(f.OrderedDeviceIDs) < 1 || len(f.OrderedDeviceIDs) > 100 {
			return false
		}
		for i, id := range f.OrderedDeviceIDs {
			if id == "" || i > 0 && id <= f.OrderedDeviceIDs[i-1] {
				return false
			}
			want = append(want, [3]string{"gateway_device", id, "manage_workflows"})
		}
	case "run_test":
		if len(f.OrderedDeviceIDs) != 0 {
			return false
		}
		want = append(want, [3]string{"test", f.TestID, "run_tests"}, [3]string{f.TargetKind, f.TargetID, "run_tests"})
	default:
		return false
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
