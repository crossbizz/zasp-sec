package authorization

// Every operation selects a fixed native entry and a fixed purpose. Caller
// supplied SQL, family names and nested operations cannot select another path.
type workerOperationSpec struct {
	purpose                  WorkerPurpose
	source, phase, statement string
	current, bindRequest     bool
	limit                    int
	testPlanning             bool
	orderedPlanning          bool
	orderedExecution         bool
	orderedSigning           bool
	orderedDomain            bool
	orderedTest              bool
	testExecution            bool
	adapter                  bool
	discovery                bool
}

func workerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: WorkerForward, source: `SELECT zasp_authorization80_worker.finding_source($1,$2::jsonb)`, phase: string(operation), bindRequest: true, limit: 8192}
	switch operation {
	case FindingApply:
		s.current = true
		s.statement = `SELECT zasp_temporal78.apply($1::jsonb)`
	case FindingReplay:
		s.statement = `SELECT zasp_temporal78.apply($1::jsonb)`
	case FindingCleanup:
		s.purpose = CapturedCompensation
		s.statement = `SELECT zasp_temporal78.cleanup($1::jsonb)`
	case "test74.adapter.resolve", "test74.adapter.start":
		s.adapter, s.testExecution, s.current, s.bindRequest = true, true, true, false
		s.source = `SELECT zasp_authorization80_worker.adapter74_source($1,$2::jsonb)`
		s.phase = string(operation)[len("test74.adapter."):]
		s.statement = `SELECT zasp_temporal74.invocation($1::jsonb)`
	case "test74.adapter.complete":
		s.purpose, s.bindRequest = CapturedCompensation, false
		s.source = `SELECT zasp_authorization80_worker.test74_completion_source($1,$2::jsonb)`
		s.phase = "complete"
		s.statement = `SELECT zasp_authorization80_worker.test74_complete($1::jsonb)`
	case "test74.adapter.receipt":
		s.purpose, s.bindRequest = CapturedCompensation, false
		s.source = `SELECT zasp_authorization80_worker.test74_receipt_source($1,$2::jsonb)`
		s.phase, s.limit = "receipt", 4096
		s.statement = `SELECT zasp_authorization80_worker.test74_receipt($1::jsonb)`
	case "test74.lifecycle.inspect", "test74.lifecycle.cleanup", "test74.lifecycle.recovery_status":
		s.purpose, s.bindRequest = CapturedCompensation, false
		s.source = `SELECT zasp_authorization80_worker.test74_lifecycle_source($1,$2::jsonb)`
		s.phase, s.limit = string(operation)[len("test74.lifecycle."):], 4096
		s.statement = `SELECT zasp_temporal74.inspect($1::jsonb)`
		if s.phase == "cleanup" {
			s.statement = `SELECT zasp_temporal74.cleanup($1::jsonb)`
		} else if s.phase == "recovery_status" {
			s.statement = `SELECT zasp_authorization80_worker.test74_recovery_status($1::jsonb)`
		}
	case "test74.settlement.input", "test74.settlement.child", "test74.settlement.snapshot", "test74.settlement.complete":
		s.purpose, s.bindRequest = CapturedCompensation, false
		s.source = `SELECT zasp_authorization80_worker.test74_settlement_source($1,$2::jsonb)`
		s.phase, s.limit = string(operation)[len("test74.settlement."):], 1600000
		s.statement = `SELECT zasp_authorization80_worker.test74_settle($1::jsonb)`
	case "test74.effect.reserve", "test74.effect.start", "test74.effect.read", "test74.effect.unknown", "test74.linked.read", "test74.linked.input", "test74.linked.dispatch", "test74.state":
		s.testExecution, s.current, s.bindRequest = true, true, false
		s.source = `SELECT zasp_authorization80_worker.test74_effect_source($1,$2::jsonb)`
		s.phase = string(operation)[len("test74."):]
		s.statement = `SELECT zasp_temporal74.effect($1::jsonb)`
		s.limit = 4096
		switch s.phase {
		case "effect.read", "effect.unknown":
			s.purpose, s.current = CapturedCompensation, false
		case "state":
			s.purpose, s.current = CapturedCompensation, false
			s.statement = `SELECT zasp_temporal74.test_state($1::jsonb)`
		case "linked.read", "linked.input", "linked.dispatch":
			s.statement = `SELECT zasp_temporal74.linked($1::jsonb)`
			s.limit = 131072
		}
	case "test74.planning.state", "test74.planning.load", "test74.planning.prepare", "test74.planning.start", "test74.planning.result", "test74.planning.settle", "test74.planning.artifacts", "test74.planning.admit", "test74.planning.reconcile", "test74.planning.late_usage", "test74.planning.recovery":
		s.testPlanning = true
		fallthrough
	case "finding.planning.state", "finding.planning.load", "finding.planning.prepare", "finding.planning.start", "finding.planning.result", "finding.planning.settle", "finding.planning.artifacts", "finding.planning.admit", "finding.planning.reconcile", "finding.planning.late_usage", "finding.planning.recovery":
		s.source = `SELECT zasp_authorization80_worker.planning78_source($1,$2::jsonb)`
		s.phase = string(operation)[len("finding.planning."):]
		s.bindRequest = false
		s.limit = 524288
		s.current = true
		s.statement = `SELECT zasp_temporal78.plan($1::jsonb)`
		switch s.phase {
		case "state":
			s.statement = `SELECT zasp_temporal78.planning_state($1::jsonb)`
			s.limit = 4096
		case "reconcile", "late_usage":
			s.purpose = CapturedCompensation
			s.current = false
			s.limit = 131072
		case "recovery":
			s.purpose = CapturedCompensation
			s.current = false
			s.limit = 4096
			s.statement = `SELECT zasp_authorization80_worker.planning78_recovery($1::jsonb)`
		}
		if s.testPlanning {
			// Literal operation cases above keep the family and phase closed.
			s.source = `SELECT zasp_authorization80_worker.planning74_source($1,$2::jsonb)`
			s.phase = string(operation)[len("test74.planning."):]
			s.statement = `SELECT zasp_temporal74.plan($1::jsonb)`
			switch s.phase {
			case "state":
				s.statement = `SELECT zasp_temporal74.planning_state($1::jsonb)`
				s.limit = 4096
			case "reconcile", "late_usage", "recovery":
				s.purpose, s.current, s.limit = CapturedCompensation, false, 131072
				if s.phase == "recovery" {
					s.limit = 4096
					s.statement = `SELECT zasp_authorization80_worker.planning74_recovery($1::jsonb)`
				}
			}
		}
	default:
		if ordered, ok := orderedTestWorkerOperation(operation); ok {
			return ordered, true
		}
		if lifecycle, ok := orderedLifecycleWorkerOperation(operation); ok {
			return lifecycle, true
		}
		if ordered, ok := orderedEffectWorkerOperation(operation); ok {
			return ordered, true
		}
		if ordered, ok := orderedWorkerOperation(operation); ok {
			ordered.orderedPlanning = true
			return ordered, true
		}
		if ordered, ok := orderedPolicyWorkerOperation(operation); ok {
			return ordered, true
		}
		if ordered, ok := orderedDomainWorkerOperation(operation); ok {
			return ordered, true
		}
		return discoveryWorkerOperation(operation)
	}
	return s, true
}

func workerCheckShape(spec workerOperationSpec, facts workerFacts) bool {
	if spec.orderedTest {
		return orderedTestWorkerCheckShape(spec, facts)
	}
	if spec.orderedDomain {
		return orderedDomainWorkerCheckShape(WorkerOperation(spec.phase), facts)
	}
	if spec.orderedSigning {
		return orderedPolicyWorkerCheckShape(WorkerOperation(spec.phase), facts)
	}
	if spec.orderedExecution {
		return orderedEffectWorkerCheckShape(facts)
	}
	if spec.orderedPlanning {
		return orderedWorkerCheckShape(facts)
	}
	if spec.discovery {
		return discoveryWorkerCheckShape(facts)
	}
	if facts.TriggerKind == "runtime_decision" && (spec.testPlanning || spec.testExecution) {
		return runtimeTestCheckShape(spec, facts)
	}
	if !spec.testPlanning && !spec.testExecution {
		return len(facts.Checks) == 3
	}
	count := 4
	switch facts.TriggerKind {
	case "manual":
	case "finding", "attack_path":
		if !spec.testExecution {
			count++
		}
	default:
		return false
	}
	if len(facts.Checks) != count || facts.TargetKind != "agent" && facts.TargetKind != "tool" {
		return false
	}
	want := [][3]string{{"security_agent", facts.DefinitionID, "manage_workflows"}, {"security_agent_run", facts.RunID, "manage_workflows"}, {"test", facts.TestID, "view"}, {facts.TargetKind, facts.TargetID, "view"}}
	if spec.testExecution {
		want[2][2], want[3][2] = "run_tests", "run_tests"
	}
	if count == 5 {
		want = append(want, [3]string{facts.TriggerKind, facts.TriggerID, "view"})
	}
	for i, target := range facts.Checks {
		if target.ID == "" || [3]string{target.Kind, target.ID, target.Permission} != want[i] {
			return false
		}
	}
	return true
}
