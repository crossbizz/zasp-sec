package authorization

func orderedDomainWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: CapturedCompensation, source: `SELECT zasp_authorization80_worker.ordered68_operation_source($1,$2::jsonb)`, phase: string(operation), limit: 32768, orderedDomain: true}
	switch operation {
	case "ordered68.application.read", "ordered68.application.complete":
		s.purpose, s.current = WorkerForward, true
		s.statement = `SELECT zasp_temporal68.application($1::jsonb)`
	case "ordered68.cleanup.prepare", "ordered68.cleanup.read", "ordered68.cleanup.complete":
		s.statement = `SELECT zasp_temporal68.cleanup($1::jsonb)`
	case "ordered68.delivery.apply.prepare":
		s.purpose, s.current = WorkerForward, true
		s.statement = `SELECT zasp_temporal68.delivery($1::jsonb)`
	case "ordered68.delivery.apply.read", "ordered68.delivery.apply.ack", "ordered68.delivery.cleanup.prepare", "ordered68.delivery.cleanup.read", "ordered68.delivery.cleanup.ack":
		s.statement = `SELECT zasp_temporal68.delivery($1::jsonb)`
	default:
		return workerOperationSpec{}, false
	}
	return s, true
}

func orderedDomainWorkerCheckShape(operation WorkerOperation, f workerFacts) bool {
	switch operation {
	case "ordered68.application.read", "ordered68.application.complete":
		return f.OrderedActionKey == "create_temporary_policy" && f.OrderedPolicyDeviceID == "" && len(f.OrderedPolicyIDs) == 0 && len(f.OrderedSourceRunIDs) == 0 && orderedEffectWorkerCheckShape(f)
	case "ordered68.delivery.apply.prepare":
		// Preparation must authorize the same full source composition as store,
		// but it is ordinary execution and never invokes the signing callback.
		return orderedPolicyWorkerCheckShape("ordered68.delivery.apply.store", f)
	}
	return false
}
