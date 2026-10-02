package authorization

func orderedLifecycleWorkerOperation(operation WorkerOperation) (workerOperationSpec, bool) {
	s := workerOperationSpec{purpose: CapturedCompensation, source: `SELECT zasp_authorization80_worker.ordered69_source($1,$2::jsonb)`, limit: 4096}
	switch operation {
	case "ordered69.inspect":
		s.phase, s.statement = "inspect", `SELECT zasp_authorization80_worker.ordered69_inspect($1::jsonb)`
	case "ordered69.message":
		s.phase, s.statement = "message", `SELECT zasp_authorization80_worker.ordered69_message($1::jsonb)`
	case "ordered69.stop":
		s.phase, s.statement = "stop", `SELECT zasp_authorization80_worker.ordered69_stop($1::jsonb)`
	default:
		return workerOperationSpec{}, false
	}
	return s, true
}
