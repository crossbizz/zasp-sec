package authorization

import "testing"

func TestOrderedDomainOperationAuthority(t *testing.T) {
	for _, tc := range []struct {
		op      WorkerOperation
		family  string
		forward bool
	}{
		{"ordered68.application.read", "application", true},
		{"ordered68.application.complete", "application", true},
		{"ordered68.cleanup.prepare", "cleanup", false},
		{"ordered68.cleanup.read", "cleanup", false},
		{"ordered68.cleanup.complete", "cleanup", false},
		{"ordered68.delivery.apply.prepare", "delivery", true},
		{"ordered68.delivery.apply.read", "delivery", false},
		{"ordered68.delivery.apply.ack", "delivery", false},
		{"ordered68.delivery.cleanup.prepare", "delivery", false},
		{"ordered68.delivery.cleanup.read", "delivery", false},
		{"ordered68.delivery.cleanup.ack", "delivery", false},
	} {
		t.Run(string(tc.op), func(t *testing.T) {
			s, ok := workerOperation(tc.op)
			purpose := CapturedCompensation
			if tc.forward {
				purpose = WorkerForward
			}
			if !ok || s.purpose != purpose || s.current != tc.forward || s.phase != string(tc.op) || s.source != `SELECT zasp_authorization80_worker.ordered68_operation_source($1,$2::jsonb)` || s.statement != "SELECT zasp_temporal68."+tc.family+"($1::jsonb)" || s.bindRequest || s.orderedSigning || s.orderedPlanning || s.adapter || s.discovery || s.limit != 32768 {
				t.Fatal("wrong native operation boundary")
			}
		})
	}
	for _, op := range []WorkerOperation{"ordered68.application.source", "ordered68.delivery.apply.store", "ordered68.cleanup.renew", "ordered68.delivery.other.prepare", "ordered68.application.sql"} {
		if _, ok := orderedDomainWorkerOperation(op); ok {
			t.Fatal("unclassified operation accepted", op)
		}
	}
}

func TestOrderedDomainCompleteAuthorityShape(t *testing.T) {
	for _, op := range []WorkerOperation{"ordered68.application.read", "ordered68.application.complete"} {
		s, _ := workerOperation(op)
		for _, count := range []int{1, 100} {
			f := orderedEffectShapeFixture(t, "create_temporary_policy", count)
			if !workerCheckShape(s, f) {
				t.Fatal("complete Block set refused", op, count)
			}
			f.Checks[len(f.Checks)-1].Permission = "view"
			if workerCheckShape(s, f) {
				t.Fatal("weakened destination permission accepted")
			}
		}
		if workerCheckShape(s, orderedEffectShapeFixture(t, "run_test", 1)) {
			t.Fatal("Test authority accepted for Block completion")
		}
	}
	s, _ := workerOperation("ordered68.delivery.apply.prepare")
	for _, count := range []int{1, 100} {
		f := orderedPolicyShapeFixture(count)
		if !workerCheckShape(s, f) {
			t.Fatal("complete composition refused", count)
		}
		f.Checks = f.Checks[:len(f.Checks)-1]
		if workerCheckShape(s, f) {
			t.Fatal("truncated composition accepted")
		}
	}
}
