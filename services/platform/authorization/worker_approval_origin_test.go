package authorization

import (
	"context"
	"testing"
)

func TestApprovalOriginExecutionRejectsUnprovedAndNonAdmitOperations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, v := range []struct {
		e   *WorkerExecutor
		ctx context.Context
		d   WorkerDecision
	}{{nil, context.Background(), WorkerDecision{operation: "finding.planning.admit"}}, {&WorkerExecutor{}, context.Background(), WorkerDecision{operation: "finding.planning.admit"}}, {&WorkerExecutor{}, ctx, WorkerDecision{operation: "finding.planning.admit"}}} {
		if out, err := v.e.ExecuteWithApprovalOrigin(v.ctx, v.d); out != nil || err != ErrInvalid {
			t.Fatal("unsigned/canceled origin admitted")
		}
	}
	for _, op := range []WorkerOperation{"finding.planning.load", "finding.planning.reconcile", "test74.planning.result", "ordered68.planning.recovery", FindingApply, "approval.sql"} {
		if _, ok := approvalOriginStatement(op); ok {
			t.Fatal("unbounded origin operation admitted")
		}
	}
}
