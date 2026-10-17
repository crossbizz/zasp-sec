package authorization

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"strings"
	"testing"
)

func TestApprovalActivationPreservesClosedForwardDispatch(t *testing.T) {
	activated := &WorkerExecutor{approvalOriginProfile: "original", approvalActivationProfile: "activation"}
	legacy := &WorkerExecutor{approvalOriginProfile: "original"}
	for _, op := range []WorkerOperation{"finding.planning.admit", "test74.planning.admit", "ordered68.planning.admit", "ordered68.progress"} {
		want, ok := approvalOriginStatement(op)
		got, activatedOK := activated.approvalOriginExecutionStatement(op)
		old, oldOK := legacy.approvalOriginExecutionStatement(op)
		if !ok || !activatedOK || !oldOK || old != want || got != strings.Replace(want, "zasp_approval_maintenance.", "zasp_approval_activation_v1.", 1) {
			t.Fatal("closed native forward dispatch changed", op)
		}
	}
	for _, op := range []WorkerOperation{FindingCleanup, FindingApply, "ordered68.cleanup", "finding.planning.load", "approval.sql", "ordered68.progress "} {
		if q, ok := activated.approvalOriginExecutionStatement(op); ok || q != "" {
			t.Fatal("non-admission/compensation redirected", op)
		}
	}
	unproved := &WorkerExecutor{approvalActivationProfile: "activation"}
	if q, ok := unproved.approvalOriginExecutionStatement("finding.planning.admit"); ok || q != "" {
		t.Fatal("activation without original profile admitted")
	}
}

func TestApprovalActivationConstructorRejectsWrongPinsBeforeDatabase(t *testing.T) {
	activation, err := migrations.ApprovalActivationProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	connector, err := migrations.ConnectorMaintenanceProfileChecksum()
	if err != nil {
		t.Fatal(err)
	}
	approval := migrations.ApprovalMaintenanceProfileChecksum()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name                            string
		ctx                             context.Context
		approval, connector, activation string
	}{
		{"absent", context.Background(), approval, connector, ""},
		{"unknown activation", context.Background(), approval, connector, strings.Repeat("0", 64)},
		{"missing original", context.Background(), "", connector, activation},
		{"wrong original", context.Background(), strings.Repeat("0", 64), connector, activation},
		{"wrong connector", context.Background(), approval, strings.Repeat("0", 64), activation},
		{"canceled", canceled, approval, connector, activation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := NewActivatedCurrentMaintenanceWorkerExecutor(tc.ctx, nil, nil, "", "", nil, tc.approval, tc.connector, tc.activation)
			if e != nil || err != ErrInvalid {
				t.Fatalf("invalid activation admitted: %v", err)
			}
		})
	}
}
