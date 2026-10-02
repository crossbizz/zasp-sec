package orchestration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
)

// A configured definition must switch the actual Schedule action away from the
// legacy rule-blind Activity, without changing its stable Schedule identity.
func TestTemporalAutomaticScheduleSelection(t *testing.T) {
	d := selectorDesired()
	s := &selectorSourceFixture{desired: d}
	transport := &scheduleTransportFixture{}
	r, err := NewTestSelectorReconciler(transport, s, "tests", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(context.Background(), d.Ref); err != nil {
		t.Fatal(err)
	}
	legacy := transport.options
	if legacy.Action.(*client.ScheduleWorkflowAction).Workflow != "TestSelectorWorkflow" {
		t.Fatal("omitted rule behavior changed")
	}
	var wire map[string]any
	raw, _ := json.Marshal(d)
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("desired fixture")
	}
	wire["automatic"] = true
	raw, _ = json.Marshal(wire)
	if json.Unmarshal(raw, &s.desired) != nil {
		t.Fatal("configured desired contract")
	}
	transport.exists = true
	if err := r.Reconcile(context.Background(), d.Ref); err != nil {
		t.Fatal(err)
	}
	action, ok := transport.schedule.Action.(*client.ScheduleWorkflowAction)
	if !ok || action.Workflow != "AutomaticCatchupWorkflow" || action.ID != legacy.Action.(*client.ScheduleWorkflowAction).ID || action.TaskQueue != "tests" || action.WorkflowExecutionTimeout != 0 {
		t.Fatalf("configured Schedule action=%#v", action)
	}
	s.desired.Enabled = false
	if err := r.Reconcile(context.Background(), d.Ref); err != nil || !transport.schedule.State.Paused {
		t.Fatal("configured pause", err)
	}
}
