package orchestration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
)

// Read-only diagnosis of this task's retained local test execution. Never starts
// a Workflow, mutates the namespace or prints private product input/output.
func TestAutomaticSourceRetainedHistoryDiagnostic(t *testing.T) {
	run, workflowID := os.Getenv("ZASP_TEST77_DIAGNOSTIC_RUN"), os.Getenv("ZASP_TEST77_DIAGNOSTIC_WORKFLOW")
	if run == "" || !strings.HasPrefix(workflowID, "security-agent-test/v1/") {
		t.Skip("requires exact owned retained execution")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var token []byte
	for {
		page, err := c.WorkflowService().ListNamespaces(ctx, &workflowservice.ListNamespacesRequest{PageSize: 100, NextPageToken: token})
		if err != nil {
			t.Fatal(err)
		}
		for _, ns := range page.Namespaces {
			name := ns.NamespaceInfo.GetName()
			if !strings.HasPrefix(name, "automatic-source77-") {
				continue
			}
			found, err := c.WorkflowService().GetWorkflowExecutionHistory(ctx, &workflowservice.GetWorkflowExecutionHistoryRequest{Namespace: name, Execution: &commonpb.WorkflowExecution{WorkflowId: workflowID, RunId: run}})
			if err != nil {
				continue
			}
			t.Log("owned namespace", name)
			for _, ev := range found.History.Events {
				t.Log("event", ev.EventId, ev.EventTime.AsTime(), ev.EventType.String())
				if a := ev.GetActivityTaskScheduledEventAttributes(); a != nil {
					t.Log("activity", a.ActivityType.GetName())
				}
				if a := ev.GetActivityTaskCompletedEventAttributes(); a != nil {
					var state RunState
					if converter.GetDefaultDataConverter().FromPayloads(a.Result, &state) == nil && state.Phase != "" {
						t.Log("redacted phase", state.Phase)
					}
				}
				if a := ev.GetActivityTaskFailedEventAttributes(); a != nil {
					t.Log("failed", a.ScheduledEventId, a.RetryState.String(), a.Failure.GetMessage())
				}
			}
			if len(found.NextPageToken) != 0 {
				t.Fatal("diagnostic history exceeds first page")
			}
			return
		}
		token = page.NextPageToken
		if len(token) == 0 {
			t.Fatal("owned execution not found")
		}
	}
}
