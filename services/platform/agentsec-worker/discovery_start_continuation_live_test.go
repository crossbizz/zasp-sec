package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/types/known/durationpb"
)

// This controlled workflow exists only to exercise our duplicate-start trust
// boundary against real Temporal continued-chain descriptions/history. It is
// not collection/authority evidence; the267-page installed case supplies that.
func discoveryStartContinuedFixture(ctx workflow.Context, start orchestration.DiscoveryStart) (string, error) {
	if start.Continuation.CheckpointVersion == 0 {
		start.Continuation = &orchestration.DiscoveryContinuation{Deadline: start.Continuation.Deadline, CheckpointVersion: 256, ReceiptDigest: strings.Repeat("a", 64)}
		return "", workflow.NewContinueAsNewError(ctx, "DiscoveryWorkflow", start)
	}
	return "continued", nil
}

func TestProductDiscoveryContinuedStartLive(t *testing.T) {
	if os.Getenv("ZASP_P4B_LOCAL_TEMPORAL") != "1" {
		t.Skip("explicit owned local Temporal test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	namespace := fmt.Sprintf("p4b-owned-%d", time.Now().UnixNano())
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.WorkflowService().RegisterNamespace(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: "P4B owned local integration", WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	defer deleteOwnedDiscoveryNamespace(t, c, namespace)
	queue := namespace + "-start"
	w := worker.New(c, queue, worker.Options{WorkerStopTimeout: 5 * time.Second})
	w.RegisterWorkflowWithOptions(discoveryStartContinuedFixture, workflow.RegisterOptions{Name: "DiscoveryWorkflow"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	start := orchestration.DiscoveryStart{Ref: orchestration.RunRef{OrganizationID: discoveryCredentialID(1).String(), WorkspaceID: discoveryCredentialID(2).String(), EnvironmentID: discoveryCredentialID(3).String(), RunID: discoveryCredentialID(4).String()}, IntegrationID: discoveryCredentialID(5).String(), InputDigest: strings.Repeat("b", 64), Continuation: &orchestration.DiscoveryContinuation{Deadline: time.Now().UTC().Add(time.Hour)}}
	starter, err := orchestration.NewDiscoveryStarter(c, queue, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := starter.Start(ctx, start); err != nil {
		t.Fatal("initial start", err)
	}
	id, _ := orchestration.DiscoveryWorkflowID(start)
	var result string
	if err := c.GetWorkflow(ctx, id, "").Get(ctx, &result); err != nil || result != "continued" {
		t.Fatal("continued fixture", result, err)
	}
	description, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil || description.WorkflowExecutionInfo.Execution.RunId == description.WorkflowExecutionInfo.FirstRunId {
		t.Fatal("fixture did not continue", err)
	}
	if err := starter.Start(ctx, start); err != nil {
		t.Fatal("confirmed continued duplicate refused", err)
	}
	foreign := start
	foreign.InputDigest = strings.Repeat("f", 64)
	if err := starter.Start(ctx, foreign); err == nil {
		t.Fatal("foreign continued input acknowledged")
	}
	t.Log("confirmed continued-chain duplicate; foreign input refused")
}
