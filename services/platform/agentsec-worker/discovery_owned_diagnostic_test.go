package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
)

// Read-only by default. Cancellation needs an exact caller-supplied namespace
// and workflow ID and verifies our owned local-test description first.
func TestProductDiscoveryOwnedDiagnostic(t *testing.T) {
	mode := os.Getenv("ZASP_P4B_OWNED_DIAGNOSTIC")
	if mode == "" {
		t.Skip("explicit local diagnostic only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if mode == "list" {
		response, err := c.WorkflowService().ListNamespaces(ctx, &workflowservice.ListNamespacesRequest{PageSize: 1000})
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range response.Namespaces {
			if strings.HasPrefix(n.NamespaceInfo.Name, "p4b-owned-") {
				t.Log(n.NamespaceInfo.Name, n.NamespaceInfo.Description)
			}
		}
		return
	}
	ns, id := os.Getenv("ZASP_P4B_OWNED_NAMESPACE"), os.Getenv("ZASP_P4B_OWNED_WORKFLOW")
	if mode != "cancel" || !strings.HasPrefix(ns, "p4b-owned-") || !strings.HasPrefix(id, "discovery/v1/") {
		t.Fatal("exact owned diagnostic required")
	}
	n, err := c.WorkflowService().DescribeNamespace(ctx, &workflowservice.DescribeNamespaceRequest{Namespace: ns})
	if err != nil || n.NamespaceInfo.Description != "P4B owned local integration" {
		t.Fatal("foreign namespace", err)
	}
	d, err := c.WorkflowService().DescribeWorkflowExecution(ctx, &workflowservice.DescribeWorkflowExecutionRequest{Namespace: ns, Execution: &commonpb.WorkflowExecution{WorkflowId: id}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.WorkflowService().RequestCancelWorkflowExecution(ctx, &workflowservice.RequestCancelWorkflowExecutionRequest{Namespace: ns, WorkflowExecution: d.WorkflowExecutionInfo.Execution, Identity: "p4b-owned-diagnostic-cancel"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("cancel requested for exact owned diagnostic", ns, id)
}
