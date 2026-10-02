package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

type workerAuthorityRefusalDatabase struct {
	apiserver.JSONDatabase
	failure error
	calls   int
}

func (d *workerAuthorityRefusalDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	if statement != `SELECT zasp_temporal74.inspect($1::jsonb)` {
		return nil, errors.New("unexpected forward operation")
	}
	d.calls++
	return nil, fmt.Errorf("private source detail: %w", d.failure)
}

type workerAuthorityCleanupObserver struct {
	orchestration.SingleTestProduct
	cleanups int
	request  orchestration.CleanupRequest
}

func (p *workerAuthorityCleanupObserver) Cleanup(_ context.Context, q orchestration.CleanupRequest) error {
	p.cleanups++
	p.request = q
	return nil
}

// The actual product maps its database boundary before actual Activities enter
// workflow history. Cleanup here is a counted routing boundary, not SQL proof.
func TestWorkerAuthorityActivityClassificationAndCleanup(t *testing.T) {
	q := orchestration.StartRequest{Ref: orchestration.RunRef{OrganizationID: "pid_6a000001-0000-4000-8000-000000000001", WorkspaceID: "pid_6a000002-0000-4000-8000-000000000002", EnvironmentID: "pid_6a000003-0000-4000-8000-000000000003", RunID: "pid_8e190001-0000-4000-8000-000000000001"}, DefinitionVersion: 2, InputDigest: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name      string
		failure   error
		attempts  int
		kind      string
		permanent bool
	}{
		{"denied", authorization.ErrDenied, 1, "ProductRefused", true},
		{"invalid", authorization.ErrInvalid, 1, "ProductRefused", true},
		{"pending", authorization.ErrPending, 5, "ProductUnavailable", false},
		{"revision", authorization.ErrConflict, 5, "ProductUnavailable", false},
		{"transport", authorization.ErrUnavailable, 5, "ProductUnavailable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &workerAuthorityRefusalDatabase{failure: tc.failure}
			product := &workerAuthorityCleanupObserver{SingleTestProduct: (&temporalSecurityAgentProduct{executor: db}).SingleTestProduct()}
			activities := &orchestration.SingleTestActivities{Product: product}
			_, err := activities.Observe(context.Background(), q)
			var app *temporal.ApplicationError
			if !errors.As(err, &app) || app.Type() != tc.kind || app.NonRetryable() != tc.permanent || strings.Contains(err.Error(), "private source") || app.HasDetails() {
				t.Fatalf("redacted Activity classification: %v", err)
			}
			db.calls = 0
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			env.RegisterActivityWithOptions(activities.Observe, activity.RegisterOptions{Name: "SingleObserve"})
			env.RegisterActivityWithOptions(activities.Cleanup, activity.RegisterOptions{Name: "SingleCleanup"})
			env.ExecuteWorkflow(orchestration.SingleTestWorkflow, q)
			if env.GetWorkflowError() == nil || db.calls != tc.attempts || product.cleanups != 1 || product.request.Start != q || product.request.Reason != "workflow_failed" {
				t.Fatalf("authority attempts and cleanup: calls=%d cleanups=%d error=%v", db.calls, product.cleanups, env.GetWorkflowError())
			}
		})
	}
}
