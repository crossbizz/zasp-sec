package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/operatorservice/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/types/known/durationpb"
)

// One real Apply activity, not a replacement SecurityAgentWorkflow. The source
// contract test and actual server history pin its published retry/timeout
// settings. No fake Observe state or simulated clock is used.
func orderedCapacityApplyWorkflow(ctx workflow.Context, q orchestration.StartRequest) error {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 20 * time.Minute, ScheduleToCloseTimeout: time.Hour,
		HeartbeatTimeout: 30 * time.Second, WaitForCancellation: true,
		RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: time.Minute, MaximumAttempts: 5},
	})
	return workflow.ExecuteActivity(ctx, "Apply", q).Get(ctx, nil)
}

type orderedCapacityAttemptProduct struct {
	*temporalSecurityAgentProduct
	t                 *testing.T
	owner             *pgxpool.Pool
	trace             *orderedCapacityTrace
	mu                sync.Mutex
	attempts, pending int
}

func (p *orderedCapacityAttemptProduct) observe(ctx context.Context, q orchestration.StartRequest, attempt int32, boundary string) {
	p.t.Helper()
	read, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var desired, applied, generation int64
	var stored, sources, deliveries, receipts int
	err := p.owner.QueryRow(read, `SELECT desired,applied,generation,
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$2 AND phase='apply' AND state='stored'),
 (SELECT count(*) FROM zasp_security_agent_temporary_policy_targets WHERE run_id=$2 AND phase='apply' AND state='verified'),
 (SELECT count(*) FROM zasp_temporal68.deliveries WHERE run_id=$2 AND phase='apply' AND state='acknowledged'),
 (SELECT count(*) FROM zasp_sa_multistep_receipts WHERE run_id=$2 AND receipt_kind='temporary_policy_applied.v1')
 FROM zasp_authorization79.organizations WHERE organization_id=$1`, q.Ref.OrganizationID, q.Ref.RunID).Scan(&desired, &applied, &generation, &stored, &sources, &deliveries, &receipts)
	if err != nil {
		p.t.Error("capacity attempt observation", boundary, "class", orderedCapacityClass(err))
		return
	}
	p.t.Log("capacity attempt", attempt, boundary, "projection_converged", desired == applied, "desired", desired, "applied", applied, "generation", generation, "stored_sources", stored, "verified_sources", sources, "acknowledged_deliveries", deliveries, "application_receipts", receipts)
}

func (p *orderedCapacityAttemptProduct) Apply(ctx context.Context, q orchestration.StartRequest) error {
	attempt := activity.GetInfo(ctx).Attempt
	p.mu.Lock()
	p.attempts++
	expected := p.attempts
	p.mu.Unlock()
	if attempt < 1 || attempt > 5 || int(attempt) != expected {
		p.t.Error("capacity SDK attempt outside sequential production bound")
		return orchestration.ErrInvalid
	}
	p.observe(ctx, q, attempt, "before")
	began := time.Now()
	// The actual public product method preserves inspect/reserve/start replay,
	// error translation and the shipped serial source/delivery/receipt loop.
	err := p.temporalSecurityAgentProduct.Apply(ctx, q)
	p.mu.Lock()
	if errors.Is(err, authorization.ErrPending) {
		p.pending++
	}
	p.mu.Unlock()
	p.t.Log("capacity attempt", attempt, "elapsed_ms", time.Since(began).Milliseconds(), "class", orderedCapacityClass(err), "last_phase", p.trace.lastPhase())
	p.observe(ctx, q, attempt, "after")
	return err
}

type orderedCapacityQuietLogger struct{}

func (orderedCapacityQuietLogger) Debug(string, ...interface{}) {}
func (orderedCapacityQuietLogger) Info(string, ...interface{})  {}
func (orderedCapacityQuietLogger) Warn(string, ...interface{})  {}
func (orderedCapacityQuietLogger) Error(string, ...interface{}) {}

func newOrderedCapacityWorker(c client.Client, queue string, activities *orchestration.Activities) worker.Worker {
	w := worker.New(c, queue, worker.Options{WorkerStopTimeout: 15 * time.Second, MaxConcurrentActivityExecutionSize: 1, MaxConcurrentWorkflowTaskExecutionSize: 2})
	w.RegisterWorkflow(orderedCapacityApplyWorkflow)
	w.RegisterActivityWithOptions(activities.Apply, activity.RegisterOptions{Name: "Apply"})
	return w
}

// Catch our worker configuration/registration error without repeating the
// expensive database producer. Lazy construction starts no server or activity.
func TestOrderedCapacityWorkerConstruction(t *testing.T) {
	c, err := client.NewLazyClient(client.Options{HostPort: "127.0.0.1:7233", Namespace: "capacity-constructor-only", Logger: orderedCapacityQuietLogger{}})
	if err != nil {
		t.Fatal("capacity lazy client construction")
	}
	defer c.Close()
	if newOrderedCapacityWorker(c, "capacity-constructor-only", &orchestration.Activities{Product: &temporalSecurityAgentProduct{}}) == nil {
		t.Fatal("capacity worker absent")
	}
}

func runOrderedCapacityApplyActivity(t *testing.T, ctx context.Context, owner *pgxpool.Pool, p *temporalSecurityAgentProduct, q orchestration.StartRequest, trace *orderedCapacityTrace) error {
	t.Helper()
	const prefix = "p7-ordered-capacity-"
	const description = "P7 owned Ordered100 Apply activity integration"
	namespace := fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
	options := client.Options{HostPort: "127.0.0.1:7233", Logger: orderedCapacityQuietLogger{}}
	connect, cancelConnect := context.WithTimeout(ctx, 10*time.Second)
	admin, err := client.DialContext(connect, options)
	cancelConnect()
	if err != nil {
		t.Fatal("capacity namespace client", orderedCapacityClass(err))
	}
	defer admin.Close()
	setup, cancelSetup := context.WithTimeout(ctx, 10*time.Second)
	_, err = admin.WorkflowService().RegisterNamespace(setup, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: description, WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
	cancelSetup()
	if err != nil {
		t.Fatal("capacity owned namespace registration", orderedCapacityClass(err))
	}
	retireNamespace := true
	// Install ownership-checked retirement before the scoped dial/worker setup,
	// so their failures cannot strand an already registered namespace.
	defer func() {
		if !retireNamespace {
			t.Error("capacity cleanup incomplete; retained owned namespace", namespace)
			return
		}
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if !strings.HasPrefix(namespace, prefix) {
			t.Error("foreign capacity namespace")
			return
		}
		if _, err := strconv.ParseInt(strings.TrimPrefix(namespace, prefix), 10, 64); err != nil {
			t.Error("malformed capacity namespace")
			return
		}
		d, err := admin.WorkflowService().DescribeNamespace(clean, &workflowservice.DescribeNamespaceRequest{Namespace: namespace})
		if err != nil || d.NamespaceInfo == nil || d.NamespaceInfo.Description != description {
			t.Error("capacity namespace ownership unavailable")
			return
		}
		if _, err := admin.OperatorService().DeleteNamespace(clean, &operatorservice.DeleteNamespaceRequest{Namespace: namespace}); err != nil {
			t.Error("capacity namespace retirement", orderedCapacityClass(err))
		} else {
			t.Log("retired owned capacity namespace")
		}
	}()
	options.Namespace = namespace
	dial, cancelDial := context.WithTimeout(ctx, 10*time.Second)
	c, err := client.DialContext(dial, options)
	cancelDial()
	if err != nil {
		t.Fatal("capacity Temporal client", orderedCapacityClass(err))
	}
	defer c.Close()
	measured := &orderedCapacityAttemptProduct{temporalSecurityAgentProduct: p, t: t, owner: owner, trace: trace}
	activities := &orchestration.Activities{Product: measured}
	queue := namespace + "-apply"
	w := newOrderedCapacityWorker(c, queue, activities)
	if err := w.Start(); err != nil {
		t.Fatal("capacity worker startup", orderedCapacityClass(err))
	}
	defer func() {
		w.Stop()
		drain, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := activities.Close(drain); err != nil {
			retireNamespace = false
			t.Error("capacity activities not drained", orderedCapacityClass(err))
		}
	}()
	// Start RPC failure is ambiguous: the server may already have accepted it.
	// Leave the owned namespace intact unless exact execution terminality is
	// later confirmed. Local worker drain alone cannot rule out queued retries.
	retireNamespace = false
	run, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: namespace + "-one-apply", TaskQueue: queue}, orderedCapacityApplyWorkflow, q)
	if err != nil {
		t.Fatal("capacity workflow start", orderedCapacityClass(err))
	}
	result := run.Get(ctx, nil)
	cancelJoined := true
	if ctx.Err() != nil {
		join, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if err := c.CancelWorkflow(join, run.GetID(), run.GetRunID()); err != nil {
			t.Error("capacity workflow cancellation", orderedCapacityClass(err))
		}
		joined := run.Get(join, nil)
		if !temporal.IsCanceledError(joined) {
			cancelJoined = false
			t.Error("capacity workflow cancellation not joined", orderedCapacityClass(joined))
		}
		cancel()
	}
	// A client/observer failure is not evidence the server execution stopped.
	// Never retire a namespace while this owned activity may still be running.
	statusCtx, cancelStatus := context.WithTimeout(context.Background(), 10*time.Second)
	status, statusErr := c.DescribeWorkflowExecution(statusCtx, run.GetID(), run.GetRunID())
	cancelStatus()
	if statusErr != nil || status == nil || status.WorkflowExecutionInfo == nil || status.WorkflowExecutionInfo.Status == enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING || status.WorkflowExecutionInfo.Status == enumspb.WORKFLOW_EXECUTION_STATUS_UNSPECIFIED {
		t.Error("capacity workflow terminal state unconfirmed", orderedCapacityClass(statusErr))
	} else if cancelJoined {
		retireNamespace = true
	}
	measured.mu.Lock()
	attempts, pending := measured.attempts, measured.pending
	measured.mu.Unlock()
	t.Log("capacity actual SDK activity attempts", attempts, "pending_attempts", pending, "workflow_class", orderedCapacityClass(result))
	read, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	history := c.GetWorkflowHistory(read, run.GetID(), run.GetRunID(), false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	scheduled := 0
	for history.HasNext() {
		event, err := history.Next()
		if err != nil {
			t.Error("capacity history unavailable", orderedCapacityClass(err))
			break
		}
		if a := event.GetActivityTaskScheduledEventAttributes(); a != nil {
			scheduled++
			r := a.RetryPolicy
			if a.ActivityType.GetName() != "Apply" || a.StartToCloseTimeout.AsDuration() != 20*time.Minute || a.ScheduleToCloseTimeout.AsDuration() != time.Hour || a.HeartbeatTimeout.AsDuration() != 30*time.Second || r == nil || r.InitialInterval.AsDuration() != time.Second || r.BackoffCoefficient != 2 || r.MaximumInterval.AsDuration() != time.Minute || r.MaximumAttempts != 5 || len(r.NonRetryableErrorTypes) != 0 {
				t.Error("scheduled capacity activity differs from production retry contract")
			}
		}
	}
	if scheduled != 1 || attempts < 1 || attempts > 5 {
		t.Error("capacity activity execution cardinality")
	}
	return result
}
