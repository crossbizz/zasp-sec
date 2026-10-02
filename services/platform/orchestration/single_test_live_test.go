package orchestration

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/protobuf/types/known/durationpb"
)

type singleTestLivePendingProduct struct {
	observations atomic.Int32
	proved       atomic.Bool
	reentered    atomic.Bool
}

func (p *singleTestLivePendingProduct) Observe(context.Context, StartRequest) (RunState, error) {
	return RunState{Phase: "terminal"}, nil
}
func (p *singleTestLivePendingProduct) Plan(context.Context, StartRequest) error {
	p.reentered.Store(true)
	return ErrConflict
}
func (p *singleTestLivePendingProduct) Test(context.Context, StartRequest) error {
	p.reentered.Store(true)
	return ErrConflict
}
func (p *singleTestLivePendingProduct) Settle(context.Context, StartRequest) error {
	p.reentered.Store(true)
	return ErrConflict
}
func (p *singleTestLivePendingProduct) Cleanup(context.Context, CleanupRequest) error {
	p.observations.Add(1)
	if !p.proved.Load() {
		return ErrCleanupPending
	}
	return nil
}

// Real local Temporal validates our registered continuation and history-proof
// client together. Product proof is controlled here, not PostgreSQL evidence.
func TestSingleTestLiveCleanupContinuation(t *testing.T) {
	if os.Getenv("ZASP_SINGLE_TEST_LIVE_TEMPORAL") != "true" {
		t.Skip("requires explicit owned local Temporal test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	namespace := fmt.Sprintf("p4c-test74-cleanup-%d", time.Now().UnixNano())
	nc, err := client.NewNamespaceClient(client.Options{HostPort: "127.0.0.1:7233"})
	if err != nil {
		t.Fatal(err)
	}
	err = nc.Register(ctx, &workflowservice.RegisterNamespaceRequest{Namespace: namespace, Description: "owned specialized cleanup contract", WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour)})
	nc.Close()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := &singleTestLivePendingProduct{}
	a := &SingleTestActivities{Product: p}
	w := worker.New(c, namespace, worker.Options{WorkerStopTimeout: 2 * time.Second})
	w.RegisterWorkflow(SingleTestWorkflow)
	w.RegisterWorkflow(SingleTestCleanupWorkflow)
	for name, handler := range map[string]any{"SingleObserve": a.Observe, "SinglePlan": a.Plan, "SingleTest": a.Test, "SingleSettle": a.Settle, "SingleCleanup": a.Cleanup} {
		w.RegisterActivityWithOptions(handler, activity.RegisterOptions{Name: name})
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	e, err := NewTemporalEngine(c, namespace, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	q := request()
	id, _ := SingleTestWorkflowID(q.Ref)
	if err := e.StartSingleTest(ctx, q); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for p.observations.Load() < 66 {
		select {
		case <-ctx.Done():
			t.Fatal("same workflow cleanup continuation did not progress", ctx.Err(), p.observations.Load())
		case <-ticker.C:
			if err := e.WakeSingleTest(ctx, q); err != nil {
				t.Fatal("existing cleanup wake", err)
			}
		}
	}
	description, err := c.DescribeWorkflowExecution(ctx, id, "")
	if err != nil || description.GetWorkflowExecutionInfo().GetType().GetName() != "SingleTestCleanupWorkflow" {
		t.Fatal("history rotation did not select cleanup-only workflow", err)
	}
	if err := e.StartSingleTest(ctx, q); err != nil {
		t.Fatal("actual continued-chain repeat start", err)
	}
	p.proved.Store(true)
	if err := e.WakeSingleTest(ctx, q); err != nil {
		t.Fatal(err)
	}
	if err := c.GetWorkflow(ctx, id, "").Get(ctx, nil); err != nil {
		t.Fatal("cleanup did not complete after proof", err)
	}
	if err := e.StartSingleTest(ctx, q); err != nil {
		t.Fatal("actual terminal-chain repeat start", err)
	}
	if p.reentered.Load() {
		t.Fatal("cleanup continuation reentered business execution")
	}
	t.Log("real local Temporal same workflow cleanup continued after64 pending observations, live and terminal repeat-start chain verified; controlled product proof, no database/provider claim")
}
