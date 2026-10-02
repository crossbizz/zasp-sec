package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/worker"
)

type automaticMiddleBarrier struct {
	product *temporalSecurityAgentProduct
	block   bool
}

func (b automaticMiddleBarrier) AutomaticSourcePage(ctx context.Context, q orchestration.AutomaticSourceStart) (orchestration.AutomaticPage, error) {
	if b.block && q.After != "" {
		fmt.Fprintln(os.Stdout, "AUTOMATIC77_MIDDLE_PAGE_READY")
		select {}
	}
	return b.product.AutomaticSourcePage(ctx, q)
}
func (b automaticMiddleBarrier) AutomaticCatchupPage(ctx context.Context, q orchestration.AutomaticCatchupStart) (orchestration.AutomaticPage, error) {
	return b.product.AutomaticCatchupPage(ctx, q)
}

func TestTemporalAutomaticMiddlePageWorker(t *testing.T) {
	dsn := os.Getenv("ZASP_TEST77_PAGE_DSN")
	if dsn == "" {
		t.Skip("requires owned automatic-page fixture")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil || net.ParseIP(config.Host) == nil || !net.ParseIP(config.Host).IsLoopback() {
		t.Fatal("owned loopback database required", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var principal string
	if err := conn.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "middle_page_executor" {
		t.Fatal("page Activity must use registered executor", principal, err)
	}
	db := &release61WorkerPG{orderedPricingWorkerPG: orderedPricingWorkerPG{conn: conn}, t: t}
	if present, err := automaticSourcesAvailable(ctx, db); err != nil || !present {
		t.Fatal("actual77 executor readiness", present, err)
	}
	var ref orchestration.AutomaticSourceRef
	if json.Unmarshal([]byte(os.Getenv("ZASP_TEST77_PAGE_REF")), &ref) != nil || !ref.Valid() {
		t.Fatal("scoped source reference")
	}
	phase := os.Getenv("ZASP_TEST77_PAGE_PHASE")
	if phase != "block" && phase != "recover" {
		t.Fatal("owned process phase")
	}
	namespace := os.Getenv("ZASP_TEST77_NAMESPACE")
	queue := namespace + "-pages"
	c, err := client.Dial(client.Options{HostPort: os.Getenv("ZASP_TEST77_ADDRESS"), Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := &temporalSecurityAgentProduct{executor: db, automaticSourcesEnabled: true}
	a := &orchestration.AutomaticActivities{Product: automaticMiddleBarrier{product: p, block: phase == "block"}}
	w := worker.New(c, queue, worker.Options{WorkerStopTimeout: time.Second, MaxConcurrentActivityExecutionSize: 1})
	w.RegisterWorkflow(orchestration.AutomaticSourceWorkflow)
	w.RegisterActivityWithOptions(a.Source, activity.RegisterOptions{Name: "AutomaticSourcePage"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	starter, err := orchestration.NewAutomaticSourceStarter(c, queue, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := orchestration.AutomaticSourceWorkflowID(ref)
	if phase == "block" {
		// Start can dispatch an Activity before ACK finishes. Each owner needs
		// its own connection; pgx.Conn does not permit concurrent SQL calls.
		storeConn, err := pgx.ConnectConfig(ctx, config.Copy())
		if err != nil {
			t.Fatal(err)
		}
		defer storeConn.Close(context.Background())
		if err := storeConn.QueryRow(ctx, `SELECT session_user`).Scan(&principal); err != nil || principal != "middle_page_executor" {
			t.Fatal("source ACK must use registered executor", principal, err)
		}
		store := orchestration.AutomaticSourceSQLStore{Database: automaticNativeDB{conn: storeConn}, Timeout: 10 * time.Second}
		if err := store.Attempt(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if err := starter.Start(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if err := store.Ack(ctx, ref); err != nil {
			t.Fatal(err)
		}
		<-ctx.Done()
		t.Fatal("parent did not replace owned blocked process")
	}
	if err := c.GetWorkflow(ctx, id, "").Get(ctx, nil); err != nil {
		t.Fatal("native middle-page recovery", err)
	}
	// Completed execution still owns this occurrence. A replay must not open a
	// second Workflow or depend on only the currently running execution.
	if err := starter.Start(ctx, ref); err != nil {
		t.Fatal("completed native dispatcher acceptance", err)
	}
	history := c.GetWorkflowHistory(ctx, id, "", false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	rootPages, laterPages := 0, 0
	for history.HasNext() {
		event, err := history.Next()
		if err != nil {
			t.Fatal(err)
		}
		if a := event.GetActivityTaskScheduledEventAttributes(); a != nil && a.GetActivityType().GetName() == "AutomaticSourcePage" {
			var q orchestration.AutomaticSourceStart
			if converter.GetDefaultDataConverter().FromPayloads(a.GetInput(), &q) != nil || q.Ref != ref {
				t.Fatal("native page identity changed")
			}
			if q.After == "" {
				rootPages++
			} else {
				laterPages++
			}
			if a.GetStartToCloseTimeout().AsDuration() != 30*time.Second {
				t.Fatal("native page deadline changed")
			}
		}
	}
	if rootPages != 1 || laterPages < 5 {
		t.Fatal("restart lost durable middle cursor", rootPages, laterPages)
	}
	closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := a.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	t.Log("replacement process completed native >25 dispatch with original cursor and completed-workflow replay", id, rootPages, laterPages)
}
