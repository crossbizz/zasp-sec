package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/apiserver"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/jobqueue"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
)

type productStartIO struct {
	err   error
	calls int
	start orchestration.DiscoveryStart
}

func (s *productStartIO) Start(_ context.Context, q orchestration.DiscoveryStart) error {
	s.calls++
	s.start = q
	return s.err
}

func TestProductDiscoveryInstalledStartProcessor(t *testing.T) {
	dsn := os.Getenv("ZASP_P4B_WORKER_DSN")
	if dsn == "" {
		t.Skip("requires owned72 PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	db, err := apiserver.NewPostgresJSONDatabase(&workerPostgresDriver{pool: pool})
	if err != nil {
		t.Fatal(err)
	}
	var start orchestration.DiscoveryStart
	if json.Unmarshal([]byte(os.Getenv("ZASP_P4B_START")), &start) != nil {
		t.Fatal("start")
	}
	o, _ := domain.ParseProductID(start.Ref.OrganizationID)
	w, _ := domain.ParseProductID(start.Ref.WorkspaceID)
	e, _ := domain.ParseProductID(start.Ref.EnvironmentID)
	j, _ := domain.ParseProductID(start.Ref.RunID)
	scope, _ := domain.NewScope(o, w, e)
	steps := []string{}
	queue := &recordingDiscoveryQueue{steps: &steps, deliveries: []jobqueue.Delivery{{Job: jobqueue.Job{Scope: scope, JobID: j, Kind: "discovery", Payload: []byte(os.Getenv("ZASP_P4B_PAYLOAD"))}}}}
	starter := &productStartIO{err: errors.New("controlled response lost after start")}
	p, err := newTemporalDiscoveryStartProcessor(db, queue, starter, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.RunOnce(ctx); err == nil || strings.Contains(strings.Join(steps, ","), "ack") {
		t.Fatal("ambiguous start acknowledged", steps, err)
	}
	starter.err = nil
	if err = p.RunOnce(ctx); err != nil {
		t.Fatal("redelivery", err)
	}
	if len(steps) == 0 || steps[len(steps)-1] != "ack" || starter.calls != 2 || starter.start.Continuation == nil || !starter.start.Continuation.Deadline.Equal(start.Continuation.Deadline) {
		t.Fatal("redelivery changed budget or skipped confirmation", steps, starter.calls)
	}
	queue.deliveries[0].Job.Payload = []byte(strings.Replace(string(queue.deliveries[0].Job.Payload), start.IntegrationID, "pid_72009999-0000-4000-8000-000000000099", 1))
	steps = nil
	if err = p.RunOnce(ctx); err == nil || starter.calls != 2 || strings.Contains(strings.Join(steps, ","), "ack") {
		t.Fatal("foreign envelope acknowledged", err, steps)
	}
}
