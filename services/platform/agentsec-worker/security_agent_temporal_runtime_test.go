package main

import (
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/orchestration"
	"go.temporal.io/sdk/worker"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Missing configured keys/principals must fail before opening a provider or
// registering a worker that could accept durable product tasks.
func TestTemporalRuntimeRefusesIncompleteConfiguration(t *testing.T) {
	cfg := validSecurityAgentRuntimeConfig()
	cfg.TemporalExecutorDSN = "postgres://executor@127.0.0.1/test"
	cfg.TemporalCompensationDSN = cfg.TemporalExecutorDSN
	if _, err := buildTemporalSecurityAgentRuntime(context.Background(), cfg, nil); err == nil {
		t.Fatal("same/missing authority accepted")
	}
	if _, err := newTemporalSecurityAgentWorker(nil, "queue", &temporalSecurityAgentProduct{}, func(context.Context) error { return orchestration.ErrUnavailable }, func() error { return nil }, time.Second, 1); err == nil {
		t.Fatal("worker accepted absent Temporal connection")
	}
}

func TestTemporalRuntimeCloudUsesApprovedAuthority(t *testing.T) {
	cfg := workerRuntimeConfig{AWSRegion: "us-west-2", RedTeamRoleARN: "arn:aws:iam::123456789012:role/zasp-red-team-worker", RedTeamTokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"}
	cloud := temporalSecurityAgentCloudConfig(cfg)
	if !validProductionDiscoveryCloudConfig(cloud) || cloud.RoleARN != cfg.RedTeamRoleARN || cloud.TokenFile != cfg.RedTeamTokenFile || cloud.SecretRoot != "zasp/red-team" {
		t.Fatal("Temporal constructor refuses approved red-team cloud authority")
	}
	cfg.RedTeamTokenFile = "/tmp/ambient-token"
	if validProductionDiscoveryCloudConfig(temporalSecurityAgentCloudConfig(cfg)) {
		t.Fatal("Temporal constructor relaxed web identity authority")
	}
}

type temporalLifecycleWorker struct {
	worker.Worker
	calls   atomic.Int32
	release chan struct{}
}

func (w *temporalLifecycleWorker) Stop() { w.calls.Add(1); <-w.release }

func TestTemporalRuntimeConcurrentCloseJoinsWorker(t *testing.T) {
	w := &temporalLifecycleWorker{release: make(chan struct{})}
	var closed atomic.Int32
	r := &temporalSecurityAgentRuntime{worker: w, activities: &orchestration.Activities{}, ready: func(context.Context) error { return nil }, closeClients: func() error { closed.Add(1); return nil }, stopped: make(chan struct{}), timeout: time.Second}
	var group sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() { defer group.Done(); results <- r.Close() }()
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !r.closing.Load() {
		select {
		case <-deadline.C:
			t.Fatal("closing not visible")
		case <-ticker.C:
		}
	}
	if r.Ready(context.Background()) == nil || closed.Load() != 0 {
		t.Fatal("client closed under unjoined worker")
	}
	close(w.release)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if w.calls.Load() != 1 || closed.Load() != 1 {
		t.Fatal("non-idempotent close", w.calls.Load(), closed.Load())
	}
}
