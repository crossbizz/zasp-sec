package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLineageProducerLoopRotatesAndReconcilesWithConsumer(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	socket, _, provider := startLineageGRPCFixture(t, "v1.7.0")
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if err := os.Chmod(spool.root.Name(), 0750); err != nil {
		t.Fatal(err)
	}
	acks, ackPath := acknowledgmentFixture(t)
	defer acks.Close()
	receipts, err := newLineageReceiptReader(ackPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Close()
	completion, err := newLineageCompletionReader(spool.root.Name(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer completion.Close()
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	scope := lineageProducerConfig{EnrollmentBinding: strings.Repeat("b", 64), Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}
	slots, err := newLineageConsumerSlots(state, lineageSlotConfig{EnrollmentBinding: scope.EnrollmentBinding, Destination: scope.Destination, Producer: completion, Acknowledgments: acks})
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	var starts atomic.Int32
	seen := map[string]bool{}
	start := func(ctx context.Context) (*lineageGeneration, error) {
		endpoint, err := newLineageSocket(socket, uint32(os.Geteuid()))
		if err != nil {
			return nil, err
		}
		generation, err := startLineageGeneration(ctx, "node-a", scope.EnrollmentBinding, api, boot, endpoint, spool)
		if err == nil {
			// Drain the fixture's bounded request queue for every connection.
			// This test observation isn't a production registration fence.
			select {
			case <-provider.requests:
			case <-ctx.Done():
				generation.Close()
				return nil, errLineageGeneration
			}
			if seen[generation.Source().GenerationID] {
				t.Error("rotation reused source identity")
			}
			seen[generation.Source().GenerationID] = true
			starts.Add(1)
		}
		return generation, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	ready := make(chan bool, 128)
	done := make(chan error, 1)
	config := lineageProducerLoopConfig{Scope: scope, NodeName: "node-a", Pump: lineagePumpConfig{BatchSize: 16, FlushInterval: 50 * time.Millisecond, CheckInterval: 50 * time.Millisecond, MaximumDuration: 100 * time.Millisecond}, OperationTimeout: time.Second}
	go func() {
		done <- runLineageProducerLoop(ctx, spool, receipts, config, start, ticker.C, func(value bool) {
			select {
			case ready <- value:
			default:
			}
		})
	}()
	requests := 0
	client := lineageControllerClient(t, scope.EnrollmentBinding, &requests)
	released := 0
	consumerTicks := time.NewTicker(10 * time.Millisecond)
	defer consumerTicks.Stop()
	for released < 10 {
		select {
		case <-ctx.Done():
			t.Fatal("rotation/reconciliation stalled", starts.Load(), released)
		case err := <-done:
			t.Fatal("producer stopped early", err)
		case <-consumerTicks.C:
			// Concurrent producer publication can invalidate an observation tick.
			// Retained state must converge on subsequent ticks without adoption.
			progress, _ := slots.ReconcileConsumer(ctx, client, 16)
			released += progress.Released
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if starts.Load() < 10 || requests != 0 {
		t.Fatal("rotation didn't cross capacity with empty sources", starts.Load(), requests)
	}
	spool.mu.Lock()
	active := spool.active
	spool.mu.Unlock()
	if active != nil {
		t.Fatal("shutdown left active producer")
	}
	if entries, err := os.ReadDir(state); err != nil || len(entries) > 7*lineageSpoolSlots+1 {
		t.Fatal("state unbounded", len(entries), err)
	}
	if _, err := os.Stat(filepath.Join(spool.root.Name(), ".producer.lock")); err != nil {
		t.Fatal("runtime closed borrowed spool", err)
	}
}
