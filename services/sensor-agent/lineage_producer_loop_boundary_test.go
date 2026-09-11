package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func lineageProducerLoopFixture(t *testing.T) (*lineageSpool, *lineageReceiptReader, lineageProducerLoopConfig) {
	t.Helper()
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spool.Close() })
	acks, path := acknowledgmentFixture(t)
	t.Cleanup(func() { acks.Close() })
	receipts, err := newLineageReceiptReader(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receipts.Close() })
	return spool, receipts, lineageProducerLoopConfig{Scope: lineageProducerConfig{EnrollmentBinding: lineageSpoolSource().EnrollmentBinding, Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}, NodeName: "node-a", Pump: lineagePumpConfig{BatchSize: 16, FlushInterval: 50 * time.Millisecond, CheckInterval: 50 * time.Millisecond, MaximumDuration: time.Second}, OperationTimeout: time.Second}
}

func TestLineageProducerLoopFullSpoolDoesNotOpenSubscription(t *testing.T) {
	spool, receipts, config := lineageProducerLoopFixture(t)
	for index := 0; index < 8; index++ {
		source := lineageSpoolSource()
		source.GenerationID = fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index+1)
		generation, err := spool.Create(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		if err := generation.Seal(context.Background(), "rotation", 0, 0); err != nil {
			t.Fatal(err)
		}
		generation.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticks := make(chan time.Time)
	ready := make(chan bool, 4)
	var starts atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- runLineageProducerLoop(ctx, spool, receipts, config, func(context.Context) (*lineageGeneration, error) { starts.Add(1); return nil, errLineageGeneration }, ticks, func(value bool) { ready <- value })
	}()
	for attempt := 0; attempt < 2; attempt++ {
		if attempt != 0 {
			ticks <- time.Now()
		}
		select {
		case value := <-ready:
			if value {
				t.Fatal("full producer ready")
			}
		case <-ctx.Done():
			t.Fatal("full-spool tick stalled")
		}
	}
	cancel()
	if err := <-done; err != nil || starts.Load() != 0 {
		t.Fatal("full spool opened a subscription", starts.Load(), err)
	}
	if inventory, err := spool.ListProducerWork(context.Background(), config.Scope); err != nil || len(inventory) != 8 {
		t.Fatal("retained history lost", len(inventory), err)
	}
}

func TestLineageProducerLoopRetriesStartupOnlyOnTicks(t *testing.T) {
	spool, receipts, config := lineageProducerLoopFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticks := make(chan time.Time)
	ready := make(chan bool, 4)
	var starts atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- runLineageProducerLoop(ctx, spool, receipts, config, func(context.Context) (*lineageGeneration, error) { starts.Add(1); return nil, errLineageGeneration }, ticks, func(value bool) { ready <- value })
	}()
	for attempt := int32(1); attempt <= 2; attempt++ {
		if attempt != 1 {
			ticks <- time.Now()
		}
		select {
		case value := <-ready:
			if value || starts.Load() != attempt {
				t.Fatal("startup retry not tick bounded", value, starts.Load())
			}
		case <-ctx.Done():
			t.Fatal("startup tick stalled")
		}
	}
	close(ticks)
	if err := <-done; err == nil {
		t.Fatal("closed tick source didn't stop runtime")
	}
}

func TestLineageProducerLoopClosesGenerationAfterEarlyPumpRejection(t *testing.T) {
	spool, receipts, config := lineageProducerLoopFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticks := make(chan time.Time)
	ready := make(chan bool, 4)
	created := make(chan *lineageGeneration, 1)
	done := make(chan error, 1)
	go func() {
		done <- runLineageProducerLoop(ctx, spool, receipts, config, func(ctx context.Context) (*lineageGeneration, error) {
			storage, err := spool.Create(ctx, lineageSpoolSource())
			if err != nil {
				return nil, err
			}
			lifetime, stop := context.WithCancel(ctx)
			generation := &lineageGeneration{source: storage.source, storage: storage, context: lifetime, cancel: stop}
			created <- generation
			return generation, nil // Missing pump prerequisites must still close ownership.
		}, ticks, func(value bool) { ready <- value })
	}()
	var generation *lineageGeneration
	select {
	case generation = <-created:
	case <-ctx.Done():
		t.Fatal("start not reached")
	}
	for {
		select {
		case value := <-ready:
			if !value {
				goto stopped
			}
		case <-ctx.Done():
			t.Fatal("pump rejection not observed")
		}
	}
stopped:
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if generation.context.Err() == nil || !generation.storage.closed || spool.active != nil {
		t.Fatal("early rejection abandoned generation")
	}
	if _, err := os.Stat(filepath.Join(spool.root.Name(), "generation-"+generation.Source().GenerationID, "manifest.json")); err != nil {
		t.Fatal("rejected pump lost history", err)
	}
}
