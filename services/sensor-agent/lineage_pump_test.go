package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/types"
)

type lineagePumpTappedReceive struct {
	grpc.ServerStreamingClient[tetragon.GetEventsResponse]
	count     int
	onReceive func(int)
}

func (tap *lineagePumpTappedReceive) Recv() (*tetragon.GetEventsResponse, error) {
	event, err := tap.ServerStreamingClient.Recv()
	if err == nil {
		tap.count++
		tap.onReceive(tap.count)
	}
	return event, err
}

func TestLineagePumpIdentityFailureCountsPendingQueuedAndSenderHeld(t *testing.T) {
	generation, api, events, _, path := lineagePumpFixture(t)
	third := make(chan struct{})
	generation.subscription.events = &lineagePumpTappedReceive{ServerStreamingClient: generation.subscription.events, onReceive: func(count int) {
		if count == 3 {
			close(third)
		}
	}}
	api.onNamespace = func() {
		if api.namespaceCalls != 5 {
			return
		}
		select {
		case <-third:
		case <-generation.context.Done():
			return
		}
		// Next holds recv through its final cancellation check. Acquiring it
		// after the third transport receive ensures the returned record is owned
		// by the worker, even if its channel send has not run yet.
		generation.subscription.recv.Lock()
		generation.subscription.recv.Unlock()
		api.node.UID = types.UID("ffffffff-ffff-4fff-8fff-ffffffffffff")
	}
	for i := 0; i < 3; i++ {
		events.events <- lineageProviderFixture("exec")
	}
	result, err := runLineagePump(context.Background(), generation, lineagePumpTestConfig(1))
	if err == nil || result.Reason != "identity_changed" || result.Records != 0 || result.Dropped != 3 || !result.Sealed {
		t.Fatalf("queued accounting: %#v %v", result, err)
	}
	if readLineagePumpSeal(t, path).Dropped != 3 {
		t.Fatal("seal missed queued/held records")
	}
}

func TestLineagePumpReceiverCancellationDoesNotNeedQueueSpace(t *testing.T) {
	generation, _, events, _, _ := lineagePumpFixture(t)
	held := &heldLineageReceive{ServerStreamingClient: generation.subscription.events, received: make(chan struct{}), release: make(chan struct{})}
	generation.subscription.events = held
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := make(chan lineagePumpReceive, 1)
	output <- lineagePumpReceive{} // Keep the only queue slot occupied.
	counts, done := &lineagePumpCounts{}, make(chan struct{})
	go receiveLineagePump(ctx, generation.subscription, output, counts, done)
	events.events <- lineageProviderFixture("exec")
	select {
	case <-held.received:
	case <-generation.context.Done():
		close(held.release)
		t.Fatal("record not received")
	}
	close(held.release)
	generation.subscription.recv.Lock()
	generation.subscription.recv.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled sender remained blocked")
	}
	if counts.received != 1 || counts.overflow {
		t.Fatal("sender-held record wasn't counted")
	}
}

func TestLineagePumpCounterRefusesWrap(t *testing.T) {
	value := uint64(math.MaxUint64 - 1)
	if !incrementLineagePumpCount(&value) || value != math.MaxUint64 || incrementLineagePumpCount(&value) || value != math.MaxUint64 {
		t.Fatal("counter wrapped")
	}
}

func TestLineagePumpIdleRecheckStopsChangedSource(t *testing.T) {
	generation, api, _, _, path := lineagePumpFixture(t)
	api.onNamespace = func() {
		if api.namespaceCalls == 5 {
			api.node.UID = types.UID("ffffffff-ffff-4fff-8fff-ffffffffffff")
		}
	}
	config := lineagePumpTestConfig(10)
	config.FlushInterval, config.CheckInterval = 30*time.Second, 50*time.Millisecond
	result, err := runLineagePump(context.Background(), generation, config)
	if err == nil || result.Reason != "identity_changed" || result.Records != 0 || result.Dropped != 0 || !result.Sealed {
		t.Fatalf("idle identity: %#v", result)
	}
	if readLineagePumpSeal(t, path).Chunks != 0 {
		t.Fatal("idle check wrote events")
	}
}

func TestLineagePumpCannotRunTwiceOrAdoptPopulatedStorage(t *testing.T) {
	t.Run("active", func(t *testing.T) {
		generation, _, events, _, _ := lineagePumpFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		config := lineagePumpTestConfig(1)
		done := make(chan lineagePumpResult, 1)
		go func() { result, _ := runLineagePump(ctx, generation, config); done <- result }()
		events.events <- lineageProviderFixture("exec")
		waitLineagePumpCommitted(t, generation, 1)
		if _, err := runLineagePump(ctx, generation, config); err == nil {
			t.Fatal("concurrent pump admitted")
		}
		events.events <- lineageProviderFixture("exec")
		waitLineagePumpCommitted(t, generation, 2)
		cancel()
		if result := <-done; result.Records != 2 || !result.Sealed {
			t.Fatal("rejected duplicate stopped active pump")
		}
		if _, err := runLineagePump(context.Background(), generation, config); err == nil {
			t.Fatal("completed generation resumed")
		}
	})
	t.Run("populated", func(t *testing.T) {
		generation, api, _, _, path := lineagePumpFixture(t)
		line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
		if _, err := generation.storage.Append(context.Background(), [][]byte{line}); err != nil {
			t.Fatal(err)
		}
		if _, err := runLineagePump(context.Background(), generation, lineagePumpTestConfig(1)); err == nil {
			t.Fatal("existing data adopted into pump accounting")
		}
		if api.nodeCalls != 4 {
			t.Fatal("nonempty storage triggered identity lookups")
		}
		if _, err := os.Stat(filepath.Join(path, "chunk-0000000001.jsonl")); err != nil {
			t.Fatal("old data removed")
		}
		if _, err := os.Stat(filepath.Join(path, "closed.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("old data sealed by failed pump")
		}
	})
}

func TestLineagePumpByteBoundaryKeepsOverflowRecordForFinalFlush(t *testing.T) {
	generation, _, events, server, path := lineagePumpFixture(t)
	event := lineageProviderFixture("file")
	event.GetProcessKprobe().Process.Binary = "/" + strings.Repeat("b", 4095)
	event.GetProcessKprobe().Args[0].GetFileArg().Path = "/" + strings.Repeat("p", 4095)
	line, err := sanitizeLineageEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	total := lineageChunkBytes/(len(line)+1) + 1
	if total >= 1000 {
		t.Fatal("fixture doesn't reach byte boundary before record boundary")
	}
	last := make(chan struct{})
	generation.subscription.events = &lineagePumpTappedReceive{ServerStreamingClient: generation.subscription.events, onReceive: func(count int) {
		if count == total {
			close(last)
		}
	}}
	done := make(chan lineagePumpResult, 1)
	config := lineagePumpTestConfig(1000)
	config.FlushInterval, config.CheckInterval = 30*time.Second, 30*time.Second
	go func() { result, _ := runLineagePump(context.Background(), generation, config); done <- result }()
	go func() {
		for i := 0; i < total; i++ {
			select {
			case events.events <- event:
			case <-generation.context.Done():
				return
			}
		}
	}()
	select {
	case <-last:
	case <-generation.context.Done():
		t.Fatal("large records not received")
	}
	// The last Recv already returned an event. Server disconnect doesn't cancel
	// the subscription's caller context, so Next can finish converting that event.
	server.Stop()
	result := <-done
	if result.Reason != "disconnect" || result.Records != total || result.Chunks != 2 || result.Dropped != 0 || !result.Sealed {
		t.Fatalf("overflow record lost: %#v", result)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lines, err := readLineageSpoolChunk(root, "chunk-0000000002.jsonl", generation.source, uint32(os.Getuid()))
	if err != nil || len(lines) != 1 {
		t.Fatal("overflow wasn't retained for final checked flush")
	}
}

func TestLineagePumpCancellationDuringFinalIdentityCheckDiscardsBatch(t *testing.T) {
	generation, api, events, server, path := lineagePumpFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api.onNamespace = func() {
		if api.namespaceCalls == 5 {
			cancel()
		}
	}
	last := make(chan struct{})
	generation.subscription.events = &lineagePumpTappedReceive{ServerStreamingClient: generation.subscription.events, onReceive: func(count int) {
		if count == 1 {
			close(last)
		}
	}}
	done := make(chan lineagePumpResult, 1)
	config := lineagePumpTestConfig(10)
	config.FlushInterval, config.CheckInterval = 30*time.Second, 30*time.Second
	go func() { result, _ := runLineagePump(ctx, generation, config); done <- result }()
	events.events <- lineageProviderFixture("exec")
	select {
	case <-last:
	case <-generation.context.Done():
		t.Fatal("record not received")
	}
	server.Stop()
	result := <-done
	if result.Reason != "shutdown" || result.Records != 0 || result.Dropped != 1 || !result.Sealed || api.namespaceCalls != 5 {
		t.Fatalf("final-check cancellation: %#v", result)
	}
	if readLineagePumpSeal(t, path).Records != 0 {
		t.Fatal("canceled final check persisted event")
	}
}

func TestLineagePumpCapacityPreservesAllCommittedChunks(t *testing.T) {
	generation, _, events, _, path := lineagePumpFixture(t)
	go func() {
		for i := 0; i < lineageSpoolChunks+1; i++ {
			select {
			case events.events <- lineageProviderFixture("exec"):
			case <-generation.context.Done():
				return
			}
		}
	}()
	config := lineagePumpTestConfig(1)
	config.FlushInterval, config.CheckInterval = 30*time.Second, 30*time.Second
	result, err := runLineagePump(context.Background(), generation, config)
	if err == nil || result.Reason != "capacity" || result.Records != lineageSpoolChunks || result.Chunks != lineageSpoolChunks || result.Dropped != 1 || result.Uncertain != 0 || !result.Sealed {
		t.Fatalf("capacity: %#v %v", result, err)
	}
	seal := readLineagePumpSeal(t, path)
	if seal.Records != lineageSpoolChunks || seal.Dropped != 1 {
		t.Fatal("capacity seal mismatch")
	}
	if _, err := os.Stat(filepath.Join(path, "chunk-0000000001.jsonl")); err != nil {
		t.Fatal("first committed chunk removed")
	}
	if _, err := os.Stat(filepath.Join(path, "chunk-0000000128.jsonl")); err != nil {
		t.Fatal("last committed chunk removed")
	}
}

func lineagePumpFixture(t *testing.T) (*lineageGeneration, *lineageIdentityAPIFixture, *lineageGRPCFixture, *grpc.Server, string) {
	t.Helper()
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	path, server, events := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spool.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	generation, err := startLineageGeneration(ctx, "node-a", strings.Repeat("b", 64), api, boot, endpoint, spool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { generation.Close() })
	return generation, api, events, server, filepath.Join(parent, "generation-"+generation.source.GenerationID)
}

func lineagePumpTestConfig(batch int) lineagePumpConfig {
	return lineagePumpConfig{BatchSize: batch, FlushInterval: 50 * time.Millisecond, CheckInterval: time.Second}
}

func waitLineagePumpFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if _, err := os.Stat(path); err == nil {
				return
			}
		case <-deadline.C:
			t.Fatal("expected spool publication absent")
		}
	}
}

func readLineagePumpSeal(t *testing.T, path string) lineageSpoolSeal {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path, "closed.json"))
	var seal lineageSpoolSeal
	if err != nil || json.Unmarshal(data, &seal) != nil {
		t.Fatalf("missing seal: %v", err)
	}
	return seal
}

func waitLineagePumpCommitted(t *testing.T, generation *lineageGeneration, chunks int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			generation.storage.spool.mu.Lock()
			committed := generation.storage.chunks >= chunks
			generation.storage.spool.mu.Unlock()
			if committed {
				return
			}
		case <-deadline.C:
			t.Fatal("chunk wasn't committed")
		}
	}
}

func TestLineagePumpActualStreamBatchesAndAccountsForExcludedRecords(t *testing.T) {
	generation, api, events, server, path := lineagePumpFixture(t)
	done := make(chan lineagePumpResult, 1)
	go func() {
		config := lineagePumpTestConfig(2)
		config.FlushInterval = 30 * time.Second
		result, _ := runLineagePump(context.Background(), generation, config)
		done <- result
	}()
	filtered := lineageProviderFixture("exec")
	filtered.GetProcessExec().Process.Pod.Namespace = "kube-system"
	events.events <- filtered
	events.events <- &tetragon.GetEventsResponse{}
	for i := 0; i < 4; i++ {
		events.events <- lineageProviderFixture("exec")
	}
	waitLineagePumpFile(t, filepath.Join(path, "chunk-0000000002.jsonl"))
	server.Stop()
	result := <-done
	if result.Reason != "disconnect" || result.Records != 4 || result.Dropped != 1 || result.Filtered != 1 || result.Uncertain != 0 || !result.Sealed {
		t.Fatalf("accounting: %#v", result)
	}
	if api.nodeCalls < 8 {
		t.Fatal("batches weren't identity rechecked")
	}
	seal := readLineagePumpSeal(t, path)
	if seal.Records != 4 || seal.Dropped != 1 || seal.Filtered != 1 || seal.CoverageComplete {
		t.Fatalf("seal: %#v", seal)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"chunk-0000000001.jsonl", "chunk-0000000002.jsonl"} {
		lines, err := readLineageSpoolChunk(root, name, generation.source, uint32(os.Getuid()))
		if err != nil || len(lines) != 2 {
			t.Fatal("actual records unavailable")
		}
	}
}

func TestLineagePumpTimerPublishesPartialBatchAndShutdownSeals(t *testing.T) {
	generation, _, events, _, path := lineagePumpFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan lineagePumpResult, 1)
	go func() { result, _ := runLineagePump(ctx, generation, lineagePumpTestConfig(10)); done <- result }()
	events.events <- lineageProviderFixture("exec")
	waitLineagePumpCommitted(t, generation, 1)
	cancel()
	result := <-done
	if result.Reason != "shutdown" || result.Records != 1 || result.Dropped != 0 || !result.Sealed {
		t.Fatalf("shutdown: %#v", result)
	}
	if readLineagePumpSeal(t, path).Reason != "shutdown" {
		t.Fatal("wrong terminal reason")
	}
}

func TestLineagePumpIdentityFailureNeverPublishesPendingRecords(t *testing.T) {
	for _, kind := range []string{"identity_changed", "identity_unavailable", "source_mismatch"} {
		t.Run(kind, func(t *testing.T) {
			generation, api, events, _, path := lineagePumpFixture(t)
			api.onNamespace = func() {
				if api.namespaceCalls == 5 {
					switch kind {
					case "identity_changed":
						api.node.UID = types.UID("ffffffff-ffff-4fff-8fff-ffffffffffff")
					case "identity_unavailable":
						api.namespace = nil
					}
				}
			}
			event := lineageProviderFixture("exec")
			if kind == "source_mismatch" {
				event.NodeName = "node-b"
			}
			events.events <- event
			result, err := runLineagePump(context.Background(), generation, lineagePumpTestConfig(1))
			if err == nil || result.Reason != kind || result.Records != 0 || result.Dropped != 1 || !result.Sealed {
				t.Fatalf("identity failure: %#v %v", result, err)
			}
			if _, err := os.Stat(filepath.Join(path, "chunk-0000000001.jsonl")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unqualified records persisted")
			}
			if readLineagePumpSeal(t, path).Dropped != 1 {
				t.Fatal("discard not recorded")
			}
		})
	}
}

type lineagePumpUncertainStore struct {
	generation *lineageSpoolGeneration
	path       string
}

func (store lineagePumpUncertainStore) Append(ctx context.Context, lines [][]byte) (lineageSpoolChunk, error) {
	base, cancel := context.WithCancel(ctx)
	defer cancel()
	return store.generation.Append(lineagePublicationContext{Context: base, path: filepath.Join(store.path, "chunk-0000000001.jsonl"), cancel: cancel}, lines)
}
func (store lineagePumpUncertainStore) Seal(ctx context.Context, reason string, dropped, filtered uint64) error {
	return store.generation.Seal(ctx, reason, dropped, filtered)
}

func TestLineagePumpUncertainAppendNeverClaimsDefiniteDropOrSeal(t *testing.T) {
	generation, _, events, _, path := lineagePumpFixture(t)
	events.events <- lineageProviderFixture("exec")
	result, err := runLineagePumpWithStorage(context.Background(), generation, lineagePumpTestConfig(1), lineagePumpUncertainStore{generation.storage, path})
	if err == nil || result.Reason != "spool_error" || result.Records != 0 || result.Dropped != 0 || result.Uncertain != 1 || result.Sealed {
		t.Fatalf("uncertain accounting: %#v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(path, "closed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncertain append sealed")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if lines, err := readLineageSpoolChunk(root, "chunk-0000000001.jsonl", generation.source, uint32(os.Getuid())); err != nil || len(lines) != 1 {
		t.Fatal("uncertain published record wasn't preserved")
	}
}
