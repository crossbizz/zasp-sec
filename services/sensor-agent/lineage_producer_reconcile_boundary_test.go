package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func producerPrivateFixture(t *testing.T, fixture lineageReceiptFixtureState, enrollment string) string {
	t.Helper()
	source := fixture.generation.source
	source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	source.EnrollmentBinding = enrollment
	path := filepath.Join(fixture.generation.spool.root.Name(), ".creating-"+source.GenerationID)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := lineageManifestBytes(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), raw, 0440); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLineageProducerRejectsMixedScopeBeforeAnyMutation(t *testing.T) {
	for _, kind := range []string{"private enrollment", "public enrollment", "intent enrollment", "intent destination", "intent uid"} {
		t.Run(kind, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
			private := producerPrivateFixture(t, fixture, config.EnrollmentBinding)
			manifest := filepath.Join(fixture.reader.root.Name(), "manifest.json")
			if strings.HasPrefix(kind, "intent") {
				if done, err := spool.ReclaimAcknowledged(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
				switch kind {
				case "intent enrollment":
					config.EnrollmentBinding = strings.Repeat("a", 64)
				case "intent destination":
					config.Destination = "https://different.example.test/internal/v1/runtime/events"
				case "intent uid":
					config.ConsumerUID++
				}
			} else {
				if kind == "private enrollment" {
					manifest = filepath.Join(private, "manifest.json")
				}
				raw, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(manifest, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, bytes.ReplaceAll(raw, []byte(config.EnrollmentBinding), []byte(strings.Repeat("a", 64))), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(manifest, 0440); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryEvidence(t, private)
			if work, err := spool.ListProducerWork(context.Background(), config); err == nil || work != nil {
				t.Fatal("foreign scope enumerated", work, err)
			}
			if progress, err := spool.ReconcileProducer(context.Background(), fixture.receipts, config); err == nil || progress != (lineageProducerProgress{}) {
				t.Fatal("mixed scope partially executed", progress, err)
			}
			if !bytes.Equal(before, recoveryEvidence(t, private)) {
				t.Fatal("mixed scope changed private work")
			}
		})
	}
}

func TestLineageProducerResumesEveryIntentBoundaryBeforePrivateWork(t *testing.T) {
	for _, stage := range reclaimBoundaries {
		t.Run(stage, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
			base, cancel := context.WithCancel(context.Background())
			ctx := &lineageReclaimBoundaryContext{Context: base, path: spool.root.Name(), id: fixture.generation.source.GenerationID, stage: stage, action: cancel}
			if done, err := spool.ReclaimAcknowledged(ctx, fixture.receipts, reclaimFixtureRequest(fixture)); err == nil || done || !ctx.fired {
				t.Fatal("boundary fixture", err)
			}
			cancel()
			private := producerPrivateFixture(t, fixture, config.EnrollmentBinding)
			work, err := spool.ListProducerWork(context.Background(), config)
			if err != nil || len(work) != 2 {
				t.Fatal("interrupted work not enumerated", work, err)
			}
			if stage != "intent scratch" && (!work[0].HasIntent || work[0].Source != fixture.generation.source) {
				t.Fatal("durable intent not first", work)
			}
			progress, err := spool.ReconcileProducer(context.Background(), fixture.receipts, config)
			if stage == "intent scratch" {
				// The scratch has no durable owner record yet. Earlier private
				// work waits one tick; the matching ACKed source still proceeds.
				if err == nil || progress.ReservationsDiscarded != 0 {
					t.Fatal("scratch contention wasn't reported", progress, err)
				}
				progress, err = spool.ReconcileProducer(context.Background(), fixture.receipts, config)
			}
			if err != nil || progress.ReservationsDiscarded != 1 || progress.AwaitingConsumer != 1 {
				t.Fatal("bounded retry didn't finish", progress, err)
			}
			if _, err := os.Lstat(private); !os.IsNotExist(err) {
				t.Fatal("private work starved", err)
			}
		})
	}
}

// Trigger after ListProducerWork releases its lifetime lock, before the first
// operation. No production hooks or timing sleeps are needed.
type lineageProducerSnapshotContext struct {
	context.Context
	spool    *lineageSpool
	unlocked int
	action   func()
	fired    bool
}

func (ctx *lineageProducerSnapshotContext) Err() error {
	if !ctx.fired && ctx.spool.mu.TryLock() {
		ctx.spool.mu.Unlock()
		ctx.unlocked++
		if ctx.unlocked == 2 {
			ctx.fired = true
			ctx.action()
		}
	}
	return ctx.Context.Err()
}

func TestLineageProducerRechecksPrivateScopeAfterSnapshot(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
	private := producerPrivateFixture(t, fixture, config.EnrollmentBinding)
	manifest := filepath.Join(private, "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	foreign := bytes.ReplaceAll(raw, []byte(config.EnrollmentBinding), []byte(strings.Repeat("a", 64)))
	ctx := &lineageProducerSnapshotContext{Context: context.Background(), spool: spool, action: func() {
		if err := os.Chmod(manifest, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifest, foreign, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manifest, 0440); err != nil {
			t.Fatal(err)
		}
	}}
	progress, err := spool.ReconcileProducer(ctx, fixture.receipts, config)
	if err == nil || !ctx.fired || progress.ReservationsDiscarded != 0 || progress.SourcesReclaimed != 1 {
		t.Fatal("scope replacement lost or independent progress blocked", progress, err)
	}
	got, err := os.ReadFile(manifest)
	if err != nil || !bytes.Equal(got, foreign) {
		t.Fatal("foreign metadata deleted", err)
	}
}

func TestLineageProducerPreservesInvalidReceiptWhileClosingIndependentSource(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
	source := fixture.generation.source
	source.GenerationID = "ffffffff-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	gen, err := spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	gen.Close()
	ack := filepath.Join(fixture.ackPath, "ack-"+fixture.generation.source.GenerationID+".json")
	if err := os.Chmod(ack, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ack, []byte(`{"foreign":"receipt"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ack, 0440); err != nil {
		t.Fatal(err)
	}
	before := recoveryEvidence(t, fixture.reader.root.Name())
	progress, err := spool.ReconcileProducer(context.Background(), fixture.receipts, config)
	if err == nil || progress.SourcesReclaimed != 0 || progress.SourcesClosed != 1 || progress.AwaitingConsumer != 1 {
		t.Fatal("failure starved independent source", progress, err)
	}
	if strings.Contains(err.Error(), spool.root.Name()) || strings.Contains(err.Error(), source.GenerationID) {
		t.Fatal("error exposed metadata")
	}
	if !bytes.Equal(before, recoveryEvidence(t, fixture.reader.root.Name())) {
		t.Fatal("invalid receipt deleted source")
	}
}

func TestLineageProducerRejectsInvalidConfigAndClosedLifetime(t *testing.T) {
	fixture := lineageReceiptFixture(t, true)
	spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
	for _, kind := range []string{"enrollment", "destination", "uid", "nil context", "cancelled", "closed receipt", "closed spool"} {
		t.Run(kind, func(t *testing.T) {
			bad := config
			ctx := context.Background()
			switch kind {
			case "enrollment":
				bad.EnrollmentBinding = ""
			case "destination":
				bad.Destination += "?credential=private"
			case "uid":
				bad.ConsumerUID = ^uint32(0)
			case "nil context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed receipt":
				fixture.receipts.Close()
			case "closed spool":
				spool.Close()
			}
			if progress, err := spool.ReconcileProducer(ctx, fixture.receipts, bad); err == nil || progress != (lineageProducerProgress{}) {
				t.Fatal("invalid input progressed", progress, err)
			}
		})
	}
}

func TestLineageProducerLeavesNewActiveGenerationForNextSnapshot(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
	var active *lineageSpoolGeneration
	ctx := &lineageProducerSnapshotContext{Context: context.Background(), spool: spool, action: func() {
		source := fixture.generation.source
		source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		var err error
		active, err = spool.Create(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
	}}
	progress, err := spool.ReconcileProducer(ctx, fixture.receipts, config)
	if err != nil || !ctx.fired || active == nil || progress.Active != 0 || progress.SourcesReclaimed != 1 {
		t.Fatal("snapshot grew during execution", progress, err)
	}
	defer active.Close()
	progress, err = spool.ReconcileProducer(context.Background(), fixture.receipts, config)
	if err != nil || progress.Active != 1 || !active.valid() {
		t.Fatal("new active generation lost", progress, err)
	}
	if _, err := os.Lstat(filepath.Join(active.root.Name(), "closed.json")); !os.IsNotExist(err) {
		t.Fatal("new writer sealed", err)
	}
}

func TestLineageProducerResumesAfterActualProcessDeath(t *testing.T) {
	if path := os.Getenv("ZASP_TEST_PRODUCER_RECONCILE_PATH"); path != "" {
		spool, err := newLineageSpool(path, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		receipts, err := newLineageReceiptReader(os.Getenv("ZASP_TEST_PRODUCER_RECONCILE_ACKS"), uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		config := lineageProducerConfig{EnrollmentBinding: lineageSpoolSource().EnrollmentBinding, Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}
		ctx := &lineageReclaimBoundaryContext{Context: context.Background(), path: path, id: lineageSpoolSource().GenerationID, stage: os.Getenv("ZASP_TEST_PRODUCER_RECONCILE_STAGE"), action: func() { os.Exit(73) }}
		_, _ = spool.ReconcileProducer(ctx, receipts, config)
		t.Fatal("process didn't reach crash boundary")
	}
	for _, stage := range reclaimBoundaries {
		t.Run(stage, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			path, config := fixture.generation.spool.root.Name(), producerFixtureConfig(fixture)
			fixture.generation.spool.Close()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageProducerResumesAfterActualProcessDeath$")
			child.WaitDelay = time.Second
			child.Env = append(os.Environ(), "ZASP_TEST_PRODUCER_RECONCILE_PATH="+path, "ZASP_TEST_PRODUCER_RECONCILE_ACKS="+fixture.ackPath, "ZASP_TEST_PRODUCER_RECONCILE_STAGE="+stage)
			output, err := child.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("child failed outside requested boundary: %v %s", err, output)
			}
			spool, err := newLineageSpool(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			progress, err := spool.ReconcileProducer(context.Background(), fixture.receipts, config)
			if err != nil || progress.AwaitingConsumer != 1 {
				t.Fatal("restart did not resume discovered work", progress, err)
			}
			work, err := spool.ListProducerWork(context.Background(), config)
			if err != nil || len(work) != 1 || !work[0].Complete || work[0].HasSource {
				t.Fatal("restart didn't durably complete source", work, err)
			}
		})
	}
}
