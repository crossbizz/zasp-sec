package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func producerFixtureConfig(fixture lineageReceiptFixtureState) lineageProducerConfig {
	request := reclaimFixtureRequest(fixture)
	return lineageProducerConfig{EnrollmentBinding: request.Source.EnrollmentBinding, Destination: request.Destination, ConsumerUID: request.ConsumerUID}
}

func TestLineageProducerReconcilesDiscoveredSourceAndCompletion(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
	ctx := context.Background()
	before := recoveryEvidence(t, spool.root.Name())
	work, err := spool.ListProducerWork(ctx, config)
	if err != nil || len(work) != 1 || work[0].Source != fixture.reader.Source() || work[0].Active || !work[0].Sealed || !work[0].HasSource {
		t.Fatal("owned source not discovered", work, err)
	}
	if !bytes.Equal(before, recoveryEvidence(t, spool.root.Name())) {
		t.Fatal("discovery mutated source")
	}
	progress, err := spool.ReconcileProducer(ctx, fixture.receipts, config)
	if err != nil || progress.SourcesReclaimed != 1 || progress.CompletionsCollected != 0 || progress.AwaitingConsumer != 1 {
		t.Fatal("reconciliation didn't reclaim ACKed source", progress, err)
	}
	if err := os.Chmod(spool.root.Name(), 0750); err != nil {
		t.Fatal(err)
	}
	completion, err := newLineageCompletionReader(spool.root.Name(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer completion.Close()
	store, err := newLineageAcknowledgments(fixture.ackPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if done, err := store.RetireAcknowledgment(ctx, completion, reclaimFixtureRequest(fixture), fixture.cursor, 16, nil); err != nil || !done {
		t.Fatal(err)
	}
	work, err = spool.ListProducerWork(ctx, config)
	if err != nil || len(work) != 1 || !work[0].Complete || !work[0].HasIntent || work[0].HasSource || work[0].Source != fixture.reader.Source() {
		t.Fatal("completion discovery lost original identity", work, err)
	}
	progress, err = spool.ReconcileProducer(ctx, fixture.receipts, config)
	if err != nil || progress.CompletionsCollected != 1 || progress.SourcesReclaimed != 0 {
		t.Fatal("retired completion not collected", progress, err)
	}
	if done, err := store.ForgetRetirement(ctx, completion, reclaimFixtureRequest(fixture)); err != nil || !done {
		t.Fatal(err)
	}
	work, err = spool.ListProducerWork(ctx, config)
	if err != nil || len(work) != 0 {
		t.Fatal("finished source remained in queue", work, err)
	}
}

func TestLineageProducerDiscoversPrivateAndInterruptedWorkWithoutClosingActiveSource(t *testing.T) {
	fixture := lineageReceiptFixture(t, true)
	spool, config := fixture.generation.spool, producerFixtureConfig(fixture)
	ctx := context.Background()
	private := fixture.generation.source
	private.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	base, cancel := context.WithCancel(ctx)
	interrupted := &lineageReservationContext{Context: base, spool: spool.root.Name(), id: private.GenerationID, stage: "manifest", action: cancel}
	if gen, err := spool.Create(interrupted, private); err == nil || gen != nil || !interrupted.fired {
		t.Fatal("reservation fixture", err)
	}
	cancel()
	orphan := private
	orphan.GenerationID = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	gen, err := spool.Create(ctx, orphan)
	if err != nil {
		t.Fatal(err)
	}
	gen.Close()
	active := private
	active.GenerationID = "33333333-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	live, err := spool.Create(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	progress, err := spool.ReconcileProducer(ctx, fixture.receipts, config)
	if err != nil || progress.ReservationsDiscarded != 1 || progress.SourcesClosed != 1 || progress.Active != 1 || progress.SourcesReclaimed != 1 {
		t.Fatal("bounded mixed work not reconciled", progress, err)
	}
	if _, err := os.Lstat(filepath.Join(live.root.Name(), "closed.json")); !os.IsNotExist(err) {
		t.Fatal("live source closed", err)
	}
	if !live.valid() {
		t.Fatal("active writer lost ownership")
	}
	reader, err := newLineageSpoolReader(filepath.Join(spool.root.Name(), "generation-"+orphan.GenerationID), config.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if seal, found, err := reader.ReadSeal(); err != nil || !found || !seal.CountersUnknown {
		t.Fatal("orphan didn't close honestly", seal, err)
	}
}
