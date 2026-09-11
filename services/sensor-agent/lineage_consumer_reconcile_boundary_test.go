package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestLineageConsumerControllerRejectsForeignSnapshotBeforeWrites(t *testing.T) {
	for _, kind := range []string{"unknown", "symlink", "foreign-enrollment", "duplicate-state", "producer-lock-missing", "orphan-assignment-scratch"} {
		t.Run(kind, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			spool := fixture.generation.spool.root.Name()
			switch kind {
			case "unknown":
				err = os.WriteFile(filepath.Join(spool, "foreign"), []byte("retain"), 0440)
			case "symlink":
				err = os.Symlink(fixture.reader.root.Name(), filepath.Join(spool, "generation-11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"))
			case "foreign-enrollment":
				source := fixture.reader.Source()
				source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
				source.EnrollmentBinding = strings.Repeat("c", 64)
				generation, createErr := fixture.generation.spool.Create(context.Background(), source)
				err = createErr
				if generation != nil {
					generation.Close()
				}
			case "duplicate-state":
				err = os.Mkdir(filepath.Join(spool, ".creating-"+fixture.reader.Source().GenerationID), 0700)
			case "producer-lock-missing":
				err = os.Rename(filepath.Join(spool, ".producer.lock"), filepath.Join(t.TempDir(), "preserved.lock"))
			case "orphan-assignment-scratch":
				if err := os.WriteFile(filepath.Join(path, ".slots.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				err = os.WriteFile(filepath.Join(path, lineageSlotScratch(0, "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb")), nil, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir(path)
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			progress, err := slots.ReconcileConsumer(context.Background(), lineageControllerClient(t, config.EnrollmentBinding, &requests), 16)
			if err == nil || progress != (lineageConsumerProgress{}) || requests != 0 {
				t.Fatal("foreign snapshot accepted", progress, requests, err)
			}
			after, err := os.ReadDir(path)
			if err != nil || len(after) != len(before) {
				t.Fatal("rejected snapshot wrote consumer state", len(before), len(after), err)
			}
		})
	}
}

func TestLineageConsumerControllerRejectsForeignCompletionBeforeRetirement(t *testing.T) {
	for _, kind := range []string{"destination", "consumer", "spool", "source"} {
		t.Run(kind, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			name := filepath.Join(fixture.generation.spool.root.Name(), "reclaim-"+assignment.Source.GenerationID+".json")
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			var record lineageReclaimRecord
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("record")
			}
			switch kind {
			case "destination":
				record.Request.Destination = "https://foreign.example.test/internal/v1/runtime/events"
			case "consumer":
				record.Request.ConsumerUID++
			case "spool":
				record.SpoolInode++
			case "source":
				record.Request.Source.BootID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			}
			raw, _ = json.Marshal(record)
			if err := os.Chmod(name, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(name, 0440); err != nil {
				t.Fatal(err)
			}
			progress, err := slots.ReconcileConsumer(context.Background(), nil, 16)
			if err == nil || progress != (lineageConsumerProgress{}) {
				t.Fatal(progress, err)
			}
			if _, err := os.Lstat(filepath.Join(slots.root.Name(), lineageSlotRetirementName(assignment.Slot))); !os.IsNotExist(err) {
				t.Fatal("foreign completion became local authority", err)
			}
			if _, err := os.Lstat(filepath.Join(slots.root.Name(), lineageSlotCursor(assignment.Slot))); err != nil {
				t.Fatal("checkpoint lost", err)
			}
		})
	}
}

func TestLineageConsumerControllerPreservesMissingAssignedSource(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	assignment, err := slots.Reserve(context.Background(), fixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fixture.reader.root.Name(), filepath.Join(t.TempDir(), "preserved-source")); err != nil {
		t.Fatal(err)
	}
	if _, err := slots.ReconcileConsumer(context.Background(), nil, 16); err == nil {
		t.Fatal("absence counted as completion")
	}
	list, err := slots.List(context.Background())
	if err != nil || len(list) != 1 || list[0] != assignment {
		t.Fatal("lost assignment", list, err)
	}
}

func TestLineageConsumerControllerResumesEvidenceAfterAssignmentUnlink(t *testing.T) {
	fixture, slots, assignment := lineageRetiringSlotFixture(t)
	ctx := context.Background()
	if _, err := slots.ReconcileConsumer(ctx, nil, 16); err != nil {
		t.Fatal(err)
	}
	if done, err := fixture.generation.spool.CollectCompletion(ctx, fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(ctx)
	defer cancel()
	boundary := &lineageSlotRetirementContext{Context: base, path: slots.root.Name(), acks: slots.config.Acknowledgments.root.Name(), assignment: assignment, stage: "assignment removed", action: cancel}
	if done, err := slots.Release(boundary, assignment); err == nil || done || !boundary.fired {
		t.Fatal("boundary not reached", done, err)
	}
	progress, err := slots.ReconcileConsumer(ctx, nil, 16)
	if err != nil || progress.Released != 1 {
		t.Fatal("orphan evidence not recovered", progress, err)
	}
}

func TestLineageConsumerControllerRechecksSnapshotSourceIdentity(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	work, err := slots.ListConsumerWork(context.Background())
	if err != nil || len(work) != 1 {
		t.Fatal(err)
	}
	if err := os.Rename(fixture.reader.root.Name(), filepath.Join(t.TempDir(), "preserved-source")); err != nil {
		t.Fatal(err)
	}
	generation, err := fixture.generation.spool.Create(context.Background(), fixture.reader.Source())
	if err != nil {
		t.Fatal(err)
	}
	generation.Close()
	requests := 0
	if _, _, err := slots.processConsumerSource(context.Background(), lineageControllerClient(t, config.EnrollmentBinding, &requests), 16, work[0]); err == nil || requests != 0 {
		t.Fatal("replacement adopted", requests, err)
	}
	if entries, _ := os.ReadDir(path); len(entries) != 0 {
		t.Fatal("stale snapshot wrote assignment")
	}
}

func TestLineageConsumerControllerBusySourceDoesNotStarveOtherSource(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	assignment, err := slots.Reserve(context.Background(), fixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(path, lineageSlotCursor(assignment.Slot)+".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	source := fixture.reader.Source()
	source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	generation, err := fixture.generation.spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
		t.Fatal(err)
	}
	generation.Close()
	requests := 0
	progress, err := slots.ReconcileConsumer(context.Background(), lineageControllerClient(t, config.EnrollmentBinding, &requests), 16)
	if err == nil || progress.SourcesProcessed != 1 || progress.Acknowledged != 1 || requests != 0 {
		t.Fatal("independent empty source starved", progress, requests, err)
	}
}

func TestLineageConsumerControllerWaitsForIncompleteProducerReclamation(t *testing.T) {
	for _, stage := range []string{"intent", "rename", "directory removal", "completion scratch"} {
		t.Run(stage, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			requests := 0
			if progress, err := slots.ReconcileConsumer(context.Background(), lineageControllerClient(t, config.EnrollmentBinding, &requests), 16); err != nil || progress.Acknowledged != 1 {
				t.Fatal(progress, err)
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := reclaimFixtureRequest(fixture)
			boundary := &lineageReclaimBoundaryContext{Context: base, path: fixture.generation.spool.root.Name(), id: request.Source.GenerationID, stage: stage, action: cancel}
			if done, err := fixture.generation.spool.ReclaimAcknowledged(boundary, fixture.receipts, request); err == nil || done || !boundary.fired {
				t.Fatal("reclaim boundary missing", done, err)
			}
			before := recoveryEvidence(t, path)
			progress, err := slots.ReconcileConsumer(context.Background(), nil, 16)
			if err != nil || progress.Waiting != 1 || progress.Retired != 0 || string(before) != string(recoveryEvidence(t, path)) {
				t.Fatal("incomplete producer work wasn't retained", progress, err)
			}
			if done, err := fixture.generation.spool.ReclaimAcknowledged(context.Background(), fixture.receipts, request); err != nil || !done {
				t.Fatal(err)
			}
			if progress, err := slots.ReconcileConsumer(context.Background(), nil, 16); err != nil || progress.Retired != 1 {
				t.Fatal(progress, err)
			}
		})
	}
}

func TestLineageConsumerControllerResumesReservationAndIgnoresPrivateStartup(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	boundary := &lineageSlotBoundaryContext{Context: base, path: path, id: fixture.reader.Source().GenerationID, stage: "written", action: cancel}
	if _, err := slots.Reserve(boundary, fixture.reader); err == nil || !boundary.fired {
		t.Fatal("reservation boundary", err)
	}
	cancel()
	slots.Close()
	source := fixture.reader.Source()
	source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	base, cancel = context.WithCancel(context.Background())
	defer cancel()
	private := &lineageReservationContext{Context: base, spool: fixture.generation.spool.root.Name(), id: source.GenerationID, stage: "manifest", action: cancel}
	if generation, err := fixture.generation.spool.Create(private, source); err == nil || generation != nil || !private.fired {
		t.Fatal("private boundary", err)
	}
	slots, err = newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	requests := 0
	progress, err := slots.ReconcileConsumer(context.Background(), lineageControllerClient(t, config.EnrollmentBinding, &requests), 16)
	if err != nil || progress.SourcesProcessed != 1 || progress.Acknowledged != 1 || requests != 0 {
		t.Fatal("consumer didn't resume public assignment", progress, err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.generation.spool.root.Name(), ".creating-"+source.GenerationID)); err != nil {
		t.Fatal("consumer changed private startup", err)
	}
}

func TestLineageConsumerControllerSerializesConcurrentRetirementTicks(t *testing.T) {
	fixture, slots, _ := lineageRetiringSlotFixture(t)
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
				t.Fatal(err)
			}
		}
		results := make([]lineageConsumerProgress, 4)
		failures := make([]error, 4)
		var group sync.WaitGroup
		for index := range results {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				results[index], failures[index] = slots.ReconcileConsumer(context.Background(), nil, 16)
			}(index)
		}
		group.Wait()
		released := 0
		for index, result := range results {
			if failures[index] != nil {
				t.Fatal(failures[index])
			}
			released += result.Released
		}
		if released != phase {
			t.Fatal("concurrent ticks duplicated release", phase, released)
		}
	}
}

func TestLineageConsumerControllerLocalCleanupSurvivesUnavailableUploadClient(t *testing.T) {
	fixture, slots, assignment := lineageRetiringSlotFixture(t)
	source := assignment.Source
	source.GenerationID = "11111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	generation, err := fixture.generation.spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	generation.Close()
	progress, err := slots.ReconcileConsumer(context.Background(), nil, 16)
	if err == nil || progress.Retired != 1 || progress.Waiting != 1 || progress.SourcesProcessed != 0 {
		t.Fatal("upload failure blocked local retirement", progress, err)
	}
	if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
		t.Fatal(err)
	}
	progress, err = slots.ReconcileConsumer(context.Background(), nil, 16)
	if err == nil || progress.Released != 1 {
		t.Fatal("upload failure blocked local release", progress, err)
	}
	work, err := slots.ListConsumerWork(context.Background())
	if err != nil || len(work) != 1 || work[0].Source != source || work[0].Assigned {
		t.Fatal("unavailable client adopted new work", work, err)
	}
}

func TestLineageConsumerControllerCancellationBeforeTickWritesNothing(t *testing.T) {
	_, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if progress, err := slots.ReconcileConsumer(ctx, nil, 16); err == nil || progress != (lineageConsumerProgress{}) {
		t.Fatal(progress, err)
	}
	if entries, _ := os.ReadDir(path); len(entries) != 0 {
		t.Fatal("cancelled tick wrote state")
	}
}
