package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func lineageSlotsFixture(t *testing.T) (lineageReceiptFixtureState, string, lineageSlotConfig) {
	t.Helper()
	fixture := lineageReceiptFixture(t, true)
	if err := os.Chmod(fixture.generation.spool.root.Name(), 0750); err != nil {
		t.Fatal(err)
	}
	producer, err := newLineageCompletionReader(fixture.generation.spool.root.Name(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { producer.Close() })
	acks, err := newLineageAcknowledgments(fixture.ackPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { acks.Close() })
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return fixture, path, lineageSlotConfig{EnrollmentBinding: fixture.generation.source.EnrollmentBinding, Destination: reclaimFixtureRequest(fixture).Destination, Producer: producer, Acknowledgments: acks}
}

func TestLineageSlotsReserveDurablyAndReuseExactAssignmentAfterRestart(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal("slot admission", err)
	}
	assignment, err := slots.Reserve(context.Background(), fixture.reader)
	if err != nil || assignment.Slot != 0 || assignment.Source != fixture.reader.Source() || assignment.SourceInode == 0 {
		t.Fatal("first reservation", assignment, err)
	}
	cursor, err := slots.CursorPath(assignment)
	if err != nil || cursor != filepath.Join(path, "cursor-0.json") {
		t.Fatal("fixed cursor path", cursor, err)
	}
	slots.Close()
	slots, err = newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	again, err := slots.Reserve(context.Background(), fixture.reader)
	if err != nil || again != assignment {
		t.Fatal("restart changed assignment", again, err)
	}
	list, err := slots.List(context.Background())
	if err != nil || len(list) != 1 || list[0] != assignment {
		t.Fatal("assignment not discoverable", list, err)
	}
	if _, err := os.Lstat(cursor); !os.IsNotExist(err) {
		t.Fatal("reservation created checkpoint", err)
	}
}

func TestLineageSlotsBoundAssignmentsAndRetainHistory(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	for index := 0; index < 8; index++ {
		if index > 0 {
			source := fixture.generation.source
			source.GenerationID = string(rune('0'+index)) + "1111111-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			generation, err := fixture.generation.spool.Create(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			generation.Close()
			reader, err := newLineageSpoolReader(filepath.Join(fixture.generation.spool.root.Name(), "generation-"+source.GenerationID), config.EnrollmentBinding, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			fixture.reader = reader
		}
		assignment, err := slots.Reserve(context.Background(), fixture.reader)
		if err != nil || assignment.Slot != index {
			t.Fatal("fixed bounded allocation", assignment, err)
		}
	}
	list, err := slots.List(context.Background())
	if err != nil || len(list) != 8 {
		t.Fatal("bounded inventory", list, err)
	}
	for _, assignment := range list {
		if _, err := slots.CursorPath(assignment); err != nil {
			t.Fatal("assignment lost without checkpoint", err)
		}
	}
	request := lineageReclaimRequest{Source: list[0].Source, Destination: config.Destination, ConsumerUID: uint32(os.Geteuid())}
	if done, err := fixture.generation.spool.ReclaimAcknowledged(context.Background(), fixture.receipts, request); err != nil || !done {
		t.Fatal("free producer fixture directory", err)
	}
	source := fixture.generation.source
	source.GenerationID = "99999999-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	generation, err := fixture.generation.spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	generation.Close()
	reader, err := newLineageSpoolReader(filepath.Join(fixture.generation.spool.root.Name(), "generation-"+source.GenerationID), config.EnrollmentBinding, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := slots.Reserve(context.Background(), reader); err != errLineageSpoolFull {
		t.Fatal("source absence released assignment history", err)
	}
	if retained, err := slots.List(context.Background()); err != nil || len(retained) != 8 || retained[0] != list[0] {
		t.Fatal("retained history changed", retained, err)
	}
}
