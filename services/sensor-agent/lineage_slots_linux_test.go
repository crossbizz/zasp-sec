package main

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestLineageSlotsLinuxSyncFailureNeverReturnsUsableAssignment(t *testing.T) {
	for _, stage := range []string{"before reservation", "empty", "written", "published", "retry", "cursor path"} {
		t.Run(stage, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			failSync := func() {
				fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				slots.dir.Close()
				slots.dir = os.NewFile(uintptr(fd), path)
			}
			var record lineageSlotAssignment
			if stage == "retry" || stage == "cursor path" {
				record, err = slots.Reserve(context.Background(), fixture.reader)
				if err != nil {
					t.Fatal(err)
				}
				failSync()
			}
			if stage == "cursor path" {
				if path, err := slots.CursorPath(record); err == nil || path != "" {
					t.Fatal("unsynced assignment exposed cursor", path, err)
				}
			} else {
				var ctx context.Context = context.Background()
				if stage == "before reservation" {
					failSync()
				} else if stage != "retry" {
					ctx = &lineageSlotBoundaryContext{Context: ctx, path: path, id: fixture.reader.Source().GenerationID, stage: stage, action: failSync}
				}
				if _, err := slots.Reserve(ctx, fixture.reader); err == nil {
					t.Fatal("failed directory sync reported durable assignment")
				}
			}
			slots.Close()
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			if record, err := slots.Reserve(context.Background(), fixture.reader); err != nil || record.Slot != 0 {
				t.Fatal("normal-handle retry couldn't recover", record, err)
			}
		})
	}
}
