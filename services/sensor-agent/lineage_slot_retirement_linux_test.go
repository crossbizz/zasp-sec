package main

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestLineageSlotRetirementLinuxSyncFailuresRequireRecovery(t *testing.T) {
	for _, stage := range []string{"before evidence", "evidence published", "phase published", "ACK forgotten", "assignment removed", "evidence removed", "ACK phase sync"} {
		t.Run(stage, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			release := stage == "ACK forgotten" || stage == "assignment removed" || stage == "evidence removed"
			if release {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal(err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			path, config := slots.root.Name(), slots.config
			var restored *os.File
			failSync := func() {
				target := &slots.dir
				directory := path
				if stage == "ACK phase sync" {
					target = &config.Acknowledgments.dir
					directory = fixture.ackPath
				}
				fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				if stage == "ACK phase sync" {
					restored = *target
				} else {
					(*target).Close()
				}
				*target = os.NewFile(uintptr(fd), directory)
			}
			var ctx context.Context = context.Background()
			if stage == "before evidence" {
				failSync()
			} else {
				boundary := stage
				if stage == "ACK phase sync" {
					boundary = "ACK retired"
				}
				ctx = &lineageSlotRetirementContext{Context: ctx, path: path, acks: fixture.ackPath, assignment: assignment, stage: boundary, action: failSync}
			}
			var done bool
			var err error
			if release {
				done, err = slots.Release(ctx, assignment)
			} else {
				done, err = slots.Retire(ctx, assignment, 16)
			}
			if err == nil || done {
				t.Fatal("failed durability reported completion", done, err)
			}
			if restored != nil {
				config.Acknowledgments.dir.Close()
				config.Acknowledgments.dir = restored
			}
			slots.Close()
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			if !release {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal("retirement durability retry", done, err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			if done, err := slots.Release(context.Background(), assignment); err != nil || !done {
				t.Fatal("release durability retry", done, err)
			}
		})
	}
}
