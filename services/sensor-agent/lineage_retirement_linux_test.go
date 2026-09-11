package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageReclaimRequiresDurableConsumerACKBeforeSourceDeletion(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	fd, err := unix.Open(fixture.ackPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixture.receipts.dir.Close()
	fixture.receipts.dir = os.NewFile(uintptr(fd), fixture.ackPath)
	if !fixture.receipts.valid() {
		t.Fatal("O_PATH metadata admission")
	}
	if complete, err := fixture.generation.spool.ReclaimAcknowledged(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err == nil || complete {
		t.Fatal("source reclaimed before consumer ACK directory durability", err)
	}
	if _, found, err := fixture.reader.ReadSeal(); err != nil || !found {
		t.Fatal("failed ACK barrier deleted source", err)
	}
}

func TestLineageRetirementLinuxDirectorySyncFailuresRequireRecovery(t *testing.T) {
	for _, stage := range []string{"retired publication", "collection receipt sync", "collection deletion", "forget producer sync", "forget deletion"} {
		t.Run(stage, func(t *testing.T) {
			fixture, store, completion := lineageCompletionFixture(t, false)
			spool := fixture.generation.spool
			request := reclaimFixtureRequest(fixture)
			pathOnly := func(target **os.File, path string) {
				fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				(*target).Close()
				*target = os.NewFile(uintptr(fd), path)
			}
			if stage != "retired publication" {
				if done, err := store.RetireAcknowledgment(context.Background(), completion, request, fixture.cursor, 16, nil); err != nil || !done {
					t.Fatal(err)
				}
			}
			if stage == "forget producer sync" || stage == "forget deletion" {
				if done, err := spool.CollectCompletion(context.Background(), fixture.receipts, request); err != nil || !done {
					t.Fatal(err)
				}
			}
			ctx := &lineageRetirementBoundaryContext{Context: context.Background(), spool: spool.root.Name(), acks: fixture.ackPath, cursor: fixture.cursor, id: request.Source.GenerationID}
			var done bool
			var err error
			switch stage {
			case "retired publication":
				ctx.stage = "retirement published"
				ctx.action = func() { pathOnly(&store.dir, fixture.ackPath) }
				done, err = store.RetireAcknowledgment(ctx, completion, request, fixture.cursor, 16, nil)
			case "collection receipt sync":
				pathOnly(&fixture.receipts.dir, fixture.ackPath)
				done, err = spool.CollectCompletion(context.Background(), fixture.receipts, request)
			case "collection deletion":
				ctx.stage = "completion removed"
				ctx.action = func() { pathOnly(&spool.dir, spool.root.Name()) }
				done, err = spool.CollectCompletion(ctx, fixture.receipts, request)
			case "forget producer sync":
				pathOnly(&completion.directory.dir, spool.root.Name())
				done, err = store.ForgetRetirement(context.Background(), completion, request)
			case "forget deletion":
				ctx.stage = "retirement removed"
				ctx.action = func() { pathOnly(&store.dir, fixture.ackPath) }
				done, err = store.ForgetRetirement(ctx, completion, request)
			}
			if err == nil || done {
				t.Fatal("failed directory sync reported completion", err)
			}
			if stage == "collection receipt sync" {
				if _, err := os.Lstat(filepath.Join(spool.root.Name(), "reclaim-"+request.Source.GenerationID+".json")); err != nil {
					t.Fatal("completion deleted before receipt durability", err)
				}
			}
			if stage == "forget producer sync" {
				if _, err := os.Lstat(filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")); err != nil {
					t.Fatal("retirement deleted before producer absence durability", err)
				}
			}
			wire := lineageRetirementProcessFixture{Spool: spool.root.Name(), Acks: fixture.ackPath, Cursor: fixture.cursor, Request: request}
			spool.Close()
			store.Close()
			completion.Close()
			fixture.receipts.Close()
			if err := runRetirementStages(context.Background(), wire); err != nil {
				t.Fatal("normal-handle recovery failed", err)
			}
		})
	}
}
