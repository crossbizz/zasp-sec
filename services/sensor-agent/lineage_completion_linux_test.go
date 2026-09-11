package main

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageCompletionLinuxSyncFailurePreservesCheckpoint(t *testing.T) {
	fixture, store, reader := lineageCompletionFixture(t, false)
	path := fixture.generation.spool.root.Name()
	ctx := &lineageCompletionBoundaryContext{Context: context.Background(), cursor: fixture.cursor, action: func() {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		reader.directory.dir.Close()
		reader.directory.dir = os.NewFile(uintptr(fd), path)
	}}
	if complete, err := store.RetireCheckpoint(ctx, reader, reclaimFixtureRequest(fixture), fixture.cursor, 16, nil); err == nil || complete || !ctx.fired {
		t.Fatal("failed producer-directory sync admitted retirement", err)
	}
	if _, err := os.Lstat(fixture.cursor); err != nil {
		t.Fatal("checkpoint removed on uncertain producer sync", err)
	}
	reader.Close()
	reopened, err := newLineageCompletionReader(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if complete, err := store.RetireCheckpoint(context.Background(), reopened, reclaimFixtureRequest(fixture), fixture.cursor, 16, nil); err != nil || !complete {
		t.Fatal("normal-handle retry failed", err)
	}
}
