package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageReclaimLinuxDirectorySyncFailureRequiresDurableRetry(t *testing.T) {
	for _, stage := range []string{"intent", "rename", "directory removal", "completion"} {
		t.Run(stage, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			spool := fixture.generation.spool
			path := spool.root.Name()
			ctx := &lineageReclaimBoundaryContext{Context: context.Background(), path: path, id: request.Source.GenerationID, stage: stage, action: func() {
				fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				spool.dir.Close()
				spool.dir = os.NewFile(uintptr(fd), path)
			}}
			if complete, err := spool.ReclaimAcknowledged(ctx, fixture.receipts, request); err == nil || complete || !ctx.fired {
				t.Fatal("failed parent sync reported completion", err)
			}
			if stage == "intent" || stage == "rename" {
				name := "generation-" + request.Source.GenerationID
				if stage == "rename" {
					name = ".reclaim-" + request.Source.GenerationID
				}
				entries, err := os.ReadDir(filepath.Join(path, name))
				if err != nil || len(entries) != 3 {
					t.Fatal("files deleted before durable rename", err)
				}
			}
			spool.Close()
			restarted, err := newLineageSpool(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			if complete, err := restarted.ReclaimAcknowledged(context.Background(), nil, request); err != nil || !complete {
				t.Fatal("durable retry failed", err)
			}
		})
	}
}
