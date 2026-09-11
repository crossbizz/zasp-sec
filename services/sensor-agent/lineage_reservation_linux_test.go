package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageReservationLinuxSyncFailuresRequireRecovery(t *testing.T) {
	for _, stage := range []string{"before publication", "published", "before discard", "renamed", "metadata removed", "directory removed"} {
		t.Run(stage, func(t *testing.T) {
			path := t.TempDir()
			source := lineageSpoolSource()
			spool, err := newLineageSpool(path, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { spool.Close() }()
			failSync := func() {
				fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				spool.dir.Close()
				spool.dir = os.NewFile(uintptr(fd), path)
			}
			if stage == "before publication" || stage == "published" {
				var ctx context.Context = context.Background()
				if stage == "before publication" {
					failSync()
				} else {
					ctx = &lineageReservationContext{Context: ctx, spool: path, id: source.GenerationID, stage: stage, action: failSync}
				}
				if gen, err := spool.Create(ctx, source); err == nil || gen != nil {
					t.Fatal("uncertain publication succeeded", err)
				}
			} else {
				private := filepath.Join(path, ".creating-"+source.GenerationID)
				if err := os.Mkdir(private, 0700); err != nil {
					t.Fatal(err)
				}
				raw, _ := lineageManifestBytes(source)
				if err := os.WriteFile(filepath.Join(private, "manifest.json"), raw, 0440); err != nil {
					t.Fatal(err)
				}
				var ctx context.Context = context.Background()
				if stage == "before discard" {
					failSync()
				} else {
					ctx = &lineageDiscardContext{Context: ctx, spool: path, id: source.GenerationID, stage: stage, action: failSync}
				}
				if done, err := spool.DiscardUnpublished(ctx, source.GenerationID); err == nil || done {
					t.Fatal("uncertain discard succeeded", err)
				}
				if stage == "before discard" || stage == "renamed" {
					name := ".creating-"
					if stage == "renamed" {
						name = ".discard-"
					}
					if _, err := os.Lstat(filepath.Join(path, name+source.GenerationID, "manifest.json")); err != nil {
						t.Fatal("metadata deleted before parent barrier", err)
					}
				}
			}
			spool.Close()
			spool, err = newLineageSpool(path, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			if stage == "published" {
				if done, err := spool.DiscardUnpublished(context.Background(), source.GenerationID); err != nil || done {
					t.Fatal("published source discarded", err)
				}
				if done, err := spool.SealInterrupted(context.Background(), source); err != nil || !done {
					t.Fatal("published recovery failed", err)
				}
			} else if done, err := spool.DiscardUnpublished(context.Background(), source.GenerationID); err != nil || !done {
				t.Fatal("normal-handle retry failed", err)
			}
		})
	}
}
