package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageRecoveryLinuxDirectorySyncFailureRequiresRetry(t *testing.T) {
	for _, stage := range []string{"before publication", "fragment", "seal"} {
		t.Run(stage, func(t *testing.T) {
			generation, path := lineageSpoolReaderFixture(t)
			spool := generation.spool
			if stage == "fragment" {
				if err := os.WriteFile(filepath.Join(path, ".pending"), []byte(`{"version":"tetragon-`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			generation.Close()
			failSync := func() {
				fd, err := unix.Open(filepath.Dir(path), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				spool.dir.Close()
				spool.dir = os.NewFile(uintptr(fd), filepath.Dir(path))
			}
			var ctx context.Context = context.Background()
			if stage == "before publication" {
				failSync()
			} else {
				ctx = &lineageRecoveryBoundaryContext{Context: ctx, path: path, stage: stage, action: failSync}
			}
			if done, err := spool.SealInterrupted(ctx, generation.source); err == nil || done {
				t.Fatal("uncertain sync reported success", err)
			}
			spool.Close()
			spool, err := newLineageSpool(filepath.Dir(path), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			if done, err := spool.SealInterrupted(context.Background(), generation.source); err != nil || !done {
				t.Fatal("normal-handle recovery failed", err)
			}
		})
	}
}

func TestLineageSpoolReaderLinuxNonRootRecovery(t *testing.T) {
	t.Setenv("ZASP_TEST_RECOVERY_PERMISSION", "1")
	TestLineageSpoolReaderLinuxNonRootConsumerCannotWriteProducerFiles(t)
}
