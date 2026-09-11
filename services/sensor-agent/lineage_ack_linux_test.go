package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageAcknowledgmentLinuxDirectorySyncFailureNeedsDurableRetry(t *testing.T) {
	store, path := acknowledgmentFixture(t)
	// An O_PATH descriptor has the right inode and valid metadata but rejects
	// fsync. This reaches the real post-rename barrier without production hooks.
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	store.dir.Close()
	store.dir = os.NewFile(uintptr(fd), path)
	ack := lineageAckPublicationFixture()
	if err := store.publish(context.Background(), ack); err == nil {
		t.Fatal("directory sync failure reported success")
	}
	name := filepath.Join(path, "ack-"+ack.Consumption.Source.GenerationID+".json")
	if info, err := os.Stat(name); err != nil || info.Mode().Perm() != 0440 {
		t.Fatal("failure wasn't after rename", err)
	}
	if err := store.publish(context.Background(), ack); err == nil {
		t.Fatal("identical receipt bypassed uncertain directory sync")
	}
	store.Close()
	restarted, err := newLineageAcknowledgments(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.publish(context.Background(), ack); err != nil {
		t.Fatal("durable identical retry failed", err)
	}
}

func TestLineageAcknowledgmentLinuxRejectsForeignOwnedScratch(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	store, path := acknowledgmentFixture(t)
	name := filepath.Join(path, ".pending")
	if err := os.WriteFile(name, []byte("foreign partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(name, 65532, -1); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.publish(context.Background(), lineageAckPublicationFixture()); err == nil {
		t.Fatal("foreign scratch reclaimed")
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(before, after) || !lineageOwnedRegular(after, 65532, 0600) {
		t.Fatal("foreign scratch changed", err)
	}
}
