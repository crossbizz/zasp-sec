package sensoradapter

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestChunkRetirementLinuxActualDirectorySyncFailure(t *testing.T) {
	config, retirement := chunkRetirementFixture(t, false)
	parentPath := filepath.Dir(config.CursorPath)
	parent, err := os.OpenRoot(filepath.Dir(parentPath))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	root, err := parent.OpenRoot(filepath.Base(parentPath))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fd, err := unix.Open(parentPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	directory := os.NewFile(uintptr(fd), parentPath)
	defer directory.Close()
	name := filepath.Base(config.CursorPath)
	lock, err := root.OpenFile(name+".lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("lock")
	}
	state := &chunkRetirementState{parent: parent, root: root, directory: directory, lock: lock, parentName: filepath.Base(parentPath), name: name}
	if !state.valid() {
		t.Fatal("O_PATH metadata admission failed")
	}
	if err := root.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := state.syncAbsent(context.Background()); err == nil {
		t.Fatal("failed directory sync reported durable absence")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RetireConsumedCheckpoint(context.Background(), retirement); err != nil {
		t.Fatal("authorized normal-handle retry failed", err)
	}
}
