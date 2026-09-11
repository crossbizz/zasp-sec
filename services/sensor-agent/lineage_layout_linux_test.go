package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLineageLayoutCompletedDirectoryRequiresSync(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	path := t.TempDir()
	if err := os.Mkdir(filepath.Join(path, "producer"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(path, "producer"), 0, 65532); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.Lstat("producer")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(path, "producer"), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "producer")
	defer file.Close()
	entry := lineageLayoutEntry{name: "producer", uid: 0, gid: 65532, mode: 0750, info: info, complete: true}
	if err := syncCompletedLineageLayoutEntry(root, file, entry); err == nil {
		t.Fatal("correct metadata bypassed failed inode sync")
	}
	after, err := root.Lstat("producer")
	if err != nil || !os.SameFile(info, after) || after.Mode() != info.Mode() {
		t.Fatal("failed barrier changed directory", err)
	}
}

func TestLineageLayoutActualBinaryInitializesAndRestarts(t *testing.T) {
	if os.Getenv("ZASP_TEST_LINEAGE_LAYOUT_BINARY") != "/proof/sensor-agent" {
		t.Skip("requires isolated compiled layout fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("initializer fixture must be root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("requires disposable container")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{"acks", "consumer"} {
			target := filepath.Join(path, name)
			if _, err := os.Lstat(target); err == nil {
				if err := os.Chown(target, 0, -1); err != nil {
					t.Error(err)
				}
			}
		}
	})
	run := func(extra ...string) error {
		command := exec.Command("/proof/sensor-agent")
		command.Env = []string{"GOMEMLIMIT=32MiB", "ZASP_SENSOR_ROLE=lineage-layout", "ZASP_LINEAGE_LAYOUT_DIRECTORY=" + path, "ZASP_LINEAGE_CONSUMER_UID=65532"}
		command.Env = append(command.Env, extra...)
		return command.Run()
	}
	if err := run("ZASP_SENSOR_TOKEN_FILE=/not-mounted/token"); err == nil {
		t.Fatal("layout role accepted product token configuration")
	}
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
		t.Fatal("rejected executable wrote state")
	}
	if err := run(); err != nil {
		t.Fatal("compiled initialization", err)
	}
	before, err := os.Lstat(filepath.Join(path, "consumer"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run(); err != nil {
		t.Fatal("compiled restart", err)
	}
	after, err := os.Lstat(filepath.Join(path, "consumer"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("compiled restart replaced state", err)
	}
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 4 {
		t.Fatal("unexpected initialized entries", err)
	}
}
