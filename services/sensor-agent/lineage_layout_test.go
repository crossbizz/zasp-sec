package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLineageLayoutRejectsNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root admission test")
	}
	path := t.TempDir()
	if err := initializeLineageLayout(path, uint32(os.Geteuid())); err == nil {
		t.Fatal("non-root initializer admitted")
	}
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
		t.Fatal("rejected initializer wrote state")
	}
}

func TestLineageLayoutCreatesExactDirectoriesAndPreservesRestart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root CHOWN fixture")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initializeLineageLayout(path, 65532); err != nil {
		t.Fatal("initial layout", err)
	}
	for name, mode := range map[string]os.FileMode{"producer": 0750, "acks": 0750, "consumer": 0700} {
		info, err := os.Lstat(filepath.Join(path, name))
		if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
			t.Fatal("incorrect layout", name, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		uid := uint32(65532)
		if name == "producer" {
			uid = 0
		}
		if !ok || stat.Uid != uid || stat.Gid != 65532 {
			t.Fatal("incorrect directory ownership", name)
		}
	}
	before, err := os.Lstat(filepath.Join(path, "consumer"))
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeLineageLayout(path, 65532); err != nil {
		t.Fatal("restart", err)
	}
	after, err := os.Lstat(filepath.Join(path, "consumer"))
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("restart replaced state", err)
	}
	// Root harness has CHOWN but no DAC override; restore only its fixtures.
	t.Cleanup(func() {
		for _, name := range []string{"acks", "consumer"} {
			if err := os.Chown(filepath.Join(path, name), 0, -1); err != nil {
				t.Error(err)
			}
		}
	})
}

func TestLineageLayoutRecoversOnlyEmptyOwnedPartialDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root CHOWN fixture")
	}
	for _, name := range []string{"producer", "acks", "consumer"} {
		for _, mode := range []os.FileMode{0700, 0750} {
			if name == "consumer" && mode == 0750 {
				continue
			}
			t.Run(name+"-"+mode.String(), func(t *testing.T) {
				path := t.TempDir()
				if err := os.Chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(path, name)
				if err := os.Mkdir(target, mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(target, 0, 0); err != nil {
					t.Fatal(err)
				}
				before, _ := os.Lstat(target)
				if err := initializeLineageLayout(path, 65532); err != nil {
					t.Fatal("partial restart", err)
				}
				after, err := os.Lstat(target)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("partial directory replaced", err)
				}
				t.Cleanup(func() {
					for _, name := range []string{"acks", "consumer"} {
						if err := os.Chown(filepath.Join(path, name), 0, -1); err != nil {
							t.Error(err)
						}
					}
				})
			})
		}
	}
}

func TestLineageLayoutPreservesCompletedFilesAndRejectsBusyLock(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root CHOWN fixture")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := initializeLineageLayout(path, 65532); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{"acks", "consumer"} {
			os.Chown(filepath.Join(path, name), 0, -1)
		}
	})
	target := filepath.Join(path, "producer", "retained-proof")
	if err := os.WriteFile(target, []byte("retain"), 0440); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Lstat(target)
	if err := initializeLineageLayout(path, 65532); err != nil {
		t.Fatal("restart with existing work", err)
	}
	after, err := os.Lstat(target)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Fatal("retained file changed", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "retain" {
		t.Fatal("retained contents changed")
	}
	lock, err := os.OpenFile(filepath.Join(path, ".layout.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("fixture lock")
	}
	if err := initializeLineageLayout(path, 65532); err == nil {
		t.Fatal("concurrent initializer acquired held lock")
	}
}

func TestLineageLayoutRejectsForeignEntriesBeforeWrites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires isolated root fixture")
	}
	for _, kind := range []string{"unknown", "symlink", "wrong-mode", "foreign-owner", "partial-nonempty"} {
		t.Run(kind, func(t *testing.T) {
			path := t.TempDir()
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(path, "producer")
			switch kind {
			case "unknown":
				if err := os.WriteFile(filepath.Join(path, "legacy-cursor"), []byte("retain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(t.TempDir(), target); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "wrong-mode" {
					if err := os.Chmod(target, 0777); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "foreign-owner" {
					if err := os.Chown(target, 65532, 65532); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { os.Chown(target, 0, -1) })
				}
				if kind == "partial-nonempty" {
					if err := os.WriteFile(filepath.Join(target, "retain"), []byte("retain"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, _ := os.ReadDir(path)
			if err := initializeLineageLayout(path, 65532); err == nil {
				t.Fatal("foreign layout admitted")
			}
			after, err := os.ReadDir(path)
			if err != nil || len(after) != len(before) {
				t.Fatal("rejected layout wrote entries", err)
			}
		})
	}
}
