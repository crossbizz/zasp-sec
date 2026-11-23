//go:build windows

package pretool

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestScopedFixedDriveRejectsAliasesAndOutsideRoots(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "sub")
	if e := os.Mkdir(child, 0700); e != nil {
		t.Fatal(e)
	}
	if !ScopedWindowsCWD(root, child) || ScopedWindowsCWD(root, filepath.Dir(root)) || ScopedWindowsCWD(root, root+`\sub\..\sub`) {
		t.Fatal("working-directory scope mismatch")
	}
	first := filepath.Join(child, "sample.txt")
	if e := os.WriteFile(first, []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	if reason, ok := pathChain(first); !ok || reason != "" {
		t.Fatalf("regular file: %s", reason)
	}
	alias := filepath.Join(child, "alias.txt")
	if e := os.Link(first, alias); e != nil {
		t.Fatal(e)
	}
	if reason, _ := pathChain(alias); reason != "unverifiable_path" {
		t.Fatal("ambiguous hard link")
	}
	junction := filepath.Join(root, "junction")
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	// The built-in mklink command creates a directory junction without enabling
	// developer-mode symbolic links. All paths here are test-owned.
	if out, err := exec.Command(filepath.Join(sys, "cmd.exe"), "/d", "/c", "mklink", "/J", junction, child).CombinedOutput(); err != nil {
		t.Fatalf("fixture junction: %v %s", err, out)
	}
	if ScopedWindowsCWD(root, junction) {
		t.Fatal("junction presented as a verified working directory")
	}
	// NTFS alternate data streams and nonlocal volumes are lexical refusals.
	for _, value := range []string{first + ":metadata", `\\fixture.invalid\external\file`} {
		if reason, _ := pathChain(value); reason != "unverifiable_path" {
			t.Fatal("unscoped path")
		}
	}
}
