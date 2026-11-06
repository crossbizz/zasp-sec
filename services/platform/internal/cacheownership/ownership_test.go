package cacheownership

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCacheOwnershipExclusiveLifetime(t *testing.T) {
	if !Supported() {
		t.Skip("Linux flock required")
	}
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	g, e := Acquire(root, "cache.json")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	if !g.Valid() {
		t.Fatal("new guard invalid")
	}
	if other, e := Acquire(root, "cache.json"); e == nil {
		other.Close()
		t.Fatal("second owner accepted")
	}
	independent, e := Acquire(root, "another.json")
	if e != nil {
		t.Fatal("distinct basename blocked", e)
	}
	independent.Close()
	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
	if g.Valid() {
		t.Fatal("closed guard valid")
	}
	next, e := Acquire(root, "cache.json")
	if e != nil {
		t.Fatal("release failed", e)
	}
	next.Close()
	if e = g.Close(); e != nil {
		t.Fatal("close not idempotent", e)
	}
}
func TestCacheOwnershipPathAndReplacementRefusal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux ownership")
	}
	dir := t.TempDir()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	for _, name := range []string{"", ".", "..", "../cache", "a/b", "/absolute"} {
		if g, e := Acquire(root, name); e == nil {
			g.Close()
			t.Fatalf("accepted %q", name)
		}
	}
	g, e := Acquire(root, "cache")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatalf("lock file count: %v %d", e, len(entries))
	}
	name := entries[0].Name()
	info, e := entries[0].Info()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("lock mode/type")
	}
	if e = os.Rename(filepath.Join(dir, name), filepath.Join(dir, "old-lock")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, name), nil, 0600); e != nil {
		t.Fatal(e)
	}
	if g.Valid() {
		t.Fatal("replaced inode valid")
	}
	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, name)); e != nil {
		t.Fatal("Close removed replacement", e)
	}
}
func TestCacheOwnershipUnsafeExistingLock(t *testing.T) {
	if !Supported() {
		t.Skip("Linux flock")
	}
	dir := t.TempDir()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	g, e := Acquire(root, "cache")
	if e != nil {
		t.Fatal(e)
	}
	g.Close()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("stable lock retained")
	}
	path := filepath.Join(dir, entries[0].Name())
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if g, e = Acquire(root, "cache"); e == nil {
		g.Close()
		t.Fatal("unsafe existing mode accepted")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("target", path); e != nil {
		t.Fatal(e)
	}
	if g, e = Acquire(root, "cache"); e == nil {
		g.Close()
		t.Fatal("symlink accepted")
	}
}
func TestCacheOwnershipCrossProcess(t *testing.T) {
	if os.Getenv("ZASP_CACHE_LOCK_CHILD") == "1" {
		root, e := os.OpenRoot(os.Getenv("ZASP_CACHE_LOCK_ROOT"))
		if e != nil {
			os.Exit(12)
		}
		defer root.Close()
		g, e := Acquire(root, "cache")
		if e == nil {
			g.Close()
			os.Exit(13)
		}
		return
	}
	if !Supported() {
		t.Skip("Linux flock")
	}
	dir := t.TempDir()
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	g, e := Acquire(root, "cache")
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCacheOwnershipCrossProcess$")
	cmd.Env = append(os.Environ(), "ZASP_CACHE_LOCK_CHILD=1", "ZASP_CACHE_LOCK_ROOT="+dir)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("child exclusion: %v %s", e, out)
	}
}
