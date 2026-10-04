package authorization

// PRIVATE future tests of the actual internal reader lifecycle, not test hooks.
// Missing helpers/compile failure are NOT RED. Execute only after Root's body
// RED and explicit authorization to implement the reader.
import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComplianceCurrentKeyActualOwnerPredicate(t *testing.T) {
	path := currentKeyWriteFixture(t)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !complianceCurrentKeyFileAdmissible(fi, os.Geteuid()) {
		t.Fatal("actual owner-readonly file refused")
	}
	if complianceCurrentKeyFileAdmissible(fi, os.Geteuid()+1) {
		t.Fatal("owner mismatch admitted")
	}
}
func currentKeyHeldFixture(t *testing.T, path string) *heldComplianceCurrentKeyFile {
	t.Helper()
	h, err := holdComplianceCurrentKeyFile(path)
	if err != nil || h == nil {
		t.Fatalf("valid held file refused: %v", err)
	}
	t.Cleanup(func() { _ = h.validateAndClose() })
	return h
}
func currentKeyReadOrCloseMustRefuse(t *testing.T, h *heldComplianceCurrentKeyFile) {
	t.Helper()
	seed, readErr := h.readSeed()
	clear(seed)
	closeErr := h.validateAndClose()
	if !errors.Is(readErr, ErrInvalid) && !errors.Is(closeErr, ErrInvalid) {
		t.Fatal("real held reader accepted identity drift")
	}
}
func TestComplianceCurrentKeyHeldReaderNormalLifecycle(t *testing.T) {
	h := currentKeyHeldFixture(t, currentKeyWriteFixture(t))
	seed, err := h.readSeed()
	defer clear(seed)
	if err != nil || string(seed) != currentKeyFixtureSeed {
		t.Fatal("normal held read refused or changed fixture")
	}
	if err = h.validateAndClose(); err != nil {
		t.Fatal("normal held close refused")
	}
	if seed2, err := h.readSeed(); err == nil || len(seed2) != 0 {
		clear(seed2)
		t.Fatal("closed reader reused")
	}
}
func TestComplianceCurrentKeyHeldAncestorReplacement(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "seed")
	if err := os.WriteFile(path, []byte(currentKeyFixtureSeed), 0400); err != nil {
		t.Fatal(err)
	}
	h := currentKeyHeldFixture(t, path)
	if err := os.Rename(parent, parent+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(currentKeyFixtureSeed), 0400); err != nil {
		t.Fatal(err)
	}
	currentKeyReadOrCloseMustRefuse(t, h)
}
func TestComplianceCurrentKeyLeafReplacementAfterOpen(t *testing.T) {
	path := currentKeyWriteFixture(t)
	h := currentKeyHeldFixture(t, path)
	if err := os.Rename(path, path+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(currentKeyFixtureSeed), 0400); err != nil {
		t.Fatal(err)
	}
	currentKeyReadOrCloseMustRefuse(t, h)
}
func TestComplianceCurrentKeySameSizeReadMutationRestoredMtime(t *testing.T) {
	path := currentKeyWriteFixture(t)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	h := currentKeyHeldFixture(t, path)
	seed, err := h.readSeed()
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("abcdef0123456789abcdef0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Now(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := h.validateAndClose(); !errors.Is(err, ErrInvalid) {
		t.Fatal("same-size postread mutation with restored mtime admitted")
	}
}
func TestComplianceCurrentKeyPostReadHardlinkMutation(t *testing.T) {
	path := currentKeyWriteFixture(t)
	h := currentKeyHeldFixture(t, path)
	seed, err := h.readSeed()
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+"-alias"); err != nil {
		t.Fatal(err)
	}
	if err := h.validateAndClose(); !errors.Is(err, ErrInvalid) {
		t.Fatal("post-read additional hardlink admitted")
	}
}
func TestComplianceCurrentKeyPostReadModeMutationRestored(t *testing.T) {
	path := currentKeyWriteFixture(t)
	h := currentKeyHeldFixture(t, path)
	seed, err := h.readSeed()
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if err := h.validateAndClose(); !errors.Is(err, ErrInvalid) {
		t.Fatal("post-read mode mutation restored before close admitted")
	}
}
