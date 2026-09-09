package main

import (
	"bytes"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunnerReadsConfinedProjectedConfigMapCA(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	root := t.TempDir()
	version := filepath.Join(root, "..2026_09_09_000001")
	if err := os.Mkdir(version, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(version, "ca.crt"), certificate, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(version), filepath.Join(root, "..data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "ca.crt")
	if err := os.Symlink("..data/ca.crt", path); err != nil {
		t.Fatal(err)
	}
	actual, ok := readRunnerPinnedCA(path)
	if !ok || !bytes.Equal(actual, certificate) {
		t.Fatal("Kubernetes atomic ConfigMap projection rejected")
	}
	for _, target := range []string{filepath.Join(version, "ca.crt"), "../" + filepath.Base(root) + "/..data/ca.crt", "missing"} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, ok := readRunnerPinnedCA(path); ok {
			t.Fatalf("unconfined or dangling CA symlink accepted: %q", target)
		}
	}
}
