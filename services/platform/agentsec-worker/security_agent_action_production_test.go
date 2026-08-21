package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecurityAgentActionPrivateKeyRequiresCanonicalBoundedReadOnlySecret(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "gateway-signing-private-key")
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(privateKey)), 0o400); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSecurityAgentActionPrivateKey(path)
	if err != nil || !privateKey.Equal(loaded) {
		t.Fatalf("loaded=%d err=%v", len(loaded), err)
	}
	for index := range loaded {
		loaded[index] = 0
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(privateKey)+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecurityAgentActionPrivateKey(path); err == nil {
		t.Fatal("accepted noncanonical private key")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecurityAgentActionPrivateKey(path); err == nil {
		t.Fatal("accepted world-readable private key")
	}
}
