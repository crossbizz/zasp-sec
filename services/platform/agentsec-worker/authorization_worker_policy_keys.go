package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/policy"
)

// loadWorkerGatewayPolicyKeys reads only independent public verifier material.
// It never loads a signer or returns an error containing a configured path.
func loadWorkerGatewayPolicyKeys(path string) (policy.GatewayPolicyKeys, error) {
	value, err := loadWorkerGatewayPolicyVerifier(path)
	return value.keys, err
}

type workerGatewayPolicyVerifier struct {
	keys   policy.GatewayPolicyKeys
	digest [32]byte
}

func loadWorkerGatewayPolicyVerifier(path string) (workerGatewayPolicyVerifier, error) {
	invalid := workerGatewayPolicyVerifier{}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return invalid, errWorkerExecution
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o400 || before.Size() < 1 || before.Size() > 65536 {
		return invalid, errWorkerExecution
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return invalid, errWorkerExecution
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o400 || !os.SameFile(before, opened) || before.Size() != opened.Size() || !before.ModTime().Equal(opened.ModTime()) {
		_ = file.Close()
		return invalid, errWorkerExecution
	}
	body, readErr := io.ReadAll(io.LimitReader(file, 65537))
	closeErr := file.Close()
	after, afterErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || afterErr != nil || !after.Mode().IsRegular() || after.Mode().Perm() != 0o400 || !os.SameFile(opened, after) || before.Size() != after.Size() || before.Size() != int64(len(body)) || !before.ModTime().Equal(after.ModTime()) {
		return invalid, errWorkerExecution
	}
	var wire struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &wire) != nil || len(wire.Keys) < 1 || len(wire.Keys) > 32 {
		return invalid, errWorkerExecution
	}
	// The configuration has one canonical JSON representation. Round-trip
	// equality also refuses unknown, duplicate, missing and null fields.
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(bytes.TrimSpace(body), canonical) {
		return invalid, errWorkerExecution
	}
	values := make(map[string]ed25519.PublicKey, len(wire.Keys))
	for _, entry := range wire.Keys {
		public, err := base64.RawURLEncoding.Strict().DecodeString(entry.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(public) != entry.PublicKey {
			return invalid, errWorkerExecution
		}
		if _, exists := values[entry.KeyID]; exists {
			return invalid, errWorkerExecution
		}
		values[entry.KeyID] = ed25519.PublicKey(public)
	}
	keys, err := policy.NewGatewayPolicyKeys(values)
	if err != nil {
		return invalid, errWorkerExecution
	}
	return workerGatewayPolicyVerifier{keys: keys, digest: sha256.Sum256(body)}, nil
}
