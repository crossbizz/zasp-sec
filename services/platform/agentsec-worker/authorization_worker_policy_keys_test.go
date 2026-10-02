package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A public verifier set is independent configuration, never derived by loading
// the private signer. Wrong file/JSON/key identities must not become trusted.
func TestWorkerGatewayPolicyVerifierFile(t *testing.T) {
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	entry := `{"key_id":"gateway-key-1","public_key":"` + base64.RawURLEncoding.EncodeToString(public) + `"}`
	valid := `{"keys":[` + entry + `]}`
	for _, mode := range []string{"exact", "32-keys", "33-keys", "empty", "unknown", "duplicate-field", "duplicate-id", "null-list", "null-key", "private-key", "bad-base64", "padded-base64", "bad-id", "trailing", "oversized", "symlink", "directory", "fifo", "writable", "relative", "missing"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy-keys.json")
			body := valid
			switch mode {
			case "32-keys", "33-keys":
				n := 32
				if mode == "33-keys" {
					n++
				}
				items := make([]string, n)
				for i := range items {
					items[i] = strings.Replace(entry, "gateway-key-1", fmt.Sprintf("gateway-key-%d", i+1), 1)
				}
				body = `{"keys":[` + strings.Join(items, ",") + `]}`
			case "empty":
				body = `{"keys":[]}`
			case "unknown":
				body = `{"keys":[` + entry + `],"private_key":"forbidden"}`
			case "duplicate-field":
				body = `{"keys":[],"keys":[` + entry + `]}`
			case "duplicate-id":
				body = `{"keys":[` + entry + `,` + entry + `]}`
			case "null-list":
				body = `{"keys":null}`
			case "null-key":
				body = `{"keys":[null]}`
			case "private-key":
				body = strings.Replace(valid, base64.RawURLEncoding.EncodeToString(public), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{31}, ed25519.PrivateKeySize)), 1)
			case "bad-base64":
				body = strings.Replace(valid, base64.RawURLEncoding.EncodeToString(public), "not-base64", 1)
			case "padded-base64":
				body = strings.Replace(valid, base64.RawURLEncoding.EncodeToString(public), base64.StdEncoding.EncodeToString(public), 1)
			case "bad-id":
				body = strings.Replace(valid, "gateway-key-1", "../key", 1)
			case "trailing":
				body += `{}`
			case "oversized":
				body = strings.Repeat(" ", 65537) + valid
			}
			if err := os.WriteFile(path, []byte(body), 0o400); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "symlink":
				link := filepath.Join(dir, "link")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "directory":
				path = dir
			case "fifo":
				path = filepath.Join(dir, "fifo")
				if err := syscall.Mkfifo(path, 0o400); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "relative":
				path = "policy-keys.json"
			case "missing":
				path = filepath.Join(dir, "missing")
			}
			keys, err := loadWorkerGatewayPolicyKeys(path)
			if mode == "exact" || mode == "32-keys" {
				if err != nil || !keys.Valid() || !keys.Contains("gateway-key-1", public) {
					t.Fatal("valid independent verifier refused", err)
				}
				if mode == "32-keys" && !keys.Contains("gateway-key-32", public) {
					t.Fatal("maximum verifier set truncated")
				}
			} else if err == nil || keys.Valid() {
				t.Fatal("unsafe verifier configuration accepted")
			}
		})
	}
}
