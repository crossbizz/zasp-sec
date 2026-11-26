package openbaoclient

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequestUsesVerifiedTLSFreshTokenAndRedactedErrors(t *testing.T) {
	var token = "short-lived-token-A"
	redirects := 0
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects++ }))
	defer other.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			http.Error(w, "secret provider error", 403)
			return
		}
		switch r.URL.Path {
		case "/v1/kv/read":
			w.Write([]byte(`{"data":"present"}`))
		case "/v1/kv/missing":
			w.WriteHeader(404)
		case "/v1/kv/sealed":
			http.Error(w, "secret provider error", 503)
		case "/v1/kv/redirect":
			http.Redirect(w, r, other.URL, 307)
		case "/v1/kv/large":
			w.Write([]byte(strings.Repeat("a", (1<<20)+1)))
		case "/v1/kv/malformed":
			w.Write([]byte("invalid JSON"))
		default:
			t.Errorf("unexpected path %v", r.URL.Path)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	c := Config{Address: server.URL, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca.pem")}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(c.CAFile, cert, 0600); err != nil {
		t.Fatal(err)
	}
	writeToken := func(content string) {
		t.Helper()
		if err := os.WriteFile(c.TokenFile, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeToken(token)
	client, err := New(c, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	read := func(path string) error {
		var result struct{ Data string }
		return client.Do(context.Background(), http.MethodGet, path, nil, &result)
	}
	if err := read("kv/read"); err != nil {
		t.Fatal(err)
	}
	token = "short-lived-token-B"
	if err := read("kv/read"); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret provider error") {
		t.Fatal("expected redacted authentication error")
	}
	writeToken(token + "\n")
	if err := read("kv/read"); err != nil {
		t.Fatal("rotated token:", err)
	}
	if err := read("kv/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, path := range []string{"kv/sealed", "kv/redirect", "kv/large", "kv/malformed", "..", "kv/../token", "kv/%2f", "kv//read", "/kv/read"} {
		if err := read(path); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v", path, err)
		}
	}
	if redirects != 0 {
		t.Fatal("redirect was followed")
	}
	if err := os.Chmod(c.TokenFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err := read("kv/read"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted public token file")
	}
	if err := os.Chmod(c.TokenFile, 0600); err != nil {
		t.Fatal(err)
	}
	c.CAFile = ""
	untrusted, err := New(c, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.CloseIdleConnections()
	if err := untrusted.Do(context.Background(), http.MethodGet, "kv/read", nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted unknown CA")
	}
	for _, origin := range []string{"http://localhost:8200", "https://x@host", "https://host/?x=y", "https://host#fragment", "https://host/v1"} {
		c.Address = origin
		if c.Valid() {
			t.Errorf("accepted %q", origin)
		}
	}
}
