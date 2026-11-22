package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWorkerBindsOneUploadAndExcludesContent(t *testing.T) {
	const id = "pid_45d20ba8-ac12-4c2a-8bfa-72946ee3bc5c"
	const origin = "https://worker.example.invalid"
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	root, err := os.OpenRoot(testSpool(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	scope := strings.Join([]string{id, id, id}, "/")
	w := &worker{origin: origin, scope: scope, uiOrigin: "https://app.invalid", key: key.Public().(ed25519.PublicKey), markers: root, seats: make(chan struct{}, 1)}
	var body bytes.Buffer
	z := zip.NewWriter(&body)
	f, err := z.Create("SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("# TICKET_PRIVATE_CONTENT\n<!-- private note -->"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body.Bytes())
	base := grant{"private-addon-upload.v1", origin, scope, id, id, "sha256:" + hex.EncodeToString(sum[:]), int64(body.Len()), time.Now().Unix() + 299, false, 0}
	send := func(g grant, contents []byte, origin string) *httptest.ResponseRecorder {
		raw, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(key, append([]byte("zasp-private-addon-upload.v1\x00"), raw...))
		token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig)
		req := httptest.NewRequest("PUT", "/v1/uploads/"+id, bytes.NewReader(contents))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/zip")
		req.Header.Set("Origin", origin)
		resp := httptest.NewRecorder()
		w.ServeHTTP(resp, req)
		return resp
	}
	for _, mutate := range []func(*grant){func(v *grant) { v.Scope = "another" }, func(v *grant) { v.Audience = "https://other.invalid" }, func(v *grant) { v.Expires = time.Now().Unix() - 1 }} {
		g := base
		mutate(&g)
		if resp := send(g, body.Bytes(), ""); resp.Code != 403 {
			t.Fatalf("foreign/expired grant: %d", resp.Code)
		}
	}
	if resp := send(base, body.Bytes(), "https://other.invalid"); resp.Code != 403 {
		t.Fatal("foreign web origin")
	}
	if resp := send(base, []byte("short"), ""); resp.Code != 400 {
		t.Fatal("mismatched length")
	}
	resp := send(base, body.Bytes(), "https://app.invalid")
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), "instruction.hidden_text") || strings.Contains(resp.Body.String(), "TICKET_PRIVATE_CONTENT") || strings.Contains(resp.Body.String(), "SKILL.md") || resp.Header().Get("Access-Control-Allow-Origin") != "https://app.invalid" {
		t.Fatalf("unsafe scan result: %d %s", resp.Code, resp.Body.String())
	}
	if resp := send(base, body.Bytes(), ""); resp.Code != 409 {
		t.Fatal("grant replay")
	}
	marker, err := root.Lstat(id)
	if err != nil || marker.Size() != 0 {
		t.Fatalf("marker contains source: %v", err)
	}
	req := httptest.NewRequest("OPTIONS", "/v1/uploads/"+id, nil)
	req.Header.Set("Origin", "https://app.invalid")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	pre := httptest.NewRecorder()
	w.ServeHTTP(pre, req)
	if pre.Code != http.StatusNoContent {
		t.Fatal("preflight")
	}
	w.expireMarkers(time.Now().Add(2 * time.Hour))
	if _, err = root.Lstat(id); !os.IsNotExist(err) {
		t.Fatal("expired marker retained")
	}
}

func TestPrivateWorkerLocalListener(t *testing.T) {
	for _, tc := range []struct {
		env, addr string
		valid     bool
	}{{"production", "", true}, {"local", "127.0.0.1:8444", true}, {"test", "[::1]:9200", true}, {"production", "127.0.0.1:8444", false}, {"test", "0.0.0.0:8444", false}, {"local", "unverified.invalid:8443", false}, {"local", ":8443", false}, {"test", "127.0.0.1:99999", false}} {
		got, err := workerListenAddress(tc.env, tc.addr)
		if (err == nil) != tc.valid || tc.addr == "" && got != ":8443" {
			t.Fatalf("listener %s %s: %s %v", tc.env, tc.addr, got, err)
		}
	}
}
