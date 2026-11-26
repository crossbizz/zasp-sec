package openbaokv

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/openbaoclient"
)

func TestKVProtocolIsolationCreateOnlyAndConsumeOnce(t *testing.T) {
	type entry struct {
		Version int
		Record  record
	}
	values := make(map[string]entry)
	var mu sync.Mutex
	maxVersions := 1
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/v1/test/config" && r.Method == http.MethodGet {
			fmt.Fprintf(w, `{"data":{"max_versions":%d}}`, maxVersions)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/test/data/tenant-a/") {
			t.Errorf("escaped namespace %q", r.URL.Path)
			w.WriteHeader(403)
			return
		}
		key := r.URL.Path
		current := values[key]
		switch r.Method {
		case http.MethodGet:
			if current.Version == 0 {
				w.WriteHeader(404)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": current.Record, "metadata": map[string]int{"version": current.Version}}}); err != nil {
				t.Error(err)
			}
		case http.MethodPost:
			var input struct {
				Data    record
				Options struct{ CAS *int }
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Options.CAS == nil || *input.Options.CAS != current.Version {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"errors":["check-and-set parameter did not match the current version"]}`)
				return
			}
			values[key] = entry{current.Version + 1, input.Data}
			fmt.Fprintf(w, `{"data":{"version":%d}}`, current.Version+1)
		default:
			t.Errorf("unexpected %s", r.Method)
			w.WriteHeader(405)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	cfg := Config{Provider: Provider, Mount: "test", Client: openbaoclient.Config{Address: server.URL, TokenFile: filepath.Join(dir, "token"), CAFile: filepath.Join(dir, "ca")}}
	for path, data := range map[string][]byte{cfg.Client.TokenFile: []byte("scoped-token"), cfg.Client.CAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := New(cfg, "tenant-a", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer store.CloseIdleConnections()
	ctx := context.Background()
	if err = store.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	maxVersions = 10
	mu.Unlock()
	if err = store.Ready(ctx); err == nil {
		t.Fatal("accepted version retention")
	}
	mu.Lock()
	maxVersions = 1
	mu.Unlock()
	name := "tenant-a/oauth/one"
	binary := []byte{0, 0xff, 'a', 0}
	if err = store.Create(ctx, name, binary); err != nil {
		t.Fatal(err)
	}
	if err = store.Create(ctx, name, []byte("wrong")); err == nil {
		t.Fatal("overwrote previous bytes")
	}
	actual, err := store.Read(ctx, name)
	if err != nil || !bytes.Equal(actual, binary) {
		t.Fatal("lost binary data", err)
	}
	for _, wrong := range []string{"tenant-b/oauth/one", "tenant-ab/oauth/one", "tenant-a/../tenant-b/key", "tenant-a/encoded%2fkey"} {
		if err = store.Create(ctx, wrong, binary); err == nil {
			t.Errorf("created %s", wrong)
		}
		if _, err = store.Read(ctx, wrong); err == nil {
			t.Errorf("read %s", wrong)
		}
		if err = store.Delete(ctx, wrong); err == nil {
			t.Errorf("deleted %s", wrong)
		}
	}
	const count = 8
	var wg sync.WaitGroup
	out := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); out <- store.Delete(ctx, name) }()
	}
	wg.Wait()
	close(out)
	successes := 0
	for err := range out {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("%d successful consumes", successes)
	}
	if _, err := store.Read(ctx, name); !errors.Is(err, openbaoclient.ErrNotFound) {
		t.Fatal("read consumed grant", err)
	}
	if err = store.Create(ctx, name, binary); err == nil {
		t.Fatal("recreated consumed grant")
	}
	key := "tenant-a/okta/refresh-key"
	if err = store.Create(ctx, key, binary); err != nil {
		t.Fatal(err)
	}
	if err = store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err = store.Create(ctx, key, []byte("new-value")); err != nil {
		t.Fatal(err)
	}
	actual, err = store.Read(ctx, key)
	if err != nil || string(actual) != "new-value" {
		t.Fatal("credential rotation failed", err)
	}
}

func TestProviderSelectionRequiresCompleteConfiguration(t *testing.T) {
	for _, provider := range []string{"", "aws-secrets-manager"} {
		getenv := func(k string) string {
			if k == "ZASP_CONNECTOR_SECRETS_PROVIDER" {
				return provider
			}
			return ""
		}
		if !FromEnvironment(getenv).Valid() {
			t.Fatalf("legacy default %q rejected", provider)
		}
	}
	for _, cfg := range []Config{{Provider: "unknown"}, {Provider: Provider}, {Provider: "aws-secrets-manager", Mount: "test"}, {Provider: Provider, Mount: "kv/../x"}} {
		if cfg.Valid() {
			t.Errorf("accepted %#v", cfg)
		}
	}
}
