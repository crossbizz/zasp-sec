package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type benchmarkTransport func(*http.Request) (*http.Response, error)

func (f benchmarkTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDevBenchmarkSendsOnlyFixedObservations(t *testing.T) {
	key := filepath.Join(t.TempDir(), "fixture.key")
	if err := os.WriteFile(key, []byte("sk-or-v1-development-fixture-token"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	calls := 0
	client := &http.Client{Transport: benchmarkTransport(func(r *http.Request) (*http.Response, error) {
		payload, err := io.ReadAll(r.Body)
		if err != nil || r.URL.String() != "https://openrouter.ai/api/v1/chat/completions" || !strings.Contains(string(payload), fixedCases[calls].action) || !strings.Contains(string(payload), `"zdr":true`) {
			t.Fatal("invalid synthetic call")
		}
		data := fmt.Sprintf(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"%s"}}]}`, fixedCases[calls].want)
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(data))}, nil
	})}
	if n, err := runSyntheticEvaluation(context.Background(), client, f); err != nil || n != len(fixedCases) || calls != n {
		t.Fatalf("benchmark result %d/%d: %v", n, calls, err)
	}
}
