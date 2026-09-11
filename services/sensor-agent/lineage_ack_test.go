package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func acknowledgmentFixture(t *testing.T) (*lineageAcknowledgments, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acks")
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	store, err := newLineageAcknowledgments(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, path
}

func TestLineageAcknowledgmentRequiresSealedVerifiedConsumption(t *testing.T) {
	for _, state := range []string{"pending", "unsealed", "unconsumed", "complete", "empty", "changed chunk", "replaced manifest", "replaced generation", "closed reader", "closed consumer", "closed store", "canceled"} {
		t.Run(state, func(t *testing.T) {
			calls := 0
			generation, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) {
				calls++
				if state == "pending" {
					return nil, errors.New("offline")
				}
				return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
			})
			if state != "empty" {
				line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
				if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
					t.Fatal(err)
				}
			}
			if state != "unsealed" {
				if err := generation.Seal(context.Background(), "disconnect", 2, 3); err != nil {
					t.Fatal(err)
				}
			}
			store, path := acknowledgmentFixture(t)
			consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, cursor, 16, nil, store)
			if err != nil {
				t.Fatal(err)
			}
			defer consumer.Close()
			if state != "unconsumed" {
				_, err := consumer.ProcessAvailable(context.Background())
				if state == "pending" && err != sensoradapter.ErrClientRetryable || state != "pending" && err != nil {
					t.Fatal(err)
				}
			}
			if state == "changed chunk" {
				file := filepath.Join(reader.root.Name(), "chunk-0000000001.jsonl")
				if err := os.Chmod(file, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte("changed"), 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(file, 0440); err != nil {
					t.Fatal(err)
				}
			}
			beforeCalls := calls
			ctx := context.Background()
			switch state {
			case "replaced manifest":
				path := filepath.Join(reader.root.Name(), "manifest.json")
				if err := os.Rename(path, filepath.Join(t.TempDir(), "manifest.old")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, reader.manifestBytes, 0440); err != nil {
					t.Fatal(err)
				}
			case "replaced generation":
				if err := os.Rename(reader.root.Name(), reader.root.Name()+".old"); err != nil {
					t.Fatal(err)
				}
			case "closed reader":
				reader.Close()
			case "closed consumer":
				consumer.Close()
			case "closed store":
				store.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = consumer.Acknowledge(ctx)
			name := "ack-" + reader.Source().GenerationID + ".json"
			if state != "complete" && state != "empty" {
				if err == nil {
					t.Fatal("incomplete source acknowledged")
				}
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 0 {
					t.Fatal("failed proof mutated acknowledgment directory")
				}
			} else {
				if err != nil {
					t.Fatal("verified source not acknowledged", err)
				}
				raw, err := os.ReadFile(filepath.Join(path, name))
				if err != nil {
					t.Fatal(err)
				}
				var ack lineageConsumptionAck
				if json.Unmarshal(raw, &ack) != nil || ack.Version != "tetragon-consumption-ack-v1" || ack.Consumption.Source != reader.Source() || ack.Seal.Dropped != 2 || ack.Seal.Filtered != 3 || ack.Seal.CoverageComplete || ack.Manifest != lineageHash(reader.manifestBytes) || ack.Consumption.Progress.NextSequence != ack.Seal.Chunks+1 {
					t.Fatal("acknowledgment lost exact generation or closure accounting")
				}
				if err := consumer.Acknowledge(context.Background()); err != nil {
					t.Fatal("identical acknowledgment retry", err)
				}
				again, _ := os.ReadFile(filepath.Join(path, name))
				if !bytes.Equal(raw, again) {
					t.Fatal("retry changed acknowledgment")
				}
			}
			if calls != beforeCalls {
				t.Fatal("acknowledgment uploaded or read credentials")
			}
		})
	}
}

func TestLineageAcknowledgmentRootIsolationBeforeWrites(t *testing.T) {
	for _, overlap := range []string{"source", "spool", "cursor", "token"} {
		t.Run(overlap, func(t *testing.T) {
			_, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) { t.Fatal("transport"); return nil, nil })
			path := filepath.Dir(cursor)
			protected := []sensoradapter.PinnedInput{}
			switch overlap {
			case "source":
				path = reader.root.Name()
			case "spool":
				path = reader.parent.Name()
			case "token":
				path = t.TempDir()
				root, err := os.OpenRoot(path)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				protected = []sensoradapter.PinnedInput{{Parent: root, Name: "token"}}
			}
			if err := os.Chmod(path, 0750); err != nil {
				t.Fatal(err)
			}
			store, err := newLineageAcknowledgments(path)
			if err != nil {
				return
			} // Read-only admission may reject existing producer files.
			defer store.Close()
			if consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, cursor, 16, protected, store); err == nil {
				consumer.Close()
				t.Fatal("overlapping output accepted")
			}
			for _, name := range []string{filepath.Join(path, ".consumer.lock"), cursor + ".lock"} {
				if _, err := os.Stat(name); !os.IsNotExist(err) {
					t.Fatal("unsafe construction wrote state")
				}
			}
		})
	}
}
