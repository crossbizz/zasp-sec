package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLineageRecoveryPreservesPublishedPrefixAndUncertainTail(t *testing.T) {
	for _, state := range []string{"empty", "published", "complete pending chunk", "partial pending chunk", "shared prefix", "empty pending", "complete pending seal", "partial pending seal"} {
		t.Run(state, func(t *testing.T) {
			generation, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
			})
			ctx := context.Background()
			spool, source, path := generation.spool, generation.source, generation.root.Name()
			wantRecords := 0
			if state != "empty" {
				line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
				if _, err := generation.Append(ctx, [][]byte{line}); err != nil {
					t.Fatal(err)
				}
				wantRecords = 1
			}
			var fragment []byte
			wantFragment := false
			switch state {
			case "complete pending chunk", "partial pending chunk":
				line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
				chunk, err := generation.Append(ctx, [][]byte{line})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(path, chunk.Name), filepath.Join(path, ".pending")); err != nil {
					t.Fatal(err)
				}
				if state == "complete pending chunk" {
					wantRecords++
				} else {
					fragment = []byte(`{"version":"tetragon-spool-chunk-v1","manifest_sha256":"`)
					if err := os.Chmod(filepath.Join(path, ".pending"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(path, ".pending"), fragment, 0600); err != nil {
						t.Fatal(err)
					}
					wantFragment = true
				}
			case "empty pending":
				wantFragment = true
				if err := os.WriteFile(filepath.Join(path, ".pending"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "shared prefix":
				fragment = []byte(`{"version":"tetragon-`)
				wantFragment = true
				if err := os.WriteFile(filepath.Join(path, ".pending"), fragment, 0600); err != nil {
					t.Fatal(err)
				}
			case "complete pending seal", "partial pending seal":
				if err := generation.Seal(ctx, "disconnect", 2, 3); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(path, "closed.json"), filepath.Join(path, ".pending")); err != nil {
					t.Fatal(err)
				}
				if state == "partial pending seal" {
					fragment = []byte(`{"version":"tetragon-spool-closed-v1","manifest_sha256":"broken`)
					if err := os.Chmod(filepath.Join(path, ".pending"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(path, ".pending"), fragment, 0600); err != nil {
						t.Fatal(err)
					}
					wantFragment = true
				}
			}
			generation.Close()
			spoolPath := spool.root.Name()
			spool.Close()
			spool, err := newLineageSpool(spoolPath, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			for retry := 0; retry < 2; retry++ {
				if complete, err := spool.SealInterrupted(ctx, source); err != nil || !complete {
					t.Fatal("interrupted source not closed", err)
				}
			}
			seal, found, err := reader.ReadSeal()
			if err != nil || !found || seal.Records != wantRecords || seal.CoverageComplete {
				t.Fatal("invalid recovered prefix", seal, err)
			}
			raw, err := os.ReadFile(filepath.Join(path, "closed.json"))
			if err != nil {
				t.Fatal(err)
			}
			var metadata map[string]any
			if json.Unmarshal(raw, &metadata) != nil {
				t.Fatal("seal JSON")
			}
			if state == "complete pending seal" {
				if seal.Reason != "disconnect" || seal.Dropped != 2 || seal.Filtered != 3 {
					t.Fatal("lost complete original seal")
				}
			} else if seal.Reason != "producer_restart" || metadata["counters_unknown"] != true {
				t.Fatal("recovery invented known counters", string(raw))
			}
			if wantFragment {
				got, err := os.ReadFile(filepath.Join(path, "interrupted.bin"))
				if err != nil || !bytes.Equal(got, fragment) || metadata["interrupted_sha256"] != lineageHash(fragment) {
					t.Fatal("lost fragment", err)
				}
			}
			store, ackPath := acknowledgmentFixture(t)
			consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, cursor, 16, nil, store)
			if err != nil {
				t.Fatal(err)
			}
			for step := 0; step <= seal.Chunks; step++ {
				if _, err := consumer.ProcessAvailable(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := consumer.Acknowledge(ctx); err != nil {
				t.Fatal("recovered source not ACKable", err)
			}
			consumer.Close()
			receipts, err := newLineageReceiptReader(ackPath, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer receipts.Close()
			request := lineageReclaimRequest{Source: source, Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: uint32(os.Getuid())}
			if complete, err := spool.ReclaimAcknowledged(ctx, receipts, request); err != nil || !complete {
				t.Fatal("acknowledged fragment not reclaimed", err)
			}
		})
	}
}
