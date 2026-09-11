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

type lineageReceiptFixtureState struct {
	generation      *lineageSpoolGeneration
	reader          *lineageSpoolReader
	receipts        *lineageReceiptReader
	ackPath, cursor string
	ack             lineageConsumptionAck
}

func lineageReceiptFixture(t *testing.T, empty bool) lineageReceiptFixtureState {
	t.Helper()
	generation, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	})
	if !empty {
		line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
		if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
			t.Fatal(err)
		}
	}
	if err := generation.Seal(context.Background(), "disconnect", 3, 2); err != nil {
		t.Fatal(err)
	}
	store, ackPath := acknowledgmentFixture(t)
	consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, cursor, 16, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	if _, err := consumer.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := consumer.Acknowledge(context.Background()); err != nil {
		t.Fatal(err)
	}
	// This fixture's consumer is finished. Release its ACK writer ownership so
	// a restarted consumer can acquire the same persistent lock for retirement.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The producer retains its lock, but this target no longer has a live writer.
	generation.Close()
	receipts, err := newLineageReceiptReader(ackPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receipts.Close() })
	raw, err := os.ReadFile(filepath.Join(ackPath, "ack-"+reader.Source().GenerationID+".json"))
	var ack lineageConsumptionAck
	if err != nil || json.Unmarshal(raw, &ack) != nil {
		t.Fatal("receipt fixture missing", err)
	}
	return lineageReceiptFixtureState{generation: generation, reader: reader, receipts: receipts, ackPath: ackPath, cursor: cursor, ack: ack}
}

func TestLineageProducerReceiptVerifiesExactSealedSourceWithoutConsumerState(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "record", true: "empty"}[empty], func(t *testing.T) {
			fixture := lineageReceiptFixture(t, empty)
			if err := os.Remove(fixture.cursor); err != nil {
				t.Fatal(err)
			}
			ackFile := filepath.Join(fixture.ackPath, "ack-"+fixture.reader.Source().GenerationID+".json")
			before, _ := os.ReadFile(ackFile)
			ack, found, err := fixture.generation.spool.VerifyAcknowledgment(context.Background(), fixture.receipts, fixture.reader.Source(), "https://runtime.example.test/internal/v1/runtime/events")
			if err != nil || !found || ack != fixture.ack {
				t.Fatal("genuine sealed consumption not admitted", err)
			}
			after, err := os.ReadFile(ackFile)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("producer changed consumer receipt")
			}
			if _, err := os.Stat(fixture.cursor); !os.IsNotExist(err) {
				t.Fatal("producer recreated consumer cursor")
			}
			if _, found, err := fixture.reader.ReadSeal(); err != nil || !found {
				t.Fatal("producer validation changed source", err)
			}
		})
	}
}

func TestLineageProducerReceiptRejectsContradictionsWithoutDeleting(t *testing.T) {
	for _, mutation := range []string{"missing", "version", "source", "destination", "device", "inode", "manifest", "seal", "seal hash", "chain", "records", "accounting", "noncanonical", "unknown field", "duplicate field", "wrong mode", "symlink", "hardlink", "changed chunk", "missing seal", "active target", "closed spool", "closed receipts", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			file := filepath.Join(fixture.ackPath, "ack-"+fixture.reader.Source().GenerationID+".json")
			ack := fixture.ack
			ctx := context.Background()
			switch mutation {
			case "version":
				ack.Version = "other"
			case "source":
				ack.Consumption.Source.NodeName = "other-node"
			case "destination":
				ack.Consumption.Destination = "https://other.example.test/internal/v1/runtime/events"
			case "device":
				ack.Consumption.Device++
			case "inode":
				ack.Consumption.Inode++
			case "manifest":
				ack.Manifest = strings.Repeat("0", 64)
			case "seal":
				ack.Seal.Dropped++
			case "seal hash":
				ack.SealDigest = strings.Repeat("0", 64)
			case "chain":
				ack.Consumption.Progress.Chain = strings.Repeat("0", 64)
			case "records":
				ack.Consumption.Progress.Read++
			case "accounting":
				ack.Consumption.Progress.Dropped++
			}
			data, _ := json.Marshal(ack)
			switch mutation {
			case "noncanonical":
				data = append(data, '\n')
			case "unknown field":
				data = append([]byte(`{"unknown":1,`), data[1:]...)
			case "duplicate field":
				data = append([]byte(`{"version":"tetragon-consumption-ack-v1",`), data[1:]...)
			}
			if err := os.Chmod(file, 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, data, 0440); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(file, 0440); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "wrong mode":
				if err := os.Chmod(file, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				outside := filepath.Join(t.TempDir(), "receipt")
				if err := os.Rename(file, outside); err != nil {
					t.Fatal(err)
				}
				var err error
				if mutation == "symlink" {
					err = os.Symlink(outside, file)
				} else {
					err = os.Link(outside, file)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "changed chunk":
				chunk := filepath.Join(fixture.reader.root.Name(), "chunk-0000000001.jsonl")
				if err := os.Chmod(chunk, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(chunk, []byte("changed"), 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(chunk, 0440); err != nil {
					t.Fatal(err)
				}
			case "missing seal":
				if err := os.Remove(filepath.Join(fixture.reader.root.Name(), "closed.json")); err != nil {
					t.Fatal(err)
				}
			case "active target":
				fixture.generation.spool.active = fixture.generation
			case "closed spool":
				fixture.generation.spool.Close()
			case "closed receipts":
				fixture.receipts.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before, statErr := os.Lstat(file)
			_, found, err := fixture.generation.spool.VerifyAcknowledgment(ctx, fixture.receipts, fixture.reader.Source(), "https://runtime.example.test/internal/v1/runtime/events")
			if mutation == "missing" {
				if err != nil || found {
					t.Fatal("missing receipt not distinguished", err)
				}
			} else if err == nil || found {
				t.Fatal("contradictory receipt accepted", mutation, err)
			}
			after, afterErr := os.Lstat(file)
			if statErr == nil && (afterErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode()) {
				t.Fatal("failed validation changed receipt")
			}
		})
	}
}
