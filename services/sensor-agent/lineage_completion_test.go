package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func lineageCompletionFixture(t *testing.T, empty bool) (lineageReceiptFixtureState, *lineageAcknowledgments, *lineageCompletionReader) {
	t.Helper()
	fixture := lineageReceiptFixture(t, empty)
	spool := fixture.generation.spool
	if complete, err := spool.ReclaimAcknowledged(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !complete {
		t.Fatal(err)
	}
	if err := os.Chmod(spool.root.Name(), 0750); err != nil {
		t.Fatal(err)
	}
	reader, err := newLineageCompletionReader(spool.root.Name(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	store, err := newLineageAcknowledgments(fixture.ackPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return fixture, store, reader
}

func TestLineageCompletionChecksACKOutputIsolationBeforeTakingWriterLock(t *testing.T) {
	for _, overlap := range []string{"cursor", "protected input"} {
		t.Run(overlap, func(t *testing.T) {
			fixture, store, reader := lineageCompletionFixture(t, false)
			cursor := fixture.cursor
			var protected []sensoradapter.PinnedInput
			if overlap == "cursor" {
				cursor = filepath.Join(fixture.ackPath, "cursor.json")
			} else {
				protected = []sensoradapter.PinnedInput{{Parent: store.root, Name: "token"}}
			}
			complete, err := store.RetireCheckpoint(context.Background(), reader, reclaimFixtureRequest(fixture), cursor, 16, protected)
			if err == nil || complete || store.lock != nil {
				t.Fatal("overlapping output acquired writer ownership", err)
			}
			if _, err := os.Lstat(fixture.cursor); err != nil {
				t.Fatal("input changed", err)
			}
		})
	}
}

func TestLineageCompletionRetiresCheckpointWithExactProducerAndConsumerEvidence(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "record", true: "empty"}[empty], func(t *testing.T) {
			fixture, store, reader := lineageCompletionFixture(t, empty)
			request := reclaimFixtureRequest(fixture)
			ackPath := filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
			completionPath := filepath.Join(fixture.generation.spool.root.Name(), "reclaim-"+request.Source.GenerationID+".json")
			ackBefore, _ := os.ReadFile(ackPath)
			completionBefore, _ := os.ReadFile(completionPath)
			for retry := 0; retry < 2; retry++ {
				complete, err := store.RetireCheckpoint(context.Background(), reader, request, fixture.cursor, 16, nil)
				if err != nil || !complete {
					t.Fatal("authenticated retirement failed", err)
				}
				if _, err := os.Lstat(fixture.cursor); !os.IsNotExist(err) {
					t.Fatal("checkpoint remains", err)
				}
			}
			ackAfter, _ := os.ReadFile(ackPath)
			completionAfter, _ := os.ReadFile(completionPath)
			if !bytes.Equal(ackBefore, ackAfter) || !bytes.Equal(completionBefore, completionAfter) {
				t.Fatal("retirement changed handshake evidence")
			}
		})
	}
}

func TestLineageCompletionRejectsInvalidAuthorityWithoutDeletingCheckpoint(t *testing.T) {
	for _, mutation := range []string{"missing", "not complete", "wrong source", "wrong destination", "wrong consumer", "wrong spool", "unknown field", "source returned", "tombstone returned", "missing ack", "different ack", "completion mode", "completion symlink", "completion hardlink", "completion replaced owner", "closed reader", "closed store", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, store, reader := lineageCompletionFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			spoolPath := fixture.generation.spool.root.Name()
			marker := filepath.Join(spoolPath, "reclaim-"+request.Source.GenerationID+".json")
			ackPath := filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
			raw, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			var record lineageReclaimRecord
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("fixture record")
			}
			ctx := context.Background()
			rewrite := false
			switch mutation {
			case "missing":
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			case "not complete":
				record.Complete = false
				rewrite = true
			case "wrong source":
				request.Source.NodeName = "different-node"
			case "wrong destination":
				request.Destination = "https://different.example.test/internal/v1/runtime/events"
			case "wrong consumer":
				request.ConsumerUID++
			case "wrong spool":
				record.SpoolInode++
				rewrite = true
			case "unknown field":
				raw = append([]byte(`{"other":true,`), raw[1:]...)
				rewrite = true
			case "source returned", "tombstone returned":
				name := "generation-"
				if mutation == "tombstone returned" {
					name = ".reclaim-"
				}
				if err := os.Mkdir(filepath.Join(spoolPath, name+request.Source.GenerationID), 0750); err != nil {
					t.Fatal(err)
				}
			case "missing ack":
				if err := os.Remove(ackPath); err != nil {
					t.Fatal(err)
				}
			case "different ack":
				ack := record.Ack
				ack.Seal.Filtered++
				data, _ := json.Marshal(ack)
				if err := os.Chmod(ackPath, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(ackPath, data, 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(ackPath, 0440); err != nil {
					t.Fatal(err)
				}
			case "completion mode":
				if err := os.Chmod(marker, 0640); err != nil {
					t.Fatal(err)
				}
			case "completion symlink", "completion hardlink":
				if err := os.Rename(marker, marker+".held"); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if mutation == "completion symlink" {
					link = os.Symlink
				}
				if err := link(marker+".held", marker); err != nil {
					t.Fatal(err)
				}
			case "completion replaced owner":
				reader.Close()
				reader, err = newLineageCompletionReader(spoolPath, uint32(os.Getuid())+1)
				if err != nil {
					return
				}
				defer reader.Close()
			case "closed reader":
				reader.Close()
			case "closed store":
				store.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if rewrite {
				if mutation != "unknown field" {
					raw, _ = json.Marshal(record)
				}
				if err := os.Chmod(marker, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, raw, 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(marker, 0440); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(fixture.cursor)
			if err != nil {
				t.Fatal(err)
			}
			complete, err := store.RetireCheckpoint(ctx, reader, request, fixture.cursor, 16, nil)
			if complete || mutation != "missing" && err == nil || mutation == "missing" && err != nil {
				t.Fatal("invalid authority outcome", complete, err)
			}
			after, err := os.ReadFile(fixture.cursor)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid authority deleted checkpoint", err)
			}
		})
	}
}
