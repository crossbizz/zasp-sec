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
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func acknowledgeReclaimGeneration(t *testing.T, generation *lineageSpoolGeneration) *lineageReceiptReader {
	t.Helper()
	ctx := context.Background()
	if err := generation.Seal(ctx, "shutdown", 0, 0); err != nil {
		t.Fatal(err)
	}
	reader, err := newLineageSpoolReader(generation.root.Name(), generation.source.EnrollmentBinding, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: generation.source.EnrollmentBinding, Now: func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) }, Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil }, Do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	store, path := acknowledgmentFixture(t)
	consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, filepath.Join(t.TempDir(), "cursor.json"), 16, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	for {
		result, err := consumer.ProcessAvailable(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if result.Idle {
			break
		}
	}
	if err := consumer.Acknowledge(ctx); err != nil {
		t.Fatal(err)
	}
	generation.Close()
	receipts, err := newLineageReceiptReader(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { receipts.Close() })
	return receipts
}

func TestLineageReclaimBoundsCompletionMarkersAndFreesSourceSlots(t *testing.T) {
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	for index := 0; index <= lineageSpoolSlots; index++ {
		source := lineageSpoolSource()
		source.GenerationID = fmt.Sprintf("%08d-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)
		generation, err := spool.Create(context.Background(), source)
		if err != nil {
			t.Fatal("source slot wasn't reusable", err)
		}
		receipts := acknowledgeReclaimGeneration(t, generation)
		request := lineageReclaimRequest{Source: source, ConsumerUID: uint32(os.Geteuid()), Destination: "https://runtime.example.test/internal/v1/runtime/events"}
		complete, err := spool.ReclaimAcknowledged(context.Background(), receipts, request)
		if index < lineageSpoolSlots {
			if err != nil || !complete {
				t.Fatal(err)
			}
		} else {
			if err != errLineageSpoolFull || complete {
				t.Fatal("ninth completion marker accepted", err)
			}
			if _, err := os.Stat(filepath.Join(spool.root.Name(), "generation-"+source.GenerationID, "closed.json")); err != nil {
				t.Fatal("quota deleted unreclaimed source", err)
			}
		}
	}
	inventory, err := spool.reclaimInventory()
	if err != nil || len(inventory.markers) != 8 || len(inventory.directories) != 1 || inventory.pending {
		t.Fatal("reclamation quotas drifted", err)
	}
}

func TestLineageReclaimMaximumChunkInventory(t *testing.T) {
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	generation, err := spool.Create(context.Background(), lineageSpoolSource())
	if err != nil {
		t.Fatal(err)
	}
	line, err := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < lineageSpoolChunks; index++ {
		if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
			t.Fatal(err)
		}
	}
	source := generation.source
	receipts := acknowledgeReclaimGeneration(t, generation)
	if complete, err := spool.ReclaimAcknowledged(context.Background(), receipts, lineageReclaimRequest{Source: source, ConsumerUID: uint32(os.Geteuid()), Destination: "https://runtime.example.test/internal/v1/runtime/events"}); err != nil || !complete {
		t.Fatal("maximal inventory not reclaimed", err)
	}
	marker, err := spool.readReclaimMarker("reclaim-" + source.GenerationID + ".json")
	if err != nil {
		t.Fatal(err)
	}
	defer marker.file.Close()
	if !marker.record.Complete || len(marker.record.Files) != 130 || len(marker.raw) > lineageReclaimBytes {
		t.Fatal("maximal completion record not bounded")
	}
}
