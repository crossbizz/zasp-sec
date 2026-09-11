package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func reclaimFixtureRequest(fixture lineageReceiptFixtureState) lineageReclaimRequest {
	return lineageReclaimRequest{Source: fixture.reader.source, Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}
}

func TestLineageReclaimRemovesOnlyAcknowledgedClosedGeneration(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "record", true: "empty"}[empty], func(t *testing.T) {
			fixture := lineageReceiptFixture(t, empty)
			request := reclaimFixtureRequest(fixture)
			ackName := filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
			ackBefore, _ := os.ReadFile(ackName)
			cursorBefore, _ := os.ReadFile(fixture.cursor)
			if complete, err := fixture.generation.spool.ReclaimAcknowledged(context.Background(), fixture.receipts, request); err != nil || !complete {
				t.Fatal("acknowledged generation not reclaimed", err)
			}
			for _, name := range []string{"generation-" + request.Source.GenerationID, ".reclaim-" + request.Source.GenerationID} {
				if _, err := os.Lstat(filepath.Join(fixture.generation.spool.root.Name(), name)); !os.IsNotExist(err) {
					t.Fatal("source directory remains", err)
				}
			}
			marker := filepath.Join(fixture.generation.spool.root.Name(), "reclaim-"+request.Source.GenerationID+".json")
			data, err := os.ReadFile(marker)
			if err != nil || !bytes.Contains(data, []byte(`"complete":true`)) {
				t.Fatal("durable completion receipt missing", err)
			}
			if info, err := os.Lstat(marker); err != nil || !lineageOwnedRegular(info, uint32(os.Geteuid()), 0440) {
				t.Fatal("completion receipt ownership", err)
			}
			if complete, err := fixture.generation.spool.ReclaimAcknowledged(context.Background(), nil, request); err != nil || !complete {
				t.Fatal("completed retry required consumer state", err)
			}
			ackAfter, _ := os.ReadFile(ackName)
			cursorAfter, _ := os.ReadFile(fixture.cursor)
			if !bytes.Equal(ackBefore, ackAfter) || !bytes.Equal(cursorBefore, cursorAfter) {
				t.Fatal("producer changed consumer state")
			}
			if generation, err := fixture.generation.spool.Create(context.Background(), request.Source); err == nil {
				generation.Close()
				t.Fatal("reclaimed UUID reused")
			}
			next := request.Source
			next.GenerationID = "11111111-1111-4111-8111-111111111111"
			generation, err := fixture.generation.spool.Create(context.Background(), next)
			if err != nil {
				t.Fatal("source slot not reusable", err)
			}
			generation.Close()
		})
	}
}

func TestLineageReclaimDoesNotMutateWithoutFreshMatchingAcknowledgment(t *testing.T) {
	for _, mutation := range []string{"missing receipt", "changed receipt", "wrong source", "wrong destination", "wrong issuer", "active target", "canceled", "nil receipts"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			ctx := context.Background()
			receipts := fixture.receipts
			switch mutation {
			case "missing receipt":
				if err := os.Remove(filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")); err != nil {
					t.Fatal(err)
				}
			case "changed receipt":
				file := filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
				if err := os.Chmod(file, 0640); err != nil {
					t.Fatal(err)
				}
			case "wrong source":
				request.Source.NodeName = "other-node"
			case "wrong destination":
				request.Destination = "https://other.example.test/internal/v1/runtime/events"
			case "wrong issuer":
				request.ConsumerUID++
			case "active target":
				fixture.generation.spool.active = fixture.generation
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil receipts":
				receipts = nil
			}
			complete, err := fixture.generation.spool.ReclaimAcknowledged(ctx, receipts, request)
			if complete || (mutation == "missing receipt" && err != nil) || (mutation != "missing receipt" && err == nil) {
				t.Fatal("invalid reclaim outcome", complete, err)
			}
			if _, found, err := fixture.reader.ReadSeal(); err != nil || !found {
				t.Fatal("unacknowledged source changed", err)
			}
			entries, err := os.ReadDir(fixture.generation.spool.root.Name())
			if err != nil || len(entries) != 2 {
				t.Fatal("failed proof wrote intent", err)
			}
		})
	}
}
