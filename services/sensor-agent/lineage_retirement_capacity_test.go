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

func TestLineageRetirementReusesBoundedSlotsAcrossTwentyFourGenerations(t *testing.T) {
	fixture, store, completion := lineageCompletionFixture(t, false)
	spool := fixture.generation.spool
	request := reclaimFixtureRequest(fixture)
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: request.Source.EnrollmentBinding, Now: func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) }, Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil }, Do: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	initialLock, err := os.Lstat(fixture.cursor + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for index := 0; index < 24; index++ {
		if index > 0 {
			request.Source.GenerationID = fmt.Sprintf("%08d-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)
			generation, err := spool.Create(ctx, request.Source)
			if err != nil {
				t.Fatal("source quota not reusable", index, err)
			}
			if index%2 != 0 {
				line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
				if _, err := generation.Append(ctx, [][]byte{line}); err != nil {
					t.Fatal(err)
				}
			}
			if err := generation.Seal(ctx, "shutdown", 0, 0); err != nil {
				t.Fatal(err)
			}
			reader, err := newLineageSpoolReader(generation.root.Name(), request.Source.EnrollmentBinding, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			consumer, err := newAcknowledgingLineageChunkConsumer(reader, client, fixture.cursor, 16, nil, store)
			if err != nil {
				reader.Close()
				t.Fatal(err)
			}
			if _, err := consumer.ProcessAvailable(ctx); err != nil {
				t.Fatal(err)
			}
			if err := consumer.Acknowledge(ctx); err != nil {
				t.Fatal(err)
			}
			consumer.Close()
			reader.Close()
			generation.Close()
			if complete, err := spool.ReclaimAcknowledged(ctx, fixture.receipts, request); err != nil || !complete {
				t.Fatal(err)
			}
		}
		if complete, err := store.RetireAcknowledgment(ctx, completion, request, fixture.cursor, 16, nil); err != nil || !complete {
			t.Fatal("ACK quota not reusable", index, err)
		}
		if complete, err := spool.CollectCompletion(ctx, fixture.receipts, request); err != nil || !complete {
			t.Fatal(err)
		}
		if complete, err := store.ForgetRetirement(ctx, completion, request); err != nil || !complete {
			t.Fatal(err)
		}
		for _, path := range []string{spool.root.Name(), fixture.ackPath, filepath.Dir(fixture.cursor)} {
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 1 {
				t.Fatal("state grew across generations", index, path, err)
			}
		}
		currentLock, err := os.Lstat(fixture.cursor + ".lock")
		if err != nil || !os.SameFile(initialLock, currentLock) {
			t.Fatal("cursor slot lock replaced", err)
		}
	}
}
