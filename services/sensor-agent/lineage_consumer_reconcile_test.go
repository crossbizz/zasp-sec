package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func TestLineageConsumerControllerContinuesAfterCanceledUpload(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	for index := 1; index <= 2; index++ {
		source := fixture.reader.Source()
		source.GenerationID = fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)
		source.NodeUID = source.GenerationID
		generation, err := fixture.generation.spool.Create(context.Background(), source)
		if err != nil {
			t.Fatal(err)
		}
		line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
		if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
			t.Fatal(err)
		}
		if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
			t.Fatal(err)
		}
		generation.Close()
	}
	for index := 1; index <= 2; index++ {
		ctx, cancel := context.WithCancel(context.Background())
		requests := 0
		client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
			BaseURL: "https://runtime.example.test", EnrollmentBinding: config.EnrollmentBinding,
			Now:   func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) },
			Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil },
			Do: func(request *http.Request) (*http.Response, error) {
				requests++
				raw, err := io.ReadAll(request.Body)
				if err != nil || !strings.Contains(string(raw), fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)) {
					t.Error("tick retried a stalled generation before the next source", index, err)
				}
				cancel()
				return nil, context.Canceled
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := slots.ReconcileConsumer(ctx, client, 16)
		cancel()
		if err == nil || requests != 1 || progress.Submitted != 0 {
			t.Fatal(progress, requests, err)
		}
	}
}

func lineageControllerClient(t *testing.T, enrollment string, requests *int) *sensoradapter.ProductionClient {
	t.Helper()
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: enrollment,
		Now:   func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) },
		Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil },
		Do: func(*http.Request) (*http.Response, error) {
			*requests++
			return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewBufferString(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestLineageConsumerControllerDiscoversProcessesAndReleases(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	ctx := context.Background()
	for index := 1; index <= 2; index++ {
		source := fixture.reader.Source()
		source.GenerationID = fmt.Sprintf("%08x-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)
		generation, err := fixture.generation.spool.Create(ctx, source)
		if err != nil {
			t.Fatal(err)
		}
		line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
		for chunk := 0; chunk < 2; chunk++ {
			if _, err := generation.Append(ctx, [][]byte{line}); err != nil {
				t.Fatal(err)
			}
		}
		if err := generation.Seal(ctx, "shutdown", 0, 0); err != nil {
			t.Fatal(err)
		}
		generation.Close()
	}
	work, err := slots.ListConsumerWork(ctx)
	if err != nil || len(work) != 3 {
		t.Fatal("automatic discovery", work, err)
	}
	if entries, _ := os.ReadDir(path); len(entries) != 0 {
		t.Fatal("listing wrote consumer state")
	}
	requests := 0
	client := lineageControllerClient(t, config.EnrollmentBinding, &requests)
	first, err := slots.ReconcileConsumer(ctx, client, 16)
	if err != nil || first.SourcesProcessed != 3 || first.Acknowledged != 1 || first.Read != 2 || requests != 2 {
		t.Fatal("bounded first tick", first, requests, err)
	}
	second, err := slots.ReconcileConsumer(ctx, client, 16)
	if err != nil || second.Acknowledged != 3 || second.Read != 2 || requests != 4 {
		t.Fatal("resume next chunk", second, requests, err)
	}
	producer := lineageProducerConfig{EnrollmentBinding: config.EnrollmentBinding, Destination: config.Destination, ConsumerUID: uint32(os.Geteuid())}
	if _, err := fixture.generation.spool.ReconcileProducer(ctx, fixture.receipts, producer); err != nil {
		t.Fatal(err)
	}
	retired, err := slots.ReconcileConsumer(ctx, nil, 16)
	if err != nil || retired.Retired != 3 || retired.Released != 0 {
		t.Fatal("credential-free retirement", retired, err)
	}
	if _, err := fixture.generation.spool.ReconcileProducer(ctx, fixture.receipts, producer); err != nil {
		t.Fatal(err)
	}
	released, err := slots.ReconcileConsumer(ctx, nil, 16)
	if err != nil || released.Released != 3 {
		t.Fatal("credential-free release", released, err)
	}
	if work, err := slots.ListConsumerWork(ctx); err != nil || len(work) != 0 {
		t.Fatal("remaining work", work, err)
	}
	if entries, _ := os.ReadDir(path); len(entries) != 5 {
		t.Fatal("expected coverage record, controller and three cursor locks", len(entries))
	}
}

func TestLineageConsumerControllerRetiresWithoutAClient(t *testing.T) {
	fixture, slots, _ := lineageRetiringSlotFixture(t)
	ctx := context.Background()
	progress, err := slots.ReconcileConsumer(ctx, nil, 16)
	if err != nil || progress.Retired != 1 || progress.Waiting != 1 {
		t.Fatal(progress, err)
	}
	if done, err := fixture.generation.spool.CollectCompletion(ctx, fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
		t.Fatal(err)
	}
	progress, err = slots.ReconcileConsumer(ctx, nil, 16)
	if err != nil || progress.Released != 1 {
		t.Fatal(progress, err)
	}
}
