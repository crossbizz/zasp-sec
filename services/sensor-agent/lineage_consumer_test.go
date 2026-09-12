package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

func lineageConsumerFixture(t *testing.T, do func(*http.Request) (*http.Response, error), profiles ...string) (*lineageSpoolGeneration, *lineageSpoolReader, *sensoradapter.ProductionClient, string) {
	t.Helper()
	generation, path := lineageSpoolReaderFixture(t, profiles...)
	reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: generation.source.EnrollmentBinding,
		Now:   func() time.Time { return time.Date(2026, 9, 10, 12, 0, 1, 0, time.UTC) },
		Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil }, Do: do,
	})
	if err != nil {
		t.Fatal(err)
	}
	return generation, reader, client, filepath.Join(t.TempDir(), "cursor.json")
}

func TestLineageConsumerBridgesOwnedChunksAndReplaysAfterRestart(t *testing.T) {
	var bodies [][]byte
	generation, reader, client, cursor := lineageConsumerFixture(t, func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			return nil, errors.New("lost response")
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewBufferString(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	})
	line, err := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
		t.Fatal(err)
	}
	consumer, err := newLineageChunkConsumer(reader, client, cursor, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.ProcessAvailable(context.Background()); err != sensoradapter.ErrClientRetryable {
		t.Fatalf("lost response: %v", err)
	}
	consumer.Close()
	consumer, err = newLineageChunkConsumer(reader, client, cursor, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	result, err := consumer.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || !bytes.Contains(bodies[0], []byte(`"boot_id":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"`)) {
		t.Fatalf("source replay: %+v %v", result, err)
	}
	progress, durable, err := consumer.Committed()
	if err != nil || !durable || progress.NextSequence != 2 {
		t.Fatal("source commit lost", err)
	}
	if _, found, err := reader.ReadSeal(); err != nil || !found {
		t.Fatal("consumer closed borrowed reader or changed seal", err)
	}
	if result, err := consumer.ProcessAvailable(context.Background()); err != nil || !result.Idle || len(bodies) != 2 {
		t.Fatal("committed generation uploaded again", err)
	}
}

func TestLineageConsumerRejectsRevokedAdmissionBeforePendingReplay(t *testing.T) {
	for _, mutation := range []string{"closed reader", "replaced manifest", "replaced generation", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			calls := 0
			generation, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("offline") })
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
				t.Fatal(err)
			}
			consumer, err := newLineageChunkConsumer(reader, client, cursor, 16, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer consumer.Close()
			if _, err := consumer.ProcessAvailable(context.Background()); err != sensoradapter.ErrClientRetryable {
				t.Fatal(err)
			}
			before, err := os.ReadFile(cursor)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			switch mutation {
			case "closed reader":
				reader.Close()
			case "replaced manifest":
				path := filepath.Join(reader.root.Name(), "manifest.json")
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, reader.manifestBytes, 0440); err != nil {
					t.Fatal(err)
				}
			case "replaced generation":
				if err := os.Rename(reader.root.Name(), reader.root.Name()+".old"); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := consumer.ProcessAvailable(ctx); err == nil {
				t.Fatal("invalid admission consumed pending")
			}
			after, err := os.ReadFile(cursor)
			if err != nil || !bytes.Equal(before, after) || calls != 1 {
				t.Fatal("invalid admission changed checkpoint or uploaded")
			}
		})
	}
}

func TestLineageConsumerRejectsUnsafeConstructionWithoutClosingReader(t *testing.T) {
	_, reader, client, cursor := lineageConsumerFixture(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected upload"); return nil, nil })
	for _, path := range []string{filepath.Join(reader.root.Name(), "cursor"), filepath.Join(reader.parent.Name(), "cursor")} {
		consumer, err := newLineageChunkConsumer(reader, client, path, 16, nil)
		if err == nil {
			consumer.Close()
			t.Fatal("producer cursor accepted")
		}
	}
	consumer, err := newLineageChunkConsumer(reader, client, cursor, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.ReadChunk(1); err != nil {
		t.Fatal("borrowed reader closed", err)
	}
	if _, err := consumer.ProcessAvailable(context.Background()); err == nil {
		t.Fatal("closed consumer ran")
	}
}

func TestLineageConsumerHoldsReaderLifetimeUntilUploadReturns(t *testing.T) {
	entered := make(chan struct{})
	generation, reader, client, cursor := lineageConsumerFixture(t, func(request *http.Request) (*http.Response, error) {
		close(entered)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	consumer, err := newLineageChunkConsumer(reader, client, cursor, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := consumer.ProcessAvailable(ctx); finished <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("upload did not start")
	}
	if reader.mu.TryLock() {
		reader.mu.Unlock()
		t.Error("borrowed reader can close during pending upload")
	}
	closed := make(chan error, 1)
	go func() { closed <- reader.Close() }()
	cancel()
	select {
	case err := <-finished:
		if err != sensoradapter.ErrClientRetryable {
			t.Error("canceled upload result", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled consumer did not join")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Error("reader close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reader lifetime remained locked")
	}
}
