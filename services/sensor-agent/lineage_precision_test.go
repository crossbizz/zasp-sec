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
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/types"
)

func TestLineageConfiguredGenerationPreservesLegacyDefault(t *testing.T) {
	for _, selected := range []string{"", "tetragon-local-stream-v2"} {
		t.Run(selected, func(t *testing.T) {
			environment := lineageDaemonEnvironment()
			environment["ZASP_LINEAGE_SOURCE_PROFILE"] = selected
			config, err := loadLineageProducerDaemonConfig(func(key string) string { return environment[key] })
			if err != nil {
				t.Fatal(err)
			}
			boot, _ := fixtureBootReader(t)
			api := newLineageIdentityAPIFixture()
			socket, _, _ := startLineageGRPCFixture(t, "v1.7.0")
			endpoint, err := newLineageSocket(socket, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			generation, err := startConfiguredLineageGeneration(context.Background(), config, api, boot, endpoint, spool)
			if err != nil {
				t.Fatal(err)
			}
			defer generation.Close()
			if generation.Source().Profile != "tetragon-local-stream-v2" {
				t.Fatal("default producer activated precision")
			}
		})
	}
}

func TestLineagePrecisionOwnedStreamSpoolAndRetry(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	socket, server, events := startLineageGRPCFixture(t, "v1.7.0")
	endpoint, err := newLineageSocket(socket, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	spool, err := newLineageSpool(root, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	environment := lineageDaemonEnvironment()
	environment["ZASP_LINEAGE_SOURCE_PROFILE"] = "tetragon-local-stream-v3"
	config, err := loadLineageProducerDaemonConfig(func(key string) string { return environment[key] })
	if err != nil {
		t.Fatal(err)
	}
	generation, err := startConfiguredLineageGeneration(ctx, config, api, boot, endpoint, spool)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	source := generation.Source()
	if source.Profile != "tetragon-local-stream-v3" || source.BootID != fixtureHostBootID || api.nodeCalls != 4 {
		t.Fatal("precise source not admitted through owned identity checks", source, api.nodeCalls)
	}
	path := filepath.Join(root, "generation-"+source.GenerationID)
	manifest, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil || !bytes.Contains(manifest, []byte(`"record_format":"zasp-tetragon-record-v3"`)) {
		t.Fatal("V3 manifest not durable", err)
	}
	provider := lineageProviderFixture("exec")
	stamp := time.Date(2026, 9, 10, 12, 0, 0, 123999999, time.UTC)
	provider.Time = timestamppb.New(stamp)
	provider.GetProcessExec().Process.StartTime = timestamppb.New(time.Date(2026, 9, 10, 12, 0, 0, 123456789, time.UTC))
	done := make(chan lineagePumpResult, 1)
	go func() { result, _ := runLineagePump(ctx, generation, lineagePumpTestConfig(1)); done <- result }()
	events.events <- provider
	waitLineagePumpFile(t, filepath.Join(path, "chunk-0000000001.jsonl"))
	server.Stop()
	select {
	case result := <-done:
		if result.Records != 1 || !result.Sealed {
			t.Fatal("owned pump did not seal", result)
		}
	case <-ctx.Done():
		t.Fatal("pump did not terminate")
	}
	reader, err := newLineageSpoolReader(path, source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if reader.Source() != source {
		t.Fatal("reader changed source authority")
	}
	var bodies [][]byte
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: source.EnrollmentBinding, Now: func() time.Time { return stamp.Add(time.Second) }, Token: func() ([]byte, error) { return []byte(fixtureAgentToken()), nil }, Do: func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Zasp-Runtime-Schema") != "runtime-event-enrollment-v2" || request.Header.Get("X-Zasp-Expected-Enrollment") != source.EnrollmentBinding {
			t.Fatal("consumer chose legacy or unbound transport")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			return nil, sensoradapter.ErrClientRetryable
		}
		return &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{"Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(`{"batch_id":"pid_10000001-0000-4000-8000-000000000001"}`))}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	cursor := filepath.Join(t.TempDir(), "precise.json")
	consumer, err := newLineageChunkConsumer(reader, client, cursor, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.ProcessAvailable(ctx); err != sensoradapter.ErrClientRetryable {
		t.Fatal("uncertain precise upload", err)
	}
	consumer.Close()
	consumer, err = newLineageChunkConsumer(reader, client, cursor, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	if result, err := consumer.ProcessAvailable(ctx); err != nil || result.Submitted != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("durable precise retry", result, err)
	}
	var body struct {
		Events []sensoradapter.PreciseRuntimeEvent `json:"events"`
	}
	if err := json.Unmarshal(bodies[1], &body); err != nil || len(body.Events) != 1 || body.Events[0].ObservedLineage.SourceEventTime != "2026-09-10T12:00:00.123999999Z" || body.Events[0].ObservedLineage.ProcessStartTime != "2026-09-10T12:00:00.123456789Z" || body.Events[0].ObservedLineage.BootID != source.BootID {
		t.Fatal("owned precise lineage lost", err)
	}
}

func TestLineagePrecisionRejectsIdentityDriftBeforePublication(t *testing.T) {
	boot, _ := fixtureBootReader(t)
	api := newLineageIdentityAPIFixture()
	endpoint, _ := lineageGenerationFixture(t, func() { api.node.UID = types.UID("12345678-1234-1234-1234-123456789099") })
	root := t.TempDir()
	spool, err := newLineageSpool(root, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	generation, err := startPreciseLineageGeneration(context.Background(), "node-a", strings.Repeat("b", 64), api, boot, endpoint, spool)
	if err != errLineageGeneration || generation != nil || spool.active != nil {
		t.Fatal("identity drift admitted precise source", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "generation-") {
			t.Fatal("drift published generation")
		}
	}
	endpoint.mu.Lock()
	closed := endpoint.closed
	endpoint.mu.Unlock()
	if !closed {
		t.Fatal("failed precise startup retained owned endpoint")
	}
}
