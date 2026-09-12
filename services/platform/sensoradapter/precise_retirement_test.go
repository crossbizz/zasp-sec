package sensoradapter

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"
)

func preciseRetirementFixture(t *testing.T) (ChunkProcessorConfig, ChunkRetirementConfig) {
	t.Helper()
	chunk := chunkFixture(1, string(preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.123456789Z", false)))
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { return chunk, true, nil }, func(*http.Request) (*http.Response, error) { return envelopeAccepted(), nil })
	config.Source.Profile = "tetragon-local-stream-v3"
	p, err := NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	proof, err := p.VerifyConsumed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return config, ChunkRetirementConfig{CursorPath: config.CursorPath, Source: config.Source, Destination: proof.Destination, Consumption: proof, MaximumProcesses: config.MaximumProcesses, DisjointRoots: []*os.Root{config.SpoolRoot}, Authorize: func(context.Context) error { return nil }}
}

func TestPreciseRetirementRequiresOwnContractAndRetainsSlotLock(t *testing.T) {
	config, retirement := preciseRetirementFixture(t)
	if err := VerifyConsumptionSource(context.Background(), config.SourceRoot, config.Source, retirement.Destination, retirement.Consumption, config.ReadChunk); err != ErrStream {
		t.Fatal("V1 accepted precise source proof", err)
	}
	if err := VerifyPreciseConsumptionSource(context.Background(), config.SourceRoot, config.Source, retirement.Destination, retirement.Consumption, config.ReadChunk); err != nil {
		t.Fatal("precise source proof rejected", err)
	}
	if err := RetireConsumedCheckpoint(context.Background(), retirement); err != ErrStream {
		t.Fatal("V1 retired precise checkpoint", err)
	}
	lock, err := os.Lstat(config.CursorPath + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	authorizations := 0
	retirement.Authorize = func(context.Context) error { authorizations++; return nil }
	for i := 0; i < 2; i++ {
		if err := RetirePreciseConsumedCheckpoint(context.Background(), retirement); err != nil {
			t.Fatal("precise retirement", err)
		}
	}
	if _, err := os.Lstat(config.CursorPath); !os.IsNotExist(err) {
		t.Fatal("checkpoint remains", err)
	}
	after, err := os.Lstat(config.CursorPath + ".lock")
	if err != nil || !os.SameFile(lock, after) || authorizations < 2 {
		t.Fatal("slot lock changed or absent retry skipped authority", err)
	}
	_, legacy := chunkRetirementFixture(t, false)
	if err := RetirePreciseConsumedCheckpoint(context.Background(), legacy); err != ErrStream {
		t.Fatal("precise retirement adopted V1", err)
	}
}

func TestPreciseRetirementRejectsMismatchAndDenialWithoutDeletion(t *testing.T) {
	for _, kind := range []string{"denied", "source", "progress", "version", "pending", "live lock"} {
		t.Run(kind, func(t *testing.T) {
			config, retirement := preciseRetirementFixture(t)
			before, err := os.ReadFile(config.CursorPath)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "denied":
				retirement.Authorize = func(context.Context) error { return ErrStream }
			case "source":
				retirement.Source.BootID = "12345678-1234-1234-1234-123456789099"
			case "progress":
				retirement.Consumption.Progress.Submitted = 0
			case "version":
				before = bytes.Replace(before, []byte("tetragon-chunk-checkpoint-v2"), []byte("tetragon-chunk-checkpoint-v1"), 1)
			case "pending":
				before = bytes.Replace(before, []byte(`"cache":`), []byte(`"pending":{},"cache":`), 1)
			case "live lock":
				p, err := NewPreciseChunkProcessor(config)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
			}
			if kind == "version" || kind == "pending" {
				if err := os.WriteFile(config.CursorPath, before, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := RetirePreciseConsumedCheckpoint(context.Background(), retirement); err != ErrStream {
				t.Fatal("unsafe precise retirement accepted", err)
			}
			after, err := os.ReadFile(config.CursorPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected retirement changed bytes", err)
			}
		})
	}
}
