package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPreciseChunkRestartRetainsEnvelopeAndProcessCache(t *testing.T) {
	reads, tokens := 0, 0
	first := chunkFixture(1, string(preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.123456789Z", false)))
	second := chunkFixture(2, string(preciseProviderLine(t, "process_kprobe", "2026-08-20T12:00:01.987654321Z", "2026-08-20T12:00:00.123456789Z", true)))
	var bodies [][]byte
	var auth []string
	config := chunkConfig(t, func(_ context.Context, sequence int) (ImmutableChunk, bool, error) {
		reads++
		if sequence == 1 {
			return first, true, nil
		}
		if sequence == 2 {
			return second, true, nil
		}
		t.Fatal("unexpected source read")
		return ImmutableChunk{}, false, nil
	}, func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("X-Zasp-Runtime-Schema") != "runtime-event-enrollment-v2" || request.Header.Get("X-Zasp-Expected-Enrollment") != strings.Repeat("a", 64) {
			t.Fatal("wrong precise transport constraints")
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		auth = append(auth, request.Header.Get("Authorization"))
		if len(bodies) == 1 {
			return nil, ErrClientRetryable
		}
		return envelopeAccepted(), nil
	})
	config.Source.Profile = "tetragon-local-stream-v3"
	credential := envelopeCredential(t, 11)
	config.Client.token = func() ([]byte, error) {
		tokens++
		raw, err := os.ReadFile(config.CursorPath)
		var saved struct {
			Version string `json:"version"`
			Pending *struct {
				Envelope *PreciseRuntimeEnvelope `json:"envelope"`
			} `json:"pending"`
		}
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Version != "tetragon-chunk-checkpoint-v2" || saved.Pending == nil || saved.Pending.Envelope == nil {
			t.Fatal("upload before durable precise checkpoint")
		}
		return []byte(credential), nil
	}
	p, err := NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ProcessAvailable(context.Background()); err != ErrClientRetryable {
		t.Fatal("uncertain send", err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	credential = envelopeCredential(t, 12)
	p, err = NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if result, err := p.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatal("restart", result, err)
	}
	if reads != 1 || tokens != 2 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || auth[0] == auth[1] {
		t.Fatal("restart reread source or changed frozen request")
	}
	if result, err := p.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatal("restored cache file event", result, err)
	}
	var body struct {
		Events []PreciseRuntimeEvent `json:"events"`
	}
	if err := json.Unmarshal(bodies[2], &body); err != nil || len(body.Events) != 1 || body.Events[0].Class != "file" || body.Events[0].ObservedLineage.ProcessStartTime != "2026-08-20T12:00:00.123456789Z" || body.Events[0].ObservedLineage.SourceEventTime != "2026-08-20T12:00:01.987654321Z" {
		t.Fatal("restored process precision lost", err)
	}
	progress, durable, err := p.Committed()
	if err != nil || !durable || progress.NextSequence != 3 || progress.Submitted != 2 {
		t.Fatal("durable progress", progress, durable, err)
	}
}

func TestPreciseChunkPersistenceFailureBlocksUpload(t *testing.T) {
	reads, uploads := 0, 0
	chunk := chunkFixture(1, string(preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.123456789Z", false)))
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { reads++; return chunk, true, nil }, func(*http.Request) (*http.Response, error) { uploads++; return envelopeAccepted(), nil })
	config.Source.Profile = "tetragon-local-stream-v3"
	allowed := false
	config.Client.token = func() ([]byte, error) {
		if !allowed {
			t.Error("failed persistence reached credentials")
		}
		return []byte(envelopeCredential(t, 11)), nil
	}
	p, err := NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.writeCheckpoint = func(*os.Root, string, []byte) error { return ErrStream }
	if _, err := p.ProcessAvailable(context.Background()); err != ErrStream || uploads != 0 {
		t.Fatal("failed persistence uploaded", err, uploads)
	}
	p.writeCheckpoint = writeCheckpointBytes
	allowed = true
	if result, err := p.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || reads != 1 || uploads != 1 {
		t.Fatal("pending retry lost state", result, err, reads, uploads)
	}
}

func TestPreciseChunkPreparationFailureSurvivesRestart(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "clock panic", true: "expired"}[expired], func(t *testing.T) {
			reads, uploads := 0, 0
			chunk := chunkFixture(1, string(preciseProviderLine(t, "process_exec", "2026-08-20T12:00:00.123999999Z", "2026-08-20T12:00:00.123456789Z", false)))
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { reads++; return chunk, true, nil }, func(*http.Request) (*http.Response, error) { uploads++; return envelopeAccepted(), nil })
			config.Source.Profile = "tetragon-local-stream-v3"
			config.Client.now = func() time.Time {
				if !expired {
					panic("clock unavailable")
				}
				return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
			}
			want := ErrClientRetryable
			if expired {
				want = ErrEnvelopeExpired
			}
			p, err := NewPreciseChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.ProcessAvailable(context.Background()); err != want {
				t.Fatal("preparation", err)
			}
			p.Close()
			before, err := os.ReadFile(config.CursorPath)
			if err != nil {
				t.Fatal(err)
			}
			var saved chunkCheckpointOf[PreciseRuntimeEvent]
			if json.Unmarshal(before, &saved) != nil || saved.Pending == nil || saved.Pending.Envelope != nil || len(saved.Pending.Events) != 1 {
				t.Fatal("failed preparation did not save precise events")
			}
			p, err = NewPreciseChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if _, err := p.ProcessAvailable(context.Background()); err != want || reads != 1 || uploads != 0 {
				t.Fatal("restart lost pending preparation", err, reads, uploads)
			}
			after, err := os.ReadFile(config.CursorPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed preparation changed saved event", err)
			}
			if !expired {
				config.Client.now = func() time.Time { return time.Date(2026, 8, 20, 12, 0, 1, 0, time.UTC) }
				if result, err := p.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || reads != 1 || uploads != 1 {
					t.Fatal("clock recovery lost pending event", result, err)
				}
			}
		})
	}
}

func TestPreciseChunkAllDroppedCommitsWithoutCredentials(t *testing.T) {
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
		return chunkFixture(1, `{"node_name":"node-a","unsupported":true}`), true, nil
	}, func(*http.Request) (*http.Response, error) { t.Fatal("all dropped batch uploaded"); return nil, nil })
	config.Source.Profile = "tetragon-local-stream-v3"
	config.Client.token = func() ([]byte, error) { t.Fatal("all dropped batch read token"); return nil, nil }
	p, err := NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := p.ProcessAvailable(context.Background()); err != nil || result.Read != 1 || result.Dropped != 1 || result.Submitted != 0 {
		t.Fatal("all dropped", result, err)
	}
	p.Close()
	p, err = NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	progress, durable, err := p.Committed()
	if err != nil || !durable || progress.NextSequence != 2 || progress.Dropped != 1 || progress.Submitted != 0 {
		t.Fatal("dropped accounting not durable", progress, durable, err)
	}
}

func TestPreciseChunkRefusesOtherGenerationCheckpoint(t *testing.T) {
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { return ImmutableChunk{}, false, nil }, func(*http.Request) (*http.Response, error) {
		t.Fatal("mismatched checkpoint uploaded")
		return nil, nil
	})
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.Close()
	old, err := os.ReadFile(config.CursorPath)
	if err != nil {
		t.Fatal(err)
	}
	config.Source.Profile = "tetragon-local-stream-v3"
	precise, err := NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := precise.ProcessAvailable(context.Background()); err != ErrStream {
		t.Fatal("V3 adopted legacy checkpoint", err)
	}
	precise.Close()
	current, err := os.ReadFile(config.CursorPath)
	if err != nil || !bytes.Equal(old, current) {
		t.Fatal("refusal changed old checkpoint", err)
	}
	// Use a distinct cursor for the V3 generation, then try old and changed-boot
	// configurations against its actual serialized checkpoint.
	config.CursorPath += ".precise"
	precise, err = NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := precise.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	precise.Close()
	config.Source.Profile = "tetragon-local-stream-v1"
	p, err = NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ProcessAvailable(context.Background()); err != ErrStream {
		t.Fatal("V1 adopted precise checkpoint", err)
	}
	p.Close()
	config.Source.Profile = "tetragon-local-stream-v3"
	config.Source.BootID = "12345678-1234-1234-1234-123456789099"
	precise, err = NewPreciseChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer precise.Close()
	if _, err := precise.ProcessAvailable(context.Background()); err != ErrStream {
		t.Fatal("changed boot adopted checkpoint", err)
	}
}
