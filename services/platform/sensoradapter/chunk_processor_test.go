package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func chunkFixture(sequence int, lines ...string) ImmutableChunk {
	chunk := ImmutableChunk{Sequence: sequence}
	hash := sha256.New()
	for _, line := range lines {
		chunk.Lines = append(chunk.Lines, []byte(line))
		hash.Write([]byte(line + "\n"))
	}
	chunk.Digest = hex.EncodeToString(hash.Sum(nil))
	return chunk
}

func chunkConfig(t testing.TB, read func(context.Context, int) (ImmutableChunk, bool, error), do func(*http.Request) (*http.Response, error)) ChunkProcessorConfig {
	t.Helper()
	spoolPath := t.TempDir()
	generationPath := filepath.Join(spoolPath, "generation")
	if err := os.Mkdir(generationPath, 0750); err != nil {
		t.Fatal(err)
	}
	spool, err := os.OpenRoot(spoolPath)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenRoot(generationPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close(); spool.Close() })
	client, err := NewProductionClient(ProductionClientConfig{
		BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64),
		Token: func() ([]byte, error) { return []byte(envelopeCredential(t, 11)), nil },
		Now:   func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) }, Do: do,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ChunkProcessorConfig{Source: lineageSourceFixture(), SourceRoot: source, SpoolRoot: spool,
		CursorPath: filepath.Join(t.TempDir(), "chunks.json"), Client: client, MaximumProcesses: 16, ReadChunk: read}
}

// Losing pending state, rereading the source on replay, or preparing a new body
// after restart must fail this test. Only the external HTTP transport is replaced.
func TestChunkProcessorReplaysDurableEnvelopeBeforeReadingNextChunk(t *testing.T) {
	reads := 0
	first := chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture()), `{"node_name":"node-a","unsupported":true}`)
	var bodies [][]byte
	var keys, authorizations []string
	config := chunkConfig(t, func(_ context.Context, sequence int) (ImmutableChunk, bool, error) {
		reads++
		if sequence != 1 {
			t.Fatalf("unexpected source read: %d", sequence)
		}
		return first, true, nil
	}, func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		if len(bodies) == 1 {
			return nil, errors.New("transport interrupted")
		}
		return envelopeAccepted(), nil
	})
	credential := envelopeCredential(t, 11)
	config.Client.token = func() ([]byte, error) {
		raw, err := os.ReadFile(config.CursorPath)
		var saved chunkCheckpoint
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Pending == nil || saved.Pending.Envelope == nil {
			t.Fatal("credential accessed before durable exact envelope")
		}
		if saved.Pending.Digest != first.Digest || saved.Pending.Result.Read != 2 || saved.Pending.Result.Dropped != 1 {
			t.Fatal("pending does not bind rejected source record")
		}
		return []byte(credential), nil
	}
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.ProcessAvailable(context.Background()); err == nil {
		t.Fatal("failed upload accepted")
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	credential = envelopeCredential(t, 12)
	p, err = NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	result, err := p.ProcessAvailable(context.Background())
	if err != nil || result.Read != 2 || result.Submitted != 1 || result.Dropped != 1 {
		t.Fatalf("replay: %+v %v", result, err)
	}
	if reads != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || keys[0] == "" || keys[0] != keys[1] || authorizations[0] == authorizations[1] {
		t.Fatal("replay changed identity/body, reused credential, or reread source")
	}
	progress, durable, err := p.Committed()
	if err != nil || !durable || progress.NextSequence != 2 || progress.Read != 2 || progress.Submitted != 1 || progress.Dropped != 1 {
		t.Fatalf("commit: %+v %v %v", progress, durable, err)
	}
}

func TestChunkProcessorRestoresQualifiedCacheAcrossChunks(t *testing.T) {
	chunks := []ImmutableChunk{chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), chunkFixture(2, strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"2026-08-20T12:00:00.000Z"}`, 1))}
	var events []RuntimeEvent
	config := chunkConfig(t, func(_ context.Context, seq int) (ImmutableChunk, bool, error) { return chunks[seq-1], true, nil }, func(request *http.Request) (*http.Response, error) {
		var body runtimeEnvelopeBody
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		events = append(events, body.Events...)
		return envelopeAccepted(), nil
	})
	for i := 0; i < 2; i++ {
		p, err := NewChunkProcessor(config)
		if err != nil {
			t.Fatal(err)
		}
		result, err := p.ProcessAvailable(context.Background())
		p.Close()
		if err != nil || result.Submitted != 1 {
			t.Fatalf("chunk %d: %+v %v", i+1, result, err)
		}
	}
	if len(events) != 2 || events[1].ObservedLineage.PodUID == "" || events[0].ObservedLineage != events[1].ObservedLineage {
		t.Fatal("restart lost qualified process identity")
	}
}

func TestChunkProcessorRejectsBadInputWithoutAdvancing(t *testing.T) {
	for _, kind := range []string{"digest", "sequence", "newline", "oversized", "foreign node"} {
		t.Run(kind, func(t *testing.T) {
			chunk := chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture()))
			switch kind {
			case "digest":
				chunk.Digest = strings.Repeat("0", 64)
			case "sequence":
				chunk.Sequence = 2
			case "newline":
				chunk = chunkFixture(1, "a\nb")
			case "oversized":
				chunk = chunkFixture(1, strings.Repeat("a", (256<<10)+1))
			case "foreign node":
				chunk = chunkFixture(1, strings.Replace(qualifiedTetragonFixture(tetragonExecFixture()), "node-a", "node-b", 1))
			}
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { return chunk, true, nil }, func(*http.Request) (*http.Response, error) { t.Fatal("bad source uploaded"); return nil, nil })
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if _, err := p.ProcessAvailable(context.Background()); err == nil {
				t.Fatal("bad input consumed")
			}
			if _, err := os.Stat(config.CursorPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("bad input advanced checkpoint")
			}
		})
	}
}

func TestChunkProcessorAllRejectedRecordsCommitWithoutCredentials(t *testing.T) {
	chunk := chunkFixture(1, `{"node_name":"node-a","unsupported":true}`)
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { return chunk, true, nil }, func(*http.Request) (*http.Response, error) { t.Fatal("drop uploaded"); return nil, nil })
	config.Client.token = func() ([]byte, error) { t.Fatal("drop read credential"); return nil, nil }
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	result, err := p.ProcessAvailable(context.Background())
	if err != nil || result.Read != 1 || result.Submitted != 0 || result.Dropped != 1 {
		t.Fatalf("drop: %+v %v", result, err)
	}
	progress, durable, err := p.Committed()
	if err != nil || !durable || progress.Bytes != int64(len(chunk.Lines[0])+1) || progress.NextSequence != 2 {
		t.Fatalf("source accounting: %+v %v %v", progress, durable, err)
	}
}

func TestChunkProcessorCheckpointFailuresNeverSkipOrChangePending(t *testing.T) {
	for _, failure := range []string{"before pending", "after pending", "before commit", "after commit"} {
		t.Run(failure, func(t *testing.T) {
			reads, calls := 0, 0
			var bodies [][]byte
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
				reads++
				return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
			}, func(request *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
				return envelopeAccepted(), nil
			})
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			writes := 0
			p.writeCheckpoint = func(root *os.Root, name string, raw []byte) error {
				writes++
				shouldFail := writes == 1 && strings.HasSuffix(failure, "pending") || writes == 2 && strings.HasSuffix(failure, "commit")
				if shouldFail && strings.HasPrefix(failure, "before") {
					return ErrStream
				}
				if err := writeCheckpointBytes(root, name, raw); err != nil {
					return err
				}
				if shouldFail {
					return ErrStream
				}
				return nil
			}
			if _, err := p.ProcessAvailable(context.Background()); err == nil {
				t.Fatal("persistence failure accepted")
			}
			wantCalls := 0
			if strings.HasSuffix(failure, "commit") {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("upload crossed persistence barrier: %d", calls)
			}
			if _, durable, err := p.Committed(); err != nil || durable {
				t.Fatal("uncertain commit reported durable")
			}
			p.writeCheckpoint = writeCheckpointBytes
			result, err := p.ProcessAvailable(context.Background())
			if err != nil || result.Submitted != 1 || reads != 1 || calls != wantCalls+1 {
				t.Fatalf("pending recovery: %+v %v reads=%d calls=%d", result, err, reads, calls)
			}
			if len(bodies) == 2 && !bytes.Equal(bodies[0], bodies[1]) {
				t.Fatal("acknowledgment failure changed replay")
			}
		})
	}
}

func TestChunkProcessorInternalNormalizationFailureDoesNotDropChunk(t *testing.T) {
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
		return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
	}, func(*http.Request) (*http.Response, error) { return envelopeAccepted(), nil })
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	// An empty but broken cache panics on insertion. This is not an input drop.
	p.normalizer.values = nil
	if _, err := p.ProcessAvailable(context.Background()); !errors.Is(err, ErrStream) {
		t.Fatalf("internal failure: %v", err)
	}
	if _, err := os.Stat(config.CursorPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("internal failure was durably skipped")
	}
	result, err := p.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || result.Dropped != 0 {
		t.Fatalf("cache not restored after failure: %+v %v", result, err)
	}
}

func TestChunkProcessorRejectsCorruptCheckpointBeforeSourceOrCredentials(t *testing.T) {
	for _, mutation := range []string{"legacy", "chain", "sequence", "read", "bytes", "cache node", "event lineage", "duplicate", "unknown", "enrollment", "destination", "source"} {
		t.Run(mutation, func(t *testing.T) {
			reads, calls := 0, 0
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
				reads++
				return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
			}, func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("offline") })
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.ProcessAvailable(context.Background()); err == nil {
				t.Fatal("offline request accepted")
			}
			p.Close()
			raw, err := os.ReadFile(config.CursorPath)
			if err != nil {
				t.Fatal(err)
			}
			var saved chunkCheckpoint
			if err := json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "legacy":
				saved.Version = cursorContractVersion
			case "chain":
				saved.Pending.Next.Chain = strings.Repeat("0", 64)
			case "sequence":
				saved.Pending.Sequence++
			case "read":
				saved.Pending.Next.Read++
			case "bytes":
				saved.Pending.Bytes = 1<<20 + 1
			case "cache node":
				saved.Pending.Cache[0].Node = "node-b"
			case "event lineage":
				var body runtimeEnvelopeBody
				if err := json.Unmarshal(saved.Pending.Envelope.Body, &body); err != nil {
					t.Fatal(err)
				}
				body.Events[0].ObservedLineage.NodeUID = "78950009-0000-4000-8000-000000009999"
				saved.Pending.Envelope.Body, err = json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				saved.Pending.Envelope.IdempotencyKey = envelopeIdempotency(saved.Pending.Envelope.Body)
			case "enrollment":
				config.Source.EnrollmentBinding = strings.Repeat("b", 64)
				config.Client.enrollment = config.Source.EnrollmentBinding
			case "destination":
				config.Client.base.Host = "other.example.test"
			case "source":
				config.Source.BootID = "78950009-0000-4000-8000-000000009999"
			}
			raw, err = json.Marshal(saved)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "duplicate" {
				raw = bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"other","version":`), 1)
			}
			if mutation == "unknown" {
				raw = bytes.Replace(raw, []byte(`"version":`), []byte(`"extra":true,"version":`), 1)
			}
			if err := os.WriteFile(config.CursorPath, append(raw, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			p, err = NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if _, err := p.ProcessAvailable(context.Background()); !errors.Is(err, ErrStream) {
				t.Fatalf("corrupt checkpoint: %v", err)
			}
			if reads != 1 || calls != 1 {
				t.Fatal("corrupt checkpoint reached source or transport")
			}
		})
	}
}

func TestChunkProcessorCursorIsolationAndBorrowedOwnership(t *testing.T) {
	for _, collision := range []string{"generation", "spool", "token", "parent writable", "parent special", "enrollment"} {
		t.Run(collision, func(t *testing.T) {
			config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
				t.Fatal("read")
				return ImmutableChunk{}, false, nil
			}, func(*http.Request) (*http.Response, error) { t.Fatal("upload"); return nil, nil })
			switch collision {
			case "generation":
				config.CursorPath = filepath.Join(config.SourceRoot.Name(), "cursor")
			case "spool":
				config.CursorPath = filepath.Join(config.SpoolRoot.Name(), "cursor")
			case "token":
				root, err := os.OpenRoot(filepath.Dir(config.CursorPath))
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				config.ProtectedInputs = []PinnedInput{{Parent: root, Name: filepath.Base(config.CursorPath) + ".lock"}}
			case "parent writable":
				if err := os.Chmod(filepath.Dir(config.CursorPath), 0770); err != nil {
					t.Fatal(err)
				}
			case "parent special":
				if err := os.Chmod(filepath.Dir(config.CursorPath), 0700|os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
			case "enrollment":
				config.Client.enrollment = strings.Repeat("b", 64)
			}
			p, err := NewChunkProcessor(config)
			if err == nil {
				p.Close()
				t.Fatal("unsafe cursor accepted")
			}
			if _, err := config.SourceRoot.Stat("."); err != nil {
				t.Fatal("borrowed source closed")
			}
			if _, err := config.SpoolRoot.Stat("."); err != nil {
				t.Fatal("borrowed spool closed")
			}
			if _, err := os.Stat(config.CursorPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe construction created lock")
			}
		})
	}
}

func TestChunkProcessorEmptyGenerationIsDurableButNotAcknowledged(t *testing.T) {
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) { return ImmutableChunk{}, false, nil }, func(*http.Request) (*http.Response, error) { t.Fatal("empty uploaded"); return nil, nil })
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, durable, err := p.Committed(); err != nil || durable {
		t.Fatal("new empty state already durable")
	}
	if _, err := NewChunkProcessor(config); err == nil {
		t.Fatal("second consumer took cursor lock")
	}
	result, err := p.ProcessAvailable(context.Background())
	if err != nil || !result.Idle {
		t.Fatalf("idle: %+v %v", result, err)
	}
	progress, durable, err := p.Committed()
	if err != nil || !durable || progress.NextSequence != 1 || progress.Read != 0 {
		t.Fatalf("empty progress: %+v %v %v", progress, durable, err)
	}
	p.Close()
	if _, err := config.SourceRoot.Stat("."); err != nil {
		t.Fatal("Close closed borrowed source")
	}
}

func TestChunkProcessorExpiredPendingRetainsOriginalRecords(t *testing.T) {
	reads := 0
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
		reads++
		return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
	}, func(*http.Request) (*http.Response, error) { t.Fatal("expired uploaded"); return nil, nil })
	config.Client.now = func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) }
	config.Client.token = func() ([]byte, error) { t.Fatal("expired credential read"); return nil, nil }
	var original []byte
	for i := 0; i < 2; i++ {
		p, err := NewChunkProcessor(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.ProcessAvailable(context.Background()); !errors.Is(err, ErrEnvelopeExpired) {
			t.Fatalf("expired: %v", err)
		}
		if _, durable, err := p.Committed(); err != nil || durable {
			t.Fatal("expired source acknowledged")
		}
		p.Close()
		raw, err := os.ReadFile(config.CursorPath)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			original = raw
		} else if !bytes.Equal(original, raw) {
			t.Fatal("expired replay mutated frozen checkpoint")
		}
	}
	if reads != 1 || !bytes.Contains(original, []byte("2026-08-20T12:00:00.000Z")) {
		t.Fatal("expired input reread or retimestamped")
	}
}

func TestChunkProcessorRestartAfterUncertainAcknowledgment(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("after-write-%v", afterWrite), func(t *testing.T) {
			reads, uploads := 0, 0
			config := chunkConfig(t, func(_ context.Context, seq int) (ImmutableChunk, bool, error) {
				reads++
				if seq == 2 {
					return ImmutableChunk{}, false, nil
				}
				return chunkFixture(1, qualifiedTetragonFixture(tetragonExecFixture())), true, nil
			}, func(*http.Request) (*http.Response, error) { uploads++; return envelopeAccepted(), nil })
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			p.writeCheckpoint = func(root *os.Root, name string, raw []byte) error {
				writes++
				if writes == 2 && !afterWrite {
					return ErrStream
				}
				if err := writeCheckpointBytes(root, name, raw); err != nil {
					return err
				}
				if writes == 2 {
					return ErrStream
				}
				return nil
			}
			if _, err := p.ProcessAvailable(context.Background()); err != ErrStream {
				t.Fatal("ack failure lost")
			}
			p.Close()
			p, err = NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			result, err := p.ProcessAvailable(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if afterWrite {
				if !result.Idle || uploads != 1 || reads != 2 {
					t.Fatal("durably committed source replayed")
				}
			} else if result.Submitted != 1 || uploads != 2 || reads != 1 {
				t.Fatal("uncommitted pending skipped on restart")
			}
		})
	}
}

func TestChunkProcessorEnforcesGenerationByteAndSequenceBounds(t *testing.T) {
	for _, quota := range []string{"bytes", "sequences"} {
		t.Run(quota, func(t *testing.T) {
			reads := 0
			config := chunkConfig(t, func(_ context.Context, seq int) (ImmutableChunk, bool, error) {
				reads++
				if quota == "sequences" {
					return chunkFixture(seq, "x"), true, nil
				}
				line := strings.Repeat("x", (256<<10)-1)
				return chunkFixture(seq, line, line, line, line), true, nil
			}, func(*http.Request) (*http.Response, error) { t.Fatal("rejected input uploaded"); return nil, nil })
			p, err := NewChunkProcessor(config)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			count := 8
			if quota == "sequences" {
				count = 128
			}
			for i := 0; i < count; i++ {
				if _, err := p.ProcessAvailable(context.Background()); err != nil {
					t.Fatalf("before quota at %d: %v", i, err)
				}
			}
			result, err := p.ProcessAvailable(context.Background())
			if quota == "bytes" {
				if err != ErrStream || reads != 9 {
					t.Fatal("source byte quota bypassed")
				}
			} else if err != nil || !result.Idle || reads != 128 {
				t.Fatal("sequence quota bypassed")
			}
			progress, durable, err := p.Committed()
			if err != nil || !durable || progress.NextSequence != count+1 {
				t.Fatal("quota advanced source")
			}
		})
	}
}

// A cache cannot predate the generation's own consumed source history. Otherwise
// a corrupted initial checkpoint can qualify a partial event from old identity.
func TestChunkProcessorRejectsCacheWithoutConsumedSourceHistory(t *testing.T) {
	config := chunkConfig(t, func(context.Context, int) (ImmutableChunk, bool, error) {
		t.Fatal("unearned cache reached source")
		return ImmutableChunk{}, false, nil
	}, func(*http.Request) (*http.Response, error) { t.Fatal("unearned cache uploaded"); return nil, nil })
	p, err := NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Committed(); err != nil {
		t.Fatal(err)
	}
	normalizer, err := NewLineageNormalizer(16, config.Source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizer.Normalize([]byte(qualifiedTetragonFixture(tetragonExecFixture()))); err != nil {
		t.Fatal(err)
	}
	cache, err := normalizer.checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := *p.checkpoint
	checkpoint.Cache = cache
	raw, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.CursorPath, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	p.Close()
	p, err = NewChunkProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, _, err := p.Committed(); err != ErrStream {
		t.Fatalf("cache with zero source history accepted: %v", err)
	}
}
