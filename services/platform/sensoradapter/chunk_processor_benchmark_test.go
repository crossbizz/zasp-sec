package sensoradapter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Measure the compiled non-race binary under the actual container memory/CPU
// ceiling. This deliberately stresses the accepted cache bound, not a claim
// that this many identities fit in a particular producer generation fixture.
func BenchmarkChunkProcessorMaximalCacheNewChunkRetry(b *testing.B) {
	benchmarkChunkProcessorBounds(b, false)
}

func BenchmarkChunkProcessorMaximalPendingReplay(b *testing.B) {
	benchmarkChunkProcessorBounds(b, true)
}

func benchmarkChunkProcessorBounds(b *testing.B, savedPending bool) {
	b.Cleanup(func() { reportCheckpointCgroup(b) })
	reads, attempts := 0, 0
	line := qualifiedTetragonFixture(tetragonExecFixture())
	chunk := chunkFixture(101)
	lines := []string{}
	for len(lines) < 1000 && (len(lines)+1)*(len(line)+1) <= 1<<20 {
		lines = append(lines, line)
	}
	chunk = chunkFixture(101, lines...)
	config := chunkConfig(b, func(_ context.Context, sequence int) (ImmutableChunk, bool, error) {
		reads++
		if sequence != 101 {
			b.Fatal("wrong source sequence", sequence)
		}
		return chunk, true, nil
	}, func(request *http.Request) (*http.Response, error) {
		attempts++
		if count, err := io.Copy(io.Discard, request.Body); err != nil || count < 256<<10 {
			b.Fatal("stress envelope missing", count, err)
		}
		if attempts%3 == 0 {
			return envelopeAccepted(), nil
		}
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})
	config.MaximumProcesses = 100_000
	p, err := NewChunkProcessor(config)
	if err != nil {
		b.Fatal(err)
	}
	cache := []cachedProcessIdentity{}
	cacheBytes := 2
	for pid := uint32(1000); pid < 101000; pid++ {
		identity := cachedProcessIdentity{Node: "node-a", PID: pid, StartedAt: "2026-08-20T12:00:00.000000000Z", ExecID: fmt.Sprintf("exec-%d", pid), Namespace: "ns", PodName: "pod", PodUID: "uid", ContainerID: "container", ContainerName: "container"}
		size, err := cacheIdentitySize(identity)
		if err != nil {
			b.Fatal(err)
		}
		if size > maximumCacheEncodedBytes-cacheBytes {
			break
		}
		cache = append(cache, identity)
		cacheBytes += size
	}
	baseline := &chunkCheckpoint{Version: chunkCheckpointVersion, Source: p.binding, Target: streamSinkTarget(config.Client), Committed: ChunkProgress{NextSequence: 101, Chain: strings.Repeat("a", 64), Read: 100000, Submitted: 100000, Bytes: 7 << 20}, Cache: cache}
	wantRecords := len(lines)
	if savedPending {
		event, err := NormalizeTetragonLine([]byte(line))
		if err != nil {
			b.Fatal(err)
		}
		event.Content = map[string]string{}
		for i := 0; i < 8; i++ {
			event.Content[fmt.Sprintf("key%d", i)] = strings.Repeat("<", 256)
		}
		events := make([]RuntimeEvent, 600)
		for i := range events {
			events[i] = event
		}
		envelope, err := config.Client.PrepareEnvelope(events)
		if err != nil || len(envelope.Body) < 7<<20 {
			b.Fatal("maximal saved envelope fixture", err)
		}
		wantRecords = len(events)
		next := ChunkProgress{NextSequence: 102, Chain: chunkChain(baseline.Committed.Chain, 101, chunk.Digest), Read: 100600, Submitted: 100600, Bytes: 8 << 20}
		baseline.Cache = nil
		baseline.Pending = &pendingChunk{Sequence: 101, Digest: chunk.Digest, Bytes: 1 << 20, Result: StreamResult{Read: 600, Submitted: 600}, Next: next, Envelope: &envelope, Cache: cache}
	}
	if err := p.persist(baseline); err != nil {
		b.Fatal(err)
	}
	if cacheBytes < 7<<20 {
		b.Fatal("fixture does not approach cache bound")
	}
	cacheEntries := len(cache)
	cache = nil
	// Retain only the encoded baseline for restaging, not its decoded cache.
	// This additional test-only buffer counts against the measured memory cap.
	baselineBytes, err := readCheckpointBytes(p.cursorRoot, p.cursorName)
	if err != nil {
		b.Fatal(err)
	}
	p.Close()
	baseline = nil
	runtime.GC()
	b.ReportAllocs()
	b.ResetTimer()
	var longest time.Duration
	for i := 0; i < b.N; i++ {
		p, err := NewChunkProcessor(config)
		if err != nil {
			b.Fatal(err)
		}
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			start := time.Now()
			result, err := p.ProcessAvailable(ctx)
			elapsed, contextErr := time.Since(start), ctx.Err()
			cancel()
			if elapsed > longest {
				longest = elapsed
			}
			if contextErr != nil {
				b.Fatal("operation exceeded 10s", contextErr)
			}
			if attempt < 2 {
				if err != ErrClientRetryable || result != (StreamResult{}) {
					b.Fatal("failed transport lost pending", result, err)
				}
			} else if err != nil || result.Read != wantRecords || result.Submitted != wantRecords || result.Dropped != 0 {
				b.Fatal("commit lost source", result, err)
			}
		}
		if err := writeCheckpointBytes(p.cursorRoot, p.cursorName, baselineBytes); err != nil {
			b.Fatal(err)
		}
		p.Close()
	}
	wantReads := b.N
	if savedPending {
		wantReads = 0
	}
	if reads != wantReads || attempts != 3*b.N {
		b.Fatal("retry reread source or skipped transport", reads, attempts)
	}
	b.ReportMetric(float64(cacheEntries), "cache-entries")
	b.ReportMetric(float64(wantRecords), "source-records")
	b.ReportMetric(float64(longest.Nanoseconds()), "max-operation-ns")
}
