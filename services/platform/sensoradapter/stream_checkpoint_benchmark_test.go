package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Run the compiled, non-race test binary with -test.run=^$
// -test.bench=BenchmarkStreamCheckpointMaximalReplay -test.benchtime=3x.
// Measure process peak RSS externally; allocations/op is not a peak bound.
func BenchmarkStreamCheckpointMaximalReplay(b *testing.B) {
	benchmarkStreamCheckpointMaximalReplay(b, false, false)
}

func BenchmarkStreamCheckpointMaximalTransportRetry(b *testing.B) {
	benchmarkStreamCheckpointMaximalReplay(b, true, false)
}

func BenchmarkStreamCheckpointMaximalAcknowledgment(b *testing.B) {
	benchmarkStreamCheckpointMaximalReplay(b, true, true)
}

func benchmarkStreamCheckpointMaximalReplay(b *testing.B, transport, acknowledge bool) {
	directory := b.TempDir()
	b.Cleanup(func() { reportCheckpointCgroup(b) })
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		b.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	attempts := 0
	credential := envelopeCredential(b, 91)
	client, err := NewProductionClient(ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) {
		if !transport {
			b.Fatal("unexpected credential read")
		}
		return []byte(credential), nil
	}, Do: func(request *http.Request) (*http.Response, error) {
		if !transport {
			b.Fatal("unexpected transport")
		}
		attempts++
		if size, err := io.Copy(io.Discard, request.Body); err != nil || size < 7<<20 {
			b.Fatal("transport did not consume the maximal request", size, err)
		}
		if acknowledge && attempts%3 == 0 {
			return envelopeAccepted(), nil
		}
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	}})
	if err != nil {
		b.Fatal(err)
	}
	newProcessor := func() *FileProcessor {
		normalizer, _ := NewNormalizer(100_000)
		processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: client, MaximumLines: 1000})
		if err != nil {
			b.Fatal(err)
		}
		return processor
	}
	cache := make([]cachedProcessIdentity, 0)
	cacheBytes := 2
	for pid := uint32(1); pid <= 100_000; pid++ {
		identity := cachedProcessIdentity{Node: "node", PID: pid, StartedAt: "2026-08-20T12:00:00.000000000Z", ExecID: fmt.Sprintf("exec-%d", pid), Namespace: "ns", PodName: "pod", PodUID: "uid", ContainerID: "container", ContainerName: "container"}
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
	event, err := NormalizeTetragonLine([]byte(tetragonExecFixture()))
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
	envelope, err := client.PrepareEnvelope(events)
	if err != nil {
		b.Fatal(err)
	}
	processor := newProcessor()
	from := cursorState{Version: cursorContractVersion, Device: 1, Inode: 1}
	next := from
	next.Offset = 1
	checkpoint := &streamCheckpoint{Version: streamCheckpointVersion, Source: processor.sourceBinding, Target: streamSinkTarget(client), Committed: &from, Pending: &pendingStream{From: from, State: next, EndOffset: 1, Cache: cache, Envelope: &envelope, Result: StreamResult{Read: len(events), Submitted: len(events)}}}
	if err := processor.persistCheckpoint(checkpoint); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(cursorPath)
	if err != nil {
		b.Fatal(err)
	}
	if cacheBytes < 7<<20 || len(envelope.Body) < 7<<20 || info.Size() < 16<<20 {
		b.Fatal("stress fixture did not approach configured byte limits")
	}
	cacheEntries := len(cache)
	processor.Close()
	checkpoint = nil
	cache = nil
	events = nil
	envelope = RuntimeEnvelope{}
	runtime.GC()
	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(cacheEntries), "cache-entries")
	b.ReportMetric(float64(info.Size()), "checkpoint-bytes")
	var longestOperation time.Duration
	for i := 0; i < b.N; i++ {
		processor := newProcessor()
		wantErr := ErrClientRetryable
		if !transport {
			processor.writeCheckpoint = func(*os.Root, string, []byte) error { return ErrStream }
			wantErr = ErrStream
		}
		var replayFixture *streamCheckpoint
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			started := time.Now()
			result, err := processor.ProcessAvailable(ctx)
			elapsed := time.Since(started)
			contextErr := ctx.Err()
			cancel()
			if elapsed > longestOperation {
				longestOperation = elapsed
			}
			if contextErr != nil {
				b.Fatal("operation exceeded the configured deployment timeout", contextErr)
			}
			if acknowledge && attempt == 2 {
				if err != nil || result != (StreamResult{Read: 600, Submitted: 600}) || processor.pending != nil || processor.checkpoint.Pending != nil {
					b.Fatal("accepted request did not commit its checkpoint", result, err)
				}
			} else if err != wantErr || result != (StreamResult{}) {
				b.Fatal("failed attempt lost pending batch", result, err)
			}
			if attempt == 0 {
				replayFixture = processor.checkpoint
			}
		}
		if acknowledge {
			// Test-only restaging allows every benchmark iteration to measure
			// the same pending fixture, including a real acknowledgment write.
			if err := processor.persistCheckpoint(replayFixture); err != nil {
				b.Fatal(err)
			}
		}
		processor.Close()
	}
	b.ReportMetric(float64(longestOperation.Nanoseconds()), "max-operation-ns")
	if transport && attempts != 3*b.N {
		b.Fatal("transport retry was bypassed", attempts)
	}
}

func BenchmarkStreamCheckpointHostileDecode(b *testing.B) {
	directory := b.TempDir()
	b.Cleanup(func() { reportCheckpointCgroup(b) })
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		b.Fatal(err)
	}
	newProcessor := func() *FileProcessor {
		normalizer, _ := NewNormalizer(100_000)
		processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1000})
		if err != nil {
			b.Fatal(err)
		}
		return processor
	}
	processor := newProcessor()
	header, err := json.Marshal(streamCheckpoint{Version: streamCheckpointVersion, Source: processor.sourceBinding, Target: streamSinkTarget(processor.sink), Committed: &cursorState{Version: cursorContractVersion, Device: 1, Inode: 1}, Cache: []cachedProcessIdentity{}})
	if err != nil || !bytes.HasSuffix(header, []byte(`[]}`)) {
		b.Fatal("hostile fixture header", err)
	}
	var buffer bytes.Buffer
	buffer.Grow(maximumCheckpointBytes)
	buffer.Write(header[:len(header)-2])
	entry := []byte(`{"node":"` + strings.Repeat("x", 300) + `","pid":1}`)
	for i := 0; i < 100_000; i++ {
		if i != 0 {
			buffer.WriteByte(',')
		}
		buffer.Write(entry)
	}
	buffer.WriteString("]}\n")
	if buffer.Len() < 30<<20 || buffer.Len() > maximumCheckpointBytes || !checkpointJSONBounded(buffer.Bytes(), 100_000) {
		b.Fatal("hostile fixture must reach struct decoding near the input-byte and cache-entry bounds")
	}
	if err := os.WriteFile(cursorPath, buffer.Bytes(), 0o600); err != nil {
		b.Fatal(err)
	}
	fileBytes := buffer.Len()
	buffer = bytes.Buffer{}
	processor.Close()
	runtime.GC()
	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(fileBytes), "checkpoint-bytes")
	for i := 0; i < b.N; i++ {
		processor := newProcessor()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result, err := processor.ProcessAvailable(ctx)
		contextErr := ctx.Err()
		cancel()
		if err != ErrStream || result != (StreamResult{}) || contextErr != nil || processor.pending != nil || processor.checkpoint != nil {
			b.Fatal("hostile checkpoint was not rejected before state publication", result, err, contextErr)
		}
		processor.Close()
	}
}

func reportCheckpointCgroup(b *testing.B) {
	b.Helper()
	for _, name := range []string{"memory.max", "memory.peak", "memory.events"} {
		if data, err := os.ReadFile("/sys/fs/cgroup/" + name); err == nil {
			b.Logf("cgroup %s: %s", name, data)
		}
	}
}
