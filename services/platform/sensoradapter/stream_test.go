package sensoradapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFileProcessorAdvancesOnlyAfterExactIngestAcknowledgement(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n"+tetragonFileFixture()+"\n")
	sink := &recordingStreamSink{}
	processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	result, err := processor.ProcessAvailable(context.Background())
	if err != nil || result.Read != 2 || result.Submitted != 2 || result.Dropped != 0 || len(sink.calls) != 1 || len(sink.calls[0]) != 2 {
		t.Fatalf("first ProcessAvailable = %#v, %v, calls=%d", result, err, len(sink.calls))
	}
	stateBefore := readFixtureCursor(t, cursorPath)
	result, err = processor.ProcessAvailable(context.Background())
	if err != nil || result != (StreamResult{Idle: true}) || len(sink.calls) != 1 {
		t.Fatalf("idle ProcessAvailable = %#v, %v, calls=%d", result, err, len(sink.calls))
	}
	appendFixtureLog(t, logPath, tetragonNetworkFixture()+"\n")
	result, err = processor.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || len(sink.calls) != 2 || sink.calls[1][0].Class != "network" || readFixtureCursor(t, cursorPath) == stateBefore {
		t.Fatalf("appended ProcessAvailable = %#v, %v, calls=%#v", result, err, sink.calls)
	}
}

func TestFileProcessorRetriesExactBatchAndCursorAfterUnknownIngest(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n"+tetragonFileFixture()+"\n")
	sink := &recordingStreamSink{err: ErrClientRetryable}
	processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	if result, err := processor.ProcessAvailable(context.Background()); !errors.Is(err, ErrClientRetryable) || result != (StreamResult{}) || fileExists(cursorPath) {
		t.Fatalf("failed ProcessAvailable = %#v, %v, cursor=%t", result, err, fileExists(cursorPath))
	}
	sink.err = nil
	result, err := processor.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 2 || len(sink.calls) != 2 || !reflect.DeepEqual(sink.calls[0], sink.calls[1]) {
		t.Fatalf("retried ProcessAvailable = %#v, %v, calls=%#v", result, err, sink.calls)
	}
}

func TestFileProcessorDefersPartialLinesAndResetsOnRotation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture())
	sink := &recordingStreamSink{}
	processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	if result, err := processor.ProcessAvailable(context.Background()); err != nil || result != (StreamResult{Idle: true}) || len(sink.calls) != 0 {
		t.Fatalf("partial ProcessAvailable = %#v, %v", result, err)
	}
	appendFixtureLog(t, logPath, "\n")
	if result, err := processor.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatalf("completed line = %#v, %v", result, err)
	}
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	writeFixtureLog(t, logPath, strings.ReplaceAll(tetragonExecFixture(), "exec-1", "exec-2")+"\n")
	if result, err := processor.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || len(sink.calls) != 2 {
		t.Fatalf("rotated ProcessAvailable = %#v, %v, calls=%d", result, err, len(sink.calls))
	}
}

func TestFileProcessorCommitsBoundedMalformedDropsWithoutSendingProviderBytes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, `{"process_exec":{},"token":"super-secret"}`+"\n"+tetragonExecFixture()+"\n")
	sink := &recordingStreamSink{}
	processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	result, err := processor.ProcessAvailable(context.Background())
	if err != nil || result.Read != 2 || result.Submitted != 1 || result.Dropped != 1 || len(sink.calls) != 1 {
		t.Fatalf("ProcessAvailable = %#v, %v, calls=%d", result, err, len(sink.calls))
	}
	if encoded := readFixtureCursor(t, cursorPath); strings.Contains(encoded, "secret") || !strings.Contains(encoded, `"dropped":1`) {
		t.Fatalf("cursor = %s", encoded)
	}
}

func TestFileProcessorReconstructsCorrelationAcrossRestartAndPriorMalformedLines(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, `{"process_exec":{}}`+"\n"+tetragonExecFixture()+"\n")
	firstSink := &recordingStreamSink{}
	first := newFixtureFileProcessor(t, logPath, cursorPath, firstSink)
	if result, err := first.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || result.Dropped != 1 {
		t.Fatalf("first ProcessAvailable = %#v, %v", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	partial := strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"2026-08-20T12:00:00.000Z"}`, 1)
	appendFixtureLog(t, logPath, partial+"\n")
	secondSink := &recordingStreamSink{}
	second := newFixtureFileProcessor(t, logPath, cursorPath, secondSink)
	t.Cleanup(func() { _ = second.Close() })
	if result, err := second.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || result.Dropped != 0 || len(secondSink.calls) != 1 || secondSink.calls[0][0].Class != "file" {
		t.Fatalf("restart ProcessAvailable = %#v, %v, calls=%#v", result, err, secondSink.calls)
	}
}

func TestFileProcessorRejectsUnsafeFilesAndConfiguration(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	normalizer, _ := NewNormalizer(128)
	sink := &recordingStreamSink{}
	for name, config := range map[string]FileProcessorConfig{
		"relative log":    {LogPath: "tetragon.log", CursorPath: cursorPath, Normalizer: normalizer, Sink: sink, MaximumLines: 10},
		"same files":      {LogPath: logPath, CursorPath: logPath, Normalizer: normalizer, Sink: sink, MaximumLines: 10},
		"nil normalizer":  {LogPath: logPath, CursorPath: cursorPath, Sink: sink, MaximumLines: 10},
		"nil sink":        {LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, MaximumLines: 10},
		"unbounded lines": {LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: sink, MaximumLines: 1001},
	} {
		name, config := name, config
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if value, err := NewFileProcessor(config); err == nil || value != nil {
				t.Fatalf("NewFileProcessor = %#v, %v", value, err)
			}
		})
	}
	linkPath := filepath.Join(directory, "linked.log")
	if err := os.Symlink(logPath, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	processor := newFixtureFileProcessor(t, linkPath, cursorPath, sink)
	if result, err := processor.ProcessAvailable(context.Background()); err == nil || result != (StreamResult{}) {
		t.Fatalf("symlink ProcessAvailable = %#v, %v", result, err)
	}
}

type recordingStreamSink struct {
	calls [][]RuntimeEvent
	err   error
}

func (sink *recordingStreamSink) Ingest(_ context.Context, events []RuntimeEvent) error {
	sink.calls = append(sink.calls, cloneRuntimeEvents(events))
	return sink.err
}

func newFixtureFileProcessor(t *testing.T, logPath, cursorPath string, sink StreamSink) *FileProcessor {
	t.Helper()
	normalizer, err := NewNormalizer(128)
	if err != nil {
		t.Fatalf("NewNormalizer: %v", err)
	}
	processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: sink, MaximumLines: 10})
	if err != nil {
		t.Fatalf("NewFileProcessor: %v", err)
	}
	return processor
}

func writeFixtureLog(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}
func appendFixtureLog(t *testing.T, path, value string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err = file.WriteString(value); err != nil {
		_ = file.Close()
		t.Fatalf("append: %v", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
func readFixtureCursor(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	return string(value)
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
