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

func TestFileProcessorRestartRetainsUncertainBatchBeforeAppendedLines(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	firstSink := &recordingStreamSink{err: ErrClientRetryable}
	first := newFixtureFileProcessor(t, logPath, cursorPath, firstSink)
	if _, err := first.ProcessAvailable(context.Background()); !errors.Is(err, ErrClientRetryable) || len(firstSink.calls) != 1 {
		t.Fatalf("uncertain first submission: %v, calls=%d", err, len(firstSink.calls))
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	appendFixtureLog(t, logPath, tetragonNetworkFixture()+"\n")
	secondSink := &recordingStreamSink{}
	second := newFixtureFileProcessor(t, logPath, cursorPath, secondSink)
	defer second.Close()
	result, err := second.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || len(secondSink.calls) != 1 || !reflect.DeepEqual(firstSink.calls[0], secondSink.calls[0]) {
		t.Fatalf("restart changed uncertain batch: result=%+v error=%v calls=%d", result, err, len(secondSink.calls))
	}
	result, err = second.ProcessAvailable(context.Background())
	if err != nil || result.Submitted != 1 || len(secondSink.calls) != 2 || secondSink.calls[1][0].Class != "network" {
		t.Fatalf("appended event not submitted separately: result=%+v error=%v calls=%d", result, err, len(secondSink.calls))
	}
}

func TestFileProcessorRestartRetainsExecIdentityAcrossAcknowledgedRotation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	firstSink := &recordingStreamSink{}
	first := newFixtureFileProcessor(t, logPath, cursorPath, firstSink)
	if result, err := first.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatalf("first exec: %+v, %v", result, err)
	}
	if err := os.Rename(logPath, filepath.Join(directory, "tetragon-2026-08-20T12-00-01.000.log")); err != nil {
		t.Fatal(err)
	}
	partial := strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"2026-08-20T12:00:00.000Z"}`, 1)
	writeFixtureLog(t, logPath, partial+"\n")
	if result, err := first.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || result.Dropped != 0 {
		t.Fatalf("live rotated cache positive control: %+v, %v", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	nextPartial := strings.Replace(partial, `"time":"2026-08-20T12:00:00.000Z"`, `"time":"2026-08-20T12:00:02.000Z"`, 1)
	if nextPartial == partial {
		t.Fatal("next partial event needs a distinct source identity")
	}
	appendFixtureLog(t, logPath, nextPartial+"\n")
	secondSink := &recordingStreamSink{}
	second := newFixtureFileProcessor(t, logPath, cursorPath, secondSink)
	defer second.Close()
	if result, err := second.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || result.Dropped != 0 || len(secondSink.calls) != 1 || secondSink.calls[0][0].Class != "file" {
		t.Fatalf("restart lost prior-file process identity: %+v, %v, calls=%d", result, err, len(secondSink.calls))
	}
}
