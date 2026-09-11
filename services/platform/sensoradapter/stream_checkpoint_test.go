package sensoradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStreamCheckpointPersistenceFailuresNeverAdvanceUnconfirmedWork(t *testing.T) {
	for _, phase := range []string{"before pending", "after pending", "before ack", "after ack"} {
		t.Run(phase, func(t *testing.T) {
			directory := t.TempDir()
			logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
			writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
			sink := &recordingStreamSink{}
			processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
			write := processor.writeCheckpoint
			writes := 0
			processor.writeCheckpoint = func(root *os.Root, name string, payload []byte) error {
				writes++
				fail := writes == 1 && strings.Contains(phase, "pending") || writes == 2 && strings.Contains(phase, "ack")
				if fail && strings.HasPrefix(phase, "before") {
					return ErrStream
				}
				if err := write(root, name, payload); err != nil {
					return err
				}
				if fail {
					return ErrStream
				}
				return nil
			}
			if result, err := processor.ProcessAvailable(context.Background()); err == nil || result != (StreamResult{}) {
				t.Fatal("persistence failure was ignored", err)
			}
			wantSends := 0
			if strings.Contains(phase, "ack") {
				wantSends = 1
			}
			if len(sink.calls) != wantSends {
				t.Fatal("send occurred before durable pending state")
			}
			appendFixtureLog(t, logPath, tetragonNetworkFixture()+"\n")
			// Even an uncertain post-rename/sync error retains exact pending state
			// in memory. A live retry must durably republish it before any send.
			if result, err := processor.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || len(sink.calls) != wantSends+1 {
				t.Fatal("persistence retry changed batch", result, err)
			}
			if wantSends == 1 && !reflect.DeepEqual(sink.calls[0], sink.calls[1]) {
				t.Fatal("ack-write failure regrouped the accepted batch")
			}
			if err := processor.Close(); err != nil {
				t.Fatal(err)
			}
			restartedSink := &recordingStreamSink{}
			restarted := newFixtureFileProcessor(t, logPath, cursorPath, restartedSink)
			if result, err := restarted.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || restartedSink.calls[0][0].Class != "network" {
				t.Fatal("restart lost next batch", result, err)
			}
		})
	}
}

func TestStreamCheckpointRestartAfterFailedAckReplaysAcceptedBatch(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	sink := &recordingStreamSink{}
	first := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	write := first.writeCheckpoint
	writes := 0
	first.writeCheckpoint = func(root *os.Root, name string, payload []byte) error {
		writes++
		if writes == 2 {
			return ErrStream
		}
		return write(root, name, payload)
	}
	if _, err := first.ProcessAvailable(context.Background()); err == nil || len(sink.calls) != 1 {
		t.Fatal("ack persistence fixture failed", err)
	}
	first.Close()
	appendFixtureLog(t, logPath, tetragonNetworkFixture()+"\n")
	replay := &recordingStreamSink{}
	second := newFixtureFileProcessor(t, logPath, cursorPath, replay)
	if result, err := second.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || !reflect.DeepEqual(sink.calls[0], replay.calls[0]) {
		t.Fatal("restart did not replay accepted pending batch", result, err)
	}
}

func TestStreamCheckpointPendingStoresOneCursorBoundPostCache(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	sink := &recordingStreamSink{}
	first := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	if _, err := first.ProcessAvailable(context.Background()); err != nil {
		t.Fatal(err)
	}
	appendFixtureLog(t, logPath, strings.ReplaceAll(tetragonExecFixture(), `"pid":42`, `"pid":43`)+"\n")
	sink.err = ErrClientRetryable
	if _, err := first.ProcessAvailable(context.Background()); err != ErrClientRetryable {
		t.Fatal(err)
	}
	var checkpoint streamCheckpoint
	if err := json.Unmarshal([]byte(readFixtureCursor(t, cursorPath)), &checkpoint); err != nil || checkpoint.Committed == nil || checkpoint.Pending == nil || checkpoint.Cache != nil || len(checkpoint.Pending.Cache) != 2 {
		t.Fatal("pending checkpoint duplicated cache or lost post-cursor identity", err)
	}
	first.Close()
	second := newFixtureFileProcessor(t, logPath, cursorPath, &recordingStreamSink{})
	if result, err := second.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 {
		t.Fatal("pending cache replay failed", result, err)
	}
	checkpoint = streamCheckpoint{}
	if err := json.Unmarshal([]byte(readFixtureCursor(t, cursorPath)), &checkpoint); err != nil || checkpoint.Pending != nil || len(checkpoint.Cache) != 2 {
		t.Fatal("ack did not bind post-cache to committed cursor", err)
	}
}

func TestStreamCheckpointFrozenProductionEnvelopeSurvivesRestartAndRotation(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	wire := envelopeCredential(t, 11)
	var bodies [][]byte
	var authorization []string
	reads := 0
	config := ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) {
		reads++
		var checkpoint streamCheckpoint
		if err := json.Unmarshal([]byte(readFixtureCursor(t, cursorPath)), &checkpoint); err != nil || checkpoint.Pending == nil || checkpoint.Pending.Envelope == nil {
			t.Fatal("credential read before durable envelope", err)
		}
		return []byte(wire), nil
	}, Do: func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		authorization = append(authorization, request.Header.Get("Authorization"))
		if len(bodies) == 1 {
			return nil, errors.New("response lost")
		}
		return envelopeAccepted(), nil
	}}
	client, err := NewProductionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	first := newFixtureFileProcessor(t, logPath, cursorPath, client)
	if _, err := first.ProcessAvailable(context.Background()); !errors.Is(err, ErrClientRetryable) {
		t.Fatal(err)
	}
	frozen := readFixtureCursor(t, cursorPath)
	if strings.Contains(frozen, wire) || strings.Contains(frozen, "Authorization") {
		t.Fatal("checkpoint retained credential")
	}
	first.Close()
	appendFixtureLog(t, logPath, tetragonNetworkFixture()+"\n")
	wire = envelopeCredential(t, 12)
	client, err = NewProductionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	second := newFixtureFileProcessor(t, logPath, cursorPath, client)
	if result, err := second.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || authorization[0] == authorization[1] || reads != 2 {
		t.Fatal("frozen restart request or fresh credential changed", result, err)
	}
	if result, err := second.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || len(bodies) != 3 || bytes.Equal(bodies[1], bodies[2]) {
		t.Fatal("new input merged into frozen envelope", result, err)
	}
}

func TestStreamCheckpointRejectsChangedConfigurationAndRetainsExpiredPending(t *testing.T) {
	for _, scenario := range []string{"destination", "enrollment", "source", "expired", "reduced lines", "reduced cache"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
			secondExec := strings.ReplaceAll(tetragonExecFixture(), `"pid":42`, `"pid":43`)
			writeFixtureLog(t, logPath, tetragonExecFixture()+"\n"+secondExec+"\n")
			now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
			reads := 0
			config := ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: strings.Repeat("a", 64), Now: func() time.Time { return now }, Token: func() ([]byte, error) { reads++; return []byte(envelopeCredential(t, 13)), nil }, Do: func(*http.Request) (*http.Response, error) { return nil, ErrClientRetryable }}
			client, err := NewProductionClient(config)
			if err != nil {
				t.Fatal(err)
			}
			first := newFixtureFileProcessor(t, logPath, cursorPath, client)
			if _, err := first.ProcessAvailable(context.Background()); !errors.Is(err, ErrClientRetryable) {
				t.Fatal(err)
			}
			first.Close()
			before := readFixtureCursor(t, cursorPath)
			maximum, lines := 128, 10
			switch scenario {
			case "destination":
				config.BaseURL = "https://other.example.test"
			case "enrollment":
				config.EnrollmentBinding = strings.Repeat("b", 64)
			case "source":
				logPath = filepath.Join(directory, "different.log")
				writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
			case "expired":
				now = now.Add(25 * time.Hour)
			case "reduced lines":
				lines = 1
			case "reduced cache":
				maximum = 1
			}
			client, err = NewProductionClient(config)
			if err != nil {
				t.Fatal(err)
			}
			normalizer, _ := NewNormalizer(maximum)
			second, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: client, MaximumLines: lines})
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			_, err = second.ProcessAvailable(context.Background())
			if err == nil || reads != 1 || readFixtureCursor(t, cursorPath) != before {
				t.Fatal("changed configuration or expired request advanced saved data", err)
			}
			if scenario == "expired" && !errors.Is(err, ErrEnvelopeExpired) {
				t.Fatal("expired checkpoint lost recovery-required error", err)
			}
		})
	}
}

func TestStreamCheckpointBoundsDecodeAndRecoversOnlyItsTemporarySlot(t *testing.T) {
	for _, raw := range []string{`{"cache":[null,null,null]}`, `{"cache":[],"cache":[]}`, `{"cache":[{}],"pending":{"cache":[{}]}}`, `{"cache":[],"pending":{"cache":[{}]}}`, `{"pending":{"cache":[]},"cache":[]}`, `{"events":[` + strings.Repeat("null,", 1000) + `null]}`, `{"key":"` + strings.Repeat("x", 4097) + `"}`} {
		if checkpointJSONBounded([]byte(raw), 2) {
			t.Fatal("unbounded or ambiguous checkpoint preflight accepted")
		}
	}
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	processor := newFixtureFileProcessor(t, logPath, cursorPath, &recordingStreamSink{})
	temporary := filepath.Join(directory, temporaryCheckpointName(filepath.Base(cursorPath)))
	// A crashed writer can leave a partial unpublished file. It cannot have
	// caused a send because publication and directory sync precede transport.
	if err := os.WriteFile(temporary, []byte(`{"version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(directory, temporaryCheckpointName("different-cursor.json"))
	if err := os.WriteFile(other, []byte("other processor"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := processor.ProcessAvailable(context.Background()); err != nil {
		t.Fatal("orphan slot prevented recovery", err)
	}
	if fileExists(temporary) || readFixtureCursor(t, other) != "other processor" {
		t.Fatal("temporary recovery left own orphan or touched another cursor")
	}
}

func TestStreamCheckpointMigratesLegacyCursorUsingOnlyAvailablePrefix(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, info, device, inode, err := openPinnedLog(root, "tetragon.log")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := writeCursorState(root, "cursor.json", cursorState{Version: cursorContractVersion, Device: device, Inode: inode, Offset: info.Size()}); err != nil {
		t.Fatal(err)
	}
	partial := strings.Replace(tetragonFileFixture(), tetragonProcess(), `{"pid":42,"flags":"unknown","start_time":"2026-08-20T12:00:00.000Z"}`, 1)
	appendFixtureLog(t, logPath, partial+"\n")
	sink := &recordingStreamSink{}
	processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	if result, err := processor.ProcessAvailable(context.Background()); err != nil || result.Submitted != 1 || sink.calls[0][0].Class != "file" {
		t.Fatal("legacy prefix migration failed", result, err)
	}
	if !strings.Contains(readFixtureCursor(t, cursorPath), streamCheckpointVersion) {
		t.Fatal("legacy cursor not migrated after commit")
	}
}

func TestStreamCheckpointRejectsMalformedProgressionBeforeReplay(t *testing.T) {
	for _, scenario := range []string{"rewound input", "wrong next offset", "duplicate cache", "version alias", "unknown field", "duplicate field"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
			writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
			first := newFixtureFileProcessor(t, logPath, cursorPath, &recordingStreamSink{err: ErrClientRetryable})
			if _, err := first.ProcessAvailable(context.Background()); err != ErrClientRetryable {
				t.Fatal(err)
			}
			first.Close()
			var checkpoint streamCheckpoint
			if err := json.Unmarshal([]byte(readFixtureCursor(t, cursorPath)), &checkpoint); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "rewound input":
				checkpoint.Pending.From.Offset = 1
			case "wrong next offset":
				checkpoint.Pending.State.Offset++
			case "duplicate cache":
				checkpoint.Pending.Cache = append(checkpoint.Pending.Cache, checkpoint.Pending.Cache[0])
			}
			raw, err := json.Marshal(checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "version alias":
				raw = bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1)
			case "unknown field":
				raw = append([]byte(`{"unexpected":true,`), raw[1:]...)
			case "duplicate field":
				raw = append([]byte(`{"version":"tetragon-checkpoint-v2",`), raw[1:]...)
			}
			if err := os.WriteFile(cursorPath, append(raw, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			sink := &recordingStreamSink{}
			second := newFixtureFileProcessor(t, logPath, cursorPath, sink)
			if _, err := second.ProcessAvailable(context.Background()); err == nil || len(sink.calls) != 0 {
				t.Fatal("malformed checkpoint allowed replay")
			}
		})
	}
}

func FuzzCheckpointJSONBounded(f *testing.F) {
	for _, seed := range []string{`{"cache":[],"pending":null}`, `{"cache":[null,null,null,null,null]}`, `{"body":"aGVsbG8="}`, `{"key":"\\\"\u2028"}`, `{"cache":[],"cache":[]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		if checkpointJSONBounded(raw, 4) && !json.Valid(raw) {
			t.Fatal("preflight accepted invalid JSON")
		}
	})
}
