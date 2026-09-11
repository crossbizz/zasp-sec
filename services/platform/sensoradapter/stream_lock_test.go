package sensoradapter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFileProcessorOwnsOneStableCursorLock(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	normalizer, _ := NewNormalizer(4)
	config := FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1}
	first, err := NewFileProcessor(config)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := NewFileProcessor(config); err == nil {
		second.Close()
		t.Fatal("two processors own the same cursor")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(cursorPath + ".lock")
	if err != nil {
		t.Fatal("stable lock disappeared", err)
	}
	second, err := NewFileProcessor(config)
	if err != nil {
		t.Fatal("released lock cannot be acquired", err)
	}
	defer second.Close()
	after, err := os.Stat(cursorPath + ".lock")
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lock inode changed on reopening", err)
	}
}

func TestFileProcessorCursorLockSubprocess(t *testing.T) {
	if mode := os.Getenv("ZASP_CHECKPOINT_LOCK_TEST_CHILD"); mode != "" {
		normalizer, _ := NewNormalizer(4)
		processor, err := NewFileProcessor(FileProcessorConfig{LogPath: os.Getenv("ZASP_CHECKPOINT_LOCK_TEST_LOG"), CursorPath: os.Getenv("ZASP_CHECKPOINT_LOCK_TEST_CURSOR"), Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1})
		if mode == "denied" {
			if err != ErrStream || processor != nil {
				t.Fatal("another process acquired the held cursor lock")
			}
			return
		}
		if mode != "exit-with-lock" || err != nil || processor == nil {
			t.Fatal("child could not acquire the released cursor lock", err)
		}
		// Deliberately bypass Close and Go cleanup. The operating system must
		// release the flock when this process exits, preserving its stable inode.
		os.Exit(0)
	}
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	first := newFixtureFileProcessor(t, logPath, cursorPath, &recordingStreamSink{})
	before, err := os.Stat(cursorPath + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	runChild := func(mode string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFileProcessorCursorLockSubprocess$")
		command.Env = append(os.Environ(), "ZASP_CHECKPOINT_LOCK_TEST_CHILD="+mode, "ZASP_CHECKPOINT_LOCK_TEST_LOG="+logPath, "ZASP_CHECKPOINT_LOCK_TEST_CURSOR="+cursorPath)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("cursor-lock subprocess %s failed: %v\n%s", mode, err, output)
		}
	}
	runChild("denied")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	runChild("exit-with-lock")
	last := newFixtureFileProcessor(t, logPath, cursorPath, &recordingStreamSink{})
	defer last.Close()
	after, err := os.Stat(cursorPath + ".lock")
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("process exit changed the cursor lock inode", err)
	}
}

func TestFileProcessorRejectsReplacedLockBeforeSubmission(t *testing.T) {
	directory := t.TempDir()
	logPath, cursorPath := filepath.Join(directory, "tetragon.log"), filepath.Join(directory, "cursor.json")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	sink := &recordingStreamSink{}
	processor := newFixtureFileProcessor(t, logPath, cursorPath, sink)
	defer processor.Close()
	if err := os.Rename(cursorPath+".lock", cursorPath+".previous-lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorPath+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := processor.ProcessAvailable(context.Background()); err == nil || len(sink.calls) != 0 {
		t.Fatal("replaced lock allowed submission")
	}
}

func TestFileProcessorRejectsSourceAtReservedCheckpointSlot(t *testing.T) {
	directory := t.TempDir()
	cursorPath := filepath.Join(directory, "cursor.json")
	logPath := filepath.Join(directory, temporaryCheckpointName("cursor.json"))
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	normalizer, _ := NewNormalizer(4)
	processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: cursorPath, Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1})
	if processor != nil {
		processor.Close()
	}
	if err != ErrStream {
		t.Fatal("configured source can be removed as an orphan checkpoint slot")
	}
	if body, err := os.ReadFile(logPath); err != nil || string(body) != tetragonExecFixture()+"\n" {
		t.Fatal("rejected source was modified", err)
	}
}

func TestCursorReservedSlotsUsePinnedDirectoryIdentity(t *testing.T) {
	for _, name := range []string{"cursor.json", "cursor.json.lock", temporaryCheckpointName("cursor.json")} {
		t.Run(name, func(t *testing.T) {
			directory, aliasParent := t.TempDir(), t.TempDir()
			alias := filepath.Join(aliasParent, "alias")
			if err := os.Symlink(directory, alias); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(alias, name)
			writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
			normalizer, _ := NewNormalizer(4)
			config := FileProcessorConfig{LogPath: logPath, CursorPath: filepath.Join(directory, "cursor.json"), Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1}
			processor, err := NewFileProcessor(config)
			if processor != nil {
				processor.Close()
			}
			if err != ErrStream {
				t.Fatal("directory alias bypassed input reservation")
			}
			if body, err := os.ReadFile(logPath); err != nil || string(body) != tetragonExecFixture()+"\n" {
				t.Fatal("rejected aliased source was modified", err)
			}
			// The same basename in a genuinely different directory isn't a
			// collision and remains supported.
			config.CursorPath = filepath.Join(t.TempDir(), "cursor.json")
			processor, err = NewFileProcessor(config)
			if err != nil {
				t.Fatal("disjoint directory was rejected", err)
			}
			processor.Close()
		})
	}
}

func TestCursorCannotOccupyAnotherCursorsReservedNamespace(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "tetragon.log")
	writeFixtureLog(t, logPath, tetragonExecFixture()+"\n")
	for _, name := range []string{"cursor.json.lock", temporaryCheckpointName("cursor.json")} {
		normalizer, _ := NewNormalizer(4)
		processor, err := NewFileProcessor(FileProcessorConfig{LogPath: logPath, CursorPath: filepath.Join(directory, name), Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1})
		if processor != nil {
			processor.Close()
		}
		if err != ErrStream {
			t.Fatal("cursor occupied reserved namespace")
		}
		if _, err := os.Lstat(filepath.Join(directory, name+".lock")); !os.IsNotExist(err) {
			t.Fatal("rejected cursor created a lock file", err)
		}
	}
}

func TestProtectedCheckpointInputsRejectInvalidDescriptorsBeforeLock(t *testing.T) {
	for _, name := range []string{"nil-parent", "empty", "dot", "parent", "traversal", "absolute", "closed-matching-parent", "too-many"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			input := PinnedInput{Parent: root, Name: "token"}
			switch name {
			case "nil-parent":
				input.Parent = nil
			case "empty":
				input.Name = ""
			case "dot":
				input.Name = "."
			case "parent":
				input.Name = ".."
			case "traversal":
				input.Name = "../token"
			case "absolute":
				input.Name = filepath.Join(directory, "token")
			case "closed-matching-parent":
				input.Name = "cursor.json"
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
			}
			inputs := []PinnedInput{input}
			if name == "too-many" {
				for len(inputs) < 9 {
					inputs = append(inputs, input)
				}
			}
			normalizer, _ := NewNormalizer(4)
			processor, err := NewFileProcessor(FileProcessorConfig{LogPath: filepath.Join(directory, "tetragon.log"), CursorPath: filepath.Join(directory, "cursor.json"), Normalizer: normalizer, Sink: &recordingStreamSink{}, MaximumLines: 1, ProtectedInputs: inputs})
			if processor != nil {
				processor.Close()
			}
			if err != ErrStream {
				t.Fatal("invalid protected input was accepted")
			}
			if _, err := os.Lstat(filepath.Join(directory, "cursor.json.lock")); !os.IsNotExist(err) {
				t.Fatal("invalid descriptor created cursor lock", err)
			}
		})
	}
}
