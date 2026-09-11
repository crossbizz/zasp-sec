package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Observe real filesystem publication boundaries without adding production hooks.
// Err is called by this synchronous writer after file sync and after rename/sync.
type lineagePublicationContext struct {
	context.Context
	path   string
	cancel context.CancelFunc
	action func()
}

func (ctx lineagePublicationContext) Err() error {
	if _, err := os.Lstat(ctx.path); err == nil {
		if ctx.action != nil {
			ctx.action()
		}
		if ctx.cancel != nil {
			ctx.cancel()
		}
	}
	return ctx.Context.Err()
}

func TestLineageSpoolPayloadAndChunkQuotas(t *testing.T) {
	for _, quota := range []string{"chunks", "bytes"} {
		t.Run(quota, func(t *testing.T) {
			spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			generation, err := spool.Create(context.Background(), lineageSpoolSource())
			if err != nil {
				t.Fatal(err)
			}
			defer generation.Close()
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			batch := [][]byte{line}
			if quota == "bytes" {
				batch = nil
				for len(batch) < 1000 && (len(batch)+1)*(len(line)+1) <= lineageChunkBytes {
					batch = append(batch, line)
				}
			}
			for {
				_, err = generation.Append(context.Background(), batch)
				if errors.Is(err, errLineageSpoolFull) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if quota == "chunks" && generation.chunks != lineageSpoolChunks {
				t.Fatal("wrong chunk limit")
			}
			if quota == "bytes" && (generation.bytes > lineageSpoolBytes || generation.bytes+int64(len(batch)*(len(line)+1)) <= lineageSpoolBytes || generation.chunks >= lineageSpoolChunks) {
				t.Fatal("wrong byte limit")
			}
			before, err := generation.root.ReadFile(fmt.Sprintf("chunk-%010d.jsonl", generation.chunks))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := generation.Append(context.Background(), batch); !errors.Is(err, errLineageSpoolFull) {
				t.Fatal("quota retry resumed")
			}
			after, err := generation.root.ReadFile(fmt.Sprintf("chunk-%010d.jsonl", generation.chunks))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("capacity failure modified data")
			}
			if _, err := generation.root.Lstat(".pending"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("quota failure created pending data")
			}
			if err := generation.Seal(context.Background(), "capacity", 0, 0); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLineageSpoolDirectorySyncFailurePoisonsWriter(t *testing.T) {
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	generation, err := spool.Create(context.Background(), lineageSpoolSource())
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	ctx := lineagePublicationContext{Context: context.Background(), path: filepath.Join(parent, "generation-"+generation.source.GenerationID, ".pending"), action: func() { generation.dir.Close() }}
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(ctx, [][]byte{line}); err == nil || !generation.poisoned {
		t.Fatal("directory sync failure not terminal")
	}
	if _, err := generation.root.Lstat("chunk-0000000001.jsonl"); err != nil {
		t.Fatal("failure didn't reach post-rename directory sync")
	}
	if err := generation.Seal(context.Background(), "spool_error", 0, 0); err == nil {
		t.Fatal("sync failure sealed")
	}
}

func TestLineageSpoolProcessCrashRetainsGenerationWithoutAdoption(t *testing.T) {
	if parent := os.Getenv("ZASP_TEST_LINEAGE_CRASH_PARENT"); parent != "" {
		spool, err := newLineageSpool(parent, uint32(os.Getuid()))
		if err != nil {
			t.Fatal(err)
		}
		generation, err := spool.Create(context.Background(), lineageSpoolSource())
		if err != nil {
			t.Fatal(err)
		}
		stage := os.Getenv("ZASP_TEST_LINEAGE_CRASH_STAGE")
		ctx := lineagePublicationContext{Context: context.Background(), path: filepath.Join(parent, "generation-"+generation.source.GenerationID, stage), action: func() { os.Exit(73) }}
		line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
		generation.Append(ctx, [][]byte{line})
		t.Fatal("child didn't reach crash boundary")
	}
	for _, stage := range []string{".pending", "chunk-0000000001.jsonl"} {
		t.Run(stage, func(t *testing.T) {
			parent := t.TempDir()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			childContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(childContext, binary, "-test.run=^TestLineageSpoolProcessCrashRetainsGenerationWithoutAdoption$")
			command.Env = append(os.Environ(), "ZASP_TEST_LINEAGE_CRASH_PARENT="+parent, "ZASP_TEST_LINEAGE_CRASH_STAGE="+stage)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("crash child: %v %s", err, output)
			}
			spool, err := newLineageSpool(parent, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			source := lineageSpoolSource()
			if _, err := spool.Create(context.Background(), source); err == nil {
				t.Fatal("crashed history reopened for writing")
			}
			root, err := spool.root.OpenRoot("generation-" + source.GenerationID)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err := root.Lstat("closed.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("crash reported termination")
			}
			lines, err := readLineageSpoolChunk(root, "chunk-0000000001.jsonl", source, uint32(os.Getuid()))
			if stage == ".pending" && err == nil {
				t.Fatal("crash pending record readable")
			}
			if stage != ".pending" && (err != nil || len(lines) != 1) {
				t.Fatal("published crash data lost")
			}
			source.GenerationID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
			next, err := spool.Create(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			next.Close()
		})
	}
}

func TestLineageSpoolFailedPublicationCannotSealUnderreportedCounters(t *testing.T) {
	for _, stage := range []string{".pending", "chunk-0000000001.jsonl"} {
		t.Run(stage, func(t *testing.T) {
			parent := t.TempDir()
			spool, err := newLineageSpool(parent, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			generation, err := spool.Create(context.Background(), lineageSpoolSource())
			if err != nil {
				t.Fatal(err)
			}
			defer generation.Close()
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := lineagePublicationContext{Context: base, path: filepath.Join(parent, "generation-"+generation.source.GenerationID, stage), cancel: cancel}
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			if _, err := generation.Append(ctx, [][]byte{line}); err == nil || base.Err() == nil {
				t.Fatal("publication wasn't interrupted")
			}
			if _, err := generation.Append(context.Background(), [][]byte{line}); err == nil {
				t.Fatal("uncertain writer resumed")
			}
			if err := generation.Seal(context.Background(), "spool_error", 0, 0); err == nil {
				t.Fatal("uncertain publication sealed with underreported counters")
			}
			if _, err := generation.root.Lstat("closed.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("uncertain generation has termination marker")
			}
			lines, err := readLineageSpoolChunk(generation.root, "chunk-0000000001.jsonl", generation.source, uint32(os.Getuid()))
			if stage == ".pending" && err == nil {
				t.Fatal("pending record became readable")
			}
			if stage != ".pending" && (err != nil || len(lines) != 1 || !bytes.Equal(lines[0], line)) {
				t.Fatal("published record not independently recoverable")
			}
		})
	}
}

func TestLineageSpoolRejectsReplacedGenerationDirectory(t *testing.T) {
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	generation, err := spool.Create(context.Background(), lineageSpoolSource())
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	path := filepath.Join(parent, "generation-"+generation.source.GenerationID)
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(context.Background(), [][]byte{line}); err == nil {
		t.Fatal("writer accepted detached generation")
	}
}

func TestLineageSpoolRejectsSpecialDirectoryMode(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, os.ModeSticky|0o700); err != nil {
		t.Fatal(err)
	}
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if spool != nil {
		spool.Close()
	}
	if err == nil {
		t.Fatal("special directory mode accepted")
	}
}

func TestLineageSpoolConcurrentReaderSeesOnlyPublishedChunk(t *testing.T) {
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	generation, err := spool.Create(context.Background(), lineageSpoolSource())
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	ready, release := make(chan struct{}), make(chan struct{})
	ctx := lineagePublicationContext{Context: context.Background(), path: filepath.Join(parent, "generation-"+generation.source.GenerationID, ".pending"), action: func() { close(ready); <-release }}
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	done := make(chan error, 1)
	go func() { _, err := generation.Append(ctx, [][]byte{line}); done <- err }()
	<-ready
	_, readErr := readLineageSpoolChunk(generation.root, "chunk-0000000001.jsonl", generation.source, uint32(os.Getuid()))
	_, pendingErr := readLineageSpoolChunk(generation.root, ".pending", generation.source, uint32(os.Getuid()))
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if readErr == nil || pendingErr == nil {
		t.Fatal("reader accepted pending publication")
	}
	lines, err := readLineageSpoolChunk(generation.root, "chunk-0000000001.jsonl", generation.source, uint32(os.Getuid()))
	if err != nil || len(lines) != 1 || !bytes.Equal(lines[0], line) {
		t.Fatal("reader didn't see complete published chunk")
	}
}

func lineageSpoolSource() sensoradapter.LineageSource {
	return sensoradapter.LineageSource{Profile: "tetragon-local-stream-v1", GenerationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", EnrollmentBinding: strings.Repeat("b", 64), NodeName: "node-a", ClusterUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", NodeUID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", BootID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}
}

func TestLineageSpoolPublishesImmutableManifestAndBoundChunks(t *testing.T) {
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	source := lineageSpoolSource()
	generation, err := spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	manifestPath := filepath.Join(parent, "generation-"+source.GenerationID, "manifest.json")
	before, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(manifestPath)
	if err != nil || info.Mode().Perm() != 0o440 {
		t.Fatal("manifest isn't read-only")
	}
	line, err := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if err != nil {
		t.Fatal(err)
	}
	chunk, err := generation.Append(context.Background(), [][]byte{line, line})
	if err != nil {
		t.Fatal(err)
	}
	if chunk.Sequence != 1 || chunk.Records != 2 || chunk.Bytes != int64(2*(len(line)+1)) {
		t.Fatalf("chunk: %#v", chunk)
	}
	lines, err := readLineageSpoolChunk(generation.root, chunk.Name, source, uint32(os.Getuid()))
	if err != nil || len(lines) != 2 || !bytes.Equal(lines[0], line) || !bytes.Equal(lines[1], line) {
		t.Fatalf("read: %d, %v", len(lines), err)
	}
	wrong := source
	wrong.BootID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	if _, err := readLineageSpoolChunk(generation.root, chunk.Name, wrong, uint32(os.Getuid())); err == nil {
		t.Fatal("chunk adopted into another boot")
	}
	wrong = source
	wrong.EnrollmentBinding = strings.Repeat("c", 64)
	if _, err := readLineageSpoolChunk(generation.root, chunk.Name, wrong, uint32(os.Getuid())); err == nil {
		t.Fatal("chunk adopted into another enrollment")
	}
	if err := generation.Seal(context.Background(), "shutdown", 2, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := generation.Append(context.Background(), [][]byte{line}); err == nil {
		t.Fatal("sealed generation resumed")
	}
	after, err := os.ReadFile(manifestPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("manifest changed after append/seal")
	}
	var seal map[string]any
	data, err := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), "closed.json"))
	if err != nil || json.Unmarshal(data, &seal) != nil || seal["reason"] != "shutdown" || seal["coverage_complete"] != false {
		t.Fatalf("termination: %s, %v", data, err)
	}
}

func TestLineageSpoolRefusesExistingGenerationAndConcurrentProducer(t *testing.T) {
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if duplicate, err := newLineageSpool(parent, uint32(os.Getuid())); err == nil || duplicate != nil {
		if duplicate != nil {
			duplicate.Close()
		}
		t.Fatal("second producer acquired spool")
	}
	source := lineageSpoolSource()
	generation, err := spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	generation.Close()
	if reopened, err := spool.Create(context.Background(), source); err == nil || reopened != nil {
		t.Fatal("old generation resumed")
	}
	spool.Close()
	next, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if reopened, err := next.Create(context.Background(), source); err == nil || reopened != nil {
		t.Fatal("restart adopted old generation")
	}
}

func TestLineageSpoolRejectsCorruptChunksAndUnsafeParent(t *testing.T) {
	for _, kind := range []string{"payload", "header", "symlink", "writable", "wrong-owner"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			spool, err := newLineageSpool(parent, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			source := lineageSpoolSource()
			generation, err := spool.Create(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			defer generation.Close()
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			chunk, err := generation.Append(context.Background(), [][]byte{line})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "generation-"+source.GenerationID, chunk.Name)
			owner := uint32(os.Getuid())
			switch kind {
			case "payload", "header":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "payload" {
					data = bytes.Replace(data, []byte("exec-42"), []byte("exec-43"), 1)
				} else {
					data = bytes.Replace(data, []byte(`"sequence":1`), []byte(`"sequence":2`), 1)
				}
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o440); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0o660); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				owner++
			}
			if _, err := readLineageSpoolChunk(generation.root, chunk.Name, source, owner); err == nil {
				t.Fatal("unsafe/corrupt chunk accepted")
			}
		})
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if spool, err := newLineageSpool(parent, uint32(os.Getuid())); spool != nil || err == nil {
		if spool != nil {
			spool.Close()
		}
		t.Fatal("writable parent accepted")
	}
}

func TestLineageSpoolCountsAbandonedSlotsAndRejectsPartialRecords(t *testing.T) {
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	source := lineageSpoolSource()
	generation, err := spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer generation.Close()
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	for _, invalid := range [][]byte{line[:len(line)-1], append(append([]byte(nil), line...), '\n'), []byte(`{"secret":"credential"}`)} {
		if _, err := generation.Append(context.Background(), [][]byte{invalid}); err == nil {
			t.Fatal("partial/noncanonical record accepted")
		}
	}
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal("validation-only failure poisoned writer")
	}
	generation.Close()
	for _, prefix := range []string{"11111111", "22222222", "33333333", "44444444", "55555555", "66666666", "77777777"} {
		if err := os.Mkdir(filepath.Join(parent, "generation-"+prefix+"-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source.GenerationID = "88888888-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if generation, err := spool.Create(context.Background(), source); generation != nil || err != errLineageSpoolFull {
		t.Fatalf("abandoned slots bypassed quota: %v", err)
	}
}
