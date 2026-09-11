package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lineageSpoolReaderFixture(t *testing.T) (*lineageSpoolGeneration, string) {
	t.Helper()
	parent := t.TempDir()
	spool, err := newLineageSpool(parent, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { spool.Close() })
	generation, err := spool.Create(context.Background(), lineageSpoolSource())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { generation.Close() })
	return generation, filepath.Join(parent, "generation-"+generation.source.GenerationID)
}

func TestLineageSpoolReaderAdmitsBoundManifestWhileProducerOwnsLock(t *testing.T) {
	generation, path := lineageSpoolReaderFixture(t)
	reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if reader.Source() != generation.source {
		t.Fatal("admitted source changed")
	}
	source := reader.Source()
	source.NodeName = "other"
	if reader.Source() != generation.source {
		t.Fatal("source pointer escaped")
	}
	if _, found, err := reader.ReadChunk(1); err != nil || found {
		t.Fatal("empty unsealed generation not pending")
	}
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	chunk, found, err := reader.ReadChunk(1)
	if err != nil || !found || chunk.Sequence != 1 || len(chunk.Lines) != 1 || !bytes.Equal(chunk.Lines[0], line) || chunk.Digest != lineageHash(append(append([]byte(nil), line...), '\n')) {
		t.Fatalf("chunk: %#v, %v", chunk, err)
	}
	chunk.Lines[0][0] = '!'
	again, found, err := reader.ReadChunk(1)
	if err != nil || !found || !bytes.Equal(again.Lines[0], line) {
		t.Fatal("caller mutation changed retained data")
	}
	if err := generation.Seal(context.Background(), "shutdown", 2, 3); err != nil {
		t.Fatal(err)
	}
	seal, found, err := reader.ReadSeal()
	if err != nil || !found || seal.Chunks != 1 || seal.Records != 1 || seal.Bytes != int64(len(line)+1) || seal.Dropped != 2 || seal.Filtered != 3 || seal.CoverageComplete {
		t.Fatalf("seal: %#v, %v", seal, err)
	}
	if _, found, err := reader.ReadChunk(2); err != nil || found {
		t.Fatal("sealed frontier isn't exhausted")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal("close not idempotent")
	}
	if _, _, err := reader.ReadChunk(1); err == nil {
		t.Fatal("closed reader accepted chunk")
	}
}

func TestLineageSpoolReaderRejectsForeignEnrollmentAndUnsafeAdmission(t *testing.T) {
	for _, kind := range []string{"enrollment", "empty-enrollment", "owner", "parent-mode", "directory-mode", "unpublished-directory", "symlink", "manifest-mode", "oversize", "generation", "version"} {
		t.Run(kind, func(t *testing.T) {
			generation, path := lineageSpoolReaderFixture(t)
			binding, owner := generation.source.EnrollmentBinding, uint32(os.Getuid())
			manifestPath := filepath.Join(path, "manifest.json")
			switch kind {
			case "enrollment":
				binding = strings.Repeat("f", 64)
			case "empty-enrollment":
				binding = ""
			case "owner":
				owner++
			case "parent-mode":
				if err := os.Chmod(filepath.Dir(path), 0o770); err != nil {
					t.Fatal(err)
				}
			case "unpublished-directory":
				if err := os.Chmod(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(path, 0o770); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(manifestPath, manifestPath+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(manifestPath+".original", manifestPath); err != nil {
					t.Fatal(err)
				}
			case "manifest-mode":
				if err := os.Chmod(manifestPath, 0o640); err != nil {
					t.Fatal(err)
				}
			case "oversize", "generation", "version":
				manifest := lineageSpoolManifest{Version: "tetragon-spool-v1", RecordFormat: "zasp-tetragon-record-v1", Source: generation.source}
				if kind == "generation" {
					manifest.Source.GenerationID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
				}
				if kind == "version" {
					manifest.RecordFormat = "untrusted-v2"
				}
				data, _ := json.Marshal(manifest)
				if kind == "oversize" {
					data = bytes.Repeat([]byte{'x'}, 4097)
				}
				if err := os.Chmod(manifestPath, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifestPath, data, 0o440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(manifestPath, 0o440); err != nil {
					t.Fatal(err)
				}
			}
			reader, err := newLineageSpoolReader(path, binding, owner)
			if reader != nil {
				reader.Close()
			}
			if err == nil {
				t.Fatal("unsafe/foreign manifest admitted")
			}
		})
	}
}

func TestLineageSpoolReaderRejectsMissingMiddleAndFalseSeal(t *testing.T) {
	for _, kind := range []string{"missing-middle", "seal-count", "complete-coverage", "unknown-file", "special-file"} {
		t.Run(kind, func(t *testing.T) {
			generation, path := lineageSpoolReaderFixture(t)
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			for i := 0; i < 2; i++ {
				if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
					t.Fatal(err)
				}
			}
			if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
				t.Fatal(err)
			}
			reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			switch kind {
			case "missing-middle":
				if err := os.Rename(filepath.Join(path, "chunk-0000000001.jsonl"), filepath.Join(filepath.Dir(path), "held-chunk")); err != nil {
					t.Fatal(err)
				}
			case "seal-count", "complete-coverage":
				sealPath := filepath.Join(path, "closed.json")
				data, err := os.ReadFile(sealPath)
				if err != nil {
					t.Fatal(err)
				}
				data = bytes.Replace(data, []byte(`"records":2`), []byte(`"records":3`), 1)
				if kind == "complete-coverage" {
					data = bytes.Replace(data, []byte(`"records":3`), []byte(`"records":2`), 1)
					data = bytes.Replace(data, []byte(`"coverage_complete":false`), []byte(`"coverage_complete":true`), 1)
				}
				if err := os.Chmod(sealPath, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sealPath, data, 0o440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(sealPath, 0o440); err != nil {
					t.Fatal(err)
				}
			case "unknown-file":
				if err := os.WriteFile(filepath.Join(path, "chunk-0000000129.jsonl"), []byte("bad"), 0o440); err != nil {
					t.Fatal(err)
				}
			case "special-file":
				if err := os.Mkdir(filepath.Join(path, "chunk-0000000003.jsonl"), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if _, found, err := reader.ReadSeal(); err == nil || found {
				t.Fatal("inconsistent closure accepted")
			}
			if kind == "missing-middle" {
				if _, found, err := reader.ReadChunk(1); err == nil || found {
					t.Fatal("gap treated as pending")
				}
			}
		})
	}
}

func TestLineageSpoolReaderMissingUnsealedChunkIsGapWhenLaterChunkExists(t *testing.T) {
	generation, path := lineageSpoolReaderFixture(t)
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	for i := 0; i < 2; i++ {
		if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := os.Rename(filepath.Join(path, "chunk-0000000001.jsonl"), filepath.Join(filepath.Dir(path), "held-chunk")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := reader.ReadChunk(1); err == nil || found {
		t.Fatal("unsealed gap treated as pending")
	}
}

func TestLineageSpoolReaderPinsNamedGenerationAndManifest(t *testing.T) {
	for _, kind := range []string{"directory", "manifest"} {
		t.Run(kind, func(t *testing.T) {
			generation, path := lineageSpoolReaderFixture(t)
			reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if kind == "directory" {
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatal(err)
				}
			} else {
				manifest := filepath.Join(path, "manifest.json")
				data, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(manifest, manifest+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, data, 0o440); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := reader.ReadChunk(1); err == nil {
				t.Fatal("reader accepted replaced source identity")
			}
			if _, _, err := reader.ReadSeal(); err == nil {
				t.Fatal("reader accepted replaced closure identity")
			}
		})
	}
}

func TestLineageSpoolReaderObservesPendingPublicationWithoutProducerLock(t *testing.T) {
	generation, path := lineageSpoolReaderFixture(t)
	reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	observed := false
	ctx := lineagePublicationContext{Context: context.Background(), path: filepath.Join(path, ".pending"), action: func() {
		observed = true
		if _, found, err := reader.ReadChunk(1); err != nil || found {
			t.Error("pending chunk treated as committed")
		}
		if _, found, err := reader.ReadSeal(); err != nil || found {
			t.Error("pending chunk treated as closure")
		}
	}}
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(ctx, [][]byte{line}); err != nil || !observed {
		t.Fatal("publication boundary not exercised")
	}
	if _, found, err := reader.ReadChunk(1); err != nil || !found {
		t.Fatal("published chunk not readable")
	}
	if _, found, err := reader.ReadSeal(); err != nil || found {
		t.Fatal("unsealed history marked complete")
	}
}
