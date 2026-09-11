package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLineageRecoveryRejectsConflictsWithoutChangingEvidence(t *testing.T) {
	for _, mutation := range []string{"active", "source", "hole", "unknown file", "wrong sequence", "wrong manifest", "bad payload", "wrong seal", "mode", "symlink", "hardlink", "oversize fragment", "sealed extra fragment", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			generation, path := lineageSpoolReaderFixture(t)
			spool, source := generation.spool, generation.source
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			chunk, err := generation.Append(context.Background(), [][]byte{line})
			if err != nil {
				t.Fatal(err)
			}
			chunkPath := filepath.Join(path, chunk.Name)
			original, err := os.ReadFile(chunkPath)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "sealed extra fragment" {
				if err := generation.Seal(context.Background(), "shutdown", 0, 0); err != nil {
					t.Fatal(err)
				}
			}
			if mutation != "active" {
				generation.Close()
			}
			pending := filepath.Join(path, ".pending")
			ctx := context.Background()
			switch mutation {
			case "source":
				source.BootID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "hole":
				if err := os.Rename(chunkPath, filepath.Join(path, "chunk-0000000002.jsonl")); err != nil {
					t.Fatal(err)
				}
			case "unknown file":
				if err := os.WriteFile(filepath.Join(path, "extra"), []byte("preserve"), 0440); err != nil {
					t.Fatal(err)
				}
			case "wrong sequence", "wrong manifest", "bad payload":
				head, payload, _ := bytes.Cut(original, []byte{'\n'})
				var header lineageChunkHeader
				if json.Unmarshal(head, &header) != nil {
					t.Fatal("header")
				}
				header.Sequence = 2
				if mutation == "wrong sequence" {
					header.Sequence = 1
				}
				if mutation == "wrong manifest" {
					header.Manifest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				}
				if mutation == "bad payload" {
					payload = bytes.Repeat([]byte{'x'}, len(payload))
				}
				head, _ = json.Marshal(header)
				if err := os.WriteFile(pending, append(append(head, '\n'), payload...), 0440); err != nil {
					t.Fatal(err)
				}
			case "wrong seal":
				seal := lineageSpoolSeal{Version: "tetragon-spool-closed-v1", Manifest: lineageHash(generation.manifestBytes), Reason: "shutdown", Chunks: 1, Records: 999, Bytes: int64(len(line) + 1)}
				raw, _ := json.Marshal(seal)
				if err := os.WriteFile(pending, raw, 0440); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(chunkPath, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				target := filepath.Join(t.TempDir(), "source")
				if err := os.Rename(chunkPath, target); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if mutation == "symlink" {
					link = os.Symlink
				}
				if err := link(target, chunkPath); err != nil {
					t.Fatal(err)
				}
			case "oversize fragment":
				if err := os.WriteFile(pending, make([]byte, lineageChunkBytes+1025), 0600); err != nil {
					t.Fatal(err)
				}
			case "sealed extra fragment":
				if err := os.WriteFile(filepath.Join(path, "interrupted.bin"), []byte("unexpected"), 0440); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := recoveryEvidence(t, path)
			if complete, err := spool.SealInterrupted(ctx, source); err == nil || complete {
				t.Fatal("conflicting source recovered", err)
			}
			after := recoveryEvidence(t, path)
			if !bytes.Equal(before, after) {
				t.Fatal("rejection changed evidence")
			}
		})
	}
}

func recoveryEvidence(t *testing.T, path string) []byte {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var result []byte
	for _, entry := range entries {
		result = append(result, entry.Name()...)
		info, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, info.Mode().String()...)
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(filepath.Join(path, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, raw...)
		}
	}
	return result
}

type lineageRecoveryBoundaryContext struct {
	context.Context
	path, stage string
	action      func()
	fired       bool
}

func (ctx *lineageRecoveryBoundaryContext) Err() error {
	name := map[string]string{"fragment": "interrupted.bin", "chunk": "chunk-0000000002.jsonl", "scratch": ".pending", "written scratch": ".pending", "seal": "closed.json"}[ctx.stage]
	info, err := os.Lstat(filepath.Join(ctx.path, name))
	if !ctx.fired && err == nil && (ctx.stage != "written scratch" || info.Size() > 0) {
		ctx.fired = true
		ctx.action()
	}
	return ctx.Context.Err()
}

func TestLineageRecoveryAbruptChild(t *testing.T) {
	path := os.Getenv("ZASP_TEST_RECOVERY_PATH")
	if path == "" {
		return
	}
	spool, err := newLineageSpool(filepath.Dir(path), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &lineageRecoveryBoundaryContext{Context: context.Background(), path: path, stage: os.Getenv("ZASP_TEST_RECOVERY_STAGE"), action: func() { os.Exit(73) }}
	spool.SealInterrupted(ctx, lineageSpoolSource())
	t.Fatal("child didn't reach recovery boundary")
}

func TestLineageRecoveryRestartsAcrossPublicationBoundaries(t *testing.T) {
	for _, crash := range []bool{false, true} {
		for _, stage := range []string{"fragment", "chunk", "scratch", "written scratch", "seal"} {
			mode := "cancellation/"
			if crash {
				mode = "process death/"
			}
			t.Run(mode+stage, func(t *testing.T) {
				generation, path := lineageSpoolReaderFixture(t)
				line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
				if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
					t.Fatal(err)
				}
				if stage == "fragment" {
					if err := os.WriteFile(filepath.Join(path, ".pending"), []byte(`{"version":"tetragon-`), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "chunk" {
					chunk, err := generation.Append(context.Background(), [][]byte{line})
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(filepath.Join(path, chunk.Name), filepath.Join(path, ".pending")); err != nil {
						t.Fatal(err)
					}
				}
				generation.Close()
				spool := generation.spool
				if crash {
					spool.Close()
					binary, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, binary, "-test.run=^TestLineageRecoveryAbruptChild$")
					cmd.Env = append(os.Environ(), "ZASP_TEST_RECOVERY_PATH="+path, "ZASP_TEST_RECOVERY_STAGE="+stage)
					output, err := cmd.CombinedOutput()
					if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
						t.Fatalf("unexpected child outcome: %v %s", err, output)
					}
				} else {
					base, cancel := context.WithCancel(context.Background())
					ctx := &lineageRecoveryBoundaryContext{Context: base, path: path, stage: stage, action: cancel}
					if complete, err := spool.SealInterrupted(ctx, generation.source); err == nil || complete || !ctx.fired {
						t.Fatal("cancellation didn't stop recovery", err)
					}
					cancel()
					spool.Close()
				}
				spool, err := newLineageSpool(filepath.Dir(path), uint32(os.Getuid()))
				if err != nil {
					t.Fatal(err)
				}
				defer spool.Close()
				if done, err := spool.SealInterrupted(context.Background(), generation.source); err != nil || !done {
					t.Fatal("restart failed", err)
				}
				reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				seal, found, err := reader.ReadSeal()
				want := 1
				if stage == "chunk" {
					want = 2
				}
				if err != nil || !found || seal.Records != want || !seal.CountersUnknown || seal.CoverageComplete {
					t.Fatal("recovery lost prefix", seal, err)
				}
			})
		}
	}
}

func TestLineageRecoveryRechecksEvidenceDuringSealPublication(t *testing.T) {
	for _, mutation := range []string{"manifest replaced", "chunk replaced", "generation detached", "unexpected fragment"} {
		t.Run(mutation, func(t *testing.T) {
			generation, path := lineageSpoolReaderFixture(t)
			line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
			if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
				t.Fatal(err)
			}
			generation.Close()
			actualPath := path
			ctx := &lineageRecoveryBoundaryContext{Context: context.Background(), path: path, stage: "scratch", action: func() {
				switch mutation {
				case "manifest replaced", "chunk replaced":
					name := "manifest.json"
					if mutation == "chunk replaced" {
						name = "chunk-0000000001.jsonl"
					}
					original := filepath.Join(path, name)
					raw, err := os.ReadFile(original)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(original, filepath.Join(t.TempDir(), name)); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(original, raw, 0440); err != nil {
						t.Fatal(err)
					}
				case "generation detached":
					actualPath = path + ".detached"
					if err := os.Rename(path, actualPath); err != nil {
						t.Fatal(err)
					}
				case "unexpected fragment":
					if err := os.WriteFile(filepath.Join(path, "interrupted.bin"), []byte("not admitted"), 0440); err != nil {
						t.Fatal(err)
					}
				}
			}}
			if done, err := generation.spool.SealInterrupted(ctx, generation.source); err == nil || done || !ctx.fired {
				t.Fatal("changed source sealed", err)
			}
			if _, err := os.Lstat(filepath.Join(actualPath, "closed.json")); !os.IsNotExist(err) {
				t.Fatal("invalid seal published", err)
			}
			if _, err := os.Lstat(filepath.Join(actualPath, ".pending")); err != nil {
				t.Fatal("uncertain scratch lost", err)
			}
		})
	}
}

func TestLineageRecoveryMaximumChunkInventory(t *testing.T) {
	generation, path := lineageSpoolReaderFixture(t)
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	for sequence := 1; sequence <= lineageSpoolChunks; sequence++ {
		if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(path, ".pending"), []byte(`{"version":"tetragon-`), 0600); err != nil {
		t.Fatal(err)
	}
	generation.Close()
	if done, err := generation.spool.SealInterrupted(context.Background(), generation.source); err != nil || !done {
		t.Fatal("maximum inventory recovery failed", err)
	}
	reader, err := newLineageSpoolReader(path, generation.source.EnrollmentBinding, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	seal, found, err := reader.ReadSeal()
	if err != nil || !found || seal.Chunks != lineageSpoolChunks || seal.Records != lineageSpoolChunks || seal.InterruptedDigest == "" || !seal.CountersUnknown {
		t.Fatal("maximum inventory lost evidence", seal, err)
	}
}
