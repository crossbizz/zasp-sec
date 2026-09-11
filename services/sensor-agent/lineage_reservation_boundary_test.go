package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLineageReservationRecognizesEveryCanonicalManifestPrefix(t *testing.T) {
	for _, node := range []string{"node-a", strings.Repeat("n", 253)} {
		source := lineageSpoolSource()
		source.NodeName = node
		raw, err := lineageManifestBytes(source)
		if err != nil {
			t.Fatal(err)
		}
		for size := 0; size <= len(raw); size++ {
			if !validLineageReservationMetadata(".pending", raw[:size], source.GenerationID) {
				t.Fatalf("canonical prefix %d/%d rejected", size, len(raw))
			}
			if size < len(raw) && validLineageReservationMetadata("manifest.json", raw[:size], source.GenerationID) {
				t.Fatal("incomplete final manifest accepted", size)
			}
		}
		for _, bad := range [][]byte{[]byte(`{"version":"tetragon-spool-chunk-v1"`), []byte(`{"version":null}`), append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(source.GenerationID), []byte("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), 1), bytes.Replace(raw, []byte(`"enrollment_binding":"b`), []byte(`"enrollment_binding":"z`), 1), bytes.Replace(raw, []byte(`"cluster_uid":"c`), []byte(`"cluster_uid":"Z`), 1)} {
			if validLineageReservationMetadata(".pending", bad, source.GenerationID) {
				t.Fatal("invalid startup metadata admitted", string(bad))
			}
		}
	}
}

func TestLineageReservationDiscardRejectsAmbiguousState(t *testing.T) {
	for _, mutation := range []string{"unknown file", "chunk", "both metadata", "bad prefix", "wrong id", "mode", "hardlink", "symlink", "directory mode", "public conflict", "oversize", "legacy public"} {
		t.Run(mutation, func(t *testing.T) {
			spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			source := lineageSpoolSource()
			path := filepath.Join(spool.root.Name(), ".creating-"+source.GenerationID)
			if mutation == "legacy public" {
				path = filepath.Join(spool.root.Name(), "generation-"+source.GenerationID)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			raw, _ := lineageManifestBytes(source)
			metadata := filepath.Join(path, ".pending")
			if mutation == "wrong id" {
				raw = bytes.Replace(raw, []byte(source.GenerationID), []byte("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), 1)
			}
			if mutation == "bad prefix" {
				raw = []byte(`{"version":"tetragon-spool-chunk-v1"`)
			}
			if mutation == "oversize" {
				raw = make([]byte, 4097)
			}
			if err := os.WriteFile(metadata, raw, 0600); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "unknown file", "chunk", "both metadata":
				name := map[string]string{"unknown file": "unexpected", "chunk": "chunk-0000000001.jsonl", "both metadata": "manifest.json"}[mutation]
				if err := os.WriteFile(filepath.Join(path, name), raw, 0440); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(metadata, 0660); err != nil {
					t.Fatal(err)
				}
			case "directory mode":
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			case "hardlink", "symlink":
				target := filepath.Join(t.TempDir(), "metadata")
				if err := os.Rename(metadata, target); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if mutation == "symlink" {
					link = os.Symlink
				}
				if err := link(target, metadata); err != nil {
					t.Fatal(err)
				}
			case "public conflict":
				if err := os.Mkdir(filepath.Join(spool.root.Name(), "generation-"+source.GenerationID), 0750); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryEvidence(t, path)
			done, err := spool.DiscardUnpublished(context.Background(), source.GenerationID)
			if done || mutation != "legacy public" && err == nil {
				t.Fatal("ambiguous startup discarded", err)
			}
			if !bytes.Equal(before, recoveryEvidence(t, path)) {
				t.Fatal("rejection changed startup evidence")
			}
		})
	}
}

type lineageDiscardContext struct {
	context.Context
	spool, id, stage string
	action           func()
	fired            bool
}

func (ctx *lineageDiscardContext) Err() error {
	tomb := filepath.Join(ctx.spool, ".discard-"+ctx.id)
	_, tombErr := os.Lstat(tomb)
	_, metadataErr := os.Lstat(filepath.Join(tomb, "manifest.json"))
	_, privateErr := os.Lstat(filepath.Join(ctx.spool, ".creating-"+ctx.id))
	ready := ctx.stage == "renamed" && tombErr == nil || ctx.stage == "metadata removed" && tombErr == nil && os.IsNotExist(metadataErr) || ctx.stage == "directory removed" && os.IsNotExist(tombErr) && os.IsNotExist(privateErr)
	if !ctx.fired && ready {
		ctx.fired = true
		ctx.action()
	}
	return ctx.Context.Err()
}

func TestLineageReservationRejectsLatePublicConflict(t *testing.T) {
	spool, err := newLineageSpool(t.TempDir(), uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	source := lineageSpoolSource()
	path := filepath.Join(spool.root.Name(), ".creating-"+source.GenerationID)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := lineageManifestBytes(source)
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), raw, 0440); err != nil {
		t.Fatal(err)
	}
	ctx := &lineageDiscardContext{Context: context.Background(), spool: spool.root.Name(), id: source.GenerationID, stage: "renamed", action: func() {
		if err := os.Mkdir(filepath.Join(spool.root.Name(), "generation-"+source.GenerationID), 0750); err != nil {
			t.Fatal(err)
		}
	}}
	if done, err := spool.DiscardUnpublished(ctx, source.GenerationID); err == nil || done || !ctx.fired {
		t.Fatal("late public conflict not rejected", err)
	}
	got, err := os.ReadFile(filepath.Join(spool.root.Name(), ".discard-"+source.GenerationID, "manifest.json"))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("conflict deleted pinned metadata", err)
	}
}

func TestLineageReservationCrashChild(t *testing.T) {
	path := os.Getenv("ZASP_TEST_RESERVATION_PATH")
	if path == "" {
		return
	}
	spool, err := newLineageSpool(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	id := lineageSpoolSource().GenerationID
	stage := os.Getenv("ZASP_TEST_RESERVATION_STAGE")
	if os.Getenv("ZASP_TEST_RESERVATION_DISCARD") == "1" {
		spool.DiscardUnpublished(&lineageDiscardContext{Context: context.Background(), spool: path, id: id, stage: stage, action: func() { os.Exit(73) }}, id)
	} else {
		spool.Create(&lineageReservationContext{Context: context.Background(), spool: path, id: id, stage: stage, action: func() { os.Exit(73) }}, lineageSpoolSource())
	}
	t.Fatal("child didn't reach crash boundary")
}

func TestLineageReservationRecoversAfterActualProcessDeath(t *testing.T) {
	for _, stage := range []string{"empty", "scratch", "manifest", "readable", "published", "renamed", "metadata removed", "directory removed"} {
		t.Run(stage, func(t *testing.T) {
			path := t.TempDir()
			source := lineageSpoolSource()
			discard := stage == "renamed" || stage == "metadata removed" || stage == "directory removed"
			if discard {
				private := filepath.Join(path, ".creating-"+source.GenerationID)
				if err := os.Mkdir(private, 0700); err != nil {
					t.Fatal(err)
				}
				raw, _ := lineageManifestBytes(source)
				if err := os.WriteFile(filepath.Join(private, "manifest.json"), raw, 0440); err != nil {
					t.Fatal(err)
				}
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestLineageReservationCrashChild$")
			cmd.Env = append(os.Environ(), "ZASP_TEST_RESERVATION_PATH="+path, "ZASP_TEST_RESERVATION_STAGE="+stage)
			if discard {
				cmd.Env = append(cmd.Env, "ZASP_TEST_RESERVATION_DISCARD=1")
			}
			output, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
				t.Fatalf("wrong child outcome: %v %s", err, output)
			}
			spool, err := newLineageSpool(path, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			if stage == "published" {
				if done, err := spool.SealInterrupted(context.Background(), source); err != nil || !done {
					t.Fatal(err)
				}
			} else {
				for retry := 0; retry < 2; retry++ {
					if done, err := spool.DiscardUnpublished(context.Background(), source.GenerationID); err != nil || !done {
						t.Fatal("discard restart failed", err)
					}
				}
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 1 {
					t.Fatal("metadata slot leaked", err)
				}
			}
		})
	}
}
