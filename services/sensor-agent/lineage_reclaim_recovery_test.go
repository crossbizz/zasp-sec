package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var reclaimBoundaries = []string{"intent scratch", "intent", "rename", "first deletion", "seal deletion", "last file", "directory removal", "completion scratch", "completion"}

type lineageReclaimBoundaryContext struct {
	context.Context
	path, id, stage string
	action          func()
	fired           bool
}

func (ctx *lineageReclaimBoundaryContext) Err() error {
	if !ctx.fired {
		exists := func(name string) bool { _, err := os.Lstat(filepath.Join(ctx.path, name)); return err == nil }
		original := exists("generation-" + ctx.id)
		tomb := ".reclaim-" + ctx.id
		tombExists := exists(tomb)
		marker, markerErr := os.ReadFile(filepath.Join(ctx.path, "reclaim-"+ctx.id+".json"))
		marked := markerErr == nil
		complete := bytes.Contains(marker, []byte(`"complete":true`))
		pending := exists(".reclaim.pending")
		at := false
		switch ctx.stage {
		case "intent scratch":
			at = pending && !marked
		case "intent":
			at = marked && !complete && original
		case "rename":
			at = tombExists && !original
		case "first deletion":
			at = tombExists && !exists(filepath.Join(tomb, "chunk-0000000001.jsonl")) && exists(filepath.Join(tomb, "closed.json"))
		case "seal deletion":
			at = tombExists && !exists(filepath.Join(tomb, "closed.json")) && exists(filepath.Join(tomb, "manifest.json"))
		case "last file":
			at = tombExists && !exists(filepath.Join(tomb, "manifest.json"))
		case "directory removal":
			at = marked && !complete && !original && !tombExists && !pending
		case "completion scratch":
			at = marked && !original && !tombExists && pending
		case "completion":
			at = complete
		}
		if at {
			ctx.fired = true
			ctx.action()
		}
	}
	return ctx.Context.Err()
}

func TestLineageReclaimResumesEveryCancellationBoundary(t *testing.T) {
	for _, stage := range reclaimBoundaries {
		t.Run(stage, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			path := fixture.generation.spool.root.Name()
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &lineageReclaimBoundaryContext{Context: base, path: path, id: request.Source.GenerationID, stage: stage, action: cancel}
			if complete, err := fixture.generation.spool.ReclaimAcknowledged(ctx, fixture.receipts, request); err == nil || complete || !ctx.fired {
				t.Fatal("cancellation boundary not exercised", complete, err)
			}
			fixture.generation.spool.Close()
			spool, err := newLineageSpool(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			var receipts *lineageReceiptReader
			if stage == "intent scratch" {
				receipts = fixture.receipts
			}
			if complete, err := spool.ReclaimAcknowledged(context.Background(), receipts, request); err != nil || !complete {
				t.Fatal("restart could not finish bounded operation", err)
			}
		})
	}
}

func TestLineageReclaimResumesEveryProcessDeathBoundary(t *testing.T) {
	if path := os.Getenv("ZASP_TEST_RECLAIM_PATH"); path != "" {
		spool, err := newLineageSpool(path, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		receipts, err := newLineageReceiptReader(os.Getenv("ZASP_TEST_RECLAIM_ACKS"), uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		request := lineageReclaimRequest{Source: lineageSpoolSource(), Destination: "https://runtime.example.test/internal/v1/runtime/events", ConsumerUID: uint32(os.Geteuid())}
		ctx := &lineageReclaimBoundaryContext{Context: context.Background(), path: path, id: request.Source.GenerationID, stage: os.Getenv("ZASP_TEST_RECLAIM_STAGE"), action: func() { os.Exit(73) }}
		_, _ = spool.ReclaimAcknowledged(ctx, receipts, request)
		t.Fatal("process-death boundary not reached")
	}
	for _, stage := range reclaimBoundaries {
		t.Run(stage, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			path := fixture.generation.spool.root.Name()
			fixture.generation.spool.Close()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageReclaimResumesEveryProcessDeathBoundary$")
			child.WaitDelay = time.Second
			child.Env = append(os.Environ(), "ZASP_TEST_RECLAIM_PATH="+path, "ZASP_TEST_RECLAIM_ACKS="+fixture.ackPath, "ZASP_TEST_RECLAIM_STAGE="+stage)
			output, err := child.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("child failed outside boundary: %v %s", err, output)
			}
			spool, err := newLineageSpool(path, uint32(os.Geteuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			var receipts *lineageReceiptReader
			if stage == "intent scratch" {
				receipts = fixture.receipts
			}
			if complete, err := spool.ReclaimAcknowledged(context.Background(), receipts, request); err != nil || !complete {
				t.Fatal("dead process operation did not resume", err)
			}
		})
	}
}

func prepareInterruptedReclaim(t *testing.T, stage string) (lineageReceiptFixtureState, lineageReclaimRequest) {
	t.Helper()
	fixture := lineageReceiptFixture(t, false)
	request := reclaimFixtureRequest(fixture)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &lineageReclaimBoundaryContext{Context: base, path: fixture.generation.spool.root.Name(), id: request.Source.GenerationID, stage: stage, action: cancel}
	if complete, err := fixture.generation.spool.ReclaimAcknowledged(ctx, fixture.receipts, request); err == nil || complete || !ctx.fired {
		t.Fatal("interruption preparation failed", err)
	}
	return fixture, request
}

func TestLineageReclaimRejectsAlteredResumeStateBeforeDeletingAnyRemainingFile(t *testing.T) {
	for _, mutation := range []string{"missing original chunk", "unknown tombstone file", "changed tombstone file", "replaced tombstone file", "symlink tombstone file", "hardlink tombstone file", "wrong mode", "replaced directory", "both directories", "orphan tombstone", "changed marker", "unrelated scratch", "wrong issuer", "wrong destination"} {
		t.Run(mutation, func(t *testing.T) {
			stage := "rename"
			if mutation == "missing original chunk" {
				stage = "intent"
			}
			fixture, request := prepareInterruptedReclaim(t, stage)
			spool := fixture.generation.spool
			parent := spool.root.Name()
			tomb := filepath.Join(parent, ".reclaim-"+request.Source.GenerationID)
			original := filepath.Join(parent, "generation-"+request.Source.GenerationID)
			target := filepath.Join(tomb, "chunk-0000000001.jsonl")
			switch mutation {
			case "missing original chunk":
				if err := os.Remove(filepath.Join(original, "chunk-0000000001.jsonl")); err != nil {
					t.Fatal(err)
				}
			case "unknown tombstone file":
				if err := os.WriteFile(filepath.Join(tomb, "unknown"), []byte("preserve"), 0440); err != nil {
					t.Fatal(err)
				}
			case "changed tombstone file":
				if err := os.Chmod(target, 0640); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte("changed"), 0440); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, 0440); err != nil {
					t.Fatal(err)
				}
			case "replaced tombstone file", "symlink tombstone file", "hardlink tombstone file":
				raw, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				retained := filepath.Join(t.TempDir(), "retained")
				if err := os.Rename(target, retained); err != nil {
					t.Fatal(err)
				}
				if mutation == "replaced tombstone file" {
					err = os.WriteFile(target, raw, 0440)
				} else if mutation == "symlink tombstone file" {
					err = os.Symlink(retained, target)
				} else {
					err = os.Link(retained, target)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "wrong mode":
				if err := os.Chmod(target, 0640); err != nil {
					t.Fatal(err)
				}
			case "replaced directory":
				if err := os.Rename(tomb, tomb+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(tomb, 0750); err != nil {
					t.Fatal(err)
				}
			case "both directories":
				if err := os.Mkdir(original, 0750); err != nil {
					t.Fatal(err)
				}
			case "orphan tombstone":
				if err := os.Remove(filepath.Join(parent, "reclaim-"+request.Source.GenerationID+".json")); err != nil {
					t.Fatal(err)
				}
			case "changed marker":
				file := filepath.Join(parent, "reclaim-"+request.Source.GenerationID+".json")
				if err := os.Chmod(file, 0640); err != nil {
					t.Fatal(err)
				}
			case "unrelated scratch":
				if err := os.WriteFile(filepath.Join(parent, ".reclaim.pending"), []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong issuer":
				request.ConsumerUID++
			case "wrong destination":
				request.Destination = "https://other.example.test/internal/v1/runtime/events"
			}
			remaining := tomb
			if stage == "intent" {
				remaining = original
			}
			if mutation == "replaced directory" {
				remaining = tomb + ".old"
			}
			entries, err := os.ReadDir(remaining)
			if err != nil {
				t.Fatal(err)
			}
			if complete, err := spool.ReclaimAcknowledged(context.Background(), nil, request); err == nil || complete {
				t.Fatal("altered source resumed", mutation, err)
			}
			after, err := os.ReadDir(remaining)
			if err != nil || len(after) != len(entries) {
				t.Fatal("validation failure deleted remaining files", err)
			}
		})
	}
}

func TestLineageReclaimRejectsCopiedIntentInAnotherSpool(t *testing.T) {
	fixture, request := prepareInterruptedReclaim(t, "rename")
	other, err := newLineageSpool(t.TempDir(), uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	name := "reclaim-" + request.Source.GenerationID + ".json"
	raw, err := os.ReadFile(filepath.Join(fixture.generation.spool.root.Name(), name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other.root.Name(), name), raw, 0440); err != nil {
		t.Fatal(err)
	}
	tomb := ".reclaim-" + request.Source.GenerationID
	if err := os.Rename(filepath.Join(fixture.generation.spool.root.Name(), tomb), filepath.Join(other.root.Name(), tomb)); err != nil {
		t.Fatal(err)
	}
	if complete, err := other.ReclaimAcknowledged(context.Background(), nil, request); err == nil || complete {
		t.Fatal("copied intent admitted by different spool")
	}
	entries, err := os.ReadDir(filepath.Join(other.root.Name(), tomb))
	if err != nil || len(entries) != 3 {
		t.Fatal("copied intent deleted source", err)
	}
}
