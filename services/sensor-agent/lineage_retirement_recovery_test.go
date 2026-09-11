package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var retirementBoundaries = []string{"checkpoint removed", "retirement scratch", "retirement published", "completion removed", "retirement removed"}

type lineageRetirementBoundaryContext struct {
	context.Context
	spool, acks, cursor, id, stage string
	fired                          bool
	action                         func()
}

func (ctx *lineageRetirementBoundaryContext) Err() error {
	if !ctx.fired {
		exists := func(path string) bool { _, err := os.Lstat(path); return err == nil }
		ackPath := filepath.Join(ctx.acks, "ack-"+ctx.id+".json")
		ack, err := os.ReadFile(ackPath)
		retired := err == nil && bytes.Contains(ack, []byte(`"version":"tetragon-retirement-ack-v1"`))
		marked := exists(filepath.Join(ctx.spool, "reclaim-"+ctx.id+".json"))
		at := false
		switch ctx.stage {
		case "checkpoint removed":
			at = !exists(ctx.cursor) && marked && !retired
		case "retirement scratch":
			at = exists(filepath.Join(ctx.acks, ".pending")) && !retired
		case "retirement published":
			at = retired && marked
		case "completion removed":
			at = retired && !marked
		case "retirement removed":
			at = !exists(ackPath) && !marked
		}
		if at {
			ctx.fired = true
			ctx.action()
		}
	}
	return ctx.Context.Err()
}

type lineageRetirementProcessFixture struct {
	Spool, Acks, Cursor, Stage string
	Request                    lineageReclaimRequest
}

func runRetirementStages(ctx context.Context, fixture lineageRetirementProcessFixture) error {
	spool, err := newLineageSpool(fixture.Spool, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer spool.Close()
	store, err := newLineageAcknowledgments(fixture.Acks)
	if err != nil {
		return err
	}
	defer store.Close()
	completion, err := newLineageCompletionReader(fixture.Spool, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer completion.Close()
	receipts, err := newLineageReceiptReader(fixture.Acks, uint32(os.Geteuid()))
	if err != nil {
		return err
	}
	defer receipts.Close()
	if _, err := store.RetireAcknowledgment(ctx, completion, fixture.Request, fixture.Cursor, 16, nil); err != nil {
		return err
	}
	if _, err := spool.CollectCompletion(ctx, receipts, fixture.Request); err != nil {
		return err
	}
	if complete, err := store.ForgetRetirement(ctx, completion, fixture.Request); err != nil {
		return err
	} else if !complete {
		return errLineageSpool
	}
	return nil
}

func TestLineageRetirementProcessDeathChild(t *testing.T) {
	path := os.Getenv("ZASP_TEST_RETIREMENT_PATH")
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8192 {
		t.Fatal(err)
	}
	var fixture lineageRetirementProcessFixture
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture")
	}
	ctx := &lineageRetirementBoundaryContext{Context: context.Background(), spool: fixture.Spool, acks: fixture.Acks, cursor: fixture.Cursor, id: fixture.Request.Source.GenerationID, stage: fixture.Stage, action: func() { os.Exit(73) }}
	if err := runRetirementStages(ctx, fixture); err != nil {
		t.Fatal(err)
	}
	t.Fatal("death boundary not reached")
}

func TestLineageRetirementRecoversAtEveryHandshakeBoundary(t *testing.T) {
	for _, processDeath := range []bool{false, true} {
		for _, stage := range retirementBoundaries {
			t.Run(map[bool]string{false: "cancellation/", true: "process death/"}[processDeath]+stage, func(t *testing.T) {
				fixture, store, reader := lineageCompletionFixture(t, false)
				wire := lineageRetirementProcessFixture{Spool: fixture.generation.spool.root.Name(), Acks: fixture.ackPath, Cursor: fixture.cursor, Request: reclaimFixtureRequest(fixture), Stage: stage}
				store.Close()
				reader.Close()
				fixture.generation.spool.Close()
				fixture.receipts.Close()
				if processDeath {
					path := filepath.Join(t.TempDir(), "retirement.json")
					raw, _ := json.Marshal(wire)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					child := exec.Command(os.Args[0], "-test.run=^TestLineageRetirementProcessDeathChild$", "-test.timeout=20s")
					child.Env = append(os.Environ(), "ZASP_TEST_RETIREMENT_PATH="+path)
					output, err := child.CombinedOutput()
					var failure *exec.ExitError
					if !errors.As(err, &failure) || failure.ExitCode() != 73 {
						t.Fatalf("boundary child: %v %s", err, output)
					}
				} else {
					base, cancel := context.WithCancel(context.Background())
					defer cancel()
					ctx := &lineageRetirementBoundaryContext{Context: base, spool: wire.Spool, acks: wire.Acks, cursor: wire.Cursor, id: wire.Request.Source.GenerationID, stage: stage, action: cancel}
					if err := runRetirementStages(ctx, wire); err == nil || !ctx.fired {
						t.Fatal("canceled handshake reported clean", err)
					}
				}
				if err := runRetirementStages(context.Background(), wire); err != nil {
					t.Fatal("restart did not finish cleanup", err)
				}
				for _, path := range []string{wire.Spool, wire.Acks, filepath.Dir(wire.Cursor)} {
					entries, err := os.ReadDir(path)
					if err != nil || len(entries) != 1 {
						t.Fatal("metadata leak after restart", path, err)
					}
				}
			})
		}
	}
}
