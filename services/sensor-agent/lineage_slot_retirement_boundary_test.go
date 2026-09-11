package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type lineageSlotRetirementContext struct {
	context.Context
	path, acks string
	assignment lineageSlotAssignment
	stage      string
	action     func()
	fired      bool
}

func TestLineageSlotRetirementRecoversAfterActualProcessDeath(t *testing.T) {
	if path := os.Getenv("ZASP_TEST_SLOT_RETIRE_PATH"); path != "" {
		producer, err := newLineageCompletionReader(os.Getenv("ZASP_TEST_SLOT_RETIRE_PRODUCER"), uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		acks, err := newLineageAcknowledgments(os.Getenv("ZASP_TEST_SLOT_RETIRE_ACKS"))
		if err != nil {
			t.Fatal(err)
		}
		slots, err := newLineageConsumerSlots(path, lineageSlotConfig{EnrollmentBinding: lineageSpoolSource().EnrollmentBinding, Destination: "https://runtime.example.test/internal/v1/runtime/events", Producer: producer, Acknowledgments: acks})
		if err != nil {
			t.Fatal(err)
		}
		list, err := slots.List(context.Background())
		if err != nil || len(list) != 1 {
			t.Fatal("child assignment missing", err)
		}
		assignment := list[0]
		stage := os.Getenv("ZASP_TEST_SLOT_RETIRE_STAGE")
		ctx := &lineageSlotRetirementContext{Context: context.Background(), path: path, acks: acks.root.Name(), assignment: assignment, stage: stage, action: func() { os.Exit(73) }}
		if stage == "ACK forgotten" || stage == "assignment removed" || stage == "evidence removed" {
			slots.Release(ctx, assignment)
		} else {
			slots.Retire(ctx, assignment, 16)
		}
		t.Fatal("crash boundary wasn't reached")
	}
	for _, stage := range []string{"evidence scratch", "evidence published", "checkpoint removed", "ACK retired", "phase scratch", "phase published", "ACK forgotten", "assignment removed", "evidence removed"} {
		t.Run(stage, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			release := stage == "ACK forgotten" || stage == "assignment removed" || stage == "evidence removed"
			if release {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal(err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			path, config := slots.root.Name(), slots.config
			slots.Close()
			config.Acknowledgments.Close()
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageSlotRetirementRecoversAfterActualProcessDeath$")
			child.WaitDelay = time.Second
			child.Env = append(os.Environ(), "ZASP_TEST_SLOT_RETIRE_PATH="+path, "ZASP_TEST_SLOT_RETIRE_PRODUCER="+fixture.generation.spool.root.Name(), "ZASP_TEST_SLOT_RETIRE_ACKS="+fixture.ackPath, "ZASP_TEST_SLOT_RETIRE_STAGE="+stage)
			output, err := child.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("child exited outside boundary %v %s", err, output)
			}
			config.Acknowledgments, err = newLineageAcknowledgments(fixture.ackPath)
			if err != nil {
				t.Fatal(err)
			}
			defer config.Acknowledgments.Close()
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			if !release {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal("retirement after death", done, err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			if stage == "assignment removed" {
				if list, err := slots.ListRetiring(context.Background()); err != nil || len(list) != 1 || list[0] != assignment {
					t.Fatal("orphan retirement not discoverable", list, err)
				}
			}
			if done, err := slots.Release(context.Background(), assignment); err != nil || !done {
				t.Fatal("release after death", done, err)
			}
		})
	}
}

func TestLineageSlotRetirementPreservesHostileEvidence(t *testing.T) {
	for _, kind := range []string{"foreign ACK", "retirement link", "retirement corruption", "changed assignment", "unexpected file"} {
		t.Run(kind, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
				t.Fatal(err)
			}
			if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
				t.Fatal(err)
			}
			name := filepath.Join(slots.root.Name(), lineageSlotRetirementName(assignment.Slot))
			switch kind {
			case "foreign ACK":
				name = filepath.Join(fixture.ackPath, "ack-"+assignment.Source.GenerationID+".json")
			case "changed assignment":
				name = filepath.Join(slots.root.Name(), lineageSlotName(assignment.Slot))
			case "retirement link":
				if err := os.Link(name, filepath.Join(t.TempDir(), "preserved-record")); err != nil {
					t.Fatal(err)
				}
			case "unexpected file":
				if err := os.WriteFile(filepath.Join(slots.root.Name(), "unexpected"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "foreign ACK" || kind == "retirement corruption" || kind == "changed assignment" {
				if err := os.Chmod(name, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte(`{"preserve":"foreign"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(name, 0440); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryEvidence(t, slots.root.Name())
			ackBefore := recoveryEvidence(t, fixture.ackPath)
			if done, err := slots.Release(context.Background(), assignment); err == nil || done {
				t.Fatal("hostile evidence accepted", done, err)
			}
			if !bytes.Equal(before, recoveryEvidence(t, slots.root.Name())) || !bytes.Equal(ackBefore, recoveryEvidence(t, fixture.ackPath)) {
				t.Fatal("rejection changed evidence")
			}
		})
	}
}

func (ctx *lineageSlotRetirementContext) Err() error {
	if !ctx.fired {
		record, recordErr := os.ReadFile(filepath.Join(ctx.path, lineageSlotRetirementName(ctx.assignment.Slot)))
		_, scratchErr := os.Lstat(filepath.Join(ctx.path, lineageSlotRetirementScratch(ctx.assignment)))
		ack, ackErr := os.ReadFile(filepath.Join(ctx.acks, "ack-"+ctx.assignment.Source.GenerationID+".json"))
		_, assignmentErr := os.Lstat(filepath.Join(ctx.path, lineageSlotName(ctx.assignment.Slot)))
		_, cursorErr := os.Lstat(filepath.Join(ctx.path, lineageSlotCursor(ctx.assignment.Slot)))
		retired := bytes.Contains(ack, []byte(`"version":"tetragon-retirement-ack-v1"`))
		ready := bytes.Contains(record, []byte(`"ack_retired":true`))
		at := false
		switch ctx.stage {
		case "evidence scratch":
			at = scratchErr == nil && os.IsNotExist(recordErr)
		case "evidence published":
			at = recordErr == nil && !ready && !retired
		case "checkpoint removed":
			at = recordErr == nil && os.IsNotExist(cursorErr) && !retired
		case "ACK retired":
			at = retired && !ready
		case "phase scratch":
			at = recordErr == nil && scratchErr == nil && retired && !ready
		case "phase published":
			at = ready
		case "ACK forgotten":
			at = ready && os.IsNotExist(ackErr) && assignmentErr == nil
		case "assignment removed":
			at = ready && os.IsNotExist(assignmentErr)
		case "evidence removed":
			at = os.IsNotExist(recordErr) && os.IsNotExist(assignmentErr)
		}
		if at {
			ctx.fired = true
			ctx.action()
		}
	}
	return ctx.Context.Err()
}

func TestLineageSlotRetirementRecoversEveryCancellationBoundary(t *testing.T) {
	for _, stage := range []string{"evidence scratch", "evidence published", "checkpoint removed", "ACK retired", "phase scratch", "phase published", "ACK forgotten", "assignment removed", "evidence removed"} {
		t.Run(stage, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			release := stage == "ACK forgotten" || stage == "assignment removed" || stage == "evidence removed"
			if release {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal(err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &lineageSlotRetirementContext{Context: base, path: slots.root.Name(), acks: fixture.ackPath, assignment: assignment, stage: stage, action: cancel}
			var done bool
			var err error
			if release {
				done, err = slots.Release(ctx, assignment)
			} else {
				done, err = slots.Retire(ctx, assignment, 16)
			}
			if err == nil || done || !ctx.fired {
				t.Fatal("boundary didn't interrupt operation", done, err)
			}
			path, config := slots.root.Name(), slots.config
			slots.Close()
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal("restart admission", err)
			}
			defer slots.Close()
			if !release {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal("retirement restart", done, err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			if done, err := slots.Release(context.Background(), assignment); err != nil || !done {
				t.Fatal("release restart", done, err)
			}
			if entries, err := os.ReadDir(path); err != nil || len(entries) != 2 {
				t.Fatal("restart left history", len(entries), err)
			}
		})
	}
}

func TestLineageSlotRetirementSurvivesImmediateProducerCollection(t *testing.T) {
	fixture, slots, assignment := lineageRetiringSlotFixture(t)
	ctx := &lineageSlotRetirementContext{Context: context.Background(), path: slots.root.Name(), acks: fixture.ackPath, assignment: assignment, stage: "ACK retired", action: func() {
		if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
			t.Fatal("racing producer collection", done, err)
		}
	}}
	if done, err := slots.Retire(ctx, assignment, 16); err != nil || !done || !ctx.fired {
		t.Fatal("lost completion before local phase", done, err)
	}
	if done, err := slots.Release(context.Background(), assignment); err != nil || !done {
		t.Fatal("retained proof couldn't release", done, err)
	}
}

func TestLineageSlotRetirementRejectsAncestorReplacementBeforeCheckpointDeletion(t *testing.T) {
	_, slots, assignment := lineageRetiringSlotFixture(t)
	path := slots.root.Name()
	parent := filepath.Dir(path)
	cursor := filepath.Join(path, lineageSlotCursor(assignment.Slot))
	raw, err := os.ReadFile(cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, filepath.Join(t.TempDir(), "preserved-parent")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursor, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursor+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if done, err := slots.Retire(context.Background(), assignment, 16); err == nil || done {
		t.Fatal("retirement adopted replacement cursor parent", done, err)
	}
	got, err := os.ReadFile(cursor)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("foreign checkpoint deleted", err)
	}
}

func TestLineageSlotRetirementRequiresEvidenceAndExistingCursorLock(t *testing.T) {
	for _, kind := range []string{"no evidence", "missing lock", "busy lock", "cursor reappeared"} {
		t.Run(kind, func(t *testing.T) {
			fixture, slots, assignment := lineageRetiringSlotFixture(t)
			if kind != "no evidence" {
				if done, err := slots.Retire(context.Background(), assignment, 16); err != nil || !done {
					t.Fatal(err)
				}
				if done, err := fixture.generation.spool.CollectCompletion(context.Background(), fixture.receipts, reclaimFixtureRequest(fixture)); err != nil || !done {
					t.Fatal(err)
				}
			}
			cursor := filepath.Join(slots.root.Name(), lineageSlotCursor(assignment.Slot))
			switch kind {
			case "missing lock":
				if err := os.Rename(cursor+".lock", filepath.Join(t.TempDir(), "preserved-lock")); err != nil {
					t.Fatal(err)
				}
			case "busy lock":
				file, err := os.Open(cursor + ".lock")
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			case "cursor reappeared":
				if err := os.WriteFile(cursor, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryEvidence(t, slots.root.Name())
			if done, err := slots.Release(context.Background(), assignment); done || kind != "no evidence" && err == nil {
				t.Fatal("unsafe slot release", done, err)
			}
			if !bytes.Equal(before, recoveryEvidence(t, slots.root.Name())) {
				t.Fatal("rejection changed slot state")
			}
		})
	}
}

func TestLineageSlotRetirementBlocksProcessingBeforeAcknowledgmentChanges(t *testing.T) {
	fixture, slots, assignment := lineageRetiringSlotFixture(t)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &lineageSlotRetirementContext{Context: base, path: slots.root.Name(), acks: fixture.ackPath, assignment: assignment, stage: "evidence published", action: cancel}
	if _, err := slots.Retire(ctx, assignment, 16); err == nil || !ctx.fired {
		t.Fatal(err)
	}
	if _, err := slots.CursorPath(assignment); err == nil {
		t.Fatal("retiring slot exposed processing path")
	}
	if done, err := slots.Release(context.Background(), assignment); err != nil || done {
		t.Fatal("prepared evidence permitted release", done, err)
	}
}
