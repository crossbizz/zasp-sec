package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageSlotBoundaryContext struct {
	context.Context
	path, id, stage string
	action          func()
	fired           bool
}

func (ctx *lineageSlotBoundaryContext) Err() error {
	if !ctx.fired {
		info, err := os.Lstat(filepath.Join(ctx.path, lineageSlotScratch(0, ctx.id)))
		_, finalErr := os.Lstat(filepath.Join(ctx.path, lineageSlotName(0)))
		ready := ctx.stage == "published" && finalErr == nil
		if err == nil {
			ready = ready || ctx.stage == "empty" && info.Size() == 0 || ctx.stage == "written" && info.Size() > 0 && info.Mode().Perm() == 0600 || ctx.stage == "frozen" && info.Size() > 0 && info.Mode().Perm() == 0440
		}
		if ready {
			ctx.fired = true
			ctx.action()
		}
	}
	return ctx.Context.Err()
}

func TestLineageSlotsResumeEveryPublicationBoundary(t *testing.T) {
	for _, stage := range []string{"empty", "written", "frozen", "published", "partial"} {
		t.Run(stage, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			boundary := stage
			if stage == "partial" {
				boundary = "written"
			}
			ctx := &lineageSlotBoundaryContext{Context: base, path: path, id: fixture.reader.Source().GenerationID, stage: boundary, action: cancel}
			if _, err := slots.Reserve(ctx, fixture.reader); err == nil || !ctx.fired {
				t.Fatal("publication boundary wasn't exercised", err)
			}
			slots.Close()
			if stage == "partial" {
				name := filepath.Join(path, lineageSlotScratch(0, fixture.reader.Source().GenerationID))
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, raw[:len(raw)/2], 0600); err != nil {
					t.Fatal(err)
				}
			}
			slots, err = newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			record, err := slots.Reserve(context.Background(), fixture.reader)
			if err != nil || record.Slot != 0 {
				t.Fatal("restart changed or lost slot", record, err)
			}
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 3 {
				t.Fatal("unbounded or duplicate reservation state", len(entries), err)
			}
		})
	}
}

func TestLineageSlotsRejectControllerAndCursorLockContention(t *testing.T) {
	for _, kind := range []string{"controller", "cursor"} {
		t.Run(kind, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			if kind == "controller" {
				other, err := newLineageConsumerSlots(path, config)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if _, err := other.Reserve(context.Background(), fixture.reader); err != nil {
					t.Fatal(err)
				}
			} else {
				file, err := os.OpenFile(filepath.Join(path, lineageSlotCursor(0)+".lock"), os.O_CREATE|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryEvidence(t, path)
			if _, err := slots.Reserve(context.Background(), fixture.reader); err == nil {
				t.Fatal("live writer lock bypassed")
			}
			// Taking the controller lock is allowed for a free store, but the
			// held cursor cannot be assigned or overwritten.
			if kind == "controller" && !bytes.Equal(before, recoveryEvidence(t, path)) {
				t.Fatal("controller contention mutated state")
			}
			if kind == "cursor" {
				if _, err := os.Lstat(filepath.Join(path, lineageSlotName(0))); !os.IsNotExist(err) {
					t.Fatal("busy cursor assigned", err)
				}
			}
		})
	}
}

func TestLineageSlotsRejectForeignAndMalformedHistory(t *testing.T) {
	for _, kind := range []string{"destination", "enrollment", "state copy", "unknown", "assignment link", "duplicate source", "orphan cursor", "foreign scratch"} {
		t.Run(kind, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := slots.Reserve(context.Background(), fixture.reader); err != nil {
				t.Fatal(err)
			}
			slots.Close()
			name := filepath.Join(path, lineageSlotName(0))
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "destination":
				config.Destination = "https://foreign.example.test/internal/v1/runtime/events"
			case "enrollment":
				config.EnrollmentBinding = strings.Repeat("a", 64)
			case "state copy":
				path = t.TempDir()
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, lineageSlotName(0)), raw, 0440); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(path, "unknown"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "assignment link":
				if err := os.Link(name, filepath.Join(t.TempDir(), "copy")); err != nil {
					t.Fatal(err)
				}
			case "duplicate source":
				if err := os.WriteFile(filepath.Join(path, lineageSlotName(1)), bytes.Replace(raw, []byte(`"slot":0`), []byte(`"slot":1`), 1), 0440); err != nil {
					t.Fatal(err)
				}
			case "orphan cursor":
				if err := os.WriteFile(filepath.Join(path, lineageSlotCursor(1)), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign scratch":
				if err := os.WriteFile(filepath.Join(path, lineageSlotScratch(1, fixture.reader.Source().GenerationID)), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryEvidence(t, path)
			if invalid, err := newLineageConsumerSlots(path, config); err == nil {
				invalid.Close()
				t.Fatal("foreign or malformed state admitted")
			}
			if !bytes.Equal(before, recoveryEvidence(t, path)) {
				t.Fatal("rejection changed saved history")
			}
		})
	}
}

func TestLineageSlotsRejectProtectedDirectoryBeforeWriting(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	config.ProtectedInputs = []sensoradapter.PinnedInput{{Parent: root, Name: "token"}}
	if slots, err := newLineageConsumerSlots(path, config); err == nil {
		slots.Close()
		t.Fatal("credential directory admitted")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("admission wrote before isolation", err)
	}
	_ = fixture
}

func TestLineageSlotsPreserveOpaqueScratchForItsExactGeneration(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	if err := os.WriteFile(filepath.Join(path, ".slots.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(path, lineageSlotScratch(0, fixture.reader.Source().GenerationID))
	raw := []byte(`{"version":"foreign"}`)
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	if _, err := slots.Reserve(context.Background(), fixture.reader); err == nil {
		t.Fatal("foreign scratch overwritten")
	}
	got, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("scratch evidence changed", err)
	}
	if _, err := os.Lstat(filepath.Join(path, lineageSlotName(1))); !os.IsNotExist(err) {
		t.Fatal("same source bypassed occupied slot", err)
	}
}

func TestLineageSlotsRejectMissingControllerLockWithSavedWork(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slots.Reserve(context.Background(), fixture.reader); err != nil {
		t.Fatal(err)
	}
	slots.Close()
	if err := os.Rename(filepath.Join(path, ".slots.lock"), filepath.Join(t.TempDir(), "preserved-lock")); err != nil {
		t.Fatal(err)
	}
	before := recoveryEvidence(t, path)
	if other, err := newLineageConsumerSlots(path, config); err == nil {
		other.Close()
		t.Fatal("missing durable controller lock was recreated")
	}
	if !bytes.Equal(before, recoveryEvidence(t, path)) {
		t.Fatal("corrupt ownership state changed")
	}
}

func TestLineageSlotsResumeAfterActualProcessDeath(t *testing.T) {
	if path := os.Getenv("ZASP_TEST_SLOTS_PATH"); path != "" {
		source := lineageSpoolSource()
		producer, err := newLineageCompletionReader(os.Getenv("ZASP_TEST_SLOTS_PRODUCER"), uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		acks, err := newLineageAcknowledgments(os.Getenv("ZASP_TEST_SLOTS_ACKS"))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := newLineageSpoolReader(filepath.Join(producer.directory.root.Name(), "generation-"+source.GenerationID), source.EnrollmentBinding, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		slots, err := newLineageConsumerSlots(path, lineageSlotConfig{EnrollmentBinding: source.EnrollmentBinding, Destination: "https://runtime.example.test/internal/v1/runtime/events", Producer: producer, Acknowledgments: acks})
		if err != nil {
			t.Fatal(err)
		}
		ctx := &lineageSlotBoundaryContext{Context: context.Background(), path: path, id: source.GenerationID, stage: os.Getenv("ZASP_TEST_SLOTS_STAGE"), action: func() { os.Exit(73) }}
		slots.Reserve(ctx, reader)
		t.Fatal("crash boundary not reached")
	}
	for _, stage := range []string{"empty", "written", "frozen", "published"} {
		t.Run(stage, func(t *testing.T) {
			fixture, path, config := lineageSlotsFixture(t)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestLineageSlotsResumeAfterActualProcessDeath$")
			child.WaitDelay = time.Second
			child.Env = append(os.Environ(), "ZASP_TEST_SLOTS_PATH="+path, "ZASP_TEST_SLOTS_PRODUCER="+fixture.generation.spool.root.Name(), "ZASP_TEST_SLOTS_ACKS="+fixture.ackPath, "ZASP_TEST_SLOTS_STAGE="+stage)
			output, err := child.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("child exited outside boundary %v %s", err, output)
			}
			slots, err := newLineageConsumerSlots(path, config)
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			if record, err := slots.Reserve(context.Background(), fixture.reader); err != nil || record.Slot != 0 {
				t.Fatal("process restart lost reserved slot", record, err)
			}
		})
	}
}

func TestLineageSlotsRejectReplacementSourceIdentity(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	if _, err := slots.Reserve(context.Background(), fixture.reader); err != nil {
		t.Fatal(err)
	}
	before := recoveryEvidence(t, path)
	public := fixture.reader.root.Name()
	if err := os.Rename(public, filepath.Join(t.TempDir(), "preserved-source")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(public, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "manifest.json"), fixture.reader.manifestBytes, 0440); err != nil {
		t.Fatal(err)
	}
	replacement, err := newLineageSpoolReader(public, config.EnrollmentBinding, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if _, err := slots.Reserve(context.Background(), replacement); err == nil {
		t.Fatal("same UUID adopted replacement physical source")
	}
	if !bytes.Equal(before, recoveryEvidence(t, path)) {
		t.Fatal("replacement changed assignment")
	}
}

func TestLineageSlotsRejectConflictIntroducedDuringPublication(t *testing.T) {
	fixture, path, config := lineageSlotsFixture(t)
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	var raw []byte
	ctx := &lineageSlotBoundaryContext{Context: context.Background(), path: path, id: fixture.reader.Source().GenerationID, stage: "written", action: func() {
		var err error
		raw, err = os.ReadFile(filepath.Join(path, lineageSlotScratch(0, fixture.reader.Source().GenerationID)))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, lineageSlotName(1)), bytes.Replace(raw, []byte(`"slot":0`), []byte(`"slot":1`), 1), 0440); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := slots.Reserve(ctx, fixture.reader); err == nil || !ctx.fired {
		t.Fatal("late duplicate assignment admitted", err)
	}
	got, err := os.ReadFile(filepath.Join(path, lineageSlotScratch(0, fixture.reader.Source().GenerationID)))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("conflict lost pending evidence", err)
	}
	if _, err := os.Lstat(filepath.Join(path, lineageSlotName(0))); !os.IsNotExist(err) {
		t.Fatal("conflicting publication completed", err)
	}
}

func TestLineageSlotsRejectReplacedAncestorAtProcessorConstruction(t *testing.T) {
	fixture, parent, config := lineageSlotsFixture(t)
	path := filepath.Join(parent, "state")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	slots, err := newLineageConsumerSlots(path, config)
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	assignment, err := slots.Reserve(context.Background(), fixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := slots.CursorPath(assignment)
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
	calls := 0
	client, err := sensoradapter.NewProductionClient(sensoradapter.ProductionClientConfig{BaseURL: "https://runtime.example.test", EnrollmentBinding: config.EnrollmentBinding, Now: time.Now, Token: func() ([]byte, error) { calls++; return []byte(fixtureAgentToken()), nil }, Do: func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unexpected network") }})
	if err != nil {
		t.Fatal(err)
	}
	if consumer, err := newAssignedLineageChunkConsumer(fixture.reader, client, cursor, 16, nil, config.Acknowledgments, assignment); err == nil {
		consumer.Close()
		t.Fatal("assignment handed off to replacement state directory")
	}
	if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 || calls != 0 {
		t.Fatal("rejection wrote state or called credentials/network", len(entries), calls, err)
	}
}
