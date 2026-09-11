package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Synchronous fixture action at the third context check, after the receipt FD
// is held and the first source-seal pass completes. No production test hook.
type lineageReceiptBoundaryContext struct {
	context.Context
	calls  int
	at     int
	action func()
}

func (ctx *lineageReceiptBoundaryContext) Err() error {
	ctx.calls++
	at := ctx.at
	if at == 0 {
		at = 3
	}
	if ctx.calls == at && ctx.action != nil {
		ctx.action()
	}
	return ctx.Context.Err()
}

func TestLineageProducerReceiptChecksCancellationAfterFinalFilesystemChecks(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	probe := &lineageReceiptBoundaryContext{Context: context.Background()}
	if _, found, err := fixture.generation.spool.VerifyAcknowledgment(probe, fixture.receipts, fixture.reader.source, "https://runtime.example.test/internal/v1/runtime/events"); err != nil || !found {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := false
	ctx := &lineageReceiptBoundaryContext{Context: base, at: probe.calls, action: func() { ran = true; cancel() }}
	if _, found, err := fixture.generation.spool.VerifyAcknowledgment(ctx, fixture.receipts, fixture.reader.source, "https://runtime.example.test/internal/v1/runtime/events"); err == nil || found || !ran {
		t.Fatal("late cancellation admitted receipt", err)
	}
}

func TestLineageProducerReceiptRechecksPinnedInputsAfterVerification(t *testing.T) {
	for _, mutation := range []string{"receipt replaced", "receipt changed", "manifest replaced", "seal changed", "generation moved", "receipt directory moved", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := lineageReceiptFixture(t, false)
			ackFile := filepath.Join(fixture.ackPath, "ack-"+fixture.reader.source.GenerationID+".json")
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			actionRan := false
			ctx := &lineageReceiptBoundaryContext{Context: base, action: func() {
				actionRan = true
				switch mutation {
				case "receipt replaced", "manifest replaced":
					file := ackFile
					if mutation == "manifest replaced" {
						file = filepath.Join(fixture.reader.root.Name(), "manifest.json")
					}
					raw, err := os.ReadFile(file)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(file, filepath.Join(t.TempDir(), "retained")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(file, raw, 0440); err != nil {
						t.Fatal(err)
					}
				case "receipt changed", "seal changed":
					file := ackFile
					if mutation == "seal changed" {
						file = filepath.Join(fixture.reader.root.Name(), "closed.json")
					}
					if err := os.Chmod(file, 0640); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(file, []byte("{}"), 0440); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(file, 0440); err != nil {
						t.Fatal(err)
					}
				case "generation moved":
					if err := os.Rename(fixture.reader.root.Name(), fixture.reader.root.Name()+".old"); err != nil {
						t.Fatal(err)
					}
				case "receipt directory moved":
					if err := os.Rename(fixture.ackPath, fixture.ackPath+".old"); err != nil {
						t.Fatal(err)
					}
				case "canceled":
					cancel()
				}
			}}
			if _, found, err := fixture.generation.spool.VerifyAcknowledgment(ctx, fixture.receipts, fixture.reader.source, "https://runtime.example.test/internal/v1/runtime/events"); err == nil || found || !actionRan {
				t.Fatal("verification ignored changed pinned inputs", err)
			}
		})
	}
}

func TestLineageProducerReceiptHoldsLifetimesUntilVerificationEnds(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	entered, release := make(chan struct{}), make(chan struct{})
	ctx := &lineageReceiptBoundaryContext{Context: context.Background(), action: func() { close(entered); <-release }}
	done := make(chan error, 1)
	go func() {
		_, _, err := fixture.generation.spool.VerifyAcknowledgment(ctx, fixture.receipts, fixture.reader.source, "https://runtime.example.test/internal/v1/runtime/events")
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("verification boundary not reached")
	}
	for _, mutex := range []*sync.Mutex{&fixture.generation.spool.mu, &fixture.receipts.mu} {
		if mutex.TryLock() {
			mutex.Unlock()
			close(release)
			t.Fatal("verification released ownership")
		}
	}
	closed := make(chan error, 2)
	go func() { closed <- fixture.generation.spool.Close() }()
	go func() { closed <- fixture.receipts.Close() }()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("verification deadlock")
	}
	for index := 0; index < 2; index++ {
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("close deadlock")
		}
	}
}

func TestLineageProducerReceiptRejectsMovedGenerationInReplacementSpool(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	path := fixture.generation.spool.root.Name()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	name := "generation-" + fixture.reader.source.GenerationID
	if err := os.Rename(filepath.Join(path+".old", name), filepath.Join(path, name)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := fixture.generation.spool.VerifyAcknowledgment(context.Background(), fixture.receipts, fixture.reader.source, "https://runtime.example.test/internal/v1/runtime/events"); err == nil || found {
		t.Fatal("replaced spool parent adopted")
	}
}

func TestLineageProducerReceiptAllowsClosedTargetWithDifferentActiveGeneration(t *testing.T) {
	fixture := lineageReceiptFixture(t, false)
	source := fixture.reader.source
	source.GenerationID = "11111111-1111-4111-8111-111111111111"
	active, err := fixture.generation.spool.Create(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, found, err := fixture.generation.spool.VerifyAcknowledgment(context.Background(), fixture.receipts, fixture.reader.source, "https://runtime.example.test/internal/v1/runtime/events"); err != nil || !found {
		t.Fatal("unrelated active writer blocked sealed receipt", err)
	}
}

func TestLineageReceiptReaderRejectsUnsafeAdmissionWithoutCreatingFiles(t *testing.T) {
	for _, mutation := range []string{"wrong owner", "root consumer", "symlink root", "writable root", "writable parent", "unknown file", "oversized receipt", "closed root"} {
		t.Run(mutation, func(t *testing.T) {
			store, path := acknowledgmentFixture(t)
			store.Close()
			owner := uint32(os.Geteuid())
			switch mutation {
			case "wrong owner":
				owner++
			case "symlink root":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "writable root":
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			case "writable parent":
				if err := os.Chmod(filepath.Dir(path), 0770); err != nil {
					t.Fatal(err)
				}
			case "unknown file":
				if err := os.WriteFile(filepath.Join(path, "unknown"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized receipt":
				if err := os.WriteFile(filepath.Join(path, "ack-bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.json"), make([]byte, lineageAckBytes+1), 0440); err != nil {
					t.Fatal(err)
				}
			case "closed root":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
			}
			var reader *lineageReceiptReader
			var err error
			if mutation == "root consumer" {
				reader, err = newProductionLineageReceiptReader(path, 0)
			} else {
				reader, err = newLineageReceiptReader(path, owner)
			}
			if err == nil {
				reader.Close()
				t.Fatal("unsafe receipt root admitted")
			}
			if _, err := os.Lstat(filepath.Join(path, ".consumer.lock")); !os.IsNotExist(err) {
				t.Fatal("read-only admission created consumer lock")
			}
		})
	}
}
