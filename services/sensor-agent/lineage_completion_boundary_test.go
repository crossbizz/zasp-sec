package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type lineageCompletionBoundaryContext struct {
	context.Context
	cursor string
	fired  bool
	action func()
}

func TestLineageCompletionCloseWaitsForCheckpointRetirement(t *testing.T) {
	for _, target := range []string{"reader", "store"} {
		t.Run(target, func(t *testing.T) {
			fixture, store, reader := lineageCompletionFixture(t, false)
			entered, release := make(chan struct{}), make(chan struct{})
			ctx := &lineageCompletionBoundaryContext{Context: context.Background(), cursor: fixture.cursor, action: func() { close(entered); <-release }}
			done := make(chan error, 1)
			go func() {
				complete, err := store.RetireCheckpoint(ctx, reader, reclaimFixtureRequest(fixture), fixture.cursor, 16, nil)
				if err == nil && !complete {
					err = errLineageSpool
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("retirement never held cursor ownership")
			}
			closed := make(chan error, 1)
			go func() {
				if target == "reader" {
					closed <- reader.Close()
				} else {
					closed <- store.Close()
				}
			}()
			select {
			case err := <-closed:
				close(release)
				t.Fatal("Close revoked an active lifetime", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("retirement failed", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("retirement deadlock")
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Close deadlock")
			}
		})
	}
}

func (ctx *lineageCompletionBoundaryContext) Err() error {
	if !ctx.fired {
		lock, err := os.OpenFile(ctx.cursor+".lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err == nil {
			err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			lock.Close()
			if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
				ctx.fired = true
				ctx.action()
			}
		}
	}
	return ctx.Context.Err()
}

func TestLineageCompletionRevalidatesAuthorityDuringLockedRetirement(t *testing.T) {
	for _, mutation := range []string{"completion replaced", "ack replaced", "spool replaced", "ack directory replaced", "source returned", "canceled"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, store, reader := lineageCompletionFixture(t, false)
			request := reclaimFixtureRequest(fixture)
			before, _ := os.ReadFile(fixture.cursor)
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &lineageCompletionBoundaryContext{Context: base, cursor: fixture.cursor, action: func() {
				switch mutation {
				case "completion replaced", "ack replaced":
					path := filepath.Join(fixture.generation.spool.root.Name(), "reclaim-"+request.Source.GenerationID+".json")
					if mutation == "ack replaced" {
						path = filepath.Join(fixture.ackPath, "ack-"+request.Source.GenerationID+".json")
					}
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path, path+".held"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0440); err != nil {
						t.Fatal(err)
					}
				case "spool replaced", "ack directory replaced":
					path := fixture.generation.spool.root.Name()
					if mutation == "ack directory replaced" {
						path = fixture.ackPath
					}
					if err := os.Rename(path, path+".held"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(path, 0750); err != nil {
						t.Fatal(err)
					}
				case "source returned":
					if err := os.Mkdir(filepath.Join(fixture.generation.spool.root.Name(), "generation-"+request.Source.GenerationID), 0750); err != nil {
						t.Fatal(err)
					}
				case "canceled":
					cancel()
				}
			}}
			if complete, err := store.RetireCheckpoint(ctx, reader, request, fixture.cursor, 16, nil); err == nil || complete || !ctx.fired {
				t.Fatal("changed authority admitted", err)
			}
			after, err := os.ReadFile(fixture.cursor)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("authority loss deleted checkpoint", err)
			}
		})
	}
}

func TestLineageCompletionRejectsConcurrentACKWriter(t *testing.T) {
	fixture, store, reader := lineageCompletionFixture(t, false)
	other, err := newLineageAcknowledgments(fixture.ackPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.takeLock(); err != nil {
		t.Fatal(err)
	}
	if complete, err := store.RetireCheckpoint(context.Background(), reader, reclaimFixtureRequest(fixture), fixture.cursor, 16, nil); err == nil || complete {
		t.Fatal("concurrent ACK writer admitted")
	}
	if _, err := os.Lstat(fixture.cursor); err != nil {
		t.Fatal("locked checkpoint removed", err)
	}
}
