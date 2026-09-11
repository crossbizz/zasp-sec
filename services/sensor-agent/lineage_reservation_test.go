package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type lineageReservationContext struct {
	context.Context
	spool, id, stage string
	action           func()
	fired            bool
}

func (ctx *lineageReservationContext) Err() error {
	path := filepath.Join(ctx.spool, ".creating-"+ctx.id)
	name := map[string]string{"empty": "", "scratch": ".pending", "manifest": "manifest.json", "readable": "", "published": ""}[ctx.stage]
	if ctx.stage == "published" {
		path = filepath.Join(ctx.spool, "generation-"+ctx.id)
	}
	info, err := os.Lstat(filepath.Join(path, name))
	if !ctx.fired && err == nil && (ctx.stage != "readable" || info.Mode().Perm() == 0750) {
		ctx.fired = true
		ctx.action()
	}
	return ctx.Context.Err()
}

func TestLineageReservationCreationNeverExposesPartialManifest(t *testing.T) {
	for _, stage := range []string{"empty", "scratch", "manifest", "readable", "published"} {
		t.Run(stage, func(t *testing.T) {
			path := t.TempDir()
			spool, err := newLineageSpool(path, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			defer spool.Close()
			source := lineageSpoolSource()
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &lineageReservationContext{Context: base, spool: path, id: source.GenerationID, stage: stage, action: cancel}
			generation, err := spool.Create(ctx, source)
			if generation != nil {
				generation.Close()
			}
			if err == nil || generation != nil || !ctx.fired {
				t.Fatal("private reservation boundary not enforced", err)
			}
			public := filepath.Join(path, "generation-"+source.GenerationID)
			if stage == "published" {
				reader, err := newLineageSpoolReader(public, source.EnrollmentBinding, uint32(os.Getuid()))
				if err != nil {
					t.Fatal("published interrupted source isn't readable", err)
				}
				reader.Close()
				if done, err := spool.DiscardUnpublished(context.Background(), source.GenerationID); err != nil || done {
					t.Fatal("published source discarded", err)
				}
				if done, err := spool.SealInterrupted(context.Background(), source); err != nil || !done {
					t.Fatal("published recovery failed", err)
				}
			} else {
				if _, err := os.Lstat(public); !os.IsNotExist(err) {
					t.Fatal("partial source was public", err)
				}
				for retry := 0; retry < 2; retry++ {
					if done, err := spool.DiscardUnpublished(context.Background(), source.GenerationID); err != nil || !done {
						t.Fatal("reservation not recoverable", err)
					}
				}
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 1 || entries[0].Name() != ".producer.lock" {
					t.Fatal("reservation quota leaked", err)
				}
			}
		})
	}
}

func TestLineageReservationDiscardPreservesPublicHistory(t *testing.T) {
	generation, path := lineageSpoolReaderFixture(t)
	generation.Close()
	before := recoveryEvidence(t, path)
	if done, err := generation.spool.DiscardUnpublished(context.Background(), generation.source.GenerationID); err != nil || done {
		t.Fatal("public generation treated as reservation", err)
	}
	if !bytes.Equal(before, recoveryEvidence(t, path)) {
		t.Fatal("public history changed")
	}
}

func TestLineageReservationCapacityIsSharedAndReusable(t *testing.T) {
	generation, path := lineageSpoolReaderFixture(t)
	line, _ := sanitizeLineageEvent(lineageProviderFixture("exec"))
	if _, err := generation.Append(context.Background(), [][]byte{line}); err != nil {
		t.Fatal(err)
	}
	generation.Close()
	spool := generation.spool
	original := recoveryEvidence(t, path)
	var ids []string
	for index := 1; index < lineageSpoolSlots; index++ {
		source := generation.source
		source.GenerationID = fmt.Sprintf("%08d-bbbb-4bbb-8bbb-bbbbbbbbbbbb", index)
		base, cancel := context.WithCancel(context.Background())
		ctx := &lineageReservationContext{Context: base, spool: spool.root.Name(), id: source.GenerationID, stage: "manifest", action: cancel}
		if gen, err := spool.Create(ctx, source); err == nil || gen != nil || !ctx.fired {
			t.Fatal("fixture reservation not left", err)
		}
		cancel()
		ids = append(ids, source.GenerationID)
	}
	fresh := generation.source
	fresh.GenerationID = "88888888-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if gen, err := spool.Create(context.Background(), fresh); err != errLineageSpoolFull || gen != nil {
		t.Fatal("private slots escaped quota", err)
	}
	for _, id := range ids {
		if done, err := spool.DiscardUnpublished(context.Background(), id); err != nil || !done {
			t.Fatal("reserved slot not released", err)
		}
	}
	if !bytes.Equal(original, recoveryEvidence(t, path)) {
		t.Fatal("cleanup changed established events")
	}
	gen, err := spool.Create(context.Background(), fresh)
	if err != nil {
		t.Fatal("capacity wasn't reusable", err)
	}
	gen.Close()
}
