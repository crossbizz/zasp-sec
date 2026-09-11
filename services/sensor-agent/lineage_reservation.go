package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"syscall"
)

// This is local producer namespace authority, not delivery authority inferred
// from absence of event files. Only Create enters .creating; no event writer
// can operate there. Public and legacy generation names are never discarded.
func (spool *lineageSpool) DiscardUnpublished(ctx context.Context, id string) (bool, error) {
	return spool.discardUnpublished(ctx, id, "")
}

func (spool *lineageSpool) discardUnpublished(ctx context.Context, id, enrollment string) (bool, error) {
	if spool == nil || ctx == nil || ctx.Err() != nil || !validLineageUUID(id) {
		return false, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if !spool.valid() || spool.active != nil && spool.active.source.GenerationID == id {
		return false, errLineageSpool
	}
	inventory, err := spool.reclaimInventory()
	if err != nil || inventory.pending {
		return false, errLineageSpool
	}
	name := inventory.directories[id]
	if name == "generation-"+id || name == ".reclaim-"+id || inventory.markers[id] {
		return false, nil
	}
	if name == "" {
		if ctx.Err() != nil || spool.dir.Sync() != nil || ctx.Err() != nil || !spool.valid() || !spool.reservationAbsent(id) {
			return false, errLineageSpool
		}
		return true, nil
	}
	if name != ".creating-"+id && name != ".discard-"+id {
		return false, errLineageSpool
	}
	reservation, err := spool.openLineageReservation(name, id)
	if err != nil {
		return false, err
	}
	defer reservation.close()
	reservation.expectedEnrollment = enrollment
	if reservation.sync(ctx) != nil {
		return false, errLineageSpool
	}
	if name == ".creating-"+id {
		if _, err := spool.root.Lstat(".discard-" + id); !os.IsNotExist(err) {
			return false, errLineageSpool
		}
		if ctx.Err() != nil || !reservation.valid() || spool.root.Rename(name, ".discard-"+id) != nil {
			return false, errLineageSpool
		}
		reservation.name = ".discard-" + id
		if ctx.Err() != nil || spool.dir.Sync() != nil || ctx.Err() != nil || !reservation.valid() {
			return false, errLineageSpool
		}
	}
	if reservation.metadata != nil {
		file := reservation.metadata
		if ctx.Err() != nil || !reservation.valid() || reservation.root.Remove(file.name) != nil {
			return false, errLineageSpool
		}
		file.file.Close()
		reservation.metadata = nil
		if ctx.Err() != nil {
			return false, errLineageSpool
		}
	}
	if reservation.sync(ctx) != nil || ctx.Err() != nil || !reservation.valid() || spool.root.Remove(reservation.name) != nil {
		return false, errLineageSpool
	}
	if ctx.Err() != nil || spool.dir.Sync() != nil || ctx.Err() != nil || !spool.valid() || !spool.reservationAbsent(id) {
		return false, errLineageSpool
	}
	return true, nil
}

func (spool *lineageSpool) reservationAbsent(id string) bool {
	for _, name := range []string{".creating-" + id, ".discard-" + id, "generation-" + id, ".reclaim-" + id, "reclaim-" + id + ".json"} {
		if _, err := spool.root.Lstat(name); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

type lineageReservation struct {
	spool              *lineageSpool
	root               *os.Root
	dir                *os.File
	name, id           string
	metadata           *lineageRecoveryFile
	expectedEnrollment string
}

func (spool *lineageSpool) openLineageReservation(name, id string) (_ *lineageReservation, err error) {
	root, err := spool.root.OpenRoot(name)
	if err != nil {
		return nil, errLineageSpool
	}
	r := &lineageReservation{spool: spool, root: root, name: name, id: id}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	r.dir, err = root.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	entries, err := r.entries()
	if err != nil || len(entries) > 1 {
		return nil, errLineageSpool
	}
	if len(entries) == 1 {
		name := entries[0].Name()
		if name != "manifest.json" && name != ".pending" {
			return nil, errLineageSpool
		}
		file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, errLineageSpool
		}
		r.metadata = &lineageRecoveryFile{root: root, file: file, name: name, owner: spool.owner}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 4096 {
			return nil, errLineageSpool
		}
		r.metadata.raw, err = io.ReadAll(io.LimitReader(file, 4097))
		if err != nil || !validLineageReservationMetadata(name, r.metadata.raw, id) {
			return nil, errLineageSpool
		}
	}
	if !r.valid() {
		return nil, errLineageSpool
	}
	return r, nil
}
func (r *lineageReservation) entries() ([]os.DirEntry, error) {
	dir, err := r.root.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2)
	if err != nil && err != io.EOF {
		return nil, errLineageSpool
	}
	return entries, nil
}
func (r *lineageReservation) valid() bool {
	if !r.spool.valid() || !lineageOwnedDirectory(r.dir, r.spool.owner) {
		return false
	}
	for _, name := range []string{".creating-" + r.id, ".discard-" + r.id, "generation-" + r.id, ".reclaim-" + r.id, "reclaim-" + r.id + ".json"} {
		if name != r.name {
			if _, err := r.spool.root.Lstat(name); !os.IsNotExist(err) {
				return false
			}
		}
	}
	held, err := r.dir.Stat()
	named, nameErr := r.spool.root.Lstat(r.name)
	if err != nil || nameErr != nil || !named.IsDir() || !os.SameFile(held, named) || held.Mode().Perm() != 0700 && held.Mode().Perm() != 0750 {
		return false
	}
	entries, err := r.entries()
	if err != nil {
		return false
	}
	if r.metadata == nil {
		return len(entries) == 0
	}
	return len(entries) == 1 && entries[0].Name() == r.metadata.name && r.metadata.valid() && validLineageReservationMetadata(r.metadata.name, r.metadata.raw, r.id) && (r.expectedEnrollment == "" || lineageReservationEnrollmentMatches(r.metadata.raw, r.id, r.expectedEnrollment))
}
func (r *lineageReservation) sync(ctx context.Context) error {
	if ctx.Err() != nil || !r.valid() {
		return errLineageSpool
	}
	if r.metadata != nil && r.metadata.file.Sync() != nil {
		return errLineageSpool
	}
	if r.dir.Sync() != nil || r.spool.dir.Sync() != nil || ctx.Err() != nil || !r.valid() {
		return errLineageSpool
	}
	return nil
}
func (r *lineageReservation) close() {
	if r.metadata != nil {
		r.metadata.file.Close()
	}
	if r.dir != nil {
		r.dir.Close()
	}
	if r.root != nil {
		r.root.Close()
	}
}

func (spool *lineageSpool) publishLineageReservation(ctx context.Context, generation *lineageSpoolGeneration) error {
	id := generation.source.GenerationID
	private, public := ".creating-"+id, "generation-"+id
	reservation, err := spool.openLineageReservation(private, id)
	if err != nil {
		return err
	}
	defer reservation.close()
	if reservation.metadata == nil || reservation.metadata.name != "manifest.json" || !bytes.Equal(reservation.metadata.raw, generation.manifestBytes) {
		return errLineageSpool
	}
	info, err := reservation.dir.Stat()
	held, heldErr := generation.dir.Stat()
	if err != nil || heldErr != nil || !os.SameFile(info, held) || info.Mode().Perm() != 0750 || reservation.sync(ctx) != nil {
		return errLineageSpool
	}
	if _, err := spool.root.Lstat(public); !os.IsNotExist(err) {
		return errLineageSpool
	}
	if ctx.Err() != nil || !reservation.valid() || spool.root.Rename(private, public) != nil {
		return errLineageSpool
	}
	reservation.name = public
	// Once renamed, every failure leaves established history. Never discard it
	// as startup metadata, even if this final durability barrier is uncertain.
	if ctx.Err() != nil || spool.dir.Sync() != nil || ctx.Err() != nil || !reservation.valid() {
		return errLineageSpool
	}
	root, err := spool.root.OpenRoot(public)
	if err != nil {
		return errLineageSpool
	}
	newInfo, err := lineageReadOnlyRootInfo(root)
	if err != nil || !os.SameFile(info, newInfo) {
		root.Close()
		return errLineageSpool
	}
	generation.root.Close()
	generation.root = root
	return nil
}
