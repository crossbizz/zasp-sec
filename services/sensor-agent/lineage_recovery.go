package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// Close an established interrupted generation, never reopen it for event append.
// Source is trusted installation/controller input. Pre-manifest reservations
// aren't adopted. The producer ownership lock excludes live writers on restart.
func (spool *lineageSpool) SealInterrupted(ctx context.Context, source sensoradapter.LineageSource) (bool, error) {
	if spool == nil || ctx == nil || ctx.Err() != nil {
		return false, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if !spool.valid() || spool.active != nil && spool.active.source.GenerationID == source.GenerationID {
		return false, errLineageSpool
	}
	inventory, err := spool.reclaimInventory()
	if err != nil || inventory.pending || inventory.markers[source.GenerationID] || inventory.directories[source.GenerationID] != "generation-"+source.GenerationID {
		return false, errLineageSpool
	}
	reader, err := newLineageSpoolReader(filepath.Join(spool.root.Name(), "generation-"+source.GenerationID), source.EnrollmentBinding, spool.owner)
	if err != nil {
		return false, errLineageSpool
	}
	defer reader.Close()
	parent, err := reader.parentDir.Stat()
	held, heldErr := spool.dir.Stat()
	if err != nil || heldErr != nil || !os.SameFile(parent, held) || reader.source != source {
		return false, errLineageSpool
	}
	// At most: promote a chunk or preserve a fragment, clear matching seal
	// scratch, publish the seal, then establish the final durability barrier.
	for step := 0; step < 5; step++ {
		snapshot, err := captureLineageRecovery(spool, reader)
		if err != nil {
			return false, err
		}
		done, changed, err := snapshot.recover(ctx)
		snapshot.close()
		if err != nil || done {
			return done, err
		}
		if !changed {
			return false, errLineageSpool
		}
	}
	return false, errLineageSpool
}

// These fields are comparable so ACK identity checks remain exact value checks.
// Numeric dropped/filtered values are unavailable after restart, not known zero.
func validLineageSealRecovery(seal lineageSpoolSeal) bool {
	switch seal.Reason {
	case "producer_restart":
		if !seal.CountersUnknown || seal.Dropped != 0 || seal.Filtered != 0 {
			return false
		}
	case "shutdown", "rotation", "disconnect", "capacity", "identity_changed", "identity_unavailable", "source_mismatch", "spool_error":
		if seal.CountersUnknown || seal.InterruptedDigest != "" || seal.InterruptedBytes != 0 {
			return false
		}
	default:
		return false
	}
	if seal.InterruptedDigest == "" {
		return seal.InterruptedBytes == 0
	}
	// A pending record's header and a partial seal have bounded overhead beyond
	// payload. Fragment bytes aren't submitted records or known dropped counts.
	return seal.Reason == "producer_restart" && enrollmentBindingPattern.MatchString(seal.InterruptedDigest) && seal.InterruptedBytes >= 0 && seal.InterruptedBytes <= lineageChunkBytes+1024 && seal.Bytes >= 0 && seal.Bytes+seal.InterruptedBytes <= lineageSpoolBytes+4096
}

func lineageSealFragmentMatches(root *os.Root, owner uint32, seal lineageSpoolSeal) bool {
	if seal.InterruptedDigest == "" {
		_, err := root.Lstat("interrupted.bin")
		return os.IsNotExist(err)
	}
	raw, err := readLineageOwnedBoundedFile(root, "interrupted.bin", owner, 0, lineageChunkBytes+1024)
	return err == nil && int64(len(raw)) == seal.InterruptedBytes && lineageHash(raw) == seal.InterruptedDigest
}

type lineageRecoveryFile struct {
	root  *os.Root
	file  *os.File
	name  string
	owner uint32
	raw   []byte
}

func (file *lineageRecoveryFile) valid() bool {
	held, err := file.file.Stat()
	named, nameErr := file.root.Lstat(file.name)
	if err != nil || nameErr != nil || !os.SameFile(held, named) || held.Size() != int64(len(file.raw)) || named.Size() != held.Size() {
		return false
	}
	mode := held.Mode().Perm()
	if mode != 0440 && (file.name != ".pending" || mode != 0600) || !lineageOwnedRegular(held, file.owner, mode) || !lineageOwnedRegular(named, file.owner, mode) {
		return false
	}
	raw := make([]byte, len(file.raw))
	n, err := file.file.ReadAt(raw, 0)
	return err == nil && n == len(raw) && bytes.Equal(raw, file.raw)
}

type lineageRecoverySnapshot struct {
	spool  *lineageSpool
	reader *lineageSpoolReader
	files  map[string]*lineageRecoveryFile
	seal   lineageSpoolSeal
}

func captureLineageRecovery(spool *lineageSpool, reader *lineageSpoolReader) (_ *lineageRecoverySnapshot, err error) {
	s := &lineageRecoverySnapshot{spool: spool, reader: reader, files: map[string]*lineageRecoveryFile{}, seal: lineageSpoolSeal{Version: "tetragon-spool-closed-v1", Manifest: lineageHash(reader.manifestBytes), Reason: "producer_restart", CountersUnknown: true}}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	highest, _, _, err := reader.scanLocked()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, highest+3)
	for sequence := 1; sequence <= highest; sequence++ {
		names = append(names, fmt.Sprintf("chunk-%010d.jsonl", sequence))
	}
	for _, name := range []string{"interrupted.bin", ".pending", "closed.json"} {
		if _, err := reader.root.Lstat(name); err == nil {
			names = append(names, name)
		} else if !os.IsNotExist(err) {
			return nil, errLineageSpool
		}
	}
	for _, name := range names {
		file, err := reader.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, errLineageSpool
		}
		pinned := &lineageRecoveryFile{root: reader.root, file: file, name: name, owner: reader.owner}
		s.files[name] = pinned
		info, err := file.Stat()
		limit := int64(lineageChunkBytes + 1024)
		if name == "closed.json" {
			limit = 4096
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
			return nil, errLineageSpool
		}
		pinned.raw, err = io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(pinned.raw)) > limit || !pinned.valid() {
			return nil, errLineageSpool
		}
		if sequence, ok := lineageSpoolChunkSequence(name); ok {
			lines, err := decodeLineageSpoolChunk(pinned.raw, reader.source, reader.manifestBytes, sequence)
			if err != nil {
				return nil, err
			}
			s.seal.Chunks++
			s.seal.Records += len(lines)
			for _, line := range lines {
				s.seal.Bytes += int64(len(line) + 1)
			}
			if s.seal.Bytes > lineageSpoolBytes {
				return nil, errLineageSpool
			}
		}
	}
	if fragment := s.files["interrupted.bin"]; fragment != nil {
		s.seal.InterruptedDigest = lineageHash(fragment.raw)
		s.seal.InterruptedBytes = int64(len(fragment.raw))
	}
	if !validLineageSealRecovery(s.seal) || !s.valid() {
		return nil, errLineageSpool
	}
	return s, nil
}

func (s *lineageRecoverySnapshot) close() {
	for _, file := range s.files {
		file.file.Close()
	}
}
func (s *lineageRecoverySnapshot) valid() bool {
	if !s.spool.valid() || !s.reader.valid() {
		return false
	}
	dir, err := s.reader.root.Open(".")
	if err != nil {
		return false
	}
	entries, err := dir.ReadDir(len(s.files) + 2)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) != len(s.files)+1 {
		return false
	}
	for _, entry := range entries {
		if entry.Name() != "manifest.json" && s.files[entry.Name()] == nil {
			return false
		}
	}
	for _, file := range s.files {
		if !file.valid() {
			return false
		}
	}
	return true
}
func (s *lineageRecoverySnapshot) sync(ctx context.Context) error {
	if ctx.Err() != nil || !s.valid() || s.reader.manifest.Sync() != nil {
		return errLineageSpool
	}
	for _, file := range s.files {
		if file.file.Sync() != nil {
			return errLineageSpool
		}
	}
	if s.reader.dir.Sync() != nil || s.spool.dir.Sync() != nil || ctx.Err() != nil || !s.valid() {
		return errLineageSpool
	}
	return nil
}
func (s *lineageRecoverySnapshot) renamePending(ctx context.Context, target string) error {
	file := s.files[".pending"]
	if file == nil || ctx.Err() != nil || !s.valid() {
		return errLineageSpool
	}
	if _, err := s.reader.root.Lstat(target); !os.IsNotExist(err) {
		return errLineageSpool
	}
	if file.file.Chmod(0440) != nil || s.sync(ctx) != nil || ctx.Err() != nil || !s.valid() {
		return errLineageSpool
	}
	if s.reader.root.Rename(".pending", target) != nil {
		return errLineageSpool
	}
	delete(s.files, ".pending")
	file.name = target
	s.files[target] = file
	if ctx.Err() != nil || s.reader.dir.Sync() != nil || ctx.Err() != nil || !s.valid() {
		return errLineageSpool
	}
	return nil
}
func (s *lineageRecoverySnapshot) matchesSeal(raw []byte) bool {
	var seal lineageSpoolSeal
	return lineageDecodeCanonical(raw, &seal) && seal.Version == s.seal.Version && seal.Manifest == s.seal.Manifest && !seal.CoverageComplete && seal.Chunks == s.seal.Chunks && seal.Records == s.seal.Records && seal.Bytes == s.seal.Bytes && seal.InterruptedDigest == s.seal.InterruptedDigest && seal.InterruptedBytes == s.seal.InterruptedBytes && validLineageSealRecovery(seal)
}
func (s *lineageRecoverySnapshot) recover(ctx context.Context) (done, changed bool, err error) {
	if ctx.Err() != nil || !s.valid() {
		return false, false, errLineageSpool
	}
	if closed := s.files["closed.json"]; closed != nil {
		if s.files[".pending"] != nil || !s.matchesSeal(closed.raw) {
			return false, false, errLineageSpool
		}
		if err := s.sync(ctx); err != nil {
			return false, false, err
		}
		return true, false, nil
	}
	expected, _ := json.Marshal(s.seal)
	if pending := s.files[".pending"]; pending != nil {
		if s.matchesSeal(pending.raw) {
			return false, true, s.renamePending(ctx, "closed.json")
		}
		var seal lineageSpoolSeal
		if lineageDecodeCanonical(pending.raw, &seal) {
			return false, false, errLineageSpool
		}
		lines, chunkErr := decodeLineageSpoolChunk(pending.raw, s.reader.source, s.reader.manifestBytes, s.seal.Chunks+1)
		if chunkErr == nil {
			if s.files["interrupted.bin"] != nil {
				return false, false, errLineageSpool
			}
			var size int64
			for _, line := range lines {
				size += int64(len(line) + 1)
			}
			if s.seal.Bytes+size > lineageSpoolBytes {
				return false, false, errLineageSpool
			}
			return false, true, s.renamePending(ctx, fmt.Sprintf("chunk-%010d.jsonl", s.seal.Chunks+1))
		}
		// A structurally complete conflicting object isn't a partial write.
		headerRaw, payload, _ := bytes.Cut(pending.raw, []byte{'\n'})
		var header lineageChunkHeader
		if lineageDecodeCanonical(headerRaw, &header) && (header.Version != "tetragon-spool-chunk-v1" || header.Manifest != s.seal.Manifest || header.Sequence != s.seal.Chunks+1 || header.Bytes <= int64(len(payload)) || header.Bytes > lineageChunkBytes || header.Records < 1 || header.Records > 1000) {
			return false, false, errLineageSpool
		}
		// A common JSON prefix cannot identify initial scratch as seal data.
		// Only the fragment phase, durably synced below, establishes that the
		// producer has stopped chunk publication and this is seal retry scratch.
		if s.files["interrupted.bin"] != nil && bytes.HasPrefix(expected, pending.raw) {
			if s.sync(ctx) != nil || ctx.Err() != nil || !s.valid() || s.reader.root.Remove(".pending") != nil {
				return false, false, errLineageSpool
			}
			pending.file.Close()
			delete(s.files, ".pending")
			if ctx.Err() != nil || s.reader.dir.Sync() != nil || ctx.Err() != nil || !s.valid() {
				return false, false, errLineageSpool
			}
			return false, true, nil
		}
		if s.files["interrupted.bin"] != nil || s.seal.Bytes+int64(len(pending.raw)) > lineageSpoolBytes+4096 {
			return false, false, errLineageSpool
		}
		return false, true, s.renamePending(ctx, "interrupted.bin")
	}
	if s.sync(ctx) != nil {
		return false, false, errLineageSpool
	}
	if ctx.Err() != nil || !s.valid() {
		return false, false, errLineageSpool
	}
	file, err := s.reader.root.OpenFile(".pending", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return false, false, errLineageSpool
	}
	pending := &lineageRecoveryFile{root: s.reader.root, file: file, name: ".pending", owner: s.reader.owner}
	s.files[".pending"] = pending
	if ctx.Err() != nil || !s.valid() {
		return false, false, errLineageSpool
	}
	n, err := file.Write(expected)
	pending.raw = expected
	if err != nil || n != len(expected) || ctx.Err() != nil || !s.valid() {
		return false, false, errLineageSpool
	}
	return false, true, s.renamePending(ctx, "closed.json")
}
