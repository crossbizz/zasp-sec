package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageSpoolReader struct {
	mu                       sync.Mutex
	parent, root             *os.Root
	parentDir, dir, manifest *os.File
	name                     string
	owner                    uint32
	source                   sensoradapter.LineageSource
	manifestBytes            []byte
	closed                   bool
}

type lineageReadChunk struct {
	Sequence int
	Digest   string
	Lines    [][]byte
}

func newProductionLineageSpoolReader(path, enrollment string) (*lineageSpoolReader, error) {
	if runtime.GOOS != "linux" {
		return nil, errLineageSpool
	}
	return newLineageSpoolReader(path, enrollment, 0)
}

// Admission is read-only. Expected enrollment comes from the consumer's trusted
// installation, never from the manifest. Owner injection supports local fixtures;
// production uses the root-owned constructor and controlled read-only mounts.
// No token, producer lock, deletion authority or historical adoption is implied.
func newLineageSpoolReader(path, enrollment string, owner uint32) (_ *lineageSpoolReader, err error) {
	name := filepath.Base(path)
	if !validAbsolute(path) || !enrollmentBindingPattern.MatchString(enrollment) || !strings.HasPrefix(name, "generation-") || !validLineageUUID(strings.TrimPrefix(name, "generation-")) {
		return nil, errLineageSpool
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errLineageSpool
	}
	reader := &lineageSpoolReader{parent: parent, name: name, owner: owner}
	defer func() {
		if err != nil {
			reader.Close()
		}
	}()
	reader.parentDir, err = parent.Open(".")
	if err != nil || !lineageOwnedDirectory(reader.parentDir, owner) {
		return nil, errLineageSpool
	}
	named, err := parent.Lstat(name)
	if err != nil || !named.IsDir() || named.Mode().Perm() != 0o750 {
		return nil, errLineageSpool
	}
	reader.root, err = parent.OpenRoot(name)
	if err != nil {
		return nil, errLineageSpool
	}
	reader.dir, err = reader.root.Open(".")
	if err != nil || !lineageOwnedDirectory(reader.dir, owner) {
		return nil, errLineageSpool
	}
	held, err := reader.dir.Stat()
	if err != nil || !os.SameFile(named, held) {
		return nil, errLineageSpool
	}
	data, err := readLineageOwnedFile(reader.root, "manifest.json", owner, 4096)
	if err != nil {
		return nil, errLineageSpool
	}
	var manifest lineageSpoolManifest
	if !lineageDecodeCanonical(data, &manifest) || manifest.Source.EnrollmentBinding != enrollment || "generation-"+manifest.Source.GenerationID != name || !validKubernetesName(manifest.Source.NodeName) {
		return nil, errLineageSpool
	}
	expected, err := lineageManifestBytes(manifest.Source)
	if err != nil || !bytes.Equal(data, expected) {
		return nil, errLineageSpool
	}
	reader.source, reader.manifestBytes = manifest.Source, data
	reader.manifest, err = reader.root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil || !reader.valid() {
		return nil, errLineageSpool
	}
	return reader, nil
}

func (reader *lineageSpoolReader) valid() bool {
	if reader.closed || !lineageOwnedDirectory(reader.parentDir, reader.owner) || !lineageOwnedDirectory(reader.dir, reader.owner) {
		return false
	}
	heldDir, err := reader.dir.Stat()
	namedDir, namedErr := reader.parent.Lstat(reader.name)
	if err != nil || namedErr != nil || !namedDir.IsDir() || namedDir.Mode().Perm() != 0o750 || !os.SameFile(heldDir, namedDir) {
		return false
	}
	held, err := reader.manifest.Stat()
	named, namedErr := reader.root.Lstat("manifest.json")
	if err != nil || namedErr != nil || !lineageOwnedRegular(held, reader.owner, 0o440) || !lineageOwnedRegular(named, reader.owner, 0o440) || !os.SameFile(held, named) || held.Size() != int64(len(reader.manifestBytes)) {
		return false
	}
	data := make([]byte, len(reader.manifestBytes))
	n, err := reader.manifest.ReadAt(data, 0)
	return err == nil && n == len(data) && bytes.Equal(data, reader.manifestBytes)
}

func (reader *lineageSpoolReader) Source() sensoradapter.LineageSource {
	if reader == nil {
		return sensoradapter.LineageSource{}
	}
	return reader.source
}

func lineageSpoolChunkSequence(name string) (int, bool) {
	if !strings.HasPrefix(name, "chunk-") || !strings.HasSuffix(name, ".jsonl") {
		return 0, false
	}
	sequence, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "chunk-"), ".jsonl"))
	return sequence, err == nil && sequence >= 1 && sequence <= lineageSpoolChunks && name == fmt.Sprintf("chunk-%010d.jsonl", sequence)
}

// Enumeration is bounded even for a malformed directory. Only .pending can
// legitimately disappear during publication. Its contents are never read.
func (reader *lineageSpoolReader) scanLocked() (highest int, sealed, pending bool, err error) {
	directory, err := reader.root.Open(".")
	if err != nil {
		return 0, false, false, errLineageSpool
	}
	defer directory.Close()
	entries, err := directory.ReadDir(lineageSpoolChunks + 5)
	if err != nil && err != io.EOF || len(entries) > lineageSpoolChunks+4 {
		return 0, false, false, errLineageSpool
	}
	for _, entry := range entries {
		name := entry.Name()
		info, err := reader.root.Lstat(name)
		if name == ".pending" && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, false, false, errLineageSpool
		}
		switch name {
		case "manifest.json", "closed.json":
			if !lineageOwnedRegular(info, reader.owner, 0o440) || info.Size() < 1 || info.Size() > 4096 {
				return 0, false, false, errLineageSpool
			}
			if name == "closed.json" {
				sealed = true
			}
		case ".pending":
			mode := info.Mode().Perm()
			if mode != 0o600 && mode != 0o440 || !lineageOwnedRegular(info, reader.owner, mode) || info.Size() < 0 || info.Size() > lineageChunkBytes+1024 {
				return 0, false, false, errLineageSpool
			}
			pending = true
		case "interrupted.bin":
			if !lineageOwnedRegular(info, reader.owner, 0440) || info.Size() < 0 || info.Size() > lineageChunkBytes+1024 {
				return 0, false, false, errLineageSpool
			}
		default:
			sequence, ok := lineageSpoolChunkSequence(name)
			if !ok || !lineageOwnedRegular(info, reader.owner, 0o440) || info.Size() < 1 || info.Size() > lineageChunkBytes+1024 {
				return 0, false, false, errLineageSpool
			}
			if sequence > highest {
				highest = sequence
			}
		}
	}
	return highest, sealed, pending, nil
}

// found=false never advances a cursor. A missing chunk can be pending or past a
// verified seal; the consumer must inspect closure and its own committed prefix.
func (reader *lineageSpoolReader) ReadChunk(sequence int) (lineageReadChunk, bool, error) {
	if reader == nil || sequence < 1 || sequence > lineageSpoolChunks {
		return lineageReadChunk{}, false, errLineageSpool
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.readChunkLocked(sequence)
}

// The consumer holds the reader lifetime lock through checkpoint/transport work.
func (reader *lineageSpoolReader) readChunkLocked(sequence int) (lineageReadChunk, bool, error) {
	if sequence < 1 || sequence > lineageSpoolChunks {
		return lineageReadChunk{}, false, errLineageSpool
	}
	if !reader.valid() {
		return lineageReadChunk{}, false, errLineageSpool
	}
	highest, sealed, _, err := reader.scanLocked()
	if err != nil {
		return lineageReadChunk{}, false, errLineageSpool
	}
	name := fmt.Sprintf("chunk-%010d.jsonl", sequence)
	if _, err := reader.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		// Enumeration may have raced publication. Recheck the requested name
		// before treating a later chunk or seal as an observed contradiction.
		if _, again := reader.root.Lstat(name); errors.Is(again, os.ErrNotExist) {
			if highest >= sequence {
				return lineageReadChunk{}, false, errLineageSpool
			}
			if sealed {
				seal, found, sealErr := reader.readSealLocked()
				if sealErr != nil || !found || sequence <= seal.Chunks {
					return lineageReadChunk{}, false, errLineageSpool
				}
			}
			if !reader.valid() {
				return lineageReadChunk{}, false, errLineageSpool
			}
			return lineageReadChunk{}, false, nil
		}
	}
	lines, err := readLineageSpoolChunk(reader.root, name, reader.source, reader.owner)
	if err != nil || !reader.valid() {
		return lineageReadChunk{}, false, errLineageSpool
	}
	digest := sha256.New()
	for _, line := range lines {
		digest.Write(line)
		digest.Write([]byte{'\n'})
	}
	return lineageReadChunk{Sequence: sequence, Digest: hex.EncodeToString(digest.Sum(nil)), Lines: lines}, true, nil
}

func (reader *lineageSpoolReader) ReadSeal() (lineageSpoolSeal, bool, error) {
	if reader == nil {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !reader.valid() {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	return reader.readSealLocked()
}

// Verify the claimed totals against at most 128 chunks, rejecting accumulated
// payload above 8 MiB. This proves local structural closure, not delivery, acknowledgment,
// upstream completeness or permission to reclaim the generation.
func (reader *lineageSpoolReader) readSealLocked() (lineageSpoolSeal, bool, error) {
	highest, sealed, pending, err := reader.scanLocked()
	if err != nil {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	if !sealed {
		if !reader.valid() {
			return lineageSpoolSeal{}, false, errLineageSpool
		}
		return lineageSpoolSeal{}, false, nil
	}
	if pending {
		if _, err := reader.root.Lstat(".pending"); !errors.Is(err, os.ErrNotExist) {
			return lineageSpoolSeal{}, false, errLineageSpool
		}
	}
	data, err := readLineageOwnedFile(reader.root, "closed.json", reader.owner, 4096)
	if err != nil {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	// The first directory view may have overlapped publication. Once the seal
	// has been read, a conforming producer cannot add chunks; take a fresh view.
	highest, sealed, pending, err = reader.scanLocked()
	if err != nil || !sealed || pending {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	var seal lineageSpoolSeal
	if err != nil || !lineageDecodeCanonical(data, &seal) || seal.Version != "tetragon-spool-closed-v1" || seal.Manifest != lineageHash(reader.manifestBytes) || seal.CoverageComplete || seal.Chunks != highest || seal.Chunks < 0 || seal.Chunks > lineageSpoolChunks || seal.Records < seal.Chunks || seal.Records > seal.Chunks*1000 || seal.Bytes < int64(seal.Records)*2 || seal.Bytes > lineageSpoolBytes || seal.Chunks == 0 && (seal.Records != 0 || seal.Bytes != 0) {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	if !validLineageSealRecovery(seal) || !lineageSealFragmentMatches(reader.root, reader.owner, seal) {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	var totalBytes int64
	totalRecords := 0
	for sequence := 1; sequence <= seal.Chunks; sequence++ {
		lines, err := readLineageSpoolChunk(reader.root, fmt.Sprintf("chunk-%010d.jsonl", sequence), reader.source, reader.owner)
		if err != nil {
			return lineageSpoolSeal{}, false, errLineageSpool
		}
		totalRecords += len(lines)
		for _, line := range lines {
			totalBytes += int64(len(line) + 1)
		}
		if totalBytes > lineageSpoolBytes {
			return lineageSpoolSeal{}, false, errLineageSpool
		}
	}
	finalSeal, finalErr := readLineageOwnedFile(reader.root, "closed.json", reader.owner, 4096)
	if totalRecords != seal.Records || totalBytes != seal.Bytes || finalErr != nil || !bytes.Equal(data, finalSeal) || !reader.valid() || !lineageSealFragmentMatches(reader.root, reader.owner, seal) {
		return lineageSpoolSeal{}, false, errLineageSpool
	}
	return seal, true, nil
}

func (reader *lineageSpoolReader) Close() error {
	if reader == nil {
		return nil
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	for _, file := range []*os.File{reader.manifest, reader.dir, reader.parentDir} {
		if file != nil {
			file.Close()
		}
	}
	if reader.root != nil {
		reader.root.Close()
	}
	if reader.parent != nil {
		reader.parent.Close()
	}
	return nil
}
