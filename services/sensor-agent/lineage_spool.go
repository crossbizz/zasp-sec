package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

const (
	lineageSpoolSlots  = 8
	lineageSpoolBytes  = 8 << 20
	lineageChunkBytes  = 1 << 20
	lineageSpoolChunks = 128
)

var (
	errLineageSpool     = errors.New("sensor lineage spool unavailable")
	errLineageSpoolFull = errors.New("sensor lineage spool capacity reached")
)

type lineageSpool struct {
	mu        sync.Mutex
	root      *os.Root
	dir, lock *os.File
	owner     uint32
	closed    bool
	active    *lineageSpoolGeneration
}

type lineageSpoolManifest struct {
	Version      string                      `json:"version"`
	RecordFormat string                      `json:"record_format"`
	Source       sensoradapter.LineageSource `json:"source"`
}

type lineageSpoolGeneration struct {
	spool                    *lineageSpool
	root                     *os.Root
	dir, manifest            *os.File
	source                   sensoradapter.LineageSource
	manifestBytes            []byte
	manifestHash             string
	bytes                    int64
	records, chunks          int
	closed, sealed, poisoned bool
}

type lineageSpoolChunk struct {
	Name              string
	Sequence, Records int
	Bytes             int64
}

type lineageChunkHeader struct {
	Version  string `json:"version"`
	Manifest string `json:"manifest_sha256"`
	Sequence int    `json:"sequence"`
	Records  int    `json:"records"`
	Bytes    int64  `json:"bytes"`
	Digest   string `json:"payload_sha256"`
}

type lineageSpoolSeal struct {
	Version           string `json:"version"`
	Manifest          string `json:"manifest_sha256"`
	Reason            string `json:"reason"`
	Chunks            int    `json:"chunks"`
	Records           int    `json:"records"`
	Bytes             int64  `json:"bytes"`
	Dropped           uint64 `json:"dropped"`
	Filtered          uint64 `json:"filtered"`
	CoverageComplete  bool   `json:"coverage_complete"`
	CountersUnknown   bool   `json:"counters_unknown,omitempty"`
	InterruptedBytes  int64  `json:"interrupted_bytes,omitempty"`
	InterruptedDigest string `json:"interrupted_sha256,omitempty"`
}

// A dedicated, trusted local parent is required. Files use the process's group;
// deployment must run the producer with the read-only consumer group. The raw
// control socket is not part of this volume. Old generations cannot resume event
// append. SealInterrupted can finalize their bounded recovery metadata; consumer
// read access alone never implies deletion/reclamation authority.
func newLineageSpool(path string, owner uint32) (*lineageSpool, error) {
	return newBoundLineageSpool(path, owner, nil)
}

// Optional admission binding is checked before creating the producer lock.
func newBoundLineageSpool(path string, owner uint32, expected os.FileInfo) (*lineageSpool, error) {
	if !validAbsolute(path) || uint32(os.Getuid()) != owner {
		return nil, errLineageSpool
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errLineageSpool
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errLineageSpool
	}
	if !lineageOwnedDirectory(dir, owner) {
		dir.Close()
		root.Close()
		return nil, errLineageSpool
	}
	if expected != nil {
		actual, err := dir.Stat()
		expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
		var actualStat *syscall.Stat_t
		if err == nil {
			actualStat, _ = actual.Sys().(*syscall.Stat_t)
		}
		if err != nil || !expectedOK || actualStat == nil || !os.SameFile(expected, actual) || expected.Mode() != actual.Mode() || expectedStat.Uid != actualStat.Uid || expectedStat.Gid != actualStat.Gid {
			dir.Close()
			root.Close()
			return nil, errLineageSpool
		}
	}
	lock, err := root.OpenFile(".producer.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		dir.Close()
		root.Close()
		return nil, errLineageSpool
	}
	spool := &lineageSpool{root: root, dir: dir, lock: lock, owner: owner}
	info, err := lock.Stat()
	if err != nil || !lineageOwnedRegular(info, owner, 0o600) || info.Size() != 0 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !spool.valid() {
		spool.Close()
		return nil, errLineageSpool
	}
	return spool, nil
}

func (spool *lineageSpool) valid() bool {
	if spool.closed || !lineageOwnedDirectory(spool.dir, spool.owner) {
		return false
	}
	held, err := spool.lock.Stat()
	named, nameErr := spool.root.Lstat(".producer.lock")
	return err == nil && nameErr == nil && lineageOwnedRegular(held, spool.owner, 0o600) && lineageOwnedRegular(named, spool.owner, 0o600) && held.Size() == 0 && os.SameFile(held, named)
}

func (spool *lineageSpool) Create(ctx context.Context, source sensoradapter.LineageSource) (*lineageSpoolGeneration, error) {
	manifest, err := lineageManifestBytes(source)
	if spool == nil || ctx == nil || ctx.Err() != nil || err != nil {
		return nil, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if !spool.valid() || spool.active != nil {
		return nil, errLineageSpool
	}
	inventory, err := spool.reclaimInventory()
	if err != nil || inventory.pending || inventory.directories[source.GenerationID] != "" || inventory.markers[source.GenerationID] {
		return nil, errLineageSpool
	}
	if len(inventory.directories) >= lineageSpoolSlots {
		return nil, errLineageSpoolFull
	}
	name := ".creating-" + source.GenerationID
	if spool.root.Mkdir(name, 0o700) != nil {
		return nil, errLineageSpool
	}
	// No event writer or consumer can use this private startup namespace. It
	// counts toward quota until publication or metadata-only reservation cleanup.
	root, err := spool.root.OpenRoot(name)
	if err != nil {
		return nil, errLineageSpool
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errLineageSpool
	}
	generation := &lineageSpoolGeneration{spool: spool, root: root, dir: dir, source: source, manifestBytes: manifest, manifestHash: lineageHash(manifest)}
	if err := generation.publish(ctx, "manifest.json", manifest); err != nil {
		generation.closeLocked()
		return nil, errLineageSpool
	}
	generation.manifest, err = root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil || dir.Chmod(0o750) != nil || dir.Sync() != nil || ctx.Err() != nil || spool.publishLineageReservation(ctx, generation) != nil {
		generation.closeLocked()
		return nil, errLineageSpool
	}
	spool.active = generation
	return generation, nil
}

func (generation *lineageSpoolGeneration) valid() bool {
	if generation.closed || !generation.spool.valid() || generation.spool.active != generation || !lineageOwnedDirectory(generation.dir, generation.spool.owner) {
		return false
	}
	directory, dirErr := generation.dir.Stat()
	namedDirectory, namedDirErr := generation.spool.root.Lstat("generation-" + generation.source.GenerationID)
	if dirErr != nil || namedDirErr != nil || !namedDirectory.IsDir() || !os.SameFile(directory, namedDirectory) {
		return false
	}
	held, err := generation.manifest.Stat()
	named, nameErr := generation.root.Lstat("manifest.json")
	if err != nil || nameErr != nil || !lineageOwnedRegular(held, generation.spool.owner, 0o440) || !lineageOwnedRegular(named, generation.spool.owner, 0o440) || !os.SameFile(held, named) || held.Size() != int64(len(generation.manifestBytes)) {
		return false
	}
	data := make([]byte, len(generation.manifestBytes))
	n, err := generation.manifest.ReadAt(data, 0)
	return err == nil && n == len(data) && bytes.Equal(data, generation.manifestBytes)
}

func (generation *lineageSpoolGeneration) Append(ctx context.Context, lines [][]byte) (lineageSpoolChunk, error) {
	if generation == nil || ctx == nil || ctx.Err() != nil || len(lines) == 0 || len(lines) > 1000 {
		return lineageSpoolChunk{}, errLineageSpool
	}
	size := 0
	for _, line := range lines {
		if len(line) >= lineageChunkBytes-size || !validLineageSpoolRecordShape(line, generation.source.NodeName) {
			return lineageSpoolChunk{}, errLineageSpool
		}
		size += len(line) + 1
	}
	generation.spool.mu.Lock()
	defer generation.spool.mu.Unlock()
	if !generation.valid() || generation.sealed || generation.poisoned || ctx.Err() != nil {
		return lineageSpoolChunk{}, errLineageSpool
	}
	if generation.bytes+int64(size) > lineageSpoolBytes || generation.chunks >= lineageSpoolChunks {
		return lineageSpoolChunk{}, errLineageSpoolFull
	}
	payload := make([]byte, 0, size)
	for _, line := range lines {
		payload = append(payload, line...)
		payload = append(payload, '\n')
	}
	sequence := generation.chunks + 1
	header, _ := json.Marshal(lineageChunkHeader{Version: "tetragon-spool-chunk-v1", Manifest: generation.manifestHash, Sequence: sequence, Records: len(lines), Bytes: int64(size), Digest: lineageHash(payload)})
	encoded := append(append(header, '\n'), payload...)
	name := fmt.Sprintf("chunk-%010d.jsonl", sequence)
	if err := generation.publish(ctx, name, encoded); err != nil {
		generation.poisoned = true
		return lineageSpoolChunk{}, errLineageSpool
	}
	generation.bytes += int64(size)
	generation.records += len(lines)
	generation.chunks++
	return lineageSpoolChunk{Name: name, Sequence: sequence, Records: len(lines), Bytes: int64(size)}, nil
}

// EOF never means complete coverage. A seal records the termination reason and
// known counters; crashes can leave it absent. No raw provider error is persisted.
func (generation *lineageSpoolGeneration) Seal(ctx context.Context, reason string, dropped, filtered uint64) error {
	if generation == nil || ctx == nil || ctx.Err() != nil {
		return errLineageSpool
	}
	switch reason {
	case "shutdown", "rotation", "disconnect", "capacity", "identity_changed", "identity_unavailable", "source_mismatch", "spool_error":
	default:
		return errLineageSpool
	}
	generation.spool.mu.Lock()
	defer generation.spool.mu.Unlock()
	if !generation.valid() || generation.sealed || generation.poisoned || ctx.Err() != nil {
		return errLineageSpool
	}
	data, _ := json.Marshal(lineageSpoolSeal{Version: "tetragon-spool-closed-v1", Manifest: generation.manifestHash, Reason: reason, Chunks: generation.chunks, Records: generation.records, Bytes: generation.bytes, Dropped: dropped, Filtered: filtered})
	if generation.publish(ctx, "closed.json", data) != nil {
		generation.poisoned = true
		return errLineageSpool
	}
	generation.sealed = true
	return nil
}

// Only the held producer lock writes this newly created generation. The fixed
// pending file is never a readable chunk. Failures preserve it and poison further
// writes; no unacknowledged data is deleted or overwritten as recovery.
func (generation *lineageSpoolGeneration) publish(ctx context.Context, name string, data []byte) error {
	if ctx.Err() != nil {
		return errLineageSpool
	}
	if _, err := generation.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errLineageSpool
	}
	file, err := generation.root.OpenFile(".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return errLineageSpool
	}
	defer file.Close()
	n, err := file.Write(data)
	if err != nil || n != len(data) || file.Chmod(0o440) != nil || file.Sync() != nil || ctx.Err() != nil {
		return errLineageSpool
	}
	if generation.root.Rename(".pending", name) != nil || generation.dir.Sync() != nil || ctx.Err() != nil {
		return errLineageSpool
	}
	return nil
}

func (generation *lineageSpoolGeneration) closeLocked() {
	if generation.closed {
		return
	}
	generation.closed = true
	if generation.manifest != nil {
		generation.manifest.Close()
	}
	generation.dir.Close()
	generation.root.Close()
	if generation.spool.active == generation {
		generation.spool.active = nil
	}
}

func (generation *lineageSpoolGeneration) Close() error {
	if generation == nil {
		return nil
	}
	generation.spool.mu.Lock()
	defer generation.spool.mu.Unlock()
	generation.closeLocked()
	return nil
}

func (spool *lineageSpool) Close() error {
	if spool == nil {
		return nil
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if spool.closed {
		return nil
	}
	spool.closed = true
	if spool.active != nil {
		spool.active.closeLocked()
	}
	spool.lock.Close()
	spool.dir.Close()
	spool.root.Close()
	return nil
}

func lineageManifestBytes(source sensoradapter.LineageSource) ([]byte, error) {
	if _, err := sensoradapter.NewLineageNormalizer(1, source); err != nil || !validKubernetesName(source.NodeName) {
		return nil, errLineageSpool
	}
	format := "zasp-tetragon-record-v1"
	if source.Profile == "tetragon-local-stream-v2" {
		format = "zasp-tetragon-record-v2"
	}
	return json.Marshal(lineageSpoolManifest{Version: "tetragon-spool-v1", RecordFormat: format, Source: source})
}

func lineageHash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func lineageOwnedDirectory(file *os.File, owner uint32) bool {
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == owner
}

func lineageOwnedRegular(info os.FileInfo, owner uint32, mode os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == owner && stat.Nlink == 1
}

// Storage validates only the closed canonical record shape and node binding.
// The caller must use sanitizeLineageEvent before writing; the consumer must
// apply the lineage normalizer's semantic checks before deriving runtime events.
// Neither a checksum nor this shape check authenticates provider semantics.
func validLineageSpoolRecordShape(line []byte, node string) bool {
	if len(line) == 0 || len(line) > 256<<10 || bytes.ContainsAny(line, "\r\n") {
		return false
	}
	var record lineageEventRecord
	if !lineageDecodeCanonical(line, &record) || record.Node != node {
		return false
	}
	kinds := 0
	if record.Exec != nil {
		kinds++
	}
	if record.Exit != nil {
		kinds++
	}
	if record.Probe != nil {
		kinds++
	}
	return kinds == 1
}

func lineageDecodeCanonical(data []byte, target any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	canonical, err := json.Marshal(target)
	return err == nil && bytes.Equal(canonical, data)
}

func readLineageOwnedFile(root *os.Root, name string, owner uint32, maximum int64) ([]byte, error) {
	return readLineageOwnedBoundedFile(root, name, owner, 1, maximum)
}

func readLineageOwnedBoundedFile(root *os.Root, name string, owner uint32, minimum, maximum int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !lineageOwnedRegular(before, owner, 0o440) || before.Size() < minimum || before.Size() > maximum {
		return nil, errLineageSpool
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLineageSpool
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || !lineageOwnedRegular(held, owner, 0o440) || !os.SameFile(before, held) {
		return nil, errLineageSpool
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	after, afterErr := root.Lstat(name)
	if err != nil || afterErr != nil || len(data) > int(maximum) || int64(len(data)) != held.Size() || !lineageOwnedRegular(after, owner, 0o440) || !os.SameFile(held, after) || after.Size() != held.Size() || !after.ModTime().Equal(held.ModTime()) {
		return nil, errLineageSpool
	}
	return data, nil
}

func readLineageSpoolChunk(root *os.Root, name string, source sensoradapter.LineageSource, owner uint32) ([][]byte, error) {
	if root == nil || filepath.Base(name) != name || !strings.HasPrefix(name, "chunk-") || !strings.HasSuffix(name, ".jsonl") {
		return nil, errLineageSpool
	}
	sequence, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(name, "chunk-"), ".jsonl"))
	if err != nil || sequence < 1 || sequence > lineageSpoolChunks || name != fmt.Sprintf("chunk-%010d.jsonl", sequence) {
		return nil, errLineageSpool
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	defer dir.Close()
	if !lineageOwnedDirectory(dir, owner) {
		return nil, errLineageSpool
	}
	expected, err := lineageManifestBytes(source)
	if err != nil {
		return nil, err
	}
	manifest, err := readLineageOwnedFile(root, "manifest.json", owner, 4096)
	if err != nil || !bytes.Equal(manifest, expected) {
		return nil, errLineageSpool
	}
	data, err := readLineageOwnedFile(root, name, owner, lineageChunkBytes+1024)
	if err != nil {
		return nil, err
	}
	return decodeLineageSpoolChunk(data, source, expected, sequence)
}

func decodeLineageSpoolChunk(data []byte, source sensoradapter.LineageSource, expected []byte, sequence int) ([][]byte, error) {
	if sequence < 1 || sequence > lineageSpoolChunks || len(data) > lineageChunkBytes+1024 {
		return nil, errLineageSpool
	}
	headerBytes, payload, ok := bytes.Cut(data, []byte{'\n'})
	var header lineageChunkHeader
	if !ok || len(headerBytes) > 1024 || !lineageDecodeCanonical(headerBytes, &header) || header.Version != "tetragon-spool-chunk-v1" || header.Sequence != sequence || header.Manifest != lineageHash(expected) || header.Bytes != int64(len(payload)) || header.Bytes < 1 || header.Bytes > lineageChunkBytes || header.Digest != lineageHash(payload) || header.Records < 1 || header.Records > 1000 || payload[len(payload)-1] != '\n' {
		return nil, errLineageSpool
	}
	lines := bytes.SplitN(payload[:len(payload)-1], []byte{'\n'}, header.Records+1)
	if len(lines) != header.Records {
		return nil, errLineageSpool
	}
	for _, line := range lines {
		if !validLineageSpoolRecordShape(line, source.NodeName) {
			return nil, errLineageSpool
		}
	}
	return lines, nil
}
