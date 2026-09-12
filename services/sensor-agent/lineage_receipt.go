package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

// A separate read-only type keeps the producer from acquiring the consumer's
// writer lock or scratch-recovery methods. UID is trusted installation input.
type lineageReceiptReader struct {
	mu             sync.Mutex
	parent, root   *os.Root
	parentDir, dir *os.File
	name           string
	owner          uint32
	closed         bool
}

func newProductionLineageReceiptReader(path string, consumerUID uint32) (*lineageReceiptReader, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || consumerUID == 0 {
		return nil, errLineageSpool
	}
	return newLineageReceiptReader(path, consumerUID)
}

func newLineageReceiptReader(path string, consumerUID uint32) (_ *lineageReceiptReader, err error) {
	reader, err := openLineageReadOnlyDirectory(path, consumerUID)
	if err != nil {
		return nil, err
	}
	if _, err := scanLineageAcknowledgments(reader.root, reader.owner); err != nil {
		reader.Close()
		return nil, errLineageSpool
	}
	return reader, nil
}

// Shared pinned-directory admission only. Each read-only protocol validates
// its own bounded filenames and payloads; this helper cannot publish or lock.
func openLineageReadOnlyDirectory(path string, consumerUID uint32) (_ *lineageReceiptReader, err error) {
	if !validAbsolute(path) || consumerUID == ^uint32(0) {
		return nil, errLineageSpool
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errLineageSpool
	}
	reader := &lineageReceiptReader{parent: parent, name: filepath.Base(path), owner: consumerUID}
	defer func() {
		if err != nil {
			reader.Close()
		}
	}()
	reader.parentDir, err = parent.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	reader.root, err = parent.OpenRoot(reader.name)
	if err != nil {
		return nil, errLineageSpool
	}
	reader.dir, err = reader.root.Open(".")
	if err != nil || !reader.valid() {
		return nil, errLineageSpool
	}
	return reader, nil
}

func (reader *lineageReceiptReader) valid() bool {
	if reader == nil || reader.closed || reader.parent == nil || reader.root == nil || reader.parentDir == nil || reader.dir == nil || !lineageOwnedDirectory(reader.dir, reader.owner) || (!lineageOwnedDirectory(reader.parentDir, reader.owner) && !lineageOwnedDirectory(reader.parentDir, 0)) {
		return false
	}
	held, err := reader.dir.Stat()
	named, namedErr := reader.parent.Lstat(reader.name)
	return err == nil && namedErr == nil && held.Mode().Perm() == 0750 && named.IsDir() && os.SameFile(held, named)
}

func (reader *lineageReceiptReader) Close() error {
	if reader == nil {
		return nil
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	var first error
	for _, file := range []*os.File{reader.dir, reader.parentDir} {
		if file != nil {
			if err := file.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	for _, root := range []*os.Root{reader.root, reader.parent} {
		if root != nil {
			if err := root.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// Reclamation needs durable consumer evidence, not merely a visible rename.
// Caller holds producer ownership; this barrier precedes the first intent.
func (reader *lineageReceiptReader) syncAcknowledgment(ctx context.Context, ack lineageConsumptionAck) error {
	if reader == nil || ctx == nil || ctx.Err() != nil {
		return errLineageSpool
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !reader.valid() {
		return errLineageSpool
	}
	raw, err := json.Marshal(ack)
	if err != nil {
		return errLineageSpool
	}
	file, err := pinLineageExactFile(reader.root, "ack-"+ack.Consumption.Source.GenerationID+".json", reader.owner, lineageAckBytes, raw)
	if err != nil {
		return err
	}
	defer file.file.Close()
	if ctx.Err() != nil || !reader.valid() || !file.valid() || file.file.Sync() != nil || reader.dir.Sync() != nil || ctx.Err() != nil || !reader.valid() || !file.valid() {
		return errLineageSpool
	}
	return nil
}

// VerifyAcknowledgment is read-only readiness evidence, not a reusable deletion
// capability. Reclamation must repeat validation while holding its ownership lock
// through the crash-safe mutation. Consumer UID is local trust, not service proof.
func (spool *lineageSpool) VerifyAcknowledgment(ctx context.Context, receipts *lineageReceiptReader, source sensoradapter.LineageSource, destination string) (lineageConsumptionAck, bool, error) {
	if spool == nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	return spool.verifyAcknowledgmentLocked(ctx, receipts, source, destination)
}

func (spool *lineageSpool) verifyAcknowledgmentLocked(ctx context.Context, receipts *lineageReceiptReader, source sensoradapter.LineageSource, destination string) (lineageConsumptionAck, bool, error) {
	if spool == nil || receipts == nil || ctx == nil || ctx.Err() != nil || destination == "" || len(destination) > 2048 {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	if _, err := lineageManifestBytes(source); err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	if !spool.valid() || spool.active != nil && spool.active.source.GenerationID == source.GenerationID {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	receipts.mu.Lock()
	defer receipts.mu.Unlock()
	if !receipts.valid() {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	if _, err := scanLineageAcknowledgments(receipts.root, receipts.owner); err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	reader, err := newLineageSpoolReader(filepath.Join(spool.root.Name(), "generation-"+source.GenerationID), source.EnrollmentBinding, spool.owner)
	if err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	defer reader.Close()
	reader.mu.Lock()
	defer reader.mu.Unlock()
	spoolInfo, spoolErr := spool.dir.Stat()
	parentInfo, parentErr := reader.parentDir.Stat()
	sourceInfo, sourceErr := reader.dir.Stat()
	receiptInfo, receiptErr := receipts.dir.Stat()
	if spoolErr != nil || parentErr != nil || sourceErr != nil || receiptErr != nil || !os.SameFile(spoolInfo, parentInfo) || os.SameFile(receiptInfo, spoolInfo) || os.SameFile(receiptInfo, sourceInfo) || reader.source != source || ctx.Err() != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	name := "ack-" + source.GenerationID + ".json"
	if _, err := receipts.root.Lstat(name); os.IsNotExist(err) {
		if !reader.valid() || !receipts.valid() || !spool.valid() || ctx.Err() != nil {
			return lineageConsumptionAck{}, false, errLineageSpool
		}
		return lineageConsumptionAck{}, false, nil
	} else if err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	raw, err := readLineageOwnedFile(receipts.root, name, receipts.owner, lineageAckBytes)
	if err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	file, err := receipts.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || !lineageOwnedRegular(held, receipts.owner, 0440) || held.Size() != int64(len(raw)) {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	var ack lineageConsumptionAck
	if !lineageDecodeCanonical(raw, &ack) || ack.Version != "tetragon-consumption-ack-v1" || ack.Consumption.Source != source || ack.Consumption.Destination != destination || ack.Manifest != lineageHash(reader.manifestBytes) {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	seal, found, err := reader.readSealLocked()
	if err != nil || !found || ack.Seal != seal || ack.Consumption.Progress.NextSequence != seal.Chunks+1 || ack.Consumption.Progress.Read != seal.Records || ack.Consumption.Progress.Bytes != seal.Bytes || ctx.Err() != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	sealBytes, err := json.Marshal(seal)
	if err != nil || ack.SealDigest != lineageHash(sealBytes) {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	verify := sensoradapter.VerifyConsumptionSource
	if source.Profile == "tetragon-local-stream-v3" {
		verify = sensoradapter.VerifyPreciseConsumptionSource
	}
	err = verify(ctx, reader.root, source, destination, ack.Consumption, func(ctx context.Context, sequence int) (sensoradapter.ImmutableChunk, bool, error) {
		if ctx.Err() != nil {
			return sensoradapter.ImmutableChunk{}, false, errLineageSpool
		}
		chunk, found, err := reader.readChunkLocked(sequence)
		return sensoradapter.ImmutableChunk{Sequence: chunk.Sequence, Digest: chunk.Digest, Lines: chunk.Lines}, found, err
	})
	if err != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	finalSeal, sealErr := readLineageOwnedFile(reader.root, "closed.json", reader.owner, 4096)
	finalRaw, rawErr := readLineageOwnedFile(receipts.root, name, receipts.owner, lineageAckBytes)
	named, namedErr := receipts.root.Lstat(name)
	current, currentErr := file.Stat()
	heldRaw := make([]byte, len(raw))
	n, readErr := file.ReadAt(heldRaw, 0)
	if sealErr != nil || rawErr != nil || namedErr != nil || currentErr != nil || !lineageOwnedRegular(current, receipts.owner, 0440) || !os.SameFile(current, named) || current.Size() != int64(len(raw)) || readErr != nil || n != len(raw) || !bytes.Equal(heldRaw, raw) || !bytes.Equal(finalRaw, raw) || !bytes.Equal(finalSeal, sealBytes) || !reader.valid() || !receipts.valid() || !spool.valid() || ctx.Err() != nil {
		return lineageConsumptionAck{}, false, errLineageSpool
	}
	return ack, true, nil
}
