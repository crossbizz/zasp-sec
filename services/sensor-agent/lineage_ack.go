package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

const lineageAckBytes = 8192

type lineageConsumptionAck struct {
	Version     string                            `json:"version"`
	Consumption sensoradapter.VerifiedConsumption `json:"consumption"`
	Manifest    string                            `json:"manifest_sha256"`
	Seal        lineageSpoolSeal                  `json:"seal"`
	SealDigest  string                            `json:"seal_sha256"`
}

type lineageAcknowledgments struct {
	mu                   sync.Mutex
	parent, root         *os.Root
	parentDir, dir, lock *os.File
	name                 string
	owner                uint32
	closed               bool
}

// Admission is read-only. The first verified publication takes a lifetime lock.
// The consumer owns this separate output directory, never the producer source.
func newLineageAcknowledgments(path string) (_ *lineageAcknowledgments, err error) {
	name := filepath.Base(path)
	if !validAbsolute(path) || name == "." || name == string(filepath.Separator) {
		return nil, errLineageSpool
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errLineageSpool
	}
	store := &lineageAcknowledgments{parent: parent, name: name, owner: uint32(os.Geteuid())}
	defer func() {
		if err != nil {
			store.Close()
		}
	}()
	store.parentDir, err = parent.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	store.root, err = parent.OpenRoot(name)
	if err != nil {
		return nil, errLineageSpool
	}
	store.dir, err = store.root.Open(".")
	if err != nil || !store.valid() {
		return nil, errLineageSpool
	}
	if _, err = store.scan(); err != nil {
		return nil, errLineageSpool
	}
	return store, nil
}

func (store *lineageAcknowledgments) valid() bool {
	if store == nil || store.closed || store.parent == nil || store.root == nil || store.parentDir == nil || store.dir == nil || !lineageOwnedDirectory(store.dir, store.owner) || (!lineageOwnedDirectory(store.parentDir, store.owner) && !lineageOwnedDirectory(store.parentDir, 0)) {
		return false
	}
	held, err := store.dir.Stat()
	named, namedErr := store.parent.Lstat(store.name)
	if err != nil || namedErr != nil || held.Mode().Perm() != 0750 || !named.IsDir() || !os.SameFile(held, named) {
		return false
	}
	if store.lock != nil {
		held, err = store.lock.Stat()
		named, namedErr = store.root.Lstat(".consumer.lock")
		if err != nil || namedErr != nil || !lineageOwnedRegular(held, store.owner, 0600) || !lineageOwnedRegular(named, store.owner, 0600) || held.Size() != 0 || !os.SameFile(held, named) {
			return false
		}
	}
	return true
}

func lineageAckName(name string) bool {
	return strings.HasPrefix(name, "ack-") && strings.HasSuffix(name, ".json") && validLineageUUID(strings.TrimSuffix(strings.TrimPrefix(name, "ack-"), ".json"))
}

func (store *lineageAcknowledgments) scan() (int, error) {
	return scanLineageAcknowledgments(store.root, store.owner)
}

func scanLineageAcknowledgments(root *os.Root, owner uint32) (int, error) {
	directory, err := root.Open(".")
	if err != nil {
		return 0, errLineageSpool
	}
	entries, err := directory.ReadDir(lineageSpoolSlots + 3)
	directory.Close()
	if err != nil && err != io.EOF || len(entries) > lineageSpoolSlots+2 {
		return 0, errLineageSpool
	}
	count := 0
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if err != nil {
			return 0, errLineageSpool
		}
		switch entry.Name() {
		case ".consumer.lock":
			if !lineageOwnedRegular(info, owner, 0600) || info.Size() != 0 {
				return 0, errLineageSpool
			}
		case ".pending":
			if (!lineageOwnedRegular(info, owner, 0600) && !lineageOwnedRegular(info, owner, 0440)) || info.Size() > lineageAckBytes {
				return 0, errLineageSpool
			}
		default:
			if !lineageAckName(entry.Name()) || !lineageOwnedRegular(info, owner, 0440) || info.Size() < 1 || info.Size() > lineageAckBytes {
				return 0, errLineageSpool
			}
			count++
		}
	}
	if count > lineageSpoolSlots {
		return 0, errLineageSpoolFull
	}
	return count, nil
}

func (store *lineageAcknowledgments) takeLock() error {
	if store.lock != nil {
		return nil
	}
	lock, err := store.root.OpenFile(".consumer.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errLineageSpool
	}
	store.lock = lock
	if !store.valid() || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil || !store.valid() {
		store.lock = nil
		lock.Close()
		return errLineageSpool
	}
	return nil
}

// publish is private: callers must prove sealed consumption before any output
// writes. Submitted/Dropped remain trusted local checkpoint accounting. This is
// not a cryptographic receipt from the remote service or permission to reclaim.
func (store *lineageAcknowledgments) publish(ctx context.Context, ack lineageConsumptionAck) error {
	data, err := json.Marshal(ack)
	name := "ack-" + ack.Consumption.Source.GenerationID + ".json"
	if store == nil || ctx == nil || ctx.Err() != nil || err != nil || len(data) > lineageAckBytes || !lineageAckName(name) {
		return errLineageSpool
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.valid() || store.takeLock() != nil {
		return errLineageSpool
	}
	count, err := store.scan()
	if err != nil || ctx.Err() != nil {
		return errLineageSpool
	}
	if _, err := store.root.Lstat(name); err == nil {
		previous, err := readLineageOwnedFile(store.root, name, store.owner, lineageAckBytes)
		if err != nil || !bytes.Equal(previous, data) {
			return errLineageSpool
		}
		file, err := store.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errLineageSpool
		}
		defer file.Close()
		held, err := file.Stat()
		named, namedErr := store.root.Lstat(name)
		if err != nil || namedErr != nil || !lineageOwnedRegular(held, store.owner, 0440) || !os.SameFile(held, named) || file.Sync() != nil || store.dir.Sync() != nil || !store.valid() || ctx.Err() != nil {
			return errLineageSpool
		}
		return nil
	} else if !os.IsNotExist(err) {
		return errLineageSpool
	}
	if count >= lineageSpoolSlots {
		return errLineageSpoolFull
	}
	// A failed publication may leave this one bounded, consumer-owned scratch
	// file. Recover it only under the stable lock; unknown entries are untouched.
	if info, err := store.root.Lstat(".pending"); err == nil {
		if (!lineageOwnedRegular(info, store.owner, 0600) && !lineageOwnedRegular(info, store.owner, 0440)) || info.Size() > lineageAckBytes || store.root.Remove(".pending") != nil || store.dir.Sync() != nil {
			return errLineageSpool
		}
	} else if !os.IsNotExist(err) {
		return errLineageSpool
	}
	file, err := store.root.OpenFile(".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errLineageSpool
	}
	defer file.Close()
	n, err := file.Write(data)
	if err != nil || n != len(data) || file.Chmod(0440) != nil || file.Sync() != nil || ctx.Err() != nil || !store.valid() {
		return errLineageSpool
	}
	if store.root.Rename(".pending", name) != nil || store.dir.Sync() != nil || !store.valid() || ctx.Err() != nil {
		return errLineageSpool
	}
	return nil
}

func (store *lineageAcknowledgments) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var first error
	for _, file := range []*os.File{store.lock, store.dir, store.parentDir} {
		if file != nil {
			if err := file.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	for _, root := range []*os.Root{store.root, store.parent} {
		if root != nil {
			if err := root.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}
func newAcknowledgingLineageChunkConsumer(reader *lineageSpoolReader, client *sensoradapter.ProductionClient, cursor string, maximum int, protected []sensoradapter.PinnedInput, store *lineageAcknowledgments) (*lineageChunkConsumer, error) {
	if store == nil {
		return nil, errLineageSpool
	}
	return buildLineageChunkConsumer(reader, client, cursor, maximum, protected, store)
}
func (consumer *lineageChunkConsumer) Acknowledge(ctx context.Context) error {
	if consumer == nil || consumer.reader == nil || consumer.processor == nil || consumer.acknowledgments == nil || ctx == nil || ctx.Err() != nil {
		return errLineageSpool
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	reader := consumer.reader
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !reader.valid() {
		return errLineageSpool
	}
	progress, durable, err := consumer.processor.Committed()
	if err != nil || !durable {
		return errLineageSpool
	}
	seal, found, err := reader.readSealLocked()
	if err != nil || !found || progress.NextSequence != seal.Chunks+1 || progress.Read != seal.Records || progress.Bytes != seal.Bytes {
		return errLineageSpool
	}
	proof, err := consumer.processor.VerifyConsumed(ctx)
	if err != nil || proof.Progress != progress || proof.Source != reader.source {
		return errLineageSpool
	}
	sealBytes, err := json.Marshal(seal)
	if err != nil {
		return errLineageSpool
	}
	currentSeal, err := readLineageOwnedFile(reader.root, "closed.json", reader.owner, 4096)
	if err != nil || !bytes.Equal(currentSeal, sealBytes) || !reader.valid() || ctx.Err() != nil {
		return errLineageSpool
	}
	return consumer.acknowledgments.publish(ctx, lineageConsumptionAck{
		Version: "tetragon-consumption-ack-v1", Consumption: proof,
		Manifest: lineageHash(reader.manifestBytes), Seal: seal, SealDigest: lineageHash(sealBytes),
	})
}
