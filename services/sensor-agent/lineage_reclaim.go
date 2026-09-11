package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageReclaimRequest struct {
	Source      sensoradapter.LineageSource `json:"source"`
	Destination string                      `json:"destination"`
	ConsumerUID uint32                      `json:"consumer_uid"`
}

// Only the producer's private bounded source is mutated. A durable intent owns
// one exact generation through restart. Consumer ACK/cursor retirement is separate.
func (spool *lineageSpool) ReclaimAcknowledged(ctx context.Context, receipts *lineageReceiptReader, request lineageReclaimRequest) (bool, error) {
	if spool == nil || ctx == nil || ctx.Err() != nil || request.ConsumerUID == ^uint32(0) || request.Destination == "" {
		return false, errLineageSpool
	}
	if _, err := lineageManifestBytes(request.Source); err != nil {
		return false, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	if !spool.valid() || spool.active != nil && spool.active.source.GenerationID == request.Source.GenerationID {
		return false, errLineageSpool
	}
	inventory, err := spool.reclaimInventory()
	if err != nil {
		return false, err
	}
	id := request.Source.GenerationID
	original := "generation-" + id
	tomb := ".reclaim-" + id
	markerName := "reclaim-" + id + ".json"
	if !inventory.markers[id] {
		if inventory.directories[id] == "" {
			return false, nil
		}
		if inventory.directories[id] != original {
			return false, errLineageSpool
		}
		if len(inventory.markers) >= lineageSpoolSlots {
			return false, errLineageSpoolFull
		}
		if receipts == nil || receipts.owner != request.ConsumerUID {
			return false, errLineageSpool
		}
		ack, found, err := spool.verifyAcknowledgmentLocked(ctx, receipts, request.Source, request.Destination)
		if err != nil || !found {
			return false, err
		}
		dir, err := spool.openReclaimDirectory(original, ack)
		if err != nil {
			return false, err
		}
		defer dir.Close()
		files, err := dir.capture(ack)
		if err != nil {
			return false, err
		}
		spoolInfo, err := spool.dir.Stat()
		if err != nil {
			return false, errLineageSpool
		}
		spoolStat, ok := spoolInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return false, errLineageSpool
		}
		record := lineageReclaimRecord{Version: "tetragon-reclaim-v1", Request: request, Ack: ack, Files: files, SpoolDevice: uint64(spoolStat.Dev), SpoolInode: spoolStat.Ino}
		// The recorded inventory and admitted ACK must describe the same source.
		again, found, err := spool.verifyAcknowledgmentLocked(ctx, receipts, request.Source, request.Destination)
		if err != nil || !found || again != ack {
			return false, errLineageSpool
		}
		if receipts.syncAcknowledgment(ctx, ack) != nil {
			return false, errLineageSpool
		}
		held, err := dir.files(record, true)
		if err != nil {
			return false, err
		}
		defer closeReclaimFiles(held)
		if spool.publishReclaim(ctx, record, nil) != nil {
			return false, errLineageSpool
		}
		closeReclaimFiles(held)
	}
	marker, err := spool.readReclaimMarker(markerName)
	if err != nil {
		return false, err
	}
	defer marker.file.Close()
	if marker.record.Request != request {
		return false, errLineageSpool
	}
	_, originalErr := spool.root.Lstat(original)
	_, tombErr := spool.root.Lstat(tomb)
	originalExists, tombExists := originalErr == nil, tombErr == nil
	if originalErr != nil && !os.IsNotExist(originalErr) || tombErr != nil && !os.IsNotExist(tombErr) || originalExists && tombExists {
		return false, errLineageSpool
	}
	_, pendingErr := spool.root.Lstat(".reclaim.pending")
	if pendingErr != nil && !os.IsNotExist(pendingErr) || pendingErr == nil && (originalExists || tombExists) {
		return false, errLineageSpool
	}
	if marker.record.Complete {
		if originalExists || tombExists || pendingErr == nil {
			return false, errLineageSpool
		}
		if marker.sync(ctx) != nil {
			return false, errLineageSpool
		}
		return true, nil
	}
	if originalExists || tombExists {
		name := tomb
		if originalExists {
			name = original
		}
		dir, err := spool.openReclaimDirectory(name, marker.record.Ack)
		if err != nil {
			return false, err
		}
		defer dir.Close()
		// A live-name source must still be complete. Only an admitted tombstone
		// may contain a subset left by interrupted deletion.
		held, err := dir.files(marker.record, originalExists)
		if err != nil {
			return false, err
		}
		defer closeReclaimFiles(held)
		if marker.sync(ctx) != nil {
			return false, errLineageSpool
		}
		if originalExists {
			if ctx.Err() != nil || !dir.valid() || !marker.valid() {
				return false, errLineageSpool
			}
			if _, err := spool.root.Lstat(tomb); !os.IsNotExist(err) {
				return false, errLineageSpool
			}
			if spool.root.Rename(original, tomb) != nil {
				return false, errLineageSpool
			}
			dir.name = tomb
			if ctx.Err() != nil || spool.dir.Sync() != nil || !dir.valid() || !marker.valid() {
				return false, errLineageSpool
			}
		}
		for _, file := range held {
			if ctx.Err() != nil || !marker.valid() || !dir.valid() || !file.valid(dir) {
				return false, errLineageSpool
			}
			if dir.root.Remove(file.record.Name) != nil || ctx.Err() != nil {
				return false, errLineageSpool
			}
		}
		if dir.dir.Sync() != nil || ctx.Err() != nil || !dir.valid() || !marker.valid() {
			return false, errLineageSpool
		}
		check, err := dir.root.Open(".")
		if err != nil {
			return false, errLineageSpool
		}
		remaining, readErr := check.ReadDir(1)
		check.Close()
		if readErr != nil && readErr != io.EOF || len(remaining) != 0 {
			return false, errLineageSpool
		}
		if ctx.Err() != nil || !dir.valid() || !marker.valid() || spool.root.Remove(tomb) != nil {
			return false, errLineageSpool
		}
		if ctx.Err() != nil || spool.dir.Sync() != nil {
			return false, errLineageSpool
		}
	}
	// Both names are absent. Sync that absence before publishing completion.
	if marker.sync(ctx) != nil {
		return false, errLineageSpool
	}
	completed := marker.record
	completed.Complete = true
	if spool.publishReclaim(ctx, completed, marker) != nil {
		return false, errLineageSpool
	}
	return true, nil
}

type lineageReclaimDirectory struct {
	spool         *lineageSpool
	root          *os.Root
	dir           *os.File
	name          string
	device, inode uint64
}

func (spool *lineageSpool) openReclaimDirectory(name string, ack lineageConsumptionAck) (*lineageReclaimDirectory, error) {
	named, err := spool.root.Lstat(name)
	if err != nil || !named.IsDir() {
		return nil, errLineageSpool
	}
	root, err := spool.root.OpenRoot(name)
	if err != nil {
		return nil, errLineageSpool
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errLineageSpool
	}
	result := &lineageReclaimDirectory{spool: spool, root: root, dir: dir, name: name, device: ack.Consumption.Device, inode: ack.Consumption.Inode}
	if !result.valid() {
		result.Close()
		return nil, errLineageSpool
	}
	return result, nil
}
func (dir *lineageReclaimDirectory) Close() { dir.dir.Close(); dir.root.Close() }
func (dir *lineageReclaimDirectory) valid() bool {
	if !dir.spool.valid() || !lineageOwnedDirectory(dir.dir, dir.spool.owner) {
		return false
	}
	held, err := dir.dir.Stat()
	named, namedErr := dir.spool.root.Lstat(dir.name)
	if err != nil || namedErr != nil || !named.IsDir() || held.Mode().Perm() != 0750 || !os.SameFile(held, named) {
		return false
	}
	stat, ok := held.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == dir.device && stat.Ino == dir.inode
}
func (dir *lineageReclaimDirectory) capture(ack lineageConsumptionAck) ([]lineageReclaimFile, error) {
	files := make([]lineageReclaimFile, 0, ack.Seal.Chunks+2)
	for _, name := range reclaimFileNames(ack.Seal) {
		raw, err := readLineageReclaimFile(dir.root, name, dir.spool.owner)
		if err != nil {
			return nil, errLineageSpool
		}
		info, err := dir.root.Lstat(name)
		if err != nil {
			return nil, errLineageSpool
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != dir.device {
			return nil, errLineageSpool
		}
		files = append(files, lineageReclaimFile{Name: name, Size: int64(len(raw)), Digest: lineageHash(raw), Device: uint64(stat.Dev), Inode: stat.Ino})
	}
	return files, nil
}

type lineageReclaimOpenFile struct {
	file   *os.File
	info   os.FileInfo
	record lineageReclaimFile
}

func closeReclaimFiles(files []lineageReclaimOpenFile) {
	for _, file := range files {
		file.file.Close()
	}
}
func (file lineageReclaimOpenFile) valid(dir *lineageReclaimDirectory) bool {
	held, err := file.file.Stat()
	named, namedErr := dir.root.Lstat(file.record.Name)
	return err == nil && namedErr == nil && lineageOwnedRegular(held, dir.spool.owner, 0440) && lineageOwnedRegular(named, dir.spool.owner, 0440) && os.SameFile(held, named) && os.SameFile(file.info, held) && held.Size() == file.record.Size && held.ModTime().Equal(file.info.ModTime())
}
func (dir *lineageReclaimDirectory) files(record lineageReclaimRecord, full bool) (_ []lineageReclaimOpenFile, err error) {
	files := make([]lineageReclaimOpenFile, 0, len(record.Files))
	defer func() {
		if err != nil {
			closeReclaimFiles(files)
		}
	}()
	if !dir.valid() {
		return nil, errLineageSpool
	}
	directory, err := dir.root.Open(".")
	if err != nil {
		return nil, errLineageSpool
	}
	entries, err := directory.ReadDir(len(record.Files) + 1)
	directory.Close()
	if err != nil && err != io.EOF || len(entries) > len(record.Files) || full && len(entries) != len(record.Files) {
		return nil, errLineageSpool
	}
	expected := map[string]bool{}
	for _, file := range record.Files {
		expected[file.Name] = true
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return nil, errLineageSpool
		}
	}
	for _, expected := range record.Files {
		if _, err := dir.root.Lstat(expected.Name); os.IsNotExist(err) && !full {
			continue
		} else if err != nil {
			return nil, errLineageSpool
		}
		raw, err := readLineageReclaimFile(dir.root, expected.Name, dir.spool.owner)
		if err != nil || int64(len(raw)) != expected.Size || lineageHash(raw) != expected.Digest {
			return nil, errLineageSpool
		}
		file, err := dir.root.OpenFile(expected.Name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, errLineageSpool
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, errLineageSpool
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		held := lineageReclaimOpenFile{file: file, info: info, record: expected}
		files = append(files, held)
		pinnedBytes := make([]byte, len(raw))
		n, readErr := file.ReadAt(pinnedBytes, 0)
		if !ok || uint64(stat.Dev) != expected.Device || stat.Ino != expected.Inode || readErr != nil || n != len(raw) || !bytes.Equal(pinnedBytes, raw) || !held.valid(dir) {
			return nil, errLineageSpool
		}
	}
	return files, nil
}
