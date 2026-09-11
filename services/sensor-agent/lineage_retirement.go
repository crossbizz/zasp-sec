package main

import (
	"bytes"
	"context"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"io"
	"net/url"
	"os"
	"syscall"
)

type lineageRetirementAck struct {
	Version          string                `json:"version"`
	Request          lineageReclaimRequest `json:"request"`
	CompletionDigest string                `json:"completion_sha256"`
	SpoolDevice      uint64                `json:"spool_device"`
	SpoolInode       uint64                `json:"spool_inode"`
	AckDevice        uint64                `json:"ack_device"`
	AckInode         uint64                `json:"ack_inode"`
}

func (store *lineageAcknowledgments) RetireAcknowledgment(ctx context.Context, reader *lineageCompletionReader, request lineageReclaimRequest, cursor string, maximum int, protected []sensoradapter.PinnedInput) (bool, error) {
	return store.retireCheckpoint(ctx, reader, request, cursor, maximum, protected, true)
}

func validRetirementRequest(request lineageReclaimRequest) bool {
	if _, err := lineageManifestBytes(request.Source); err != nil {
		return false
	}
	return request.ConsumerUID != ^uint32(0) && validLineageDestination(request.Destination)
}

func validLineageDestination(destination string) bool {
	target, err := url.Parse(destination)
	return len(destination) <= 2048 && err == nil && target.Scheme == "https" && target.Hostname() != "" && target.User == nil && target.Path == "/internal/v1/runtime/events" && target.RawPath == "" && target.RawQuery == "" && !target.ForceQuery && target.Fragment == "" && target.RawFragment == "" && target.Opaque == "" && target.String() == destination
}

func validRetirementAck(record lineageRetirementAck) bool {
	return record.Version == "tetragon-retirement-ack-v1" && validRetirementRequest(record.Request) && enrollmentBindingPattern.MatchString(record.CompletionDigest) && record.SpoolInode != 0 && record.AckInode != 0
}

func retirementAckFor(completion *lineagePinnedCompletion, store *lineageAcknowledgments) (lineageRetirementAck, error) {
	info, err := store.dir.Stat()
	if err != nil {
		return lineageRetirementAck{}, errLineageSpool
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return lineageRetirementAck{}, errLineageSpool
	}
	record := lineageRetirementAck{Version: "tetragon-retirement-ack-v1", Request: completion.record.Request, CompletionDigest: lineageHash(completion.file.raw), SpoolDevice: completion.record.SpoolDevice, SpoolInode: completion.record.SpoolInode, AckDevice: uint64(stat.Dev), AckInode: stat.Ino}
	if !validRetirementAck(record) {
		return lineageRetirementAck{}, errLineageSpool
	}
	return record, nil
}

func retirementDirectoriesMatch(record lineageRetirementAck, spool, acks *os.File) bool {
	sourceInfo, err := spool.Stat()
	ackInfo, ackErr := acks.Stat()
	if err != nil || ackErr != nil || os.SameFile(sourceInfo, ackInfo) {
		return false
	}
	sourceStat, sourceOK := sourceInfo.Sys().(*syscall.Stat_t)
	ackStat, ackOK := ackInfo.Sys().(*syscall.Stat_t)
	return sourceOK && ackOK && uint64(sourceStat.Dev) == record.SpoolDevice && sourceStat.Ino == record.SpoolInode && uint64(ackStat.Dev) == record.AckDevice && ackStat.Ino == record.AckInode
}

func lineageSourceNamesAbsent(root *os.Root, id string) bool {
	for _, prefix := range []string{"generation-", ".reclaim-"} {
		if _, err := root.Lstat(prefix + id); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Replace only the exact acknowledged payload after checkpoint retirement.
// This consumer-owned version change is the producer's collection permission.
func (store *lineageAcknowledgments) publishRetirement(ctx context.Context, previous *lineageExactFile, data []byte, authorize func(context.Context) error) error {
	if len(data) > lineageAckBytes || authorize(ctx) != nil {
		return errLineageSpool
	}
	if info, err := store.root.Lstat(".pending"); err == nil {
		if (!lineageOwnedRegular(info, store.owner, 0600) && !lineageOwnedRegular(info, store.owner, 0440)) || info.Size() > int64(len(data)) {
			return errLineageSpool
		}
		file, err := store.root.OpenFile(".pending", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return errLineageSpool
		}
		defer file.Close()
		held, err := file.Stat()
		if err != nil || !os.SameFile(info, held) {
			return errLineageSpool
		}
		raw, err := io.ReadAll(io.LimitReader(file, lineageAckBytes+1))
		named, namedErr := store.root.Lstat(".pending")
		if err != nil || namedErr != nil || !os.SameFile(held, named) || named.Mode() != held.Mode() || named.Size() != held.Size() || int64(len(raw)) != held.Size() || !bytes.HasPrefix(data, raw) || authorize(ctx) != nil {
			return errLineageSpool
		}
		if store.root.Remove(".pending") != nil || store.dir.Sync() != nil || ctx.Err() != nil {
			return errLineageSpool
		}
	} else if !os.IsNotExist(err) {
		return errLineageSpool
	}
	file, err := store.root.OpenFile(".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errLineageSpool
	}
	defer file.Close()
	n, err := file.Write(data)
	if err != nil || n != len(data) || file.Chmod(0440) != nil || file.Sync() != nil || authorize(ctx) != nil || !previous.valid() {
		return errLineageSpool
	}
	if store.root.Rename(".pending", previous.name) != nil || ctx.Err() != nil || store.dir.Sync() != nil || ctx.Err() != nil || !store.valid() {
		return errLineageSpool
	}
	current, err := pinLineageExactFile(store.root, previous.name, store.owner, lineageAckBytes, data)
	if err != nil {
		return err
	}
	defer current.file.Close()
	return nil
}

// Only the producer's completion file is removed. The consumer retirement
// receipt is retained until the consumer has synced this absence independently.
func (spool *lineageSpool) CollectCompletion(ctx context.Context, reader *lineageReceiptReader, request lineageReclaimRequest) (bool, error) {
	if spool == nil || reader == nil || ctx == nil || ctx.Err() != nil || !validRetirementRequest(request) || reader.owner != request.ConsumerUID {
		return false, errLineageSpool
	}
	spool.mu.Lock()
	defer spool.mu.Unlock()
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !spool.valid() || !reader.valid() || spool.active != nil && spool.active.source.GenerationID == request.Source.GenerationID || !lineageSourceNamesAbsent(spool.root, request.Source.GenerationID) {
		return false, errLineageSpool
	}
	if _, err := spool.reclaimInventory(); err != nil {
		return false, err
	}
	name := "ack-" + request.Source.GenerationID + ".json"
	if _, err := reader.root.Lstat(name); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, errLineageSpool
	}
	ack, err := pinLineageExactFile(reader.root, name, reader.owner, lineageAckBytes, nil)
	if err != nil {
		return false, err
	}
	defer ack.file.Close()
	var retired lineageRetirementAck
	if !lineageDecodeCanonical(ack.raw, &retired) || !validRetirementAck(retired) || retired.Request != request || !retirementDirectoriesMatch(retired, spool.dir, reader.dir) {
		return false, errLineageSpool
	}
	markerName := "reclaim-" + request.Source.GenerationID + ".json"
	if _, err := spool.root.Lstat(markerName); os.IsNotExist(err) {
		if ctx.Err() != nil || !spool.valid() || !reader.valid() || !ack.valid() || !lineageSourceNamesAbsent(spool.root, request.Source.GenerationID) || spool.dir.Sync() != nil || ctx.Err() != nil {
			return false, errLineageSpool
		}
		if !spool.valid() || !reader.valid() || !retirementDirectoriesMatch(retired, spool.dir, reader.dir) || !lineageSourceNamesAbsent(spool.root, request.Source.GenerationID) {
			return false, errLineageSpool
		}
		if _, err := spool.root.Lstat(markerName); !os.IsNotExist(err) {
			return false, errLineageSpool
		}
		return true, nil
	} else if err != nil {
		return false, errLineageSpool
	}
	marker, err := spool.readReclaimMarker(markerName)
	if err != nil {
		return false, err
	}
	defer marker.file.Close()
	if !marker.record.Complete || marker.record.Request != request || lineageHash(marker.raw) != retired.CompletionDigest {
		return false, errLineageSpool
	}
	if ctx.Err() != nil || !reader.valid() || !ack.valid() || ack.file.Sync() != nil || reader.dir.Sync() != nil || marker.sync(ctx) != nil || !reader.valid() || !ack.valid() || !marker.valid() || !lineageSourceNamesAbsent(spool.root, request.Source.GenerationID) {
		return false, errLineageSpool
	}
	if spool.root.Remove(markerName) != nil || ctx.Err() != nil || spool.dir.Sync() != nil || ctx.Err() != nil || !spool.valid() || !lineageSourceNamesAbsent(spool.root, request.Source.GenerationID) {
		return false, errLineageSpool
	}
	if _, err := spool.root.Lstat(markerName); !os.IsNotExist(err) {
		return false, errLineageSpool
	}
	return true, nil
}

// An absent target returns clean only after both directory barriers; it isn't
// evidence of former delivery. This operation never opens or deletes a cursor.
func (store *lineageAcknowledgments) ForgetRetirement(ctx context.Context, reader *lineageCompletionReader, request lineageReclaimRequest) (bool, error) {
	if store == nil || reader == nil || reader.directory == nil || ctx == nil || ctx.Err() != nil || !validRetirementRequest(request) || request.ConsumerUID != store.owner || request.ConsumerUID != uint32(os.Geteuid()) {
		return false, errLineageSpool
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	directory := reader.directory
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if !store.valid() || !directory.valid() {
		return false, errLineageSpool
	}
	storeInfo, err := store.dir.Stat()
	producerInfo, producerErr := directory.dir.Stat()
	if err != nil || producerErr != nil || os.SameFile(storeInfo, producerInfo) {
		return false, errLineageSpool
	}
	id := request.Source.GenerationID
	if !lineageSourceNamesAbsent(directory.root, id) {
		return false, errLineageSpool
	}
	if _, err := directory.root.Lstat("reclaim-" + id + ".json"); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, errLineageSpool
	}
	if store.takeLock() != nil {
		return false, errLineageSpool
	}
	if _, err := store.scan(); err != nil {
		return false, err
	}
	name := "ack-" + id + ".json"
	clean := func() bool {
		if ctx.Err() != nil || !store.valid() || !directory.valid() || !lineageSourceNamesAbsent(directory.root, id) {
			return false
		}
		_, err := directory.root.Lstat("reclaim-" + id + ".json")
		return os.IsNotExist(err)
	}
	if _, err := store.root.Lstat(name); os.IsNotExist(err) {
		if !clean() || directory.dir.Sync() != nil || store.dir.Sync() != nil || !clean() {
			return false, errLineageSpool
		}
		if _, err := store.root.Lstat(name); !os.IsNotExist(err) {
			return false, errLineageSpool
		}
		return true, nil
	} else if err != nil {
		return false, errLineageSpool
	}
	ack, err := pinLineageExactFile(store.root, name, store.owner, lineageAckBytes, nil)
	if err != nil {
		return false, err
	}
	defer ack.file.Close()
	var retired lineageRetirementAck
	if !lineageDecodeCanonical(ack.raw, &retired) || !validRetirementAck(retired) || retired.Request != request || !retirementDirectoriesMatch(retired, directory.dir, store.dir) {
		return false, errLineageSpool
	}
	if !clean() || !ack.valid() || directory.dir.Sync() != nil || !clean() || !ack.valid() {
		return false, errLineageSpool
	}
	if store.root.Remove(name) != nil || ctx.Err() != nil || store.dir.Sync() != nil || ctx.Err() != nil || !store.valid() {
		return false, errLineageSpool
	}
	if _, err := store.root.Lstat(name); !os.IsNotExist(err) {
		return false, errLineageSpool
	}
	return true, nil
}
