package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"
)

const lineageReclaimBytes = 64 << 10

type lineageReclaimFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"sha256"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}
type lineageReclaimRecord struct {
	SpoolDevice uint64                `json:"spool_device"`
	SpoolInode  uint64                `json:"spool_inode"`
	Version     string                `json:"version"`
	Complete    bool                  `json:"complete"`
	Request     lineageReclaimRequest `json:"request"`
	Ack         lineageConsumptionAck `json:"ack"`
	Files       []lineageReclaimFile  `json:"files"`
}

func reclaimFileNames(seal lineageSpoolSeal) []string {
	names := make([]string, 0, seal.Chunks+3)
	for sequence := 1; sequence <= seal.Chunks; sequence++ {
		names = append(names, fmt.Sprintf("chunk-%010d.jsonl", sequence))
	}
	if seal.InterruptedDigest != "" {
		names = append(names, "interrupted.bin")
	}
	return append(names, "closed.json", "manifest.json")
}

func readLineageReclaimFile(root *os.Root, name string, owner uint32) ([]byte, error) {
	minimum := int64(1)
	if name == "interrupted.bin" {
		minimum = 0
	}
	return readLineageOwnedBoundedFile(root, name, owner, minimum, reclaimFileLimit(name))
}
func reclaimFileLimit(name string) int64 {
	if name == "manifest.json" || name == "closed.json" {
		return 4096
	}
	return lineageChunkBytes + 1024
}

func validReclaimRecord(record lineageReclaimRecord) bool {
	target, targetErr := url.Parse(record.Request.Destination)
	if targetErr != nil || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || target.Path != "/internal/v1/runtime/events" || target.RawPath != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || target.RawFragment != "" || target.Opaque != "" || target.String() != record.Request.Destination || record.SpoolInode == 0 {
		return false
	}
	manifest, err := lineageManifestBytes(record.Request.Source)
	ack := record.Ack
	seal := ack.Seal
	progress := ack.Consumption.Progress
	if err != nil || record.Version != "tetragon-reclaim-v1" || record.Request.ConsumerUID == ^uint32(0) || record.Request.Destination == "" || len(record.Request.Destination) > 2048 || ack.Version != "tetragon-consumption-ack-v1" || ack.Consumption.Source != record.Request.Source || ack.Consumption.Destination != record.Request.Destination || ack.Consumption.Inode == 0 || ack.Manifest != lineageHash(manifest) || seal.Version != "tetragon-spool-closed-v1" || seal.Manifest != ack.Manifest || seal.CoverageComplete || seal.Chunks < 0 || seal.Chunks > lineageSpoolChunks || seal.Records < seal.Chunks || seal.Records > seal.Chunks*1000 || seal.Bytes < int64(seal.Records)*2 || seal.Bytes > lineageSpoolBytes || seal.Chunks == 0 && (seal.Records != 0 || seal.Bytes != 0) || progress.NextSequence != seal.Chunks+1 || progress.Read != seal.Records || progress.Bytes != seal.Bytes || progress.Submitted < 0 || progress.Submitted > progress.Read || progress.Dropped != uint64(progress.Read-progress.Submitted) || !enrollmentBindingPattern.MatchString(progress.Chain) {
		return false
	}
	if !validLineageSealRecovery(seal) {
		return false
	}
	sealBytes, _ := json.Marshal(seal)
	if ack.SealDigest != lineageHash(sealBytes) || len(record.Files) != len(reclaimFileNames(seal)) {
		return false
	}
	names := reclaimFileNames(seal)
	for index, file := range record.Files {
		minimum := int64(1)
		if file.Name == "interrupted.bin" {
			minimum = 0
		}
		if file.Name != names[index] || file.Size < minimum || file.Size > reclaimFileLimit(file.Name) || !enrollmentBindingPattern.MatchString(file.Digest) || file.Inode == 0 || file.Device != ack.Consumption.Device {
			return false
		}
		if file.Name == "interrupted.bin" && (file.Size != seal.InterruptedBytes || file.Digest != seal.InterruptedDigest) {
			return false
		}
		if file.Name == "manifest.json" && (file.Digest != ack.Manifest || file.Size != int64(len(manifest))) {
			return false
		}
		if file.Name == "closed.json" && (file.Digest != ack.SealDigest || file.Size != int64(len(sealBytes))) {
			return false
		}
	}
	return true
}

type lineageReclaimMarker struct {
	spool  *lineageSpool
	file   *os.File
	name   string
	raw    []byte
	record lineageReclaimRecord
}

func (spool *lineageSpool) readReclaimMarker(name string) (*lineageReclaimMarker, error) {
	raw, err := readLineageOwnedFile(spool.root, name, spool.owner, lineageReclaimBytes)
	if err != nil {
		return nil, errLineageSpool
	}
	var record lineageReclaimRecord
	if !lineageDecodeCanonical(raw, &record) || !validReclaimRecord(record) || name != "reclaim-"+record.Request.Source.GenerationID+".json" {
		return nil, errLineageSpool
	}
	info, err := spool.dir.Stat()
	if err != nil {
		return nil, errLineageSpool
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != record.SpoolDevice || stat.Ino != record.SpoolInode {
		return nil, errLineageSpool
	}
	file, err := spool.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLineageSpool
	}
	marker := &lineageReclaimMarker{spool: spool, file: file, name: name, raw: raw, record: record}
	if !marker.valid() {
		file.Close()
		return nil, errLineageSpool
	}
	return marker, nil
}
func (marker *lineageReclaimMarker) valid() bool {
	if !marker.spool.valid() {
		return false
	}
	held, err := marker.file.Stat()
	named, namedErr := marker.spool.root.Lstat(marker.name)
	if err != nil || namedErr != nil || !lineageOwnedRegular(held, marker.spool.owner, 0440) || !lineageOwnedRegular(named, marker.spool.owner, 0440) || held.Size() != int64(len(marker.raw)) || !os.SameFile(held, named) {
		return false
	}
	data := make([]byte, len(marker.raw))
	n, err := marker.file.ReadAt(data, 0)
	return err == nil && n == len(data) && bytes.Equal(data, marker.raw)
}
func (marker *lineageReclaimMarker) sync(ctx context.Context) error {
	if ctx.Err() != nil || !marker.valid() || marker.file.Sync() != nil || marker.spool.dir.Sync() != nil || !marker.valid() || ctx.Err() != nil {
		return errLineageSpool
	}
	return nil
}

type lineageSpoolInventory struct {
	directories map[string]string
	markers     map[string]bool
	pending     bool
}

func (spool *lineageSpool) reclaimInventory() (lineageSpoolInventory, error) {
	result := lineageSpoolInventory{directories: map[string]string{}, markers: map[string]bool{}}
	if !spool.valid() {
		return result, errLineageSpool
	}
	dir, err := spool.root.Open(".")
	if err != nil {
		return result, errLineageSpool
	}
	entries, err := dir.ReadDir(2*lineageSpoolSlots + 3)
	dir.Close()
	if err != nil && err != io.EOF || len(entries) > 2*lineageSpoolSlots+2 {
		return result, errLineageSpool
	}
	for _, entry := range entries {
		name := entry.Name()
		info, err := spool.root.Lstat(name)
		if err != nil {
			return result, errLineageSpool
		}
		if name == ".producer.lock" {
			continue
		}
		if name == ".reclaim.pending" {
			if (!lineageOwnedRegular(info, spool.owner, 0600) && !lineageOwnedRegular(info, spool.owner, 0440)) || info.Size() > lineageReclaimBytes {
				return result, errLineageSpool
			}
			result.pending = true
			continue
		}
		if strings.HasPrefix(name, "reclaim-") && strings.HasSuffix(name, ".json") {
			id := strings.TrimSuffix(strings.TrimPrefix(name, "reclaim-"), ".json")
			if !validLineageUUID(id) {
				return result, errLineageSpool
			}
			marker, err := spool.readReclaimMarker(name)
			if err != nil {
				return result, err
			}
			marker.file.Close()
			result.markers[id] = true
			continue
		}
		id := ""
		if strings.HasPrefix(name, "generation-") {
			id = strings.TrimPrefix(name, "generation-")
		} else if strings.HasPrefix(name, ".reclaim-") {
			id = strings.TrimPrefix(name, ".reclaim-")
		} else if strings.HasPrefix(name, ".creating-") {
			id = strings.TrimPrefix(name, ".creating-")
		} else if strings.HasPrefix(name, ".discard-") {
			id = strings.TrimPrefix(name, ".discard-")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !validLineageUUID(id) || !info.IsDir() || !ok || stat.Uid != spool.owner || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || (info.Mode().Perm() != 0700 && info.Mode().Perm() != 0750) || result.directories[id] != "" {
			return result, errLineageSpool
		}
		result.directories[id] = name
	}
	if len(result.directories) > lineageSpoolSlots || len(result.markers) > lineageSpoolSlots {
		return result, errLineageSpoolFull
	}
	return result, nil
}

// Recover only this protocol's owned scratch whose bytes are a prefix of the
// exact publication being retried. A different or ambiguous payload is retained.
func (spool *lineageSpool) recoverReclaimScratch(ctx context.Context, expected []byte) error {
	info, err := spool.root.Lstat(".reclaim.pending")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || (!lineageOwnedRegular(info, spool.owner, 0600) && !lineageOwnedRegular(info, spool.owner, 0440)) || info.Size() > int64(len(expected)) {
		return errLineageSpool
	}
	file, err := spool.root.OpenFile(".reclaim.pending", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errLineageSpool
	}
	defer file.Close()
	held, err := file.Stat()
	if err != nil || !os.SameFile(info, held) {
		return errLineageSpool
	}
	data, err := io.ReadAll(io.LimitReader(file, lineageReclaimBytes+1))
	named, namedErr := spool.root.Lstat(".reclaim.pending")
	if err != nil || namedErr != nil || int64(len(data)) != info.Size() || !bytes.HasPrefix(expected, data) || !os.SameFile(held, named) || named.Mode() != info.Mode() || named.Size() != info.Size() || ctx.Err() != nil || !spool.valid() {
		return errLineageSpool
	}
	if spool.root.Remove(".reclaim.pending") != nil || spool.dir.Sync() != nil || ctx.Err() != nil {
		return errLineageSpool
	}
	return nil
}

func (spool *lineageSpool) publishReclaim(ctx context.Context, record lineageReclaimRecord, previous *lineageReclaimMarker) error {
	data, err := json.Marshal(record)
	if err != nil || !validReclaimRecord(record) || len(data) > lineageReclaimBytes || ctx.Err() != nil || !spool.valid() {
		return errLineageSpool
	}
	name := "reclaim-" + record.Request.Source.GenerationID + ".json"
	if previous == nil {
		if _, err := spool.root.Lstat(name); !os.IsNotExist(err) {
			return errLineageSpool
		}
	} else if previous.name != name || !previous.valid() {
		return errLineageSpool
	}
	if spool.recoverReclaimScratch(ctx, data) != nil {
		return errLineageSpool
	}
	file, err := spool.root.OpenFile(".reclaim.pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errLineageSpool
	}
	defer file.Close()
	n, err := file.Write(data)
	if err != nil || n != len(data) || file.Chmod(0440) != nil || file.Sync() != nil || ctx.Err() != nil || !spool.valid() {
		return errLineageSpool
	}
	if previous == nil {
		if _, err := spool.root.Lstat(name); !os.IsNotExist(err) {
			return errLineageSpool
		}
	} else if !previous.valid() {
		return errLineageSpool
	}
	if spool.root.Rename(".reclaim.pending", name) != nil || ctx.Err() != nil || spool.dir.Sync() != nil || ctx.Err() != nil {
		return errLineageSpool
	}
	return nil
}
