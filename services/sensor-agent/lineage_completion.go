package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageCompletionReader struct{ directory *lineageReceiptReader }

func newLineageCompletionReader(path string, producerUID uint32) (*lineageCompletionReader, error) {
	directory, err := openLineageReadOnlyDirectory(path, producerUID)
	if err != nil {
		return nil, err
	}
	return &lineageCompletionReader{directory: directory}, nil
}

func newProductionLineageCompletionReader(path string) (*lineageCompletionReader, error) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return nil, errLineageSpool
	}
	return newLineageCompletionReader(path, 0)
}

func (reader *lineageCompletionReader) Close() error {
	if reader == nil || reader.directory == nil {
		return nil
	}
	return reader.directory.Close()
}

// The caller holds the directory lifetime mutex. This read path takes no
// producer lock, creates no file and exposes no producer mutation methods.
func (reader *lineageCompletionReader) read(request lineageReclaimRequest) (*lineagePinnedCompletion, bool, error) {
	directory := reader.directory
	if !directory.valid() {
		return nil, false, errLineageSpool
	}
	if _, err := lineageManifestBytes(request.Source); err != nil {
		return nil, false, err
	}
	name := "reclaim-" + request.Source.GenerationID + ".json"
	if _, err := directory.root.Lstat(name); os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, errLineageSpool
	}
	file, err := pinLineageExactFile(directory.root, name, directory.owner, lineageReclaimBytes, nil)
	if err != nil {
		return nil, false, err
	}
	var record lineageReclaimRecord
	if !lineageDecodeCanonical(file.raw, &record) || !validReclaimRecord(record) || !record.Complete || record.Request != request {
		file.file.Close()
		return nil, false, errLineageSpool
	}
	completion := &lineagePinnedCompletion{reader: reader, file: file, record: record}
	if !completion.valid() {
		file.file.Close()
		return nil, false, errLineageSpool
	}
	return completion, true, nil
}

type lineagePinnedCompletion struct {
	reader *lineageCompletionReader
	file   *lineageExactFile
	record lineageReclaimRecord
}

func (completion *lineagePinnedCompletion) valid() bool {
	directory := completion.reader.directory
	if !directory.valid() || !completion.file.valid() {
		return false
	}
	info, err := directory.dir.Stat()
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != completion.record.SpoolDevice || stat.Ino != completion.record.SpoolInode {
		return false
	}
	for _, prefix := range []string{"generation-", ".reclaim-"} {
		if _, err := directory.root.Lstat(prefix + completion.record.Request.Source.GenerationID); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func (completion *lineagePinnedCompletion) sync(ctx context.Context) error {
	// A visible completion rename may precede the producer's directory sync.
	// Re-establish those barriers ourselves before any consumer state deletion.
	if ctx.Err() != nil || !completion.valid() || completion.file.file.Sync() != nil || completion.reader.directory.dir.Sync() != nil || ctx.Err() != nil || !completion.valid() {
		return errLineageSpool
	}
	return nil
}

type lineageExactFile struct {
	root  *os.Root
	file  *os.File
	name  string
	owner uint32
	raw   []byte
}

func pinLineageExactFile(root *os.Root, name string, owner uint32, maximum int64, expected []byte) (*lineageExactFile, error) {
	raw, err := readLineageOwnedFile(root, name, owner, maximum)
	if err != nil || expected != nil && !bytes.Equal(raw, expected) {
		return nil, errLineageSpool
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errLineageSpool
	}
	pinned := &lineageExactFile{root: root, file: file, name: name, owner: owner, raw: raw}
	if !pinned.valid() {
		file.Close()
		return nil, errLineageSpool
	}
	return pinned, nil
}

func (file *lineageExactFile) valid() bool {
	held, err := file.file.Stat()
	named, namedErr := file.root.Lstat(file.name)
	if err != nil || namedErr != nil || !lineageOwnedRegular(held, file.owner, 0440) || !lineageOwnedRegular(named, file.owner, 0440) || held.Size() != int64(len(file.raw)) || named.Size() != held.Size() || !os.SameFile(held, named) {
		return false
	}
	data := make([]byte, len(file.raw))
	n, err := file.file.ReadAt(data, 0)
	return err == nil && n == len(data) && bytes.Equal(data, file.raw)
}

// RetireCheckpoint leaves both the ACK and producer completion record intact.
// Their retirement/collection is a separate crash-safe handshake.
func (store *lineageAcknowledgments) RetireCheckpoint(ctx context.Context, reader *lineageCompletionReader, request lineageReclaimRequest, cursor string, maximum int, protected []sensoradapter.PinnedInput) (bool, error) {
	return store.retireCheckpoint(ctx, reader, request, cursor, maximum, protected, false)
}

func (store *lineageAcknowledgments) retireCheckpoint(ctx context.Context, reader *lineageCompletionReader, request lineageReclaimRequest, cursor string, maximum int, protected []sensoradapter.PinnedInput, publishRetired bool) (bool, error) {
	return store.retireBoundCheckpoint(ctx, reader, request, cursor, maximum, protected, publishRetired, nil)
}

func (store *lineageAcknowledgments) retireBoundCheckpoint(ctx context.Context, reader *lineageCompletionReader, request lineageReclaimRequest, cursor string, maximum int, protected []sensoradapter.PinnedInput, publishRetired bool, binding *sensoradapter.ChunkStateBinding) (bool, error) {
	if store == nil || reader == nil || reader.directory == nil || ctx == nil || ctx.Err() != nil || request.ConsumerUID != uint32(os.Geteuid()) || request.ConsumerUID != store.owner || !validAbsolute(cursor) || maximum < 1 || maximum > 100_000 || len(protected) > 8 {
		return false, errLineageSpool
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	reader.directory.mu.Lock()
	defer reader.directory.mu.Unlock()
	if !store.valid() || !reader.directory.valid() {
		return false, errLineageSpool
	}
	storeInfo, err := store.dir.Stat()
	producerInfo, producerErr := reader.directory.dir.Stat()
	if err != nil || producerErr != nil || os.SameFile(storeInfo, producerInfo) {
		return false, errLineageSpool
	}
	cursorRoot, err := os.OpenRoot(filepath.Dir(cursor))
	if err != nil {
		return false, errLineageSpool
	}
	defer cursorRoot.Close()
	cursorInfo, err := lineageReadOnlyRootInfo(cursorRoot)
	if err != nil || os.SameFile(storeInfo, cursorInfo) || os.SameFile(producerInfo, cursorInfo) {
		return false, errLineageSpool
	}
	for _, input := range protected {
		if input.Parent == nil || input.Name == "" || input.Name == "." || input.Name == ".." || filepath.Base(input.Name) != input.Name {
			return false, errLineageSpool
		}
		inputInfo, err := lineageReadOnlyRootInfo(input.Parent)
		if err != nil || os.SameFile(storeInfo, inputInfo) {
			return false, errLineageSpool
		}
	}
	completion, found, err := reader.read(request)
	if err != nil || !found {
		return false, err
	}
	defer completion.file.file.Close()
	expected, _ := json.Marshal(completion.record.Ack)
	retired, err := retirementAckFor(completion, store)
	if err != nil {
		return false, err
	}
	retiredBytes, _ := json.Marshal(retired)
	ack, err := pinLineageExactFile(store.root, "ack-"+request.Source.GenerationID+".json", store.owner, lineageAckBytes, nil)
	if err != nil {
		return false, err
	}
	defer ack.file.Close()
	alreadyRetired := publishRetired && bytes.Equal(ack.raw, retiredBytes)
	if !alreadyRetired && !bytes.Equal(ack.raw, expected) {
		return false, errLineageSpool
	}
	if store.takeLock() != nil {
		return false, errLineageSpool
	}
	if _, err := store.scan(); err != nil {
		return false, err
	}
	authorize := func(ctx context.Context) error {
		if ctx.Err() != nil || !store.valid() || !ack.valid() || completion.sync(ctx) != nil || !store.valid() || !ack.valid() {
			return errLineageSpool
		}
		return nil
	}
	if authorize(ctx) != nil {
		return false, errLineageSpool
	}
	if alreadyRetired {
		if ack.file.Sync() != nil || store.dir.Sync() != nil || ctx.Err() != nil || !store.valid() || !ack.valid() {
			return false, errLineageSpool
		}
		return true, nil
	}
	err = sensoradapter.RetireConsumedCheckpoint(ctx, sensoradapter.ChunkRetirementConfig{
		CursorPath: cursor, Source: request.Source, Destination: request.Destination, Consumption: completion.record.Ack.Consumption, MaximumProcesses: maximum,
		ProtectedInputs: protected, DisjointRoots: []*os.Root{store.root, reader.directory.root}, Authorize: authorize,
		StateBinding: binding, SpoolRoot: reader.directory.root,
	})
	if err != nil || authorize(ctx) != nil {
		return false, errLineageSpool
	}
	if publishRetired && store.publishRetirement(ctx, ack, retiredBytes, authorize) != nil {
		return false, errLineageSpool
	}
	return true, nil
}

func lineageReadOnlyRootInfo(root *os.Root) (os.FileInfo, error) {
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}
