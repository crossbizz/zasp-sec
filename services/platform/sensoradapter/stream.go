package sensoradapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	cursorContractVersion = "tetragon-cursor-v1"
	maximumTetragonFile   = 128 << 20
	maximumCursorBytes    = 4096
	maximumLogFiles       = 32
	rotationTimestamp     = "2006-01-02T15-04-05.000"
)

var ErrStream = errors.New("sensor stream rejected")

type StreamSink interface {
	Ingest(context.Context, []RuntimeEvent) error
}

type FileProcessorConfig struct {
	LogPath         string
	CursorPath      string
	Normalizer      *Normalizer
	Sink            StreamSink
	MaximumLines    int
	ProtectedInputs []PinnedInput
}

// PinnedInput borrows an already-open parent from a read-only input owner.
// Construction checks that its basename cannot be replaced by cursor writes.
// The caller retains ownership of Parent and keeps it open during construction.
type PinnedInput struct {
	Parent *os.Root
	Name   string
}

type StreamResult struct {
	Read      int
	Submitted int
	Dropped   uint64
	Idle      bool
	// ProducerDroppedTotal is a durable cumulative counter, not a per-tick
	// delta. Omit new fields from legacy cursor JSON when unused.
	ProducerDroppedTotal uint64 `json:",omitempty"`
	// CoverageUnknown is the current accounting snapshot, not a new loss delta.
	CoverageUnknown bool `json:",omitempty"`
}

type cursorState struct {
	Version string `json:"version"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Offset  int64  `json:"offset"`
	Dropped uint64 `json:"dropped"`
}

type pendingStream struct {
	Events    []RuntimeEvent          `json:"events,omitempty"`
	Envelope  *RuntimeEnvelope        `json:"envelope,omitempty"`
	State     cursorState             `json:"next"`
	From      cursorState             `json:"from"`
	EndOffset int64                   `json:"end_offset"`
	Cache     []cachedProcessIdentity `json:"cache"`
	Result    StreamResult            `json:"result"`
}

type FileProcessor struct {
	mu              sync.Mutex
	logRoot         *os.Root
	logName         string
	cursorRoot      *os.Root
	cursorName      string
	cursorLock      *os.File
	sourceBinding   string
	checkpoint      *streamCheckpoint
	writeCheckpoint func(*os.Root, string, []byte) error
	normalizer      *Normalizer
	sink            StreamSink
	maximumLines    int
	pending         *pendingStream
	reconstructed   bool
	closed          bool
}

func NewFileProcessor(config FileProcessorConfig) (*FileProcessor, error) {
	if !validAbsoluteFilePath(config.LogPath) || !validAbsoluteFilePath(config.CursorPath) || config.LogPath == config.CursorPath || config.LogPath == config.CursorPath+".lock" || config.Normalizer == nil || nilInterface(config.Sink) || config.MaximumLines < 1 || config.MaximumLines > maximumBatchEvents || len(config.ProtectedInputs) > 8 {
		return nil, ErrStream
	}
	lineageSource := config.Normalizer.lineageSource
	if lineageSource != (LineageSource{}) {
		client, ok := config.Sink.(*ProductionClient)
		if !lineageSource.valid() || !ok || client == nil || client.enrollment != lineageSource.EnrollmentBinding {
			return nil, ErrStream
		}
	}
	logRoot, logName, err := openPinnedParent(config.LogPath)
	if err != nil {
		return nil, ErrStream
	}
	cursorRoot, cursorName, err := openPinnedParent(config.CursorPath)
	if err != nil {
		_ = logRoot.Close()
		return nil, ErrStream
	}
	if !validCursorName(cursorName) || !cursorInputDisjoint(cursorRoot, cursorName, logRoot, logName) {
		_ = logRoot.Close()
		_ = cursorRoot.Close()
		return nil, ErrStream
	}
	for _, input := range config.ProtectedInputs {
		if input.Parent == nil || input.Name == "" || input.Name == "." || input.Name == ".." || filepath.Base(input.Name) != input.Name || !cursorInputDisjoint(cursorRoot, cursorName, input.Parent, input.Name) {
			_ = logRoot.Close()
			_ = cursorRoot.Close()
			return nil, ErrStream
		}
	}
	lock, err := acquireCursorLock(cursorRoot, cursorName+".lock")
	if err != nil {
		_ = logRoot.Close()
		_ = cursorRoot.Close()
		return nil, ErrStream
	}
	source, err := streamSourceBinding(logRoot, config.LogPath)
	cache, cacheErr := config.Normalizer.checkpoint()
	privateNormalizer, normalizerErr := NewNormalizer(config.Normalizer.maximum)
	if normalizerErr == nil {
		privateNormalizer.lineageSource = lineageSource
	}
	if err != nil || cacheErr != nil || normalizerErr != nil || privateNormalizer.restoreCheckpoint(cache) != nil {
		_ = lock.Close()
		_ = logRoot.Close()
		_ = cursorRoot.Close()
		return nil, ErrStream
	}
	return &FileProcessor{logRoot: logRoot, logName: logName, cursorRoot: cursorRoot, cursorName: cursorName, cursorLock: lock, sourceBinding: lineageSource.bindStream(source), writeCheckpoint: writeCheckpointBytes, normalizer: privateNormalizer, sink: config.Sink, maximumLines: config.MaximumLines}, nil
}

func (processor *FileProcessor) Close() error {
	if processor == nil {
		return ErrStream
	}
	processor.mu.Lock()
	defer processor.mu.Unlock()
	if processor.closed {
		return nil
	}
	processor.closed = true
	processor.pending = nil
	logErr, cursorErr := processor.logRoot.Close(), processor.cursorRoot.Close()
	lockErr := processor.cursorLock.Close()
	if logErr != nil || cursorErr != nil || lockErr != nil {
		return ErrStream
	}
	return nil
}

func (processor *FileProcessor) ProcessAvailable(ctx context.Context) (StreamResult, error) {
	if processor == nil || ctx == nil || ctx.Err() != nil {
		return StreamResult{}, ErrStream
	}
	processor.mu.Lock()
	defer processor.mu.Unlock()
	if processor.closed || !validCursorLock(processor.cursorRoot, processor.cursorName+".lock", processor.cursorLock) {
		return StreamResult{}, ErrStream
	}
	if err := processor.loadCheckpoint(); err != nil {
		return StreamResult{}, err
	}
	if processor.pending != nil {
		return processor.commitPending(ctx)
	}
	state, found := cursorState{}, processor.checkpoint.Committed != nil
	if found {
		state = *processor.checkpoint.Committed
	}
	var err error
	var file *os.File
	var info os.FileInfo
	selectedName := ""
	for transitions := 0; transitions <= maximumLogFiles; transitions++ {
		var device, inode uint64
		file, info, device, inode, selectedName, err = openCursorLog(processor.logRoot, processor.logName, state, found)
		if err != nil || info.Size() < 0 || info.Size() > maximumTetragonFile || found && state.Offset > info.Size() {
			if file != nil {
				_ = file.Close()
			}
			return StreamResult{}, ErrStream
		}
		if !found {
			state = cursorState{Version: cursorContractVersion, Device: device, Inode: inode}
			found = true
			processor.reconstructed = true
		} else if !processor.reconstructed {
			if state.Offset > 0 && (state.Offset > maximumTetragonFile || processor.reconstruct(file, state.Offset) != nil) {
				_ = file.Close()
				return StreamResult{}, ErrStream
			}
			processor.reconstructed = true
		}
		if selectedName == processor.logName || state.Offset != info.Size() {
			break
		}
		_ = file.Close()
		state, err = nextLogState(processor.logRoot, processor.logName, selectedName, device, inode, state.Dropped)
		if err != nil {
			return StreamResult{}, err
		}
		file = nil
	}
	if file == nil {
		return StreamResult{}, ErrStream
	}
	defer file.Close()
	from := state
	lines, nextOffset, partial, err := readCompleteLines(file, state.Offset, processor.maximumLines)
	if err != nil {
		return StreamResult{}, err
	}
	if len(lines) == 0 {
		return StreamResult{Idle: partial || nextOffset == state.Offset}, nil
	}
	beforeCache, err := processor.normalizer.checkpoint()
	if err != nil {
		return StreamResult{}, err
	}
	processor.checkpoint.Cache = beforeCache
	events := make([]RuntimeEvent, 0, len(lines))
	droppedBefore := state.Dropped
	for _, line := range lines {
		event, normalizeErr := processor.normalizer.Normalize(line)
		if normalizeErr != nil {
			if state.Dropped == ^uint64(0) {
				_ = processor.normalizer.restoreCheckpoint(beforeCache)
				return StreamResult{}, ErrStream
			}
			state.Dropped++
			continue
		}
		events = append(events, event)
	}
	state.Offset = nextOffset
	if selectedName != processor.logName && nextOffset == info.Size() {
		state, err = nextLogState(processor.logRoot, processor.logName, selectedName, state.Device, state.Inode, state.Dropped)
		if err != nil {
			_ = processor.normalizer.restoreCheckpoint(beforeCache)
			return StreamResult{}, err
		}
	}
	result := StreamResult{Read: len(lines), Submitted: len(events), Dropped: state.Dropped - droppedBefore}
	cache, err := processor.normalizer.checkpoint()
	if err != nil {
		_ = processor.normalizer.restoreCheckpoint(beforeCache)
		return StreamResult{}, err
	}
	processor.pending = &pendingStream{Events: cloneRuntimeEvents(events), State: state, From: from, EndOffset: nextOffset, Result: result, Cache: cache}
	// Pending work can only be replayed, never rolled back or normalized again.
	// Its post-cursor cache is sufficient; retaining a second committed cache
	// would duplicate up to 8 MiB on disk and much more after JSON decoding.
	processor.checkpoint.Cache = nil
	processor.checkpoint.Pending = processor.pending
	return processor.commitPending(ctx)
}

func (processor *FileProcessor) commitPending(ctx context.Context) (StreamResult, error) {
	pending := processor.pending
	if pending == nil {
		return StreamResult{}, ErrStream
	}
	if pending.Envelope == nil && len(pending.Events) > 0 && processor.checkpoint.Target.Mode == runtimeEnvelopeVersion {
		client, ok := processor.sink.(*ProductionClient)
		if !ok {
			return StreamResult{}, ErrStream
		}
		envelope, err := safeStreamEnvelopePrepare(client, cloneRuntimeEvents(pending.Events))
		if err != nil {
			if persistErr := processor.persistCheckpoint(processor.checkpoint); persistErr != nil {
				return StreamResult{}, persistErr
			}
			return StreamResult{}, err
		}
		pending.Envelope = &envelope
		pending.Events = nil
	}
	// Re-persist before every attempt, including after an uncertain rename/sync.
	// No request is sent until its exact pending checkpoint is durable.
	if err := processor.persistCheckpoint(processor.checkpoint); err != nil {
		return StreamResult{}, err
	}
	if pending.Envelope != nil {
		if err := safeStreamEnvelopeIngest(processor.sink.(*ProductionClient), ctx, *pending.Envelope); err != nil {
			return StreamResult{}, err
		}
	} else if len(pending.Events) > 0 {
		if err := safeStreamIngest(processor.sink, ctx, cloneRuntimeEvents(pending.Events)); err != nil {
			return StreamResult{}, err
		}
	}
	if ctx.Err() != nil {
		return StreamResult{}, ErrClientRetryable
	}
	committed := *processor.checkpoint
	committed.Committed = &pending.State
	committed.Cache = pending.Cache
	committed.Pending = nil
	if err := processor.persistCheckpoint(&committed); err != nil {
		return StreamResult{}, err
	}
	result := pending.Result
	processor.checkpoint = &committed
	processor.pending = nil
	return result, nil
}

func (processor *FileProcessor) reconstruct(file *os.File, until int64) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrStream
	}
	reader := io.NewSectionReader(file, 0, until)
	consumed := int64(0)
	for consumed < until {
		lines, next, partial, err := readCompleteLines(reader, consumed, maximumBatchEvents)
		if err != nil || partial || next <= consumed || next > until {
			return ErrStream
		}
		for _, line := range lines {
			if len(line) != 0 {
				_, _ = processor.normalizer.Normalize(line)
			}
		}
		consumed = next
	}
	if consumed != until {
		return ErrStream
	}
	return nil
}

func readCompleteLines(file io.ReadSeeker, offset int64, maximum int) ([][]byte, int64, bool, error) {
	if file == nil || offset < 0 || maximum < 1 || maximum > maximumBatchEvents {
		return nil, offset, false, ErrStream
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, false, ErrStream
	}
	reader := bufio.NewReaderSize(file, maximumTetragonLineBytes+1)
	lines := make([][]byte, 0, maximum)
	next := offset
	retainedBytes := 0
	for len(lines) < maximum {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) {
			return lines, next, len(line) > 0, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			consumed := int64(len(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = reader.ReadSlice('\n')
				consumed += int64(len(line))
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, offset, false, ErrStream
			}
			if errors.Is(err, io.EOF) {
				return lines, next, true, nil
			}
			next += consumed
			lines = append(lines, nil)
			continue
		}
		if err != nil || len(line) < 1 || line[len(line)-1] != '\n' {
			return nil, offset, false, ErrStream
		}
		if len(line) > maximumEnvelopeBodyBytes-retainedBytes {
			return lines, next, false, nil
		}
		retainedBytes += len(line)
		next += int64(len(line))
		lines = append(lines, bytes.Clone(line[:len(line)-1]))
	}
	return lines, next, false, nil
}

func readCursorState(root *os.Root, name string) (cursorState, bool, error) {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return cursorState{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		return cursorState{}, false, ErrStream
	}
	file, err := root.Open(name)
	if err != nil {
		return cursorState{}, false, ErrStream
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return cursorState{}, false, ErrStream
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumCursorBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumCursorBytes || !bytes.HasSuffix(raw, []byte{'\n'}) {
		return cursorState{}, false, ErrStream
	}
	var state cursorState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validCursorState(state) {
		return cursorState{}, false, ErrStream
	}
	canonical, err := marshalCursorState(state)
	if err != nil || !bytes.Equal(raw, canonical) {
		return cursorState{}, false, ErrStream
	}
	return state, true, nil
}

func writeCursorState(root *os.Root, name string, state cursorState) (result error) {
	if root == nil || name == "" || !validCursorState(state) {
		return ErrStream
	}
	payload, err := marshalCursorState(state)
	if err != nil {
		return ErrStream
	}
	return writeCheckpointBytes(root, name, payload)
}

func writeCheckpointBytes(root *os.Root, name string, payload []byte) (result error) {
	if root == nil || name == "" || len(payload) == 0 || len(payload) > maximumCheckpointBytes {
		return ErrStream
	}
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
			return ErrStream
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
			return ErrStream
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStream
	}
	temporary := temporaryCheckpointName(name)
	// One reserved slot per cursor bounds crash leftovers. The caller holds
	// that cursor's lifetime lock; never remove another cursor's temporary file.
	if info, err := root.Lstat(temporary); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Size() > maximumCheckpointBytes {
			return ErrStream
		}
		if root.Remove(temporary) != nil {
			return ErrStream
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStream
	}
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrStream
	}
	defer func() {
		_ = file.Close()
		if result != nil {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Close() != nil || root.Rename(temporary, name) != nil {
		return ErrStream
	}
	directory, err := root.Open(".")
	if err != nil {
		return ErrStream
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrStream
	}
	return nil
}

func openPinnedLog(root *os.Root, name string) (*os.File, os.FileInfo, uint64, uint64, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, 0, 0, ErrStream
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, 0, 0, ErrStream
	}
	opened, err := file.Stat()
	after, afterErr := root.Lstat(name)
	if err != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		_ = file.Close()
		return nil, nil, 0, 0, ErrStream
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		_ = file.Close()
		return nil, nil, 0, 0, ErrStream
	}
	return file, opened, uint64(stat.Dev), uint64(stat.Ino), nil
}

func openCursorLog(root *os.Root, currentName string, state cursorState, found bool) (*os.File, os.FileInfo, uint64, uint64, string, error) {
	if !found {
		file, info, device, inode, err := openPinnedLog(root, currentName)
		return file, info, device, inode, currentName, err
	}
	names, err := orderedLogNames(root, currentName)
	if err != nil {
		return nil, nil, 0, 0, "", err
	}
	var match *os.File
	var matchInfo os.FileInfo
	var matchDevice, matchInode uint64
	matchName := ""
	for _, name := range names {
		file, info, device, inode, openErr := openPinnedLog(root, name)
		if openErr != nil {
			if match != nil {
				_ = match.Close()
			}
			return nil, nil, 0, 0, "", openErr
		}
		if device == state.Device && inode == state.Inode {
			if match != nil {
				_ = match.Close()
				_ = file.Close()
				return nil, nil, 0, 0, "", ErrStream
			}
			match, matchInfo, matchDevice, matchInode, matchName = file, info, device, inode, name
			continue
		}
		_ = file.Close()
	}
	if match != nil {
		return match, matchInfo, matchDevice, matchInode, matchName, nil
	}
	return nil, nil, 0, 0, "", ErrStream
}

func nextLogState(root *os.Root, currentName, selectedName string, device, inode, dropped uint64) (cursorState, error) {
	names, err := orderedLogNames(root, currentName)
	if err != nil {
		return cursorState{}, err
	}
	for index, name := range names {
		if name != selectedName {
			continue
		}
		selected, _, selectedDevice, selectedInode, openErr := openPinnedLog(root, name)
		if openErr != nil {
			return cursorState{}, openErr
		}
		_ = selected.Close()
		if selectedDevice != device || selectedInode != inode || index+1 >= len(names) {
			return cursorState{}, ErrStream
		}
		next, _, nextDevice, nextInode, openErr := openPinnedLog(root, names[index+1])
		if openErr != nil {
			return cursorState{}, openErr
		}
		_ = next.Close()
		if nextDevice == device && nextInode == inode {
			return cursorState{}, ErrStream
		}
		return cursorState{Version: cursorContractVersion, Device: nextDevice, Inode: nextInode, Dropped: dropped}, nil
	}
	return cursorState{}, ErrStream
}

func orderedLogNames(root *os.Root, currentName string) ([]string, error) {
	if root == nil || !validLogName(currentName) {
		return nil, ErrStream
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, ErrStream
	}
	defer directory.Close()
	entries, readErr := directory.ReadDir(maximumLogFiles + 1)
	if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > maximumLogFiles {
		return nil, ErrStream
	}
	rotated := make([]string, 0, len(entries))
	currentFound := false
	for _, entry := range entries {
		name := entry.Name()
		if name == currentName {
			currentFound = true
			continue
		}
		if validRotatedLogName(currentName, name) {
			rotated = append(rotated, name)
		}
	}
	if !currentFound {
		return nil, ErrStream
	}
	sort.Strings(rotated)
	return append(rotated, currentName), nil
}

func validLogName(name string) bool {
	return name != "" && filepath.Base(name) == name && name != "." && name != ".."
}

func validRotatedLogName(currentName, candidate string) bool {
	extension := filepath.Ext(currentName)
	prefix := strings.TrimSuffix(currentName, extension) + "-"
	if !validLogName(candidate) || !strings.HasPrefix(candidate, prefix) || !strings.HasSuffix(candidate, extension) {
		return false
	}
	stamp := strings.TrimSuffix(strings.TrimPrefix(candidate, prefix), extension)
	parsed, err := time.Parse(rotationTimestamp, stamp)
	return err == nil && parsed.Format(rotationTimestamp) == stamp
}

func openPinnedParent(path string) (*os.Root, string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, "", ErrStream
	}
	root, err := os.OpenRoot(resolved)
	if err != nil {
		return nil, "", ErrStream
	}
	return root, filepath.Base(path), nil
}

func marshalCursorState(state cursorState) ([]byte, error) {
	payload, err := json.Marshal(state)
	if err != nil || len(payload)+1 > maximumCursorBytes {
		return nil, ErrStream
	}
	return append(payload, '\n'), nil
}

func validCursorState(state cursorState) bool {
	return state.Version == cursorContractVersion && state.Device > 0 && state.Inode > 0 && state.Offset >= 0
}

func validAbsoluteFilePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != "." && filepath.Base(path) != string(filepath.Separator)
}

func cloneRuntimeEvents(events []RuntimeEvent) []RuntimeEvent {
	result := make([]RuntimeEvent, len(events))
	for index, event := range events {
		result[index] = event
		result[index].Content = make(map[string]string, len(event.Content))
		for key, value := range event.Content {
			result[index].Content[key] = value
		}
	}
	return result
}

func safeStreamIngest(sink StreamSink, ctx context.Context, events []RuntimeEvent) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrClientRetryable
		}
	}()
	return sink.Ingest(ctx, events)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
