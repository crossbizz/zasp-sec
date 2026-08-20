package sensoradapter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	LogPath      string
	CursorPath   string
	Normalizer   *Normalizer
	Sink         StreamSink
	MaximumLines int
}

type StreamResult struct {
	Read      int
	Submitted int
	Dropped   uint64
	Idle      bool
}

type cursorState struct {
	Version string `json:"version"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Offset  int64  `json:"offset"`
	Dropped uint64 `json:"dropped"`
}

type pendingStream struct {
	events []RuntimeEvent
	state  cursorState
	result StreamResult
}

type FileProcessor struct {
	mu            sync.Mutex
	logRoot       *os.Root
	logName       string
	cursorRoot    *os.Root
	cursorName    string
	normalizer    *Normalizer
	sink          StreamSink
	maximumLines  int
	pending       *pendingStream
	reconstructed bool
	closed        bool
}

func NewFileProcessor(config FileProcessorConfig) (*FileProcessor, error) {
	if !validAbsoluteFilePath(config.LogPath) || !validAbsoluteFilePath(config.CursorPath) || config.LogPath == config.CursorPath || config.Normalizer == nil || nilInterface(config.Sink) || config.MaximumLines < 1 || config.MaximumLines > maximumBatchEvents {
		return nil, ErrStream
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
	return &FileProcessor{logRoot: logRoot, logName: logName, cursorRoot: cursorRoot, cursorName: cursorName, normalizer: config.Normalizer, sink: config.Sink, maximumLines: config.MaximumLines}, nil
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
	if logErr != nil || cursorErr != nil {
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
	if processor.closed {
		return StreamResult{}, ErrStream
	}
	if processor.pending != nil {
		return processor.commitPending(ctx)
	}
	state, found, err := readCursorState(processor.cursorRoot, processor.cursorName)
	if err != nil {
		return StreamResult{}, err
	}
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
	lines, nextOffset, partial, err := readCompleteLines(file, state.Offset, processor.maximumLines)
	if err != nil {
		return StreamResult{}, err
	}
	if len(lines) == 0 {
		return StreamResult{Idle: partial || nextOffset == state.Offset}, nil
	}
	events := make([]RuntimeEvent, 0, len(lines))
	droppedBefore := state.Dropped
	for _, line := range lines {
		event, normalizeErr := processor.normalizer.Normalize(line)
		if normalizeErr != nil {
			state.Dropped++
			continue
		}
		events = append(events, event)
	}
	state.Offset = nextOffset
	if selectedName != processor.logName && nextOffset == info.Size() {
		state, err = nextLogState(processor.logRoot, processor.logName, selectedName, state.Device, state.Inode, state.Dropped)
		if err != nil {
			return StreamResult{}, err
		}
	}
	result := StreamResult{Read: len(lines), Submitted: len(events), Dropped: state.Dropped - droppedBefore}
	if len(events) == 0 {
		if err := writeCursorState(processor.cursorRoot, processor.cursorName, state); err != nil {
			return StreamResult{}, err
		}
		return result, nil
	}
	processor.pending = &pendingStream{events: cloneRuntimeEvents(events), state: state, result: result}
	return processor.commitPending(ctx)
}

func (processor *FileProcessor) commitPending(ctx context.Context) (StreamResult, error) {
	pending := processor.pending
	if pending == nil {
		return StreamResult{}, ErrStream
	}
	if err := safeStreamIngest(processor.sink, ctx, cloneRuntimeEvents(pending.events)); err != nil {
		return StreamResult{}, err
	}
	if err := writeCursorState(processor.cursorRoot, processor.cursorName, pending.state); err != nil {
		return StreamResult{}, err
	}
	result := pending.result
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
	if info, err := root.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
			return ErrStream
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStream
	}
	payload, err := marshalCursorState(state)
	if err != nil {
		return ErrStream
	}
	temporary, err := randomCursorName()
	if err != nil {
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

func randomCursorName() (string, error) {
	value := [8]byte{}
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", ErrStream
	}
	return ".zasp-sensor-cursor-" + hex.EncodeToString(value[:]), nil
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
