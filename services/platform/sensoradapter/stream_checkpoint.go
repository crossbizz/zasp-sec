package sensoradapter

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
	"syscall"
	"time"
)

const streamCheckpointVersion = "tetragon-checkpoint-v2"
const maximumCheckpointBytes = 32 << 20
const checkpointTemporaryPrefix = ".zasp-sensor-checkpoint-"

func temporaryCheckpointName(cursorName string) string {
	digest := sha256.Sum256([]byte("zasp.stream-temporary.v2\x00" + cursorName))
	return checkpointTemporaryPrefix + hex.EncodeToString(digest[:]) + ".tmp"
}

type streamTarget struct {
	Mode        string `json:"mode"`
	Destination string `json:"destination,omitempty"`
	Enrollment  string `json:"enrollment,omitempty"`
}

type streamCheckpoint struct {
	Version   string                  `json:"version"`
	Source    string                  `json:"source"`
	Target    streamTarget            `json:"target"`
	Committed *cursorState            `json:"committed,omitempty"`
	Cache     []cachedProcessIdentity `json:"cache"`
	Pending   *pendingStream          `json:"pending,omitempty"`
}

func streamSinkTarget(sink StreamSink) streamTarget {
	target := streamTarget{Mode: "normalized-events-v1"}
	if client, ok := sink.(*ProductionClient); ok && client != nil && client.base != nil {
		target.Destination = client.base.String() + runtimeEventsPath
		target.Enrollment = client.enrollment
		if client.enrollment != "" {
			target.Mode = runtimeEnvelopeVersion
		}
	}
	return target
}

func streamSourceBinding(root *os.Root, path string) (string, error) {
	file, err := root.Open(".")
	if err != nil {
		return "", ErrStream
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", ErrStream
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrStream
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("zasp.stream-source.v2\x00%s\x00%d\x00%d", path, stat.Dev, stat.Ino)))
	return hex.EncodeToString(digest[:]), nil
}

func (processor *FileProcessor) loadCheckpoint() error {
	if processor.checkpoint != nil {
		return nil
	}
	checkpoint := &streamCheckpoint{Version: streamCheckpointVersion, Source: processor.sourceBinding, Target: streamSinkTarget(processor.sink), Cache: []cachedProcessIdentity{}}
	raw, err := readCheckpointBytes(processor.cursorRoot, processor.cursorName)
	if errors.Is(err, os.ErrNotExist) {
		processor.checkpoint = checkpoint
		return nil
	}
	if err != nil {
		return ErrStream
	}
	var header struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ErrStream
	}
	if header.Version == cursorContractVersion {
		if processor.normalizer.lineageSource != (LineageSource{}) {
			return ErrStream
		}
		state, found, err := readCursorState(processor.cursorRoot, processor.cursorName)
		if err != nil || !found {
			return ErrStream
		}
		checkpoint.Committed = &state
		// Legacy cursors contain neither retained cache nor pending requests.
		// Existing prefix reconstruction remains explicitly best-effort.
		processor.checkpoint = checkpoint
		return nil
	}
	// Canonical comparison below rejects unknown/aliased fields. Unmarshal can
	// borrow this bounded input without Decoder's second full-size read buffer.
	if !checkpointJSONBounded(raw, processor.normalizer.maximum) || json.Unmarshal(raw, checkpoint) != nil {
		return ErrStream
	}
	if processor.validateCheckpoint(checkpoint) != nil {
		return ErrStream
	}
	comparison := &checkpointComparisonWriter{expected: raw}
	if json.NewEncoder(comparison).Encode(checkpoint) != nil || comparison.offset != len(raw) {
		return ErrStream
	}
	cache := checkpoint.Cache
	if checkpoint.Pending != nil {
		cache = checkpoint.Pending.Cache
	}
	if processor.normalizer.restoreCheckpoint(cache) != nil {
		return ErrStream
	}
	processor.checkpoint, processor.pending, processor.reconstructed = checkpoint, checkpoint.Pending, true
	return nil
}

func readCheckpointBytes(root *os.Root, name string) ([]byte, error) {
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() <= 0 || before.Size() > maximumCheckpointBytes {
		return nil, ErrStream
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, ErrStream
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrStream
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrStream
	}
	// Size was bounded before allocation. Avoid ReadAll's successive full-size
	// growth copies for a checkpoint close to the configured limit.
	raw := make([]byte, int(before.Size()))
	if _, err := io.ReadFull(file, raw); err != nil {
		return nil, ErrStream
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, ErrStream
	}
	return raw, nil
}

func cacheCheckpointSize(identities []cachedProcessIdentity, maximum int) (int, error) {
	if identities == nil || len(identities) > maximum {
		return 0, ErrStream
	}
	size := 2
	seen := make(map[processCorrelationKey]struct{})
	for _, identity := range identities {
		entrySize, err := cacheIdentitySize(identity)
		key, ok := correlationKey(identity.Node, identity.process())
		_, duplicate := seen[key]
		if err != nil || !ok || duplicate || entrySize > maximumCacheEncodedBytes-size {
			return 0, ErrStream
		}
		seen[key] = struct{}{}
		size += entrySize
	}
	return size, nil
}

func checkpointEventsSize(events []RuntimeEvent) (int, error) {
	if len(events) > maximumBatchEvents {
		return 0, ErrStream
	}
	size := 2
	for _, event := range events {
		when, err := time.Parse(timestampLayout, event.EventTime)
		if err != nil || !validRuntimeEvent(event, when) {
			return 0, ErrStream
		}
		body, err := json.Marshal(event)
		if err != nil || len(body)+1 > maximumEnvelopeBodyBytes-size {
			return 0, ErrStream
		}
		size += len(body) + 1
	}
	return size, nil
}

func (processor *FileProcessor) validateCheckpoint(checkpoint *streamCheckpoint) error {
	if checkpoint == nil || checkpoint.Version != streamCheckpointVersion || checkpoint.Source != processor.sourceBinding || checkpoint.Target != streamSinkTarget(processor.sink) || checkpoint.Committed != nil && !validCursorState(*checkpoint.Committed) {
		return ErrStream
	}
	size := 0
	if checkpoint.Pending == nil {
		var err error
		size, err = cacheCheckpointSize(checkpoint.Cache, processor.normalizer.maximum)
		if err != nil {
			return ErrStream
		}
	} else if checkpoint.Cache != nil {
		return ErrStream
	}
	size += 32 << 10 // bounded target and structural encoding overhead
	if pending := checkpoint.Pending; pending != nil {
		if !validCursorState(pending.From) || pending.EndOffset <= pending.From.Offset || pending.EndOffset > maximumTetragonFile || pending.From.Dropped > pending.State.Dropped {
			return ErrStream
		}
		if pending.From.Device == pending.State.Device && pending.From.Inode == pending.State.Inode {
			if pending.State.Offset != pending.EndOffset {
				return ErrStream
			}
		} else if pending.State.Offset != 0 {
			return ErrStream
		}
		committedDrops := uint64(0)
		if checkpoint.Committed != nil {
			committedDrops = checkpoint.Committed.Dropped
			if pending.From.Device == checkpoint.Committed.Device && pending.From.Inode == checkpoint.Committed.Inode {
				if pending.From.Offset != checkpoint.Committed.Offset {
					return ErrStream
				}
			} else if pending.From.Offset != 0 {
				return ErrStream
			}
			if pending.State.Device == checkpoint.Committed.Device && pending.State.Inode == checkpoint.Committed.Inode && pending.State.Offset <= checkpoint.Committed.Offset {
				return ErrStream
			}
		} else if pending.From.Offset != 0 {
			return ErrStream
		}
		if pending.From.Dropped != committedDrops {
			return ErrStream
		}
		if !validCursorState(pending.State) || pending.Result.Idle || pending.Result.Read < 1 || pending.Result.Read > processor.maximumLines || pending.Result.Submitted < 0 || pending.Result.Submitted > pending.Result.Read || pending.Result.Dropped != uint64(pending.Result.Read-pending.Result.Submitted) || pending.State.Dropped < committedDrops || pending.State.Dropped-committedDrops != pending.Result.Dropped {
			return ErrStream
		}
		cacheSize, err := cacheCheckpointSize(pending.Cache, processor.normalizer.maximum)
		if err != nil {
			return ErrStream
		}
		size += cacheSize
		if pending.Envelope != nil {
			envelope := pending.Envelope
			if pending.Result.Submitted < 1 || checkpoint.Target.Mode != runtimeEnvelopeVersion || envelope.Version != runtimeEnvelopeVersion || envelope.Schema != enrollmentRuntimeSchema || envelope.Destination != checkpoint.Target.Destination || envelope.EnrollmentBinding != checkpoint.Target.Enrollment || len(envelope.Body) == 0 || len(envelope.Body) > maximumEnvelopeBodyBytes || envelope.IdempotencyKey != envelopeIdempotency(envelope.Body) || len(pending.Events) != 0 {
				return ErrStream
			}
			var body runtimeEnvelopeBody
			if !checkpointJSONBounded(envelope.Body, maximumBatchEvents) || json.Unmarshal(envelope.Body, &body) != nil || body.Source != "tetragon" || len(body.Events) != pending.Result.Submitted {
				return ErrStream
			}
			if _, err := checkpointEventsSize(body.Events); err != nil {
				return ErrStream
			}
			canonical, err := json.Marshal(body)
			if err != nil || !bytes.Equal(canonical, envelope.Body) {
				return ErrStream
			}
			size += (len(envelope.Body)+2)/3*4 + 4096
		} else {
			if len(pending.Events) != pending.Result.Submitted {
				return ErrStream
			}
			eventSize, err := checkpointEventsSize(pending.Events)
			if err != nil {
				return ErrStream
			}
			size += eventSize
		}
	} else if checkpoint.Committed == nil {
		return ErrStream
	}
	if size > maximumCheckpointBytes {
		return ErrStream
	}
	return nil
}

func (processor *FileProcessor) marshalCheckpoint(checkpoint *streamCheckpoint) ([]byte, error) {
	if processor.validateCheckpoint(checkpoint) != nil {
		return nil, ErrStream
	}
	var buffer bytes.Buffer
	// Encoder supplies the final newline without appending and copying the
	// entire encoded checkpoint into a second large backing array.
	if json.NewEncoder(&buffer).Encode(checkpoint) != nil || buffer.Len() > maximumCheckpointBytes {
		return nil, ErrStream
	}
	return buffer.Bytes(), nil
}

type checkpointComparisonWriter struct {
	expected []byte
	offset   int
}

func (writer *checkpointComparisonWriter) Write(value []byte) (int, error) {
	if len(value) > len(writer.expected)-writer.offset || !bytes.Equal(value, writer.expected[writer.offset:writer.offset+len(value)]) {
		return 0, ErrStream
	}
	writer.offset += len(value)
	return len(value), nil
}

// Bound collection cardinality before unmarshalling into structs/maps. A small
// encoded array of nulls must not allocate millions of cache-entry structs.
func checkpointJSONBounded(raw []byte, maximumCache int) bool {
	parser := checkpointPreflight{raw: raw, maximumCache: maximumCache}
	if !parser.value(nil, 0) {
		return false
	}
	if parser.offset < len(raw) && raw[parser.offset] == '\n' {
		parser.offset++
	}
	// The allocation-free pass establishes collection/string bounds; the
	// standard JSON scanner remains authoritative for lexical correctness.
	return parser.offset == len(raw) && json.Valid(raw)
}

type checkpointPreflight struct {
	raw                  []byte
	offset, maximumCache int
	cacheArrays          int
}

func (parser *checkpointPreflight) take(want byte) bool {
	if parser.offset >= len(parser.raw) || parser.raw[parser.offset] != want {
		return false
	}
	parser.offset++
	return true
}

func (parser *checkpointPreflight) text(maximum int, escapes bool) ([]byte, bool) {
	if !parser.take('"') {
		return nil, false
	}
	start := parser.offset
	for parser.offset < len(parser.raw) {
		if parser.offset-start > maximum {
			return nil, false
		}
		current := parser.raw[parser.offset]
		parser.offset++
		if current == '"' {
			return parser.raw[start : parser.offset-1], true
		}
		if current < ' ' {
			return nil, false
		}
		if current == '\\' {
			if !escapes || parser.offset >= len(parser.raw) {
				return nil, false
			}
			parser.offset++
		}
	}
	return nil, false
}

func (parser *checkpointPreflight) value(key []byte, depth int) bool {
	if depth > 16 || parser.offset >= len(parser.raw) {
		return false
	}
	switch parser.raw[parser.offset] {
	case '"':
		maximum, escapes := 4096*6, true
		if bytes.Equal(key, []byte("body")) {
			maximum = (maximumEnvelopeBodyBytes + 2) / 3 * 4
			escapes = false
		}
		value, ok := parser.text(maximum, escapes)
		// Unescaped scalar values cannot use the sixfold JSON-escape allowance.
		return ok && (bytes.Equal(key, []byte("body")) || len(value) <= 4096 || bytes.IndexByte(value, '\\') >= 0)
	case '{':
		parser.offset++
		if parser.take('}') {
			return true
		}
		var seen [32][]byte
		for count := 0; count < len(seen); count++ {
			field, ok := parser.text(128, false)
			if !ok || !parser.take(':') {
				return false
			}
			for _, prior := range seen[:count] {
				if bytes.Equal(prior, field) {
					return false
				}
			}
			seen[count] = field
			if !parser.value(field, depth+1) {
				return false
			}
			if parser.take('}') {
				return true
			}
			if !parser.take(',') {
				return false
			}
		}
		return false
	case '[':
		parser.offset++
		maximum := maximumBatchEvents
		if bytes.Equal(key, []byte("cache")) {
			parser.cacheArrays++
			if parser.cacheArrays > 1 {
				return false
			}
			maximum = parser.maximumCache
		}
		if parser.take(']') {
			return true
		}
		for count := 0; count < maximum; count++ {
			if !parser.value(nil, depth+1) {
				return false
			}
			if parser.take(']') {
				return true
			}
			if !parser.take(',') {
				return false
			}
		}
		return false
	default:
		start := parser.offset
		for parser.offset < len(parser.raw) && parser.offset-start <= 64 {
			current := parser.raw[parser.offset]
			if current == ',' || current == ']' || current == '}' || current == '\n' {
				break
			}
			parser.offset++
		}
		return parser.offset > start && parser.offset-start <= 64
	}
}

func (processor *FileProcessor) persistCheckpoint(checkpoint *streamCheckpoint) error {
	if !validCursorLock(processor.cursorRoot, processor.cursorName+".lock", processor.cursorLock) {
		return ErrStream
	}
	payload, err := processor.marshalCheckpoint(checkpoint)
	if err != nil {
		return ErrStream
	}
	return processor.writeCheckpoint(processor.cursorRoot, processor.cursorName, payload)
}

func safeStreamEnvelopePrepare(client *ProductionClient, events []RuntimeEvent) (envelope RuntimeEnvelope, err error) {
	defer func() {
		if recover() != nil {
			envelope = RuntimeEnvelope{}
			err = ErrClientRetryable
		}
	}()
	return client.PrepareEnvelope(events)
}

func safeStreamEnvelopeIngest(client *ProductionClient, ctx context.Context, envelope RuntimeEnvelope) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrClientRetryable
		}
	}()
	return client.IngestEnvelope(ctx, envelope)
}
