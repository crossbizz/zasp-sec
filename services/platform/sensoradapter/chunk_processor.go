package sensoradapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

const (
	chunkCheckpointVersion  = "tetragon-chunk-checkpoint-v1"
	maximumGenerationChunks = 128
	maximumGenerationBytes  = 8 << 20
	maximumChunkBytes       = 1 << 20
)

// ImmutableChunk comes from an admitted, owned generation reader. Digest is
// SHA-256 of all Lines, each followed by LF, including rejected records.
type ImmutableChunk struct {
	Sequence int
	Digest   string
	Lines    [][]byte
}

// ChunkProcessorConfig borrows the client's and admitted reader's lifetime.
// Roots must stay open until Close. ReadChunk must revalidate the producer's
// manifest and immutable publication before returning bounded, owned records.
// No old exporter stream may be supplied as a newly qualified generation.
type ChunkProcessorConfig struct {
	Source                LineageSource
	SourceRoot, SpoolRoot *os.Root
	CursorPath            string
	Client                *ProductionClient
	MaximumProcesses      int
	ReadChunk             func(context.Context, int) (ImmutableChunk, bool, error)
	ProtectedInputs       []PinnedInput
	// Borrowed output directories must differ by inode from the cursor,
	// generation, spool and every protected-input parent, before cursor writes.
	DisjointOutputRoots []*os.Root
	// Optional durable slot binding. Compare all opened physical identities and
	// upload authority before creating a cursor lock. The processor retains its
	// opened roots, so a later pathname replacement can't redirect its writes.
	StateBinding *ChunkStateBinding
}

type ChunkStateBinding struct {
	Source                    LineageSource
	Destination               string
	CursorName                string
	CursorDevice, CursorInode uint64
	SpoolDevice, SpoolInode   uint64
	SourceDevice, SourceInode uint64
}

func chunkStateIdentityMatches(info os.FileInfo, device, inode uint64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && inode != 0 && uint64(stat.Dev) == device && stat.Ino == inode
}

// ChunkProgress counts consumed source records, not just uploaded events.
// It is not a producer acknowledgment or a proof of upstream coverage.
type ChunkProgress struct {
	NextSequence int    `json:"next_sequence"`
	Chain        string `json:"chain"`
	Read         int    `json:"read"`
	Submitted    int    `json:"submitted"`
	Dropped      uint64 `json:"dropped"`
	Bytes        int64  `json:"bytes"`
}

type pendingChunk = pendingChunkOf[RuntimeEvent]
type pendingChunkOf[E any] struct {
	Sequence int                     `json:"sequence"`
	Digest   string                  `json:"digest"`
	Bytes    int64                   `json:"bytes"`
	Result   StreamResult            `json:"result"`
	Next     ChunkProgress           `json:"next"`
	Events   []E                     `json:"events,omitempty"`
	Envelope *RuntimeEnvelope        `json:"envelope,omitempty"`
	Cache    []cachedProcessIdentity `json:"cache"`
}

type chunkCheckpoint = chunkCheckpointOf[RuntimeEvent]
type chunkCheckpointOf[E any] struct {
	Version   string                  `json:"version"`
	Source    string                  `json:"source"`
	Target    streamTarget            `json:"target"`
	Committed ChunkProgress           `json:"committed"`
	Cache     []cachedProcessIdentity `json:"cache"`
	Pending   *pendingChunkOf[E]      `json:"pending,omitempty"`
}

type ChunkProcessor = chunkProcessor[RuntimeEvent]
type chunkProcessor[E any] struct {
	mu                                sync.Mutex
	source                            LineageSource
	sourceRoot, spoolRoot, cursorRoot *os.Root
	cursorName                        string
	lock                              *os.File
	binding                           string
	client                            *ProductionClient
	normalizer                        *Normalizer
	read                              func(context.Context, int) (ImmutableChunk, bool, error)
	checkpoint                        *chunkCheckpointOf[E]
	contract                          chunkRecordContract[E]
	durable, closed                   bool
	writeCheckpoint                   func(*os.Root, string, []byte) error
}

func chunkRootInfo(root *os.Root) (os.FileInfo, error) {
	if root == nil {
		return nil, ErrStream
	}
	f, err := root.Open(".")
	if err != nil {
		return nil, ErrStream
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() {
		return nil, ErrStream
	}
	return info, nil
}

func NewChunkProcessor(config ChunkProcessorConfig) (*ChunkProcessor, error) {
	normalizer, err := NewLineageNormalizer(config.MaximumProcesses, config.Source)
	if err != nil {
		return nil, ErrStream
	}
	return newChunkProcessor(config, normalizer, legacyChunkContract(normalizer))
}

func newChunkProcessor[E any](config ChunkProcessorConfig, normalizer *Normalizer, contract chunkRecordContract[E]) (*chunkProcessor[E], error) {
	if normalizer == nil || config.Client == nil || config.Client.base == nil || config.Client.enrollment != config.Source.EnrollmentBinding || config.ReadChunk == nil || !validAbsoluteFilePath(config.CursorPath) || !validCursorName(filepath.Base(config.CursorPath)) || len(config.ProtectedInputs) > 8 || len(config.DisjointOutputRoots) > 8 {
		return nil, ErrStream
	}
	sourceInfo, err := chunkRootInfo(config.SourceRoot)
	if err != nil {
		return nil, ErrStream
	}
	spoolInfo, err := chunkRootInfo(config.SpoolRoot)
	if err != nil || os.SameFile(sourceInfo, spoolInfo) {
		return nil, ErrStream
	}
	root, name, err := openPinnedParent(config.CursorPath)
	if err != nil {
		return nil, ErrStream
	}
	accepted := false
	defer func() {
		if !accepted {
			root.Close()
		}
	}()
	info, err := chunkRootInfo(root)
	if err != nil || os.SameFile(info, sourceInfo) || os.SameFile(info, spoolInfo) || !privateChunkCursorDirectory(info) {
		return nil, ErrStream
	}
	if binding := config.StateBinding; binding != nil {
		if binding.Source != config.Source || binding.CursorName != name || binding.Destination != config.Client.base.String()+runtimeEventsPath || !chunkStateIdentityMatches(info, binding.CursorDevice, binding.CursorInode) || !chunkStateIdentityMatches(spoolInfo, binding.SpoolDevice, binding.SpoolInode) || !chunkStateIdentityMatches(sourceInfo, binding.SourceDevice, binding.SourceInode) {
			return nil, ErrStream
		}
	}
	for _, input := range config.ProtectedInputs {
		if input.Parent == nil || input.Name == "" || input.Name == "." || input.Name == ".." || filepath.Base(input.Name) != input.Name || !cursorInputDisjoint(root, name, input.Parent, input.Name) {
			return nil, ErrStream
		}
	}
	for _, output := range config.DisjointOutputRoots {
		outputInfo, err := chunkRootInfo(output)
		if err != nil || os.SameFile(outputInfo, info) || os.SameFile(outputInfo, sourceInfo) || os.SameFile(outputInfo, spoolInfo) {
			return nil, ErrStream
		}
		for _, input := range config.ProtectedInputs {
			inputInfo, err := chunkRootInfo(input.Parent)
			if err != nil || os.SameFile(outputInfo, inputInfo) {
				return nil, ErrStream
			}
		}
	}
	binding, err := chunkSourceBinding(config.SourceRoot, config.Source)
	if err != nil {
		return nil, ErrStream
	}
	lock, err := acquireCursorLock(root, name+".lock")
	if err != nil {
		return nil, ErrStream
	}
	accepted = true
	return &chunkProcessor[E]{source: config.Source, sourceRoot: config.SourceRoot, spoolRoot: config.SpoolRoot, cursorRoot: root, cursorName: name, lock: lock, binding: binding, client: config.Client, normalizer: normalizer, contract: contract, read: config.ReadChunk, writeCheckpoint: writeCheckpointBytes}, nil
}

func privateChunkCursorDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func chunkSourceBinding(root *os.Root, source LineageSource) (string, error) {
	info, err := chunkRootInfo(root)
	if err != nil {
		return "", ErrStream
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrStream
	}
	return chunkSourceIdentityBinding(source, uint64(stat.Dev), stat.Ino), nil
}

func chunkSourceIdentityBinding(source LineageSource, device, inode uint64) string {
	raw, _ := json.Marshal(source)
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("zasp.chunk-source.v1\x00%d\x00%d\x00", device, inode)), raw...))
	return hex.EncodeToString(sum[:])
}

func chunkChain(previous string, sequence int, digest string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("zasp.chunk-chain.v1\x00%s\x00%d\x00%s", previous, sequence, digest)))
	return hex.EncodeToString(sum[:])
}

func (p *chunkProcessor[E]) initialProgress() ChunkProgress {
	return ChunkProgress{NextSequence: 1, Chain: chunkChain(p.binding, 0, "")}
}

func (p *chunkProcessor[E]) valid() bool {
	if p.closed || !validCursorLock(p.cursorRoot, p.cursorName+".lock", p.lock) {
		return false
	}
	info, err := chunkRootInfo(p.cursorRoot)
	if err != nil || !privateChunkCursorDirectory(info) {
		return false
	}
	binding, err := chunkSourceBinding(p.sourceRoot, p.source)
	if err != nil || binding != p.binding {
		return false
	}
	_, err = chunkRootInfo(p.spoolRoot)
	return err == nil
}

func (p *chunkProcessor[E]) Close() error {
	if p == nil {
		return ErrStream
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	lockErr, rootErr := p.lock.Close(), p.cursorRoot.Close()
	if lockErr != nil || rootErr != nil {
		return ErrStream
	}
	return nil
}

// Committed reports durable local progress only when no upload is pending.
// Reclamation requires separate verified generation-seal and ACK handling.
func (p *chunkProcessor[E]) Committed() (ChunkProgress, bool, error) {
	if p == nil {
		return ChunkProgress{}, false, ErrStream
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.load() != nil {
		return ChunkProgress{}, false, ErrStream
	}
	return p.checkpoint.Committed, p.durable && p.checkpoint.Pending == nil, nil
}

func (p *chunkProcessor[E]) ProcessAvailable(ctx context.Context) (StreamResult, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return StreamResult{}, ErrStream
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.load() != nil {
		return StreamResult{}, ErrStream
	}
	if p.checkpoint.Pending != nil {
		return p.commitPending(ctx)
	}
	progress := p.checkpoint.Committed
	if progress.NextSequence > maximumGenerationChunks {
		return StreamResult{Idle: true}, nil
	}
	chunk, found, err := safeChunkRead(p.read, ctx, progress.NextSequence)
	if err != nil || ctx.Err() != nil {
		return StreamResult{}, ErrStream
	}
	if !found {
		if !p.durable {
			if err := p.persist(p.checkpoint); err != nil {
				return StreamResult{}, err
			}
			p.durable = true
		}
		return StreamResult{Idle: true}, nil
	}
	lines, size, err := copyChunk(chunk, progress)
	if err != nil {
		return StreamResult{}, err
	}
	before, err := p.normalizer.checkpoint()
	if err != nil {
		return StreamResult{}, err
	}
	// Restore on any internal failure. Explicit input rejection alone is a drop.
	staged := false
	defer func() {
		if !staged {
			_ = p.normalizer.restoreCheckpoint(before)
		}
	}()
	result := StreamResult{Read: len(lines)}
	events := make([]E, 0, len(lines))
	for _, line := range lines {
		if ctx.Err() != nil {
			return StreamResult{}, ErrStream
		}
		// Check node before normalization can populate the private process cache.
		var identity struct {
			NodeName string `json:"node_name"`
		}
		if json.Unmarshal(line, &identity) == nil && identity.NodeName != "" && identity.NodeName != p.source.NodeName {
			return StreamResult{}, ErrStream
		}
		event, normalizeErr := safeChunkRecordNormalize(p.contract.normalize, line)
		if normalizeErr == ErrAdapter {
			result.Dropped++
			continue
		}
		if normalizeErr != nil {
			return StreamResult{}, ErrStream
		}
		events = append(events, event)
	}
	result.Submitted = len(events)
	cache, err := p.normalizer.checkpoint()
	if err != nil {
		return StreamResult{}, err
	}
	next := ChunkProgress{NextSequence: progress.NextSequence + 1, Chain: chunkChain(progress.Chain, chunk.Sequence, chunk.Digest), Read: progress.Read + result.Read, Submitted: progress.Submitted + result.Submitted, Dropped: progress.Dropped + result.Dropped, Bytes: progress.Bytes + size}
	pending := &pendingChunkOf[E]{Sequence: chunk.Sequence, Digest: chunk.Digest, Bytes: size, Result: result, Next: next, Events: events, Cache: cache}
	checkpoint := *p.checkpoint
	checkpoint.Cache, checkpoint.Pending = nil, pending
	if p.validate(&checkpoint) != nil {
		return StreamResult{}, ErrStream
	}
	p.checkpoint = &checkpoint
	staged = true
	// The pending checkpoint owns the post-cache now. Do not retain a second
	// maximal cache through envelope preparation and durable upload retries.
	before = nil
	return p.commitPending(ctx)
}

func copyChunk(chunk ImmutableChunk, progress ChunkProgress) ([][]byte, int64, error) {
	if chunk.Sequence != progress.NextSequence || chunk.Sequence < 1 || chunk.Sequence > maximumGenerationChunks || !enrollmentBindingPattern.MatchString(chunk.Digest) || len(chunk.Lines) < 1 || len(chunk.Lines) > maximumBatchEvents {
		return nil, 0, ErrStream
	}
	size := int64(0)
	for _, line := range chunk.Lines {
		if len(line) < 1 || len(line) > maximumTetragonLineBytes || bytes.ContainsAny(line, "\r\n") {
			return nil, 0, ErrStream
		}
		size += int64(len(line) + 1)
		if size > maximumChunkBytes || size > maximumGenerationBytes-progress.Bytes {
			return nil, 0, ErrStream
		}
	}
	lines := make([][]byte, len(chunk.Lines))
	hash := sha256.New()
	for i, line := range chunk.Lines {
		lines[i] = bytes.Clone(line)
		hash.Write(lines[i])
		hash.Write([]byte{'\n'})
	}
	if hex.EncodeToString(hash.Sum(nil)) != chunk.Digest {
		return nil, 0, ErrStream
	}
	return lines, size, nil
}

func safeChunkRead(read func(context.Context, int) (ImmutableChunk, bool, error), ctx context.Context, sequence int) (chunk ImmutableChunk, found bool, err error) {
	defer func() {
		if recover() != nil {
			chunk, found, err = ImmutableChunk{}, false, ErrStream
		}
	}()
	return read(ctx, sequence)
}

func safeChunkRecordNormalize[E any](normalize func([]byte) (E, error), line []byte) (event E, err error) {
	defer func() {
		if recover() != nil {
			var zero E
			event, err = zero, ErrStream
		}
	}()
	return normalize(line)
}

func (p *chunkProcessor[E]) commitPending(ctx context.Context) (StreamResult, error) {
	pending := p.checkpoint.Pending
	if pending.Envelope == nil && len(pending.Events) > 0 {
		envelope, err := p.contract.prepare(p.client, pending.Events)
		if err != nil {
			if persistErr := p.persist(p.checkpoint); persistErr != nil {
				return StreamResult{}, persistErr
			}
			return StreamResult{}, err
		}
		pending.Events, pending.Envelope = nil, &envelope
	}
	// Repeat the persistence barrier even after uncertain rename/directory sync.
	if err := p.persist(p.checkpoint); err != nil {
		return StreamResult{}, err
	}
	if pending.Envelope != nil {
		if err := p.contract.ingest(p.client, ctx, *pending.Envelope); err != nil {
			return StreamResult{}, err
		}
	}
	if ctx.Err() != nil {
		return StreamResult{}, ErrClientRetryable
	}
	committed := *p.checkpoint
	committed.Committed, committed.Cache, committed.Pending = pending.Next, pending.Cache, nil
	if err := p.persist(&committed); err != nil {
		return StreamResult{}, err
	}
	p.checkpoint, p.durable = &committed, true
	return pending.Result, nil
}

func (p *chunkProcessor[E]) load() error {
	if p.checkpoint != nil {
		return nil
	}
	checkpoint := &chunkCheckpointOf[E]{Version: p.contract.checkpointVersion, Source: p.binding, Target: p.target(), Committed: p.initialProgress(), Cache: []cachedProcessIdentity{}}
	raw, err := readCheckpointBytes(p.cursorRoot, p.cursorName)
	if errors.Is(err, os.ErrNotExist) {
		p.checkpoint = checkpoint
		return nil
	}
	if err != nil || !checkpointJSONBounded(raw, p.normalizer.maximum) || json.Unmarshal(raw, checkpoint) != nil || p.validate(checkpoint) != nil {
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
	if p.normalizer.restoreCheckpoint(cache) != nil {
		return ErrStream
	}
	p.checkpoint, p.durable = checkpoint, true
	return nil
}

func (p *chunkProcessor[E]) persist(checkpoint *chunkCheckpointOf[E]) error {
	if !p.valid() || p.validate(checkpoint) != nil {
		return ErrStream
	}
	var buffer bytes.Buffer
	if json.NewEncoder(&buffer).Encode(checkpoint) != nil || buffer.Len() > maximumCheckpointBytes {
		return ErrStream
	}
	return p.writeCheckpoint(p.cursorRoot, p.cursorName, buffer.Bytes())
}

func (p *chunkProcessor[E]) validProgress(value ChunkProgress) bool {
	return validChunkProgress(value, p.initialProgress())
}

func (p *chunkProcessor[E]) validate(checkpoint *chunkCheckpointOf[E]) error {
	if checkpoint == nil || checkpoint.Version != p.contract.checkpointVersion || checkpoint.Source != p.binding || checkpoint.Target != p.target() || !p.validProgress(checkpoint.Committed) {
		return ErrStream
	}
	cache := checkpoint.Cache
	cacheHistory := checkpoint.Committed.Submitted
	size := 32 << 10
	if pending := checkpoint.Pending; pending != nil {
		if cache != nil || pending.Sequence != checkpoint.Committed.NextSequence || pending.Sequence > maximumGenerationChunks || !enrollmentBindingPattern.MatchString(pending.Digest) || pending.Result.Idle || pending.Result.Read < 1 || pending.Result.Read > maximumBatchEvents || pending.Result.Submitted < 0 || pending.Result.Submitted > pending.Result.Read || pending.Result.Dropped != uint64(pending.Result.Read-pending.Result.Submitted) || pending.Bytes < int64(pending.Result.Read*2) || pending.Bytes > maximumChunkBytes {
			return ErrStream
		}
		previous := checkpoint.Committed
		expected := ChunkProgress{NextSequence: previous.NextSequence + 1, Chain: chunkChain(previous.Chain, pending.Sequence, pending.Digest), Read: previous.Read + pending.Result.Read, Submitted: previous.Submitted + pending.Result.Submitted, Dropped: previous.Dropped + pending.Result.Dropped, Bytes: previous.Bytes + pending.Bytes}
		if pending.Next != expected || !p.validProgress(pending.Next) {
			return ErrStream
		}
		cache = pending.Cache
		cacheHistory = pending.Next.Submitted
		events := pending.Events
		if envelope := pending.Envelope; envelope != nil {
			if pending.Result.Submitted < 1 || len(events) != 0 || envelope.Version != p.contract.envelopeVersion || envelope.Schema != p.contract.schema || envelope.Destination != checkpoint.Target.Destination || envelope.EnrollmentBinding != checkpoint.Target.Enrollment || len(envelope.Body) == 0 || len(envelope.Body) > maximumEnvelopeBodyBytes || envelope.IdempotencyKey != p.contract.idempotency(envelope.Body) {
				return ErrStream
			}
			var err error
			events, err = p.contract.decode(envelope.Body)
			if err != nil {
				return ErrStream
			}
			size += (len(envelope.Body)+2)/3*4 + 4096
		}
		if len(events) != pending.Result.Submitted {
			return ErrStream
		}
		eventSize, err := p.contract.eventSize(events)
		if err != nil {
			return ErrStream
		}
		if pending.Envelope == nil {
			size += eventSize
		}
		for _, event := range events {
			observation := p.contract.observation(event)
			if observation.Profile != "" && (observation.ClusterUID != p.source.ClusterUID || observation.NodeUID != p.source.NodeUID || observation.BootID != p.source.BootID) {
				return ErrStream
			}
		}
	}
	// A fresh/empty generation cannot adopt cached identity from older history.
	// This necessary count bound isn't per-entry provenance proof: Submitted
	// also includes other event classes. Identity comes from the owned normalizer.
	if len(cache) > cacheHistory {
		return ErrStream
	}
	cacheSize, err := cacheCheckpointSize(cache, p.normalizer.maximum)
	if err != nil || size+cacheSize > maximumCheckpointBytes {
		return ErrStream
	}
	for _, identity := range cache {
		if identity.Node != p.source.NodeName {
			return ErrStream
		}
	}
	return nil
}
