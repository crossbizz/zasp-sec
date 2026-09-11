package main

import (
	"context"
	"os"
	"sync"

	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
)

type lineageChunkConsumer struct {
	mu              sync.Mutex
	reader          *lineageSpoolReader
	processor       *sensoradapter.ChunkProcessor
	acknowledgments *lineageAcknowledgments
}

func newLineageChunkConsumer(reader *lineageSpoolReader, client *sensoradapter.ProductionClient, cursor string, maximum int, protected []sensoradapter.PinnedInput) (*lineageChunkConsumer, error) {
	return buildLineageChunkConsumer(reader, client, cursor, maximum, protected, nil)
}

func newAssignedLineageChunkConsumer(reader *lineageSpoolReader, client *sensoradapter.ProductionClient, cursor string, maximum int, protected []sensoradapter.PinnedInput, store *lineageAcknowledgments, assignment lineageSlotAssignment) (*lineageChunkConsumer, error) {
	if store == nil || assignment.Version != "tetragon-consumer-slot-v1" || assignment.Slot < 0 || assignment.Slot >= lineageSpoolSlots || assignment.ConsumerUID != uint32(os.Geteuid()) {
		return nil, errLineageSpool
	}
	return buildBoundLineageChunkConsumer(reader, client, cursor, maximum, protected, store, lineageAssignmentBinding(assignment))
}

func lineageAssignmentBinding(assignment lineageSlotAssignment) *sensoradapter.ChunkStateBinding {
	return &sensoradapter.ChunkStateBinding{Source: assignment.Source, Destination: assignment.Destination, CursorName: lineageSlotCursor(assignment.Slot), CursorDevice: assignment.StateDevice, CursorInode: assignment.StateInode, SpoolDevice: assignment.SpoolDevice, SpoolInode: assignment.SpoolInode, SourceDevice: assignment.SourceDevice, SourceInode: assignment.SourceInode}
}

func buildLineageChunkConsumer(reader *lineageSpoolReader, client *sensoradapter.ProductionClient, cursor string, maximum int, protected []sensoradapter.PinnedInput, acknowledgments *lineageAcknowledgments) (*lineageChunkConsumer, error) {
	return buildBoundLineageChunkConsumer(reader, client, cursor, maximum, protected, acknowledgments, nil)
}

func buildBoundLineageChunkConsumer(reader *lineageSpoolReader, client *sensoradapter.ProductionClient, cursor string, maximum int, protected []sensoradapter.PinnedInput, acknowledgments *lineageAcknowledgments, binding *sensoradapter.ChunkStateBinding) (*lineageChunkConsumer, error) {
	if reader == nil {
		return nil, errLineageSpool
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if !reader.valid() {
		return nil, errLineageSpool
	}
	var outputs []*os.Root
	if acknowledgments != nil {
		acknowledgments.mu.Lock()
		defer acknowledgments.mu.Unlock()
		if !acknowledgments.valid() {
			return nil, errLineageSpool
		}
		outputs = []*os.Root{acknowledgments.root}
	}
	processor, err := sensoradapter.NewChunkProcessor(sensoradapter.ChunkProcessorConfig{
		Source: reader.source, SourceRoot: reader.root, SpoolRoot: reader.parent,
		CursorPath: cursor, MaximumProcesses: maximum, Client: client, ProtectedInputs: protected,
		DisjointOutputRoots: outputs,
		StateBinding:        binding,
		ReadChunk: func(ctx context.Context, sequence int) (sensoradapter.ImmutableChunk, bool, error) {
			// ProcessAvailable holds reader.mu through the complete operation.
			// Close cannot revoke borrowed roots halfway through a pending upload.
			if ctx.Err() != nil {
				return sensoradapter.ImmutableChunk{}, false, errLineageSpool
			}
			chunk, found, err := reader.readChunkLocked(sequence)
			if err != nil || ctx.Err() != nil {
				return sensoradapter.ImmutableChunk{}, false, errLineageSpool
			}
			return sensoradapter.ImmutableChunk{Sequence: chunk.Sequence, Digest: chunk.Digest, Lines: chunk.Lines}, found, nil
		},
	})
	if err != nil {
		return nil, err
	}
	return &lineageChunkConsumer{reader: reader, processor: processor, acknowledgments: acknowledgments}, nil
}

func (consumer *lineageChunkConsumer) ProcessAvailable(ctx context.Context) (sensoradapter.StreamResult, error) {
	if consumer == nil || consumer.reader == nil || consumer.processor == nil || ctx == nil || ctx.Err() != nil {
		return sensoradapter.StreamResult{}, errLineageSpool
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	consumer.reader.mu.Lock()
	defer consumer.reader.mu.Unlock()
	// Recheck admission even on frozen replay, which intentionally doesn't read
	// another source chunk. This lock protects reader lifetime, not producer I/O.
	if !consumer.reader.valid() {
		return sensoradapter.StreamResult{}, errLineageSpool
	}
	return consumer.processor.ProcessAvailable(ctx)
}

func (consumer *lineageChunkConsumer) Committed() (sensoradapter.ChunkProgress, bool, error) {
	if consumer == nil || consumer.reader == nil || consumer.processor == nil {
		return sensoradapter.ChunkProgress{}, false, errLineageSpool
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	consumer.reader.mu.Lock()
	defer consumer.reader.mu.Unlock()
	if !consumer.reader.valid() {
		return sensoradapter.ChunkProgress{}, false, errLineageSpool
	}
	return consumer.processor.Committed()
}

// Close owns only the cursor processor. The caller closes the borrowed reader
// and client after this consumer; no seal, ACK or reclamation is performed here.
func (consumer *lineageChunkConsumer) Close() error {
	if consumer == nil || consumer.processor == nil {
		return errLineageSpool
	}
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.processor.Close()
}
