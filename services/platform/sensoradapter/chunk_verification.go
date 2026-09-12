package sensoradapter

import (
	"context"
	"syscall"
)

// VerifiedConsumption binds durable local accounting to reread source bytes.
// Submitted/Dropped are checkpoint accounting, not independently re-normalized
// outcomes or cryptographic proof of remote acceptance. Callers must verify the
// source seal separately and keep processor/reader ownership stable until use.
type VerifiedConsumption struct {
	Source      LineageSource `json:"source"`
	Destination string        `json:"destination"`
	Device      uint64        `json:"device"`
	Inode       uint64        `json:"inode"`
	Progress    ChunkProgress `json:"progress"`
}

func (p *chunkProcessor[E]) VerifyConsumed(ctx context.Context) (VerifiedConsumption, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return VerifiedConsumption{}, ErrStream
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.load() != nil || !p.durable || p.checkpoint.Pending != nil || p.validate(p.checkpoint) != nil {
		return VerifiedConsumption{}, ErrStream
	}
	committed := p.checkpoint.Committed
	observed := p.initialProgress()
	for observed.NextSequence < committed.NextSequence {
		if ctx.Err() != nil {
			return VerifiedConsumption{}, ErrStream
		}
		chunk, found, err := safeChunkRead(p.read, ctx, observed.NextSequence)
		if err != nil || !found || ctx.Err() != nil {
			return VerifiedConsumption{}, ErrStream
		}
		lines, size, err := copyChunk(chunk, observed)
		if err != nil {
			return VerifiedConsumption{}, ErrStream
		}
		observed.Read += len(lines)
		observed.Bytes += size
		observed.Chain = chunkChain(observed.Chain, chunk.Sequence, chunk.Digest)
		observed.NextSequence++
	}
	if observed.Read != committed.Read || observed.Bytes != committed.Bytes || observed.Chain != committed.Chain || ctx.Err() != nil {
		return VerifiedConsumption{}, ErrStream
	}
	info, err := chunkRootInfo(p.sourceRoot)
	if err != nil {
		return VerifiedConsumption{}, ErrStream
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return VerifiedConsumption{}, ErrStream
	}
	// Re-establish the durability barrier even if the named checkpoint has been
	// lost since the last successful commit. No proof escapes uncertain sync.
	if p.persist(p.checkpoint) != nil || ctx.Err() != nil {
		return VerifiedConsumption{}, ErrStream
	}
	return VerifiedConsumption{Source: p.source, Destination: p.checkpoint.Target.Destination, Device: uint64(stat.Dev), Inode: stat.Ino, Progress: committed}, nil
}
