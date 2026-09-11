package sensoradapter

import (
	"context"
	"net/url"
	"os"
	"syscall"
)

// VerifyConsumptionSource rereads a bounded committed prefix without a consumer
// checkpoint, normalizer, credential or transport. Source/destination must come
// from the caller's trusted installation, not the receipt. The caller must also
// verify the receipt issuer, immutable source admission and complete source seal.
// Submitted/Dropped are checked for consistency, not independently authenticated.
// Success does not grant a reusable deletion capability or prove remote delivery.
func VerifyConsumptionSource(ctx context.Context, root *os.Root, source LineageSource, destination string, proof VerifiedConsumption, read func(context.Context, int) (ImmutableChunk, bool, error)) error {
	if ctx == nil || ctx.Err() != nil || !source.valid() || proof.Source != source || proof.Destination != destination || read == nil || len(destination) > 2048 {
		return ErrStream
	}
	if !validConsumptionDestination(destination) {
		return ErrStream
	}
	info, err := chunkRootInfo(root)
	if err != nil {
		return ErrStream
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != proof.Device || stat.Ino != proof.Inode {
		return ErrStream
	}
	binding, err := chunkSourceBinding(root, source)
	if err != nil {
		return ErrStream
	}
	observed := ChunkProgress{NextSequence: 1, Chain: chunkChain(binding, 0, "")}
	if !validChunkProgress(proof.Progress, observed) {
		return ErrStream
	}
	for observed.NextSequence < proof.Progress.NextSequence {
		if ctx.Err() != nil {
			return ErrStream
		}
		chunk, found, err := safeChunkRead(read, ctx, observed.NextSequence)
		if err != nil || !found || ctx.Err() != nil {
			return ErrStream
		}
		lines, size, err := copyChunk(chunk, observed)
		if err != nil {
			return ErrStream
		}
		observed.Read += len(lines)
		observed.Bytes += size
		observed.Chain = chunkChain(observed.Chain, chunk.Sequence, chunk.Digest)
		observed.NextSequence++
	}
	finalBinding, err := chunkSourceBinding(root, source)
	if err != nil || finalBinding != binding || ctx.Err() != nil || observed.Read != proof.Progress.Read || observed.Bytes != proof.Progress.Bytes || observed.Chain != proof.Progress.Chain {
		return ErrStream
	}
	return nil
}

func validConsumptionDestination(destination string) bool {
	target, err := url.Parse(destination)
	return len(destination) <= 2048 && err == nil && target.Scheme == "https" && target.Hostname() != "" && target.User == nil && target.Path == runtimeEventsPath && target.RawPath == "" && target.RawQuery == "" && !target.ForceQuery && target.Fragment == "" && target.RawFragment == "" && target.Opaque == "" && target.String() == destination
}

func validChunkProgress(value, initial ChunkProgress) bool {
	if value.NextSequence == 1 {
		return value == initial
	}
	// Bound before arithmetic so hostile receipt integers cannot overflow.
	if value.NextSequence < 2 || value.NextSequence > maximumGenerationChunks+1 {
		return false
	}
	chunks := value.NextSequence - 1
	return enrollmentBindingPattern.MatchString(value.Chain) && value.Read >= chunks && value.Read <= chunks*maximumBatchEvents && value.Submitted >= 0 && value.Submitted <= value.Read && value.Dropped == uint64(value.Read-value.Submitted) && value.Bytes >= int64(value.Read*2) && value.Bytes <= int64(chunks)*maximumChunkBytes && value.Bytes <= maximumGenerationBytes
}
