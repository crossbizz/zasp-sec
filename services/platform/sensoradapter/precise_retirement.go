package sensoradapter

import (
	"context"
	"os"
)

// VerifyPreciseConsumptionSource requires trusted V3 source authority. Like the
// V1 verifier, it checks bytes/accounting only, not remote acceptance or issuer.
func VerifyPreciseConsumptionSource(ctx context.Context, root *os.Root, source LineageSource, destination string, proof VerifiedConsumption, read func(context.Context, int) (ImmutableChunk, bool, error)) error {
	if !validPreciseRetirementSource(source) {
		return ErrStream
	}
	return verifyConsumptionSource(ctx, root, source, destination, proof, read)
}

// RetirePreciseConsumedCheckpoint retains all V1 filesystem and authorization
// barriers but accepts only a completed V2 checkpoint for an admitted V3 source.
func RetirePreciseConsumedCheckpoint(ctx context.Context, config ChunkRetirementConfig) error {
	if !validPreciseRetirementSource(config.Source) {
		return ErrStream
	}
	return retireConsumedCheckpoint(ctx, config, "tetragon-chunk-checkpoint-v2", preciseEnvelopeVersion)
}

func validPreciseRetirementSource(source LineageSource) bool {
	if source.Profile != "tetragon-local-stream-v3" {
		return false
	}
	// Identity constraints are unchanged. Never rewrite the actual bound source.
	source.Profile = "tetragon-local-stream-v2"
	return source.valid()
}
