package migrations

import "sync"

// TemporalSingleRecoveryMetadata is the exact immutable identity consumed by
// runtime readiness probes. Database readiness and registration are never
// cached here.
type TemporalSingleRecoveryMetadata struct {
	Checksum        string
	ReadyBodyDigest string
}

var temporalSingleRecoveryMetadata = sync.OnceValue(func() TemporalSingleRecoveryMetadata {
	source, checksum := ProductionTemporalSingleRecoverySource()
	ready := recoveryFindBody(source, "zasp_temporal_single_recovery.ready(text)")
	return TemporalSingleRecoveryMetadata{Checksum: checksum, ReadyBodyDigest: recoverySHA(ready.body)}
})

func ProductionTemporalSingleRecoveryMetadata() TemporalSingleRecoveryMetadata {
	return temporalSingleRecoveryMetadata()
}
