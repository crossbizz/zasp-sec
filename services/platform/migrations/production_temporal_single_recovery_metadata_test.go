package migrations

import "testing"

func TestProductionTemporalSingleRecoveryMetadataMatchesAssembler(t *testing.T) {
	metadata := ProductionTemporalSingleRecoveryMetadata()
	source, checksum := ProductionTemporalSingleRecoverySource()
	wantDigest := recoverySHA(recoveryFindBody(source, "zasp_temporal_single_recovery.ready(text)").body)
	if metadata.Checksum != checksum || metadata.ReadyBodyDigest != wantDigest || len(metadata.Checksum) != 64 || len(metadata.ReadyBodyDigest) != 64 {
		t.Fatal("immutable recovery metadata differs from assembler")
	}
	if again := ProductionTemporalSingleRecoveryMetadata(); again != metadata {
		t.Fatal("immutable recovery metadata changed")
	}
}
