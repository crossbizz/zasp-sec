package migrations

import "testing"

func TestTemporalAutomaticChecksumMatchesBoundMetadata(t *testing.T) {
	if actual, want := TemporalAutomaticSourcesChecksum(), ProductionTemporalAutomaticSources().Checksum(); actual != want {
		t.Fatalf("checksum-only=%s bound metadata=%s", actual, want)
	}
}
